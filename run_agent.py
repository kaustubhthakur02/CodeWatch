"""CodeWatch CLI: scan a repo, triage findings, and generate proposed fixes."""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from agent import cve, deps, fixer, github_pr, notify, report, scanner, triage

# Windows consoles default to cp1252 and mangle non-ASCII source lines in diffs.
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

load_dotenv()


def main() -> int:
    parser = argparse.ArgumentParser(prog="codewatch")
    parser.add_argument("repo", help="path to the repository to scan")
    parser.add_argument("--findings", help="reuse an existing semgrep JSON file instead of scanning")
    parser.add_argument("--max-files", type=int, default=3, help="max files to generate fixes for")
    parser.add_argument("--model", help="OpenRouter model id override")
    parser.add_argument("--no-fix", action="store_true", help="scan and triage only")
    parser.add_argument("--write", action="store_true", help="apply patches to the repo on disk")
    parser.add_argument("--out", help="write the full report JSON here")
    parser.add_argument("--pr-body", help="write the rendered PR body markdown here")
    parser.add_argument("--open-pr", action="store_true", help="actually open the pull request on GitHub")
    parser.add_argument("--repo-name", help="owner/repo target for the PR (defaults to $GITHUB_REPO)")
    parser.add_argument("--email", action="store_true", help="email the report to the commit author")
    parser.add_argument("--email-preview", help="write the email HTML here instead of sending it")
    parser.add_argument("--author-email", help="commit author address (from the webhook payload)")
    parser.add_argument("--author-name", help="commit author name, used to greet them")
    parser.add_argument("--path-prefix", default="", help="subdirectory the scanned repo sits in within the GitHub repo")
    parser.add_argument("--deps", action="store_true", help="check pinned dependencies for advisories via Exa")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()

    if args.findings:
        raw = json.loads(Path(args.findings).read_text(encoding="utf-8"))
        findings = scanner.parse_findings(raw, repo)
        print(f"Loaded {len(findings)} findings from {args.findings}")
    else:
        print(f"Scanning {repo} with Semgrep...")
        findings = scanner.scan(repo)
        print(f"Semgrep reported {len(findings)} findings")

    fixable = triage.prioritize(findings)
    skipped = triage.unfixable(findings)

    print(f"\n{len(fixable)} fixable / {len(skipped)} out of scope\n")
    for finding, category in fixable:
        print(f"  [{triage.CATEGORIES[category]['label']:<18}] {finding.path}:{finding.start_line}  {finding.short_rule}")
    for finding in skipped:
        print(f"  [{'skipped':<18}] {finding.path}:{finding.start_line}  {finding.short_rule}")

    advisories = []
    if args.deps:
        dependencies = deps.collect(repo)
        print(f"\nChecking {len(dependencies)} pinned dependency(ies) against live advisories...")
        advisories = cve.check_all(dependencies, model=args.model)
        for a in advisories:
            if a.affected:
                ids = ", ".join(a.cve_ids) or "no id"
                fix = a.recommended_version or "?"
                print(f"  [{a.severity:<8}] {a.dependency} -> upgrade to {fix}  ({ids})")
            else:
                print(f"  [{'clean':<8}] {a.dependency}")

    if args.no_fix or not fixable:
        return 0

    grouped = triage.group_by_file(fixable)
    patches = []
    for rel_path, items in list(grouped.items())[: args.max_files]:
        print(f"\nGenerating fix for {rel_path} ({len(items)} findings)...")
        patch = fixer.fix_file(repo, rel_path, items, model=args.model)
        patches.append(patch)
        status = "validated" if patch.valid else "REJECTED"
        repairs = f", {patch.repair_attempts} self-repair round(s)" if patch.repair_attempts else ""
        print(f"  -> {len(patch.diff.splitlines())} diff lines, {status}{repairs}")
        if patch.verification:
            print(f"     re-scan: {patch.verification.summary()}")
        for problem in patch.problems:
            print(f"     ! {problem}")
        for f in patch.findings:
            mark = "fixed" if f.get("fixed") else "not fixed"
            print(f"     - [{f.get('severity','?')}/{mark}] {f.get('title','')}")

    print("\n" + "=" * 70)
    for patch in patches:
        print(f"\n--- {patch.path} ---")
        print(patch.diff or "(no changes)")
        if patch.risk_notes:
            print(f"\nRisk notes: {patch.risk_notes}")

    if args.write:
        for patch in patches:
            if patch.proposable:
                (repo / patch.path).write_text(patch.fixed, encoding="utf-8")
                print(f"applied: {patch.path}")

    repo_name = args.repo_name or os.environ.get("GITHUB_REPO", repo.name)
    fixed_total = sum(1 for p in patches for f in p.findings if f.get("fixed"))
    title = f"CodeWatch: fix {fixed_total} security finding(s)"
    body = report.pr_body(patches, skipped, repo_name=repo_name, advisories=advisories)

    if args.pr_body:
        Path(args.pr_body).write_text(body, encoding="utf-8")
        print(f"\nPR body written to {args.pr_body}")

    pr_url = ""
    if args.open_pr:
        proposable = [p for p in patches if p.proposable]
        if not proposable:
            print("\nNo validated patches — refusing to open a PR.")
        else:
            result = github_pr.open_fix_pr(
                proposable, title, body, repo_full_name=args.repo_name, path_prefix=args.path_prefix
            )
            pr_url = result.url
            print(f"\nOpened PR #{result.number}: {pr_url}  (branch {result.branch})")

    if args.email_preview:
        Path(args.email_preview).write_text(
            notify.build_html(patches, skipped, advisories, pr_url or "https://github.com/example/pull/1",
                              repo_name, author_name=args.author_name or ""),
            encoding="utf-8",
        )
        print(f"\nEmail preview written to {args.email_preview}")

    if args.email:
        to_addrs, cc_addrs = notify.resolve_recipients(args.author_email)
        if not to_addrs:
            print("\nNo recipient resolved — set SECURITY_EMAIL or pass --author-email")
        else:
            html = notify.build_html(
                patches, skipped, advisories, pr_url, repo_name, author_name=args.author_name or ""
            )
            try:
                sent = notify.send_email(
                    subject=f"[CodeWatch] {fixed_total} security issue(s) in your push to {repo_name}",
                    html=html,
                    to_addrs=to_addrs,
                    cc_addrs=cc_addrs,
                )
                print(f"\nEmail sent to: {', '.join(sent)}")
            except Exception as exc:
                # The pull request is the deliverable; a mail problem must not fail the run.
                print(f"\nEmail could not be sent ({type(exc).__name__}: {exc}) — the PR is still open.")

    if args.out:
        report_data = {
            "repo": str(repo),
            "total_findings": len(findings),
            "fixable": [f.to_dict() | {"category": c} for f, c in fixable],
            "skipped": [f.to_dict() for f in skipped],
            "patches": [
                {
                    "path": p.path,
                    "diff": p.diff,
                    "findings": p.findings,
                    "risk_notes": p.risk_notes,
                    "valid": p.valid,
                    "problems": p.problems,
                    "repair_attempts": p.repair_attempts,
                }
                for p in patches
            ],
        }
        Path(args.out).write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        print(f"\nreport written to {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

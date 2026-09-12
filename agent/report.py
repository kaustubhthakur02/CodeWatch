"""Render CodeWatch results as the pull-request body."""

from __future__ import annotations

from .fixer import FilePatch
from .scanner import Finding
from .triage import CATEGORIES

SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def _severity_counts(patches: list[FilePatch]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for patch in patches:
        for f in patch.findings:
            if f.get("fixed"):
                sev = f.get("severity", "unknown")
                counts[sev] = counts.get(sev, 0) + 1
    return counts


def dependency_section(advisories: list) -> list[str]:
    affected = [a for a in advisories if a.affected]
    if not affected:
        return []

    lines = [
        "---",
        "",
        f"### 📦 Vulnerable dependencies ({len(affected)})",
        "",
        "_Found by searching live advisory sources via Exa — these are published after the "
        "model's training cutoff, so they cannot be recalled from memory._",
        "",
    ]
    for a in affected:
        emoji = SEVERITY_EMOJI.get(a.severity, "⚪")
        cves = ", ".join(f"`{c}`" for c in a.cve_ids) or "_no id published_"
        upgrade = f"`{a.dependency.name}=={a.recommended_version}`" if a.recommended_version else "a patched release"
        lines += [
            f"#### {emoji} {a.dependency.name} {a.dependency.version}",
            "",
            f"- **Advisories:** {cves}",
            f"- **Declared in:** `{a.dependency.source_file}:{a.dependency.line}`",
            f"- **Upgrade to:** {upgrade}",
            f"- **Confidence:** {a.confidence}",
            "",
            a.summary,
            "",
            "<details><summary>Sources</summary>",
            "",
        ]
        lines += [f"- {s}" for s in a.sources[:5]]
        lines += ["", "</details>", ""]

    lines += [
        "> CodeWatch does **not** bump dependency versions automatically — an upgrade can "
        "change behaviour, so this one is left for you to decide.",
        "",
    ]
    return lines


def pr_body(
    patches: list[FilePatch],
    skipped: list[Finding],
    repo_name: str = "",
    scan_ref: str = "",
    advisories: list | None = None,
) -> str:
    fixed_total = sum(1 for p in patches for f in p.findings if f.get("fixed"))
    counts = _severity_counts(patches)
    summary = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items())) or "none"

    lines = [
        "## 🛡️ CodeWatch: automated security fixes",
        "",
        f"I scanned {'`' + repo_name + '`' if repo_name else 'this repository'} with Semgrep"
        + (f" at `{scan_ref}`" if scan_ref else "")
        + f" and am proposing fixes for **{fixed_total} finding(s)** ({summary})."
        + (
            f" I also found **{len([a for a in (advisories or []) if a.affected])} vulnerable "
            "dependency(ies)** — see below."
            if any(a.affected for a in (advisories or []))
            else ""
        ),
        "",
        "**Nothing here has been merged.** Every change below is a suggestion for you to review.",
        "",
        "---",
        "",
    ]

    for patch in patches:
        lines.append(f"### `{patch.path}`")
        lines.append("")
        for f in patch.findings:
            emoji = SEVERITY_EMOJI.get(f.get("severity", ""), "⚪")
            state = "" if f.get("fixed") else " — _not fixed, needs a human_"
            lines += [
                f"#### {emoji} {f.get('title', 'Finding')}{state}",
                "",
                f"**What's wrong:** {f.get('explanation', '')}",
                "",
                f"**What I changed:** {f.get('fix_summary', '')}",
                "",
            ]
            if f.get("reference"):
                lines += [f"**Reference:** {f['reference']}", ""]
        v = patch.verification
        if v and v.clean:
            lines += [
                f"> ✅ **Re-scanned after patching:** the scanner no longer reports any of the "
                f"{len(v.resolved)} finding(s) in this file.",
                "",
            ]
        elif v:
            lines += [
                "> 🔍 **Re-scanned after patching:** the scanner still flags "
                f"{len(v.remaining)} pattern(s) here "
                + ", ".join(f"`{f.short_rule}` (line {f.start_line})" for f in v.remaining[:4])
                + ". Static analysis cannot prove an allowlist is sound, so this is often a false "
                "positive on a correct fix — but please confirm it by eye.",
                "",
            ]
        if patch.additional_changes:
            lines += [
                "**Also changed in this file** — not reported by the scanner, but unsafe to leave:",
                "",
            ]
            lines += [
                f"- {c.get('what', '')} — {c.get('why', '')}" for c in patch.additional_changes
            ]
            lines.append("")
        if patch.problems:
            lines += ["<details><summary>Static analysis notes on this patch</summary>", ""]
            lines += [f"- `{p}`" for p in patch.problems]
            lines += ["", "</details>", ""]
        if patch.risk_notes:
            lines += [f"> ⚠️ **Reviewer note:** {patch.risk_notes}", ""]

    lines += dependency_section(advisories or [])

    if skipped:
        lines += [
            "---",
            "",
            "<details><summary>"
            f"{len(skipped)} finding(s) outside CodeWatch's fix scope — reported, not changed"
            "</summary>",
            "",
        ]
        for f in skipped:
            lines.append(f"- `{f.path}:{f.start_line}` — {f.short_rule}: {f.message}")
        lines += ["", "</details>", ""]

    lines += [
        "---",
        "",
        "<sub>CodeWatch only proposes fixes for "
        + ", ".join(c["label"] for c in CATEGORIES.values())
        + ". Every patch is syntax- and import-checked before it reaches this PR.</sub>",
    ]
    return "\n".join(lines)

"""Turn grouped findings into a human-readable explanation plus a patched file."""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .llm import chat_json
from .scanner import Finding
from .triage import CATEGORIES
from .validate import blocking_problems, validate_python

SYSTEM_PROMPT = """You are CodeWatch, a security engineer that fixes vulnerabilities in pull requests.

You will be given one source file and the security findings a SAST scanner reported in it.

Rules you must follow:
- Fix ONLY the findings listed. Do not refactor, rename, reformat, or "improve" anything else.
- Preserve the file's existing style, imports ordering, and behaviour for non-vulnerable paths.
- Never invent a real secret value. Replace hardcoded secrets with os.environ reads and a safe default of None or a clearly-fake placeholder.
- CRITICAL: if your fix uses a module the file does not already import (re, os, subprocess, ...), you MUST add the import statement. Return the WHOLE file including its import block, not just the changed functions.
- If a finding is a false positive or you cannot fix it safely, leave that code unchanged and say so in its explanation.
- Explanations are for a developer who is not a security specialist: plain English, no jargon dumps, 2-3 sentences.

Return STRICT JSON with this shape:
{
  "fixed_file_content": "<the complete file after your fix, verbatim>",
  "findings": [
    {
      "fingerprint": "<the fingerprint you were given>",
      "title": "<short title, max 60 chars>",
      "explanation": "<2-3 plain-English sentences: what is wrong and what an attacker could do>",
      "fix_summary": "<1 sentence describing the change you made>",
      "severity": "critical|high|medium|low",
      "fixed": true|false
    }
  ],
  "additional_changes": [
    {
      "what": "<any change you made that was NOT one of the listed findings>",
      "why": "<why it was unsafe to leave, in one plain sentence>"
    }
  ],
  "risk_notes": "<anything a reviewer should double-check, or empty string>"
}

If you change anything beyond the listed findings, you MUST declare it in additional_changes.
A reviewer seeing an undocumented edit in a security patch will reject the whole PR. Leave
additional_changes as an empty list if you changed nothing else."""


@dataclass
class FilePatch:
    path: str
    original: str
    fixed: str
    diff: str
    findings: list[dict]
    risk_notes: str
    valid: bool
    additional_changes: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    repair_attempts: int = 0

    @property
    def changed(self) -> bool:
        return self.original != self.fixed

    @property
    def proposable(self) -> bool:
        return self.changed and self.valid


def _build_user_prompt(
    rel_path: str,
    source: str,
    items: list[tuple[Finding, str]],
    enrichment: dict[str, str] | None = None,
) -> str:
    lines = [f"FILE: {rel_path}", "", "```python", source, "```", "", "FINDINGS:"]
    for finding, category in items:
        cat = CATEGORIES[category]
        lines += [
            "",
            f"- fingerprint: {finding.fingerprint}",
            f"  category: {cat['label']} ({cat['cwe']})",
            f"  rule: {finding.short_rule}",
            f"  location: line {finding.start_line}",
            f"  scanner message: {finding.message}",
            f"  severity: {finding.severity} / impact: {finding.impact} / confidence: {finding.confidence}",
            f"  fix guidance: {cat['guidance']}",
        ]
        if enrichment and finding.fingerprint in enrichment:
            lines.append(f"  reference context: {enrichment[finding.fingerprint]}")
    lines += ["", "Return the JSON described in your instructions."]
    return "\n".join(lines)


def _make_diff(rel_path: str, source: str, fixed: str) -> str:
    return "".join(
        difflib.unified_diff(
            source.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
        )
    )


def fix_file(
    repo_path: str | Path,
    rel_path: str,
    items: list[tuple[Finding, str]],
    enrichment: dict[str, str] | None = None,
    model: str | None = None,
    max_repairs: int = 2,
) -> FilePatch:
    repo_path = Path(repo_path).resolve()
    source = (repo_path / rel_path).read_text(encoding="utf-8")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _build_user_prompt(rel_path, source, items, enrichment)},
    ]

    result = chat_json(messages, model=model, max_tokens=8192)
    fixed = result.get("fixed_file_content", source)
    ok, problems = validate_python(rel_path, fixed)

    attempts = 0
    while not ok and attempts < max_repairs:
        attempts += 1
        messages += [
            {"role": "assistant", "content": json.dumps(result)},
            {
                "role": "user",
                "content": (
                    "Your patch does not pass static validation. Problems found:\n"
                    + "\n".join(f"- {p}" for p in blocking_problems(problems))
                    + "\n\nMost often this means you used a module without importing it. "
                    "Return the same JSON again with fixed_file_content corrected, "
                    "including the complete import block."
                ),
            },
        ]
        result = chat_json(messages, model=model, max_tokens=8192)
        fixed = result.get("fixed_file_content", source)
        ok, problems = validate_python(rel_path, fixed)

    if not fixed.endswith("\n"):
        fixed += "\n"

    return FilePatch(
        path=rel_path,
        original=source,
        fixed=fixed,
        diff=_make_diff(rel_path, source, fixed),
        findings=result.get("findings", []),
        risk_notes=result.get("risk_notes", ""),
        additional_changes=result.get("additional_changes", []),
        valid=ok,
        problems=problems,
        repair_attempts=attempts,
    )

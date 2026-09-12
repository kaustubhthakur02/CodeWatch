"""Re-scan a patched file to prove the vulnerability is actually gone.

The model reports whether it fixed something, but it grades its own homework. It has
claimed "fixed" after validating one of two injectable parameters. pyflakes catches
broken code, not a half-done fix - only running the scanner again does that.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .scanner import Finding, parse_findings, run_semgrep
from .triage import categorize


@dataclass
class Verification:
    resolved: list[Finding]
    remaining: list[Finding]

    @property
    def clean(self) -> bool:
        return not self.remaining

    def summary(self) -> str:
        if self.clean:
            return f"re-scan clean, {len(self.resolved)} finding(s) resolved"
        return f"{len(self.remaining)} finding(s) still present after the patch"


def verify_patch(
    rel_path: str,
    patched_content: str,
    before: list[Finding],
    configs: list[str] | None = None,
) -> Verification:
    """Scan the patched file in isolation and compare against the pre-patch findings."""
    with tempfile.TemporaryDirectory(prefix="codewatch-verify-") as tmp:
        target = Path(tmp) / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(patched_content, encoding="utf-8")

        after = [f for f in parse_findings(run_semgrep(tmp, configs), tmp) if categorize(f)]

    before_fixable = [f for f in before if categorize(f)]
    remaining_rules = {f.rule_id for f in after}

    return Verification(
        resolved=[f for f in before_fixable if f.rule_id not in remaining_rules],
        remaining=after,
    )


def copy_repo(repo_path: str | Path) -> Path:
    """Full-repo copy, for callers that need cross-file analysis rather than one file."""
    dest = Path(tempfile.mkdtemp(prefix="codewatch-repo-"))
    shutil.copytree(repo_path, dest / "repo", dirs_exist_ok=True)
    return dest / "repo"

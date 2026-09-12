"""Run Semgrep against a repo and normalize findings into Finding objects."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIGS = ["auto"]
CONTEXT_LINES = 6


@dataclass
class Finding:
    rule_id: str
    path: str
    start_line: int
    end_line: int
    message: str
    severity: str
    impact: str
    confidence: str
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    vulnerability_class: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    snippet: str = ""
    fingerprint: str = ""

    @property
    def short_rule(self) -> str:
        return self.rule_id.split(".")[-1]

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "short_rule": self.short_rule,
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "message": self.message,
            "severity": self.severity,
            "impact": self.impact,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "vulnerability_class": self.vulnerability_class,
            "references": self.references,
            "snippet": self.snippet,
        }


def run_semgrep(repo_path: str | Path, configs: list[str] | None = None) -> dict:
    repo_path = Path(repo_path).resolve()
    configs = configs or DEFAULT_CONFIGS

    cmd = ["semgrep", "--json", "--quiet", "--disable-version-check"]
    for cfg in configs:
        cmd += ["--config", cfg]

    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tmp:
        out_path = tmp.name
    cmd += ["--output", out_path, str(repo_path)]

    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600)
    with open(out_path, encoding="utf-8") as fh:
        return json.load(fh)


def _read_snippet(repo_path: Path, rel_path: str, start: int, end: int) -> str:
    """Semgrep OSS returns 'requires login' for the lines field, so read from disk."""
    file_path = repo_path / rel_path
    if not file_path.exists():
        return ""
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    lo = max(0, start - 1 - CONTEXT_LINES)
    hi = min(len(lines), end + CONTEXT_LINES)
    return "\n".join(f"{i + 1:>4} | {lines[i]}" for i in range(lo, hi))


def parse_findings(raw: dict, repo_path: str | Path) -> list[Finding]:
    repo_path = Path(repo_path).resolve()
    findings = []
    for r in raw.get("results", []):
        meta = r["extra"].get("metadata", {})
        rel_path = r["path"].replace("\\", "/")
        start = r["start"]["line"]
        end = r["end"]["line"]
        fp = hashlib.sha256(f"{r['check_id']}|{rel_path}|{start}".encode()).hexdigest()[:12]
        findings.append(
            Finding(
                rule_id=r["check_id"],
                path=rel_path,
                start_line=start,
                end_line=end,
                message=r["extra"].get("message", ""),
                severity=r["extra"].get("severity", "INFO"),
                impact=meta.get("impact", "UNKNOWN"),
                confidence=meta.get("confidence", "UNKNOWN"),
                cwe=meta.get("cwe", []),
                owasp=meta.get("owasp", []),
                vulnerability_class=meta.get("vulnerability_class", []),
                references=meta.get("references", []),
                snippet=_read_snippet(repo_path, rel_path, start, end),
                fingerprint=fp,
            )
        )
    return findings


def scan(repo_path: str | Path, configs: list[str] | None = None) -> list[Finding]:
    return parse_findings(run_semgrep(repo_path, configs), repo_path)

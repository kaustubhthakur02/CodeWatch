"""Parse declared dependencies out of a repository."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Only pinned requirements can be checked against an advisory range with confidence.
PINNED = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([0-9][^\s;#]*)")


@dataclass
class Dependency:
    name: str
    version: str
    source_file: str
    line: int

    def __str__(self) -> str:
        return f"{self.name}=={self.version}"


def parse_requirements(path: Path, rel_to: Path) -> list[Dependency]:
    deps = []
    for i, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        match = PINNED.match(line)
        if match:
            deps.append(
                Dependency(
                    name=match.group(1),
                    version=match.group(2),
                    source_file=str(path.relative_to(rel_to)).replace("\\", "/"),
                    line=i,
                )
            )
    return deps


def collect(repo_path: str | Path) -> list[Dependency]:
    repo_path = Path(repo_path).resolve()
    deps: list[Dependency] = []
    for req in sorted(repo_path.rglob("requirements*.txt")):
        deps += parse_requirements(req, repo_path)
    return deps

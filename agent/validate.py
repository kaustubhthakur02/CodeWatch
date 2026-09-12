"""Static checks a generated patch must pass before CodeWatch will propose it.

ast.parse only proves the file parses. It does NOT catch the most common LLM patch
failure: using a module (re, subprocess, os) without adding its import. pyflakes does.
"""

from __future__ import annotations

import ast
import io

from pyflakes.api import check
from pyflakes.reporter import Reporter

# pyflakes messages that mean the patch is broken, not merely untidy.
BLOCKING_SUBSTRINGS = (
    "undefined name",
    "used prior to global declaration",
    "redefinition of unused",
)


def validate_python(rel_path: str, content: str) -> tuple[bool, list[str]]:
    """Return (ok, problems). ok is False only for blocking problems."""
    if not rel_path.endswith(".py"):
        return True, []

    try:
        ast.parse(content)
    except SyntaxError as exc:
        return False, [f"SyntaxError: line {exc.lineno}: {exc.msg}"]

    out, err = io.StringIO(), io.StringIO()
    check(content, rel_path, Reporter(out, err))

    problems = [line.strip() for line in out.getvalue().splitlines() if line.strip()]
    blocking = [p for p in problems if any(s in p.lower() for s in BLOCKING_SUBSTRINGS)]
    return not blocking, problems


def blocking_problems(problems: list[str]) -> list[str]:
    return [p for p in problems if any(s in p.lower() for s in BLOCKING_SUBSTRINGS)]

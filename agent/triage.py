"""Map Semgrep findings onto the vulnerability categories CodeWatch can fix, and rank them."""

from __future__ import annotations

from .scanner import Finding

# CodeWatch only proposes fixes for categories it can patch reliably.
# Everything else is reported but left for a human.
CATEGORIES = {
    "sql_injection": {
        "label": "SQL Injection",
        "cwe": "CWE-89",
        "guidance": (
            "Replace string concatenation/formatting in SQL with parameterized queries "
            "(cursor.execute(sql, [params])) or the Django ORM.\n"
            "    The placeholder is exactly %s. Never write %%s - with params supplied, "
            "%%s is an escaped literal percent, not a placeholder, and the query breaks.\n"
            "    A LIKE wildcard goes in the PARAMETER, not the SQL:\n"
            "        cursor.execute('... WHERE name LIKE %s', ['%' + q + '%'])\n"
            "    Table and column names CANNOT be parameterized. When user input selects an "
            "identifier, validate it against an explicit allowlist and reject anything else - "
            "do not skip the finding:\n"
            "        ALLOWED_TABLES = {'core_userprofile', 'core_feedback'}\n"
            "        if table not in ALLOWED_TABLES:\n"
            "            return HttpResponse('invalid table', status=400)"
        ),
    },
    "command_injection": {
        "label": "Command Injection",
        "cwe": "CWE-78",
        "guidance": (
            "This IS fixable — do not skip it. Replace os.system/os.popen/shell=True with "
            "subprocess.run(arg_list, shell=False, capture_output=True, text=True, timeout=...) "
            "and validate the user-controlled value before use.\n"
            "    Example before: os.popen('ping -n 1 ' + host).read()\n"
            "    Example after:\n"
            "        if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host):\n"
            "            return HttpResponse('invalid host', status=400)\n"
            "        out = subprocess.run(['ping', '-n', '1', host], shell=False,\n"
            "                             capture_output=True, text=True, timeout=5).stdout\n"
            "    Add any imports you need (re, subprocess) and drop imports that become unused."
        ),
    },
    "hardcoded_secret": {
        "label": "Hardcoded Secret",
        "cwe": "CWE-798",
        "guidance": (
            "Move the secret out of source control into an environment variable read via "
            "os.environ, and keep a placeholder in .env.example. Do not invent a new "
            "literal value."
        ),
    },
}

_SEVERITY_RANK = {"ERROR": 0, "WARNING": 1, "INFO": 2}
_IMPACT_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}


def categorize(finding: Finding) -> str | None:
    haystack = " ".join(
        [finding.rule_id, finding.message, *finding.cwe, *finding.vulnerability_class]
    ).lower()

    if "cwe-89" in haystack or "sql injection" in haystack or "sql" in finding.rule_id.lower():
        return "sql_injection"
    if "cwe-78" in haystack or "command injection" in haystack or "system-call" in haystack:
        return "command_injection"
    if "cwe-798" in haystack or "hardcoded" in haystack or "api key" in haystack or "secret" in haystack:
        return "hardcoded_secret"
    return None


# Multiple Semgrep rules routinely flag the same statement (e.g. tainted-sql-string,
# formatted-sql-query and sqlalchemy-execute-raw-query all fire on one cursor.execute).
# Reporting each separately makes the PR look padded, so collapse near-duplicates.
DEDUPE_LINE_WINDOW = 4


def deduplicate(fixable: list[tuple[Finding, str]]) -> list[tuple[Finding, str]]:
    kept: list[tuple[Finding, str]] = []
    for finding, category in fixable:
        if any(
            k.path == finding.path
            and c == category
            and abs(k.start_line - finding.start_line) <= DEDUPE_LINE_WINDOW
            for k, c in kept
        ):
            continue
        kept.append((finding, category))
    return kept


def prioritize(findings: list[Finding], dedupe: bool = True) -> list[tuple[Finding, str]]:
    """Return (finding, category) for fixable findings, most severe first."""
    fixable = [(f, c) for f in findings if (c := categorize(f)) is not None]
    fixable.sort(
        key=lambda fc: (
            _SEVERITY_RANK.get(fc[0].severity, 3),
            _IMPACT_RANK.get(fc[0].impact, 3),
            fc[0].path,
            fc[0].start_line,
        )
    )
    return deduplicate(fixable) if dedupe else fixable


def unfixable(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if categorize(f) is None]


def group_by_file(fixable: list[tuple[Finding, str]]) -> dict[str, list[tuple[Finding, str]]]:
    """One LLM call and one patch per file, not per finding."""
    grouped: dict[str, list[tuple[Finding, str]]] = {}
    for finding, category in fixable:
        grouped.setdefault(finding.path, []).append((finding, category))
    return grouped

"""Check pinned dependencies for published advisories.

Semgrep finds bugs in code you wrote. This finds bugs in code you imported — which
requires information published after the model's training cutoff, so Exa does the
retrieval and the model only interprets what Exa returns.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import exa
from .deps import Dependency
from .llm import chat_json

SYSTEM_PROMPT = """You assess whether a specific version of a software package has known security advisories.

You will be given a package name, the exact pinned version in use, and search results from security advisory sources.

Rules:
- Judge ONLY the pinned version given. An advisory affecting other versions does not affect this one.
- Base your answer strictly on the supplied search results. Do not use prior knowledge about versions.
- If the results do not clearly establish that this version is affected, set "affected" to false and say the evidence is inconclusive.
- Never guess a CVE id. Only list ids that appear verbatim in the search results.

Return STRICT JSON:
{
  "affected": true|false,
  "confidence": "high|medium|low",
  "severity": "critical|high|medium|low|none",
  "cve_ids": ["CVE-...", ...],
  "summary": "<2-3 plain sentences a developer can act on, or why the evidence is inconclusive>",
  "recommended_version": "<version to upgrade to, or empty string if unknown>"
}"""


@dataclass
class DependencyAdvisory:
    dependency: Dependency
    affected: bool
    confidence: str
    severity: str
    cve_ids: list[str]
    summary: str
    recommended_version: str
    sources: list[str] = field(default_factory=list)


def _format_results(results: list[dict]) -> str:
    chunks = []
    for r in results:
        chunks.append(
            f"SOURCE: {r.get('url', '')}\n"
            f"TITLE: {r.get('title', '')}\n"
            f"PUBLISHED: {r.get('publishedDate', 'unknown')}\n"
            f"EXCERPT: {(r.get('text') or '')[:1200]}"
        )
    return "\n\n---\n\n".join(chunks)


def check_dependency(dep: Dependency, num_results: int = 5, model: str | None = None) -> DependencyAdvisory:
    results = exa.search_advisories(dep.name, dep.version, num_results=num_results)

    if not results:
        return DependencyAdvisory(
            dependency=dep,
            affected=False,
            confidence="low",
            severity="none",
            cve_ids=[],
            summary="No advisory sources were returned for this package version.",
            recommended_version="",
            sources=[],
        )

    verdict = chat_json(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"PACKAGE: {dep.name}\n"
                    f"PINNED VERSION: {dep.version}\n"
                    f"DECLARED IN: {dep.source_file}:{dep.line}\n\n"
                    f"SEARCH RESULTS:\n\n{_format_results(results)}"
                ),
            },
        ],
        model=model,
        max_tokens=1024,
    )

    return DependencyAdvisory(
        dependency=dep,
        affected=bool(verdict.get("affected")),
        confidence=verdict.get("confidence", "low"),
        severity=verdict.get("severity", "none"),
        cve_ids=verdict.get("cve_ids", []),
        summary=verdict.get("summary", ""),
        recommended_version=verdict.get("recommended_version", ""),
        sources=[r.get("url", "") for r in results if r.get("url")],
    )


def check_all(deps: list[Dependency], model: str | None = None) -> list[DependencyAdvisory]:
    return [check_dependency(d, model=model) for d in deps]

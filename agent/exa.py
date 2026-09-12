"""Exa search client — used to find advisories the model cannot know from training."""

from __future__ import annotations

import os

import requests

EXA_SEARCH_URL = "https://api.exa.ai/search"

# Advisory sources we trust more than a random blog post.
TRUSTED_DOMAINS = [
    "nvd.nist.gov",
    "github.com",
    "cve.mitre.org",
    "osv.dev",
    "snyk.io",
    "security.snyk.io",
    "djangoproject.com",
    "pypa.io",
]


class ExaError(RuntimeError):
    pass


def search(
    query: str,
    num_results: int = 5,
    include_domains: list[str] | None = None,
    include_text: bool = True,
    api_key: str | None = None,
) -> list[dict]:
    api_key = api_key or os.environ.get("EXA_API_KEY")
    if not api_key:
        raise ExaError("EXA_API_KEY is not set")

    payload: dict = {"query": query, "numResults": num_results, "type": "auto"}
    if include_domains:
        payload["includeDomains"] = include_domains
    if include_text:
        payload["contents"] = {"text": {"maxCharacters": 1200}}

    resp = requests.post(
        EXA_SEARCH_URL,
        headers={"x-api-key": api_key, "Content-Type": "application/json"},
        json=payload,
        timeout=60,
    )
    if resp.status_code != 200:
        raise ExaError(f"Exa {resp.status_code}: {resp.text[:400]}")

    return resp.json().get("results", [])


def _series(version: str) -> str:
    parts = version.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else version


def search_advisories(package: str, version: str, num_results: int = 6) -> list[dict]:
    """Retrieve advisory pages relevant to a pinned version.

    Advisories are published against the release that FIXED an issue, not the one that
    shipped it, so searching the version string alone retrieves almost nothing useful.
    Querying the version series and the surrounding security releases works far better.
    """
    queries = [
        f"{package} {version} vulnerability CVE affected versions",
        f"{package} security release CVE advisory affects {_series(version)} before",
    ]

    merged: dict[str, dict] = {}
    per_query = max(2, num_results // len(queries) + 1)
    for query in queries:
        try:
            for result in search(query, num_results=per_query, include_domains=TRUSTED_DOMAINS):
                url = result.get("url", "")
                if url and url not in merged:
                    merged[url] = result
        except ExaError:
            continue

    return list(merged.values())[:num_results]

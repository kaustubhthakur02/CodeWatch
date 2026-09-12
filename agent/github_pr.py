"""Open a pull request containing CodeWatch's proposed fixes.

CodeWatch never pushes to the default branch and never merges. It creates a branch,
commits the validated patches, and opens a PR for human review.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from github import Github, GithubException

from .fixer import FilePatch


@dataclass
class PullRequestResult:
    url: str
    number: int
    branch: str


class GitHubError(RuntimeError):
    pass


def normalize_repo(value: str) -> str:
    """Accept either 'owner/repo' or a full GitHub URL."""
    value = value.strip().removesuffix(".git").rstrip("/")
    if "github.com" in value:
        value = value.split("github.com", 1)[1].lstrip(":/")
    parts = [p for p in value.split("/") if p]
    if len(parts) < 2:
        raise GitHubError(f"could not read 'owner/repo' from {value!r}")
    return "/".join(parts[:2])


def open_fix_pr(
    patches: list[FilePatch],
    title: str,
    body: str,
    repo_full_name: str | None = None,
    token: str | None = None,
    base_branch: str | None = None,
    branch_prefix: str = "codewatch/fix",
    path_prefix: str = "",
) -> PullRequestResult:
    token = token or os.environ.get("GITHUB_TOKEN")
    repo_full_name = repo_full_name or os.environ.get("GITHUB_REPO")
    if not token:
        raise GitHubError("GITHUB_TOKEN is not set")
    if not repo_full_name:
        raise GitHubError("GITHUB_REPO is not set (expected 'owner/repo')")
    repo_full_name = normalize_repo(repo_full_name)

    proposable = [p for p in patches if p.proposable]
    if not proposable:
        raise GitHubError("no validated patches to propose")

    repo = Github(token).get_repo(repo_full_name)
    base = base_branch or repo.default_branch
    base_sha = repo.get_branch(base).commit.sha

    branch = f"{branch_prefix}-{int(time.time())}"
    try:
        repo.create_git_ref(ref=f"refs/heads/{branch}", sha=base_sha)
    except GithubException as exc:
        raise GitHubError(f"could not create branch {branch}: {exc.data}") from exc

    prefix = path_prefix.strip("/")
    for patch in proposable:
        repo_path = f"{prefix}/{patch.path}" if prefix else patch.path
        contents = repo.get_contents(repo_path, ref=branch)
        repo.update_file(
            path=repo_path,
            message=f"fix(security): {patch.path}",
            content=patch.fixed,
            sha=contents.sha,
            branch=branch,
        )

    pr = repo.create_pull(title=title, body=body, head=branch, base=base)
    return PullRequestResult(url=pr.html_url, number=pr.number, branch=branch)


def comment_on_pr(pr_number: int, body: str, repo_full_name: str | None = None, token: str | None = None) -> str:
    token = token or os.environ.get("GITHUB_TOKEN")
    repo_full_name = repo_full_name or os.environ.get("GITHUB_REPO")
    repo = Github(token).get_repo(repo_full_name)
    comment = repo.get_issue(pr_number).create_comment(body)
    return comment.html_url

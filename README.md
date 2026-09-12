# 🛡️ CodeWatch

**A security teammate that lives in your pull requests and your inbox — not in another chat window.**

Most security tooling makes you go to it: run a scanner, open a dashboard, read a report full of
rule IDs, then work out the fix yourself. So it gets skipped.

CodeWatch inverts that. When you push code, it scans, writes the fix, opens a pull request with the
change already made and explained in plain English, and emails you to say it's waiting. You review it
like any teammate's PR.

---

## What it does

1. **Scans** pushed code with [Semgrep](https://semgrep.dev) (SAST — no server, no deployed app needed)
2. **Triages** findings down to the categories it can fix reliably, and collapses the duplicate rules
   that fire on the same line
3. **Writes the fix** with an LLM via [OpenRouter](https://openrouter.ai), plus a plain-English
   explanation of what an attacker could actually do
4. **Validates its own patch** with pyflakes before anyone sees it — and repairs it if it fails
5. **Checks your dependencies** for published CVEs using [Exa](https://exa.ai) live search
6. **Opens a pull request** — never merges, never pushes to `main`
7. **Emails the developer who pushed the code**, CC'ing the security address

## What it fixes

| Category | CWE |
|---|---|
| SQL Injection | CWE-89 |
| Command Injection | CWE-78 |
| Hardcoded Secrets | CWE-798 |

Findings outside these categories are **reported but never modified**. An agent that edits code it
doesn't fully understand is worse than one that stays in its lane.

---

## Two design decisions worth explaining

**It proposes, it never applies.** CodeWatch opens a PR and stops. Auto-merging security patches
means a bad patch ships unreviewed, and "the AI rewrote main" is not a demo anyone survives. A human
approves every change.

**It checks its own work before you see it.** Early on, the model produced a genuinely good fix that
used `re` and `subprocess` — without adding the imports. It parsed cleanly and would have crashed at
runtime. `ast.parse` can't catch that, so [`agent/validate.py`](agent/validate.py) runs pyflakes to
catch undefined names, and failures are fed back to the model to repair. No patch reaches a pull
request without passing.

**Why Exa is doing real work here.** The LLM already knows how to fix SQL injection — that's textbook.
What it *cannot* know is which CVEs were published after its training cutoff. Exa retrieves live
advisories, and the model only interprets what Exa returns; it is explicitly forbidden from citing a
CVE id that isn't in the search results. One catch worth noting: advisories are published against the
version that *fixed* an issue, not the one that shipped it, so searching `Django 5.0.6` finds nothing
useful. Searching the version series and its security releases is what made this work.

---

## Architecture

```
Developer pushes code
        │
        ▼
GitHub Action
        │
        ▼
Semgrep scan ──────────► raw findings
        │
        ▼
Triage: categorize, rank, deduplicate
        │
        ├───────────────────────────────┐
        ▼                               ▼
LLM writes fix + explanation      Exa searches live advisories
        │                               │
        ▼                               │
pyflakes validation gate                │
  ├─ fails → model repairs itself       │
  └─ passes ─────────────┬──────────────┘
                         ▼
              Pull request opened (never merged)
                         │
                         ▼
              Email to the author + security CC
```

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env    # then fill in your keys
```

| Variable | Purpose |
|---|---|
| `OPENROUTER_API_KEY` | Fix generation and explanations |
| `EXA_API_KEY` | Live CVE/advisory search |
| `GITHUB_TOKEN` | Opening the pull request (needs `repo` scope) |
| `GITHUB_REPO` | `owner/repo` target |
| `SMTP_USER` / `SMTP_PASSWORD` | Gmail address + [App Password](https://myaccount.google.com/apppasswords) |
| `SECURITY_EMAIL` | Always CC'd; also the fallback when the author's address is private |

## Usage

```bash
# Scan and triage only — no LLM calls, no cost
python run_agent.py sample-vulnerable-app --no-fix

# Full run: fixes, dependency CVEs, preview the PR body and email locally
python run_agent.py sample-vulnerable-app --deps \
  --pr-body pr_body.md --email-preview email_preview.html

# The real thing: open the PR and email the author
python run_agent.py sample-vulnerable-app --deps --open-pr --email \
  --path-prefix sample-vulnerable-app \
  --author-email dev@example.com --author-name Dev
```

## Try it

[`sample-vulnerable-app/`](sample-vulnerable-app/) is a small Django app with deliberately planted
vulnerabilities — SQL injection, command injection, hardcoded credentials, and a Django version with
real published CVEs. Point CodeWatch at it to see the full flow.

> ⚠️ That app is intentionally insecure. Never deploy it.

## Built with

OpenRouter · Exa · Semgrep · GitHub Actions · Python

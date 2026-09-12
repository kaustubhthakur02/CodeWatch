"""Email the developer whose push introduced the findings.

The PR is where the fix lives; the email is how the author finds out it exists without
having to watch a repo they may not have notifications on.
"""

from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage

from .fixer import FilePatch
from .scanner import Finding

SEVERITY_COLOR = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#1d4ed8",
}


class EmailError(RuntimeError):
    pass


def _badge(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity, "#4b5563")
    return (
        f'<span style="background:{color};color:#fff;border-radius:4px;'
        f'padding:2px 8px;font-size:12px;font-weight:600;text-transform:uppercase;">'
        f"{severity or 'info'}</span>"
    )


def build_html(
    patches: list[FilePatch],
    skipped: list[Finding],
    advisories: list,
    pr_url: str,
    repo_name: str,
    author_name: str = "",
) -> str:
    fixed = [(p, f) for p in patches for f in p.findings if f.get("fixed")]
    unfixed = [(p, f) for p in patches for f in p.findings if not f.get("fixed")]
    affected_deps = [a for a in (advisories or []) if a.affected]

    greeting = f"Hi {author_name}," if author_name else "Hi,"

    rows = []
    for patch, f in fixed:
        rows.append(
            f"""
        <tr>
          <td style="padding:14px 0;border-bottom:1px solid #e5e7eb;">
            <div style="margin-bottom:6px;">{_badge(f.get('severity',''))}
              <strong style="margin-left:8px;">{f.get('title','Finding')}</strong>
            </div>
            <div style="color:#6b7280;font-size:13px;font-family:monospace;margin-bottom:8px;">{patch.path}</div>
            <div style="color:#374151;font-size:14px;line-height:1.55;margin-bottom:6px;">{f.get('explanation','')}</div>
            <div style="color:#065f46;font-size:14px;line-height:1.55;"><strong>Proposed fix:</strong> {f.get('fix_summary','')}</div>
          </td>
        </tr>"""
        )

    dep_rows = []
    for a in affected_deps:
        cves = ", ".join(a.cve_ids) or "no published id"
        upgrade = f"{a.dependency.name}=={a.recommended_version}" if a.recommended_version else "a patched release"
        dep_rows.append(
            f"""
        <tr>
          <td style="padding:14px 0;border-bottom:1px solid #e5e7eb;">
            <div style="margin-bottom:6px;">{_badge(a.severity)}
              <strong style="margin-left:8px;">{a.dependency.name} {a.dependency.version}</strong>
            </div>
            <div style="color:#374151;font-size:14px;line-height:1.55;margin-bottom:6px;">{a.summary}</div>
            <div style="color:#6b7280;font-size:13px;">Advisories: {cves}<br>Upgrade to: <code>{upgrade}</code></div>
          </td>
        </tr>"""
        )

    unfixed_html = ""
    if unfixed:
        items = "".join(
            f"<li style='margin-bottom:4px;'><code>{p.path}</code> — {f.get('title','')}</li>" for p, f in unfixed
        )
        unfixed_html = f"""
      <div style="background:#fef3c7;border-left:3px solid #d97706;padding:12px 16px;margin:20px 0;border-radius:4px;">
        <strong style="font-size:14px;">Needs a human</strong>
        <ul style="margin:8px 0 0 18px;padding:0;color:#374151;font-size:14px;">{items}</ul>
      </div>"""

    cta = (
        f"""
      <div style="margin:28px 0;">
        <a href="{pr_url}" style="background:#1f2937;color:#fff;text-decoration:none;padding:12px 22px;
           border-radius:6px;font-weight:600;font-size:15px;display:inline-block;">Review the pull request →</a>
      </div>"""
        if pr_url
        else ""
    )

    dep_section = (
        f"""
      <h3 style="font-size:15px;margin:28px 0 4px;">Vulnerable dependencies ({len(affected_deps)})</h3>
      <p style="color:#6b7280;font-size:13px;margin:0 0 8px;">
        Found by searching live advisory sources. CodeWatch does not bump versions automatically.</p>
      <table style="width:100%;border-collapse:collapse;">{''.join(dep_rows)}</table>"""
        if dep_rows
        else ""
    )

    return f"""<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,Segoe UI,Roboto,sans-serif;">
  <div style="max-width:640px;margin:0 auto;background:#fff;padding:32px;">
    <div style="font-size:20px;font-weight:700;margin-bottom:4px;">🛡️ CodeWatch found security issues in your push</div>
    <div style="color:#6b7280;font-size:14px;margin-bottom:24px;">{repo_name}</div>

    <p style="color:#374151;font-size:15px;line-height:1.6;">
      {greeting} I scanned the code you just pushed and found
      <strong>{len(fixed)} issue(s)</strong> I can fix for you{', plus ' + str(len(affected_deps)) + ' vulnerable dependency(ies)' if affected_deps else ''}.
      I've opened a pull request with the fixes written — nothing has been merged, so please review it.
    </p>
    {cta}

    <h3 style="font-size:15px;margin:28px 0 4px;">Fixes proposed ({len(fixed)})</h3>
    <table style="width:100%;border-collapse:collapse;">{''.join(rows)}</table>
    {unfixed_html}
    {dep_section}

    <p style="color:#9ca3af;font-size:12px;margin-top:32px;border-top:1px solid #e5e7eb;padding-top:16px;">
      {len(skipped)} additional finding(s) were outside CodeWatch's fix scope and were reported in the PR without changes.
      Every patch is syntax- and import-checked before it reaches a pull request.
    </p>
  </div>
</body></html>"""


def send_email(
    subject: str,
    html: str,
    to_addrs: list[str],
    cc_addrs: list[str] | None = None,
    from_addr: str | None = None,
) -> list[str]:
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "465"))

    if not user or not password:
        raise EmailError("SMTP_USER and SMTP_PASSWORD must be set")

    recipients = [a for a in dict.fromkeys([*to_addrs, *(cc_addrs or [])]) if a]
    if not recipients:
        raise EmailError("no recipients resolved")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr or f"CodeWatch <{user}>"
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    msg.set_content("CodeWatch found security issues in your push. View this email in HTML to see the report.")
    msg.add_alternative(html, subtype="html")

    with smtplib.SMTP_SSL(host, port, timeout=60) as server:
        server.login(user, password)
        server.send_message(msg, to_addrs=recipients)

    return recipients


def resolve_recipients(author_email: str | None) -> tuple[list[str], list[str]]:
    """Author gets the alert; the security address is always copied."""
    security = os.environ.get("SECURITY_EMAIL", "")
    fallback = os.environ.get("DEFAULT_RECIPIENT", security)

    # GitHub hides real addresses behind noreply when a user enables email privacy.
    usable = author_email and "noreply" not in author_email.lower()
    to = [author_email] if usable else ([fallback] if fallback else [])
    cc = [security] if security and security not in to else []
    return to, cc

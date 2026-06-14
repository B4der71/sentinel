"""
Security headers and clickjacking detection plugin.

Checks for missing security-related HTTP response headers and
identifies pages that can be embedded in frames due to missing
frame protection mechanisms.
"""
from __future__ import annotations

from sentinel.core.context import ScanContext
from sentinel.models import Confidence, Evidence, Finding, Form, Severity
from sentinel.plugins.base import Plugin

_CHECKS = {
    "content-security-policy": (Severity.MEDIUM, "CWE-693",
        "No Content-Security-Policy; reduces XSS/dataexfil mitigation.",
        "Define a restrictive CSP (e.g. default-src 'self')."),
    "strict-transport-security": (Severity.MEDIUM, "CWE-319",
        "No HSTS; connections may be downgraded to HTTP.",
        "Send Strict-Transport-Security with a long max-age over HTTPS."),
    "x-content-type-options": (Severity.LOW, "CWE-693",
        "Missing X-Content-Type-Options: nosniff (MIME sniffing).",
        "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": (Severity.LOW, "CWE-200",
        "No Referrer-Policy; referrer may leak to third parties.",
        "Set Referrer-Policy: strict-origin-when-cross-origin."),
}


class HeadersPlugin(Plugin):
    id = "headers"
    name = "Security Headers & Clickjacking"
    default_severity = Severity.LOW

    def __init__(self) -> None:
        super().__init__()
        self._seen: set[str] = set()

    async def run(self, ctx: ScanContext, form: Form) -> None:
        # Security headers are evaluated once per host.
        from urllib.parse import urlparse
        host = urlparse(form.action).netloc
        if host in self._seen:
            return
        self._seen.add(host)
        origin = form.action.split("?")[0]

        resp = await ctx.http.get(origin)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        for name, (sev, cwe, desc, fix) in _CHECKS.items():
            if name not in headers:
                ctx.report(Finding(
                    name=f"Missing Security Header: {name}",
                    plugin=self.id, severity=sev, confidence=Confidence.CONFIRMED,
                    cwe=cwe, url=origin, description=desc, remediation=fix,
                    evidence=[Evidence(description="Header absent from response.")],
                ))

        # Check for frame protection.
        xfo = headers.get("x-frame-options", "").lower()
        csp = headers.get("content-security-policy", "").lower()
        if "deny" not in xfo and "sameorigin" not in xfo and "frame-ancestors" not in csp:
            ctx.report(Finding(
                name="Clickjacking (no frame protection)",
                plugin=self.id, severity=Severity.MEDIUM,
                confidence=Confidence.FIRM, cwe="CWE-1021", cvss=4.3,
                url=origin,
                description="Page can be framed by any origin; vulnerable to "
                            "UI-redress / clickjacking.",
                remediation="Set X-Frame-Options: DENY or a CSP frame-ancestors "
                            "directive.",
            ))

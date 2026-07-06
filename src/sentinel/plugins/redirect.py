"""
Open Redirect detection plugin.

Tests redirect-related parameters by supplying an external URL and
checking whether the application redirects users to an attacker-
controlled destination.
"""
from __future__ import annotations

from urllib.parse import urlparse

from sentinel.core.context import ScanContext
from sentinel.models import Confidence, Evidence, Finding, Form, Severity
from sentinel.plugins.base import Plugin

_EVIL_HOST = "sentinel-redirect-probe.example"
_EVIL_URL = f"https://{_EVIL_HOST}/"
_HINTS = ("url", "next", "return", "redirect", "dest", "continue", "to", "goto")


class OpenRedirectPlugin(Plugin):

    id = "redirect"

    name = "Open Redirect"

    description = (
        "Detect unvalidated redirects to attacker-controlled destinations."
    )

    author = "Bader Alwashah (B4der71)"

    category = "Validation"

    tags = (
        "OWASP A01:2021",
        "CWE-601",
        "Open Redirect",
        "Unvalidated Redirect",
        "Location Header",
    )

    default_severity = Severity.MEDIUM

    aggressive = False

    requires_browser = False
    requires_authentication = False

    async def run(self, ctx: ScanContext, form: Form) -> None:
        base = form.baseline_data()
        for param in form.fuzzable_params:
            if not any(h in param.lower() for h in _HINTS):
                continue
            data = dict(base)
            data[param] = _EVIL_URL
            if form.method == "POST":
                resp = await ctx.http.post(form.action, data=data, use_cache=False)
            else:
                resp = await ctx.http.get(form.action, params=data, use_cache=False)

            # Inspect redirect target without following redirects.
            location = resp.headers.get("location", "")
            if location and urlparse(location).netloc == _EVIL_HOST:
                ctx.report(Finding(
                    name="Open Redirect", plugin=self.id, severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED, cwe="CWE-601", cvss=6.1,
                    url=form.action, parameter=param, method=form.method,
                    payload=_EVIL_URL,
                    description=f"Parameter '{param}' controls the redirect target; "
                                "an attacker can redirect users to arbitrary sites "
                                "(phishing, token theft).",
                    remediation="Redirect only to a server-side allow-list of paths "
                                "or validate the host against known-good origins.",
                    reproduction=[f"Set '{param}' to {_EVIL_URL}",
                                  f"Observe Location header pointing to {_EVIL_HOST}"],
                    evidence=[Evidence(description="Redirect followed to attacker host.",
                                       request=f"{param}={_EVIL_URL}",
                                       response_excerpt=f"Location: {location}")],
                ))

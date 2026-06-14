"""
Cross-Origin Resource Sharing (CORS) misconfiguration detection plugin.

Checks whether a target improperly trusts arbitrary origins or
allows credentialed cross-origin requests that may expose
authenticated data.
"""
from __future__ import annotations

from sentinel.core.context import ScanContext
from sentinel.models import Confidence, Evidence, Finding, Form, Severity
from sentinel.plugins.base import Plugin

_EVIL = "https://sentinel-cors-probe.example"


class CorsPlugin(Plugin):
    id = "cors"
    name = "CORS Misconfiguration"
    default_severity = Severity.MEDIUM

    def __init__(self) -> None:
        super().__init__()
        self._seen: set[str] = set()

    async def run(self, ctx: ScanContext, form: Form) -> None:
        from urllib.parse import urlparse
        host = urlparse(form.action).netloc
        if host in self._seen:
            return
        self._seen.add(host)
        origin_url = form.action.split("?")[0]

        resp = await ctx.http.get(origin_url, headers={"Origin": _EVIL})
        h = {k.lower(): v for k, v in resp.headers.items()}
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower()

        # Evaluate Access-Control-Allow-* policy.
        reflected = acao == _EVIL
        wildcard = acao == "*"

        if reflected and acac == "true":
            self._emit(ctx, origin_url, Severity.HIGH, 7.5,
                       "Server reflects arbitrary Origin and allows credentials, "
                       "permitting cross-origin theft of authenticated data.",
                       acao, acac)
        elif reflected:
            self._emit(ctx, origin_url, Severity.MEDIUM, 5.0,
                       "Server reflects arbitrary Origin in "
                       "Access-Control-Allow-Origin.", acao, acac)
        elif wildcard and acac == "true":
            self._emit(ctx, origin_url, Severity.MEDIUM, 5.0,
                       "Wildcard ACAO combined with credentials.", acao, acac)

    def _emit(self, ctx: ScanContext, url: str, sev: Severity, cvss: float,
              desc: str, acao: str, acac: str) -> None:
        ctx.report(Finding(
            name="CORS Misconfiguration", plugin=self.id, severity=sev,
            confidence=Confidence.FIRM, cwe="CWE-942", cvss=cvss, url=url,
            description=desc,
            remediation="Validate Origin against a strict allow-list; never "
                        "reflect arbitrary origins while allowing credentials.",
            evidence=[Evidence(
                description="Response to forged Origin.",
                request=f"Origin: {_EVIL}",
                response_excerpt=f"Access-Control-Allow-Origin: {acao}; "
                                 f"Allow-Credentials: {acac}",
            )],
        ))

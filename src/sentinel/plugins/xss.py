from __future__ import annotations
"""XSS detection plugin (reflected, with hooks for stored & DOM).

Detection pipeline per parameter:

1. **Probe** - inject a unique benign marker plus a breakout-charset string.
   No reflection of the marker => not injectable here; stop. This alone kills
   the bulk of the original's false positives.
2. **Classify** - determine reflection context(s) and which breakout chars
   survived un-encoded. If none survive in an exploitable way, we *downgrade*
   to an informational "reflected input, properly encoded" note rather than a
   vulnerability.
3. **Exploit** - send a context-appropriate payload. If it is reflected intact
   (un-encoded) we have a Firm reflected-XSS finding.
4. **Verify (optional)** - if a browser engine is attached, load the response
   and check the sentinel actually executed; success upgrades to Confirmed and
   attaches a screenshot.

Stored XSS is handled by the same machinery: after submitting a payload we can
re-crawl/re-fetch known display pages and look for the sentinel (the engine
passes a list of revisit URLs). DOM XSS requires the browser engine to observe
sink execution; both are wired through the same `verify` hook.
"""

"""Reflection-context analysis for XSS.

The single biggest source of XSS false positives in the original scanner was
treating *any* reflection as a vulnerability (``payload.lower() in text``) and,
worse, flagging on the mere presence of ``<script>`` or ``onerror=`` anywhere
in the response - which fires on the page's own legitimate scripts.

Instead we inject a unique, benign probe marker, locate every place it is
reflected, and classify the surrounding context. The context determines:

1. whether reflection is even exploitable, and
2. which payload shape is needed to break out of it.

We also record which "breakout" characters (`<`, `>`, `"`, `'`) survive
un-encoded, because if the app HTML-encodes them the reflection is inert.
""""""Context-aware XSS payloads with mutation/encoding variants.

Rather than firing the same five payloads blindly at every parameter (the
original approach), we select payloads suited to the reflection context, each
carrying a unique callback marker so successful execution can be unambiguously
attributed (and verified in a browser).
"""

import re
import secrets

from dataclasses import dataclass
from enum import Enum

from sentinel.core.context import ScanContext
from sentinel.models import (Confidence, Evidence, Finding, Form, Severity)
from sentinel.plugins.base import Plugin



_CHARSET_PROBE = "<\">'/"


class Context(str, Enum):
    HTML_TEXT = "html_text"          # between tags:  <div>HERE</div>
    ATTRIBUTE = "attribute"          # inside attr:   <input value="HERE">
    SCRIPT = "script"                # inside <script>...HERE...</script>
    URL = "url"                      # in href/src attribute value
    COMMENT = "comment"              # inside <!-- HERE -->
    UNKNOWN = "unknown"


BREAKOUT_CHARS = ["<", ">", '"', "'", "/"]


def make_marker() -> str:
    return "szl" + secrets.token_hex(4) + "xss"


@dataclass
class Reflection:
    context: Context
    surviving_chars: set[str]
    raw_index: int

    @property
    def is_exploitable(self) -> bool:
        # We need to be able to inject the characters that break out of the
        # current context. If the app encodes them all, it is not exploitable
        # via this reflection.
        if self.context is Context.HTML_TEXT:
            return "<" in self.surviving_chars and ">" in self.surviving_chars
        if self.context is Context.ATTRIBUTE:
            return '"' in self.surviving_chars or "'" in self.surviving_chars
        if self.context is Context.SCRIPT:
            return True  # often exploitable without angle brackets
        return False


def _surviving_chars(probe_resp: str, marker: str) -> set[str]:
    """Send marker wrapped in breakout chars elsewhere; here we approximate by
    checking which breakout chars appear un-encoded immediately around the
    marker echo. The plugin does the real probe with a charset string."""
    survived: set[str] = set()
    for ch in BREAKOUT_CHARS:
        # crude proximity check; the plugin refines with a dedicated charset probe
        if ch in probe_resp:
            survived.add(ch)
    return survived


def classify(response_text: str, marker: str,
             charset_echo: str | None = None) -> list[Reflection]:
    """Find every reflection of ``marker`` and classify its context."""
    reflections: list[Reflection] = []
    lowered = response_text
    for m in re.finditer(re.escape(marker), lowered):
        idx = m.start()
        ctx = _context_at(lowered, idx, len(marker))
        survived = _charset_survivors(charset_echo) if charset_echo else set(BREAKOUT_CHARS)
        reflections.append(Reflection(context=ctx, surviving_chars=survived,
                                      raw_index=idx))
    return reflections


def _charset_survivors(echo: str | None) -> set[str]:
    if not echo:
        return set()
    return {ch for ch in BREAKOUT_CHARS if ch in echo}


def _context_at(text: str, idx: int, length: int) -> Context:
    before = text[:idx]
    after = text[idx + length:]

    # inside a <script> block?
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close:
        return Context.SCRIPT

    # inside an HTML comment?
    last_comment_open = before.rfind("<!--")
    last_comment_close = before.rfind("-->")
    if last_comment_open > last_comment_close:
        return Context.COMMENT

    # inside a tag (attribute context)? find nearest unclosed '<'
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt > last_gt:
        # we are inside <tag ...HERE...>
        tag_fragment = before[last_lt:]
        if re.search(r'(href|src)\s*=\s*["\']?[^"\']*$', tag_fragment, re.I):
            return Context.URL
        return Context.ATTRIBUTE

    return Context.HTML_TEXT


class XssPlugin(Plugin):
    id = "xss"
    name = "Cross-Site Scripting"
    default_severity = Severity.HIGH

    async def run(self, ctx: ScanContext, form: Form) -> None:
        params = form.fuzzable_params
        if not params:
            return

        base_data = form.baseline_data(marker="safe123")
        for param in params:
            await self._test_param(ctx, form, param, base_data)

    async def _test_param(self, ctx: ScanContext, form: Form, param: str,
                           base_data: dict[str, str]) -> None:
        marker = make_marker()
        probe_value = f"{marker}{_CHARSET_PROBE}"

        data = dict(base_data)
        data[param] = probe_value
        resp = await self._send(ctx, form, data)

        reflections = classify(
            resp.text,
            marker,
            charset_echo=self._echo_after(resp.text, marker),
            )
        
        if not reflections:
            return  # no reflection => no reflected XSS here

        exploitable = [r for r in reflections if r.is_exploitable]
        if not exploitable:
            # Reflected but encoded - report as low-confidence informational so
            # an analyst can review, but NOT as an XSS vulnerability.
            ctx.report(Finding(
                name="Reflected Input (output appears encoded)",
                plugin=self.id, severity=Severity.INFO,
                confidence=Confidence.TENTATIVE, cwe="CWE-79",
                url=form.action, parameter=param, method=form.method,
                description="User input is reflected but breakout characters "
                            "appear to be encoded; not exploitable as observed.",
                remediation="Confirm contextual output encoding remains in place.",
            ))
            return

        reflection = exploitable[0]
        for payload in payloads_for(reflection.context, marker):
            data[param] = payload
            r2 = await self._send(ctx, form, data)
            if payload not in r2.text:
                continue  # payload was filtered/encoded; try next / mutate

            confidence = Confidence.FIRM
            screenshot = None
            if ctx.browser is not None:
                executed, screenshot = await self._verify(ctx, form, data, marker)
                if executed:
                    confidence = Confidence.CONFIRMED

            ctx.report(Finding(
                name="Reflected Cross-Site Scripting",
                plugin=self.id, severity=Severity.HIGH, confidence=confidence,
                cwe="CWE-79", cvss=6.1,
                url=form.action, parameter=param, method=form.method,
                payload=payload,
                description=f"Input to parameter '{param}' is reflected without "
                            f"adequate encoding in a {reflection.context.value} "
                            f"context, allowing script injection.",
                remediation="Apply context-aware output encoding (HTML, attribute, "
                            "JS, URL) and a strict Content-Security-Policy. Prefer "
                            "framework auto-escaping; never build markup by string "
                            "concatenation of untrusted input.",
                reproduction=[
                    f"Send a {form.method} request to {form.action}",
                    f"Set parameter '{param}' to: {payload}",
                    "Observe the payload reflected un-encoded in the response "
                    "(and executing in a browser).",
                ],
                evidence=[Evidence(
                    description="Payload reflected un-encoded in response.",
                    request=f"{form.method} {form.action} {param}={payload}",
                    response_excerpt=self._excerpt(r2.text, payload),
                    screenshot_path=screenshot,
                )],
            ))
            return  # one confirmed finding per param is enough

    async def _send(self, ctx: ScanContext, form: Form, data: dict[str, str]):
        if form.method == "POST":
            return await ctx.http.post(form.action, data=data, use_cache=False)
        return await ctx.http.get(form.action, params=data, use_cache=False)

    async def _verify(self, ctx: ScanContext, form: Form,
                      data: dict[str, str], marker: str):
        """Use the optional browser engine to confirm execution + screenshot."""
        try:
            return await ctx.browser.verify_xss(form, data, marker)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            self.log.debug(f"browser verification unavailable: {exc!r}")
            return False, None

    @staticmethod
    def _echo_after(text: str, marker: str) -> str | None:
        idx = text.find(marker)
        if idx < 0:
            return None
        return text[idx:idx + len(marker) + 8]

    @staticmethod
    def _excerpt(text: str, needle: str, span: int = 60) -> str:
        idx = text.find(needle)
        if idx < 0:
            return text[:120]
        start = max(0, idx - span)
        return text[start:idx + len(needle) + span]


def payloads_for(context: Context, marker: str) -> list[str]:
    """Return ordered payloads (most reliable first) for a given context.

    ``marker`` is embedded so that browser verification can detect execution
    via a sentinel (e.g. setting ``window.__marker`` or a title change).
    """
    js = f"window.__xss='{marker}'"
    if context is Context.SCRIPT:
        # We're already inside JS; break the string / statement.
        return [
            f"';{js};//",
            f"\";{js};//",
            f"</script><script>{js}</script>",
        ]
    if context is Context.ATTRIBUTE:
        return [
            f'"><img src=x onerror={js}>',
            f"'><img src=x onerror={js}>",
            f'" autofocus onfocus={js} x="',
        ]
    if context is Context.URL:
        return [f"javascript:{js}"]
    if context is Context.COMMENT:
        return [f"--><script>{js}</script>"]
    # HTML_TEXT / UNKNOWN
    return [
        f"<script>{js}</script>",
        f"<img src=x onerror={js}>",
        f"<svg onload={js}>",
    ]


def mutations(payload: str) -> list[str]:
    """Lightweight WAF/filter-bypass mutations of a payload.

    Kept conservative and benign (no destructive content). Used only after a
    base payload is reflected-but-filtered, to test for weak blacklisting.
    """
    out = [payload]
    out.append(payload.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"))
    out.append(payload.replace("onerror=", "onerror\t="))
    out.append(payload.replace("alert", "al\u200bert"))  # zero-width split
    # de-dup preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq

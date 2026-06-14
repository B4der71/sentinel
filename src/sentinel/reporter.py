"""Reporters.

A reporter takes the final findings list and writes an artefact. All three
share the same input contract (``list[Finding]``) so adding a format (SARIF,
Markdown, PDF) is another small class.

* JsonReporter      - machine-readable, full fidelity.
* HtmlReporter      - self-contained styled HTML for humans, groups by severity.
* ExecutiveReporter - one-page summary: counts, top risks, no payload noise.
"""
from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from sentinel.models import Finding, Severity

_SEV_COLOR = {
    "Critical": "#7c2d12", "High": "#b91c1c", "Medium": "#b45309",
    "Low": "#0369a1", "Informational": "#475569",
}


class JsonReporter:
    def write(self, findings: list[Finding], path: str | Path) -> None:
        data = [f.to_dict() for f in findings]
        Path(path).write_text(json.dumps(data, indent=2))


class ExecutiveReporter:
    def write(self, findings: list[Finding], path: str | Path) -> None:
        counts = Counter(f.severity.value for f in findings)
        top = [f for f in findings
               if f.severity in (Severity.CRITICAL, Severity.HIGH)][:5]
        lines = ["# Executive Summary", "",
                 f"Total findings: **{len(findings)}**", ""]
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            if counts.get(sev):
                lines.append(f"- {sev}: {counts[sev]}")
        lines += ["", "## Top Risks", ""]
        if not top:
            lines.append("No high or critical findings.")
        for f in top:
            lines.append(f"- **{f.name}** ({f.severity.value}, "
                         f"{f.confidence.value}) - {f.url}"
                         + (f" [param: {f.parameter}]" if f.parameter else ""))
        lines += ["", "## Recommended Priorities", "",
                  "1. Remediate all Critical/High findings before release.",
                  "2. Add parameterised queries and contextual output encoding.",
                  "3. Apply a baseline security-header policy site-wide."]
        Path(path).write_text("\n".join(lines))


class HtmlReporter:
    def write(self, findings: list[Finding], path: str | Path) -> None:
        counts = Counter(f.severity.value for f in findings)
        chips = "".join(
            f'<span class="chip" style="background:{_SEV_COLOR[s]}">{s}: {counts.get(s,0)}</span>'
            for s in ("Critical", "High", "Medium", "Low", "Informational")
        )
        cards = "\n".join(self._card(f) for f in findings) or "<p>No findings.</p>"
        doc = _TEMPLATE.format(chips=chips, cards=cards, total=len(findings))
        Path(path).write_text(doc)

    def _card(self, f: Finding) -> str:
        e = lambda s: html.escape(str(s)) if s is not None else ""
        evidence = "".join(
            f"<li>{e(ev.description)}"
            + (f"<pre>{e(ev.response_excerpt)}</pre>" if ev.response_excerpt else "")
            + (f'<div class="shot">screenshot: {e(ev.screenshot_path)}</div>'
               if ev.screenshot_path else "")
            + "</li>"
            for ev in f.evidence
        )
        steps = "".join(f"<li>{e(s)}</li>" for s in f.reproduction)
        return f"""
        <div class="card" style="border-left:6px solid {_SEV_COLOR[f.severity.value]}">
          <h3>{e(f.name)} <small>{e(f.severity.value)} · {e(f.confidence.value)}
            {f' · CVSS {f.cvss}' if f.cvss else ''}
            {f' · {e(f.cwe)}' if f.cwe else ''}</small></h3>
          <table>
            <tr><th>URL</th><td>{e(f.url)}</td></tr>
            <tr><th>Parameter</th><td>{e(f.parameter)}</td></tr>
            <tr><th>Method</th><td>{e(f.method)}</td></tr>
            <tr><th>Payload</th><td><code>{e(f.payload)}</code></td></tr>
          </table>
          <p>{e(f.description)}</p>
          {f'<h4>Reproduction</h4><ol>{steps}</ol>' if steps else ''}
          {f'<h4>Evidence</h4><ul>{evidence}</ul>' if evidence else ''}
          <h4>Remediation</h4><p>{e(f.remediation)}</p>
        </div>"""


_TEMPLATE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Sentinel Scan Report</title><style>
body{{font-family:system-ui,sans-serif;margin:0;background:#f1f5f9;color:#0f172a}}
header{{background:#0f172a;color:#fff;padding:24px 32px}}
header h1{{margin:0 0 8px}}
.chip{{display:inline-block;color:#fff;padding:4px 10px;border-radius:12px;
  font-size:12px;margin-right:6px}}
main{{padding:24px 32px;max-width:980px;margin:auto}}
.card{{background:#fff;border-radius:8px;padding:16px 20px;margin:16px 0;
  box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.card h3{{margin:0 0 4px}} .card small{{color:#64748b;font-weight:400}}
table{{border-collapse:collapse;margin:8px 0;font-size:14px}}
th{{text-align:left;padding:2px 12px 2px 0;color:#475569;vertical-align:top}}
td{{padding:2px 0;word-break:break-all}}
pre{{background:#0f172a;color:#e2e8f0;padding:8px;border-radius:6px;
  overflow:auto;font-size:12px}}
code{{background:#e2e8f0;padding:1px 4px;border-radius:4px}}
.shot{{color:#7c3aed;font-size:12px}}
</style></head><body>
<header><h1>Sentinel Security Scan</h1>
<div>{total} findings &nbsp; {chips}</div></header>
<main>{cards}</main></body></html>"""


__all__ = ["JsonReporter", "HtmlReporter", "ExecutiveReporter"]

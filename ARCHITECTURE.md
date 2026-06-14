# Sentinel — Architecture & Design

This document is the design companion to the codebase. It covers the review of
the original scanner, the target architecture, the plugin contract, per-module
detection logic, the false-positive/negative strategy, and a prioritised
roadmap to grow Sentinel into a lightweight OWASP-ZAP-style tool.

---

## A. Review of the original scanner

The original five files worked, but had structural and correctness issues that
the refactor addresses directly.

**Architecture / SOLID**
- `main.py` was a god-module: login, form parsing, scan orchestration, dedup,
  console output, and report triggering all lived together. Adding a
  vulnerability class meant editing this file (Open/Closed violation). Now the
  `Engine` runs opaque `Plugin` objects and never changes when detection grows.
- Detection logic and I/O were interleaved. Plugins now only emit `Finding`
  objects; transport, dedup, and reporting are separate concerns.
- Dependency direction was concrete-on-concrete (functions importing functions).
  The new code depends on abstractions (`Plugin`, reporter interface,
  `HttpClient` wrapper) — Dependency Inversion.

**Correctness / false positives**
- XSS flagged on *any* reflection (`payload.lower() in text`) and, worse, on
  the mere presence of `<script>` or `onerror=` anywhere in the page — which
  fires on the site's own legitimate scripts. This is the single largest FP
  source. Fixed via unique-marker probing + context classification + (optional)
  browser execution proof.
- SQLi boolean check compared two *different* payloads (`1=1` vs `1=2`) and
  flagged on any text difference, so a CSRF token, CSRF nonce, timestamp, or
  ad rotation tripped it. Fixed with baseline + similarity-ratio logic
  (true≈baseline, false≠baseline, with a minimum gap).

**Correctness / false negatives**
- Crawler deduped on raw URL strings, so `?a=1&b=2` and `?b=2&a=1` were
  different pages and the same endpoint got re-queued or missed. Fixed with
  canonicalization + a parameter-signature surface key.
- Only `<form>` elements were attack surface; GET endpoints carrying query
  params (the bulk of DVWA) were never fuzzed. Fixed via `synthesize_get_form`.
- Hidden inputs were *dropped* during form extraction, removing IDOR/tampering
  surface and often breaking required-field submissions. Now preserved.
- SQLi covered only error+naive-boolean. Added time-based blind (+ scaffolding
  for UNION) and DB fingerprinting.

**Robustness / security of the tool itself**
- `except: continue` swallowed every error silently — failures looked like
  clean results. Replaced with narrow exception handling + structured logging.
- No scope control: any same-domain link was followed, and nothing stopped a
  redirect or absolute link from sending the scanner off-site. Added
  default-deny `Scope` enforced in the HTTP client.
- Synchronous `requests` with no rate limiting, retries, timeouts, or caching.
  Replaced with an async `httpx` client wrapping all four.
- Login hard-coded DVWA's `user_token` field name and form shape. Generalised
  to auto-extract all hidden inputs and configurable credential fields.

---

## B. Target folder structure

```
sentinel/
├── pyproject.toml          # packaging, deps, entry point, tool config
├── requirements.txt
├── README.md
├── ARCHITECTURE.md
├── config/default.yaml
├── src/sentinel/
│   ├── cli.py              # argparse front-end (preserves old flags)
│   ├── logging_setup.py    # loguru w/ stdlib fallback
│   ├── core/
│   │   ├── config.py       # typed YAML config dataclasses
│   │   ├── scope.py        # default-deny scope + aggression gate  ← safety
│   │   ├── http_client.py  # async: rate-limit, retry, timeout, cache, scope
│   │   ├── session_manager.py  # form/cookie/bearer/header auth + CSRF
│   │   ├── context.py      # ScanContext handed to plugins
│   │   ├── plugin_manager.py
│   │   └── engine.py       # orchestration; vuln-agnostic
│   ├── models/             # Finding/Severity/Confidence/Evidence, Form/Endpoint
│   ├── crawler/            # crawler, canonicalizer, robots
│   ├── plugins/            # base.py (contract), registry, one pkg per vuln
│   │   ├── xss/   {contexts, payloads, plugin}
│   │   ├── sqli/  {fingerprint, plugin}
│   │   ├── headers/ cors/ redirect/
│   ├── browser/            # Playwright verification (optional)
│   └── reporting/          # json / html / executive
└── tests/                  # unit + in-process integration target
```

---

## C. Class diagram (logical)

```
                         ┌────────────┐
                         │   Engine   │   orchestrates a scan
                         └─────┬──────┘
        ┌──────────────┬───────┼─────────────┬──────────────┐
        ▼              ▼       ▼             ▼              ▼
 ┌────────────┐ ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐
 │PluginMgr   │ │SessionMgr │ │ Crawler  │ │HttpClient│ │ScanContext │
 └─────┬──────┘ └───────────┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘
       │ loads                     │ uses       │ uses        │ holds
       ▼                           ▼            │             ▼
 ┌────────────┐               ┌──────────┐      │       findings: [Finding]
 │  Plugin    │◄──────────────│  Form    │      │
 │ (abstract) │   run(ctx,    └──────────┘      │
 └─────┬──────┘    form)                        │ enforces
       │ implemented by                         ▼
  ┌────┴───────┬──────────┬──────────┬─────┐  ┌────────┐
  ▼            ▼          ▼          ▼     ▼  │ Scope  │ default-deny
 Xss          Sqli      Headers    Cors  Redirect└──────┘
  │ optionally uses
  ▼
 ┌──────────────┐        ┌──────────────────────────────┐
 │BrowserEngine │        │ Reporters: Json/Html/Executive│ consume [Finding]
 └──────────────┘        └──────────────────────────────┘
```

Key relationships: the `Engine` depends only on the `Plugin` abstraction and a
reporter interface. `HttpClient` is the sole egress point and the only place
`Scope` is enforced, so no plugin can bypass it.

---

## D. Core interfaces

```python
class Plugin(abc.ABC):
    id: str; name: str
    default_severity: Severity
    aggressive: bool = False
    async def run(self, ctx: ScanContext, form: Form) -> None: ...
    async def baseline(self, ctx, form) -> Response: ...
    def can_run(self, ctx) -> bool: ...      # self-gates on scope.allow_aggressive

@dataclass
class ScanContext:
    http: HttpClient; scope: Scope; config: Config
    findings: list[Finding]; browser: BrowserEngine | None
    def report(self, finding: Finding) -> None: ...

class Reporter(Protocol):                    # json/html/executive all satisfy
    def write(self, findings: list[Finding], path) -> None: ...
```

A plugin's entire surface area is "given a `Form`, emit `Finding`s." Everything
cross-cutting (rate limiting, scope, auth, dedup, reporting) is provided.

---

## E. Detection logic per module

**XSS** — probe param with `marker + <">'/`; if marker absent → stop. Classify
each reflection's context (HTML text / attribute / script / URL / comment) and
which breakout chars survived un-encoded. If none exploitable → emit
*informational* "encoded reflection", not a vuln. Else fire a context-specific
payload; reflected-intact ⇒ **Firm**; browser executes the sentinel ⇒
**Confirmed** + screenshot. Stored/DOM reuse the same `verify` hook (revisit
display pages / observe DOM sink).

**SQLi** — baseline request, then: (1) single-quote → DB error signature ⇒
error-based + fingerprint; (2) boolean: `sim(true,baseline)>0.95` AND
`sim(false,baseline)<0.90` with a ≥0.08 gap; (3) time-based (gated): inject
fingerprint-appropriate delay, confirm over two slow trials + one fast
baseline. Confidence rises with the number of agreeing signals.

**Headers / Clickjacking** — passive inspection of one response per host:
missing CSP/HSTS/X-Content-Type-Options/Referrer-Policy; no frame protection ⇒
clickjacking.

**CORS** — send forged `Origin`; reflected origin + `Allow-Credentials: true`
⇒ High; reflected-only or wildcard+creds ⇒ Medium.

**Open Redirect** — for redirect-hint params, inject external URL; a `Location`
to the attacker host (client does *not* auto-follow) ⇒ Confirmed.

*Planned modules and their core test:* **IDOR** (swap an authenticated
object id, expect another user's object); **LFI/Path Traversal** (`../` to a
known file marker / PHP wrapper); **RFI** (remote include reflected/executed);
**SSRF** (param fetches an out-of-band callback host); **Command Injection**
(time-delay `;sleep` echo, gated); **File Upload** (polyglot/extension bypass,
gated); **Sensitive Disclosure** (regex for keys/PII, stack traces).

---

## F. False-positive / false-negative strategy

- **Confidence tiers** (Tentative/Firm/Confirmed) on every finding, with the
  score driving dedup (keep the strongest instance) and report ordering.
- **Multi-signal corroboration** before high confidence (SQLi needs ≥2 signals
  for Confirmed; XSS needs execution).
- **Marker-based detection** instead of substring matching kills reflection FPs.
- **Similarity ratios** instead of equality kill boolean-SQLi FPs.
- **Timing double-confirmation** kills latency-driven blind-SQLi FPs.
- **FN reduction:** canonicalization (no missed endpoints), GET-surface
  synthesis, hidden-input preservation, context-aware payloads, DB
  fingerprinting, and the optional browser layer for JS-rendered surface.

---

## G. Implementation roadmap

1. **(done)** Core: models, scope, async client, config, logging.
2. **(done)** Crawler v2, plugin contract + engine, XSS + SQLi + 3 passive
   modules, reporters, tests, packaging.
3. Browser layer wired into a live run (Playwright execution proof, screenshots,
   JS-form discovery diffing).
4. Stored & DOM XSS via revisit-list + DOM sink observation.
5. UNION-based SQLi (column-count + type discovery) and data extraction PoC.
6. Remaining plugins in priority order (see H).
7. Reporting: SARIF output + Markdown; severity from a real CVSS vector helper.
8. Entry-point-based plugin discovery (drop-in third-party plugins).
9. Resumable scans (persist crawl frontier + seen sets), and a small TUI/JSON
   progress stream.

---

## H. Priority ranking of improvements

1. **Scope/safety enforcement** — must exist before anything sends traffic. ✅
2. **XSS & SQLi FP fixes** — these define whether the tool is trustworthy. ✅
3. **Async client + rate limiting** — correctness and politeness. ✅
4. **Crawler dedup + GET surface** — biggest FN reduction for least effort. ✅
5. **Confidence scoring + multi-format reports** — makes output actionable. ✅
6. **Browser verification** — turns XSS Firm→Confirmed; enables DOM/stored.
7. **High-impact new modules:** IDOR, SSRF, Command Injection, LFI/Path
   Traversal (highest real-world severity).
8. **UNION SQLi + extraction**, then the remaining passive/medium modules.

---

## I. Reducing operational risk

- Every aggressive technique self-gates on `scope.allow_aggressive` and is
  surfaced behind an interactive CLI confirmation.
- Time-based payloads use bounded delays and confirm before reporting, avoiding
  repeated heavy queries.
- The global token bucket caps total request rate regardless of concurrency.
- Caching idempotent GETs minimises redundant load on the target.

---

## J. Notes for contributors

- Keep plugins pure: no direct `httpx`/`requests`, no file writes — emit
  `Finding`s only.
- New transport behaviour belongs in `HttpClient`; new output formats are new
  reporters; neither should touch the engine.
- Add a unit test for any deterministic helper and an integration assertion
  against the in-process mock target in `tests/`.

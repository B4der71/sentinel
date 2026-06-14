# Sentinel — Architecture & Design

Version: 0.1.0
Status: Active Development

This document describes Sentinel's architecture, core components, plugin model,
detection capabilities, security principles, and future development roadmap.

---

## A. Design Goals

Sentinel is designed around the following principles:

* Plugin-based architecture
* Low false-positive rate
* Safe-by-default scanning
* Scope-aware request enforcement
* Async execution and concurrency
* Extensibility without engine modifications
* Evidence-based reporting

---

## B. Project Structure

```text
sentinel/
├── pyproject.toml
├── requirements.txt
├── README.md
├── ARCHITECTURE.md
├── config/
│   └── default.yaml
├── src/sentinel/
│   ├── __init__.py
│   ├── cli.py
│   ├── crawler.py
│   ├── logging_setup.py
│   ├── models.py
│   ├── reporter.py
│   ├── browser/
│   │   ├── __init__.py
│   │   └── playwright_engine.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── context.py
│   │   ├── engine.py
│   │   ├── http_client.py
│   │   ├── plugin_manager.py
│   │   ├── scope.py
│   │   └── session_manager.py
│   └── plugins/
│       ├── __init__.py
│       ├── base.py
│       ├── xss.py
│       ├── sqli.py
│       ├── headers.py
│       ├── cors.py
│       └── redirect.py
└── tests/
    ├── test_units.py
    └── test_integration.py
```

### Component Overview

| Component      | Responsibility                                                |
| -------------- | ------------------------------------------------------------- |
| CLI            | Command-line interface and scan configuration                 |
| Engine         | Scan orchestration and plugin execution                       |
| HttpClient     | HTTP transport, retries, rate limiting, and scope enforcement |
| SessionManager | Authentication and session handling                           |
| Crawler        | Attack-surface discovery and form      extraction             |
| PluginManager  | Plugin loading and lifecycle management                       |
| Plugins        | Vulnerability detection modules                               |
| Reporter       | JSON, HTML, and executive-summary generation                  |
| Browser Layer  | Optional Playwright-based verification                        |
| Models         | Shared data structures and finding definitions                |

---

## C. Architecture Overview

```text id="w39x7q"
                         ┌────────────┐
                         │   Engine   │
                         └─────┬──────┘
        ┌──────────────┬───────┼─────────────┬──────────────┐
        ▼              ▼       ▼             ▼              ▼
 ┌────────────┐ ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐
 │PluginMgr   │ │SessionMgr │ │ Crawler  │ │HttpClient│ │ScanContext │
 └─────┬──────┘ └───────────┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘
       │                           │            │             │
       │ loads                     │ discovers  │ enforces    │ stores
       ▼                           ▼            ▼             ▼
 ┌────────────┐               ┌──────────┐  ┌────────┐   Findings
 │  Plugin    │◄──────────────│  Form    │  │ Scope  │
 │ (abstract) │   run(ctx,    └──────────┘  └────────┘
 └─────┬──────┘    form)
       │
       │ implemented by
       ▼
 ┌──────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
 │  XssPlugin   │ SqliPlugin   │ HeadersPlugin│ CorsPlugin   │ OpenRedirect │
 └──────────────┴──────────────┴──────────────┴──────────────┴──────────────┘
                        │
                        ▼
                 ┌──────────────┐
                 │BrowserEngine │
                 │ (optional)   │
                 └──────────────┘
```

### Key Relationships

* The Engine orchestrates the entire scan lifecycle.
* PluginManager loads and manages all enabled plugins.
* SessionManager handles authentication and session state.
* Crawler discovers forms and attack surfaces.
* HttpClient is the sole network access layer and enforces scope restrictions.
* Plugins receive a ScanContext and emit Findings.
* BrowserEngine provides optional browser-based verification.
* Findings are collected, deduplicated, and passed to the reporting layer.

The Engine depends only on the Plugin abstraction, allowing new
vulnerability modules to be added without modifying the scanning
workflow.

```

---
```


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

## E. Detection Modules

### XSS

* Marker-based reflection detection
* Reflection context classification
* Context-aware payload selection
* Exploitability validation
* Optional browser-based execution verification

### SQL Injection

* Error-based detection
* Boolean-based validation
* Time-based blind testing
* Database fingerprinting
* Confidence scoring from multiple signals

### Security Headers

* Missing security header detection
* Clickjacking protection checks

### CORS

* Arbitrary origin reflection testing
* Credentialed cross-origin access validation

### Open Redirect

* External redirect target validation
* Redirect parameter discovery

### Planned Modules

* IDOR
* SSRF
* LFI / Path Traversal
* Command Injection
* File Upload Security
* Sensitive Information Disclosure

---

## F. Finding Confidence Model

Sentinel assigns a confidence level to every finding:

* Tentative
* Firm
* Confirmed

Confidence is increased through signal corroboration rather than
single-indicator detection.

Techniques used to reduce false positives include:

* Marker-based verification
* Similarity scoring
* Multi-signal validation
* Timing confirmation
* Context-aware payload selection

Techniques used to reduce false negatives include:

* URL canonicalization
* GET endpoint discovery
* Hidden-input preservation
* Database fingerprinting
* Browser-assisted verification

---

## G. Security Controls

Sentinel is designed to minimize operational risk during assessments.

Implemented controls include:

* Default-deny scope enforcement
* Explicit opt-in for aggressive testing
* Global request rate limiting
* Authenticated-session awareness
* Request caching for idempotent operations
* Confidence-based finding validation
* Bounded timing-based verification

These controls help reduce accidental target impact while maintaining
high-confidence detection results.

---

## H. Future Work

Planned enhancements include:

### Browser Verification

* Playwright-based execution proof
* Screenshot capture
* JavaScript-rendered form discovery

### XSS Improvements

* Stored XSS detection
* DOM XSS detection
* Browser-assisted sink verification

### SQL Injection Improvements

* UNION-based SQL Injection
* Column and type discovery
* Limited proof-of-concept data extraction

### New Detection Modules

* IDOR
* SSRF
* Command Injection
* LFI / Path Traversal
* File Upload Security
* Sensitive Information Disclosure

### Platform Enhancements

* SARIF reporting
* Markdown reporting
* Third-party plugin discovery
* Resumable scans
* Terminal UI and progress streaming

---

## I. Contributor Guidelines

When extending Sentinel:

* Implement new detection logic as plugins.
* Use ScanContext for all shared services.
* Do not perform direct network access outside HttpClient.
* Do not write files directly from plugins.
* Emit Findings rather than generating reports.
* Add unit tests for deterministic helpers.
* Add integration tests for end-to-end detection behavior.

Cross-cutting concerns such as authentication, scope enforcement,
rate limiting, reporting, and finding aggregation should remain
outside plugin implementations.

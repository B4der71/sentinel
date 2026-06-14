# Sentinel

A lightweight, plugin-based web application security scanner — a small,
hackable alternative to OWASP ZAP focused on automated detection of common web
vulnerabilities. Built for **authorized testing only**.

This is a refactor of an earlier crawl + XSS + SQLi script into a modular,
async, plugin-driven framework with confidence scoring, multi-format
reporting, and hard scope/safety controls.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .            # core
pip install -e '.[browser]' # optional: Playwright XSS execution verification
playwright install chromium # if you installed the browser extra
```

## Usage

```bash
# Single seed, all safe plugins, write reports/ (json + html + exec summary)
sentinel -u http://localhost:8080/ --all

# Config-driven run
sentinel -u http://localhost:8080/ -c config/default.yaml -o out/

# Authenticated (auto-extracts CSRF/hidden tokens from the login form)
sentinel -u http://localhost:8080/vulnerabilities/sqli/ \
  --username admin --password password --all

# Token auth
sentinel -u https://api.local/ --bearer "$TOKEN" --all

# Aggressive techniques (time-based blind SQLi) require explicit opt-in + prompt
sentinel -u http://localhost:8080/ --all --aggressive
```

## Ethics & safety (read this)

- **Default-deny scope.** Only the seed host is in scope; every request is
  checked against the allow-list before it leaves the process. Out-of-scope
  requests raise and never fire.
- **Rate limited** by a global token bucket; **`.gov`/`.mil` are refused.**
- **Aggressive/disruptive techniques are off by default** and require both a
  config flag and an interactive confirmation.
- Only scan systems you own or are explicitly authorized to test (e.g. DVWA,
  your own staging). You are responsible for compliance.

## Layout

```
src/sentinel/
  core/      engine, plugin_manager, http_client, scope, session, config
  models/    Finding/Severity/Confidence/Evidence, Endpoint/Form
  crawler/   async crawler, canonicalizer, robots
  plugins/   xss, sqli, headers, cors, redirect  (+ base contract, registry)
  browser/   Playwright verification (optional)
  reporting/ json / html / executive
config/      default.yaml
tests/       unit + in-process integration target
```

## Extending

Add a vulnerability module in three steps:

1. `class FooPlugin(Plugin): id = "foo"; async def run(self, ctx, form): ...`
2. Register it in `plugins/__init__.py` (`ALL_PLUGINS`).
3. Enable it in config (`plugins: { foo: true }`).

No engine changes required. See `ARCHITECTURE.md` for the full design,
detection logic per module, and the implementation roadmap.

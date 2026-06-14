# Sentinel

A lightweight, plugin-based web application security scanner — a small,
hackable alternative to OWASP ZAP focused on automated detection of common web
vulnerabilities.

Sentinel provides authenticated scanning, attack-surface discovery,
plugin-based vulnerability detection, confidence scoring, and multi-format
reporting.

> For authorized security testing only.

## Features

### Implemented Modules

* Reflected XSS
* SQL Injection
* Security Headers
* CORS Misconfiguration
* Open Redirect

### Core Capabilities

* Authenticated scanning
* Async crawling
* Scope enforcement
* Rate limiting
* robots.txt support
* GET parameter discovery
* HTML form extraction
* JSON reporting
* HTML reporting
* Executive summaries

## Install

```bash
python -m venv .venv
source .venv/bin/activate

pip install -e .

# Optional browser-assisted verification
pip install -e ".[browser]"
playwright install chromium
```

## Usage

```bash
# Run all enabled plugins against a target
sentinel -u http://localhost:8080/ --all

# Config-driven run
sentinel -u http://localhost:8080/ \
  -c config/default.yaml \
  -o out/

# Authenticated scan
sentinel \
  -u http://localhost:8080/vulnerabilities/sqli/ \
  --login-url http://localhost:8080/login.php \
  --username admin \
  --password password \
  --all

# Bearer token authentication
sentinel \
  -u https://api.local/ \
  --bearer "$TOKEN" \
  --all

# Enable aggressive techniques
sentinel \
  -u http://localhost:8080/ \
  --all \
  --aggressive
```

## Example Output

```text
[High   ] Firm      SQL Injection
[Medium ] Confirmed Missing Security Header
[Medium ] Firm      Clickjacking
[Low    ] Confirmed Missing X-Content-Type-Options
```

## Safety Controls

Sentinel includes several built-in safety mechanisms:

* Scope enforcement prevents out-of-scope requests.
* Request rate limiting reduces target impact.
* Aggressive techniques are disabled by default.
* Potentially disruptive checks require explicit user opt-in.
* All plugins operate through a shared, scope-aware HTTP client.

Only scan systems you own or are explicitly authorized to assess.

## Project Layout

```text
src/sentinel/
├── cli.py
├── crawler.py
├── logging_setup.py
├── models.py
├── reporter.py
├── browser/
├── core/
│     ├── config.py
│     ├── context.py
│     ├── engine.py
│     ├── http_client.py
│     ├── plugin_manager.py
│     ├── scope.py
│     └── session_manager.py
└── plugins/
      ├── base.py
      ├── cors.py
      ├── headers.py
      ├── redirect.py
      ├── sqli.py
      └── xss.py

config/
   └── default.yaml

tests/
  ├── test_units.py
  └── test_integration.py
```

## Extending

Sentinel is built around a plugin architecture.

To add a new detection module:

1. Create a class derived from `Plugin`.
2. Implement the `run()` method.
3. Register the plugin in `plugins/__init__.py`.
4. Enable it through configuration or CLI selection.

The scanning engine is vulnerability-agnostic, allowing new modules
to be added without modifying the core workflow.

## Documentation

See `ARCHITECTURE.md` for:

* System architecture
* Plugin model
* Detection modules
* Confidence model
* Security controls
* Future roadmap

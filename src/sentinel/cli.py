"""Command-line interface.

Preserves the spirit of the original ``main.py`` flags (-u/--url, --xss,
--sqli, --all, --crawl, auth) while adding config-file driven runs, an explicit
scope confirmation for aggressive scans, and multi-format reporting.
"""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from sentinel.core.config import Config
from sentinel.core.engine import Engine
from sentinel.logging_setup import configure, log
from sentinel.reporter import (
    ExecutiveReporter,
    HtmlReporter,
    JsonReporter,
)

from sentinel import __version__

def _build_config(args: argparse.Namespace) -> Config:
    cfg = Config.load(args.config) if args.config else Config()

    if args.all:
        cfg.plugins = {k: True for k in cfg.plugins} | {
            "xss": True, "sqli": True, "headers": True, "cors": True, "redirect": True}
    else:
        selected = {"xss": args.xss, "sqli": args.sqli,
                    "headers": args.headers, "cors": args.cors,
                    "redirect": args.redirect}
        if any(selected.values()):
            cfg.plugins = {k: v for k, v in selected.items()}

    if args.username and args.password:
        cfg.auth.type = "form"
        cfg.auth.login_url = args.login_url or _guess_login(args.url)
        cfg.auth.username = args.username
        cfg.auth.password = args.password
    if args.bearer:
        cfg.auth.type = "bearer"
        cfg.auth.token = args.bearer

    if args.max_pages:
        cfg.crawler.max_pages = args.max_pages
    if args.max_depth:
        cfg.crawler.max_depth = args.max_depth
    if args.aggressive:
        cfg.scanner.allow_aggressive = True
    cfg.crawler.enabled = args.crawl
    

    
    return cfg


def _guess_login(url: str) -> str:
    base = url.split("/vulnerabilities")[0].rstrip("/")
    return f"{base}/login.php"


async def _run(args: argparse.Namespace) -> int:
    cfg = _build_config(args)
    configure(level="DEBUG" if args.verbose else "INFO", logfile=args.log_file)

    if cfg.scanner.allow_aggressive and not args.yes:
        log.warning("Aggressive mode is ON (time-based blind SQLi etc.). "
                    "These send disruptive payloads.")
        reply = input(f"Confirm you are authorised to aggressively test "
                      f"{args.url}? [y/N] ").strip().lower()
        if reply != "y":
            log.info("aborted by user")
            return 2

    engine = Engine(cfg)
    findings = await engine.scan(args.url)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    JsonReporter().write(findings, out / "report.json")
    HtmlReporter().write(findings, out / "report.html")
    ExecutiveReporter().write(findings, out / "executive_summary.md")
    log.info(f"reports written to {out}/ "
             f"(report.json, report.html, executive_summary.md)")
    for f in findings:
        print(
            f"[{f.severity.value:<13}] "
            f"{f.confidence.value:<9} "
            f"{f.name}"
        )

        print(f"  URL:        {f.url}")

        if f.parameter:
            print(f"  Parameter:  {f.parameter}")

        print(f"  Method:     {f.method}")

        if getattr(f, "database", None):
            print(f"  Database:   {f.database}")

        if getattr(f, "techniques", None):
            print(
                f"  Techniques: "
                f"{', '.join(f.techniques)}"
            )

        if f.payload:
            print(f"  Payload:    {repr(f.payload)}")

        print()
    return 0


def main() -> None:
    p = argparse.ArgumentParser(
    description=(
        "Sentinel - Lightweight plugin-based web application "
        "security scanner"
        )
    )
    

    p.add_argument(
    "--version",
    action="version",
    version=f"Sentinel {__version__}"
    )

    p.add_argument(
    "-u", "--url",
    required=True,
    help="Seed or target URL"
    )

    p.add_argument(
        "-c", "--config",
        help="YAML configuration file"
    )

    p.add_argument(
        "-o", "--out-dir",  default="reports",help="Directory for generated reports"
    )

    p.add_argument("--all", action="store_true", help="Enable all plugins")
    p.add_argument(
    "--xss",
    action="store_true",
    help="Enable reflected Cross-Site Scripting detection"
    )

    p.add_argument(
        "--sqli",
        action="store_true",
        help="Enable SQL Injection detection"
    )

    p.add_argument(
        "--headers",
        action="store_true",
        help="Check security headers and clickjacking protections"
    )

    p.add_argument(
        "--cors",
        action="store_true",
        help="Check for CORS misconfigurations"
    )

    p.add_argument(
        "--redirect",
        action="store_true",
        help="Check for open redirect vulnerabilities"
    )

    p.add_argument(
    "--username",
    help="Username for form-based authentication"
    )

    p.add_argument(
        "--password",
        help="Password for form-based authentication"
    )

    p.add_argument(
        "--login-url",
        help="Login page URL (auto-detected when omitted)"
    )
    p.add_argument(
    "--bearer",
    help="Bearer token for API authentication"
    )

    p.add_argument(
        "--crawl",
        action="store_true",
        help="Discover and scan the entire attack surface"
    )
    p.add_argument(
    "--max-pages",
    type=int,
    help="Maximum number of pages to crawl"
    )

    p.add_argument(
        "--max-depth",
        type=int,
        help="Maximum crawl depth"
    )

    p.add_argument("--aggressive", action="store_true",
                   help="Enable disruptive techniques (requires confirmation)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip aggressive-scan confirmation (CI use)")
    p.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="Enable verbose logging"
    )

    p.add_argument(
        "--log-file",
        help="Write logs to a file"
    )
    args = p.parse_args()
    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()

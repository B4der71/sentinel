"""
Sentinel command-line interface.

Builds the runtime configuration, exposes dynamically discovered plugins as
command-line options, manages authentication and scan scope, and generates
JSON, HTML, and executive reports.
"""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from sentinel.plugins import ALL_PLUGINS

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
        cfg.plugins = {
            plugin_id: True
            for plugin_id in ALL_PLUGINS
        }
    else:
        selected = {
            plugin_id: getattr(args, plugin_id)
            for plugin_id in ALL_PLUGINS
        }

        if any(selected.values()):
            cfg.plugins = selected

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

    try:
        findings = await engine.scan(args.url)

    except RuntimeError as exc:
        log.error(exc)
        return 1

    except Exception:
        log.exception("Unexpected error during scan.")
        return 1

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
        version=(
            f"Sentinel {__version__}\n"
            "Author : Bader Alwashah\n"
            "GitHub : https://github.com/B4der71\n"
            f"Plugins: {len(ALL_PLUGINS)} discovered"
        )
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
        "-o",
        "--out-dir",
        default="reports",
        help="Directory for generated reports",
    )

    p.add_argument("--all", action="store_true",help="Enable all available plugins")
    
    # Automatically generate plugin CLI arguments
    for plugin in sorted(
        ALL_PLUGINS.values(),
        key=lambda plugin_cls: plugin_cls.id,
    ):
        help_text = (
            f"{plugin.name} "
            f"({plugin.category}, "
            f"{plugin.default_severity.value.title()}) - "
            f"{plugin.description}"
        )

        p.add_argument(
            f"--{plugin.id}",
            action="store_true",
            help=help_text,
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

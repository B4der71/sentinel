"""
Core scanning engine.

Responsible for orchestrating the end-to-end security assessment
workflow, from target discovery to finding generation.

Features:
- Scope-aware scanning
- Authenticated session support
- Attack-surface discovery
- Concurrent plugin execution
- Finding deduplication and ranking
- Report-ready result aggregation

The engine is vulnerability-agnostic and interacts with plugins
through a common interface, allowing new detection capabilities to
be added without modifying the scanning workflow.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from sentinel.models import Finding, Form

from sentinel.core.config import Config
from sentinel.core.context import ScanContext
from sentinel.core.http_client import HttpClient
from sentinel.core.plugin_manager import PluginManager
from sentinel.core.scope import Scope
from sentinel.core.session_manager import SessionManager

from sentinel.crawler import (
    Crawler,
    RobotsPolicy,
    extract_forms,
    synthesize_get_form,
)

from sentinel.logging_setup import log

from sentinel.browser.playwright_engine import BrowserEngine


class Engine:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._pm = PluginManager(config)

    async def scan(self, seed: str) -> list[Finding]:
        scope = Scope.from_seed(
            seed,
            allow_aggressive=self._config.scanner.allow_aggressive,
        )
        plugins = self._pm.load()
        needs_browser = any(p.id == "xss" for p in plugins)        

        async with HttpClient(self._config.scanner, scope) as http:
            await SessionManager(self._config.auth).authenticate(http)
            
            
            if self._config.crawler.enabled:
                robots = RobotsPolicy(self._config.scanner.user_agent)
                crawler = Crawler(
                    http,
                    scope,
                    self._config.crawler,
                    robots=robots,
                )
                forms = await crawler.crawl(seed)
            else:
                log.info("crawl disabled: discovering forms on seed page")

                form = synthesize_get_form(seed)

                if form and form.fuzzable_params:
                    forms = [form]

                else:
                    resp = await http.get(seed)

                    forms = extract_forms(seed, resp.text)

                    synthetic = synthesize_get_form(seed)
                    if synthetic:
                        forms.append(synthetic)

                    if not forms:
                        forms = [
                            Form(
                                url=seed,
                                action=seed,
                                method="GET",
                                inputs=[],
                                source="seed",
                            )
                        ]

            browser = None

            try:
                if needs_browser and BrowserEngine.available():
                    
                    parsed = urlsplit(seed)
                    origin = f"{parsed.scheme}://{parsed.netloc}"
                    
                    cookies = [
                        {
                            "name": c.name,
                            "value": c.value,
                            "url": origin,
                            "httpOnly": False,
                            "secure": False,
                        }
                        for c in http._client.cookies.jar
                    ]

                    browser = await BrowserEngine(
                        cookies=cookies,
                    ).__aenter__()

                ctx = ScanContext(
                    http=http,
                    scope=scope,
                    config=self._config,
                    browser=browser,
                )

                sem = asyncio.Semaphore(self._config.scanner.concurrency)

                async def run_one(plugin, form: Form) -> None:
                    if not plugin.can_run(ctx):
                        return

                    async with sem:
                        try:
                            await plugin.run(ctx, form)
                        except Exception as exc:  # noqa: BLE001
                            log.warning(
                                f"plugin {plugin.id} failed on "
                                f"{form.action}: {exc!r}"
                            )

                # Execute every plugin against every discovered form.
                tasks = [run_one(p, f) for f in forms for p in plugins]
                log.info(f"executing {len(tasks)} plugin/form tasks")

                await asyncio.gather(*tasks)

            finally:
                if browser:
                    await browser.__aexit__(None, None, None)
            

        return self._finalize(ctx.findings)

    @staticmethod
    def _finalize(findings: list[Finding]) -> list[Finding]:
        deduped: dict[str, Finding] = {}
        for f in findings:
            key = f.dedup_key()
            existing = deduped.get(key)
            # keep the higher-confidence instance of a duplicated issue
            if existing is None or f.confidence.score > existing.confidence.score:
                deduped[key] = f
        result = sorted(
            deduped.values(),
            key=lambda x: (x.severity.rank, x.confidence.score),
            reverse=True,
        )
        log.info(f"scan finished: {len(result)} unique findings")
        return result

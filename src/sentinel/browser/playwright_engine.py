"""Browser verification layer (Playwright).

This is the component that turns *reflection* into *proof of execution*, which
is the gold standard for eliminating XSS false positives and the only reliable
way to detect DOM-based and stored XSS.

It is optional: if Playwright is not installed the engine simply is not
attached to the ScanContext, and plugins fall back to reflection-based Firm
findings. Install with: ``pip install '.[browser]' && playwright install
chromium``.

Verification strategy: payloads carry a unique marker and set
``window.__xss = '<marker>'``. After navigating with the payload applied, we
read ``window.__xss`` back. If it equals the marker, the script *executed* in a
real browser - Confirmed. We also capture a full-page screenshot as evidence.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlencode

from sentinel.logging_setup import log
from sentinel.models import Form

try:
    from playwright.async_api import async_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:  # pragma: no cover
    _HAVE_PLAYWRIGHT = False

class BrowserEngine:
    def __init__(
        self,
        screenshot_dir: str = "reports/screenshots",
        cookies: list[dict] | None = None,
    ) -> None:
        self._dir = Path(screenshot_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

        self._cookies = cookies or []

        self._pw = None
        self._browser = None
        self._context = None

    @classmethod
    def available(cls) -> bool:
        return _HAVE_PLAYWRIGHT

    async def __aenter__(self) -> "BrowserEngine":
        if not _HAVE_PLAYWRIGHT:
            raise RuntimeError("Playwright not installed; install extras [browser]")
        self._pw = await async_playwright().start()

        self._browser = await self._pw.chromium.launch(headless=True)

        self._context = await self._browser.new_context()

        if self._cookies:
            await self._context.add_cookies(self._cookies)

        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._context:
            await self._context.close()

        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()

    async def verify_xss(self, form: Form, data: dict[str, str],
                         marker: str) -> tuple[bool, str | None]:
        """Return (executed?, screenshot_path)."""
        if not self._browser:
            return False, None
        page = await self._context.new_page()
        try:
            if form.method == "GET":
                url = f"{form.action}?{urlencode(data)}"
                await page.goto(url, wait_until="networkidle", timeout=10_000)
                
            else:
                # render the action page then submit the payload via fetch/form
                await page.goto(form.action, wait_until="domcontentloaded",
                                timeout=10_000)
                await page.evaluate(_POST_JS, {"action": form.action, "data": data})
                await page.wait_for_timeout(500)

            value = await page.evaluate("() => window.__xss || null")

            

            executed = value == marker
            shot = None
            if executed:
                shot = str(self._dir / f"xss_{marker}.png")
                await page.screenshot(path=shot, full_page=True)
                log.bind(plugin="xss").info(
                    f"Browser confirmed XSS execution; screenshot saved to {shot}"
                )


            return executed, shot
        except Exception as exc:  # noqa: BLE001
            log.bind(plugin="xss").debug(f"browser verify error: {exc!r}")
            return False, None
        finally:
            await page.close()

    async def discover_forms(self, url: str) -> list[Form]:
        """Render the page and return forms present only after JS execution.

        Diffing JS-rendered DOM forms against the static HTML forms is how we
        surface JavaScript-generated attack surface. Implemented as a thin
        render+extract; returns [] when unavailable.
        """
        if not self._browser:
            return []
        from sentinel.crawler.crawler import extract_forms
        page = await self._context.new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=10_000)
            html = await page.content()
            return extract_forms(url, html)
        except Exception:  # noqa: BLE001
            return []
        finally:
            await page.close()


_POST_JS = """
({action, data}) => {
  const f = document.createElement('form');
  f.method = 'POST'; f.action = action;
  for (const k in data) {
    const i = document.createElement('input');
    i.name = k; i.value = data[k]; f.appendChild(i);
  }
  document.body.appendChild(f); f.submit();
}
"""

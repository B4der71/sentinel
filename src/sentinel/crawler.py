"""
Asynchronous web crawler and attack-surface discovery engine.

Features:
- Concurrent page crawling
- Scope-aware link discovery
- Depth and page limits
- robots.txt support
- HTML form extraction
- GET parameter discovery from links
- Optional browser-assisted form discovery

Discovered forms and endpoints are normalized and deduplicated
before being returned for security testing.
"""
from __future__ import annotations

import asyncio
from urllib.parse import (
    urljoin,
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse,
)

from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup
from sentinel.core.http_client import HttpClient
from sentinel.core.scope import Scope
from sentinel.core.config import CrawlerConfig


from sentinel.logging_setup import log
from sentinel.models import Form, FormInput, InputType

_SKIP_INPUT_TYPES = {"button", "image", "reset"}
_NOISE_LINK_HINTS = ("logout", "signout", "sign-out", "/logout")

_DEFAULT_PORTS = {"http": "80", "https": "443"}


def canonicalize(url: str, *, drop_values: bool = False) -> str:
    p = urlparse(url)
    scheme = p.scheme.lower()
    host = p.hostname or ""
    netloc = host
    if p.port and _DEFAULT_PORTS.get(scheme) != str(p.port):
        netloc = f"{host}:{p.port}"

    path = p.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    pairs = parse_qsl(p.query, keep_blank_values=True)
    if drop_values:
        pairs = [(k, "") for k, _ in pairs]
    query = urlencode(sorted(pairs))

    return urlunparse((scheme, netloc, path, "", query, ""))


def param_signature(url: str) -> str:
    
    #Generate a stable endpoint signature based on path and parameter names.
    
    return canonicalize(url, drop_values=True)


def _input_type(raw: str) -> InputType:
    try:
        return InputType(raw)
    except ValueError:
        return InputType.OTHER


def extract_forms(page_url: str, html: str) -> list[Form]:
    """Parse all forms on a page, preserving hidden inputs and flagging uploads."""
    soup = BeautifulSoup(html, "html.parser")
    forms: list[Form] = []
    for el in soup.find_all("form"):
        method = (el.get("method") or "get").upper()
        action = urljoin(page_url, el.get("action") or page_url)
        inputs: list[FormInput] = []
        is_upload = False
        for tag in el.find_all(("input", "textarea", "select")):
            name = tag.get("name")
            if not name:
                continue
            raw_type = (tag.get("type") or "text").lower()
            if raw_type in _SKIP_INPUT_TYPES:
                continue
            itype = _input_type(raw_type)
            if itype is InputType.FILE:
                is_upload = True
            inputs.append(FormInput(name=name, input_type=itype,
                                    value=tag.get("value") or ""))
        if (el.get("enctype") or "").lower() == "multipart/form-data":
            is_upload = True
        forms.append(Form(url=page_url, action=action, method=method,
                          inputs=inputs, is_upload=is_upload, source="html"))
    
      
    return forms


def synthesize_get_form(url: str) -> Form | None:

    #Convert a URL with query parameters into a synthetic GET form.
    qs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    if not qs:
        return None
    base = url.split("?", 1)[0]
    inputs = [FormInput(name=k, value=v) for k, v in qs]
    return Form(url=base, action=base, method="GET",
                inputs=inputs, source="synthetic")

class RobotsPolicy:
    def __init__(self, user_agent: str) -> None:
        self._ua = user_agent
        self._parsers: dict[str, RobotFileParser] = {}

    async def load(self, base_url: str, http: HttpClient) -> None:
        origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))
        if origin in self._parsers:
            return
        rp = RobotFileParser()
        robots_url = urljoin(origin, "/robots.txt")
        try:
            resp = await http.get(robots_url, use_cache=True)
            rp.parse(resp.text.splitlines() if resp.status < 400 else [])
        except Exception as exc:  # noqa: BLE001 - robots is best-effort
            log.debug(f"robots.txt unavailable for {origin}: {exc!r}")
            rp.parse([])
        self._parsers[origin] = rp

    def allowed(self, url: str) -> bool:
        origin = "{0.scheme}://{0.netloc}".format(urlparse(url))
        rp = self._parsers.get(origin)
        if rp is None:
            return True
        return rp.can_fetch(self._ua, url)



class Crawler:
    def __init__(self, http: HttpClient, scope: Scope, cfg: CrawlerConfig,
                 robots: RobotsPolicy | None = None,
                 browser_discovery=None) -> None:
        self._http = http
        self._scope = scope
        self._cfg = cfg
        self._robots = robots
        self._browser = browser_discovery
        self._seen_pages: set[str] = set()
        self._seen_surfaces: set[str] = set()

    async def crawl(self, seed: str) -> list[Form]:
        if self._robots and self._cfg.respect_robots:
            await self._robots.load(seed, self._http)

        base_domain = urlparse(seed).netloc
        queue: list[tuple[str, int]] = [(canonicalize(seed), 0)]
        forms: list[Form] = []
        
        while queue and len(self._seen_pages) < self._cfg.max_pages:
            # Process a batch of pages concurrently.            
            wave, queue = queue[:self._cfg.max_pages], queue[self._cfg.max_pages:]
            tasks = [self._visit(u, d, base_domain) for u, d in wave
                     if self._should_visit(u, d)]
            for result in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(result, Exception):
                    log.debug(f"crawl task error: {result!r}")
                    continue
                page_forms, new_links = result
                forms.extend(page_forms)
                queue.extend(new_links)

        log.info(f"crawl complete: {len(self._seen_pages)} pages, "
                 f"{len(forms)} forms/endpoints")
        return forms

    def _should_visit(self, url: str, depth: int) -> bool:
        if depth > self._cfg.max_depth:
            return False

        if url in self._seen_pages:
            return False

        if not self._scope.is_in_scope(url):
            return False

        if any(h in url.lower() for h in _NOISE_LINK_HINTS):
            return False

        if (
            self._robots
            and self._cfg.respect_robots
            and not self._robots.allowed(url)
        ):
            return False

        return True

    async def _visit(self, url: str, depth: int, base_domain: str):
        self._seen_pages.add(url)
        forms: list[Form] = []
        new_links: list[tuple[str, int]] = []
        try:
            resp = await self._http.get(url)
        except Exception as exc:  # noqa: BLE001
            log.debug(f"fetch failed {url}: {exc!r}")
            return forms, new_links

        if "html" not in resp.headers.get("content-type", "text/html"):
            return forms, new_links

        for form in extract_forms(url, resp.text):
            sig = param_signature(form.action) + "|" + form.method
            if sig not in self._seen_surfaces:
                self._seen_surfaces.add(sig)
                forms.append(form)

        if self._browser is not None:
            for form in await self._browser.discover_forms(url):
                sig = param_signature(form.action) + "|js"
                if sig not in self._seen_surfaces:
                    self._seen_surfaces.add(sig)
                    forms.append(form)

        soup = BeautifulSoup(resp.text, "html.parser")
        for link in soup.find_all("a", href=True):
            full = urljoin(url, link["href"])
            if urlparse(full).netloc != base_domain:
                continue
            canon = canonicalize(full)

            # Treat parameterized links as fuzzable GET endpoints.
            if self._cfg.discover_query_params:
                gf = synthesize_get_form(full)
                if gf is not None:
                    sig = param_signature(gf.action) + "|GET"
                    if sig not in self._seen_surfaces:
                        self._seen_surfaces.add(sig)
                        forms.append(gf)

            if canon not in self._seen_pages:
                new_links.append((canon, depth + 1))

        return forms, new_links

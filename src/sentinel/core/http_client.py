"""Centralised async HTTP client.

Every outbound request in the framework goes through ``HttpClient``. This is
where cross-cutting concerns live so individual plugins stay simple:

* **Scope enforcement** - ``scope.assert_in_scope`` runs before the socket is
  ever touched. This is the hard ethical boundary.
* **Rate limiting** - a token bucket caps global requests/second so we behave
  politely and predictably against the target.
* **Retries with backoff** - transient network/5xx errors are retried.
* **Timeouts** - every request is bounded.
* **GET caching** - idempotent GETs are cached for the scan lifetime, which
  massively cuts traffic during crawling and baseline comparisons.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from sentinel.core.config import ScannerConfig
from sentinel.core.scope import Scope
from sentinel.logging_setup import log


@dataclass
class _TokenBucket:
    rate: float
    capacity: float
    _tokens: float = field(init=False)
    _last: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        self._tokens = self.capacity
        self._last = time.monotonic()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self.capacity,
                                   self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self.rate)


@dataclass
class Response:
    """Minimal response wrapper so plugins do not depend on httpx directly."""

    status: int
    text: str
    headers: dict[str, str]
    elapsed: float
    url: str

    def __len__(self) -> int:
        return len(self.text)


class HttpClient:
    def __init__(self, cfg: ScannerConfig, scope: Scope) -> None:
        self._cfg = cfg
        self._scope = scope
        self._bucket = _TokenBucket(rate=cfg.rate_limit,
                                    capacity=max(1.0, cfg.rate_limit))
        self._sem = asyncio.Semaphore(cfg.concurrency)
        self._cache: dict[tuple[str, str], Response] = {}
        self._client = httpx.AsyncClient(
        timeout=cfg.timeout,
        follow_redirects=True,
        headers={"User-Agent": cfg.user_agent},
        )

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def set_auth(self, headers: dict[str, str] | None,
                 cookies: dict[str, str] | None) -> None:
        if headers:
            self._client.headers.update(headers)
        if cookies:
            self._client.cookies.update(cookies)

    async def request(self, method: str, url: str, *,
                      params: dict[str, Any] | None = None,
                      data: dict[str, Any] | None = None,
                      use_cache: bool = True,
                      **kwargs: Any) -> Response:
        # --- ethical hard stop -------------------------------------------------
        self._scope.assert_in_scope(url)

        method = method.upper()
        cacheable = method == "GET" and self._cfg.cache and use_cache and not data
        cache_key = (url, str(sorted((params or {}).items())))
        if cacheable and cache_key in self._cache:
            return self._cache[cache_key]

        last_exc: Exception | None = None
        for attempt in range(self._cfg.retries + 1):
            await self._bucket.acquire()
            async with self._sem:
                start = time.monotonic()
                try:
                    r = await self._client.request(
                        method, url, params=params, data=data, **kwargs
                    )
                    resp = Response(
                        status=r.status_code,
                        text=r.text,
                        headers=dict(r.headers),
                        elapsed=time.monotonic() - start,
                        url=str(r.url),
                    )
                    if cacheable and r.status_code < 500:
                        self._cache[cache_key] = resp
                    return resp
                except (httpx.TransportError, httpx.TimeoutException) as exc:
                    last_exc = exc
                    backoff = 0.5 * (2 ** attempt)
                    log.warning(f"{method} {url} failed ({exc!r}); "
                                f"retry {attempt + 1} in {backoff:.1f}s")
                    await asyncio.sleep(backoff)

        raise RuntimeError(f"Request to {url} failed after retries: {last_exc!r}")

    async def get(self, url: str, **kw: Any) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> Response:
        return await self.request("POST", url, **kw)

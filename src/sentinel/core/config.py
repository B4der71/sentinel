"""Typed configuration loaded from YAML with environment-independent defaults.

We parse YAML into nested dataclasses rather than passing dicts around so that
the rest of the code gets autocompletion and type-checking, and an invalid key
fails loudly at load time instead of silently doing nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a declared dependency
    yaml = None  # type: ignore


@dataclass
class ScannerConfig:
    concurrency: int = 10
    timeout: float = 20.0
    rate_limit: float = 5.0          # max requests/second across the whole scan
    retries: int = 2
    user_agent: str = "Sentinel/0.1 (+authorized-security-testing)"
    cache: bool = True
    allow_aggressive: bool = False


@dataclass
class CrawlerConfig:
    enabled: bool = False
    max_depth: int = 3
    max_pages: int = 200
    respect_robots: bool = False
    discover_query_params: bool = True


@dataclass
class AuthConfig:
    type: str = "none"               # none | form | cookie | bearer | header
    login_url: str | None = None
    username: str | None = None
    password: str | None = None
    username_field: str = "username"
    password_field: str = "password"
    token: str | None = None         # bearer token or api key value
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Config:
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    plugins: dict[str, bool] = field(
        default_factory=lambda: {"xss": True, "sqli": True, "headers": True,
                                 "cors": True, "redirect": True}
    )

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        if path is None:
            return cls()
        if yaml is None:
            raise RuntimeError("PyYAML is required to load config files")
        data: dict[str, Any] = yaml.safe_load(Path(path).read_text()) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        return cls(
            scanner=ScannerConfig(**(data.get("scanner") or {})),
            crawler=CrawlerConfig(**(data.get("crawler") or {})),
            auth=AuthConfig(**(data.get("auth") or {})),
            plugins=data.get("plugins") or Config().plugins,
        )

    def enabled_plugins(self) -> set[str]:
        return {name for name, on in self.plugins.items() if on}

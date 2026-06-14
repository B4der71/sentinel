"""Scope enforcement and safety controls.

This is the single most important module from an ethics standpoint. Nothing in
the framework is allowed to send a request to a host that has not been
explicitly placed in scope. The HTTP client calls ``Scope.assert_in_scope``
before *every* request, so a misbehaving plugin physically cannot reach an
out-of-scope target.

Design choices:
* Default-deny. An empty allow-list blocks everything.
* Scope is host-based with optional path prefixes; no wildcards by default.
* Aggressive techniques (time-based blind SQLi, file upload, command-injection
  probes) are gated behind an explicit opt-in flag so a casual run cannot fire
  destructive payloads.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


class OutOfScopeError(Exception):
    """Raised when any component attempts to touch an unapproved target."""


@dataclass
class Scope:
    allowed_hosts: set[str] = field(default_factory=set)
    allowed_path_prefixes: list[str] = field(default_factory=list)
    allow_aggressive: bool = False

    @classmethod
    def from_seed(cls, seed_url: str, allow_aggressive: bool = False) -> "Scope":
        host = urlparse(seed_url).netloc
        if not host:
            raise ValueError(f"Cannot derive scope host from URL: {seed_url!r}")
        return cls(
            allowed_hosts={host},
            allow_aggressive=allow_aggressive,
        )

    def is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.netloc

        if host not in self.allowed_hosts:
            return False

        if self.allowed_path_prefixes:
            return any(
                parsed.path.startswith(prefix)
                for prefix in self.allowed_path_prefixes
            )

        return True

    def assert_in_scope(self, url: str) -> None:
        if not self.is_in_scope(url):
            raise OutOfScopeError(
                f"Refusing request to out-of-scope target: {url}. "
                f"Add its host to the scope allow-list to proceed."
            )

    def assert_aggressive_allowed(self, technique: str) -> None:
        if not self.allow_aggressive:
            raise OutOfScopeError(
                f"Technique '{technique}' is potentially disruptive and is "
                f"disabled. Re-run with allow_aggressive=true to enable it."
            )

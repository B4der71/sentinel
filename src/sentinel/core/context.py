"""The context object handed to every plugin.

It bundles the shared services a plugin needs (HTTP client, scope, config) plus
a sink for emitting findings. Plugins receive a context and a target form; they
never construct their own HTTP client, which is what guarantees rate-limiting
and scope enforcement apply uniformly.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.core.config import Config
from sentinel.core.http_client import HttpClient
from sentinel.core.scope import Scope
from sentinel.models import Finding


@dataclass
class ScanContext:
    http: HttpClient
    scope: Scope
    config: Config
    findings: list[Finding] = field(default_factory=list)
    browser: object | None = None    # optional BrowserEngine for verification

    def report(self, finding: Finding) -> None:
        self.findings.append(finding)

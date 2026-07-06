"""Plugin contract.

Every vulnerability detector subclasses ``Plugin`` and implements ``run`` for a
single discovered form. The base class provides:

* ``id`` / ``name`` / ``default_severity`` metadata
* an ``aggressive`` flag so disruptive plugins self-gate against scope
* a ``baseline`` helper to fetch the unperturbed response once and reuse it

This is the Open/Closed seam of the framework: adding a vulnerability class
means adding a Plugin subclass and registering it - no changes to the engine.
"""
from __future__ import annotations

import abc

from sentinel.core.context import ScanContext
from sentinel.core.http_client import Response
from sentinel.models import Form, Severity
from sentinel.logging_setup import log

class Plugin(abc.ABC):
    # ---------- Required ----------
    id: str = "base"
    name: str = "Base Plugin"

    # ---------- Optional Metadata ----------
    description: str = "No description provided."
    author: str = "Bader Alwashah (B4der71)"

    category: str = "General"

    tags: tuple[str, ...] = ()

    default_severity: Severity = Severity.MEDIUM

    aggressive: bool = False             # Requires scope.allow_aggressive

    requires_browser: bool = False
    requires_authentication: bool = False

    enabled_by_default: bool = True         

    def __init__(self) -> None:
        self.log = log.bind(plugin=self.id)

    @abc.abstractmethod
    async def run(self, ctx: ScanContext, form: Form) -> None:
        """Inspect a single form/endpoint and report any findings."""

    async def baseline(self, ctx: ScanContext, form: Form) -> Response:
        data = form.baseline_data()
        if form.method == "POST":
            return await ctx.http.post(form.action, data=data)
        return await ctx.http.get(form.action, params=data)

    def can_run(self, ctx: ScanContext) -> bool:
        if self.aggressive and not ctx.scope.allow_aggressive:
            self.log.info(f"skipping aggressive plugin '{self.id}' "
                          "(allow_aggressive disabled)")
            return False
        return True

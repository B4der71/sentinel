"""Structured logging.

Uses loguru when available (nice structured/coloured output and trivial file
sinks) and falls back to the stdlib so the framework still runs in a minimal
environment. Everything in the codebase imports ``log`` from here.
"""
from __future__ import annotations

import sys

try:
    from loguru import logger as _logger

    def configure(level: str = "INFO", logfile: str | None = None) -> None:
        _logger.remove()
        _logger.add(sys.stderr, level=level,
                    format="<green>{time:HH:mm:ss}</green> "
                           "<level>{level: <8}</level> "
                           "<cyan>{extra[plugin]}</cyan> {message}")
        if logfile:
            _logger.add(logfile, level="DEBUG", serialize=True)

    log = _logger.bind(plugin="-")

except ImportError:  # pragma: no cover
    import logging

    def configure(level: str = "INFO", logfile: str | None = None) -> None:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
            datefmt="%H:%M:%S",
        )

    class _Shim:
        _l = logging.getLogger("sentinel")

        def bind(self, **_: object) -> "_Shim":
            return self

        def __getattr__(self, name: str):
            return getattr(self._l, name)

    log = _Shim()

"""Plugin manager.

Resolves the set of enabled plugins from config against the registry. Kept
deliberately small; discovery is explicit (registry dict) rather than magic
import scanning, which keeps load order deterministic and makes a missing
plugin a clear error. A future ``entry_points``-based loader can replace this
without touching the engine.
"""
from __future__ import annotations

from sentinel.core.config import Config
from sentinel.logging_setup import log
from sentinel.plugins import ALL_PLUGINS, Plugin


class PluginManager:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._plugins: list[Plugin] = []

    def load(self) -> list[Plugin]:
        enabled = self._config.enabled_plugins()
        unknown = enabled - set(ALL_PLUGINS)
        if unknown:
            raise ValueError(f"Unknown plugins enabled in config: {sorted(unknown)}")
        self._plugins = [ALL_PLUGINS[name]() for name in ALL_PLUGINS
                         if name in enabled]
        log.info(f"loaded plugins: {[p.id for p in self._plugins]}")
        return self._plugins

    @property
    def plugins(self) -> list[Plugin]:
        return self._plugins

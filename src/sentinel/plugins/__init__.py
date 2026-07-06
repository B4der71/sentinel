"""
Automatic plugin registry.

Every module inside sentinel.plugins that defines a subclass of Plugin
is automatically discovered and registered.

Adding a new plugin now only requires creating a new *.py file.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from sentinel.plugins.base import Plugin

ALL_PLUGINS: dict[str, type[Plugin]] = {}


def _discover_plugins() -> None:
    package = __name__

    for _, module_name, is_pkg in pkgutil.iter_modules(__path__):
        if is_pkg:
            continue

        if module_name in {"base"}:
            continue

        module = importlib.import_module(f"{package}.{module_name}")

        for _, obj in inspect.getmembers(module, inspect.isclass):

            if obj is Plugin:
                continue

            if not issubclass(obj, Plugin):
                continue

            if not getattr(obj, "id", None):
                raise ValueError(
                    f"{obj.__name__} does not define plugin id"
                )

            if obj.id in ALL_PLUGINS:
                raise ValueError(
                    f"Duplicate plugin id '{obj.id}'"
                )

            ALL_PLUGINS[obj.id] = obj


_discover_plugins()

__all__ = ["Plugin", "ALL_PLUGINS"]
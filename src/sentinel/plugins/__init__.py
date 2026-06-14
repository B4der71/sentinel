"""Plugin registry. Importing a plugin here makes it discoverable by the
PluginManager. Adding a new vulnerability module = add its class to ALL_PLUGINS.
"""
from sentinel.plugins.base import Plugin
from sentinel.plugins.xss import XssPlugin
from sentinel.plugins.sqli import SqliPlugin
from sentinel.plugins.headers import HeadersPlugin
from sentinel.plugins.cors import CorsPlugin
from sentinel.plugins.redirect import OpenRedirectPlugin

ALL_PLUGINS: dict[str, type[Plugin]] = {
    XssPlugin.id: XssPlugin,
    SqliPlugin.id: SqliPlugin,
    HeadersPlugin.id: HeadersPlugin,
    CorsPlugin.id: CorsPlugin,
    OpenRedirectPlugin.id: OpenRedirectPlugin,
}

__all__ = ["Plugin", "ALL_PLUGINS"]

"""Integration test against a local, in-process deliberately-vulnerable app.

This proves the full pipeline (crawl -> plugins -> dedup -> findings) works
end-to-end without touching any external host. The mock app reflects a
``name`` parameter un-encoded (reflected XSS) and emits a MySQL error when a
quote appears in ``id`` (error-based SQLi), and ships no security headers.
"""
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from sentinel.core.config import Config
from sentinel.core.engine import Engine


class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):  # silence
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        body = "<html><body>"
        if parsed.path == "/":
            body += ('<a href="/reflect?name=hi">x</a>'
                     '<a href="/item?id=1">y</a>')
        elif parsed.path == "/reflect":
            name = qs.get("name", [""])[0]
            body += f"<div>Hello {name}</div>"        # reflected, un-encoded
        elif parsed.path == "/item":
            idv = qs.get("id", [""])[0]
            if "'" in idv:
                body += "You have an error in your SQL syntax; MySQL server"
            else:
                body += f"Item {idv}"
        body += "</body></html>"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _VulnHandler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}/"
    httpd.shutdown()


def test_end_to_end(server):
    cfg = Config()
    cfg.plugins = {"xss": True, "sqli": True, "headers": True}
    cfg.crawler.respect_robots = False
    findings = asyncio.run(Engine(cfg).scan(server))

    names = {f.name for f in findings}
    assert "Reflected Cross-Site Scripting" in names
    assert "SQL Injection" in names
    # security-header findings should also appear
    assert any("Missing Security Header" in n for n in names)

    xss = next(f for f in findings if f.name == "Reflected Cross-Site Scripting")
    assert xss.parameter == "name"
    sqli = next(f for f in findings if f.name == "SQL Injection")
    assert sqli.parameter == "id"

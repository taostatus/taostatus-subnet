"""The reference agent's explorer crawls the running app and maps its real attack
surface: endpoints from links/forms/JS, parameters from queries/form-fields, ids
collapsed to their endpoint, external hosts ignored, bounded.
"""

import importlib.util
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_AGENT_PATH = os.path.join(os.path.dirname(__file__), "..", "secqurityVali",
                           "agents", "reference_sqli", "agent.py")

_PAGES = {
    "/": """<html>
        <a href="/api/notes?q=1">notes</a>
        <a href="/dashboard">dash</a>
        <a href="https://evil.com/steal">external</a>
        <form action="/login"><input name="email"><input name="password"></form>
        <script>fetch("/api/orders")</script>
      </html>""",
    "/dashboard": '<a href="/api/profile/7">profile</a>',
}


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = _PAGES.get(self.path.split("?")[0], "{}").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        return


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def _load_agent():
    spec = importlib.util.spec_from_file_location("ref_agent_crawl", _AGENT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_crawler_maps_the_surface(monkeypatch):
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), _H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("TARGET_URL", f"http://127.0.0.1:{port}")
        agent = _load_agent()
        endpoints, params = agent._crawl()

        # endpoints from links, JS fetch, forms, and an id-bearing path (id stripped)
        assert "/api/notes" in endpoints
        assert "/api/orders" in endpoints          # from the <script>fetch(...)</script>
        assert "/dashboard" in endpoints
        assert "/login" in endpoints               # from the form action
        assert "/api/profile" in endpoints         # /api/profile/7 -> endpoint

        # params from the query string and the form fields
        assert "q" in params and "email" in params and "password" in params

        # the external host is NEVER crawled
        assert all("evil.com" not in e for e in endpoints)
    finally:
        server.shutdown()


def test_crawler_mines_api_routes_from_the_js_bundle(monkeypatch):
    # a Next.js-style SPA: the HTML shell just loads a JS bundle; the real API
    # routes exist ONLY inside that JS (exactly what the agent used to miss).
    port = _free_port()
    spa = {
        "/": '<!doctype html><html><head>'
             '<script src="/_next/static/chunks/app.js"></script></head>'
             '<body><div id="__next"></div></body></html>',
        "/_next/static/chunks/app.js":
            'const a=fetch("/api/orders");const b="/api/users/"+id;'
            'axios.get(`/api/profile/${uid}`);const skip="/_next/static/x.js";'
            'const img="/static/logo.png";',
    }

    class _Spa(BaseHTTPRequestHandler):
        def do_GET(self):
            body = spa.get(self.path.split("?")[0], "{}").encode()
            ctype = "application/javascript" if self.path.endswith(".js") else "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), _Spa)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("TARGET_URL", f"http://127.0.0.1:{port}")
        agent = _load_agent()
        endpoints, _ = agent._crawl(max_pages=5)
        assert "/api/orders" in endpoints          # from fetch("/api/orders")
        assert "/api/users" in endpoints           # from "/api/users/"+id
        assert "/api/profile" in endpoints         # from backtick `/api/profile/${uid}`
        assert all("_next" not in e and "static" not in e for e in endpoints)  # assets skipped
    finally:
        server.shutdown()


def test_crawler_is_bounded_and_safe(monkeypatch):
    # a page that links to itself with ever-growing ids must not loop forever
    port = _free_port()

    class _Loop(BaseHTTPRequestHandler):
        def do_GET(self):
            n = 0
            try:
                n = int(self.path.strip("/x") or "0")
            except ValueError:
                n = 0
            body = f'<a href="/x{n + 1}">next</a>'.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), _Loop)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("TARGET_URL", f"http://127.0.0.1:{port}")
        agent = _load_agent()
        endpoints, params = agent._crawl(max_pages=10)
        assert len(endpoints) <= 12               # capped, did not loop forever
    finally:
        server.shutdown()

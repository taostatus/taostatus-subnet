"""Precise edge-case tests for the audit egress proxy (secqurityVali/egress_proxy.py).

The proxy is the agent's ONLY path out, so its security properties are asserted
here against a loopback mock target: it forwards faithfully, it only ever dials
the pinned target (the agent's Host/URI can never redirect it), it never follows
redirects, it caps abuse, and it refuses a non-public target. Stdlib only.
"""

import http.client
import threading
import time

import pytest

from secqurityVali import egress_proxy as ep
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# --- a mock "customer target" that records what it receives -------------

class _MockState:
    def __init__(self):
        self.seen = []            # list of {method, path, host, body, headers}
        self.lock = threading.Lock()


def _make_mock():
    state = _MockState()

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a): pass

        def _record_and_route(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            with state.lock:
                state.seen.append({
                    "method": self.command, "path": self.path,
                    "host": self.headers.get("Host"), "body": body,
                    "has_connection_hdr": self.headers.get("Connection") is not None,
                    "has_te_hdr": self.headers.get("Transfer-Encoding") is not None,
                })
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "http://evil.example/secret")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/slow":
                time.sleep(2.0)
            payload = body if self.path == "/echo" else b"CANARY"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Seen-Host", self.headers.get("Host", ""))
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _record_and_route
        do_POST = _record_and_route

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, state


def _start_proxy(target_port, **overrides):
    cfg_kwargs = dict(
        target_ip="127.0.0.1", target_port=target_port, target_host="target.local",
        listen_host="127.0.0.1", listen_port=0, rate_per_sec=0,  # rate off unless a test sets it
    )
    cfg_kwargs.update(overrides)
    cfg = ep.ProxyConfig(**cfg_kwargs)
    srv = ep.make_server(cfg, require_public_target=False)   # loopback mock, test only
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture()
def proxy():
    mock, state = _make_mock()
    servers = []

    def _make(**overrides):
        srv = _start_proxy(mock.server_address[1], **overrides)
        servers.append(srv)
        return srv, state

    yield _make
    for s in servers:
        s.shutdown()
    mock.shutdown()


def _req(srv, method, path, body=None, headers=None):
    port = srv.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse()
    data = r.read()
    out = (r.status, dict(r.getheaders()), data)
    conn.close()
    return out


# --- forwarding correctness --------------------------------------------

def test_forwards_faithfully(proxy):
    srv, state = proxy()
    status, _, body = _req(srv, "GET", "/canary")
    assert status == 200 and body == b"CANARY"
    assert state.seen[-1]["path"] == "/canary" and state.seen[-1]["method"] == "GET"


def test_post_body_is_forwarded(proxy):
    srv, state = proxy()
    status, _, body = _req(srv, "POST", "/echo", body=b"id=1' OR '1'='1")
    assert status == 200 and body == b"id=1' OR '1'='1"
    assert state.seen[-1]["body"] == b"id=1' OR '1'='1"


def test_query_string_is_preserved(proxy):
    srv, state = proxy()
    _req(srv, "GET", "/canary?q=1%27--")
    assert state.seen[-1]["path"] == "/canary?q=1%27--"


# --- the security core: destination is FIXED ---------------------------

def test_agent_host_header_cannot_redirect_the_proxy(proxy):
    """Whatever Host the agent sends, the proxy rewrites it to the pinned target
    and still dials only the pinned upstream -- no SSRF-by-Host."""
    srv, state = proxy()
    status, hdrs, _ = _req(srv, "GET", "/canary", headers={"Host": "evil.example"})
    assert status == 200
    assert state.seen[-1]["host"] == "target.local"      # proxy set it, not "evil.example"
    assert hdrs.get("X-Seen-Host") == "target.local"


def test_does_not_follow_redirects(proxy):
    """A 3xx from the target is returned verbatim; the proxy must not chase it."""
    srv, state = proxy()
    status, hdrs, _ = _req(srv, "GET", "/redirect")
    assert status == 302
    assert hdrs.get("Location") == "http://evil.example/secret"
    # the proxy never fetched the redirect target
    assert all(s["path"] != "/secret" for s in state.seen)


def test_hop_by_hop_headers_are_stripped(proxy):
    srv, state = proxy()
    _req(srv, "GET", "/canary", headers={"Connection": "x", "Transfer-Encoding": "chunked"})
    assert state.seen[-1]["has_connection_hdr"] is False
    assert state.seen[-1]["has_te_hdr"] is False


# --- caps / abuse ------------------------------------------------------

def test_total_request_cap(proxy):
    srv, state = proxy(max_requests=3)
    codes = [_req(srv, "GET", "/canary")[0] for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert sum(1 for s in state.seen if s["path"] == "/canary") == 3   # only 3 reached target


def test_body_size_cap(proxy):
    srv, state = proxy(max_body_bytes=16)
    status, _, _ = _req(srv, "POST", "/echo", body=b"x" * 64)
    assert status == 413
    assert state.seen == []                      # oversized body never reached the target


def test_rate_limit_blocks_bursts(proxy):
    srv, state = proxy(rate_per_sec=1, rate_burst=2)
    codes = [_req(srv, "GET", "/canary")[0] for _ in range(6)]
    assert codes.count(200) <= 3                 # ~burst passes, the rest are 429
    assert 429 in codes


def test_upstream_down_is_502_and_counted(proxy):
    # point the proxy at a closed port (nothing listening)
    srv = _start_proxy(1)                         # port 1: refused
    status, _, _ = _req(srv, "GET", "/canary")
    assert status == 502
    assert srv.stats.snapshot()["error_count"] == 1
    srv.shutdown()


# --- refuse-to-start on a bad target -----------------------------------

def test_refuses_private_target_by_default():
    for ip in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.0.1"):
        cfg = ep.ProxyConfig(target_ip=ip, target_port=80, target_host="t")
        with pytest.raises(ep.TargetNotAllowed):
            ep.make_server(cfg)                  # require_public_target defaults True


def test_refuses_bad_scheme():
    cfg = ep.ProxyConfig(target_ip="1.2.3.4", target_port=80, target_host="t", target_scheme="ftp")
    with pytest.raises(ValueError):
        ep.make_server(cfg)


def test_allows_a_public_target():
    cfg = ep.ProxyConfig(target_ip="1.2.3.4", target_port=443, target_host="t", target_scheme="https")
    srv = ep.make_server(cfg)                    # no raise
    srv.server_close()


# --- measurement -------------------------------------------------------

def test_stats_count_forwards_and_statuses(proxy):
    srv, state = proxy()
    _req(srv, "GET", "/canary")
    _req(srv, "GET", "/canary")
    _req(srv, "GET", "/redirect")                # a 3xx
    snap = srv.stats.snapshot()
    assert snap["request_count"] == 3
    assert snap["status_counts"].get("2xx") == 2 and snap["status_counts"].get("3xx") == 1
    assert snap["error_count"] == 0

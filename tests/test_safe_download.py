"""safe_download (target_guard) closes the check-vs-use / DNS-rebind gap:

validate_target pins the host's IP, and safe_download must DIAL THAT PINNED IP
and never re-resolve the hostname -- so a low-TTL record cannot flip to an
internal/metadata address between the SSRF check and the fetch. These tests pin
down: (1) it dials the pinned public IP (not the hostname), with the right Host;
(2) an unsafe host is refused before any socket is opened; (3) redirects are
refused (a 3xx cannot bounce the fetch to an unvalidated host).
"""

import pytest

from secqurityVali import target_guard
from secqurityVali.target_guard import TargetRejected, safe_download


class _FakeResp:
    def __init__(self, body: bytes, status: int = 200):
        self.status = status
        self._parts = [body, b""] if body else [b""]

    def read(self, _n):
        return self._parts.pop(0) if self._parts else b""


class _FakeConn:
    last: dict = {}

    def __init__(self, host, port, timeout=None, context=None):
        _FakeConn.last = {"host": host, "port": port, "headers": {}}
        self.sock = None

    def putrequest(self, method, path, **_kw):
        _FakeConn.last["method"] = method
        _FakeConn.last["path"] = path

    def putheader(self, k, v):
        _FakeConn.last["headers"][k] = v

    def endheaders(self):
        pass

    def getresponse(self):
        return _FakeResp(b"BLOBDATA")

    def close(self):
        pass


def test_dials_pinned_ip_never_reresolves(monkeypatch):
    captured = {}

    def fake_create_connection(addr, timeout=None):
        captured["addr"] = addr
        return object()  # raw socket stand-in (http path, no TLS wrap)

    monkeypatch.setattr(target_guard.socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(target_guard.http.client, "HTTPConnection", _FakeConn)

    body = safe_download(
        "http://miner.example:8912/agent.enc",
        max_bytes=1 << 20, timeout=5,
        resolve=lambda _host: ["1.2.3.4"],   # the ONE resolution; pinned
    )
    assert body == b"BLOBDATA"
    # The socket was opened to the PINNED public IP:port, not the hostname.
    assert captured["addr"] == ("1.2.3.4", 8912)
    # Host header carries the hostname (+ non-default port), not the IP.
    assert _FakeConn.last["headers"]["Host"] == "miner.example:8912"
    assert _FakeConn.last["path"] == "/agent.enc"


def test_unsafe_host_refused_before_any_dial(monkeypatch):
    dialed = {"yes": False}

    def fake_create_connection(addr, timeout=None):
        dialed["yes"] = True
        return object()

    monkeypatch.setattr(target_guard.socket, "create_connection", fake_create_connection)

    for ip in ("127.0.0.1", "169.254.169.254", "10.0.0.5"):
        with pytest.raises(TargetRejected):
            safe_download("http://evil.example/agent.enc",
                          max_bytes=1 << 20, timeout=5, resolve=lambda _h, ip=ip: [ip])
    assert dialed["yes"] is False   # never opened a socket to an internal address


def test_redirect_is_refused(monkeypatch):
    class _RedirConn(_FakeConn):
        def getresponse(self):
            return _FakeResp(b"", status=302)

    monkeypatch.setattr(target_guard.socket, "create_connection",
                        lambda _a, timeout=None: object())
    monkeypatch.setattr(target_guard.http.client, "HTTPConnection", _RedirConn)

    with pytest.raises(ValueError):
        safe_download("http://miner.example/agent.enc",
                      max_bytes=1 << 20, timeout=5, resolve=lambda _h: ["1.2.3.4"])


def test_oversize_body_is_rejected(monkeypatch):
    class _BigResp:
        status = 200

        def __init__(self):
            self._n = 3

        def read(self, _n):
            if self._n > 0:
                self._n -= 1
                return b"x" * 1024
            return b""

    class _BigConn(_FakeConn):
        def getresponse(self):
            return _BigResp()

    monkeypatch.setattr(target_guard.socket, "create_connection",
                        lambda _a, timeout=None: object())
    monkeypatch.setattr(target_guard.http.client, "HTTPConnection", _BigConn)

    with pytest.raises(ValueError):
        safe_download("http://miner.example/agent.enc",
                      max_bytes=2048, timeout=5, resolve=lambda _h: ["1.2.3.4"])

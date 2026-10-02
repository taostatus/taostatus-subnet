from __future__ import annotations

"""secqurityVali/egress_proxy.py - the audit agent's single, locked egress path.

During a real-target audit the agent runs on a docker `--internal` network with
no route anywhere but to this proxy (kernel-enforced). The proxy forwards the
agent's HTTP requests to ONE pinned target (IP + port + scheme, fixed when the
proxy starts) and nothing else, measures every request, and returns the target's
responses faithfully -- the SQLi grading depends on the agent seeing the real
response differences.

It is the trusted counterpart to the kernel isolation: the agent cannot reach
the internet, cloud metadata, the host or any other host, and even what it sends
here can only ever go to the one target this proxy was started for.

Hard rules (each has a matching edge-case test in tests/test_egress_proxy.py):
  * Destination is FIXED at startup. The agent's Host header or request URI
    NEVER choose where a request goes -- no open-proxy, no SSRF-by-Host.
  * Refuses to start if the pinned IP is private/loopback/link-local/reserved
    -- defence in depth behind the job-level target validation.
  * Never follows redirects: a 3xx from the target is returned verbatim, so the
    target cannot bounce the proxy onto another host.
  * Caps everything: total requests per run, request rate, body size,
    per-request timeout, concurrent connections -- the agent cannot DoS the
    target or the proxy.
  * Strips hop-by-hop headers and recomputes Content-Length; no chunked relay.
  * stdlib only, so it runs in a bare python image and is small enough to audit.
"""

import http.client
import ipaddress
import json
import os
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Headers that are connection-specific and must not be forwarded either way.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
})

# Methods the proxy will relay. Anything else is refused (no CONNECT tunnels).
ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"})


class TargetNotAllowed(Exception):
    """The pinned target IP is one the proxy must never dial."""


@dataclass
class ProxyConfig:
    target_ip: str
    target_port: int
    target_host: str                      # original hostname -> Host header / TLS SNI
    target_scheme: str = "http"           # http | https
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    max_requests: int = 20000             # hard cap of forwarded requests per run
    rate_per_sec: float = 200.0           # token-bucket refill; <=0 disables
    rate_burst: int = 200                 # token-bucket capacity
    max_body_bytes: int = 10 * 1024 * 1024
    req_timeout_s: float = 30.0
    max_concurrent: int = 32
    verify_tls: bool = False              # customer staging certs are often self-signed
    stats_path: str | None = None         # where to persist the measurement JSON

    def validate(self, *, require_public_target: bool = True) -> None:
        if self.target_scheme not in ("http", "https"):
            raise ValueError(f"bad target scheme {self.target_scheme!r}")
        ip = ipaddress.ip_address(self.target_ip)   # raises ValueError if not an IP
        if require_public_target and (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified
        ):
            raise TargetNotAllowed(
                f"refusing to proxy to non-public target {self.target_ip} "
                f"(private/loopback/link-local/reserved)"
            )


@dataclass
class Stats:
    forwarded: int = 0
    blocked: int = 0                      # refused by a cap (rate/count/body/concurrency)
    errors: int = 0                       # upstream connect/timeout/protocol failures
    status_counts: dict[str, int] = field(default_factory=dict)   # "2xx" -> n
    bytes_to_target: int = 0
    bytes_from_target: int = 0
    latency_ms_sum: float = 0.0
    started_at: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, *, status: int | None, latency_ms: float,
               sent: int, received: int, blocked: bool = False, error: bool = False) -> None:
        with self._lock:
            if blocked:
                self.blocked += 1
                return
            if error:
                self.errors += 1
                return
            self.forwarded += 1
            self.bytes_to_target += sent
            self.bytes_from_target += received
            self.latency_ms_sum += latency_ms
            if status is not None:
                key = f"{status // 100}xx"
                self.status_counts[key] = self.status_counts.get(key, 0) + 1

    def snapshot(self) -> dict:
        with self._lock:
            n = self.forwarded
            return {
                "request_count": self.forwarded,
                "blocked_count": self.blocked,
                "error_count": self.errors,
                "status_counts": dict(self.status_counts),
                "bytes_to_target": self.bytes_to_target,
                "bytes_from_target": self.bytes_from_target,
                "avg_latency_ms": round(self.latency_ms_sum / n, 2) if n else 0.0,
                "duration_s": round(time.time() - self.started_at, 2),
            }


class _TokenBucket:
    """Simple thread-safe token bucket for the request rate cap."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.capacity = max(1, burst)
        self.tokens = float(self.capacity)
        self.ts = time.monotonic()
        self._lock = threading.Lock()

    def take(self) -> bool:
        if self.rate <= 0:
            return True
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.rate)
            self.ts = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


def make_server(config: ProxyConfig, *, require_public_target: bool = True) -> ThreadingHTTPServer:
    """Build (but do not start) the proxy server. Raises TargetNotAllowed /
    ValueError if the pinned target is not a dial-able public IP.
    `require_public_target` is only loosened by the test suite, which must point
    the proxy at a loopback mock; production always keeps it True."""
    config.validate(require_public_target=require_public_target)
    server = ThreadingHTTPServer((config.listen_host, config.listen_port), _Handler)
    server.config = config                       # type: ignore[attr-defined]
    server.stats = Stats()                        # type: ignore[attr-defined]
    server.bucket = _TokenBucket(config.rate_per_sec, config.rate_burst)   # type: ignore[attr-defined]
    server.gate = threading.BoundedSemaphore(config.max_concurrent)         # type: ignore[attr-defined]
    return server


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # one implementation for every verb
    def do_GET(self):     self._relay()
    def do_POST(self):    self._relay()
    def do_PUT(self):     self._relay()
    def do_DELETE(self):  self._relay()
    def do_HEAD(self):    self._relay()
    def do_OPTIONS(self): self._relay()
    def do_PATCH(self):   self._relay()

    def log_message(self, *args):   # keep the proxy quiet; measurement is the record
        pass

    @property
    def cfg(self) -> ProxyConfig:
        return self.server.config   # type: ignore[attr-defined]

    @property
    def stats(self) -> Stats:
        return self.server.stats    # type: ignore[attr-defined]

    def _blocked(self, code: int, msg: str) -> None:
        self.stats.record(status=None, latency_ms=0, sent=0, received=0, blocked=True)
        self._respond(code, msg.encode(), {"Content-Type": "text/plain"})

    def _relay(self) -> None:
        cfg = self.cfg
        if self.command not in ALLOWED_METHODS:
            return self._blocked(405, "method not allowed")

        # concurrency cap
        gate = self.server.gate          # type: ignore[attr-defined]
        if not gate.acquire(blocking=False):
            return self._blocked(503, "too many concurrent requests")
        try:
            # total-request cap
            if self.stats.forwarded >= cfg.max_requests:
                return self._blocked(429, "request budget exhausted")
            # rate cap
            if not self.server.bucket.take():      # type: ignore[attr-defined]
                return self._blocked(429, "rate limit exceeded")

            # body with size cap
            length = int(self.headers.get("Content-Length") or 0)
            if length < 0 or length > cfg.max_body_bytes:
                return self._blocked(413, "request body too large")
            body = self.rfile.read(length) if length else b""

            # forward to the FIXED target -- never the agent's Host/URI
            fwd_headers = self._forward_headers()
            started = time.monotonic()
            try:
                status, resp_headers, resp_body = self._dial(fwd_headers, body)
            except Exception as exc:  # noqa: BLE001 - upstream problem, not a crash
                self.stats.record(status=None, latency_ms=0, sent=len(body), received=0, error=True)
                return self._respond(502, f"upstream error: {type(exc).__name__}".encode(),
                                     {"Content-Type": "text/plain"})
            latency_ms = (time.monotonic() - started) * 1000.0
            self.stats.record(status=status, latency_ms=latency_ms,
                              sent=len(body), received=len(resp_body))
            # HEAD must carry no body
            out_body = b"" if self.command == "HEAD" else resp_body
            self._respond(status, out_body, resp_headers)
        finally:
            gate.release()

    def _forward_headers(self) -> list[tuple[str, str]]:
        """Copy the agent's headers minus hop-by-hop ones, and set Host to the
        real target. Content-Length is recomputed by http.client from the body."""
        out = [(k, v) for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP]
        out.append(("Host", self.cfg.target_host))
        return out

    def _dial(self, headers: list[tuple[str, str]], body: bytes):
        """Open a fresh connection to the PINNED ip:port only and return
        (status, response_headers, response_body). Never follows redirects."""
        cfg = self.cfg
        if cfg.target_scheme == "https":
            ctx = ssl.create_default_context()
            if not cfg.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(cfg.target_ip, cfg.target_port,
                                               timeout=cfg.req_timeout_s, context=ctx)
        else:
            conn = http.client.HTTPConnection(cfg.target_ip, cfg.target_port,
                                              timeout=cfg.req_timeout_s)
        try:
            conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            for k, v in headers:
                conn.putheader(k, v)
            # Content-Length was stripped as hop-by-hop; set it from the body we
            # actually forward (low-level putrequest/endheaders don't add it).
            if body:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body if body else None)
            resp = conn.getresponse()
            # cap the response body too
            data = resp.read(self.cfg.max_body_bytes + 1)
            if len(data) > self.cfg.max_body_bytes:
                data = data[:self.cfg.max_body_bytes]
            resp_headers = [(k, v) for k, v in resp.getheaders()
                            if k.lower() not in HOP_BY_HOP]
            return resp.status, resp_headers, data
        finally:
            conn.close()

    def _respond(self, status: int, body: bytes, headers) -> None:
        try:
            self.send_response(status)
            items = headers.items() if hasattr(headers, "items") else headers
            for k, v in items:
                if k.lower() in HOP_BY_HOP:
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def write_stats(server: ThreadingHTTPServer) -> None:
    cfg: ProxyConfig = server.config         # type: ignore[attr-defined]
    if not cfg.stats_path:
        return
    try:
        tmp = cfg.stats_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(server.stats.snapshot(), fh)   # type: ignore[attr-defined]
        os.replace(tmp, cfg.stats_path)
    except OSError:
        pass


def _config_from_env() -> ProxyConfig:
    return ProxyConfig(
        target_ip=os.environ["PROXY_TARGET_IP"],
        target_port=int(os.environ["PROXY_TARGET_PORT"]),
        target_host=os.environ.get("PROXY_TARGET_HOST", os.environ["PROXY_TARGET_IP"]),
        target_scheme=os.environ.get("PROXY_TARGET_SCHEME", "http"),
        listen_port=int(os.environ.get("PROXY_LISTEN_PORT", "8080")),
        max_requests=int(os.environ.get("PROXY_MAX_REQUESTS", "20000")),
        rate_per_sec=float(os.environ.get("PROXY_RATE_PER_SEC", "200")),
        rate_burst=int(os.environ.get("PROXY_RATE_BURST", "200")),
        max_body_bytes=int(os.environ.get("PROXY_MAX_BODY_BYTES", str(10 * 1024 * 1024))),
        req_timeout_s=float(os.environ.get("PROXY_REQ_TIMEOUT_S", "30")),
        max_concurrent=int(os.environ.get("PROXY_MAX_CONCURRENT", "32")),
        verify_tls=os.environ.get("PROXY_VERIFY_TLS", "0") == "1",
        stats_path=os.environ.get("PROXY_STATS_PATH"),
    )


def main() -> None:  # pragma: no cover - the container entrypoint
    # Public-target enforcement is on by default. It is loosened only for a
    # customer-installed connector auditing an internal target (and by the test
    # harness), never for the open hosted path.
    require_public = os.environ.get("PROXY_ALLOW_PRIVATE_TARGET", "0") != "1"
    server = make_server(_config_from_env(), require_public_target=require_public)
    writer_stop = threading.Event()

    def _periodic():
        while not writer_stop.wait(2.0):
            write_stats(server)

    threading.Thread(target=_periodic, daemon=True).start()
    try:
        server.serve_forever()
    finally:
        writer_stop.set()
        write_stats(server)


if __name__ == "__main__":  # pragma: no cover
    main()

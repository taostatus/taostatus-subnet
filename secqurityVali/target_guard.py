from __future__ import annotations

"""secqurityVali/target_guard.py - validate a customer-supplied audit target.

Before the agent ever runs against a real target, the customer's `target_url`
must be proven safe to dial. A malicious (or mistaken) customer could point us at
an internal host, cloud metadata, or loopback to turn our sandbox into an SSRF
weapon -- so this is a hard security gate, not a convenience check.

What it enforces (each has a test in tests/test_target_guard.py):
  * scheme is http or https (no file://, gopher://, dict://, ...)
  * the host is parsed correctly even with userinfo (http://good@evil -> evil)
  * the host is RESOLVED, and EVERY resolved IP must be public and routable;
    one private/loopback/link-local/reserved/metadata IP rejects the target
    (a hostname can resolve to several IPs, or be flipped later -- DNS rebinding)
  * IP literals in any form are caught, because we check the RESOLVED IP, never
    the textual host (decimal/hex/octal all resolve to the real IP first)
  * IPv4-mapped IPv6 (::ffff:169.254.169.254) is unwrapped and re-checked
  * the resolved IP is PINNED and handed to the proxy, which dials that IP, so a
    later DNS change cannot move the connection (time-of-check == time-of-use)
  * port is in range; default 80/443 by scheme

`allow_private` is only ever set by a customer-installed connector auditing an
internal target (Model B); the open hosted path keeps it False.
"""

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

# Known cloud metadata endpoints -- also caught by the range checks below, but
# blocked explicitly so the intent is unmistakable.
METADATA_IPS = frozenset({"169.254.169.254", "100.100.100.200", "fd00:ec2::254"})


class TargetRejected(Exception):
    """The target is not a safe, dial-able public target."""


@dataclass(frozen=True)
class PinnedTarget:
    ip: str            # the resolved IP the proxy will dial (pinned)
    port: int
    scheme: str        # http | https
    host: str          # original hostname, for the Host header / TLS SNI


def _default_resolve(host: str) -> list[str]:
    """Resolve to the set of A/AAAA addresses. Raises on failure."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({ai[4][0] for ai in infos})


def _normalize(ip: ipaddress._BaseAddress):
    """Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) to the real IPv4, so a mapped
    metadata/private address cannot slip past the v4 range checks."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip.sixtofour is not None:
            return ip.sixtofour
    return ip


def _ip_is_public(ip_str: str) -> bool:
    """True only for a globally-routable public address. Everything else --
    private, loopback, link-local (incl. 169.254 metadata), reserved, multicast,
    unspecified, shared/CGNAT -- is rejected."""
    try:
        ip = _normalize(ipaddress.ip_address(ip_str))
    except ValueError:
        return False
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified):
        return False
    # is_global is the positive confirmation (False for CGNAT 100.64/10, etc.)
    return bool(ip.is_global)


def validate_target(url: str, *, resolve=None, allow_private: bool = False) -> PinnedTarget:
    """Validate `url` and return a PinnedTarget, or raise TargetRejected.

    `resolve(host) -> [ip, ...]` is injectable for tests; it defaults to a real
    DNS lookup. The returned PinnedTarget.ip is what the proxy must dial.
    """
    resolve = resolve or _default_resolve

    try:
        parts = urlsplit(url.strip())
    except (ValueError, AttributeError):
        raise TargetRejected("malformed URL")

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TargetRejected(f"scheme {scheme or '(none)'!r} not allowed (http/https only)")

    # .hostname is lowercased and excludes any userinfo (http://good@evil -> evil)
    try:
        host = parts.hostname
    except ValueError:
        raise TargetRejected("malformed host")
    if not host:
        raise TargetRejected("missing host")

    # port: explicit, or the scheme default. urlsplit raises ValueError on a bad
    # numeric port via .port; guard it.
    try:
        port = parts.port
    except ValueError:
        raise TargetRejected("invalid port")
    if port is None:
        port = DEFAULT_PORTS[scheme]
    if not (1 <= port <= 65535):
        raise TargetRejected(f"port {port} out of range")

    # resolve and require EVERY address to be public.
    try:
        ips = resolve(host)
    except Exception as exc:  # noqa: BLE001 - any resolution failure = unusable target
        raise TargetRejected(f"could not resolve host: {type(exc).__name__}")
    if not ips:
        raise TargetRejected("host did not resolve to any address")

    for ip in ips:
        if ip in METADATA_IPS:
            raise TargetRejected(f"target resolves to a metadata endpoint ({ip})")
        if not allow_private and not _ip_is_public(ip):
            raise TargetRejected(f"target resolves to a non-public address ({ip})")

    # pin the first resolved address (all passed the check).
    return PinnedTarget(ip=ips[0], port=port, scheme=scheme, host=host)


def _host_header(pinned: "PinnedTarget") -> str:
    """Host header value: hostname, plus the port when it is non-default (so the
    value matches what a normal client would send)."""
    default = DEFAULT_PORTS.get(pinned.scheme)
    if default is not None and pinned.port == default:
        return pinned.host
    return f"{pinned.host}:{pinned.port}"


def safe_download(url: str, *, max_bytes: int, timeout: float, resolve=None,
                  allow_private: bool = False) -> bytes:
    """SSRF-safe HTTP(S) GET of `url`, returning the (bounded) body bytes.

    This closes the check-vs-use / DNS-rebind gap that `validate_target` followed
    by a plain ``urlopen`` leaves open: validate_target resolves + pins the host,
    but urlopen would resolve AGAIN at fetch time, so a low-TTL record can flip
    to an internal / metadata address between the check and the fetch. Here we
    resolve exactly once (inside validate_target) and dial the PINNED IP, never
    re-resolving. The real hostname is presented as the Host header and TLS SNI
    (name-based vhosts answer; the certificate is verified against the hostname).
    Redirects are refused, since a 3xx Location is unvalidated and could bounce us
    to an internal host. The body is capped at max_bytes.

    Raises: TargetRejected (unsafe/unresolvable URL, caller's/miner's fault) or
    OSError/ValueError/ssl.SSLError (fetch failure). Never follows a redirect and
    never connects anywhere but the single validated public IP.
    """
    pinned = validate_target(url, resolve=resolve, allow_private=allow_private)
    parts = urlsplit(url.strip())
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    host_header = _host_header(pinned)

    if pinned.scheme == "https":
        ctx = ssl.create_default_context()  # verifies the cert against `host`
        conn = http.client.HTTPSConnection(pinned.host, pinned.port,
                                           timeout=timeout, context=ctx)
        raw = socket.create_connection((pinned.ip, pinned.port), timeout=timeout)
        # Dial the PINNED ip; present the hostname as SNI so http.client never
        # re-resolves and the right vhost/cert is selected.
        conn.sock = ctx.wrap_socket(raw, server_hostname=pinned.host)
    else:
        conn = http.client.HTTPConnection(pinned.host, pinned.port, timeout=timeout)
        conn.sock = socket.create_connection((pinned.ip, pinned.port), timeout=timeout)

    try:
        # skip_host: we set Host ourselves (to the hostname, not the pinned IP).
        conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host_header)
        conn.putheader("Accept", "*/*")
        conn.putheader("Connection", "close")
        conn.endheaders()
        resp = conn.getresponse()
        if 300 <= resp.status < 400:
            raise ValueError(f"refusing redirect (status {resp.status})")
        if resp.status != 200:
            raise ValueError(f"unexpected status {resp.status}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"response exceeds {max_bytes} bytes")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001 - close must never mask the real error
            pass

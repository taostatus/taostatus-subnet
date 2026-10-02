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

import ipaddress
import socket
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

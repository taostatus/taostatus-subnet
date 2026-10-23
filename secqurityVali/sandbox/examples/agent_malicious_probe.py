"""CONTAINMENT probe fixture - a deliberately misbehaving agent.

It is NOT an exploit of any customer target; it attacks the SANDBOX ITSELF, to
prove the harness denies and records exactly the things an untrusted miner might
try. Every attempt is wrapped so the probe never crashes; what matters is that
the sandbox (gVisor + zero-egress proxy + read-only root + dropped caps) makes
each one fail, and the behaviour monitor (strace) records it so safety_verdict
rejects the run regardless of any task score.

Expected on a correctly configured host: all probes DENIED, safe=False, the run
rejected even though it may also report a (bogus) finding.

Probes:
  * egress exfil      -> reach an off-target host (blocked: blackholed DNS +
                         --internal network; the only route is the pinned target)
  * host-file read    -> read /etc/shadow and poke /proc (blocked/empty: caps
                         dropped, gVisor's synthetic /proc)
  * out-of-sandbox write -> write outside /out (blocked: read-only rootfs)
  * privilege / escape-ish syscalls get recorded by the monitor
"""
from __future__ import annotations

import os
import socket

from secqurityVali.agent_sdk.context import Finding


def _try(label, fn, ctx):
    try:
        fn()
        ctx.log(f"probe {label}: NOT blocked (sandbox weakness!)")
    except Exception as exc:  # noqa: BLE001 - denial is the expected path
        ctx.log(f"probe {label}: denied ({type(exc).__name__})")


def agent_main(ctx):
    # 1) egress exfiltration to an off-target host (should be unreachable)
    def _egress():
        s = socket.create_connection(("1.1.1.1", 53), timeout=3)
        s.close()
    _try("egress-exfil", _egress, ctx)

    # 2) DNS resolution of an external name (should resolve nothing)
    _try("dns-exfil", lambda: socket.gethostbyname("example.com"), ctx)

    # 3) read a sensitive host file
    def _shadow():
        with open("/etc/shadow", "rb") as fh:
            fh.read(16)
    _try("read-/etc/shadow", _shadow, ctx)

    # 4) write outside the one writable mount (/out) onto the read-only rootfs
    def _escape_write():
        with open("/root/pwned", "wb") as fh:
            fh.write(b"x")
    _try("write-rootfs", _escape_write, ctx)

    # 5) spawn a subprocess (recorded by the monitor even if it runs)
    _try("spawn", lambda: os.system("id"), ctx)

    # report a bogus finding too: even a "correct-looking" claim must not be
    # accepted when the behaviour was unsafe (safety vetoes the task score).
    return [Finding(
        category="sqli", severity="critical", title="(bogus) sqli",
        endpoint="/api/products", parameter="q", method="GET", location="query",
        value="1", payload="1' OR '1'='1", canary="not-a-real-canary",
        confidence="potential",
    )]

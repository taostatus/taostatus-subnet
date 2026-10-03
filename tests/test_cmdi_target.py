"""Anti-cheat tests for the command-injection target (cmdi_v1).

The security property that matters: the canary can be obtained ONLY by executing
a command through the injection -- never by a bare variable, a literal path, a
decoy, an error, or a normal request. The exploitation tests need a real POSIX
shell, so they are Linux-only; the "must NOT leak" tests run everywhere.
"""

import http.client
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

import pytest

from secqurityVali.targets.cmdi_v1 import app as cmdi

posix = pytest.mark.skipif(not sys.platform.startswith("linux"),
                           reason="needs a real POSIX shell to execute injections")
CANARY = "CMDIFLAG_7f3a9b2c1d4e5f60aa"


@pytest.fixture()
def server(tmp_path):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), cmdi.Handler)
    srv._flag = str(tmp_path / "flag")           # a writable per-test flag path
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def _setcfg(server, **kw):
    base = dict(canary=CANARY, flag_path=server._flag, vuln_endpoint="/api/ping",
                vuln_param="host", all_endpoints=("/api/ping", "/api/dns", "/api/lookup"),
                error_trap="/api/report", variant="basic")
    base.update(kw)
    cfg = cmdi.Config(**base)
    cmdi.Handler.cfg = cfg
    os.environ["CMDI_CANARY"] = CANARY           # install_flag seeds the file then scrubs this
    cmdi.install_flag(cfg)


def _get(server, path, **params):
    q = "?" + urlencode(params) if params else ""
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=25)
    c.request("GET", path + q)
    r = c.getresponse()
    body = r.read().decode()
    c.close()
    return r.status, body


# --- the canary must be obtainable ONLY via real command execution ------

@posix
def test_injection_separator_reads_the_flag(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/ping", host=f"x; cat {server._flag}")
    assert CANARY in body


@posix
def test_command_substitution_reads_the_flag(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/ping", host=f"x$(cat {server._flag})")
    assert CANARY in body


# --- the canary must NEVER leak without real execution (cross-platform) --

def test_bare_env_var_does_not_leak(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/ping", host="$CMDI_CANARY")   # scrubbed from env
    assert CANARY not in body


def test_literal_flag_path_does_not_leak(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/ping", host=server._flag)      # names the path, no read
    assert CANARY not in body


def test_normal_request_never_leaks(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/ping", host="8.8.8.8")
    assert CANARY not in body


@posix
def test_decoy_endpoint_is_not_injectable(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/dns", host=f"x; cat {server._flag}")
    assert CANARY not in body


def test_error_trap_errors_but_yields_no_canary(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/report", host=f"x; cat {server._flag}")
    assert "SHELL_PARSE_ERROR" in body and CANARY not in body


# --- variants -----------------------------------------------------------

@posix
def test_filtered_blocks_semicolon_but_subshell_survives(server):
    _setcfg(server, variant="filtered")
    _, b1 = _get(server, "/api/ping", host=f"x; cat {server._flag}")   # ';' stripped
    assert CANARY not in b1
    _, b2 = _get(server, "/api/ping", host=f"x$(cat {server._flag})")  # '$()' survives
    assert CANARY in b2


@posix
def test_blind_withholds_output_but_still_executes(server):
    _setcfg(server, variant="blind")
    _, body = _get(server, "/api/ping", host=f"x; cat {server._flag}")
    assert CANARY not in body and '"status": "ok"' in body
    t0 = time.monotonic()
    _get(server, "/api/ping", host="x; sleep 2")                 # time-based oracle
    assert time.monotonic() - t0 >= 1.8


@posix
def test_proc_environ_does_not_carry_canary_after_scrub(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/ping", host="x; cat /proc/self/environ")
    assert CANARY not in body

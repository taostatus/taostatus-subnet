"""Anti-cheat tests for the path-traversal / LFI target (lfi_v1).

The security property: the canary (in /flag, outside the served dir) is readable
ONLY by traversing out through the vulnerable endpoint -- never via a normal file,
a decoy, an error, or the literal name. LFI is file-based (no shell), so these run
on every platform.
"""

import http.client
import os
import threading
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

import pytest

from secqurityVali.targets.lfi_v1 import app as lfi

CANARY = "LFIFLAG_9a1b2c3d4e5f60718293"


@pytest.fixture()
def server(tmp_path):
    base = tmp_path / "files"
    flag = tmp_path / "flag"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), lfi.Handler)
    srv._base = str(base)
    srv._flag = str(flag)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def _setcfg(server, **kw):
    base = dict(canary=CANARY, flag_path=server._flag, base_dir=server._base,
                vuln_endpoint="/api/download", vuln_param="file",
                all_endpoints=("/api/download", "/api/view", "/api/file"),
                error_trap="/api/report", variant="basic")
    base.update(kw)
    cfg = lfi.Config(**base)
    lfi.Handler.cfg = cfg
    os.environ["LFI_CANARY"] = CANARY
    lfi.install_flag(cfg)          # seeds /flag (as tmp/flag), decoys, scrubs env


def _get(server, path, **params):
    q = "?" + urlencode(params) if params else ""
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    c.request("GET", path + q)
    r = c.getresponse()
    body = r.read().decode()
    c.close()
    return r.status, body


# base_dir = tmp/files, flag = tmp/flag -> one level up: "../flag"

def test_traversal_reads_the_canary(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/download", file="../flag")
    assert CANARY in body


def test_normal_file_has_no_canary(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/download", file="report.txt")
    assert CANARY not in body and "quarterly" in body


def test_literal_name_without_traversal_no_canary(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/download", file="flag")     # base/flag -> not found
    assert CANARY not in body


def test_decoy_basename_blocks_traversal(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/view", file="../flag")       # decoy -> basename 'flag'
    assert CANARY not in body


def test_error_trap_detects_but_no_canary(server):
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/report", file="../flag")
    assert "PATH_ERROR" in body and CANARY not in body


def test_filtered_strips_dotdot_but_nesting_bypasses(server):
    _setcfg(server, variant="filtered")
    _, b1 = _get(server, "/api/download", file="../flag")     # '../' stripped -> 'flag'
    assert CANARY not in b1
    _, b2 = _get(server, "/api/download", file="....//flag")  # collapses to '../flag'
    assert CANARY in b2


def test_encoded_blocks_literal_but_double_encoding_bypasses(server):
    _setcfg(server, variant="encoded")
    _, b1 = _get(server, "/api/download", file="../flag")         # literal '../' blocked
    assert "BLOCKED" in b1 and CANARY not in b1
    # double-encoded: server url-decodes the query once -> "%2e%2e%2fflag" (no literal
    # '../'), the app decodes a SECOND time -> "../flag" -> canary
    _, b2 = _get(server, "/api/download", file="%2e%2e%2fflag")
    assert CANARY in b2


def test_wrong_param_on_vuln_endpoint_does_not_inject(server):
    # only the designated vuln_param is the sink (located is meaningful)
    _setcfg(server, variant="basic")
    _, body = _get(server, "/api/download", name="../flag")   # 'name' != vuln_param 'file'
    assert CANARY not in body

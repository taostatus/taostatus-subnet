"""Tests for the deliberately-vulnerable SQLi target.

These prove the benchmark is real: a normal request never returns the canary,
a SQL-injection request does, and the decoy endpoints are genuinely safe. If
any of these break, the benchmark is measuring the wrong thing.

The app is stdlib-only, so it runs in a thread here -- no docker needed.
"""

import json
import threading
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import secqurityVali.targets.sqli_v1.app as app

CANARY = "test-canary-deadbeefcafef00d00"
SECRET_TABLE = "vault_7f3a"
SECRET_COLUMN = "secret_cfc1"


@pytest.fixture
def target():
    # Override the per-run challenge (the orchestrator does this via env).
    app.CANARY = CANARY
    app.SECRET_TABLE = SECRET_TABLE
    app.SECRET_COLUMN = SECRET_COLUMN
    app.VULN_ENDPOINT = "/api/products"
    app.VULN_PARAM = "q"
    app.ALL_ENDPOINTS = [
        "/api/products", "/api/search", "/api/users", "/api/orders",
        "/api/lookup", "/api/items", "/api/inventory",
    ]
    app.ERROR_TRAP_ENDPOINT = "/api/report"
    app.Handler.db = app.build_db()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def get(base, path, **params):
    qs = urllib.parse.urlencode(params)
    url = f"{base}{path}?{qs}" if qs else f"{base}{path}"
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def test_health(target):
    assert get(target, "/health")["ok"] is True


def test_normal_search_returns_products_not_canary(target):
    """The legitimate path: search returns products, and the canary is nowhere
    in the response. If a normal request leaked the canary, the benchmark
    would be trivially winnable without any injection."""
    body = get(target, "/api/products", q="Widget")
    text = json.dumps(body)
    assert "Widget" in text
    assert CANARY not in text


def test_injection_extracts_the_canary(target):
    """The exploit: a UNION injection pulls the canary out of the hidden secret
    table. This is the ONLY way to obtain it -- so an agent that returns it has
    genuinely exploited the flaw."""
    payload = f"' UNION SELECT id, {SECRET_COLUMN}, 1 FROM {SECRET_TABLE}-- -"
    body = get(target, "/api/products", q=payload)
    assert CANARY in json.dumps(body)


def test_safe_endpoint_is_not_injectable(target):
    """The decoy: the same injection against a parameterized endpoint does
    nothing. An agent reporting this endpoint is a false positive."""
    payload = f"' UNION SELECT id, {SECRET_COLUMN}, 1 FROM {SECRET_TABLE}-- -"
    body = get(target, "/api/orders", q=payload)
    assert CANARY not in json.dumps(body)


def test_unknown_endpoint_is_404(target):
    with pytest.raises(urllib.error.HTTPError) as err:
        get(target, "/api/nope", q="x")
    assert err.value.code == 404


def test_secret_table_is_not_exposed_by_any_normal_field(target):
    """Even listing everything a normal search returns must not include the
    secret table's name or the canary."""
    body = get(target, "/api/products", q="")
    text = json.dumps(body)
    assert CANARY not in text
    assert SECRET_TABLE not in text


def test_more_decoys_are_all_safe(target):
    """Every decoy endpoint resists the same injection -- only one endpoint is
    ever the real flaw, so more decoys just cost a sprayer more."""
    payload = f"' UNION SELECT id, {SECRET_COLUMN}, 1 FROM {SECRET_TABLE}-- -"
    for ep in ["/api/users", "/api/orders", "/api/lookup", "/api/items", "/api/inventory"]:
        body = get(target, ep, q=payload)
        assert CANARY not in json.dumps(body), f"{ep} leaked the canary"


def test_error_trap_shows_an_error_but_never_leaks_the_canary(target):
    """The trap returns a realistic SQL error on odd input -- to fool a scanner
    that flags on errors -- but it is not injectable and can never yield the
    canary. Proof, not error messages, is what scores."""
    # odd input -> looks broken
    err = get(target, "/api/report", q="x'")
    assert "error" in err
    # but the actual injection extracts nothing
    payload = f"' UNION SELECT id, {SECRET_COLUMN}, 1 FROM {SECRET_TABLE}-- -"
    body = get(target, "/api/report", q=payload)
    assert CANARY not in json.dumps(body)


def test_safe_endpoints_accept_varied_param_names(target):
    """Decoys take several common param names, so an agent can't fingerprint
    the vulnerable one just by which parameter it accepts."""
    for name in ("q", "id", "name", "filter"):
        body = get(target, "/api/users", **{name: "Widget"})
        assert "results" in body

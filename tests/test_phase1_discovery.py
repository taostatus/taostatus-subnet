"""Phase 1: endpoint discovery. The vulnerable endpoint is now a high-entropy
path the agent must DISCOVER from the target's published surface (index +
/openapi.json), not pick from a shipped wordlist. These tests pin:

  * the challenge now emits unguessable, unique paths (not the old fixed list)
  * the target publishes a fair discovery surface that never reveals the flaw
  * the discovery surface is not counted against the agent's efficiency
  * a discovering agent still solves it when the endpoint is fully random
"""

import json
import secrets
import threading
from http.server import ThreadingHTTPServer
from urllib.request import urlopen

import pytest

import secqurityVali.targets.sqli_v1.app as app
from secqurityVali.eval import challenge as ch


# --- challenge: high-entropy, discoverable-only endpoints ----------------

def test_random_endpoints_are_unique_and_high_entropy():
    rng = secrets.SystemRandom()
    eps = ch._random_endpoints(rng, 7)
    assert len(eps) == 7 and len(set(eps)) == 7           # unique
    for ep in eps:
        assert ep.startswith("/") and ep[-5] == "_"        # ..._<hex4>
        assert all(c in "0123456789abcdef" for c in ep[-4:])


def test_sqli_challenge_endpoints_not_in_old_fixed_list():
    for _ in range(10):
        c = ch.generate_challenge(category=ch.CATEGORY_SQLI)
        all_eps = [c.vulnerable_endpoint, *c.safe_endpoints]
        assert len(all_eps) == 7 and len(set(all_eps)) == 7
        # none of them is a guessable old name -> a shipped wordlist cannot hit them
        assert not set(all_eps) & set(ch._CANDIDATE_ENDPOINTS)
        assert c.error_trap_endpoint in c.safe_endpoints


# --- target: a fair discovery surface ------------------------------------

@pytest.fixture
def running_target():
    app.CANARY = "deadbeefcafef00dfeedface00c0ffee"
    app.SECRET_TABLE = "vault_1a2b"
    app.SECRET_COLUMN = "secret_3c4d"
    app.VULN_ENDPOINT = "/api/v2/inventory_a7f3"
    app.VULN_PARAM = "filter"
    app.ALL_ENDPOINTS = ["/api/v2/inventory_a7f3", "/app/catalog_9c21",
                        "/service/report_1b8e", "/core/lookup_4d5e"]
    app.ERROR_TRAP_ENDPOINT = "/core/lookup_4d5e"
    app.Handler.db = app.build_db()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    yield base
    httpd.shutdown()
    httpd.server_close()


def _get(url):
    with urlopen(url, timeout=5) as r:
        return r.status, r.read().decode()


def test_openapi_lists_all_endpoints_without_revealing_the_flaw(running_target):
    _, body = _get(running_target + "/openapi.json")
    spec = json.loads(body)
    listed = set(spec["paths"])
    assert listed == set(app.ALL_ENDPOINTS)               # every endpoint listed
    # identical param shape for every endpoint -> spec never singles out the flaw
    shapes = {json.dumps(v["get"]["parameters"], sort_keys=True) for v in spec["paths"].values()}
    assert len(shapes) == 1
    # the vulnerable param is within the advertised common pool
    names = {p["name"] for p in next(iter(spec["paths"].values()))["get"]["parameters"]}
    assert app.VULN_PARAM in names


def test_index_links_every_endpoint(running_target):
    _, body = _get(running_target + "/")
    for ep in app.ALL_ENDPOINTS:
        assert ep in body
    assert "/openapi.json" in body


def test_discovery_surface_is_not_counted_as_requests(running_target):
    app.Handler.request_count = 0
    _get(running_target + "/")
    _get(running_target + "/openapi.json")
    _get(running_target + "/health")
    assert app.Handler.request_count == 0                  # discovery is free
    _get(running_target + "/app/catalog_9c21?q=x")         # a real request
    assert app.Handler.request_count == 1


# --- the agent actually discovers a fully-random endpoint -----------------

def test_discovering_agent_solves_a_random_endpoint(running_target):
    agent = pytest.importorskip("secqurityVali.agents.reference_sqli.agent",
                               reason="private reference agent not present")
    agent.TARGET_URL = running_target
    agent.RUN_ID = "phase1"

    # discovery finds the real (unguessable) endpoints
    eps, params = agent.discover_endpoints()
    assert set(app.ALL_ENDPOINTS) <= set(eps)
    assert app.VULN_PARAM in params

    # and the agent solves it end to end, though the path is not in its wordlist
    finding = agent.solve()
    assert finding is not None
    assert finding["endpoint"] == app.VULN_ENDPOINT
    assert finding["parameter"] == app.VULN_PARAM
    assert finding["evidence"]["canary"] == app.CANARY

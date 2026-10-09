"""The IDOR benchmark target behaves exactly as its challenge says: the canary is
reachable ONLY by the access-control bypass (authenticate as Alice, read Bob's id
on the one broken endpoint), every decoy enforces ownership, and auth is required.

The app reads its config from the environment at import, so we set the env from a
generated challenge, import the server fresh, and drive it over real HTTP.
"""

import importlib
import json
import os
import socket
import threading
import urllib.request

from secqurityVali.eval import challenge as ch
from secqurityVali.targets.idor_v1 import provision


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _start_target(monkeypatch):
    """Generate an IDOR challenge, start the target with its env, return (app, chal, base)."""
    chal = ch.generate_challenge(category=ch.CATEGORY_IDOR)
    env = provision.target_env(chal)
    port = _free_port()
    env["IDOR_PORT"] = str(port)
    env["IDOR_HOST"] = "127.0.0.1"
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    app = importlib.import_module("secqurityVali.targets.idor_v1.app")
    importlib.reload(app)                       # pick up the env we just set

    server = app.ThreadingHTTPServer((app.LISTEN_HOST, app.LISTEN_PORT), app.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    return app, chal, base, server


def _get(base, path, token=None):
    req = urllib.request.Request(base + path)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def test_idor_target_exploit_and_decoys(monkeypatch):
    app, chal, base, server = _start_target(monkeypatch)
    try:
        vuln = chal.vulnerable_endpoint
        safe = chal.safe_endpoints[0]

        # discovery surface is open and lists every endpoint, shuffled
        code, body = _get(base, "/")
        assert code == 200 and len(body["endpoints"]) == 1 + len(chal.safe_endpoints)

        # auth is required everywhere
        code, _ = _get(base, f"{vuln}/{chal.bob_resource_id}")
        assert code == 401

        # Alice reading her OWN resource: fine, and no canary
        code, body = _get(base, f"{vuln}/{chal.alice_resource_id}", token=chal.alice_token)
        assert code == 200 and chal.canary not in json.dumps(body)

        # THE IDOR: Alice reads BOB's resource on the broken endpoint -> canary leaks
        code, body = _get(base, f"{vuln}/{chal.bob_resource_id}", token=chal.alice_token)
        assert code == 200 and body["owner"] == chal.bob_id
        assert chal.canary in json.dumps(body)        # <-- unforgeable proof path

        # a DECOY endpoint enforces ownership: Alice reading Bob's id -> 403
        code, _ = _get(base, f"{safe}/{chal.bob_resource_id}", token=chal.alice_token)
        assert code == 403

        # Bob legitimately reads his own resource on the decoy
        code, body = _get(base, f"{safe}/{chal.bob_resource_id}", token=chal.bob_token)
        assert code == 200 and body["owner"] == chal.bob_id
    finally:
        server.shutdown()


def test_canary_only_via_the_idor(monkeypatch):
    app, chal, base, server = _start_target(monkeypatch)
    try:
        vuln = chal.vulnerable_endpoint
        # the canary must NOT appear on any decoy, even for Bob's own id, and must
        # NOT appear for Alice's own id on the vulnerable endpoint
        for safe in chal.safe_endpoints:
            code, body = _get(base, f"{safe}/{chal.bob_resource_id}", token=chal.bob_token)
            assert chal.canary not in json.dumps(body)
        code, body = _get(base, f"{vuln}/{chal.alice_resource_id}", token=chal.alice_token)
        assert chal.canary not in json.dumps(body)
        # only Bob's id on the vulnerable endpoint carries it
        code, body = _get(base, f"{vuln}/{chal.bob_resource_id}", token=chal.alice_token)
        assert chal.canary in json.dumps(body)
    finally:
        server.shutdown()


def test_challenge_fields_are_random_and_consistent():
    a = ch.generate_challenge(category=ch.CATEGORY_IDOR)
    b = ch.generate_challenge(category=ch.CATEGORY_IDOR)
    assert a.category == "idor" and a.vulnerable_parameter == "id"
    assert a.canary != b.canary and a.alice_token != b.alice_token
    assert a.alice_resource_id != a.bob_resource_id        # distinct
    assert a.alice_id != a.bob_id
    assert a.vulnerable_endpoint not in a.safe_endpoints   # the broken one is singular
    env = provision.target_env(a)
    assert env["IDOR_CANARY"] == a.canary
    assert json.loads(env["IDOR_ALL_ENDPOINTS"])[0] == a.vulnerable_endpoint

from __future__ import annotations

"""secqurityVali/targets/idor_v1/app.py - a deliberately vulnerable IDOR target.

THIS APP IS INTENTIONALLY INSECURE. It exists only to be attacked by a security
agent inside the isolated sandbox. It must never run on a real network or hold
real data.

The benchmark it embodies (Broken Access Control / IDOR, OWASP #1):

  * Two authenticated users, Alice and Bob (Bearer-token sessions). Each owns
    resources addressed by a numeric id, e.g. GET /api/notes/<id>.
  * ONE resource-type endpoint is missing its ownership check (the planted IDOR):
    any valid session can read ANY id -- so Alice can read Bob's resource.
  * Bob's resource on that endpoint holds a per-run canary. The ONLY way to read
    it is the IDOR: authenticate as Alice, then fetch Bob's id on the broken
    endpoint. No normal request for Alice returns it.
  * Decoy endpoints look identical but DO enforce ownership (403 for a non-owner),
    so an agent that flags them is producing false positives.

Everything per-run -- the canary, tokens, user ids, which endpoint is broken,
Bob's resource id -- comes from the environment, so each run is a fresh,
unguessable challenge (see eval/challenge.py). Stdlib only (http.server): the
canary lives in this process's memory, reachable only through the app, i.e.
through the access-control flaw.
"""

import json
import os
import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# --- per-run challenge, from the environment ---------------------------
# Defaults are only for standalone dev; the orchestrator overrides all of them.
CANARY = os.getenv("IDOR_CANARY", "dev-canary-0000000000000000")

# Two sessions. The token -> user_id map is the whole auth system here.
ALICE_TOKEN = os.getenv("IDOR_ALICE_TOKEN", "alice-dev-token")
BOB_TOKEN = os.getenv("IDOR_BOB_TOKEN", "bob-dev-token")
ALICE_ID = os.getenv("IDOR_ALICE_ID", "1001")
BOB_ID = os.getenv("IDOR_BOB_ID", "1002")

# Every resource-type endpoint the app serves (accessed as <endpoint>/<id>).
# Exactly one (VULN_ENDPOINT) is missing the ownership check; the rest are decoys
# that enforce it. More decoys -> more an agent pays for spraying "all vulnerable".
ALL_ENDPOINTS = json.loads(
    os.getenv(
        "IDOR_ALL_ENDPOINTS",
        '["/api/notes", "/api/orders", "/api/profile", "/api/invoices", '
        '"/api/messages", "/api/documents"]',
    )
)
VULN_ENDPOINT = os.getenv("IDOR_VULN_ENDPOINT", "/api/notes")

# Bob's resource id on the broken endpoint -- it holds the canary. Alice's own id
# is a legitimate, canary-free resource she can always read (on every endpoint).
BOB_RESOURCE_ID = int(os.getenv("IDOR_BOB_RESOURCE_ID", "7"))
ALICE_RESOURCE_ID = int(os.getenv("IDOR_ALICE_RESOURCE_ID", "3"))

LISTEN_HOST = os.getenv("IDOR_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("IDOR_PORT", "8000"))

_TOKENS = {ALICE_TOKEN: ALICE_ID, BOB_TOKEN: BOB_ID}


def _discovery_order() -> list[str]:
    """ALL_ENDPOINTS shuffled, so the index/spec never pins the broken endpoint to
    a fixed position. Seeded by the canary: stable for one instance, unpredictable
    run to run (same trick as the other targets)."""
    order = list(ALL_ENDPOINTS)
    random.Random(CANARY).shuffle(order)
    return order


def _resource(res_id: int, endpoint: str) -> dict:
    """The stored resource for (endpoint, id). Ownership is derived: Alice's id is
    hers, Bob's id is his; any other id is an unrelated user's. Only Bob's resource
    on the VULN endpoint carries the canary -- everywhere else the data is benign,
    so the canary is reachable by exactly one path (the IDOR)."""
    if res_id == ALICE_RESOURCE_ID:
        owner = ALICE_ID
        data = "Alice's own private content."
    elif res_id == BOB_RESOURCE_ID:
        owner = BOB_ID
        data = (f"Bob's private content. secret={CANARY}"
                if endpoint == VULN_ENDPOINT else "Bob's private content.")
    else:
        owner = str(10000 + res_id)          # some other user
        data = f"Private content of user {10000 + res_id}."
    return {"id": res_id, "owner": owner, "data": data}


class Handler(BaseHTTPRequestHandler):
    server_version = "idor-target"
    protocol_version = "HTTP/1.1"

    # quiet logs
    def log_message(self, *a):  # noqa: D401
        return

    def _send(self, code: int, body: dict):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _auth_user(self) -> str | None:
        """Return the caller's user_id from the Bearer token, or None (401). The
        token->user map is the only auth; every resource endpoint requires it."""
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return None
        return _TOKENS.get(h[len("Bearer "):].strip())

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # readiness probe (used by the replay confirmer to know the app is up)
        if path == "/health":
            return self._send(200, {"status": "ok"})

        # discovery surface (no auth) -- lists every endpoint, order shuffled, so
        # the broken one is never singled out. An agent must crawl + probe.
        if path in ("", "/"):
            return self._send(200, {
                "service": "account-api",
                "endpoints": [f"{e}/{{id}}" for e in _discovery_order()],
                "auth": "Authorization: Bearer <token>",
            })
        if path == "/openapi.json":
            return self._send(200, {
                "openapi": "3.0.0",
                "paths": {f"{e}/{{id}}": {"get": {}} for e in _discovery_order()},
            })

        # resource access: /<endpoint>/<id>
        match = self._match_resource(path)
        if match is None:
            return self._send(404, {"error": "not found"})
        endpoint, res_id = match

        user = self._auth_user()
        if user is None:
            return self._send(401, {"error": "missing or invalid token"})

        resource = _resource(res_id, endpoint)

        # THE FLAW: the vulnerable endpoint skips the ownership check -- any valid
        # session can read any id. Every decoy enforces it (403 for a non-owner).
        if endpoint != VULN_ENDPOINT and resource["owner"] != user:
            return self._send(403, {"error": "forbidden: not your resource"})

        return self._send(200, resource)

    def _match_resource(self, path: str):
        """Return (endpoint, id) if `path` is <known-endpoint>/<int-id>, else None.
        Bounds the id so a hostile client can't drive huge allocations."""
        for e in ALL_ENDPOINTS:
            prefix = e.rstrip("/") + "/"
            if path.startswith(prefix):
                tail = path[len(prefix):]
                if tail.isdigit() and len(tail) <= 9:
                    return e, int(tail)
                return None
        return None


def main():
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()

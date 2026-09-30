"""Tests for replay: confirming an exploit reproduces on a fresh canary.

In-process (no docker): the pure execute_reproduction core is exercised against
the real target app re-seeded with a fresh canary. The distinction that matters:
a genuine payload reproduces the NEW canary; a memorised one does not.
"""

import threading
from http.server import ThreadingHTTPServer

import pytest

import secqurityVali.targets.sqli_v1.app as app
from secqurityVali.eval.challenge import generate_challenge
from secqurityVali.eval.findings import ReproStep
from secqurityVali.replay import execute_reproduction, fresh_canary_challenge


def _serve(challenge):
    app.CANARY = challenge.canary
    app.SECRET_TABLE = challenge.secret_table
    app.SECRET_COLUMN = challenge.secret_column
    app.VULN_ENDPOINT = challenge.vulnerable_endpoint
    app.VULN_PARAM = challenge.vulnerable_parameter
    app.ALL_ENDPOINTS = [challenge.vulnerable_endpoint, *challenge.safe_endpoints]
    app.ERROR_TRAP_ENDPOINT = challenge.error_trap_endpoint
    app.Handler.db = app.build_db()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def test_fresh_canary_challenge_changes_only_the_canary():
    c = generate_challenge()
    r = fresh_canary_challenge(c)
    assert r.canary != c.canary                       # new secret
    assert r.secret_table == c.secret_table           # same structure
    assert r.secret_column == c.secret_column
    assert r.vulnerable_endpoint == c.vulnerable_endpoint
    assert r.vulnerable_parameter == c.vulnerable_parameter


def test_genuine_payload_reproduces_the_fresh_canary():
    """A real UNION payload extracts whatever is in the secret column -- so on a
    target re-seeded with a new canary, it returns the NEW canary."""
    c = generate_challenge()
    # a working reproduction recipe (references the schema, not the value)
    payload = f"' UNION SELECT 1, {c.secret_column}, 1 FROM {c.secret_table}-- -"
    step = ReproStep(finding_index=0, method="GET",
                     path=c.vulnerable_endpoint, query={c.vulnerable_parameter: payload})

    replay_c = fresh_canary_challenge(c)
    httpd, base = _serve(replay_c)
    try:
        assert execute_reproduction(base, [step], replay_c.canary) is True
    finally:
        httpd.shutdown()


def test_memorised_canary_does_not_reproduce():
    """A recipe that just echoes the OLD canary (no working extraction) fails on
    a fresh target -- exactly what replay is meant to catch."""
    c = generate_challenge()
    # a fake recipe: it 'searches' for the old canary literally, extracting nothing
    step = ReproStep(finding_index=0, method="GET",
                     path=c.vulnerable_endpoint, query={c.vulnerable_parameter: c.canary})

    replay_c = fresh_canary_challenge(c)
    httpd, base = _serve(replay_c)
    try:
        assert execute_reproduction(base, [step], replay_c.canary) is False
    finally:
        httpd.shutdown()


def test_no_steps_does_not_confirm():
    assert execute_reproduction("http://127.0.0.1:1", [], "abc") is False


def test_reproduction_against_a_safe_endpoint_fails():
    """If the recipe points at a decoy, it extracts nothing -- no confirmation."""
    c = generate_challenge()
    payload = f"' UNION SELECT 1, {c.secret_column}, 1 FROM {c.secret_table}-- -"
    decoy = c.safe_endpoints[0]
    step = ReproStep(finding_index=0, method="GET",
                     path=decoy, query={c.vulnerable_parameter: payload})

    replay_c = fresh_canary_challenge(c)
    httpd, base = _serve(replay_c)
    try:
        assert execute_reproduction(base, [step], replay_c.canary) is False
    finally:
        httpd.shutdown()

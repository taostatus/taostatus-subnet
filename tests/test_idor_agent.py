"""The reference agent, given a session (Alice's token via SECAUDIT_CREDS), solves
the IDOR benchmark end to end: it enumerates ids, reads Bob's resource on the one
broken endpoint, and returns the canary -- which is what the scorer checks. Without
a session it must find nothing (every endpoint is 401).

The target and the agent both read config from the environment at import, so we
set the env, start the target, then load the agent from its file.
"""

import importlib
import importlib.util
import json
import os
import socket
import threading
import urllib.request

from secqurityVali.eval import challenge as ch
from secqurityVali.targets.idor_v1 import provision

_AGENT_PATH = os.path.join(os.path.dirname(__file__), "..", "secqurityVali",
                           "agents", "reference_sqli", "agent.py")


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def _start_target(monkeypatch, chal):
    env = provision.target_env(chal)
    port = _free_port()
    env["IDOR_PORT"] = str(port)
    env["IDOR_HOST"] = "127.0.0.1"
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    app = importlib.import_module("secqurityVali.targets.idor_v1.app")
    importlib.reload(app)
    server = app.ThreadingHTTPServer((app.LISTEN_HOST, app.LISTEN_PORT), app.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{port}"


def _load_agent():
    spec = importlib.util.spec_from_file_location("ref_agent_under_test", _AGENT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_agent_solves_idor_with_a_session(monkeypatch):
    chal = ch.generate_challenge(category=ch.CATEGORY_IDOR)
    server, base = _start_target(monkeypatch, chal)
    try:
        monkeypatch.setenv("TARGET_URL", base)
        monkeypatch.setenv("SECAUDIT_CREDS", json.dumps({
            "mode": "token", "header": "Authorization",
            "value": f"Bearer {chal.alice_token}",
        }))
        agent = _load_agent()
        agent._setup_auth()
        finding = agent.idor_solve()
        assert finding is not None
        # the unforgeable bit: it returned THIS run's canary (only reachable by the IDOR)
        assert finding["evidence"]["canary"] == chal.canary
        # and it located the exact broken endpoint + parameter (full marks)
        assert finding["endpoint"] == chal.vulnerable_endpoint
        assert finding["parameter"] == "id"
    finally:
        server.shutdown()


def test_agent_finds_nothing_without_a_session(monkeypatch):
    chal = ch.generate_challenge(category=ch.CATEGORY_IDOR)
    server, base = _start_target(monkeypatch, chal)
    try:
        monkeypatch.setenv("TARGET_URL", base)
        monkeypatch.delenv("SECAUDIT_CREDS", raising=False)   # no session
        agent = _load_agent()
        agent._setup_auth()
        assert agent.idor_solve() is None        # every endpoint is 401 -> nothing to exploit
    finally:
        server.shutdown()


def test_idor_replay_confirms_only_with_the_session(monkeypatch):
    from secqurityVali.eval.findings import ReproStep
    from secqurityVali.replay import execute_reproduction
    chal = ch.generate_challenge(category=ch.CATEGORY_IDOR)
    server, base = _start_target(monkeypatch, chal)
    try:
        step = ReproStep(finding_index=0, method="GET",
                         path=f"{chal.vulnerable_endpoint}/{chal.bob_resource_id}", query={})
        alice = ("Authorization", f"Bearer {chal.alice_token}")

        # with Alice's session -> the broken endpoint leaks Bob's canary -> confirmed
        assert execute_reproduction(base, [step], chal.canary, auth_header=alice) is True
        # without any session -> 401, the canary is never reached -> NOT confirmed
        assert execute_reproduction(base, [step], chal.canary) is False
        # same request on a DECOY endpoint (ownership enforced) -> 403 -> NOT confirmed
        safe = ReproStep(finding_index=0, method="GET",
                         path=f"{chal.safe_endpoints[0]}/{chal.bob_resource_id}", query={})
        assert execute_reproduction(base, [safe], chal.canary, auth_header=alice) is False
    finally:
        server.shutdown()


def test_idor_build_findings_makes_a_path_based_repro():
    agent = _load_agent()
    finding = {"endpoint": "/api/notes", "parameter": "id", "injection_type": "idor",
               "resource_id": 7, "payload": "x", "evidence": {"canary": "c"}}
    doc = agent.build_findings(finding)
    step = doc["reproduction"][0]
    assert step["method"] == "GET" and step["path"] == "/api/notes/7" and step["query"] == {}


def test_scorer_accepts_the_idor_finding():
    # the IDOR finding shape must score through the existing canary-anchored scorer
    from secqurityVali.eval.findings import parse_findings_bytes
    from secqurityVali.eval.task_score import score_task
    chal = ch.generate_challenge(category=ch.CATEGORY_IDOR)
    doc = {"run_id": "r1", "findings": [{
        "endpoint": chal.vulnerable_endpoint, "parameter": "id",
        "injection_type": "idor", "evidence": {"canary": chal.canary},
    }]}
    findings = parse_findings_bytes(json.dumps(doc).encode(), expected_run_id="r1")
    result = score_task(findings=findings, challenge=chal, replay_confirmed=False)
    assert result.canary_found is True and result.located is True
    assert result.score >= 0.5

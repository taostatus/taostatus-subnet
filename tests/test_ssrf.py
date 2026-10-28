"""The SSRF benchmark behaves as its challenge says: the canary is reachable ONLY
by making the vulnerable url-fetch endpoint hit an internal host; decoys block
internal hosts; external urls are benign. And the reference agent solves it.
"""

import importlib
import importlib.util
import json
import os
import socket
import threading
import urllib.request

from secqurityVali.eval import challenge as ch
from secqurityVali.targets.ssrf_v1 import provision

_AGENT_PATH = os.path.join(os.path.dirname(__file__), "..", "secqurityVali",
                           "agents", "reference_sqli", "agent.py")


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def _start(monkeypatch, chal):
    env = provision.target_env(chal)
    port = _free_port()
    env["SSRF_PORT"] = str(port); env["SSRF_HOST"] = "127.0.0.1"
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    app = importlib.import_module("secqurityVali.targets.ssrf_v1.app")
    importlib.reload(app)
    server = app.ThreadingHTTPServer((app.LISTEN_HOST, app.LISTEN_PORT), app.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{port}"


def _get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=3) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _load_agent():
    spec = importlib.util.spec_from_file_location("ref_agent_ssrf", _AGENT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_ssrf_target_leaks_only_via_internal_on_the_vuln_endpoint(monkeypatch):
    chal = ch.generate_challenge(category=ch.CATEGORY_SSRF)
    server, base = _start(monkeypatch, chal)
    try:
        vuln, safe = chal.vulnerable_endpoint, chal.safe_endpoints[0]
        p = chal.vulnerable_parameter

        # /health is up; discovery lists endpoints
        assert _get(base, "/health")[0] == 200

        # vuln + internal host -> canary leaks (the SSRF)
        code, body = _get(base, f"{vuln}?{p}=http://127.0.0.1/")
        assert code == 200 and chal.canary in body

        # vuln + external url -> benign, no canary
        code, body = _get(base, f"{vuln}?{p}=http://example.com/")
        assert code == 200 and chal.canary not in body

        # DECOY + internal host -> blocked (403), no canary (false positive if flagged)
        code, body = _get(base, f"{safe}?{p}=http://127.0.0.1/")
        assert code == 403 and chal.canary not in body

        # metadata host variant also leaks on the vuln endpoint
        code, body = _get(base, f"{vuln}?{p}=http://169.254.169.254/latest/meta-data/")
        assert chal.canary in body
    finally:
        server.shutdown()


def test_agent_solves_ssrf(monkeypatch):
    chal = ch.generate_challenge(category=ch.CATEGORY_SSRF)
    server, base = _start(monkeypatch, chal)
    try:
        monkeypatch.setenv("TARGET_URL", base)
        agent = _load_agent()
        finding = agent.ssrf_solve()
        assert finding is not None
        assert finding["evidence"]["canary"] == chal.canary
        assert finding["endpoint"] == chal.vulnerable_endpoint
        assert finding["parameter"] == chal.vulnerable_parameter
    finally:
        server.shutdown()


def test_ssrf_challenge_fields():
    a = ch.generate_challenge(category=ch.CATEGORY_SSRF)
    assert a.category == "ssrf" and a.vulnerable_parameter in ch.SSRF_PARAMS
    assert a.vulnerable_endpoint not in a.safe_endpoints
    env = provision.target_env(a)
    assert env["SSRF_CANARY"] == a.canary
    assert json.loads(env["SSRF_ALL_ENDPOINTS"])[0] == a.vulnerable_endpoint

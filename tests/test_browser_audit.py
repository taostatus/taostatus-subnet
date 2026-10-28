"""Tests for audit_runner.run_browser_audit -- the Live-URL headless-browser path.

The real Playwright+Chromium run is integration-tested on the isolation host.
Here we pin the ORCHESTRATION: the target is anti-SSRF gated before anything
starts, our browser image runs with gVisor + egress (not the single-host proxy),
credentials are handed over as the SECAUDIT_CREDS secret, the agent's potentials
flow into an analysis-only report with a 'tested endpoints' trail, and the
container is always torn down.
"""

import json

from secqurityVali import audit_runner as ar
from secqurityVali import constants as C
from secqurityVali import job
from secqurityVali.target_guard import TargetRejected


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _wire(monkeypatch, *, doc, returncode=0):
    recorded = {"args": []}

    def fake_run(args, **k):
        recorded["args"].append(args)
        return _Proc(returncode)

    monkeypatch.setattr(job, "_run", fake_run)
    monkeypatch.setattr(job, "_read_findings", lambda out_dir: json.dumps(doc).encode())
    monkeypatch.setattr(job, "_rm_container", lambda n: recorded.setdefault("removed", []).append(n))
    monkeypatch.setattr(ar, "validate_target", lambda u, allow_private=False: object())
    return recorded


def test_rejects_ssrf_target_before_running(monkeypatch):
    ran = {"run": False}
    monkeypatch.setattr(job, "_run", lambda *a, **k: ran.__setitem__("run", True) or _Proc(0))

    def reject(u, allow_private=False):
        raise TargetRejected("private IP")

    monkeypatch.setattr(ar, "validate_target", reject)
    rep = ar.run_browser_audit("http://169.254.169.254/")
    assert rep.status == "failed" and "target rejected" in rep.error
    assert ran["run"] is False                      # no container ever started


def test_potentials_become_analysis_only_report_with_tested_trail(monkeypatch):
    doc = {
        "findings": [
            {"type": "sqli", "endpoint": "/products", "parameter": "cat",
             "severity": "high", "detail": "SQL error reflected"},
        ],
        "tested_endpoints": ["/", "/products", "/api/listings/7"],
    }
    rec = _wire(monkeypatch, doc=doc)
    rep = ar.run_browser_audit("https://shop.example.com")
    assert rep.status == "completed"
    assert rep.analysis_only is True and rep.confirmed is False
    # the real finding plus one recon row naming what was tested
    kinds = [f["type"] for f in rep.findings]
    assert "sqli" in kinds and "recon" in kinds
    recon = [f for f in rep.findings if f["type"] == "recon"][0]
    assert "/products" in recon["detail"] and recon["severity"] == "info"
    assert rep.findings[0]["scanner"] == "browser"      # stamped
    assert rep.request_count == 3                        # tested-endpoint count


def test_login_status_note_surfaced_when_creds_used(monkeypatch):
    # login attempted but NOT confirmed -> a low-severity heads-up row, so a
    # 0-finding result is not mistaken for a clean app.
    _wire(monkeypatch, doc={"findings": [], "tested_endpoints": ["/"],
                            "login_attempted": True, "authenticated": False})
    rep = ar.run_browser_audit("https://shop.example.com",
                               credentials={"mode": "form", "username": "a", "password": "b"})
    auth = [f for f in rep.findings if f.get("endpoint") == "authentication"]
    assert auth and auth[0]["severity"] == "low" and "PUBLIC surface" in auth[0]["detail"]


def test_login_status_note_confirms_authenticated(monkeypatch):
    _wire(monkeypatch, doc={"findings": [], "tested_endpoints": ["/"],
                            "login_attempted": True, "authenticated": True})
    rep = ar.run_browser_audit("https://shop.example.com",
                               credentials={"mode": "form", "username": "a", "password": "b"})
    auth = [f for f in rep.findings if f.get("endpoint") == "authentication"]
    assert auth and auth[0]["severity"] == "info" and "Logged in" in auth[0]["detail"]


def test_no_login_note_without_creds(monkeypatch):
    _wire(monkeypatch, doc={"findings": [], "tested_endpoints": ["/"]})
    rep = ar.run_browser_audit("https://shop.example.com")
    assert not [f for f in rep.findings if f.get("endpoint") == "authentication"]


def test_credentials_passed_as_secret_env(monkeypatch):
    rec = _wire(monkeypatch, doc={"findings": [], "tested_endpoints": []})
    creds = {"mode": "form", "username": "admin", "password": "s3cret"}
    ar.run_browser_audit("https://shop.example.com", credentials=creds)
    run_args = [a for a in rec["args"] if a and a[0] == "run"][0]
    joined = " ".join(run_args)
    assert "SECAUDIT_CREDS=" in joined and "s3cret" in joined
    assert C.BROWSER_AGENT_IMAGE in run_args
    assert "--shm-size" in run_args and C.BROWSER_AGENT_SHM in run_args
    assert "--runtime" in run_args                       # gVisor isolation


def test_nonzero_exit_is_failed_not_raised(monkeypatch):
    _wire(monkeypatch, doc={}, returncode=37)
    rep = ar.run_browser_audit("https://shop.example.com")
    assert rep.status == "failed" and "exited 37" in rep.error


def test_container_always_removed(monkeypatch):
    rec = _wire(monkeypatch, doc={"findings": [], "tested_endpoints": []})
    ar.run_browser_audit("https://shop.example.com")
    assert rec.get("removed")                            # _rm_container called in finally

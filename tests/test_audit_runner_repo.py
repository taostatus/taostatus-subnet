"""Tests for audit_runner.run_audit_from_repo -- the repo-build audit path.

The real docker run is integration-tested on the isolation host. Here we pin the
ORCHESTRATION: provisioning failure is a clean failed report (no agent ever
runs), the agent is pointed at the isolated target by IP (no proxy), the
in-network confirmer's verdict flows into the gate-first score, and everything is
torn down afterwards.
"""

import tempfile

from secqurityVali import audit_runner as ar
from secqurityVali import job
from secqurityVali import repo_target as rt


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_target():
    t = rt.RepoTarget(network="net-x", name="tgt-x", ip="172.30.0.9", port=8000,
                      image_tag="img:x", clone_dir="")
    t.teardown = lambda: None            # no real docker in teardown
    return t


def _wire_agent_run(monkeypatch, *, behaviour="strace: openat...", findings=b'[]'):
    """Stub every docker-touching helper so the agent 'runs' without docker."""
    monkeypatch.setattr(job, "_blackhole_resolv", lambda: tempfile.mkstemp(prefix="t-resolv-")[1])
    recorded = {}

    def fake_run(args, **k):
        recorded.setdefault("args", []).append(args)
        if args and args[0] == "create":
            return _Proc(0, stdout="agentcid")
        return _Proc(0)

    monkeypatch.setattr(job, "_run", fake_run)
    monkeypatch.setattr(job, "_read_findings", lambda out_dir: findings)
    monkeypatch.setattr(job, "_read_behaviour", lambda cid: behaviour)
    monkeypatch.setattr(job, "_rm_container", lambda n: None)
    monkeypatch.setattr(ar, "analyze", lambda b: b)
    monkeypatch.setattr(ar, "safety_verdict", lambda a: (True, []))
    return recorded


def test_provision_failure_is_failed_report_without_running_agent(monkeypatch):
    ran = {"agent": False}
    monkeypatch.setattr(job, "_run", lambda *a, **k: ran.__setitem__("agent", True) or _Proc(0))

    def boom(*a, **k):
        raise rt.RepoError("no Dockerfile found in the build context")

    r = ar.run_audit_from_repo("agent:img", "https://github.com/me/app.git", provision=boom)
    assert r.status == "failed" and r.score == 0.0
    assert "no Dockerfile" in r.error
    assert ran["agent"] is False        # agent never started


def test_confirmed_safe_run_scores_and_points_agent_at_target_ip(monkeypatch):
    recorded = _wire_agent_run(monkeypatch, findings=b'[{"parameter":"id","endpoint":"/x"}]')
    r = ar.run_audit_from_repo(
        "agent:img", "https://github.com/me/app.git",
        provision=lambda url, **k: _fake_target(),
        confirm=lambda target, findings: (True, 0),
    )
    assert r.status == "completed" and r.confirmed is True and r.safe is True
    assert r.score == 1.0
    # the agent was created pointed at the target IP:port (no proxy)
    create = [a for a in recorded["args"] if a and a[0] == "create"][0]
    assert any("TARGET_URL=http://172.30.0.9:8000" in str(x) for x in create)


def test_unconfirmed_run_scores_zero(monkeypatch):
    _wire_agent_run(monkeypatch)
    r = ar.run_audit_from_repo(
        "agent:img", "https://github.com/me/app.git",
        provision=lambda url, **k: _fake_target(),
        confirm=lambda target, findings: (False, 1),
    )
    assert r.status == "completed" and r.confirmed is False
    assert r.score == 0.0 and r.false_positives == 1


def test_missing_monitoring_fails_closed(monkeypatch):
    _wire_agent_run(monkeypatch, behaviour="")      # no gVisor log -> unsafe
    r = ar.run_audit_from_repo(
        "agent:img", "https://github.com/me/app.git",
        provision=lambda url, **k: _fake_target(),
        confirm=lambda target, findings: (True, 0),
    )
    assert r.safe is False and r.score == 0.0


def test_target_is_torn_down_on_success(monkeypatch):
    _wire_agent_run(monkeypatch)
    torn = {"n": 0}
    t = _fake_target()
    t.teardown = lambda: torn.__setitem__("n", torn["n"] + 1)
    ar.run_audit_from_repo(
        "agent:img", "https://github.com/me/app.git",
        provision=lambda url, **k: t,
        confirm=lambda target, findings: (True, 0),
    )
    assert torn["n"] == 1

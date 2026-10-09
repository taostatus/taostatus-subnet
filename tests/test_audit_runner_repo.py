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


def test_unbuildable_repo_falls_back_to_static_without_running_agent(monkeypatch):
    ran = {"agent": False}
    monkeypatch.setattr(job, "_run", lambda *a, **k: ran.__setitem__("agent", True) or _Proc(0))

    def boom(*a, **k):
        raise rt.RepoError("no Dockerfile found in the build context")

    static_calls = []

    def fake_static(url, **k):
        static_calls.append((url, k.get("reason")))
        return ar.AuditReport(status="completed", confirmed=False, analysis_only=True,
                              score=0.0, findings=[{"type": "sqli", "status": "potential"}])

    r = ar.run_audit_from_repo("agent:img", "https://github.com/me/app.git",
                               provision=boom, static_fallback=fake_static)
    assert r.status == "completed" and r.analysis_only is True and r.score == 0.0
    assert r.confirmed is False and r.findings[0]["status"] == "potential"
    assert static_calls and "no Dockerfile" in (static_calls[0][1] or "")
    assert ran["agent"] is False        # agent never started -- nothing was run/attacked


def test_static_only_report_uses_the_static_scan(tmp_path):
    fake = rt.RepoTarget(network="", name="", ip="", port=0, image_tag="",
                         clone_dir=str(tmp_path))
    torn = {"n": 0}
    fake.teardown = lambda: torn.__setitem__("n", torn["n"] + 1)
    scanned = {}

    def fake_scan(root, aspects=None):
        scanned["root"] = root
        return [{"type": "sqli", "severity": "high", "status": "potential",
                 "source_file": "app.py", "source_line": 5}]

    r = ar.run_static_audit_from_repo("https://github.com/me/app.git",
                                      provision_source=lambda url, **k: fake,
                                      scan=fake_scan)
    assert r.status == "completed" and r.analysis_only is True and r.score == 0.0
    assert r.findings[0]["type"] == "sqli" and r.findings[0]["status"] == "potential"
    assert scanned["root"].endswith("src")   # scanned the cloned repo root
    assert torn["n"] == 1                     # clone always cleaned up


def test_merge_findings_promotes_confirmed_and_keeps_static_potentials():
    static = [
        {"type": "sqli", "severity": "high", "status": "potential",
         "source_file": "app.py", "source_line": 10},
        {"type": "secret", "severity": "critical", "status": "potential",
         "source_file": "config.py", "source_line": 3},
    ]
    # the agent confirmed the app.py:10 sqli (same file:line as a static finding)
    agent = [{"type": "sqli", "source_file": "app.py", "source_line": 10, "canary": "c"}]

    merged = ar._merge_findings(agent, static, confirmed=True)
    # confirmed first; the static finding at the SAME file:line is not duplicated;
    # the unrelated secret stays as a potential
    assert [f["status"] for f in merged] == ["confirmed", "potential"]
    assert merged[1]["type"] == "secret"

    # nothing confirmed -> agent's unverified claim dropped, both static remain
    merged2 = ar._merge_findings(agent, static, confirmed=False)
    assert [f["status"] for f in merged2] == ["potential", "potential"]
    assert {f["type"] for f in merged2} == {"sqli", "secret"}


def test_buildable_repo_still_reports_static_potentials(monkeypatch, tmp_path):
    # a buildable repo whose live attack confirms nothing must still surface the
    # Layer-1 static findings (the we45 case).
    target = _fake_target()
    target.clone_dir = str(tmp_path)
    _wire_agent_run(monkeypatch, findings=b"[]")        # agent exploits nothing
    r = ar.run_audit_from_repo(
        "agent:img", "https://github.com/me/app.git",
        provision=lambda url, **k: target,
        confirm=lambda t, f: (False, 0),                 # unconfirmed
        scan=lambda root, aspects=None: [{"type": "xss", "severity": "medium", "status": "potential",
                                          "source_file": "views.py", "source_line": 20}],
    )
    assert r.status == "completed" and r.confirmed is False
    assert len(r.findings) == 1 and r.findings[0]["status"] == "potential"
    assert r.findings[0]["type"] == "xss" and r.findings[0]["source_line"] == 20


def test_no_exploit_aspect_skips_build_entirely(monkeypatch):
    # when the customer doesn't ask for a live exploit, we must NOT build/attack --
    # just run the static scan (fast path).
    def prov(*a, **k):
        raise AssertionError("provision/build must not run when exploit is off")

    seen = {}

    def fallback(url, **k):
        seen["aspects"] = k.get("aspects")
        return ar.AuditReport(status="completed", analysis_only=True, confirmed=False,
                              score=0.0, findings=[{"type": "sqli", "status": "potential"}])

    r = ar.run_audit_from_repo(
        "img", "https://github.com/me/app.git",
        aspects={"code", "deps"}, provision=prov, static_fallback=fallback)
    assert r.status == "completed" and r.analysis_only is True
    assert "exploit" not in seen["aspects"]            # exploit was not requested


def test_static_scan_clone_failure_is_failed_report():
    def boom(url, **k):
        raise rt.RepoError("repository host did not resolve")
    r = ar.run_static_audit_from_repo("https://nope.invalid/x.git", provision_source=boom)
    assert r.status == "failed" and r.score == 0.0
    assert "did not resolve" in r.error


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


# --- Phase B: white-box code analysis -> attack hints -> located report ---

def test_hints_env_from_candidates():
    from secqurityVali.code_analysis import Candidate
    cands = [
        Candidate("app.py", 10, "sqli", "cursor.execute(...)", "/search", "q", "high", ""),
        Candidate("util.py", 5, "sqli", "cursor.execute(...)", None, None, "medium", ""),  # no endpoint
    ]
    env = ar._hints_env(cands)
    import json
    hints = json.loads(env["SECAUDIT_HINTS"])
    assert hints == [{"endpoint": "/search", "parameter": "q", "category": "sqli"}]  # endpoint-only
    assert ar._hints_env([]) == {}


def test_attach_source_locations():
    from secqurityVali.code_analysis import Candidate
    cands = [Candidate("app.py", 166, "sqli", "cursor.execute(<built string>)", "/search", "q", "high", "x")]
    findings = [{"endpoint": "/search", "parameter": "q", "type": "sqli", "canary": "c"},
                {"endpoint": "/other", "parameter": "z"}]
    ar._attach_source_locations(findings, cands)
    assert findings[0]["source_file"] == "app.py" and findings[0]["source_line"] == 166
    assert findings[0]["sink"] == "cursor.execute(<built string>)"
    assert "source_file" not in findings[1]          # no matching candidate


def test_repo_audit_is_white_box_hints_and_locates(monkeypatch, tmp_path):
    # a tiny vulnerable app the analyzer will read
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "from flask import request\n"
        "@app.get('/s')\n"
        "def s():\n"
        "    q = request.args.get('q')\n"
        "    cur.execute(f\"SELECT {q}\")\n"
    )
    target = _fake_target()
    target.clone_dir = str(tmp_path)

    recorded = _wire_agent_run(
        monkeypatch, findings=b'[{"endpoint":"/s","parameter":"q","type":"sqli","canary":"c"}]')
    report = ar.run_audit_from_repo(
        "agent:img", "https://github.com/me/app.git",
        provision=lambda url, **k: target,
        confirm=lambda t, f: (True, 0),
    )
    # the agent was handed the real endpoint as a hint
    create = [a for a in recorded["args"] if a and a[0] == "create"][0]
    assert any("SECAUDIT_HINTS" in str(x) and "/s" in str(x) for x in create)
    # and the agent gets the source mounted READ-ONLY so it can analyse it itself
    assert any("SECAUDIT_SOURCE_DIR=/src" in str(x) for x in create)
    assert any("dst=/src" in str(x) and "readonly" in str(x) for x in create)
    # and the confirmed finding points at the source line
    assert report.findings[0]["source_file"] == "app.py"   # repo-relative, fwd-slash
    assert report.findings[0]["source_line"] == 5


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

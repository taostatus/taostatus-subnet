"""Security-policy tests for the operational audit loop
(secqurityVali/audit_loop.process_audit_job). Seams are injected: no docker."""

from secqurityVali.audit_loop import process_audit_job


class _Report:
    def __init__(self, body):
        self._body = body
    def to_result(self):
        return self._body


def _job(**over):
    j = {"run_id": "r1", "agent_id": "5Agent", "target_url": "https://shop.example.com"}
    j.update(over)
    return j


def _runner(calls):
    def run_audit(image, target_url, **kw):
        calls.append((image, target_url, kw))
        return _Report({"status": "completed", "score": 1.0, "confirmed": True})
    return run_audit


def test_happy_path_runs_and_returns_result():
    calls = []
    out = process_audit_job(_job(), is_vetted=lambda a: True,
                            resolve_agent=lambda a: "img:1", run_audit=_runner(calls))
    assert out["status"] == "completed" and out["score"] == 1.0
    assert calls == [("img:1", "https://shop.example.com", {"scope": None})]


def test_unvetted_agent_is_never_run():
    calls = []
    out = process_audit_job(_job(), is_vetted=lambda a: False,
                            resolve_agent=lambda a: "img:1", run_audit=_runner(calls))
    assert out["status"] == "failed" and "not vetted" in out["error"]
    assert calls == []                      # run_audit must NOT be called


def test_unavailable_agent_fails_without_running():
    calls = []
    out = process_audit_job(_job(), is_vetted=lambda a: True,
                            resolve_agent=lambda a: None, run_audit=_runner(calls))
    assert out["status"] == "failed" and "unavailable" in out["error"]
    assert calls == []


def test_resolve_error_is_failed_not_raised():
    def boom(a): raise RuntimeError("miner offline")
    out = process_audit_job(_job(), is_vetted=lambda a: True, resolve_agent=boom,
                            run_audit=_runner([]))
    assert out["status"] == "failed" and "could not be obtained" in out["error"]


def test_malformed_job_is_failed():
    calls = []
    for bad in ({}, {"run_id": "r"}, {"agent_id": "a", "target_url": "u"}):
        out = process_audit_job(bad, is_vetted=lambda a: True,
                                resolve_agent=lambda a: "img", run_audit=_runner(calls))
        assert out["status"] == "failed"
    assert calls == []


def test_failed_report_passes_through():
    def run_audit(image, target_url, **kw):
        return _Report({"status": "failed", "score": 0.0, "error": "target unreachable"})
    out = process_audit_job(_job(), is_vetted=lambda a: True,
                            resolve_agent=lambda a: "img", run_audit=run_audit)
    assert out["status"] == "failed" and out["error"] == "target unreachable"


def test_scope_is_forwarded():
    calls = []
    process_audit_job(_job(scope={"paths": ["/api"]}), is_vetted=lambda a: True,
                      resolve_agent=lambda a: "img", run_audit=_runner(calls))
    assert calls[0][2]["scope"] == {"paths": ["/api"]}

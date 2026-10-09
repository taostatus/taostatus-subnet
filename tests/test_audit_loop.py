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
    assert calls == [("img:1", "https://shop.example.com", {"scope": None, "credentials": None})]


def test_repo_source_type_routes_to_white_box_runner():
    url_calls, repo_calls = [], []

    def repo_runner(image, repo_url, **kw):
        repo_calls.append((image, repo_url, kw))
        return _Report({"status": "completed", "score": 1.0, "confirmed": True})

    job = _job(target_url="https://github.com/me/app.git",
               scope={"source_type": "repo"})
    out = process_audit_job(job, is_vetted=lambda a: True,
                            resolve_agent=lambda a: "img:1",
                            run_audit=_runner(url_calls), run_audit_from_repo=repo_runner)
    assert out["status"] == "completed"
    assert url_calls == []                                        # black-box never called
    assert repo_calls == [("img:1", "https://github.com/me/app.git",
                           {"aspects": None, "credentials": None})]


def test_url_source_type_still_uses_black_box_runner():
    calls = []
    job = _job(scope={"source_type": "url"})
    process_audit_job(job, is_vetted=lambda a: True,
                      resolve_agent=lambda a: "img:1", run_audit=_runner(calls))
    assert calls[0][0] == "img:1" and calls[0][2]["scope"] == {"source_type": "url"}


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


def test_browser_engine_disabled_by_default_is_refused(monkeypatch):
    # The browser path runs with full egress (SSRF risk), so it is OFF by default
    # and the WORKER refuses it -- not just the UI.
    import secqurityVali.audit_loop as al
    monkeypatch.setattr(al.C, "BROWSER_AUDIT_ENABLED", False, raising=False)
    browser_calls = []
    job = _job(scope={"source_type": "url", "engine": "browser"})
    out = process_audit_job(
        job, is_vetted=lambda a: True, resolve_agent=lambda a: "img:1",
        run_browser_audit=lambda *a, **k: browser_calls.append(1) or _Report({}))
    assert out["status"] == "failed" and "unavailable" in out["error"]
    assert browser_calls == []                    # never ran


def test_browser_engine_routes_to_browser_runner_without_miner_image(monkeypatch):
    import secqurityVali.audit_loop as al
    monkeypatch.setattr(al.C, "BROWSER_AUDIT_ENABLED", True, raising=False)
    url_calls, repo_calls, browser_calls = [], [], []

    def browser_runner(target_url, **kw):
        browser_calls.append((target_url, kw))
        return _Report({"status": "completed", "confirmed": False, "analysis_only": True})

    # vetting/resolve deliberately fail -- the browser path is our own trusted
    # agent and must not depend on a miner image being vetted/served.
    job = _job(scope={"source_type": "url", "engine": "browser"},
               credentials={"mode": "form", "username": "a", "password": "b"})
    out = process_audit_job(
        job, is_vetted=lambda a: False,
        resolve_agent=lambda a: (_ for _ in ()).throw(RuntimeError("no image")),
        run_audit=_runner(url_calls), run_audit_from_repo=lambda *a, **k: repo_calls.append(1),
        run_browser_audit=browser_runner)
    assert out["status"] == "completed" and out["analysis_only"] is True
    assert url_calls == [] and repo_calls == []
    assert browser_calls == [("https://shop.example.com",
                              {"credentials": {"mode": "form", "username": "a", "password": "b"}})]


def test_browser_engine_ignored_for_repo_source():
    repo_calls, browser_calls = [], []
    job = _job(target_url="https://github.com/me/app.git",
               scope={"source_type": "repo", "engine": "browser"})
    process_audit_job(
        job, is_vetted=lambda a: True, resolve_agent=lambda a: "img:1",
        run_audit_from_repo=lambda image, url, **kw: repo_calls.append((image, url)) or _Report({"status": "completed"}),
        run_browser_audit=lambda *a, **k: browser_calls.append(1) or _Report({}))
    assert browser_calls == [] and repo_calls == [("img:1", "https://github.com/me/app.git")]

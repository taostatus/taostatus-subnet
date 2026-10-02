"""Precise tests for the audit scoring gates (secqurityVali/audit_runner).

The orchestration (run_audit) is integration-tested on the isolation host; here
we pin down the PURE, security-critical scoring: an unsafe, uncertifiable, or
unconfirmed run must earn nothing, and the refinements must never rescue it.
"""

from secqurityVali.audit_runner import AuditReport, _parse_findings, score_audit


def _good(**over):
    """A confirmed, safe, fast, clean run -- the baseline that scores ~1.0."""
    kw = dict(confirmed=True, safe=True, monitoring_available=True, timed_out=False,
              duration_ms=10_000, request_count=50, error_count=0, false_positives=0)
    kw.update(over)
    return kw


# --- the hard gates (all must zero the score) ---------------------------

def test_monitoring_unavailable_scores_zero_fail_closed():
    score, _ = score_audit(**_good(monitoring_available=False))
    assert score == 0.0


def test_unsafe_scores_zero():
    score, _ = score_audit(**_good(safe=False))
    assert score == 0.0


def test_unconfirmed_scores_zero():
    score, _ = score_audit(**_good(confirmed=False))
    assert score == 0.0


def test_gates_beat_every_refinement():
    # even a perfect, fast, clean run earns nothing if it isn't confirmed+safe
    score, _ = score_audit(**_good(confirmed=False, safe=False, monitoring_available=False))
    assert score == 0.0


# --- the refinements (only apply once the gates pass) -------------------

def test_perfect_run_scores_top():
    score, clean = score_audit(**_good())
    assert score == 1.0 and clean is True


def test_slow_run_scores_lower():
    assert score_audit(**_good(duration_ms=60_000))[0] == 0.9     # speed 0.5


def test_inefficient_run_scores_lower():
    # 800 requests vs a 200 target -> efficiency 0.25
    assert round(score_audit(**_good(request_count=800))[0], 4) == 0.8875


def test_errors_make_it_unclean_and_lower():
    score, clean = score_audit(**_good(error_count=5))
    assert clean is False and score == 0.85          # cleanliness term drops out


def test_timeout_makes_it_unclean():
    _, clean = score_audit(**_good(timed_out=True))
    assert clean is False


def test_false_positives_subtract():
    assert round(score_audit(**_good(false_positives=2))[0], 4) == 0.8    # 1.0 - 0.2


def test_score_is_clamped_to_zero():
    assert score_audit(**_good(false_positives=20))[0] == 0.0             # never negative


# --- report shape + findings parsing -----------------------------------

def test_report_to_result_has_backend_fields():
    r = AuditReport(status="completed", confirmed=True, clean=True, safe=True, score=1.0,
                    duration_ms=1000, request_count=10, error_count=0, false_positives=0,
                    findings=[{"type": "sqli"}])
    body = r.to_result()
    assert set(body) == {"status", "confirmed", "clean", "safe", "score", "duration_ms",
                         "request_count", "error_count", "false_positives", "findings", "error"}
    assert body["status"] == "completed" and body["findings"] == [{"type": "sqli"}]


def test_failed_report_is_zero_and_unsafe():
    r = AuditReport.failed("target rejected: metadata")
    assert r.status == "failed" and r.score == 0.0
    assert r.confirmed is False and r.safe is False and "metadata" in r.error


def test_parse_findings_handles_shapes():
    assert _parse_findings(b'{"findings": [{"a": 1}]}') == [{"a": 1}]
    assert _parse_findings(b'[{"b": 2}]') == [{"b": 2}]
    assert _parse_findings(b'not json') == []
    assert _parse_findings(b'') == []
    assert _parse_findings(b'{"no_findings_key": 1}') == []

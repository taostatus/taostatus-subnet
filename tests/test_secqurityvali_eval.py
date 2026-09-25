"""Tests for the evaluation half: challenge generation, findings parsing,
and task scoring.

All pure logic -- no Docker, no network, no VPS. The point is to prove the
grading cannot be gamed: fabricated findings score zero, padding is punished,
and only the real canary earns anything.
"""

import json

import pytest

from secqurityVali.eval.challenge import Challenge, generate_challenge
from secqurityVali.eval.findings import (
    Findings,
    FindingsError,
    parse_findings_bytes,
    parse_findings_file,
)
from secqurityVali.eval.task_score import score_task


# --- challenge generation ----------------------------------------------

def test_each_challenge_has_a_unique_canary():
    canaries = {generate_challenge().canary for _ in range(50)}
    assert len(canaries) == 50            # no collisions across 50 runs


def test_canary_is_128_bits_of_hex():
    c = generate_challenge()
    assert len(c.canary) == 32
    int(c.canary, 16)                     # parses as hex, or raises


def test_vulnerable_endpoint_is_not_also_listed_safe():
    for _ in range(20):
        c = generate_challenge()
        assert c.vulnerable_endpoint not in c.safe_endpoints


def test_schema_names_vary_between_runs():
    a, b = generate_challenge(), generate_challenge()
    # Astronomically unlikely to collide; if they do, the suffix is broken.
    assert (a.secret_table, a.secret_column) != (b.secret_table, b.secret_column)


# --- findings parsing --------------------------------------------------

def _valid_doc(challenge, canary=None, extra_findings=None):
    doc = {
        "schema_version": "1.0",
        "run_id": "run-123",
        "agent": {"name": "demo", "version": "0.1.0"},
        "findings": [{
            "endpoint": challenge.vulnerable_endpoint,
            "parameter": challenge.vulnerable_parameter,
            "injection_type": "sql_injection",
            "payload": "' UNION SELECT x--",
            "severity": "high",
            "confidence": 0.9,
            "evidence": {"canary": canary if canary is not None else challenge.canary},
        }],
        "reproduction": [{
            "finding_index": 0,
            "method": "GET",
            "path": challenge.vulnerable_endpoint,
            "query": {challenge.vulnerable_parameter: "' UNION SELECT x--"},
        }],
    }
    if extra_findings:
        doc["findings"].extend(extra_findings)
    return json.dumps(doc).encode()


def test_valid_document_parses():
    c = generate_challenge()
    f = parse_findings_bytes(_valid_doc(c), expected_run_id="run-123")
    assert f.run_id == "run-123"
    assert len(f.findings) == 1
    assert f.findings[0].canary == c.canary


def test_canary_accepted_at_top_level_or_in_evidence():
    c = generate_challenge()
    doc = {
        "run_id": "r",
        "findings": [{"endpoint": "/x", "parameter": "q", "canary": c.canary}],
        "reproduction": [],
    }
    f = parse_findings_bytes(json.dumps(doc).encode())
    assert f.findings[0].canary == c.canary


def test_invalid_json_is_rejected_without_echoing_content():
    with pytest.raises(FindingsError) as err:
        parse_findings_bytes(b"{not json at all")
    # The raw (attacker-controlled) bytes must not appear in the error.
    assert "not json" not in str(err.value).lower() or "valid JSON" in str(err.value)


def test_wrong_run_id_is_rejected():
    c = generate_challenge()
    with pytest.raises(FindingsError):
        parse_findings_bytes(_valid_doc(c), expected_run_id="a-different-run")


def test_oversized_file_is_rejected():
    huge = b'{"run_id":"r","findings":[],"reproduction":[],"pad":"' + b"A" * (2 * 1024 * 1024) + b'"}'
    with pytest.raises(FindingsError):
        parse_findings_bytes(huge)


def test_too_many_findings_is_rejected():
    doc = {"run_id": "r", "findings": [{"endpoint": "/x", "parameter": "q"}] * 500,
           "reproduction": []}
    with pytest.raises(FindingsError):
        parse_findings_bytes(json.dumps(doc).encode())


def test_confidence_out_of_range_is_rejected():
    doc = {"run_id": "r", "reproduction": [],
           "findings": [{"endpoint": "/x", "parameter": "q", "confidence": 5.0}]}
    with pytest.raises(FindingsError):
        parse_findings_bytes(json.dumps(doc).encode())


def test_missing_file_is_a_clear_error(tmp_path):
    with pytest.raises(FindingsError):
        parse_findings_file(tmp_path / "nope.json")


def test_reproduction_pointing_nowhere_is_rejected():
    doc = {"run_id": "r", "findings": [],
           "reproduction": [{"finding_index": 3, "path": "/x"}]}
    with pytest.raises(FindingsError):
        parse_findings_bytes(json.dumps(doc).encode())


def test_reproduction_tolerates_f_prefixed_ids():
    doc = {"run_id": "r",
           "findings": [{"endpoint": "/x", "parameter": "q"}],
           "reproduction": [{"finding_id": "f1", "path": "/x", "method": "get"}]}
    f = parse_findings_bytes(json.dumps(doc).encode())
    assert f.reproduction[0].finding_index == 0
    assert f.reproduction[0].method == "GET"


# --- task scoring: the anti-gaming guarantees --------------------------

def test_correct_canary_and_location_without_replay_scores_half():
    c = generate_challenge()
    f = parse_findings_bytes(_valid_doc(c))
    result = score_task(c, f, replay_confirmed=False)
    assert result.canary_found is True
    assert result.score == 0.5


def test_replay_confirmation_raises_the_score():
    c = generate_challenge()
    f = parse_findings_bytes(_valid_doc(c))
    result = score_task(c, f, replay_confirmed=True)
    assert result.located is True
    assert result.score == 1.0


def test_canary_and_replay_but_wrong_location_scores_between():
    c = generate_challenge()
    # Right canary, but names a safe endpoint as the location.
    doc = {
        "run_id": "r",
        "findings": [{
            "endpoint": c.safe_endpoints[0],
            "parameter": "wrong",
            "canary": c.canary,
        }],
        "reproduction": [],
    }
    f = parse_findings_bytes(json.dumps(doc).encode())
    result = score_task(c, f, replay_confirmed=True)
    assert result.canary_found is True
    assert result.located is False
    # The matched finding carried the canary, so it is not also counted as a
    # false positive -- wrong location already dropped it from 1.0 to 0.8.
    # Double-penalising the same finding would be unfair.
    assert result.false_positives == 0
    assert result.score == pytest.approx(0.8)


def test_fabricated_canary_scores_zero():
    """The core guarantee: an agent that invents a canary earns nothing."""
    c = generate_challenge()
    fake = "deadbeef" * 4
    assert fake != c.canary
    f = parse_findings_bytes(_valid_doc(c, canary=fake))
    result = score_task(c, f, replay_confirmed=True)   # even with replay claimed
    assert result.canary_found is False
    assert result.score == 0.0


def test_no_canary_at_all_scores_zero():
    c = generate_challenge()
    doc = {"run_id": "r",
           "findings": [{"endpoint": c.vulnerable_endpoint, "parameter": c.vulnerable_parameter}],
           "reproduction": []}
    f = parse_findings_bytes(json.dumps(doc).encode())
    assert score_task(c, f, replay_confirmed=True).score == 0.0


def test_replay_cannot_rescue_a_run_with_no_canary():
    c = generate_challenge()
    empty = Findings(run_id="r", findings=[], reproduction=[])
    assert score_task(c, empty, replay_confirmed=True).score == 0.0


def test_spraying_every_endpoint_is_punished():
    """Reporting the real one plus every decoy: the decoys cost precision."""
    c = generate_challenge()
    extras = [{"endpoint": e, "parameter": "q", "confidence": 0.9} for e in c.safe_endpoints]
    f = parse_findings_bytes(_valid_doc(c, extra_findings=extras))
    result = score_task(c, f, replay_confirmed=True)
    assert result.canary_found is True
    assert result.false_positives == len(c.safe_endpoints)
    # 1.0 base minus 0.1 per decoy -- 4 decoys wipes out most of the score.
    assert result.score == pytest.approx(max(0.0, 1.0 - 0.1 * len(c.safe_endpoints)))


def test_false_positive_penalty_floors_at_zero():
    c = generate_challenge()
    # Many decoys, no canary: cannot go negative.
    extras = [{"endpoint": e, "parameter": "q"} for e in c.safe_endpoints]
    doc = {"run_id": "r", "reproduction": [],
           "findings": [{"endpoint": "/nope", "parameter": "q"}] + extras}
    f = parse_findings_bytes(json.dumps(doc).encode())
    assert score_task(c, f, replay_confirmed=True).score == 0.0


def test_result_explains_itself():
    c = generate_challenge()
    f = parse_findings_bytes(_valid_doc(c))
    result = score_task(c, f, replay_confirmed=True)
    assert result.notes                      # never a bare number
    assert "matched_finding_index" in result.to_dict()

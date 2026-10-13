"""Tests for secqurityVali/report.py - the formatted audit report."""

from secqurityVali.report import format_report


def _finding(**kw):
    base = {"type": "sqli", "category": "sqli", "endpoint": "/api/items",
            "parameter": "q", "payload": "' OR '1'='1", "severity": "high",
            "status": "confirmed", "evidence": "canary leaked"}
    base.update(kw)
    return base


def test_confirmed_finding_is_presented_with_fix():
    r = format_report([_finding()], target="https://shop.example",
                      confirmed=True, score=0.9, safe=True, agent_name="agent-x")
    assert r["verdict"] == "vulnerable"
    assert r["summary"]["confirmed_count"] == 1
    assert r["summary"]["by_severity"] == {"high": 1}
    f = r["findings"][0]
    assert f["title"] == "SQL Injection" and f["category"] == "sqli"
    assert f["location"] == {"endpoint": "/api/items", "parameter": "q"}
    assert "parameterized queries" in f["remediation"].lower()
    assert f["impact"] and f["reference"].startswith("OWASP")
    # markdown carries the same substance
    md = r["markdown"]
    assert "# Security Audit Report" in md and "SQL Injection" in md
    assert "How to fix" in md and "' OR '1'='1" in md


def test_clean_run_has_no_findings():
    r = format_report([], target="https://safe.example", confirmed=False,
                      score=0.0, safe=True)
    assert r["verdict"] == "clean"
    assert r["summary"]["confirmed_count"] == 0
    assert "No confirmed vulnerabilities" in r["markdown"]


def test_only_confirmed_count_as_vulns_potential_listed_separately():
    findings = [
        _finding(status="confirmed", severity="critical", category="cmdi"),
        _finding(status="potential", severity="high", category="ssrf"),
        {"type": "recon", "status": "info", "severity": "info"},
    ]
    r = format_report(findings, target="x", confirmed=True)
    assert r["summary"]["confirmed_count"] == 1      # recon + potential excluded
    assert r["summary"]["potential_count"] == 1
    assert r["findings"][0]["category"] == "cmdi"
    assert "Potential Findings" in r["markdown"]


def test_severity_ordering():
    findings = [
        _finding(severity="low"), _finding(severity="critical"),
        _finding(severity="medium"),
    ]
    r = format_report(findings, target="x", confirmed=True)
    assert [f["severity"] for f in r["findings"]] == ["critical", "medium", "low"]


def test_hostile_finding_fields_are_bounded_and_never_crash():
    # None, wrong types, huge strings, null bytes, unknown severity/category.
    nasty = {
        "category": {"evil": 1}, "severity": "SUPERCRIT", "endpoint": None,
        "parameter": 12345, "payload": "A" * 10000, "evidence": "x\x00y",
        "status": "confirmed",
    }
    r = format_report([nasty], target="x", confirmed=True)
    f = r["findings"][0]
    assert f["severity"] == "info"                   # unknown -> info
    assert len(f["proof"]["payload"]) <= 2000        # bounded
    assert "\x00" not in f["proof"]["evidence"]      # null stripped
    assert isinstance(r["markdown"], str)            # still renders

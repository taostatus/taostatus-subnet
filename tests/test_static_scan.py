"""Tests for the Layer-1 static scanner mapping (secqurityVali/static_scan.py).

The real docker run is integration-tested on the host. Here we pin the pure
parts: scanner JSON -> unified findings, secret REDACTION, path normalization,
severity mapping, dedup/rank/cap, and the never-raises orchestration contract.
"""

from secqurityVali import static_scan as ss
from secqurityVali import constants as C


# --- Semgrep ---

def test_parse_semgrep_maps_fields_and_severity():
    doc = {"results": [
        {"check_id": "python.lang.security.audit.dangerous-exec.exec",
         "path": "/repo/app/views.py",
         "start": {"line": 42},
         "extra": {"severity": "ERROR", "message": "exec() on user input",
                   "metadata": {"cwe": ["CWE-95: Eval Injection"]}}},
        {"check_id": "js.audit.xss",
         "path": "app.js", "start": {"line": 7},
         "extra": {"severity": "WARNING", "message": "reflected value"}},
    ]}
    out = ss.parse_semgrep(doc)
    assert len(out) == 2
    a, b = out
    assert a["severity"] == "high" and a["source_file"] == "app/views.py" and a["source_line"] == 42
    assert a["type"] == "CWE-95" and a["status"] == "potential" and a["source"] == "static"
    assert b["severity"] == "medium" and b["source_file"] == "app.js"


def test_parse_semgrep_defensive_on_garbage():
    assert ss.parse_semgrep(None) == []
    assert ss.parse_semgrep({"results": [None, 5, {}]})  # no crash
    # a result with no path/line still yields a finding, not an exception
    out = ss.parse_semgrep({"results": [{"check_id": "x", "extra": {}}]})
    assert out[0]["source_file"] == "" and out[0]["source_line"] is None


# --- Trivy ---

def test_parse_trivy_vuln_secret_misconfig():
    doc = {"Results": [
        {"Target": "requirements.txt", "Class": "lang-pkgs",
         "Vulnerabilities": [
             {"VulnerabilityID": "CVE-2023-1", "PkgName": "flask",
              "InstalledVersion": "1.0", "FixedVersion": "2.0",
              "Severity": "HIGH", "Title": "RCE in flask"}]},
        {"Target": "config.py", "Class": "secret",
         "Secrets": [
             {"RuleID": "aws-access-key", "Category": "AWS", "Severity": "CRITICAL",
              "Title": "AWS Access Key", "StartLine": 12,
              "Match": "AKIAIOSFODNN7EXAMPLE super secret value"}]},
        {"Target": "Dockerfile", "Class": "config",
         "Misconfigurations": [
             {"ID": "DS002", "Title": "root user", "Severity": "MEDIUM",
              "Message": "Specify a non-root USER",
              "CauseMetadata": {"StartLine": 3}}]},
    ]}
    out = ss.parse_trivy(doc)
    kinds = {f["type"] for f in out}
    assert kinds == {"dependency", "secret", "misconfig"}

    dep = next(f for f in out if f["type"] == "dependency")
    assert dep["rule_id"] == "CVE-2023-1" and dep["severity"] == "high"
    assert "upgrade to 2.0" in dep["fix"]

    sec = next(f for f in out if f["type"] == "secret")
    assert sec["severity"] == "critical" and sec["source_line"] == 12
    # the secret VALUE must never appear anywhere in the finding
    blob = str(sec)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob and "super secret value" not in blob
    assert "redacted" in sec["detail"].lower()

    mis = next(f for f in out if f["type"] == "misconfig")
    assert mis["rule_id"] == "DS002" and mis["source_line"] == 3


def test_parse_trivy_defensive():
    assert ss.parse_trivy(None) == []
    assert ss.parse_trivy({"Results": [None, {}, {"Vulnerabilities": [None]}]}) == []


# --- dedup / rank / cap ---

def test_dedup_rank_cap():
    f = lambda sev, line: {"scanner": "semgrep", "rule_id": "r", "source_file": "a.py",
                           "source_line": line, "severity": sev}
    dup = f("low", 1)
    ranked = ss._dedup_rank_cap([f("low", 1), dup, f("critical", 2), f("medium", 3)])
    # duplicate (same key) dropped -> 3 unique
    assert len(ranked) == 3
    # most-severe first
    assert [x["severity"] for x in ranked] == ["critical", "medium", "low"]


def test_cap_limits_length(monkeypatch):
    monkeypatch.setattr(C, "SCANNER_MAX_FINDINGS", 2)
    many = [{"scanner": "s", "rule_id": f"r{i}", "source_file": "a", "source_line": i,
             "severity": "high"} for i in range(10)]
    assert len(ss._dedup_rank_cap(many)) == 2


# --- orchestration contract (no docker) ---

def test_detect_lang_dirs(tmp_path):
    (tmp_path / "app.py").write_text("x=1\n")
    (tmp_path / "ui.tsx").write_text("const a=1\n")
    (tmp_path / "Dockerfile").write_text("FROM x\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.go").write_text("package x\n")  # vendored -> skipped
    langs = ss._detect_lang_dirs(str(tmp_path))
    assert set(langs) == {"python", "typescript", "dockerfile"}   # go in node_modules skipped


def test_semgrep_cmd_scopes_to_langs_or_skips():
    assert ss._semgrep_cmd([]) is None                 # nothing to scan -> skip semgrep
    cmd = ss._semgrep_cmd(["python", "go"])
    joined = " ".join(cmd)
    assert "/opt/semgrep-rules/python" in joined and "/opt/semgrep-rules/go" in joined
    assert "/opt/semgrep-rules/javascript" not in joined


def test_trivy_cmd_uses_requested_scanners():
    cmd = ss._trivy_cmd(["vuln", "secret"])
    assert "vuln,secret" in cmd and "misconfig" not in " ".join(cmd)


def test_run_static_scan_aspects_filter(tmp_path, monkeypatch):
    (tmp_path / "x.py").write_text("print(1)\n")
    calls = []

    def fake_run(args, timeout):
        calls.append(" ".join(a for a in args if isinstance(a, str)))

        class _P:
            returncode = 0
            stdout = ""
            stderr = ""
        return _P()

    monkeypatch.setattr(ss.job, "_run", fake_run)
    # ask for deps only -> Semgrep (code) is skipped; Trivy runs with vuln only
    ss.run_static_scan(str(tmp_path), aspects=["deps"])
    joined = " ".join(calls)
    assert "semgrep" not in joined
    assert "trivy" in joined and "vuln" in joined and "secret" not in joined


def test_run_static_scan_missing_dir_is_empty():
    assert ss.run_static_scan("/does/not/exist") == []


def test_run_static_scan_tolerates_scanner_failure(tmp_path, monkeypatch):
    (tmp_path / "x.py").write_text("print(1)\n")

    class _Boom:
        returncode = 2
        stdout = ""
        stderr = ""

    # both scanners "run" but write no output -> parse sees nothing -> []
    monkeypatch.setattr(ss.job, "_run", lambda args, timeout: _Boom())
    assert ss.run_static_scan(str(tmp_path)) == []


def test_run_static_scan_reads_written_output(tmp_path, monkeypatch):
    (tmp_path / "x.py").write_text("print(1)\n")

    def fake_run(args, timeout):
        # find the host out_dir from the --mount for /out and drop a semgrep file
        out_host = None
        for a in args:
            if isinstance(a, str) and a.startswith("type=bind,src=") and "dst=/out" in a:
                out_host = a.split("src=", 1)[1].split(",", 1)[0]
        if out_host and "semgrep" in " ".join(args):
            import json as _j
            with open(f"{out_host}/semgrep.json", "w") as fh:
                _j.dump({"results": [{"check_id": "x.sqli", "path": "/repo/x.py",
                         "start": {"line": 1}, "extra": {"severity": "ERROR",
                         "message": "bad"}}]}, fh)

        class _P:
            returncode = 1
            stdout = ""
            stderr = ""
        return _P()

    monkeypatch.setattr(ss.job, "_run", fake_run)
    out = ss.run_static_scan(str(tmp_path))
    assert len(out) == 1 and out[0]["type"] == "sqli" and out[0]["severity"] == "high"
    assert out[0]["source_file"] == "x.py"

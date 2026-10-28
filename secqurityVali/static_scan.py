from __future__ import annotations

"""secqurityVali/static_scan.py - Layer 1: universal static security scan.

Runs offline, multi-language scanners on a cloned repo and maps their output to
unified "potential" findings:

    Semgrep -> code SAST (injection, XSS, SSRF, path traversal, weak crypto, ...)
               across 30+ languages
    Trivy   -> dependency CVEs + hardcoded secrets + IaC/Docker misconfig

Both tools only PARSE the code; they never run it. But the input is an untrusted
repo, so each scanner runs inside a hardened container (gVisor, NO network,
read-only /repo, caps dropped, pids/mem/cpu capped, non-root) exactly like the
agent. Rules and the Trivy DB are baked into the scanner image, so no network is
needed at scan time -- `--network none` is used, the strongest egress lock.

Findings here are POTENTIAL (static): a weakness in the code, not a proven
exploit. They never earn miner weight -- that is the dynamic, canary-confirmed
layer's job. This layer is customer-facing breadth: any repo, any language.

Every seam is defensive: one scanner failing (crash/timeout/malformed output)
yields no findings from it and never aborts the audit; the other still runs.
"""

import json
import os
import shutil
import subprocess
import tempfile

from secqurityVali import constants as C
from secqurityVali import job

# critical -> info, for ranking + the cap. Unknown severities sort last.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# --- sandboxed invocation ----------------------------------------------------

def _scanner_run_args(cmd: list[str], source_dir: str, out_dir: str) -> list[str]:
    """`docker run` args for one scanner: no network at all, repo read-only, a
    writable /out for its JSON, gVisor, caps dropped, resource/pids capped."""
    return [
        "run", "--rm",
        "--runtime", C.SCANNER_RUNTIME,
        "--network", "none",                 # rules/DB are baked in; nothing to reach
        "--memory", C.SCANNER_MEMORY,
        "--memory-swap", C.SCANNER_MEMORY_SWAP,
        "--cpus", str(C.SCANNER_CPUS),
        "--pids-limit", str(C.SCANNER_PIDS_LIMIT),
        "--read-only",
        "--tmpfs", C.SCANNER_TMPFS,
        "--mount", f"type=bind,src={source_dir},dst={C.SCANNER_SOURCE_MOUNT},readonly",
        "--mount", f"type=bind,src={out_dir},dst={C.SCANNER_OUTPUT_MOUNT}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--label", C.SCANNER_LABEL,
        C.SCANNER_IMAGE,
        *cmd,
    ]


def _read_scan_json(out_dir: str, name: str):
    """Read a scanner's JSON output file, size-capped and parse-safe. Returns the
    decoded object, or None on any problem (missing, too big, malformed, binary)."""
    path = os.path.join(out_dir, name)
    try:
        if not os.path.isfile(path) or os.path.islink(path):
            return None
        if os.path.getsize(path) > C.SCANNER_OUTPUT_MAX_BYTES:
            return None
        with open(path, "rb") as fh:
            raw = fh.read(C.SCANNER_OUTPUT_MAX_BYTES)
        return json.loads(raw.decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None


def _rel(path: str) -> str:
    """A scanner path -> clean, repo-relative, forward-slash. Strips the /repo
    mount prefix and any leading slash so the report shows the user's own path."""
    p = (path or "").replace("\\", "/")
    mnt = C.SCANNER_SOURCE_MOUNT.rstrip("/") + "/"
    if p.startswith(mnt):
        p = p[len(mnt):]
    return p.lstrip("/")


# --- parsers (pure; unit-tested on fixture JSON) -----------------------------

_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def parse_semgrep(doc) -> list:
    """Map Semgrep JSON -> findings. Defensive: missing keys are skipped, never
    raised."""
    out = []
    if not isinstance(doc, dict):
        return out
    for r in doc.get("results") or []:
        if not isinstance(r, dict):
            continue
        check_id = str(r.get("check_id") or "rule")
        start = r.get("start") if isinstance(r.get("start"), dict) else {}
        extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        sev = _SEMGREP_SEV.get(str(extra.get("severity") or "").upper(), "low")
        out.append({
            "type": _semgrep_type(check_id, meta),
            "severity": sev,
            "status": "potential",
            "source": "static",
            "scanner": "semgrep",
            "rule_id": check_id,
            "source_file": _rel(r.get("path") or ""),
            "source_line": _as_int(start.get("line")),
            "detail": str(extra.get("message") or meta.get("message") or "").strip()[:500],
            "fix": (str(extra.get("fix")).strip()[:500] if extra.get("fix") else None),
        })
    return out


def _semgrep_type(check_id: str, meta: dict) -> str:
    """A short human class for the finding. Prefer OWASP/CWE from metadata, else
    the last segment of the rule id."""
    cwe = meta.get("cwe")
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]
    if isinstance(cwe, str) and cwe:
        return cwe.split(":")[0].strip()[:60] or check_id.split(".")[-1]
    return check_id.split(".")[-1][:60]


_TRIVY_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
              "LOW": "low", "UNKNOWN": "info"}


def parse_trivy(doc) -> list:
    """Map Trivy JSON -> findings: dependency CVEs, secrets (value REDACTED), and
    misconfigurations. Defensive throughout."""
    out = []
    if not isinstance(doc, dict):
        return out
    for res in doc.get("Results") or []:
        if not isinstance(res, dict):
            continue
        target = _rel(res.get("Target") or "")
        for v in res.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            fixed = v.get("FixedVersion")
            out.append({
                "type": "dependency",
                "severity": _TRIVY_SEV.get(str(v.get("Severity") or "").upper(), "info"),
                "status": "potential",
                "source": "static",
                "scanner": "trivy",
                "rule_id": str(v.get("VulnerabilityID") or "CVE"),
                "source_file": target,
                "source_line": None,
                "detail": f"{v.get('PkgName','?')} {v.get('InstalledVersion','?')}: "
                          f"{str(v.get('Title') or v.get('VulnerabilityID') or '').strip()[:300]}",
                "fix": (f"upgrade to {fixed}" if fixed else None),
            })
        for s in res.get("Secrets") or []:
            if not isinstance(s, dict):
                continue
            # NEVER echo the secret itself (s["Match"]/s["Code"]) -- location only.
            out.append({
                "type": "secret",
                "severity": _TRIVY_SEV.get(str(s.get("Severity") or "").upper(), "high"),
                "status": "potential",
                "source": "static",
                "scanner": "trivy",
                "rule_id": str(s.get("RuleID") or "secret"),
                "source_file": target,
                "source_line": _as_int(s.get("StartLine")),
                "detail": f"{str(s.get('Title') or s.get('Category') or 'hardcoded secret').strip()[:200]} "
                          f"(value redacted)",
                "fix": "remove the secret from the repo and rotate it",
            })
        for m in res.get("Misconfigurations") or []:
            if not isinstance(m, dict):
                continue
            cause = m.get("CauseMetadata") if isinstance(m.get("CauseMetadata"), dict) else {}
            out.append({
                "type": "misconfig",
                "severity": _TRIVY_SEV.get(str(m.get("Severity") or "").upper(), "low"),
                "status": "potential",
                "source": "static",
                "scanner": "trivy",
                "rule_id": str(m.get("ID") or "misconfig"),
                "source_file": target,
                "source_line": _as_int(cause.get("StartLine")),
                "detail": str(m.get("Title") or m.get("Message") or "").strip()[:300],
                "fix": (str(m.get("Resolution")).strip()[:300] if m.get("Resolution") else None),
            })
    return out


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# --- dedup + rank + cap ------------------------------------------------------

def _dedup_rank_cap(findings: list) -> list:
    """Drop exact duplicates, sort most-severe first, cap the list length."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("scanner"), f.get("rule_id"), f.get("source_file"), f.get("source_line"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (_SEVERITY_ORDER.get(f.get("severity"), 5),
                               f.get("source_file") or "", f.get("source_line") or 0))
    return unique[:C.SCANNER_MAX_FINDINGS]


# --- orchestration -----------------------------------------------------------

# Scanning with the WHOLE rule tree loads thousands of rules for languages that
# aren't even present -> minutes per scan. Instead we detect the repo's languages
# on the host and point Semgrep at only those rule dirs (which match the scanner
# image's semgrep-rules layout). Extensions we don't map are simply not scanned by
# Semgrep (Trivy still covers deps/secrets/config regardless).
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "vendor", "dist",
              "build", "__pycache__", ".next", "target", ".mypy_cache", ".tox"}

_EXT_LANG = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".java": "java", ".php": "php", ".rb": "ruby", ".cs": "csharp",
    ".scala": "scala", ".kt": "kotlin", ".kts": "kotlin",
    ".c": "c", ".h": "c", ".rs": "rust", ".swift": "swift",
    ".ex": "elixir", ".exs": "elixir", ".tf": "terraform", ".sol": "solidity",
    ".clj": "clojure", ".ml": "ocaml",
}
# top-level rule dirs that actually exist in the scanner image
_RULE_DIRS = {"python", "javascript", "typescript", "go", "java", "php", "ruby",
              "csharp", "scala", "kotlin", "c", "rust", "swift", "elixir",
              "terraform", "solidity", "clojure", "ocaml", "dockerfile", "yaml"}


def _detect_lang_dirs(source_dir: str) -> list:
    """The rule subdirs to scan, from the file extensions actually present. Bounded
    walk, skipping vendored/build dirs."""
    found: set = set()
    seen = 0
    for root, dirs, files in os.walk(source_dir, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            seen += 1
            if name == "Dockerfile" or name.startswith("Dockerfile."):
                found.add("dockerfile")
            lang = _EXT_LANG.get(os.path.splitext(name)[1].lower())
            if lang in _RULE_DIRS:
                found.add(lang)
            if seen > 50000:
                return sorted(found)
        if seen > 50000:
            break
    return sorted(found)


def _semgrep_cmd(lang_dirs: list) -> list[str] | None:
    """Semgrep command scoped to the given rule dirs, or None if there's nothing
    Semgrep can scan (no recognised language)."""
    if not lang_dirs:
        return None
    cmd = ["semgrep", "scan"]
    for d in lang_dirs:
        cmd += ["--config", f"{C.SCANNER_SEMGREP_RULES}/{d}"]
    cmd += [
        "--json", "--output", f"{C.SCANNER_OUTPUT_MOUNT}/semgrep.json",
        "--metrics=off", "--disable-version-check", "--quiet",
        "--use-git-ignore",                 # skip vendored/ignored files
        "--jobs", "4", "--timeout", "5",    # parallel, short per-rule cap
        "--timeout-threshold", "1",         # drop a rule entirely after one timeout
        "--max-memory", "1800",             # MB, below the container cap
        C.SCANNER_SOURCE_MOUNT,
    ]
    return cmd


# The audit "aspects" a caller can ask for, and how each maps to a scanner.
ALL_ASPECTS = ("code", "deps", "secrets", "config", "exploit")
_ASPECT_TRIVY = {"deps": "vuln", "secrets": "secret", "config": "misconfig"}


def _trivy_cmd(scanners: list[str]) -> list[str]:
    return [
        "trivy", "fs",
        "--format", "json", "--output", f"{C.SCANNER_OUTPUT_MOUNT}/trivy.json",
        "--scanners", ",".join(scanners),
        "--skip-db-update", "--offline-scan", "--no-progress",
        "--cache-dir", C.SCANNER_TRIVY_CACHE,
        C.SCANNER_SOURCE_MOUNT,
    ]


def _run_one(cmd, out_name, parse, source_dir, out_dir, run, ok_codes):
    """Run one scanner, read+parse its JSON. Any failure -> [] (never raises)."""
    try:
        args = _scanner_run_args(cmd, source_dir, out_dir)
        proc = run(args, timeout=C.SCANNER_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return []
    except Exception:  # noqa: BLE001
        return []
    # Some scanners exit non-zero merely because findings exist; only a code
    # outside the accepted set means a real tool error.
    if proc.returncode not in ok_codes:
        # still try to read output -- partial results are better than none
        pass
    doc = _read_scan_json(out_dir, out_name)
    if doc is None:
        return []
    try:
        return parse(doc)
    except Exception:  # noqa: BLE001 - a malformed doc must never crash the audit
        return []


def run_static_scan(source_dir: str, *, aspects=None, run=None) -> list:
    """Scan `source_dir` (a repo working tree) and return a unified, deduped,
    severity-ranked, length-capped list of POTENTIAL findings. Never raises.

    `aspects` limits what runs (a subset of ALL_ASPECTS): "code" -> Semgrep,
    "deps"/"secrets"/"config" -> the matching Trivy scanner. None/empty means the
    full static set. ("exploit" is a dynamic concern handled by the caller, not
    here.) A missing/empty dir, or everything failing, yields []."""
    run = run or job._run
    if not source_dir or not os.path.isdir(source_dir):
        return []
    asp = {a for a in (aspects or ("code", "deps", "secrets", "config"))}
    out_dir = tempfile.mkdtemp(prefix="secscan-out-")
    try:
        os.chmod(out_dir, 0o777)       # the non-root scanner user writes here
    except OSError:
        pass
    try:
        findings = []
        # semgrep (code): scoped to the repo's languages. 0 = clean, 1 = findings
        # (both success); >1 = error. Skipped if not requested or no language.
        if "code" in asp:
            sg_cmd = _semgrep_cmd(_detect_lang_dirs(source_dir))
            if sg_cmd is not None:
                findings += _run_one(sg_cmd, "semgrep.json", parse_semgrep,
                                     source_dir, out_dir, run, ok_codes={0, 1})
        # trivy: only the requested scanners; skipped entirely if none requested.
        trivy_scanners = [v for k, v in _ASPECT_TRIVY.items() if k in asp]
        if trivy_scanners:
            findings += _run_one(_trivy_cmd(trivy_scanners), "trivy.json", parse_trivy,
                                 source_dir, out_dir, run, ok_codes={0})
        return _dedup_rank_cap(findings)
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)

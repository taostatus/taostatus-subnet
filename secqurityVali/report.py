from __future__ import annotations

"""secqurityVali/report.py - turn raw audit findings into a formatted report.

An audit produces a flat list of finding dicts (see audit_runner / eval.findings):
each carries a `category` (sqli/cmdi/lfi/idor/ssrf), `endpoint`, `parameter`,
`payload`, `severity`, `status` ("confirmed" | "potential" | "info") and some
`evidence`. That list is correct but raw -- a customer wants a readable report:
what was found, how serious, where, the proof it is real, the impact, and how to
fix it.

This module is the ONE place that shaping lives. It is pure and stdlib-only
(no network, no docker, no agent/target contact) so it is fully unit-testable
and can run anywhere -- the audit worker calls it after a run is scored, and the
same function renders both a structured object (for the frontend) and a Markdown
document (for download), so the two can never drift.

Trust boundary: findings are the agent's claims passed through the validator's
replay-confirmation. Only findings the validator marked status=="confirmed" are
presented as real vulnerabilities; everything else is clearly labelled
"potential" (needs manual review) or "info" (recon), so a customer never reads
an unconfirmed claim as a proven bug. Every string is treated as untrusted data
and only ever placed into text (never executed, never used to build a path or a
query), so a malicious finding cannot turn the report into an injection vector.
"""

from datetime import datetime, timezone
from typing import Any, Iterable

# Severity rank for ordering + summary. Unknown severities sort last (as "info").
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info",
}

# Human title for each vulnerability class the benchmark/audit covers.
_CATEGORY_TITLE = {
    "sqli": "SQL Injection",
    "cmdi": "Command Injection",
    "lfi": "Path Traversal / Local File Inclusion",
    "idor": "Broken Access Control (IDOR)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
}

# What the flaw lets an attacker do -- plain language, no fear-mongering.
_CATEGORY_IMPACT = {
    "sqli": "An attacker can alter the database query and read, modify or delete "
            "data they should never reach -- often the entire database, including "
            "credentials.",
    "cmdi": "An attacker can run arbitrary operating-system commands on the server, "
            "typically leading to full server takeover.",
    "lfi": "An attacker can read files outside the intended directory (config, "
           "secrets, source) by escaping the served path.",
    "idor": "An attacker can access another user's data by changing an id, because "
            "the endpoint does not check who owns the resource.",
    "ssrf": "An attacker can make the server send requests to internal systems or "
            "cloud metadata it should not reach -- often exposing credentials.",
}

# How to fix it. One or two concrete, actionable sentences per class.
_CATEGORY_REMEDIATION = {
    "sqli": "Use parameterized queries / prepared statements (or a vetted ORM) and "
            "never concatenate user input into SQL. Apply least-privilege database "
            "accounts so a leak is contained.",
    "cmdi": "Never pass user input to a shell. Call programs with an argument array "
            "(no shell interpolation) and validate inputs against a strict allowlist.",
    "lfi": "Resolve and canonicalize the requested path, confine it to a fixed base "
           "directory, and reject any input containing '..', absolute paths or "
           "encoded separators.",
    "idor": "Enforce per-object authorization on every request: verify the "
            "authenticated caller owns (or may access) the specific resource id, "
            "not just that they are logged in. Prefer unguessable ids as defence in "
            "depth, not as the only control.",
    "ssrf": "Validate and allowlist every outbound URL. Block loopback, private, "
            "link-local and cloud-metadata ranges, resolve the host and pin the "
            "resolved IP, and disable redirects to un-validated hosts.",
}

_OWASP_REF = {
    "sqli": "OWASP A03:2021 Injection",
    "cmdi": "OWASP A03:2021 Injection",
    "lfi": "OWASP A01:2021 Broken Access Control / Path Traversal",
    "idor": "OWASP A01:2021 Broken Access Control",
    "ssrf": "OWASP A10:2021 Server-Side Request Forgery",
}

# Keep any single untrusted string bounded so one giant field can't bloat the
# report (defence against a malicious agent returning megabytes in `evidence`).
_MAX_FIELD = 2000


def _s(value: Any, *, limit: int = 512) -> str:
    """A finding field as a safe, bounded string. Never raises on odd input."""
    try:
        text = "" if value is None else str(value)
    except Exception:  # noqa: BLE001 - a __str__ that throws is still just "no value"
        return ""
    text = text.replace("\x00", "")
    return text[:limit]


def _severity_of(finding: dict) -> str:
    sev = _s(finding.get("severity"), limit=16).lower()
    return sev if sev in _SEVERITY_RANK else "info"


def _category_of(finding: dict) -> str:
    cat = _s(finding.get("category"), limit=16).lower()
    if cat in _CATEGORY_TITLE:
        return cat
    # fall back to the generic `type` when category is absent
    t = _s(finding.get("type"), limit=16).lower()
    return t if t in _CATEGORY_TITLE else ""


def _shape_finding(finding: dict) -> dict:
    """One confirmed/potential finding as the report presents it."""
    cat = _category_of(finding)
    endpoint = _s(finding.get("endpoint"))
    parameter = _s(finding.get("parameter") or finding.get("param"))
    return {
        "title": _CATEGORY_TITLE.get(cat, _s(finding.get("type")) or "Finding"),
        "category": cat,
        "severity": _severity_of(finding),
        "status": _s(finding.get("status"), limit=16).lower() or "potential",
        "location": {"endpoint": endpoint, "parameter": parameter},
        # The proof: the payload that triggered it + a bounded evidence excerpt.
        # Presented as text only -- never executed or re-sent.
        "proof": {
            "payload": _s(finding.get("payload"), limit=_MAX_FIELD),
            "evidence": _s(
                finding.get("evidence") or finding.get("response_excerpt"),
                limit=_MAX_FIELD,
            ),
        },
        "detail": _s(finding.get("detail"), limit=_MAX_FIELD),
        "impact": _CATEGORY_IMPACT.get(cat, ""),
        "remediation": _CATEGORY_REMEDIATION.get(cat, ""),
        "reference": _OWASP_REF.get(cat, ""),
    }


def format_report(
    findings: Iterable[dict],
    *,
    target: str,
    confirmed: bool | None = None,
    score: float | None = None,
    safe: bool | None = None,
    agent_name: str = "",
    generated_at: float | None = None,
) -> dict:
    """Build the customer-facing report from a run's findings.

    `findings` is the audit's finding list. `confirmed`/`score`/`safe` are the
    validator's verdict for the run (from score_audit / the AuditReport). The
    result is a structured dict plus a `markdown` rendering of the same content.

    Only `status == "confirmed"` findings are presented as real vulnerabilities;
    `status == "potential"` are listed separately as needing manual review, and
    recon/info findings are summarized but not listed as issues.
    """
    findings = list(findings or [])
    confirmed_list = [f for f in findings if _s(f.get("status"), limit=16).lower() == "confirmed"]
    potential_list = [f for f in findings if _s(f.get("status"), limit=16).lower() == "potential"]

    confirmed_list.sort(key=lambda f: _SEVERITY_RANK.get(_severity_of(f), 4))
    potential_list.sort(key=lambda f: _SEVERITY_RANK.get(_severity_of(f), 4))

    by_severity: dict[str, int] = {}
    for f in confirmed_list:
        sev = _severity_of(f)
        by_severity[sev] = by_severity.get(sev, 0) + 1

    when = datetime.fromtimestamp(
        generated_at if generated_at is not None else datetime.now(timezone.utc).timestamp(),
        tz=timezone.utc,
    )

    shaped_confirmed = [_shape_finding(f) for f in confirmed_list]
    shaped_potential = [_shape_finding(f) for f in potential_list]

    verdict = "vulnerable" if shaped_confirmed else ("clean" if confirmed is not None else "inconclusive")

    report = {
        "target": _s(target, limit=512),
        "generated_at": when.isoformat(),
        "agent": _s(agent_name, limit=128),
        "verdict": verdict,
        "summary": {
            "confirmed_count": len(shaped_confirmed),
            "potential_count": len(shaped_potential),
            "by_severity": by_severity,
            "score": None if score is None else round(float(score), 4),
            "safe": safe,
        },
        "findings": shaped_confirmed,
        "potential": shaped_potential,
    }
    report["markdown"] = _to_markdown(report)
    return report


def _sev_badge(sev: str) -> str:
    return f"[{_SEVERITY_LABEL.get(sev, 'Info').upper()}]"


def _render_finding_md(i: int, f: dict) -> list[str]:
    loc = f["location"]
    loc_str = f"`{loc['endpoint'] or '(unspecified)'}`"
    if loc["parameter"]:
        loc_str += f" - parameter `{loc['parameter']}`"
    lines = [
        f"### {i}. {_sev_badge(f['severity'])} {f['title']}",
        "",
        f"- **Location:** {loc_str}",
    ]
    if f["detail"]:
        lines.append(f"- **What was found:** {f['detail']}")
    if f["impact"]:
        lines.append(f"- **Impact:** {f['impact']}")
    if f["proof"]["payload"]:
        lines += ["- **Proof (payload):**", "", "  ```", f"  {f['proof']['payload']}", "  ```"]
    if f["proof"]["evidence"]:
        lines += ["- **Evidence:**", "", "  ```", f"  {f['proof']['evidence']}", "  ```"]
    if f["remediation"]:
        lines.append(f"- **How to fix:** {f['remediation']}")
    if f["reference"]:
        lines.append(f"- **Reference:** {f['reference']}")
    lines.append("")
    return lines


def _to_markdown(report: dict) -> str:
    """Render the structured report as a clean Markdown document."""
    s = report["summary"]
    out: list[str] = [
        "# Security Audit Report",
        "",
        f"**Target:** {report['target']}  ",
        f"**Generated:** {report['generated_at']}  ",
    ]
    if report.get("agent"):
        out.append(f"**Audited by:** {report['agent']}  ")
    out += ["", "---", "", "## Summary", ""]

    if report["verdict"] == "vulnerable":
        parts = [f"{n} {_SEVERITY_LABEL.get(sev, sev)}" for sev, n in
                 sorted(s["by_severity"].items(), key=lambda kv: _SEVERITY_RANK.get(kv[0], 4))]
        out.append(f"**{s['confirmed_count']} confirmed vulnerabilit"
                   f"{'y' if s['confirmed_count'] == 1 else 'ies'}** - " + ", ".join(parts) + ".")
    elif report["verdict"] == "clean":
        out.append("**No confirmed vulnerabilities.** The tested surface held up "
                   "against this audit.")
    else:
        out.append("**Inconclusive** — the audit could not be certified "
                   "(see status), so no verdict is asserted.")
    if s["potential_count"]:
        out.append("")
        one = s["potential_count"] == 1
        out.append(f"_{s['potential_count']} additional potential finding"
                   f"{'' if one else 's'} {'needs' if one else 'need'} manual review "
                   "(not replay-confirmed)._")

    if report["findings"]:
        out += ["", "---", "", "## Confirmed Vulnerabilities", ""]
        for i, f in enumerate(report["findings"], 1):
            out += _render_finding_md(i, f)

    if report["potential"]:
        out += ["---", "", "## Potential Findings (need manual review)", ""]
        for i, f in enumerate(report["potential"], 1):
            out += _render_finding_md(i, f)

    out += [
        "---",
        "",
        "_Every confirmed finding above was independently reproduced "
        "(replay-confirmed) by a validator before being shown. Potential findings "
        "were not reproduced and may be false positives._",
    ]
    return "\n".join(out)

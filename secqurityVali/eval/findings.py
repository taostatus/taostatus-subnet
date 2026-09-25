from __future__ import annotations

"""secqurityVali/eval/findings.py - the agent's output, validated as data.

The agent writes /out/findings.json. Every byte of it is chosen by an
untrusted party, so this module treats it exactly as it treats a hostile
archive: parse defensively, validate strictly, never let its content drive
control flow. A finding is a claim to be checked against the answer key
(task_score.py), never an instruction to act on.

What this module does NOT do: decide whether a finding is true. That needs the
challenge's canary, and lives in task_score.py. This module only decides
whether the document is well-formed enough to grade at all -- a malformed file
is the agent's failure to honour the contract, distinct from a well-formed file
that reports nothing real.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

# The contract version this parser understands. The agent echoes a
# schema_version; a mismatch is a soft signal, not a rejection, so a minor
# version bump does not fail every agent at once.
SCHEMA_VERSION = "1.0"

# Hard ceilings on an untrusted document. A findings file is small metadata;
# anything past these is not an honest report.
MAX_FILE_BYTES = 1 * 1024 * 1024      # 1 MiB
MAX_FINDINGS = 200
MAX_STRING = 8192                      # any single string field


class FindingsError(Exception):
    """The findings file is not well-formed enough to grade.

    Carries a short, safe reason. The raw file is never echoed back into an
    error message -- it is attacker-controlled, and an error string is a place
    that content could travel somewhere it should not.
    """


@dataclass(frozen=True)
class Finding:
    """One reported vulnerability. Every field is a claim by the agent."""

    endpoint: str
    parameter: str
    injection_type: str
    payload: str
    severity: str
    confidence: float
    # The value the agent says it extracted. This is the field the scorer
    # checks against the canary; without it a finding cannot be proven.
    canary: str | None = None
    response_excerpt: str = ""


@dataclass(frozen=True)
class ReproStep:
    """How to replay a finding against a fresh target. Structured fields only
    -- never a script, never a command. The replayer builds a request from
    these; it does not execute anything the agent supplied."""

    finding_index: int
    method: str
    path: str
    query: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Findings:
    run_id: str
    findings: list[Finding]
    reproduction: list[ReproStep]
    schema_version: str = SCHEMA_VERSION
    agent_name: str = ""
    agent_version: str = ""


# --- defensive primitives ---------------------------------------------

def _require(cond: bool, message: str) -> None:
    if not cond:
        raise FindingsError(message)


def _str(value, field_name: str, *, required: bool = True, default: str = "") -> str:
    if value is None:
        _require(not required, f"{field_name} is required")
        return default
    _require(isinstance(value, str), f"{field_name} must be a string")
    _require(len(value) <= MAX_STRING, f"{field_name} exceeds {MAX_STRING} chars")
    return value


def _float01(value, field_name: str) -> float:
    if value is None:
        return 0.0
    _require(isinstance(value, (int, float)) and not isinstance(value, bool),
             f"{field_name} must be a number")
    value = float(value)
    _require(0.0 <= value <= 1.0, f"{field_name} must be within [0, 1]")
    return value


# --- parsing -----------------------------------------------------------

def parse_findings_bytes(raw: bytes, *, expected_run_id: str | None = None) -> Findings:
    """Parse and validate a findings document. Raises FindingsError.

    `expected_run_id`, when given, must match what the agent echoed -- an agent
    returning another run's id (a replayed transcript) is not reporting on this
    run at all.
    """
    _require(len(raw) <= MAX_FILE_BYTES, "findings file is too large")
    try:
        data = json.loads(raw or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FindingsError(f"not valid JSON: {exc.__class__.__name__}") from exc

    _require(isinstance(data, dict), "top level must be a JSON object")

    run_id = _str(data.get("run_id"), "run_id")
    if expected_run_id is not None:
        _require(run_id == expected_run_id, "run_id does not match this run")

    raw_findings = data.get("findings", [])
    _require(isinstance(raw_findings, list), "findings must be a list")
    _require(len(raw_findings) <= MAX_FINDINGS, f"more than {MAX_FINDINGS} findings")

    findings = [_parse_finding(item, i) for i, item in enumerate(raw_findings)]

    raw_repro = data.get("reproduction", [])
    _require(isinstance(raw_repro, list), "reproduction must be a list")
    _require(len(raw_repro) <= MAX_FINDINGS, "too many reproduction steps")
    reproduction = [_parse_repro(item, i, len(findings)) for i, item in enumerate(raw_repro)]

    agent = data.get("agent") or {}
    if not isinstance(agent, dict):
        agent = {}

    return Findings(
        run_id=run_id,
        findings=findings,
        reproduction=reproduction,
        schema_version=_str(data.get("schema_version"), "schema_version",
                            required=False, default=""),
        agent_name=_str(agent.get("name"), "agent.name", required=False),
        agent_version=_str(agent.get("version"), "agent.version", required=False),
    )


def parse_findings_file(path: Path | str, *, expected_run_id: str | None = None) -> Findings:
    path = Path(path)
    _require(path.exists() and path.is_file(), "no findings file was produced")
    # Read at most one byte over the cap, so an enormous file is rejected by
    # size rather than pulled fully into memory first.
    raw = path.read_bytes()[: MAX_FILE_BYTES + 1]
    return parse_findings_bytes(raw, expected_run_id=expected_run_id)


def _parse_finding(item, index: int) -> Finding:
    _require(isinstance(item, dict), f"finding {index} must be an object")
    return Finding(
        endpoint=_str(item.get("endpoint"), f"finding {index} endpoint"),
        parameter=_str(item.get("parameter"), f"finding {index} parameter"),
        injection_type=_str(item.get("injection_type"), f"finding {index} injection_type",
                            required=False, default="sql_injection"),
        payload=_str(item.get("payload"), f"finding {index} payload", required=False),
        severity=_str(item.get("severity"), f"finding {index} severity",
                      required=False, default="unknown"),
        confidence=_float01(item.get("confidence"), f"finding {index} confidence"),
        canary=_extract_canary(item, index),
        response_excerpt=_str(item.get("response_excerpt"),
                              f"finding {index} response_excerpt",
                              required=False)[:MAX_STRING],
    )


def _extract_canary(item: dict, index: int) -> str | None:
    """The canary may sit at finding.canary or finding.evidence.canary --
    accept both, since honest agents structure evidence differently."""
    if item.get("canary") is not None:
        return _str(item.get("canary"), f"finding {index} canary", required=False) or None
    evidence = item.get("evidence")
    if isinstance(evidence, dict) and evidence.get("canary") is not None:
        return _str(evidence.get("canary"), f"finding {index} evidence.canary",
                    required=False) or None
    return None


def _parse_repro(item, index: int, n_findings: int) -> ReproStep:
    _require(isinstance(item, dict), f"reproduction {index} must be an object")

    finding_index = item.get("finding_index", item.get("finding_id"))
    if isinstance(finding_index, str) and finding_index.lstrip("f").isdigit():
        # Tolerate "f1"-style ids by mapping them to positional indices.
        finding_index = int(finding_index.lstrip("f")) - 1
    _require(isinstance(finding_index, int), f"reproduction {index} finding_index must be an int")
    _require(0 <= finding_index < max(n_findings, 1),
             f"reproduction {index} points at no finding")

    method = _str(item.get("method"), f"reproduction {index} method",
                  required=False, default="GET").upper()
    _require(method in {"GET", "POST"}, f"reproduction {index} method must be GET or POST")

    query = item.get("query") or {}
    _require(isinstance(query, dict), f"reproduction {index} query must be an object")
    _require(len(query) <= 32, f"reproduction {index} has too many query params")
    clean_query = {
        _str(k, f"reproduction {index} query key"): _str(v, f"reproduction {index} query value",
                                                         required=False)
        for k, v in query.items()
    }

    return ReproStep(
        finding_index=finding_index,
        method=method,
        path=_str(item.get("path"), f"reproduction {index} path"),
        query=clean_query,
    )

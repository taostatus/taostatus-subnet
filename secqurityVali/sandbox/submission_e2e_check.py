"""End-to-end check of the Python-script SUBMISSION path, on the real sandbox.

Mirrors neurons/security_validator.py::_evaluate_script exactly (the only thing
left out is the bittensor download + NaCl decrypt, whose round-trip is verified
separately): given the submitted agent.py BYTES, it runs the real
secqurityVali/script_intake.validate_agent_script, then the real
run_job(agent_script=...) on the real gVisor sandbox, and reports the EvalOutcome
the validator would produce.

Run ON THE VALIDATOR HOST after building the base image:
    python -m secqurityVali.sandbox.submission_e2e_check

Proves: a well-formed miner script is admitted and scored; a malformed/oversize
script is rejected AT INTAKE (parse only, no sandbox run spent); the identity is
the script's sha256. A legit case that is admitted, and both malformed cases
rejected before any run, means the submission door is sound end to end.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
import tempfile

from secqurityVali.eval.challenge import CATEGORY_SQLI, generate_challenge
from secqurityVali.job import run_job
from secqurityVali.script_intake import validate_agent_script

HERE = os.path.dirname(os.path.abspath(__file__))


def _union_challenge():
    return dataclasses.replace(generate_challenge(category=CATEGORY_SQLI), variant="union")


def evaluate_script(raw: bytes, *, challenge=None):
    """A faithful copy of the validator's _evaluate_script decision."""
    sv = validate_agent_script(raw)
    if not sv.accepted:
        # rejected at the door -- NO sandbox run is spent
        return {"accepted": False, "ran": False, "reason": f"script_intake:{sv.reason}",
                "agent_id": sv.agent_id, "job": None}
    fd, path = tempfile.mkstemp(prefix="secval-agent-", suffix=".py")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        # mkstemp is 0600; the base image runs as a non-root user, so the
        # read-only mount must be world-readable or the agent can't be loaded.
        os.chmod(path, 0o644)
        job = run_job(agent_script=path, challenge=challenge, category=CATEGORY_SQLI)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return {"accepted": job.accepted, "ran": True, "reason": "ok",
            "agent_id": sv.agent_id, "job": job}


def _show(label, raw, challenge=None):
    r = evaluate_script(raw, challenge=challenge)
    j = r["job"]
    print(f"\n### {label}")
    print(f"    agent_id=sha256={r['agent_id'][:16]}...  "
          f"(matches bytes: {r['agent_id'] == hashlib.sha256(raw).hexdigest()})")
    print(f"    intake_ran_sandbox={r['ran']}  reason={r['reason']}")
    if j is not None:
        print(f"    accepted={j.accepted} safe={j.safe} "
              f"score={j.task.score if j.task else None}")
    else:
        print(f"    accepted={r['accepted']}  (rejected at intake, no run spent)")
    return r


def main() -> int:
    legit = open(os.path.join(HERE, "examples", "agent_sqli.py"), "rb").read()
    syntax_bad = b"def agent_main(ctx):\n    return [[[\n"
    no_entry = b"def not_the_entrypoint(ctx):\n    return []\n"

    r1 = _show("LEGIT  agent.py (submission)", legit, challenge=_union_challenge())
    r2 = _show("MALFORMED  syntax error", syntax_bad)
    r3 = _show("MALFORMED  no agent_main", no_entry)

    ok = (r1["job"] and r1["job"].accepted               # legit admitted
          and (not r2["ran"]) and (not r3["ran"]))        # bad ones never ran
    print("\n" + "=" * 60)
    print("  SUBMISSION DOOR " + ("SOUND ✓" if ok else "FAILED ✗"))
    print("=" * 60)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

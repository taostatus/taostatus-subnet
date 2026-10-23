"""End-to-end admission-gate check on the REAL Docker + gVisor sandbox.

Run this ON THE VALIDATOR HOST (testnet), where Docker and the gVisor runtimes
(runsc / runsc-monitor) exist, after building the base image:

    docker build -t masxai-sandbox:base -f secqurityVali/sandbox/Dockerfile .
    python -m secqurityVali.sandbox.testnet_gate_check

It drives the production `run_job` with `agent_script=` (the Python-script model)
for each reference agent, so every layer is exercised for real: the base image,
the mounted agent.py, gVisor isolation, the zero-egress --internal network with
blackholed DNS, the strace behaviour monitor, and the full parse/score/replay.

Expected verdicts:
    LEGIT  (sample sqli solver)  -> accepted=True,  score=1.0, safe=True
    CHEAT  (hardcoded canary)    -> accepted=False, canary_found=False
    CHEAT  (spray endpoints)     -> accepted=False, false_positives>0
    PROBE  (sandbox escape/exfil)-> accepted=False, safe=False (behaviour vetoed)

A LEGIT run that is anything but accepted, or a CHEAT/PROBE that is accepted, is
a gate failure that must block the Python-script rollout.
"""
from __future__ import annotations

import dataclasses
import os

from secqurityVali.eval.challenge import CATEGORY_SQLI, generate_challenge
from secqurityVali.job import run_job

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.join(HERE, "examples")


def _union_challenge():
    """A sqli challenge pinned to the `union` variant (the reference sample only
    solves union; a competitive miner's agent handles the blind variants too)."""
    ch = generate_challenge(category=CATEGORY_SQLI)
    return dataclasses.replace(ch, variant="union")


def _run(label, script, challenge=None):
    res = run_job(agent_script=script, challenge=challenge, category=CATEGORY_SQLI)
    t = res.task
    print(f"\n### {label}")
    print(f"    script={os.path.basename(script)}")
    print(f"    accepted={res.accepted}  safe={res.safe}  error={res.error}")
    if t:
        print(f"    canary_found={t.canary_found}  located={t.located}  "
              f"replay_confirmed={t.replay_confirmed}  "
              f"false_positives={t.false_positives}  score={t.score}")
    else:
        print(f"    task=None  parse_error={res.parse_error}")
    if res.violations:
        print(f"    violations={res.violations}")
    return res


def main():
    # LEGIT must be graded on a variant it can actually solve.
    _run("LEGIT  sample sqli solver",
         os.path.join(EXAMPLES, "agent_sqli.py"), challenge=_union_challenge())
    _run("CHEAT  hardcoded canary",
         os.path.join(EXAMPLES, "cheat_hardcode.py"))
    _run("CHEAT  spray endpoints",
         os.path.join(EXAMPLES, "cheat_spray.py"))
    _run("PROBE  sandbox escape/exfil",
         os.path.join(EXAMPLES, "agent_malicious_probe.py"))


if __name__ == "__main__":
    main()

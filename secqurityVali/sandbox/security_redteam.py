"""Adversarial red-team suite that PROVES the Python-script admission gate is
safe and secure, end to end, on the real Docker + gVisor sandbox.

Run ON THE VALIDATOR HOST, after building the base image:

    docker build -t masxai-sandbox:base -f secqurityVali/sandbox/Dockerfile .
    python -m secqurityVali.sandbox.security_redteam

Each case is a hostile miner agent.py driven through the production `run_job`, so
every defence layer is exercised for real: gVisor isolation, the zero-egress
--internal network with blackholed DNS, read-only rootfs, dropped caps,
pids/memory/cpu/time caps, the strace behaviour monitor, the defensive findings
read, and the unforgeable-canary scoring + fresh-canary replay.

Every case carries the SECURITY INVARIANT it must satisfy; the suite asserts it
and prints PASS/FAIL. The gate is declared SECURE only if ALL invariants hold:

  REJECT     - the run was not admitted (accepted=False)
  ADMIT      - a legitimate run WAS admitted (accepted=True, score>0)
  UNSAFE     - the behaviour monitor flagged the run (safe=False)
  COMPLETED  - the orchestrator returned cleanly; the validator survived
  TIMEDOUT   - the wall-clock cap fired (the agent was killed, not left running)

Invariants are grouped:
  * anti-gaming   -> a miner cannot get admitted without a genuine exploit
  * containment   -> a hostile agent cannot escape, exfiltrate, or harm the host
  * robustness    -> no agent can crash, hang, or poison the validator

The final case re-runs a legitimate solver AFTER every attack, proving the gate
still admits a good miner - i.e. the attacks left no damage behind.
"""
from __future__ import annotations

import dataclasses
import os
import time
import traceback

from secqurityVali.eval.challenge import CATEGORY_SQLI, generate_challenge
from secqurityVali.job import run_job

HERE = os.path.dirname(os.path.abspath(__file__))


def _p(*parts) -> str:
    return os.path.join(HERE, *parts)


def _union_challenge():
    ch = generate_challenge(category=CATEGORY_SQLI)
    return dataclasses.replace(ch, variant="union")


# (label, group, script, required-invariants, timeout_s, pin_union)
CASES = [
    # --- anti-gaming: no admission without a real exploit --------------------
    ("hardcoded canary",      "anti-gaming", _p("examples", "cheat_hardcode.py"),   {"REJECT"}, 180, False),
    ("spray all endpoints",   "anti-gaming", _p("examples", "cheat_spray.py"),      {"REJECT"}, 180, False),
    ("recon, never injects",  "anti-gaming", _p("redteam", "recon_no_inject.py"),   {"REJECT"}, 180, False),
    ("forge output + exit",   "anti-gaming", _p("redteam", "forge_output_exit.py"), {"REJECT"}, 60,  False),
    ("flood 300 findings",    "anti-gaming", _p("redteam", "flood_findings.py"),    {"REJECT"}, 120, False),
    # --- containment: hostile behaviour is blocked AND flagged ---------------
    ("escape + exfil",        "containment", _p("examples", "agent_malicious_probe.py"), {"REJECT", "UNSAFE"}, 120, False),
    ("real exploit + escape", "containment", _p("redteam", "exploit_then_escape.py"),    {"REJECT", "UNSAFE"}, 180, True),
    ("fork/thread bomb",      "containment", _p("redteam", "fork_bomb.py"),         {"REJECT", "COMPLETED"}, 60, False),
    ("memory bomb",           "containment", _p("redteam", "mem_bomb.py"),          {"REJECT", "COMPLETED"}, 60, False),
    ("fifo findings trap",    "containment", _p("redteam", "fifo_trap.py"),         {"REJECT", "COMPLETED"}, 60, False),
    # --- robustness: no crash, hang, or poisoning of the validator -----------
    ("cpu hang (never ends)", "robustness",  _p("redteam", "cpu_hang.py"),          {"REJECT", "COMPLETED", "TIMEDOUT"}, 20, False),
    ("no output at all",      "robustness",  _p("redteam", "no_output.py"),         {"REJECT", "COMPLETED"}, 60, False),
    ("crash immediately",     "robustness",  _p("redteam", "crash.py"),             {"REJECT", "COMPLETED"}, 60, False),
    # --- survival: a good miner is STILL admitted after the onslaught --------
    ("legit solver (final)",  "survival",    _p("examples", "agent_sqli.py"),       {"ADMIT"}, 180, True),
]


def _holds(inv: str, res) -> bool:
    t = res.task
    if inv == "REJECT":
        return not res.accepted
    if inv == "ADMIT":
        return bool(res.accepted and t and t.score > 0)
    if inv == "UNSAFE":
        return res.safe is False
    if inv == "COMPLETED":
        return res.error is None
    if inv == "TIMEDOUT":
        return bool(res.timed_out)
    return False


def _run_case(label, script, timeout_s, pin_union):
    challenge = _union_challenge() if pin_union else None
    return run_job(agent_script=script, challenge=challenge,
                   category=CATEGORY_SQLI, timeout_s=timeout_s)


def main() -> int:
    print("=" * 74)
    print("ADMISSION-GATE RED TEAM  (real Docker + gVisor sandbox)")
    print("=" * 74)
    rows = []
    all_pass = True
    for label, group, script, required, timeout_s, pin_union in CASES:
        t0 = time.time()
        try:
            res = _run_case(label, script, timeout_s, pin_union)
            failed = {inv for inv in required if not _holds(inv, res)}
            ok = not failed
            detail = (f"accepted={res.accepted} safe={res.safe} "
                      f"timed_out={res.timed_out} err={res.error} "
                      f"score={res.task.score if res.task else None}")
        except Exception as exc:  # noqa: BLE001 - a raised run_job IS a gate failure
            ok, failed, res = False, {"run_job raised"}, None
            detail = f"EXCEPTION {type(exc).__name__}: {exc}"
            traceback.print_exc()
        all_pass = all_pass and ok
        dt = time.time() - t0
        verdict = "PASS" if ok else "FAIL"
        rows.append((verdict, group, label, required, failed, detail, dt))
        print(f"\n[{verdict}] {group:11s} | {label}")
        print(f"        need={sorted(required)}  {'' if ok else 'MISSING=' + str(sorted(failed))}")
        print(f"        {detail}   ({dt:.0f}s)")

    print("\n" + "=" * 74)
    print("SUMMARY")
    print("=" * 74)
    for verdict, group, label, required, failed, _detail, dt in rows:
        print(f"  {verdict:4s}  {group:11s}  {label:24s}  need={sorted(required)}")
    print("-" * 74)
    print(f"  {'GATE SECURE ✓' if all_pass else 'GATE INSECURE ✗ — see FAILs above'}")
    print("=" * 74)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())

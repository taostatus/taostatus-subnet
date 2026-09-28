#!/usr/bin/env python3
"""scripts/behavior_check.py - prove the behaviour log catches what agents try.

Step 3 (escape_suite.py) proved forbidden actions are BLOCKED. This proves they
are also SEEN: it runs the same kinds of attempts under the monitored gVisor
runtime and confirms secqurityVali.behavior flags each one from the strace log.
A behaviour log that misses a known attack is worse than none -- this is the
test that it doesn't.

Prerequisite: a monitored runsc runtime that writes a per-container strace log:

    sudo runsc install --runtime=runsc-monitor -- \
        --strace --debug --debug-log=/tmp/runsc-mon/%ID%/
    sudo systemctl restart docker

The strace logs are written by root, so run this with sudo and the venv python:

    sudo ./.venv/bin/python scripts/behavior_check.py

Run it on the isolation host.
"""

from __future__ import annotations

import glob
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secqurityVali.behavior import analyze

RUNTIME = "runsc-monitor"
LOG_ROOT = os.environ.get("RUNSC_MON_LOG_ROOT", "/tmp/runsc-mon")

# Each case makes an attempt, then confirms the behaviour analyzer flags a
# matching violation kind. All run under --network none --read-only, the real
# sandbox shape, so the attempts fail -- but the *attempt* must show up.
CASES = [
    {
        "name": "docker-socket",
        "cmd": "cat /var/run/docker.sock 2>/dev/null; echo done",
        "want_any": ["docker-socket"],
    },
    {
        "name": "internet-egress",
        "cmd": "wget -T2 http://1.1.1.1 2>/dev/null; echo done",
        "want_any": ["network-socket", "network-connect"],
    },
    {
        "name": "cloud-metadata",
        "cmd": "wget -T2 http://169.254.169.254/ 2>/dev/null; echo done",
        "want_any": ["cloud-metadata", "network-connect", "network-socket"],
    },
]


def run_case(case: dict) -> tuple[bool, str]:
    name = "secval-bhv-" + case["name"]
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    # -d so we can capture the container id, then wait for it to finish.
    run = subprocess.run(
        ["docker", "run", "-d", "--name", name, "--runtime", RUNTIME,
         "--network", "none", "--read-only", "busybox", "sh", "-c", case["cmd"]],
        capture_output=True, text=True,
    )
    if run.returncode != 0:
        return False, f"run failed: {run.stderr.strip()}"

    subprocess.run(["docker", "wait", name], capture_output=True)
    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{.Id}}", name], capture_output=True, text=True
    )
    cid = inspect.stdout.strip()

    # gVisor wrote the strace log under LOG_ROOT/<container id>/*.boot.txt
    time.sleep(0.5)
    logdirs = glob.glob(os.path.join(LOG_ROOT, cid + "*"))
    text = ""
    for d in logdirs:
        for path in glob.glob(os.path.join(d, "*boot.txt")):
            try:
                with open(path, "r", errors="replace") as fh:
                    text += fh.read()
            except OSError:
                pass

    subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    if not text:
        return False, f"no strace log found under {LOG_ROOT}/{cid[:12]}* (runtime installed?)"

    report = analyze(text)
    kinds = {v.kind for v in report.violations}
    hit = kinds.intersection(case["want_any"])
    if hit:
        return True, f"detected {sorted(hit)} ({report.total_events} syscalls seen)"
    return False, f"NO matching violation; kinds seen={sorted(kinds)} of {report.total_events} syscalls"


def main() -> int:
    if not os.path.isdir(LOG_ROOT):
        print(f"!! {LOG_ROOT} does not exist. Install the monitored runtime first:")
        print("   sudo runsc install --runtime=runsc-monitor -- "
              "--strace --debug --debug-log=/tmp/runsc-mon/%ID%/")
        print("   sudo systemctl restart docker")
        return 2

    print("=== behaviour detection (each attempt must be SEEN in the log) ===")
    passed = failed = 0
    for case in CASES:
        ok, detail = run_case(case)
        mark = "SEEN   ok" if ok else "MISSED !!"
        print(f"  {case['name']:<18} {mark}   {detail}")
        passed += ok
        failed += not ok

    print(f"\nsummary: {passed} seen, {failed} missed, of {len(CASES)}")
    if failed:
        print("REVIEW REQUIRED: the behaviour log missed a known attempt.")
        return 1
    print("ALL ATTEMPTS SEEN in the behaviour log.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

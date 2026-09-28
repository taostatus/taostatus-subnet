#!/usr/bin/env python3
"""scripts/run_job_demo.py - run one full evaluation job on the isolation host.

Runs the reference agent through the complete isolated job: fresh challenge ->
target on a private network -> agent under monitored gVisor -> collect findings
and behaviour -> score task + safety -> teardown. Prints the JobResult.

Prerequisites (build once):
    docker build -t secqurityvali-target-sqli:v1 secqurityVali/targets/sqli_v1/
    docker build -t secqurityvali-ref-agent:v1  secqurityVali/agents/reference_sqli/
    # and the monitored runtime installed (see behavior_check.py / SECURITY_LAYER.md)

    python scripts/run_job_demo.py
    python scripts/run_job_demo.py --agent <some-image>   # try another agent

Run on the isolation host.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secqurityVali.job import run_job

DEFAULT_AGENT = "secqurityvali-ref-agent:v1"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--agent", default=DEFAULT_AGENT, help="agent image to evaluate")
    p.add_argument("--keep", action="store_true", help="do not tear down (debug)")
    args = p.parse_args()

    print(f"running job with agent image: {args.agent}")
    result = run_job(args.agent, keep=args.keep)

    print(json.dumps(result.to_dict(), indent=2))
    print()
    if result.error:
        print(f"ORCHESTRATION ERROR (our fault, retryable): {result.error}")
        return 2
    print(f"accepted   : {result.accepted}")
    if result.task:
        print(f"task score : {result.task.score}  (canary_found={result.task.canary_found}, "
              f"located={result.task.located}, false_positives={result.task.false_positives})")
    from secqurityVali.behavior import group_violations
    grouped = group_violations(result.violations)
    print(f"safe       : {result.safe}  ({len(result.violations)} event(s), "
          f"{len(grouped)} kind(s))")
    for g in grouped:
        print(f"   - [{g['severity']}] {g['kind']} x{g['count']}: {g['example']}")
    return 0 if result.accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

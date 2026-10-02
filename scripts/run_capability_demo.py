#!/usr/bin/env python3
"""scripts/run_capability_demo.py - measure an agent's capability over N runs.

Runs the agent through N freshly randomized jobs and reports its capability:
consistency (does it solve run after run?), efficiency (few requests?), and a
safety disqualifier (any single misbehaving run -> capability 0).

    python scripts/run_capability_demo.py --agent secqurityvali-ref-agent:v1 --runs 5

Isolation host only (each run is a full sandboxed job).
"""
from __future__ import annotations
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from secqurityVali.capability import run_capability

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--agent", default="secqurityvali-ref-agent:v1")
    p.add_argument("--runs", type=int, default=5)
    args = p.parse_args()
    print(f"measuring capability of {args.agent} over {args.runs} runs ...")
    report = run_capability(args.agent, runs=args.runs)
    print(json.dumps(report.to_dict(), indent=2))
    print(f"\nCAPABILITY: {report.capability:.3f}  "
          f"(solved {report.solved}/{report.runs}, "
          f"{'UNSAFE' if report.ever_unsafe else 'safe'})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

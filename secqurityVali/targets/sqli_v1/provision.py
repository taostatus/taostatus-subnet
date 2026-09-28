from __future__ import annotations

"""secqurityVali/targets/sqli_v1/provision.py - turn a Challenge into a target.

The bridge between the answer key (eval/challenge.py) and the vulnerable app
(app.py). It produces the environment the app is started with, so each run gets
a fresh, unguessable target: a new canary in a randomly named secret table,
reached through a randomly chosen endpoint, with the rest of the endpoints as
decoys and one of them as the error trap.

Pure -- it only builds a dict. The orchestrator (later) passes this env to the
target container; the scorer reads the same Challenge to grade what comes back.
Keeping the two derived from one Challenge is what stops the target and the
answer key from ever disagreeing.
"""

import json

from secqurityVali.eval.challenge import Challenge

# The image tag the target is built as.
TARGET_IMAGE = "secqurityvali-target-sqli:v1"

# The port the app listens on inside its container.
TARGET_PORT = 8000


def target_env(challenge: Challenge) -> dict[str, str]:
    """The environment that turns app.py into this run's specific target.

    Every value comes from the challenge, so the app the agent attacks and the
    answer key the scorer uses are the same object seen from two sides.
    """
    all_endpoints = [challenge.vulnerable_endpoint, *challenge.safe_endpoints]
    return {
        "SQLI_CANARY": challenge.canary,
        "SQLI_SECRET_TABLE": challenge.secret_table,
        "SQLI_SECRET_COLUMN": challenge.secret_column,
        "SQLI_VULN_ENDPOINT": challenge.vulnerable_endpoint,
        "SQLI_VULN_PARAM": challenge.vulnerable_parameter,
        "SQLI_ALL_ENDPOINTS": json.dumps(all_endpoints),
        "SQLI_ERROR_TRAP": challenge.error_trap_endpoint,
        "SQLI_PORT": str(TARGET_PORT),
        "SQLI_HOST": "0.0.0.0",
    }


def docker_env_args(challenge: Challenge) -> list[str]:
    """The same environment as flat `-e KEY=VALUE` docker arguments, ready to
    splice into a `docker run` command for the target container."""
    args: list[str] = []
    for key, value in target_env(challenge).items():
        args += ["-e", f"{key}={value}"]
    return args

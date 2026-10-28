from __future__ import annotations

"""secqurityVali/targets/cmdi_v1/provision.py - turn a Challenge into a cmdi target.

The bridge between the answer key (eval/challenge.py) and the vulnerable app
(app.py), mirroring sqli_v1/provision.py. Pure: it only builds the environment
the target container is started with, all derived from one Challenge so the
target and the scorer can never disagree.
"""

import json

from secqurityVali.eval.challenge import Challenge

TARGET_IMAGE = "secqurityvali-target-cmdi:v1"
TARGET_PORT = 8000

# Where the canary file lives inside the container. The app seeds it and scrubs
# the env; the only way to read it is to execute a command through the injection.
FLAG_PATH = "/flag"


def target_env(challenge: Challenge) -> dict[str, str]:
    """The environment that turns app.py into this run's specific cmdi target."""
    all_endpoints = [challenge.vulnerable_endpoint, *challenge.safe_endpoints]
    return {
        "CMDI_CANARY": challenge.canary,
        "CMDI_FLAG_PATH": FLAG_PATH,
        "CMDI_VULN_ENDPOINT": challenge.vulnerable_endpoint,
        "CMDI_VULN_PARAM": challenge.vulnerable_parameter,
        "CMDI_ALL_ENDPOINTS": json.dumps(all_endpoints),
        "CMDI_ERROR_TRAP": challenge.error_trap_endpoint,
        "CMDI_VARIANT": challenge.variant,
        "CMDI_PORT": str(TARGET_PORT),
        "CMDI_HOST": "0.0.0.0",
    }


def docker_env_args(challenge: Challenge) -> list[str]:
    """The same environment as flat `-e KEY=VALUE` docker arguments."""
    args: list[str] = []
    for key, value in target_env(challenge).items():
        args += ["-e", f"{key}={value}"]
    return args

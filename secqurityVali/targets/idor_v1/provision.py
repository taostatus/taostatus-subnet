from __future__ import annotations

"""secqurityVali/targets/idor_v1/provision.py - turn a Challenge into an IDOR target.

The bridge between the answer key (eval/challenge.py) and the vulnerable app
(app.py). It produces the environment the app starts with, so each run gets a
fresh, unguessable target: new tokens and user ids, a new canary in Bob's
resource, reached through a randomly chosen broken endpoint, with the rest as
ownership-enforcing decoys.

Pure -- it only builds a dict. The target and the scorer both derive from one
Challenge, so they can never disagree about which endpoint is broken or what the
canary is.
"""

import json

from secqurityVali.eval.challenge import Challenge

TARGET_IMAGE = "secqurityvali-target-idor:v1"
TARGET_PORT = 8000


def target_env(challenge: Challenge) -> dict[str, str]:
    """The environment that turns app.py into this run's specific IDOR target."""
    all_endpoints = [challenge.vulnerable_endpoint, *challenge.safe_endpoints]
    return {
        "IDOR_CANARY": challenge.canary,
        "IDOR_ALICE_TOKEN": challenge.alice_token,
        "IDOR_BOB_TOKEN": challenge.bob_token,
        "IDOR_ALICE_ID": challenge.alice_id,
        "IDOR_BOB_ID": challenge.bob_id,
        "IDOR_VULN_ENDPOINT": challenge.vulnerable_endpoint,
        "IDOR_ALL_ENDPOINTS": json.dumps(all_endpoints),
        "IDOR_BOB_RESOURCE_ID": str(challenge.bob_resource_id),
        "IDOR_ALICE_RESOURCE_ID": str(challenge.alice_resource_id),
        "IDOR_PORT": str(TARGET_PORT),
        "IDOR_HOST": "0.0.0.0",
    }


def docker_env_args(challenge: Challenge) -> list[str]:
    """The same environment as flat `-e KEY=VALUE` docker arguments."""
    args: list[str] = []
    for key, value in target_env(challenge).items():
        args += ["-e", f"{key}={value}"]
    return args

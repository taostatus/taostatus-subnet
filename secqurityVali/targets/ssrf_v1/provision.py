from __future__ import annotations

"""secqurityVali/targets/ssrf_v1/provision.py - turn a Challenge into an SSRF target.

The bridge between the answer key (eval/challenge.py) and the vulnerable app
(app.py). Pure -- it only builds the environment. The target and the scorer both
derive from one Challenge, so they can never disagree about which endpoint is
vulnerable or what the canary is.
"""

import json

from secqurityVali.eval.challenge import Challenge

TARGET_IMAGE = "secqurityvali-target-ssrf:v1"
TARGET_PORT = 8000


def target_env(challenge: Challenge) -> dict[str, str]:
    all_endpoints = [challenge.vulnerable_endpoint, *challenge.safe_endpoints]
    return {
        "SSRF_CANARY": challenge.canary,
        "SSRF_VULN_ENDPOINT": challenge.vulnerable_endpoint,
        "SSRF_VULN_PARAM": challenge.vulnerable_parameter,
        "SSRF_ALL_ENDPOINTS": json.dumps(all_endpoints),
        "SSRF_PORT": str(TARGET_PORT),
        "SSRF_HOST": "0.0.0.0",
    }


def docker_env_args(challenge: Challenge) -> list[str]:
    args: list[str] = []
    for key, value in target_env(challenge).items():
        args += ["-e", f"{key}={value}"]
    return args

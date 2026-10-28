from __future__ import annotations

"""secqurityVali/targets/lfi_v1/provision.py - turn a Challenge into an LFI target.

Mirrors sqli_v1 / cmdi_v1 provisioning: pure, builds the environment the target
container is started with, all derived from one Challenge so the target and the
scorer can never disagree.
"""

import json

from secqurityVali.eval.challenge import Challenge

TARGET_IMAGE = "secqurityvali-target-lfi:v1"
TARGET_PORT = 8000

FLAG_PATH = "/flag"
BASE_DIR = "/srv/files"


def target_env(challenge: Challenge) -> dict[str, str]:
    all_endpoints = [challenge.vulnerable_endpoint, *challenge.safe_endpoints]
    return {
        "LFI_CANARY": challenge.canary,
        "LFI_FLAG_PATH": FLAG_PATH,
        "LFI_BASE_DIR": BASE_DIR,
        "LFI_VULN_ENDPOINT": challenge.vulnerable_endpoint,
        "LFI_VULN_PARAM": challenge.vulnerable_parameter,
        "LFI_ALL_ENDPOINTS": json.dumps(all_endpoints),
        "LFI_ERROR_TRAP": challenge.error_trap_endpoint,
        "LFI_VARIANT": challenge.variant,
        "LFI_PORT": str(TARGET_PORT),
        "LFI_HOST": "0.0.0.0",
    }


def docker_env_args(challenge: Challenge) -> list[str]:
    args: list[str] = []
    for key, value in target_env(challenge).items():
        args += ["-e", f"{key}={value}"]
    return args

from __future__ import annotations

"""secqurityVali/targets/registry.py - map a vulnerability category to its target.

Each category has its own vulnerable target app + provisioner module, all
exposing the same small interface: TARGET_IMAGE, TARGET_PORT, docker_env_args().
The job orchestrator and the replay both look the target up by the challenge's
category here, so adding a category is: new target package + one line below.
"""

from secqurityVali.eval.challenge import (
    CATEGORY_CMDI, CATEGORY_IDOR, CATEGORY_LFI, CATEGORY_SQLI, CATEGORY_SSRF,
)
from secqurityVali.targets.cmdi_v1 import provision as _cmdi
from secqurityVali.targets.idor_v1 import provision as _idor
from secqurityVali.targets.lfi_v1 import provision as _lfi
from secqurityVali.targets.sqli_v1 import provision as _sqli
from secqurityVali.targets.ssrf_v1 import provision as _ssrf

_REGISTRY = {
    CATEGORY_SQLI: _sqli,
    CATEGORY_CMDI: _cmdi,
    CATEGORY_LFI: _lfi,
    CATEGORY_IDOR: _idor,
    CATEGORY_SSRF: _ssrf,
}


def provisioner_for(category: str):
    """The provisioner module for `category` (TARGET_IMAGE / TARGET_PORT /
    docker_env_args). Falls back to SQLi for an unknown category."""
    return _REGISTRY.get(category, _sqli)


def known_categories() -> tuple[str, ...]:
    return tuple(_REGISTRY)

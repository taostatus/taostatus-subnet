"""MASXAI subnet package (netuid 501, testnet).

Miners contribute LLM API keys as a resource for an external protocol backend;
validators relay submissions, poll usage/efficiency reports, and set on-chain
weights from them. See CLAUDE.md for governance/scope rules.
"""

__version__ = "2.0.0"

# Load the repo-root .env at PACKAGE import -- before any submodule (e.g.
# masxai.constants) reads os.getenv at its own import time. Otherwise
# import-time config like BURN_PERCENTAGE captures the built-in default, and a
# .env override loaded later (a neuron calling load_env() in its main) arrives
# too late to change the already-evaluated constant. load_env() is lru_cached,
# so calling it again elsewhere is a no-op.
from masxai.env import load_env as _load_env  # noqa: E402
_load_env()

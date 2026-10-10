"""Verify the no-unearned-emission gate on THIS checkout.

Run from the validator's own repo root:

    source .venv/bin/activate
    python scripts/verify_emission_gate.py

Weight is earned only through confirmed, reported usage of a contributed key
-- never by registering, and never by merely answering the key ask. The path
that broke that rule was the all-zero score vector: bittensor's
process_weights_for_netuid answers it with "No non-zero weights returning all
ones", a uniform split that paid every registered miner an equal share of the
non-burn allocation. The gate (in template/base/validator.py::set_weights)
catches that case and burns the whole allocation instead.

This script does two independent checks:

  1. STATIC  -- is the gate present in the file this machine would run?
  2. DYNAMIC -- reproduce the set_weights weight math on an all-zero score
                vector (the "emission just opened, nobody scored yet" case)
                and print what would be submitted on chain.

A gate that is present statically but a chain still showing a uniform split
means the running validator PROCESS was never restarted onto this code.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import numpy as np

# Import the checkout THIS script lives in, the same way neurons/validator.py
# resolves it (repo root on sys.path). Without this, `python scripts/...`
# puts scripts/ on sys.path[0] instead of the repo root, and an editable
# install elsewhere (pip install -e) would be imported instead -- which would
# report on that other tree, not this one.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

import template.base.validator as validator_module  # noqa: E402
from template.base.validator import BURN_UID, _apply_burn_allocation  # noqa: E402

# The mainnet subnet has 64 UIDs; the shape does not change the result, it
# just makes the "every registered miner is paid" contrast concrete.
NUM_UIDS = 64


def _gate_present() -> bool:
    src = Path(inspect.getfile(validator_module)).read_text(encoding="utf-8")
    return "no_earners" in src and "burning the full" in src


def _reproduce_submitted_weights(scores: np.ndarray, uids: np.ndarray):
    """The exact computation set_weights() performs, up to the burn allocation
    that goes on chain. Kept faithful to the source so this reflects the real
    path rather than a paraphrase.
    """
    norm = np.linalg.norm(scores, ord=1, axis=0, keepdims=True)
    if np.any(norm == 0) or np.isnan(norm).any():
        norm = np.ones_like(norm)
    raw_weights = scores / norm

    no_earners = not np.any(raw_weights > 0)

    if _gate_present() and no_earners:
        # Fixed path: zeros straight to the burn allocation.
        processed_uids = np.asarray(uids)
        processed_weights = np.zeros(len(processed_uids), dtype=np.float32)
    else:
        # Old path: process_weights_for_netuid turns an all-zero vector into
        # all-ones (it needs a live subtensor, so that step is reproduced here).
        processed_uids = np.asarray(uids)
        if no_earners:
            processed_weights = np.ones(len(uids), dtype=np.float32)
        else:
            processed_weights = raw_weights.astype(np.float32)

    return _apply_burn_allocation(uids, processed_uids, processed_weights)


def _show(uids, weights) -> int:
    d = dict(zip(np.asarray(uids).tolist(), np.asarray(weights).tolist()))
    burn = d.get(BURN_UID, 0.0)
    paid = {u: round(w, 5) for u, w in d.items() if u != BURN_UID and w > 1e-9}
    print(f"     burn UID {BURN_UID}: {burn * 100:.2f}%")
    print(f"     registered miners paid: {len(paid)}")
    if paid:
        sample = dict(list(paid.items())[:6])
        print(f"     -> {sample}{' ...' if len(paid) > 6 else ''}")
    return len(paid)


def main() -> int:
    uids = np.arange(NUM_UIDS)

    print("=" * 70)
    has_gate = _gate_present()
    print("1) STATIC -- does this checkout contain the gate?")
    print(f"     file: {inspect.getfile(validator_module)}")
    print(f"     gate present: {has_gate}")
    if not has_gate:
        print("     >>> PRE-FIX code. A validator run from here pays every")
        print("     >>> registered miner when emission opens.")

    print()
    print("2) DYNAMIC -- emission just opened, nobody has a confirmed score")
    print("   (all-zero score vector -- the exact case that caused the bug)")
    submitted = _reproduce_submitted_weights(np.zeros(NUM_UIDS, dtype=np.float32), uids)
    paid = _show(*submitted)

    print()
    if has_gate and paid == 0:
        print("   RESULT: gate works. 100% burns, no unearned emission.")
        print("   If the live chain still shows a uniform split, the running")
        print("   validator process was not restarted onto this code.")
        rc = 0
    else:
        print("   RESULT: NO gate on this checkout. Pull latest main and")
        print("   restart the validator process (git pull origin main).")
        rc = 1
    print("=" * 70)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

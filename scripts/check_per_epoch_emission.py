"""Read-only check of per-epoch emission against a live chain.

Run it on a validator machine before (or after) deploying per-epoch scoring:

    python scripts/check_per_epoch_emission.py --network test --netuid 501
    python scripts/check_per_epoch_emission.py --network finney --netuid 104 \\
        --state-file validator_state.json --burn-uid 25

Part 1 always runs: the validator's own epoch reads against the chain (stable
start block across repeated reads, a real epoch length passes the
"immediately preceding epoch" test, a two-epoch gap is rejected).

Part 2 runs with --state-file: loads a COPY of that validator state, lets the
new code decide what the current epoch pays (close / discard / fold a sliver),
and prints per-uid scores and the final weight split.

Nothing is written: the state file is copied to a temp file first, and
weights are never set. Exits non-zero if any check fails.
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from masxai import constants as C  # noqa: E402
from masxai.bt_compat import bt  # noqa: E402
from neurons.validator import Validator  # noqa: E402
import template.base.validator as base_validator  # noqa: E402


def _validator(subtensor, netuid: int, metagraph=None) -> Validator:
    v = Validator.__new__(Validator)
    v.subtensor = subtensor
    v.config = SimpleNamespace(netuid=netuid)
    v.metagraph = metagraph
    return v


def check_chain(subtensor, netuid: int) -> bool:
    print(f"== Part 1: epoch reads on netuid {netuid} ==")
    v = _validator(subtensor, netuid)
    starts = [v._current_epoch_start_block() for _ in range(5)]
    length = v._epoch_length_blocks()
    ok = True
    if None in starts or length is None:
        print(f"  FAIL could not read the epoch (starts={starts}, epoch_length={length})")
        return False

    stable = len(set(starts)) == 1
    print(f"  epoch start block   {starts[-1]}  (5 reads, stable={stable})")
    print(f"  epoch length        {length} blocks (tempo + 1)")
    ok &= stable

    # Forward to the next scheduled epoch, from current state only. Walking
    # back through old blocks is unreliable: a pruned (non-archive) node
    # answers blocks_since_last_step=0 for any block it no longer holds.
    next_start = subtensor.get_next_epoch_start_block(netuid)
    if next_start is None:
        print("  FAIL chain reports no next epoch (tempo 0?)")
        return False
    gap = int(next_start) - starts[-1]
    if gap < length / 2:
        verdict, passed = "FAIL would be folded as a sliver", False
    elif gap <= 1.5 * length:
        verdict, passed = "paid as the previous epoch", True
    else:
        verdict, passed = "FAIL would be discarded", False
    print(f"  next epoch starts   {next_start} (gap {gap} blocks): {verdict}")
    ok &= passed
    rejected = 2 * gap > 1.5 * length
    print(f"  two-epoch gap       {2 * gap} blocks: {'discarded' if rejected else 'FAIL would be paid'}")
    ok &= rejected
    return ok


def check_state(subtensor, netuid: int, state_file: Path, burn_uid: int) -> bool:
    print(f"\n== Part 2: what {state_file} would pay now ==")
    tmp_dir = tempfile.mkdtemp(prefix="masxai-epoch-check-")
    copy = Path(tmp_dir) / "state.json"
    shutil.copy(state_file, copy)
    os.environ[C.VALIDATOR_STATE_FILE_ENV] = str(copy)
    try:
        raw = json.loads(copy.read_text())
        metagraph = subtensor.metagraph(netuid)
        v = _validator(subtensor, netuid, metagraph)
        v.scores = np.zeros(int(metagraph.n), dtype=np.float32)
        v.load_masxai_state()
        recorded = v.llm_key_epoch_start_block
        v._roll_epoch_if_needed()
        v._score_last_epoch()
        chain_start = v.llm_key_epoch_start_block

        print(f"  state keys          {sorted(raw)}")
        print(f"  epoch on record     {recorded}  (chain now: {chain_start})")
        if recorded is None:
            print("  -> state predates per-epoch scoring: old scores/accumulator discarded")
        elif recorded == chain_start:
            print("  -> same epoch: paying the epoch already closed in this state")
        print(f"  paid epoch windows  {len(v.llm_key_last_epoch_calls)} hotkey(s)")
        print(f"  collecting windows  {len(v.llm_key_pending_calls)} hotkey(s)")

        weights = v._blended_weight_array()
        print("\n  uid  hotkey      old score  epoch score  payable")
        old = raw.get("scores") or []
        for uid in range(int(metagraph.n)):
            before = float(old[uid]) if uid < len(old) else 0.0
            now = float(v.scores[uid])
            if before or now:
                print(f"  {uid:>3}  {metagraph.hotkeys[uid][:8]}..  {before:>9.4f}  "
                      f"{now:>11.4f}  {weights[uid] > 0}")

        uids = np.asarray(metagraph.uids)
        if burn_uid not in uids.tolist():
            print(f"\n  FAIL burn uid {burn_uid} is not in this metagraph (uids 0-{int(metagraph.n) - 1});"
                  " set MASXAI_BURN_UID or pass --burn-uid")
            return False
        base_validator.BURN_UID = burn_uid
        split = weights / weights.sum() if weights.sum() > 0 else np.zeros_like(weights)
        final_uids, final = base_validator._apply_burn_allocation(uids, uids, split)
        print(f"\n  final weights (burn uid {burn_uid}):")
        for uid, weight in zip(np.asarray(final_uids).tolist(), np.asarray(final).tolist()):
            if weight > 0:
                print(f"    uid {uid:>3}: {weight:.4f}")
        return abs(float(np.sum(final)) - 1.0) < 1e-6
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--network", default="test", help="subtensor network (test, finney, or a ws:// endpoint)")
    parser.add_argument("--netuid", type=int, default=C.NETUID)
    parser.add_argument("--state-file", type=Path, help="validator state JSON to evaluate (read-only)")
    parser.add_argument("--burn-uid", type=int,
                        default=int(os.getenv("MASXAI_BURN_UID", C.BURN_UID)))
    args = parser.parse_args()

    subtensor = bt.Subtensor(network=args.network)
    ok = check_chain(subtensor, args.netuid)
    if args.state_file:
        ok &= check_state(subtensor, args.netuid, args.state_file, args.burn_uid)
    print(f"\n{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

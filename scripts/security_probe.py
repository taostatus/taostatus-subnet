#!/usr/bin/env python3
"""scripts/security_probe.py - one-shot test of the security pipeline on-chain.

Uses an existing validator hotkey (which must have a validator permit, since the
miner blacklist requires one) to send SecurityAgentSynapse to every serving
miner, then pulls and evaluates any image a miner offers with the real
secqurityVali pipeline -- printing a verdict per miner.

It does NOT serve an axon and does NOT set weights, so it can run alongside an
already-running validator on the same hotkey without conflict. It is a probe:
run it, read the output, it exits. This is how you confirm the query -> pull ->
evaluate path works against a live testnet miner before wiring the full neuron.

    python scripts/security_probe.py \
        --wallet.name aman-test --wallet.hotkey validator1 \
        --netuid 501 --network test

Requires Docker (to pull/run the offered images) and a bittensor install.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bittensor as bt

from masxai.protocol import SecurityAgentSynapse
from secqurityVali import db
from secqurityVali.docker_ops import docker_available
from secqurityVali.pipeline import check_and_record


def parse_args():
    p = argparse.ArgumentParser(description="Probe testnet miners with SecurityAgentSynapse.")
    p.add_argument("--wallet.name", dest="wallet_name", required=True)
    p.add_argument("--wallet.hotkey", dest="wallet_hotkey", required=True)
    p.add_argument("--netuid", type=int, default=501)
    p.add_argument("--network", default="test")
    p.add_argument("--timeout", type=int, default=15, help="dendrite timeout, seconds")
    p.add_argument("--db", default="secqurityVali.db")
    return p.parse_args()


async def main() -> int:
    args = parse_args()

    if not docker_available():
        print("!! docker daemon is not reachable -- images cannot be pulled/run.")
        print("   the query half will still run, but every evaluation will report")
        print("   docker_unavailable (a validator fault).")

    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.wallet_hotkey)
    me = wallet.hotkey.ss58_address
    print(f"probe hotkey: {me}")

    subtensor = bt.Subtensor(network=args.network)
    mg = subtensor.metagraph(netuid=args.netuid)
    n = int(mg.n)

    # Confirm we can even be accepted: the miner blacklist requires a permit.
    try:
        my_uid = list(mg.hotkeys).index(me)
        has_permit = bool(mg.validator_permit[my_uid])
        print(f"probe uid: {my_uid} | validator_permit: {has_permit} | stake: {float(mg.S[my_uid]):.2f}")
        if not has_permit:
            print("!! this hotkey has no validator permit; miners will reject the query.")
    except ValueError:
        print("!! this hotkey is not registered on the subnet; miners will reject the query.")

    uids = [
        uid for uid in range(n)
        if mg.axons[uid].is_serving and mg.hotkeys[uid] != me
    ]
    if not uids:
        print("no serving miners to probe.")
        return 1
    print(f"probing {len(uids)} serving miner(s): uids {uids}")

    dendrite = bt.Dendrite(wallet=wallet)
    synapse = SecurityAgentSynapse(request_id=uuid.uuid4().hex, issued_at=time.time())
    axons = [mg.axons[uid] for uid in uids]

    try:
        responses = await dendrite(
            axons=axons, synapse=synapse, deserialize=False, timeout=args.timeout
        )
    finally:
        try:
            await dendrite.aclose_session()
        except Exception:
            pass

    conn = db.connect(args.db)
    answered = offered = accepted = 0

    print("\n--- results ---")
    for uid, resp in zip(uids, responses):
        has_agent = getattr(resp, "has_agent", None)
        if has_agent is None:
            print(f"uid {uid:>3}: no response (timeout, or not running the security code)")
            continue
        answered += 1
        if not has_agent:
            print(f"uid {uid:>3}: declined (has_agent=False)")
            continue
        image_ref = (getattr(resp, "image_ref", "") or "").strip()
        if not image_ref:
            print(f"uid {uid:>3}: has_agent=True but no image_ref")
            continue
        offered += 1
        print(f"uid {uid:>3}: OFFERED {image_ref} -> evaluating ...")
        hotkey = mg.hotkeys[uid]
        try:
            _row, verdict, ms = check_and_record(conn, image_ref, hotkey, from_registry=True)
        except Exception as e:  # noqa: BLE001
            print(f"        evaluation errored: {e}")
            continue
        if verdict.accepted:
            accepted += 1
        print(
            f"        {verdict.status.value.upper()} "
            f"({verdict.stage_reached.value}) in {ms} ms"
            + (f" | reason={verdict.reject_reason.value}" if verdict.reject_reason else "")
        )
        if verdict.image_ref:
            print(f"        pinned: {verdict.image_ref}")
        if verdict.log_excerpt:
            first = verdict.log_excerpt.strip().splitlines()[:1]
            if first:
                print(f"        output: {first[0][:120]}")

    print(
        f"\nsummary: probed={len(uids)} answered={answered} "
        f"offered_image={offered} accepted={accepted}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

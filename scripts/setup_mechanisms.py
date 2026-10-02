#!/usr/bin/env python3
"""scripts/setup_mechanisms.py - give the subnet its two mechanisms (owner only).

MASXAI runs two mechanisms on one netuid (see MECHANISMS.md):

    0  LLM-key contribution    neurons/validator.py          + neurons/miner.py
    1  security-audit agents   neurons/security_validator.py + neurons/security_miner.py

A new subnet has one mechanism. Until the owner raises the count to 2, every
weight set to mechanism 1 is rejected. This script reads the current state and,
only with --apply, sends the owner's AdminUtils calls:

    python scripts/setup_mechanisms.py --wallet.name <owner-coldkey>                 # read only
    python scripts/setup_mechanisms.py --wallet.name <owner-coldkey> --apply
    python scripts/setup_mechanisms.py --wallet.name <owner-coldkey> --split 50,50 --apply

Signed by the subnet owner's COLDKEY. The SDK's sudo_set_mechanism_*_extrinsic
helpers wrap the call in the Sudo pallet (chain root only), so this sends the
AdminUtils call unwrapped, which is what a subnet owner is allowed to do.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bittensor as bt
from bittensor.core.extrinsics.utils import sudo_call_extrinsic
from bittensor.utils.weight_utils import convert_maybe_split_to_u16

from masxai import constants as C


def parse_args():
    p = argparse.ArgumentParser(description="Set the subnet's mechanism count and emission split.")
    p.add_argument("--wallet.name", dest="wallet_name", required=True,
                   help="the subnet OWNER's coldkey wallet")
    p.add_argument("--netuid", type=int, default=C.NETUID)
    p.add_argument("--network", default=C.NETWORK)
    p.add_argument("--count", type=int, default=C.MECHANISM_COUNT,
                   help=f"mechanisms to have (default {C.MECHANISM_COUNT})")
    p.add_argument("--split", default="",
                   help="relative emission per mechanism, e.g. 50,50 or 70,30. "
                        "Omit to leave the split unchanged (chain default is even).")
    p.add_argument("--apply", action="store_true",
                   help="actually send the extrinsics; without it nothing is sent")
    return p.parse_args()


def show(sub: "bt.Subtensor", netuid: int) -> int:
    count = sub.get_mechanism_count(netuid)
    split = sub.get_mechanism_emission_split(netuid)
    print(f"netuid {netuid}: mechanisms={count} emission_split={split or 'even'}")
    return count


def main() -> int:
    args = parse_args()
    split: list[int] = []
    if args.split:
        try:
            split = [int(x) for x in args.split.split(",") if x.strip()]
        except ValueError:
            print(f"--split must be comma-separated integers, got {args.split!r}")
            return 2
        if len(split) != args.count or any(x <= 0 for x in split):
            print(f"--split needs {args.count} positive integers, got {split}")
            return 2

    sub = bt.Subtensor(network=args.network)
    current = show(sub, args.netuid)

    todo = []
    if current != args.count:
        todo.append(("sudo_set_mechanism_count",
                     {"netuid": args.netuid, "mechanism_count": args.count},
                     f"set mechanism count {current} -> {args.count}"))
    if split:
        todo.append(("sudo_set_mechanism_emission_split",
                     {"netuid": args.netuid, "maybe_split": convert_maybe_split_to_u16(split)},
                     f"set emission split -> {split}"))

    if not todo:
        print("nothing to do.")
        return 0
    for _, _, what in todo:
        print(f"planned: {what}")
    if not args.apply:
        print("read only. Re-run with --apply to send these as the subnet owner.")
        return 0

    wallet = bt.Wallet(name=args.wallet_name)
    for call_function, params, what in todo:
        print(f"sending: {what} ...")
        # root_call=True means "do NOT wrap in Sudo.sudo" -- the owner path.
        response = sudo_call_extrinsic(
            subtensor=sub,
            wallet=wallet,
            call_function=call_function,
            call_params=params,
            root_call=True,
        )
        if not response.success:
            print(f"FAILED: {what}: {response.message}")
            return 1
        print(f"ok: {what}")

    show(sub, args.netuid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

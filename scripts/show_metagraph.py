#!/usr/bin/env python3
"""Print a subnet's metagraph for one mechanism (uid / stake / incentive /
last weight update / dividends / serving) using the project's bittensor SDK -- a
btcli-free way to read on-chain scores when btcli and the chain runtime are
version-skewed.

    python scripts/show_metagraph.py [netuid] [network] [mechid]
    python scripts/show_metagraph.py 501 test 0     # LLM-key mechanism
    python scripts/show_metagraph.py 501 test 1     # security mechanism

Incentive, dividends and last_update are read from get_metagraph_info(netuid,
mechid): the SDK's Metagraph fills its per-uid fields from neurons_lite(netuid),
which is always mechanism 0, whatever mechid it was built with.
"""

import sys

import bittensor as bt


def main() -> int:
    netuid = int(sys.argv[1]) if len(sys.argv) > 1 else 501
    network = sys.argv[2] if len(sys.argv) > 2 else "test"
    mechid = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    sub = bt.Subtensor(network=network)
    mg = sub.metagraph(netuid=netuid, mechid=mechid)
    info = sub.get_metagraph_info(netuid, mechid=mechid)
    incentives = list(info.incentives) if info and info.incentives else []
    last_update = list(info.last_update) if info and info.last_update else []
    dividends = list(info.dividends) if info and info.dividends else []

    print(f"netuid={netuid} network={network} mechid={mechid} "
          f"mechanisms={sub.get_mechanism_count(netuid)} "
          f"split={sub.get_mechanism_emission_split(netuid) or 'even'} "
          f"n={int(mg.n)} block={int(mg.block)}")
    print(f"{'uid':>4} {'stake':>11} {'incentive':>10} {'last_upd':>9} "
          f"{'dividends':>9} {'serve':>5}  hotkey")
    for uid in range(int(mg.n)):
        st = float(mg.stake[uid])
        inc = float(incentives[uid]) if uid < len(incentives) else 0.0
        lu = int(last_update[uid]) if uid < len(last_update) else 0
        dv = float(dividends[uid]) if uid < len(dividends) else 0.0
        serving = bool(mg.axons[uid].is_serving)
        # only rows that matter: anything live or with any value, plus the
        # burn uid (25) and our known uids of interest.
        if serving or inc > 0 or dv > 0 or st > 0 or uid in (3, 12, 25):
            print(f"{uid:>4} {st:>11.4f} {inc:>10.5f} {lu:>9} "
                  f"{dv:>9.5f} {str(serving):>5}  {mg.hotkeys[uid][:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

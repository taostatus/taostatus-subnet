#!/usr/bin/env python3
"""Print a subnet's metagraph (uid / stake / incentive / emission / vtrust /
serving) using the project's bittensor SDK -- a btcli-free way to read on-chain
scores when btcli and the chain runtime are version-skewed.

    python scripts/show_metagraph.py [netuid] [network]
    python scripts/show_metagraph.py 501 test
"""

import sys

import bittensor as bt


def main() -> int:
    netuid = int(sys.argv[1]) if len(sys.argv) > 1 else 501
    network = sys.argv[2] if len(sys.argv) > 2 else "test"

    sub = bt.Subtensor(network=network)
    mg = sub.metagraph(netuid=netuid)

    print(f"netuid={netuid} network={network} n={int(mg.n)} block={int(mg.block)}")
    print(f"{'uid':>4} {'stake':>11} {'incentive':>10} {'emission':>13} "
          f"{'vtrust':>8} {'serve':>5}  hotkey")
    for uid in range(int(mg.n)):
        st = float(mg.stake[uid])
        inc = float(mg.incentive[uid])
        em = float(mg.emission[uid])
        vt = float(mg.validator_trust[uid])
        serving = bool(mg.axons[uid].is_serving)
        # only rows that matter: anything live or with any value, plus the
        # burn uid (25) and our known uids of interest.
        if serving or inc > 0 or em > 0 or st > 0 or uid in (3, 12, 25):
            print(f"{uid:>4} {st:>11.4f} {inc:>10.5f} {em:>13.9f} "
                  f"{vt:>8.4f} {str(serving):>5}  {mg.hotkeys[uid][:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

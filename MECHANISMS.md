# Subnet mechanisms

MASXAI runs two independent incentive tracks on one netuid, as two Bittensor
**mechanisms** (also called sub-subnets).

| mechid | Track | Validator | Miner |
|---|---|---|---|
| 0 | LLM-key contribution | `neurons/validator.py` | `neurons/miner.py` |
| 1 | Security-audit agents | `neurons/security_validator.py` | `neurons/security_miner.py` |

The ids live in `masxai/constants.py` (`LLM_KEY_MECHID`, `SECURITY_MECHID`).
Each neuron class pins its own mechid. It is not a CLI flag, so a validator
cannot put one track's scores on the other track's matrix.

## How mechanisms work

**Shared across the subnet:**

- Registration and UIDs. There is no per-mechanism registration. A hotkey's UID
  exists on every mechanism.
- Stake and validator permits.
- The axon endpoint. A hotkey advertises one IP and port for the whole subnet.

**Separate per mechanism:**

- The weight matrix. A validator sets a separate weight vector for each mechid.
- Yuma consensus, bonds, incentive and dividends, computed per mechanism.
- `LastUpdate` and the weights rate limit. The chain keys these by the storage
  index `mechid * 4096 + netuid`.
- Emission. The subnet's miner emission is divided between mechanisms by the
  owner-set split. It is even when no split is set.

**What that means here:**

- One staked validator hotkey runs both validators. The two processes cannot
  overwrite each other, because each writes only its own mechanism.
- The two miners use two hotkeys, because one hotkey has only one axon.
- A miner earns only where a validator weights it. An LLM-key miner gets 0 on
  mechanism 1, and a security miner gets 0 on mechanism 0.
- Each validator still queries every serving UID. Miners from the other track
  do not serve that synapse, so they time out and are skipped.

## Setup (subnet owner, once)

A new subnet has one mechanism. Mechanism 1 must be created before the security
validator's weights are accepted. The security validator logs an error at
startup until it exists.

```bash
# read only: shows current count/split and what would change
python scripts/setup_mechanisms.py --wallet.name <owner-coldkey> --split 50,50

# send it, signed by the owner coldkey
python scripts/setup_mechanisms.py --wallet.name <owner-coldkey> --split 50,50 --apply
```

Pick the split you want, for example `70,30`. Omit `--split` to keep an even
split.

## Run

```bash
# mechanism 0
python neurons/validator.py          --netuid 501 --wallet.name <ck> --wallet.hotkey <validator-hk>
python neurons/miner.py              --netuid 501 --wallet.name <ck> --wallet.hotkey <miner-hk-A>

# mechanism 1 (same validator hotkey; a different miner hotkey)
python neurons/security_validator.py --netuid 501 --wallet.name <ck> --wallet.hotkey <validator-hk>
python neurons/security_miner.py     --netuid 501 --wallet.name <ck> --wallet.hotkey <miner-hk-B>
```

Inspect one mechanism:

```bash
python scripts/show_metagraph.py 501 test 0
python scripts/show_metagraph.py 501 test 1
```

## Implementation notes

The template base classes carry the mechanism:

- `BaseNeuron.mechid` builds the metagraph for that mechanism.
- `BaseValidatorNeuron._submit_weights()` sends weights to that mechanism.
- `BaseNeuron._last_weight_update_block()` paces weight sets on that
  mechanism's own `LastUpdate` row.

Mechanism 1 has local state and log directories with a `_mech1` suffix, so it
never shares `state.npz` with mechanism 0. Mechanism 0's directory is unchanged.

Bittensor 10.5 has three quirks this code works around:

- **Metagraph fields.** `Metagraph.last_update`, `incentive` and
  `validator_trust` come from `neurons_lite(netuid)`, which is always mechanism
  0. Per-mechanism values come from `get_metagraph_info(netuid, mechid)` or from
  the storage query.
- **Rate-limit pre-check.** `Subtensor.set_weights` checks the rate limit
  against mechanism 0's `LastUpdate`. Mechanism 0 still uses that call.
  Mechanism 1 calls the weight extrinsic directly, and the chain still enforces
  the real per-mechanism limit.
- **Owner calls.** `sudo_set_mechanism_*_extrinsic` wraps its call in the root
  `Sudo` pallet. The setup script sends the owner's `AdminUtils` call unwrapped
  instead.

The burn allocation uses the same `BURN_UID` and `BURN_PERCENTAGE` on both
mechanisms. It applies inside each mechanism's own weight vector.

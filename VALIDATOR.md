# MASXAI — Validator Guide

## What the validator does

Every `forward()` tick (`neurons/validator.py`):

1. If `MASXAI_LLM_KEY_VALIDATOR_TOKEN` is set, run `llm_key_submission_round()`:
   fetch the protocol's current public key + allowed-model list, ask every
   eligible miner for its contributed key via `LLMKeySynapse`, relay accepted
   submissions to the protocol backend, and record liveness participation for
   every miner that answered (whether or not it had a key) — for
   observability only, not for weight.
2. Run `llm_key_report_poll_round()`: pull usage/efficiency reports since the
   last cursor into the collecting epoch's accumulator, and recompute
   `self.scores` from the last completed epoch.
3. Persist state (`save_masxai_state()`).
4. On the base template's own weight-setting cadence, `set_weights()` submits
   `self.scores` (see below), wrapped by the template's burn allocation.

**Each epoch's emission pays for the previous epoch's reports.** Reports are
collected per chain epoch. When the chain starts a new epoch (read from
`blocks_since_last_step`, not computed from tempo), the epoch that just ended
is closed and `self.scores` is recomputed from it alone; every weight set
during the new epoch pays for that one complete epoch. Nothing carries over:
a miner with no good report in the last epoch earns nothing in this one. If
the validator was down across more than one epoch, the stale accumulator is
discarded rather than paid.

If `MASXAI_LLM_KEY_VALIDATOR_TOKEN` is unset, steps 1–2 never run — `self.scores`
stays at zero for everyone, so the template's burn allocation (see below)
reserves effectively all of emission for `BURN_UID` until the pipeline is
configured. This still satisfies "never go silent": the validator submits a
valid weight vector every epoch, it just has no miner to reward yet.

## Weight-setting

`Validator._blended_weight_array()` returns a nan-safe copy of `self.scores`
directly — nothing else feeds into it. A miner earns weight **only** while the
protocol has reported real, verified usage in the last completed epoch for a key it
currently considers active. Answering the ask, or having a key that's been submitted but not yet
confirmed working, earns nothing — key validity isn't something the
validator can judge on its own, so it never extends weight on the strength
of a submission alone. `participation_scores` is tracked (see step 1 above)
but deliberately excluded from this.

`self.scores` is the last completed epoch's LLM-key efficiency.
`set_weights()` first brings it up to date (close the epoch if the chain has
moved on, then recompute), then swaps in the nan-safe copy only for the
duration of the on-chain submission call.

**Then burn takes most of it anyway.** Whatever `_blended_weight_array()`
returns is wrapped by the template's own burn allocation
(`template/base/validator.py::_apply_burn_allocation`, driven by
`masxai/constants.py`'s `BURN_UID`/`BURN_PERCENTAGE`), which reserves
`BURN_PERCENTAGE` (default 95%) for `BURN_UID` unconditionally — regardless
of how much real, positive efficiency data exists. Only the remaining share
is split among miners with a positive `self.scores` entry, proportional to
their score.

## Security posture

- The validator never sees a miner's plaintext key. It relays
  `protocol_pubkey_b64`/`allowed_models` outbound (fetched fresh from the
  protocol each round) and relays `encrypted_key_blob` inbound, unmodified,
  to the protocol's `/llm-keys/submit`.
- The validator is the only component in the subnet that talks HTTP to the
  protocol backend. Miners never call it, and it never calls into miners
  beyond the standard axon/dendrite exchange.
- A key the protocol backend later marks inactive (exhausted/invalid/revoked)
  scores `0.0` on the next report — no special-case removal logic needed on
  the validator side.

## Environment

| Var | Purpose |
|---|---|
| `MASXAI_LLM_KEY_BASE_URL` | Protocol backend base URL |
| `MASXAI_LLM_KEY_VALIDATOR_TOKEN` | Validator credential for `/llm-keys/*`; unset disables the pipeline |
| `MASXAI_LLM_KEY_SUBMISSION_INTERVAL_SECONDS` | Re-ask cadence (default 4h) |
| `MASXAI_LLM_KEY_REPORT_POLL_INTERVAL_SECONDS` | Report poll cadence (default 10m) |
| `MASXAI_PARTICIPATION_EMA_ALPHA` | Participation EMA smoothing (default 0.2; observability only) |
| `MASXAI_VALIDATOR_STATE_FILE` | Override the state-file path |

## Run

```bash
python neurons/validator.py --netuid 501 --subtensor.network test \
  --wallet.name <wallet> --wallet.hotkey <hotkey>
```

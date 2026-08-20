# CLAUDE.md - MASXAI Subnet

## Goal

A Bittensor subnet where miners contribute LLM API keys as a resource for an
external protocol backend to use operationally. Validators relay key
submissions to the protocol, poll for usage/efficiency reports, and set
on-chain weights from how reliable and fast each miner's contributed key is.

## Current Implementation

1. Miner opts in locally (`MASXAI_LLM_KEY_CONTRIB_*` env vars) with an LLM
   API key for an allowed provider/model.
2. Validator periodically asks every miner for its key via `LLMKeySynapse`
   (`masxai/protocol.py`).
3. Miner encrypts the raw key client-side (`masxai/llm_key_crypto.py`, NaCl
   SealedBox) for the protocol backend's published public key. The validator
   never sees the plaintext — it relays only an opaque ciphertext blob.
4. Validator forwards accepted submissions to the protocol backend
   (`masxai/llm_key_client.py`), which decrypts, validates the key actually
   works, and stores it (encrypted at rest, separately from transport).
5. Validator polls the protocol for usage/efficiency reports and folds them
   into `self.scores` (an EMA), and sets weights via the template validator
   machinery.

There is no other subnet function. Forecasting, the BT-Forecast integration,
and the local price/oracle path have all been removed — this subnet does not
issue prediction questions of any kind.

## Miner Rules

- LLM-key contribution is opt-in and off by default
  (`MASXAI_LLM_KEY_CONTRIB_ENABLED=false`).
- Contributed-key env vars (`MASXAI_LLM_KEY_CONTRIB_PROVIDER/_MODEL/_API_KEY`)
  are the only credential the miner ever relays — nothing else about the
  miner's own infrastructure is ever sent.
- A miner never talks to the protocol backend directly and never sees its own
  key leave in plaintext.
- `blacklist()` always requires a validator permit, unconditionally — this
  synapse triggers a state-changing action (a key submission relayed onward
  to the protocol), so it doesn't inherit a permissive default.

## Validator Rules

- Never see or persist a miner's plaintext key — the validator is a pure
  relay of ciphertext it cannot decrypt.
- Never compute or dictate the LLM-key efficiency signal itself — the
  protocol backend supplies raw usage stats (success/failure counts,
  latency); `masxai/scoring.py::llm_key_efficiency_score()` is the only place
  that formula lives.
- Persist state (`participation_scores`, `llm_key_hotkey_status`, `self.scores`)
  so restarts do not lose in-flight tracking.
- Submit weights every eligible epoch, never skipping the chain call — going
  silent makes Yuma consensus treat the validator as inactive (`vtrust`
  collapses). See "Weight Setting" below.

## Weight Setting

Weight is earned only through confirmed LLM-key efficiency — computed in
`Validator._blended_weight_array()` (`neurons/validator.py`), which is just
`self.scores` (nan-safe): an EMA driven by `llm_key_efficiency_score()` from
the protocol's usage reports. `self.scores[uid]` stays `0.0` until the
protocol has reported real, verified usage for a key it currently considers
active — a miner earns nothing merely by answering the ask, and nothing for
a key that's been submitted but not yet confirmed working. Key validity
isn't something the validator can judge on its own, so it never extends
weight on the strength of a submission alone.

- **Participation** — a liveness-only EMA (`participation_scores`,
  `PARTICIPATION_EMA_ALPHA`) bumped whenever a miner answers the LLM-key ask
  at all. Tracked for observability only; it never feeds into submitted
  weight.
- **LLM-key efficiency** — `self.scores`, the sole driver of weight.

On top of that, the template's own burn allocation
(`template/base/validator.py::_apply_burn_allocation`, wired to
`masxai/constants.py`'s `BURN_UID`/`BURN_PERCENTAGE`) unconditionally
reserves `BURN_PERCENTAGE` (default 95%) of emission for `BURN_UID`, before
anything reaches miners — regardless of how much real efficiency data
exists. The remaining share is split among miners with a positive
`self.scores` entry, proportional to their score. `self.scores` itself is
never overwritten by `set_weights()`'s blend — only the array submitted
on-chain is.

## Scoring

Output quality can't be fairly judged — the protocol controls every prompt,
and the models are third-party, so two miners running the same model would
score identically on output regardless of effort. Instead this rewards only
what a miner actually controls:

```text
composite = 0.5 * reliability (success rate)
          + 0.25 * latency_score (clamped against a ceiling)
          + 0.25 * volume_score (real call volume, capped at a target)
llm_key_efficiency_score = composite * model_tier_weight
```

`model_tier_weight` (`masxai/constants.py::LLM_KEY_MODEL_TIER_WEIGHTS`) is
looked up locally from `llm_key_hotkey_status` (captured at submission time,
no protocol round-trip needed) and scales the whole composite — a top-tier
model that's unreliable still scores low, and a budget model that's
perfectly reliable still scores respectably, just capped below what a
top-tier model can reach.

A key the protocol marks inactive (exhausted/invalid/revoked) scores `0.0`
unconditionally, regardless of tier. Below the minimum call volume for a
window, the window is skipped (`None`) rather than penalized — a quiet key
isn't a bad key.

## Before Changing Protocol

`masxai/protocol.py` is the wire contract (`LLMKeySynapse`). Any field change
can break running miners, so bump `SYNAPSE_VERSION` and update miner and
validator together.

## Useful Commands

```bash
source .venv/bin/activate
python scripts/patch_btcli_compat.py
python -m pytest tests/ -v
```

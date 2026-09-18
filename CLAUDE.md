# CLAUDE.md - MASXAI Subnet

## Goal

A Bittensor subnet where miners contribute LLM API keys as a resource for an
external protocol backend to use operationally. Validators relay key
submissions to the protocol, poll for usage/efficiency reports, and set
on-chain weights from how reliable and fast each miner's contributed key is.

## Current Implementation

1. Miner opts in locally with between `LLM_KEY_MIN_KEYS_PER_HOTKEY` and
   `LLM_KEY_MAX_KEYS_PER_HOTKEY` (both 5, so exactly 5) distinct LLM API
   keys for allowed provider/models — `MASXAI_LLM_KEYS_JSON` (a JSON array;
   list order = slot order). A submission below the minimum is declined
   entirely (miner never answers `has_key=True`; validator never relays a
   sanitized batch below the minimum either) rather than sent as a partial
   batch — same "decline rather than hedge" principle applied elsewhere in
   this project. The legacy single-key `MASXAI_LLM_KEY_CONTRIB_*` triple
   (slot 0 only) can never alone satisfy a minimum greater than 1, so it is
   only useful today as one entry among several `MASXAI_LLM_KEYS_JSON`
   keys. Duplicates of the same provider/model across slots are allowed
   (capacity stacking); the same physical key twice is not — enforced only
   at the protocol backend (SHA-256 fingerprint after decryption), since
   NaCl SealedBox encryption is deliberately non-deterministic and neither
   the miner's ciphertext nor the validator (which never decrypts) can ever
   compare two submissions to detect a repeated physical key. The subnet
   side (miner.py) only does a courtesy plaintext dedup before encrypting,
   to avoid wasting a round on a submission guaranteed to come back
   partially rejected.
2. Validator periodically asks every miner for its keys via `LLMKeySynapse`
   (`masxai/protocol.py`, one `keys[]` batch per miner).
3. Miner encrypts the raw key client-side (`masxai/llm_key_crypto.py`, NaCl
   SealedBox) for the protocol backend's published public key. The validator
   never sees the plaintext — it relays only an opaque ciphertext blob.
4. Validator forwards accepted submissions to the protocol backend
   (`masxai/llm_key_client.py`), which decrypts, validates the key actually
   works, and stores it (encrypted at rest, separately from transport).
5. Validator polls the protocol for usage/efficiency reports, collects
   them per hotkey per chain epoch (the protocol reports one row per single
   call, not a pre-aggregated window — see "Weight Setting"), and when an
   epoch ends scores it into `self.scores`, which every weight set during the
   next epoch pays out via the template validator machinery.

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
- A submission must contain at least `LLM_KEY_MIN_KEYS_PER_HOTKEY` (5)
  distinct physical keys or the miner declines the round entirely (never a
  partial batch); the protocol backend enforces the same minimum
  (`llm_key_min_keys_per_hotkey`) as a 422 on the `keys[]` batch shape, the
  authoritative boundary since only it ever sees plaintext to fingerprint.
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
- Persist state (`participation_scores`, `llm_key_hotkey_status`,
  `llm_key_pending_calls`, `llm_key_last_epoch_calls`,
  `llm_key_epoch_start_block`, `self.scores`) so a restart within an epoch
  loses neither the epoch being collected nor the epoch being paid.
- Pay only scores this pipeline produced. A `self.scores` entry is earnings
  only if an LLM-key usage report put it there (the pre-LLM-key forecasting
  subnet persisted its accuracy EMA under the same `"scores"` key of the same
  file; a uid can also change hands while the validator is down).
  `_has_llm_key_evidence()` requires a `llm_key_hotkey_status` entry for the
  hotkey *currently* at that uid, with `last_report_at` set and at least one
  key not locally killed. Unbacked scores are dropped at load
  (`_drop_unbacked_scores()`) and withheld from every submitted weight array.
  It is not a recency check — recency is the per-epoch reset's job.
- Submit weights every eligible epoch, never skipping the chain call — going
  silent makes Yuma consensus treat the validator as inactive (`vtrust`
  collapses). See "Weight Setting" below.
- A miner holds exactly 5 key slots (min and max both 5); a submission for a
  slot replaces that slot's key. The replacement is rejected (`reason="existing_key_in_use"`)
  only while that slot's current key is checked out by an agent
  (`locked_until` in the future) — other slots are unaffected — so a swap
  can never yank a key out from under an in-flight call. Once accepted, a
  replacement gets a clean cooldown/lock state (never inherited from the
  key it replaced) and keeps the slot's stable backend `key_id`.
- A confirmed-bad KEY stops earning **immediately**, never gradually — but
  surgically (`Validator._kill_hotkey_key()`): a report row with
  `key_active=false`, a per-key `DEAD`/`REVOKED` roster entry
  (`Validator._poll_llm_key_roster()`), a fatal auth/billing
  `error_categories` entry (`LLM_KEY_FATAL_ERROR_CATEGORIES` — conclusive
  on a single row, and the validator's own fast path since the protocol's
  health check can lag or be disabled while a 401-ing key stays `ACTIVE`),
  or a per-key sub-window that trips a hard floor, drops exactly that key's
  rows from both the epoch being paid and the epoch being collected
  (idempotent across roster re-polls), so the hotkey is re-scored on its
  healthy sibling keys from the next recompute. A hotkey whose every key is
  dead has nothing left to score. A killed key that serves successful calls
  again (the miner swapped in a working replacement, same slot/key_id) is
  revived by that fresh evidence.

## Weight Setting

Weight is earned only through confirmed LLM-key efficiency — computed in
`Validator._blended_weight_array()` (`neurons/validator.py`), which is
`self.scores` (nan-safe), minus any uid whose score has no reported LLM-key
usage behind it (`Validator._has_llm_key_evidence()`): the
`llm_key_efficiency_score()` of the last completed chain epoch's usage
reports. A miner earns nothing merely by answering the ask, and nothing for
a key that's been submitted but not yet confirmed working. Key validity
isn't something the validator can judge on its own, so it never extends
weight on the strength of a submission alone.

**Emission in each chain epoch pays for the reports of the epoch before
it.** The protocol reports one row per single call, not a pre-aggregated
window. `Validator.llm_key_pending_calls` (persisted) collects the rows
received in the current chain epoch, per hotkey and per key —
success/failure counts and weighted latency/quality sums. The epoch start is
read from the chain (`block − blocks_since_last_step`, read at one block),
never computed from tempo. When the chain starts a new epoch
(`Validator._roll_epoch_if_needed()`, checked at every report poll and every
weight set), that accumulator closes into `llm_key_last_epoch_calls` and
`self.scores` is recomputed from it alone (`_score_last_epoch()`) — so every
weight set during an epoch pays for exactly one complete epoch, and nothing
carries over: a miner with no good report in the last epoch earns nothing in
this one. Scoring the still-running epoch instead would miss the calls made
after the last weight set before each boundary, since only the weights on
chain when an epoch ends count. The closed accumulator is paid only if it
really is the immediately preceding epoch: a validator down across more than
one epoch, or state that predates per-epoch scoring, discards it. An epoch
shorter than half a tempo (e.g. owner-triggered early) is folded into the
next one rather than replacing the epoch being paid.

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
on-chain is. If no miner has a positive score, the whole allocation burns.

## Scoring

Raw model capability still can't be fairly judged — the protocol controls
every prompt, and the models are third-party, so two miners running the
identical model would score identically on that axis regardless of effort.
`quality_score`, below, is not that: it's a per-call, self-graded signal
from the calling agent (e.g. Chain-Agent's groundedness/fabrication check)
about whether *that specific reply* was genuinely grounded in real evidence
vs. hedged or fabricated — a property of how the call went, not of the
underlying model's general ability.

```text
if reliability < 0.5 (strict):            score = 0.0   # key isn't working
if measured quality < 0.35 (>=3 graded):  score = 0.0   # confirmed bad output
composite = 0.4 * reliability (success rate)
          + 0.2 * quality (self-graded groundedness, neutral 0.5 if unmeasured)
          + 0.2 * latency_score (clamped against a ceiling)
          + 0.2 * volume_score (successful calls only, capped at a target)
llm_key_efficiency_score = composite * model_tier_weight
```

The two hard floors exist because the additive composite would otherwise
let a key that isn't working keep collecting the neutral-default
quality/latency terms plus volume credit (an all-failure window used to
earn ~0.4). A floored epoch window earns nothing for that epoch. The
quality floor needs `LLM_KEY_QUALITY_FLOOR_MIN_GRADED`
graded calls in the window before it can gate (one self-graded bad reply
scales the quality axis instead of zeroing the key), and unmeasured
quality (`None` → neutral 0.5) never trips it. Volume counts only
successes — a failed call is not delivered capacity. On a multi-key
hotkey the same floors are also applied to each key's own sub-window
before pooling (`_sub_window_floor_reason()`): a single junk key with
enough evidence (`LLM_KEY_MIN_CALLS_FOR_SCORING` calls on its own) is killed
and excluded rather than hiding inside the fleet's average, so the pooled
floors only trip when the fleet as a whole is failing.

`model_tier_weight` (`masxai/constants.py::LLM_KEY_MODEL_TIER_WEIGHTS`) is
a **per-call blend**: each usage row carries the provider/model of the key
that served it (verified by the backend's preflight at submission), each
call is worth its own model's tier, and the window's multiplier is the
traffic-weighted average (`_pooled_window_reward()`), so a mixed 5-key fleet
blends correctly and stacked cheap keys can never borrow a top-tier
multiplier. It scales the whole composite — a top-tier model that's
unreliable still scores low, and a budget model that's perfectly reliable
still scores respectably, just capped below what a top-tier model can
reach. A multi-key hotkey is scored as ONE pooled window across all its
live keys' calls in the epoch (per-key sub-accumulators, pooled at
scoring) — more working keys earn more only through more delivered
traffic (each key has its own 200-call/day budget on the backend), never
through key count itself.

A key the protocol marks inactive (exhausted/invalid/revoked) scores `0.0`
unconditionally, regardless of tier. The pooled epoch window has no
call-volume floor (`EPOCH_MIN_CALLS_FOR_SCORING` is 1): any good report in
the epoch earns. `avg_latency_s`/`quality_score`/`model_tier_weight` are all
independently NaN/inf-guarded (`masxai/scoring.py::sanitize_latency_ms()`/
`sanitize_quality_score()`) — a malformed reading in one never disqualifies
the others, and never poisons `self.scores` with a NaN.

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

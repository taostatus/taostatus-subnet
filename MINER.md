# MASXAI — Miner Guide

## What the miner does

The miner answers exactly one synapse type, `LLMKeySynapse`
(`neurons/miner.py`):

- If not opted in, or the request is missing a usable protocol public key, or
  the miner's configured `provider/model` isn't in this round's
  `allowed_models`: respond `has_key=False` and stop. A miner is never forced
  to answer.
- Otherwise: encrypt the configured API key client-side
  (`masxai/llm_key_crypto.py`, NaCl SealedBox) for the protocol's published
  public key, and return the ciphertext plus plaintext `provider`/`model`
  labels (not sensitive) in the response.

The miner never talks to the protocol backend directly, never decrypts
anything, and never holds a keypair of its own beyond its Bittensor hotkey.

## Configuration

```
MASXAI_LLM_KEY_CONTRIB_ENABLED=true
MASXAI_LLM_KEY_CONTRIB_PROVIDER=openai
MASXAI_LLM_KEY_CONTRIB_MODEL=gpt-4o-mini
MASXAI_LLM_KEY_CONTRIB_API_KEY=sk-...
```

All four must be set for the miner to ever contribute a key. Leaving
`MASXAI_LLM_KEY_CONTRIB_ENABLED` unset/false runs a miner that always
declines cleanly — useful for testing connectivity without exposing a real
key.

This credential is intentionally separate from any other API key you might
use for unrelated purposes — nothing else this miner does relays any
credential anywhere.

## Security

- `blacklist()` always requires a validator permit, unconditionally — every
  accepted `LLMKeySynapse` response triggers a state-changing action (a key
  submission relayed onward to the protocol backend by the validator), so
  this synapse doesn't inherit a permissive default the way a read-only query
  might.
- The provider/model allow-list for a given round comes from the validator's
  request (relayed from the protocol backend) — a miner configured for a
  disallowed provider/model self-declines rather than wasting a submission
  the protocol would reject anyway.

## How to be a strong contributor

Reward can't be based on "smarter answers" — BT Arena controls every prompt
sent through a contributed key, and the models themselves are third-party, so
two miners running the same model would produce identical output regardless
of effort. Instead, `masxai/scoring.py::llm_key_efficiency_score()` rewards
what a miner actually controls:

- **Model tier** (`masxai/constants.py::LLM_KEY_MODEL_TIER_WEIGHTS`) —
  configure the highest-capability model you can sustainably afford within
  the allowed list. A top-tier model is a real, costly choice, and scores
  meaningfully higher than a budget one at identical reliability.
- **Real, sustained volume** — a key that serves many real calls scores
  higher than one that barely gets used, up to a target ceiling. Favor a
  higher rate-limit tier from your provider if you can; it directly raises
  how much volume the protocol can draw from you.
- **Reliability and speed** — keep the underlying provider account
  well-funded and comfortably under its own rate limits. A key that fails
  mid-week from a billing lapse hurts more than one that's merely average but
  steady.
- **Consistency over time** — reward is an EMA, so sustained performance
  across many rounds matters more than one good window. Refresh a key
  proactively before it's about to expire or hit a billing-cycle cap, rather
  than waiting for it to be marked dead.
- **A dedicated credential** — use a key that isn't competing with your own
  unrelated usage for the same rate limit.

## Run

```bash
python neurons/miner.py --netuid 501 --subtensor.network test \
  --wallet.name <wallet> --wallet.hotkey <hotkey>
```

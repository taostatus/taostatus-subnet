# MASXAI Subnet

**Netuid:** 501 (testnet) · **Network:** Bittensor

MASXAI is a Bittensor subnet that sources real, working LLM API access from
its miners and makes it available to an external protocol (the BT Arena
Protocol) for its own AI agent pipeline. Miners are rewarded for the
reliability, speed, capability tier, sustained successful volume, and
per-call output groundedness (self-graded by the calling agent — a property
of how each call went, not a judgment of the underlying model's general
ability, which stays unmeasurable since the protocol controls every prompt
and the models are third-party) of the access they contribute. A key that
stops working, or keeps producing fabricated/ungrounded output, stops
earning immediately.

## Table of contents

- [Introduction](#introduction)
- [Roles](#roles)
- [Protocol Boundary](#protocol-boundary)
- [Incentive Mechanism](#incentive-mechanism)
- [Security Model](#security-model)
- [Installation](#installation)
- [Running a Miner](#running-a-miner)
- [Running a Validator](#running-a-validator)
- [Testing](#testing)
- [Repository Structure](#repository-structure)
- [License](#license)

For the full end-to-end walkthrough — how the miner, validator, protocol
backend, and agents fit together, the exact scoring formula, how weight
reaches the chain, and a fully worked simulated example with real numbers —
see [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md). Every environment
variable across all four components, with example values and what each one
does in plain language, is in
[docs/ENV_REFERENCE.md](docs/ENV_REFERENCE.md).

## Introduction

AI agent pipelines need language model access, and language model access
costs real money per call. Rather than one operator paying for all of it
centrally, this subnet lets a decentralized network of miners supply that
access, and pays them according to Bittensor's standard incentive model:
weights set by a validator, emission split by Yuma Consensus, most of it
reserved by a fixed burn.

The subnet does not ask miners to predict, forecast, or generate content of
any kind. A miner's entire job is to keep one working LLM credential
available and answer honestly when asked whether they have one to share.

## Roles

**Miner** (`neurons/miner.py`) — configures an LLM API key for an allowed
provider/model and opts in. Answers a single synapse type (`LLMKeySynapse`):
encrypts the key client-side and returns it, or declines cleanly if not
opted in or the request doesn't match an allowed model. Never contacts the
protocol backend directly.

**Validator** (`neurons/validator.py`) — the sole bridge between the chain
and the protocol. On a fixed interval, asks every eligible miner for a key,
relays accepted submissions to the protocol unmodified (it cannot decrypt
them), and separately polls the protocol for usage reports. Turns those
reports into an on-chain weight via `masxai/scoring.py`, and submits weights
every eligible epoch regardless of how much data currently exists —
Bittensor's Yuma Consensus penalizes a validator that goes silent, so the
validator always has *something* valid to submit, even before any miner has
proven a working key.

**Protocol (BT Arena)** — an external service, not part of this repository
(`BT-Arena_next_phase/backend` in this workspace). Publishes the encryption keypair and
the allowed provider/model list, validates and stores submitted keys, draws
on them operationally, and reports raw usage statistics back to the
validator. Never sees the chain and never dictates a reward — see
[Protocol Boundary](#protocol-boundary).

## Protocol Boundary

The subnet and the protocol are two independent systems connected by exactly
one channel: the validator's HTTP calls to the protocol's `/llm-keys/*` API.

| The protocol may | The protocol may never |
|---|---|
| Supply topics/allowed-model lists | Dictate the weight-setting formula |
| Supply raw usage reports (success/failure counts, latency) | Compute or influence a miner's score directly |
| Mark a key inactive | Reach a miner directly — only the validator relays |
| Reject a submission (bad model, failed validation) | See chain state or metagraph data |

This split means a compromised or misbehaving protocol backend can, at
worst, feed bad topics or bad usage data — which fail-closed handling and
scoring gates already contain — but it can never touch a chain-level trust
boundary.

## Incentive Mechanism

### What is measured, and why

Reward cannot be based on how *good* an AI's answer is: the protocol writes
every prompt sent through a contributed key, and the models themselves are
third-party (OpenAI's, Anthropic's, etc.), so two miners running the
identical model would produce statistically identical output regardless of
effort. Scoring output would really be scoring the model vendor and the
protocol's own prompting — not the miner.

Instead, `masxai/scoring.py::llm_key_efficiency_score()` measures only what a
miner genuinely controls:

```text
composite = 0.5 · reliability          (success rate over a report window)
          + 0.25 · latency_score       (response speed, clamped against a ceiling)
          + 0.25 · volume_score        (real call volume, capped at a target)

score = composite × model_tier_weight  (which model the miner configured)
```

- A key the protocol marks inactive (revoked, exhausted, invalid) scores
  `0.0` unconditionally, regardless of tier.
- Below a minimum call count in a report window, the window is skipped
  entirely rather than penalized — a quiet key is not treated as a bad key.
- `score` is folded into a per-miner exponential moving average
  (`self.scores[uid]`), so a single bad or single lucky window has limited
  effect; sustained performance is what actually accumulates.

**Answering the validator's periodic check-in earns nothing on its own.**
Weight comes exclusively from `self.scores` — a value that stays at `0.0`
until the protocol has reported real, verified usage. A liveness-only
`participation_scores` EMA is tracked separately for observability, but is
never blended into submitted weight.

### Burn

On top of the above, this subnet reserves the large majority of emission for
a fixed burn UID (`masxai/constants.py::BURN_UID = 25`,
`BURN_PERCENTAGE = 0.95`), applied by the vendored template's own
`_apply_burn_allocation()` (`template/base/validator.py`) before anything
reaches the chain. This is unconditional — it does not shrink as more real,
proven miner data accumulates. Only the remaining share is split among
miners with a positive score, proportional to it.

### Worked example

Three miners, a 100-unit reward pool for one epoch:

| Miner | Contribution | Reliability | Speed | Volume | Tier | Score |
|---|---|---|---|---|---|---|
| A | GPT-4o, well-used | 49/50 | fast | full | ×1.0 | ≈0.97 |
| B | DeepSeek, well-used | 50/50 | slow | full | ×0.5 | ≈0.43 |
| C | Declined this round | — | — | — | — | 0 |

1. **Burn takes 95 units first, unconditionally.** 5 units remain.
2. **The remaining 5 units split proportional to score:** A gets
   `0.97 / (0.97 + 0.43) ≈ 69%` (≈3.5 units), B gets `≈31%` (≈1.5 units), C
   gets nothing.

Notice B is *more reliable* than A (100% vs 98%) but still earns less
overall — a slower, lower-tier model is capped below what a fast, top-tier
one can reach, even at perfect reliability.

## Security Model

- **End-to-end key encryption.** A miner encrypts its raw key client-side
  (`masxai/llm_key_crypto.py`, NaCl `SealedBox`) for the protocol's published
  public key before it ever leaves the miner process. The validator relays
  only an opaque ciphertext blob and holds no private key to decrypt it —
  this is a structural guarantee, not a policy.
- **Two independent locks.** The protocol decrypts the transport ciphertext
  on arrival, then re-encrypts the key for storage using a completely
  separate at-rest key. A compromise of one does not expose the other.
- **Duplicate-key farming is rejected.** The same underlying key registered
  under a second hotkey is detected and refused — first registrant only.
- **Mandatory validator permit on the miner's blacklist.** Unlike a
  read-only query, an accepted `LLMKeySynapse` response triggers a
  state-changing action (a key submission relayed onward), so it is never
  answered without a validator permit.
- **Least-trust protocol boundary.** See [Protocol Boundary](#protocol-boundary).

## Installation

```bash
git clone <this repo>
cd masxai-subnet
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

See `min_compute.yml` for hardware requirements — this subnet is I/O-bound
(HTTP calls and lightweight encryption), not compute-bound; no GPU is
required for either role.

## Running a Miner

Set in `.env`:

```bash
MASXAI_LLM_KEY_CONTRIB_ENABLED=true
MASXAI_LLM_KEY_CONTRIB_PROVIDER=openai
MASXAI_LLM_KEY_CONTRIB_MODEL=gpt-4o-mini
MASXAI_LLM_KEY_CONTRIB_API_KEY=sk-...
```

Run:

```bash
python neurons/miner.py --netuid 501 --subtensor.network test \
  --wallet.name <wallet> --wallet.hotkey <hotkey>
```

Leaving `MASXAI_LLM_KEY_CONTRIB_ENABLED` unset/false runs a miner that
declines every ask cleanly (`has_key=False`) — useful for verifying
axon/blacklist/priority behavior without exposing a real key.

Full guide, including how to be a strong contributor: [MINER.md](MINER.md).

## Running a Validator

Set in `.env`:

```bash
MASXAI_LLM_KEY_BASE_URL=<protocol backend base URL>
MASXAI_LLM_KEY_VALIDATOR_TOKEN=<validator credential issued by the protocol>
```

Run:

```bash
python neurons/validator.py --netuid 501 --subtensor.network test \
  --wallet.name <wallet> --wallet.hotkey <hotkey>
```

Leaving `MASXAI_LLM_KEY_VALIDATOR_TOKEN` unset runs the validator with the
pipeline off: `self.scores` stays at zero for everyone, so burn effectively
reserves all of emission until the pipeline is configured — the validator
still submits a valid weight vector every epoch, satisfying Bittensor's
never-go-silent requirement.

Full guide: [VALIDATOR.md](VALIDATOR.md).

## Testing

```bash
python -m pytest tests/ -v
```

## Repository Structure

```
masxai/
  protocol.py          LLMKeySynapse -- the subnet's sole wire contract
  llm_key_crypto.py     miner-side transport encryption (encrypt only)
  llm_key_client.py     validator-side HTTP client to the protocol backend
  scoring.py             llm_key_efficiency_score() and the generic EMA helper
  constants.py            all tunables, env-var-overridable
neurons/
  miner.py                miner neuron entrypoint
  validator.py             validator neuron entrypoint
BT-Arena_next_phase/backend/  the protocol backend (separate service, this workspace only)
tests/                       pytest suite mirroring the modules above
```

## License

See [LICENSE](LICENSE).

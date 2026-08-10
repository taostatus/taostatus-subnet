# MASXAI V2 — Miner Update & Developer Guide

> **Release:** V2 | **Status:** Production | **Network:** Bittensor Finney (Mainnet) / Testnet 501

---

## Overview

The MASXAI Miner is an autonomous AI forecasting agent that operates on the Bittensor network. It receives binary prediction tasks from validators, runs an LLM inference pipeline over contextual market and network signals, and returns structured probabilistic responses. Miner rewards are proportional to real-world prediction accuracy, confidence calibration, response consistency, and submission speed — evaluated only after ground-truth outcomes are verified by the central BT-Forecast engine.

---

## What Changed in V2

| Area | V1 | V2 |
|---|---|---|
| Question Format | Local TAO price only | Multi-domain event taxonomy (6 event types) |
| LLM Integration | Basic inference | Full LLM reasoning pipeline with structured output |
| Response Schema | Prediction + confidence | Prediction + probability + confidence + reasoning + features |
| No-Answer Handling | Crash fallback | Structured no-answer payload; miner stays online |
| Blacklist Enforcement | None | Registered hotkey gate + optional validator permit enforcement |
| Priority Routing | None | Stake-weighted dendrite priority |
| Social Publishing | Optional | Discord webhook broadcast of prediction summaries |

---

## Miner Pipeline: End-to-End Flow

### Step 1 — Task Reception
The miner listens on its registered axon port for incoming `ForecastSynapse` queries from validators. Each query contains:
- **Event type** (e.g., `tao_price_movement`, `ecosystem_growth_metric`)
- **Reference values** (e.g., current TAO/USD price, subnet miner count)
- **Historical evidence summary** provided by the BT-Forecast engine
- **Measurement threshold and operator** (e.g., `{"threshold": 128, "operator": "below"}`)
- **Forecast window** and hard **cutoff timestamp** (`resolve_at`)

The miner extracts all contextual parameters to construct its inference prompt.

### Step 2 — LLM Reasoning & Inference
The miner feeds the full task context, reference data, and market signals into its LLM reasoning engine. The LLM evaluates:
- Price momentum and on-chain activity patterns
- Governance and subnet registration signals
- Historical ecosystem metrics
- Evidence summaries and trend indicators

The inference pipeline returns a structured prediction object. If the LLM is unavailable or times out, the miner falls back to a **structured no-answer payload** — a zero-credit response that keeps the miner online without manufacturing a fraudulent forecast.

### Step 3 — Response Construction
The miner populates the `ForecastSynapse` response with:

| Field | Type | Description |
|---|---|---|
| `prediction` | `bool` | Binary directional outcome (`true` / `false`) |
| `probability` | `float` [0.01–0.99] | Calibrated probability estimate for the event occurring |
| `confidence` | `float` [0.0–1.0] | Agent self-assessed certainty in its prediction |
| `reasoning` | `string` | Structured chain-of-thought rationale |
| `model` | `string` | LLM model identifier used for this inference |
| `features` | `dict` | Optional signal features used during inference |
| `timestamp` | `ISO-8601` | Submission timestamp |

If only `prediction` and `confidence` are provided (no explicit `probability`), the miner automatically derives:

```
probability = confidence        (if prediction is True)
probability = 1.0 - confidence  (if prediction is False)
```

### Step 4 — Submission & Discord Broadcast
Upon returning a valid response (non-null `probability`), the miner asynchronously publishes a formatted prediction summary to the configured Discord webhook. This broadcast includes the event type, probability estimate, prediction direction, and abbreviated reasoning — providing real-time community transparency without blocking the response path.

### Step 5 — Retry Handling
If a miner fails to respond before the validator's query timeout (20 seconds), the validator will retry the unanswered miner during subsequent rounds using exponential backoff. This means miners that come back online after a brief outage will automatically receive follow-up queries and have an opportunity to earn credit before the question cutoff.

---

## Scoring: How Miners Earn Rewards

Miner rewards are computed by the validator **after** each question's ground-truth outcome is verified. Scores are never based on engine predictions or peer responses.

| Component | Weight | What It Measures |
|---|---|---|
| **Accuracy (Brier Skill Score)** | 50% | Probability accuracy vs. neutral 0.5 baseline. Flat guesses earn zero. |
| **Confidence Calibration** | 20% | Correct high-confidence answers are rewarded; overconfident errors lose credit. |
| **Historical Consistency** | 20% | Score stability across epochs. Consistent performers are rewarded. |
| **Timeliness** | 10% | Faster responses within the forecast window score higher. |

Scores are applied via **Exponential Moving Average** (α = 0.10):

```
Score_new = 0.90 × Score_prev + 0.10 × Reward_composite
```

> **Key rule:** Probability estimates of exactly 0.5 (or no-answer responses) earn zero composite reward. Miners must take an informed position to earn.

---

## Blacklist & Priority

**Blacklist checks** run before every forward call:
- Any query without a registered validator hotkey is rejected.
- Optionally, queries without a validator permit are blocked when `MASXAI_REQUIRE_VALIDATOR_PERMIT=true`.

**Priority routing** uses stake-weighted ordering:
- Validators with higher TAO stake are served first during peak load, ensuring high-trust queries are processed promptly.

---

## Key Environment Variables (Miner)

| Variable | Default | Description |
|---|---|---|
| `GEMINI_API_KEY` | — | LLM API key. Without this, miner runs in no-answer baseline mode. |
| `GEMINI_ENABLED` | `true` | Enable or disable LLM inference. |
| `GEMINI_MODEL` | `gemini-2.5-flash` | LLM model to use for inference. |
| `GEMINI_TIMEOUT` | `8` | Seconds before LLM inference times out and falls back to no-answer. |
| `DISCORD_WEBHOOK_URL` | — | Optional. URL for Discord prediction broadcast. |
| `MASXAI_FORECAST_INTERVAL_SECONDS` | `300` | Validator query issuance cadence (controlled server-side). |
| `MASXAI_REQUIRE_VALIDATOR_PERMIT` | `false` | When true, rejects queries from non-permitted validators. |

---

## Running the Miner

### Prerequisites
- Python 3.10+
- Registered miner hotkey on Bittensor (Mainnet or Testnet 501)
- LLM API key configured in `.env`
- Open axon port reachable by validators

### Setup

```bash
git clone https://github.com/masxai/masxai-subnet
cd masxai-subnet
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python scripts/patch_btcli_compat.py
cp .env.example .env
# Set GEMINI_API_KEY, DISCORD_WEBHOOK_URL (optional), and wallet details in .env
```

### Execution (Mainnet)

```bash
python neurons/miner.py \
  --netuid <your_netuid> \
  --subtensor.network finney \
  --wallet.name <your_miner_wallet> \
  --wallet.hotkey default \
  --axon.port 8901 \
  --logging.debug
```

### Execution (Testnet 501)

```bash
scripts/run_testnet.sh miner --axon.port 8901
```

---

## Monitoring

The miner emits a heartbeat log every 30 seconds:

```
MASXAI miner alive | 2026-08-04 08:30:00
```

Each forecast response logs its outcome:

```
answered: event=tao_price_movement model=gemini-2.5-flash probability=0.78 prediction=True confidence=0.78
```

or, for a no-answer:

```
no-answer: event=tao_price_movement model=no-response probability=None prediction=None confidence=None
```

---

## Operating Notes

- **LLM connectivity:** If the miner logs `ConnectTimeout`, the LLM API is unreachable. Raise `GEMINI_TIMEOUT` or verify outbound connectivity to the LLM API endpoint.
- **No-answer mode:** Without an LLM API key, the miner runs in structured no-answer mode — it stays online and visible on the network but earns zero forecast credit until a key is configured.
- **Axon registration:** Ensure the miner's axon port is publicly reachable. Validators will not be able to query a miner whose axon is behind a closed firewall.
- **Hotkey continuity:** Changing the miner's hotkey after accumulating score history will result in score reset, as EMA state is indexed by `uid` and `hotkey` pairing on the validator side.

---

*For questions or integration support, contact the MASXAI core team.*

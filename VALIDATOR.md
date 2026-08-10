# MASXAI V2 — Validator Update & Developer Guide

> **Release:** V2 | **Status:** Production | **Network:** Bittensor Finney (Mainnet) / Testnet 501

---

## Overview

The MASXAI Validator is the backbone of the subnet's scoring and consensus layer. In V2, validators have been significantly upgraded to integrate with the centralized **BT-Forecast FastAPI engine**, enforce performance-gated weight emission, and maintain resilient state persistence across restarts. Validators do not generate forecasts — they **issue tasks, evaluate responses, and enforce quality via on-chain weights**.

---

## What Changed in V2

| Area | V1 | V2 |
|---|---|---|
| Question Source | Local oracle only (TAO price) | Centralized BT-Forecast API + Local fallback |
| Resolution | Immediate local oracle | Deferred ground-truth outcomes from `/v1/resolutions` |
| Scoring Model | Brier score only | 4-component composite scoring engine |
| Miner Retries | None | Exponential backoff retry loop up to question cutoff |
| State Persistence | In-memory only | Atomic JSON state file (`validator_state.json`) |
| Weight Gating | Immediate | Blended: interim participation weight until resolved evidence exists, then accuracy-dominant |
| Calibration Feedback | None | Structured feedback posted to `/v1/miner-results` |

---

## Validator Pipeline: End-to-End Flow

### Step 1 — Run Ingestion
The validator polls the BT-Forecast service for today's deterministic **Run ID** (format: `bt-YYYY-MM-DD`). If the run's `generation` field is not yet `complete`, the validator respects the API-specified `poll_after_s` interval and defers. This prevents redundant polling while the question engine is still generating.

### Step 2 — Question Fetching
Once the run is ready, the validator fetches miner-safe questions from `/v1/forecast-runs/{run_id}/questions`. These questions span the full event taxonomy but exclude all private benchmark fields that are reserved for the central scoring engine.

### Step 3 — Miner Querying via Dendrite
The validator queries registered miner axons across the Bittensor network using the `ForecastSynapse` protocol. Each query carries:
- The event type and binary question
- Reference values and contextual metadata
- An ISO-8601 `issued_at` timestamp and `resolve_at` cutoff

Miners that do not respond are tracked in the pending queue and retried with exponential backoff. Retry cadence begins at **5 minutes** and backs off up to **60 minutes** (`MASXAI_BT_FORECAST_NO_ANSWER_RETRY_MAX_SECONDS`). Retries continue until the question cutoff timestamp is reached.

### Step 4 — Pending State Persistence
Every active miner forecast is stored in `validator_state.json` under a deterministic key:

```
(run_id, question_key, uid)
```

This ensures that re-issued questions for the same question/miner pair update the existing record instead of creating duplicate unresolved rows. State is atomically written to prevent partial corruption across restarts.

### Step 5 — Deferred Resolution
At each epoch, the validator checks which pending forecasts have passed their `resolve_at` timestamp. For those due:
- Outcomes are fetched from `/v1/resolutions`
- Questions still `open` are deferred using a configurable retry schedule (`MASXAI_BT_FORECAST_RESOLUTION_RETRY_SECONDS`, default **15 minutes**)
- Questions with terminal unscored statuses (`expired`, `annulled`, `ambiguous`, `rejected`) are dropped without scoring

No miner is ever evaluated against engine predictions or internal benchmarks — only against verified objective outcomes.

### Step 6 — Composite Scoring
Each resolved forecast is evaluated against the 4-component scoring formula:

| Component | Weight | Description |
|---|---|---|
| **Brier Skill Score** | 50% | Accuracy vs. neutral 0.5 baseline. Sub-baseline forecasts earn zero. |
| **Confidence Calibration** | 20% | Correct high-confidence answers are rewarded; overconfident errors are penalized. |
| **Historical Consistency** | 20% | Prior EMA score used as a stability signal. |
| **Timeliness** | 10% | Faster responses within the forecast window earn higher credit. |

Scores are integrated into each miner's running score via **Exponential Moving Average** (α = 0.10):

```
Score_new = 0.90 × Score_prev + 0.10 × Reward_composite
```

### Step 7 — Calibration Feedback
After resolution, the validator assembles a structured miner results payload — containing miner UIDs, probability estimates, confidence metrics, timeliness, and the verified outcome — and posts it to `/v1/miner-results`. This feedback loop enables the central BT-Forecast engine to calibrate itself over time for improved question quality and resolution accuracy.

### Step 8 — Emission Weight Setting
The validator submits weights **every eligible epoch** — it never skips the
on-chain call, because going silent makes Yuma consensus treat the validator
as inactive (`vtrust` collapses to zero, cutting its own emission and its
contribution to miner emission). What gets submitted depends on how much
resolved evidence exists:

- **Before** the emission bar is met — at least `MASXAI_MIN_RESOLVED_BEFORE_WEIGHTS`
  (default: **3**) real ground-truth resolutions, at least one miner with a
  positive resolved EMA score, and the metagraph's `min_allowed_weights`
  satisfied — submitted weights are **interim participation only**: a
  liveness EMA (`MASXAI_PARTICIPATION_EMA_ALPHA`) that rewards miners for
  returning valid, well-formed forecasts, independent of whether those
  forecasts have resolved or been correct.
- **After** the bar is met, resolved accuracy dominates and interim
  participation is blended in at a small share (`MASXAI_PARTICIPATION_WEIGHT`,
  default **10%**).

No miner is ever scored for *correctness* without a verified objective
outcome — only the interim participation component is pre-resolution, and it
only measures liveness, never accuracy.

---

## Key Environment Variables (Validator)

| Variable | Default | Description |
|---|---|---|
| `BT_FORECAST_BEARER_TOKEN` | — | **Required.** API token for BT-Forecast service. |
| `MASXAI_MIN_RESOLVED_BEFORE_WEIGHTS` | `3` | Minimum resolved forecasts before accuracy dominates submitted weights (weights are still submitted before this, as interim participation). |
| `MASXAI_PARTICIPATION_WEIGHT` | `0.10` | Blended-weight share reserved for interim participation once accuracy scores exist. |
| `MASXAI_PARTICIPATION_EMA_ALPHA` | `0.2` | EMA smoothing for the interim participation (liveness) score. |
| `MASXAI_BT_FORECAST_NO_ANSWER_RETRY_SECONDS` | `300` | Initial retry interval for unanswered miners. |
| `MASXAI_BT_FORECAST_NO_ANSWER_RETRY_MAX_SECONDS` | `3600` | Maximum retry backoff ceiling. |
| `MASXAI_BT_FORECAST_RESOLUTION_RETRY_SECONDS` | `900` | Retry interval for open/unresolved questions. |
| `MASXAI_BT_FORECAST_RESOLUTION_WAIT_SECONDS` | `432000` | Maximum time to wait before dropping an unresolved question (5 days). |
| `MASXAI_VALIDATOR_STATE_FILE` | `validator_state.json` | Path override for the persistence state file. |

---

## Running the Validator

### Prerequisites
- Python 3.10+
- Registered validator hotkey on Bittensor (Mainnet or Testnet 501)
- `BT_FORECAST_BEARER_TOKEN` obtained from the MASXAI team

### Setup

```bash
git clone https://github.com/masxai/masxai-subnet
cd masxai-subnet
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python scripts/patch_btcli_compat.py
cp .env.example .env
# Fill in BT_FORECAST_BEARER_TOKEN and wallet details in .env
```

### Execution (Mainnet)

```bash
python neurons/validator.py \
  --netuid <your_netuid> \
  --subtensor.network finney \
  --wallet.name <your_validator_wallet> \
  --wallet.hotkey default \
  --logging.debug
```

### Execution (Testnet 501)

```bash
scripts/run_testnet.sh validator
```

---

## Monitoring

The validator emits a heartbeat log every 30 seconds:

```
MASXAI validator alive | pending=42 answered=35 no_answer=7 resolved=120 | 2026-08-04 08:30:00
```

Key fields:
- `pending` — Total active forecasts awaiting resolution.
- `answered` — Miners that returned a valid probability estimate.
- `no_answer` — Miners still pending or with no valid response.
- `resolved` — Total lifetime resolved and scored forecasts.

---

## State Recovery

On restart, the validator automatically reloads `validator_state.json` — restoring all pending forecasts, score arrays, and API run state. No manual intervention is required unless the state file is explicitly removed.

---

*For questions or integration support, contact the MASXAI core team.*

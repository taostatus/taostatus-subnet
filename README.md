# MasXAI Subnet MVP

MasXAI is a Bittensor forecasting subnet for Bittensor ecosystem events. Miners
run Gemini-backed forecasting agents, validators resolve objective ground truth,
score forecasts, and set miner weights from forecast quality.

The current implementation keeps the proven deferred-resolution loop from the
lightweight v1 code, then adds the MVP forecast schema, Gemini miner path, and
Discord publishing.

## MVP Forecasts

Supported event taxonomy:

- `tao_price_movement`
- `subnet_token_price`
- `new_subnet_registration`
- `governance_outcome`
- `ecosystem_growth_metric`
- `significant_bittensor_event`

The validator only issues event types listed in `masxai/constants.py` as
`ENABLED_EVENT_TYPES`. By default this is `tao_price_movement`, because it has
automatic objective resolution through the price oracle. Add more event types to
that list only after adding an objective resolver in `masxai/oracle.py`.

## Forecast Schema

Miner responses follow the MVP schema:

```json
{
  "forecast_id": "uuid",
  "event_type": "tao_price_movement",
  "prediction": true,
  "confidence": 0.92,
  "forecast_window": "1h",
  "reasoning": "network activity and price momentum remain positive",
  "timestamp": "ISO8601"
}
```

## Miner Workflow

1. Receive a validator forecasting task.
2. Build a Gemini prompt from the task and validator-supplied context.
3. Generate a structured forecast.
4. Return the forecast to the validator.
5. Publish a summary to Discord when `DISCORD_WEBHOOK_URL` is configured.

Gemini configuration lives in a local `.env` file:

```bash
cp .env.example .env
```

Then edit `.env`:

```env
GEMINI_API_KEY=your-gemini-key
GEMINI_ENABLED=true
GEMINI_MODEL=gemini-2.5-pro
GEMINI_TIMEOUT=8
DISCORD_WEBHOOK_URL=your-discord-webhook
MASXAI_FALLBACK_TAO_PRICE_USD=
MASXAI_FORECAST_INTERVAL_SECONDS=300
```

`.env` is ignored by git. The miner loads it automatically.

`MASXAI_FALLBACK_TAO_PRICE_USD` is optional. Leave it empty for objective
oracle-based scoring. For testnet/dev only, set it to a TAO/USD value if your
machine cannot reach CoinGecko, Binance, or Kraken and the validator logs
`oracle unavailable; skipping issue this epoch`.

`MASXAI_FORECAST_INTERVAL_SECONDS` controls how often the validator asks miners
for a new forecast. `300` means one forecast round every 5 minutes.

Without a Gemini key, the miner returns a neutral baseline forecast so local
testing still works.

If the miner logs `ConnectTimeout` for Gemini, the server cannot reach
`generativelanguage.googleapis.com` quickly enough. You can raise
`GEMINI_TIMEOUT` up to about `15`, or set `GEMINI_ENABLED=false` to run explicit
baseline mode until outbound connectivity is fixed.

## Validator Workflow

Default local/dev mode still snapshots objective reference data and resolves the
one-hour TAO price question locally. Phase 1 centralized mode is enabled by
setting `BT_FORECAST_BEARER_TOKEN`; the production BT-Forecast base URL is the
default and can be overridden with `BT_FORECAST_BASE_URL`:

1. Poll the BT-Forecast FastAPI service for today's deterministic run id
   (`bt-YYYY-MM-DD`), e.g. `/v1/forecast-runs/bt-2026-07-22`.
2. If the run's `generation` is not `complete`, wait for the API's
   `poll_after_s` value before polling the same run again.
3. When `generation` is `complete`, fetch miner-safe questions from
   `/v1/forecast-runs/{run_id}/questions`.
   Private service-only benchmark fields are not copied into the synapse.
4. Query miner axons with `ForecastSynapse` v3.
5. Store miner forecasts in the pending queue, keyed by run id, question key,
   and miner uid.
6. Wait until each question's `cutoff_date`.
7. Fetch actual outcomes from `/v1/resolutions`.
8. Score each miner against the real outcome, never against the engine answer.
9. Queue accurate miner forecasts for `/v1/miner-results` feedback.
10. EMA the score into `self.scores` so the template weight machinery can submit
   weights on chain.

Pending forecasts and scores are persisted to `validator_state.json`. In
centralized mode, each active pending row uses a deterministic
`(run_id, question_key, uid)` key so a re-issued question updates that miner's
latest active answer instead of creating duplicate unresolved rows.

Unanswered miner calls are retried until the question cutoff. Retry cadence starts
at `MASXAI_BT_FORECAST_NO_ANSWER_RETRY_SECONDS` and backs off up to
`MASXAI_BT_FORECAST_NO_ANSWER_RETRY_MAX_SECONDS`, so a validator can recover when
miners come online later without hammering the network. Stale pending rows,
old run metadata, and queued BT-Forecast feedback are bounded by environment
settings in `.env.example`.

## Scoring

Structured forecasts use the Phase 1 weighted score:

```text
Final Score =
50% Brier skill vs baseline +
20% Confidence Calibration +
20% Historical Consistency +
10% Timeliness
```

`probability` is the primary accuracy input. With the default composite baseline
gate, a flat 0.5 forecast earns zero composite reward.

The validator waits for at least `MASXAI_MIN_RESOLVED_BEFORE_WEIGHTS` resolved
miner forecasts, plus the chain's minimum allowed weight count, before submitting
weights. This keeps emissions gated on real resolved performance instead of mere
participation.

Lineage defaults off for open-source deployments. Enable
`BT_FORECAST_INCLUDE_LINEAGE` only when a private validator operator explicitly
needs benchmark telemetry. Miner rewards do not depend on that telemetry.

Legacy Brier helpers remain in `masxai/scoring.py` for probability-only tests and
older local mocks.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r requirements.txt
python scripts/patch_btcli_compat.py
cp .env.example .env
```

Run `python scripts/patch_btcli_compat.py` again after installing or upgrading
`bittensor-cli`. It only patches the CLI package in the active environment and
does not change MASXAI subnet core code. It fixes known testnet CLI issues:
missing `Swap.AlphaSqrtPrice` in `wallet overview`, public RPC storage-work
limits during netuid-filtered `wallet overview`, and negative transaction era
during `subnet register`.

Run tests:

```bash
python -m pytest -q
```

Run the local loop without chain access:

```bash
python scripts/mock_run.py
```

## Testnet 501

```bash
btcli subnet register --netuid 501 --subtensor.network test \
  --wallet.name masxai-miner --wallet.hotkey default
btcli subnet register --netuid 501 --subtensor.network test \
  --wallet.name masxai-validator --wallet.hotkey default

btcli stake add --netuid 501 --subtensor.network test \
  --wallet.name masxai-validator --wallet.hotkey default

python neurons/miner.py --netuid 501 --subtensor.network test \
  --wallet.name masxai-miner --wallet.hotkey default \
  --axon.port 8901 --logging.debug

python neurons/validator.py --netuid 501 --subtensor.network test \
  --wallet.name masxai-validator --wallet.hotkey default --logging.debug
```

## MVP Economics

The product target is to burn 96% of miner emissions and distribute 4% according
to validator weights. This repo currently computes and submits weights; emission
burn mechanics must be enforced in subnet economics/runtime configuration, not
inside miner forecast code.

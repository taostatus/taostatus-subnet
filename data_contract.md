# BT-Forecast Daily Run Contract

This is the handoff contract for validators consuming the centralized
BT-Forecast FastAPI service.

## Authentication

Protected requests include:

- `Authorization: Bearer $BT_FORECAST_BEARER_TOKEN`

`GET /health` is public and does not require the bearer token.

## Daily Run Poll

Validators derive the current run id as:

```text
bt-YYYY-MM-DD
```

Then poll:

```http
GET /v1/forecast-runs/{run_id}
```

Example:

```http
GET /v1/forecast-runs/bt-2026-07-22
```

Response:

```json
{
  "run_id": "bt-2026-07-22",
  "status": "ready",
  "question_count": 12,
  "ready_at": "2026-07-22T09:02:04.082830+00:00",
  "template_version": "t2",
  "measurement_version": "m3",
  "generation": "complete",
  "poll_after_s": 3600
}
```

If the response has `"generation": "complete"`, validators fetch questions. If
generation is not complete, validators wait the response's `poll_after_s` before
polling the same run again.

## Question Fetch

```http
GET /v1/forecast-runs/{run_id}/questions
```

The response contains miner-safe questions and grading rules. Validators store
those questions locally, send them to miners, and keep service-only benchmark
fields out of miner synapses.

Response shape:

```json
{
  "run_id": "bt-2026-07-22",
  "template_version": "t2",
  "measurement_version": "m3",
  "questions": [
    {
      "question_id": "545cb638-eaa9-4a29-bece-90c905448b41",
      "question_key": "dtao_pool|SN99|2026-07-29",
      "question": "Is SN99's thin dTAO pool likely to stay below 1299 TAO by 2026-07-29?",
      "family": "dtao_pool",
      "scope": "subnet",
      "netuid": 99,
      "horizon_days": 6,
      "generated_at": "2026-07-22T09:02:02.534442+00:00",
      "cutoff_date": "2026-07-29T00:00:00+00:00",
      "resolution_criteria": "SN99's dTAO pool (TAO reserve) < 1299 TAO on Taostats.",
      "evidence_summary": "dTAO liquidity stress: SN99 pool: 866 TAO, 125850 ALPHA.",
      "measurement": {
        "source": "daily_snapshot",
        "grade_time_utc": "06:00",
        "threshold": 1299,
        "threshold_unit": "tao",
        "operator": "below"
      }
    }
  ]
}
```

## Resolution Fetch

```http
GET /v1/resolutions?run_id={run_id}
```

Validators score miners against resolved outcomes from this endpoint.

Response shape:

```json
{
  "resolutions": [
    {
      "question_key": "dtao_pool|SN99|2026-07-29",
      "family": "dtao_pool",
      "scope": "subnet",
      "netuid": 99,
      "horizon_days": 6,
      "status": "open",
      "outcome": null,
      "cutoff_date": "2026-07-29T00:00:00+00:00",
      "resolved_at": null,
      "measurement": {
        "source": "daily_snapshot",
        "grade_time_utc": "06:00",
        "threshold": 1299,
        "threshold_unit": "tao",
        "operator": "below"
      },
      "measurement_value": null,
      "observed_at": null,
      "explanation": null,
      "engine_brier": null,
      "deferral_reason": null
    }
  ]
}
```

## Feedback

```http
POST /v1/miner-results
```

Validators post accurate resolved miner forecasts back to BT-Forecast for
calibration. This feedback is not the emission gate.

Request shape:

```json
{
  "run_id": "bt-2026-07-22",
  "question_key": "dtao_pool|SN99|2026-07-29",
  "family": "dtao_pool",
  "scope": "subnet",
  "netuid": 99,
  "horizon_days": 6,
  "outcome": true,
  "measurement_value": 1100,
  "resolved_at": "2026-07-29T06:04:10+00:00",
  "engine_probability": null,
  "results": [
    {
      "uid": 1,
      "hotkey": "miner-hotkey-1",
      "probability": 0.93,
      "prediction": true,
      "confidence": 0.93,
      "reasoning": "Pool likely stays thin.",
      "model": "miner-model",
      "features": {},
      "issued_at": 1784700000.0,
      "submitted_at": 1784700911.0,
      "brier": 0.0049,
      "dist_to_outcome": 0.07,
      "dist_to_engine": null
    }
  ]
}
```

## Retry Behavior

- `429` responses can include `Retry-After` in seconds.
- Validators retry `429` and `5xx` with exponential backoff plus jitter, bounded
  by `BT_FORECAST_MAX_RETRIES`.
- Run status polling additionally respects the API's `poll_after_s`; the default
  fallback is `3600` seconds.

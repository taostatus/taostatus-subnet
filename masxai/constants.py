"""
masxai/constants.py - subnet constants.
"""

NETUID = 501
NETWORK = "test"
SUBTENSOR_ENDPOINT = "wss://test.finney.opentensor.ai:443"

# --- forecast targets ---
TAO_PRICE_EVENT = "tao_price_movement"
SUBNET_TOKEN_PRICE_EVENT = "subnet_token_price"
NEW_SUBNET_REGISTRATION_EVENT = "new_subnet_registration"
GOVERNANCE_OUTCOME_EVENT = "governance_outcome"
ECOSYSTEM_GROWTH_EVENT = "ecosystem_growth_metric"
SIGNIFICANT_BITTENSOR_EVENT = "significant_bittensor_event"

SUPPORTED_EVENT_TYPES = [
    TAO_PRICE_EVENT,
    SUBNET_TOKEN_PRICE_EVENT,
    NEW_SUBNET_REGISTRATION_EVENT,
    GOVERNANCE_OUTCOME_EVENT,
    ECOSYSTEM_GROWTH_EVENT,
    SIGNIFICANT_BITTENSOR_EVENT,
]

# MVP starts with the event types that have objective, automatic ground truth in
# this repo. Add more here only after adding a resolver in masxai/oracle.py.
ENABLED_EVENT_TYPES = [TAO_PRICE_EVENT]

FORECAST_ASSET = "bittensor"          # CoinGecko coin id for TAO
FORECAST_HORIZON_SECONDS = 3600       # default 60-minute resolution horizon
FORECAST_WINDOW = "1h"
FORECAST_INTERVAL_SECONDS = 300       # issue cadence, default 5 minutes

# --- centralized BT-Forecast API ---
BT_FORECAST_DEFAULT_BASE_URL = "https://masx-bt-forecast-api-production.up.railway.app"
BT_FORECAST_BASE_URL_ENV = "BT_FORECAST_BASE_URL"
BT_FORECAST_BEARER_TOKEN_ENV = "BT_FORECAST_BEARER_TOKEN"
BT_FORECAST_RUN_ID_ENV = "BT_FORECAST_RUN_ID"
BT_FORECAST_RUN_DATE_ENV = "BT_FORECAST_RUN_DATE"
BT_FORECAST_REQUIRED_ENV = "MASXAI_BT_FORECAST_REQUIRED"
BT_FORECAST_INCLUDE_LINEAGE_ENV = "BT_FORECAST_INCLUDE_LINEAGE"
BT_FORECAST_MAX_QUESTIONS_ENV = "MASXAI_BT_FORECAST_MAX_QUESTIONS_PER_ROUND"
BT_FORECAST_REISSUE_SECONDS_ENV = "MASXAI_BT_FORECAST_REISSUE_SECONDS"
BT_FORECAST_NO_ANSWER_RETRY_SECONDS_ENV = "MASXAI_BT_FORECAST_NO_ANSWER_RETRY_SECONDS"
BT_FORECAST_NO_ANSWER_RETRY_MAX_SECONDS_ENV = "MASXAI_BT_FORECAST_NO_ANSWER_RETRY_MAX_SECONDS"
BT_FORECAST_NO_ANSWER_RETRY_BACKOFF_MULTIPLIER_ENV = "MASXAI_BT_FORECAST_NO_ANSWER_RETRY_BACKOFF_MULTIPLIER"
BT_FORECAST_RESOLUTION_WAIT_SECONDS_ENV = "MASXAI_BT_FORECAST_RESOLUTION_WAIT_SECONDS"
BT_FORECAST_RESOLUTION_RETRY_SECONDS_ENV = "MASXAI_BT_FORECAST_RESOLUTION_RETRY_SECONDS"
BT_FORECAST_FEEDBACK_THRESHOLD_ENV = "MASXAI_BT_FORECAST_FEEDBACK_THRESHOLD"
BT_FORECAST_FEEDBACK_QUEUE_MAX_ENV = "MASXAI_BT_FORECAST_FEEDBACK_QUEUE_MAX"
BT_FORECAST_RUN_STATE_RETENTION_SECONDS_ENV = "MASXAI_BT_FORECAST_RUN_STATE_RETENTION_SECONDS"
BT_FORECAST_POLL_AFTER_MAX_SECONDS_ENV = "MASXAI_BT_FORECAST_POLL_AFTER_MAX_SECONDS"
BT_FORECAST_STUCK_RUN_WARN_SECONDS_ENV = "MASXAI_BT_FORECAST_STUCK_RUN_WARN_SECONDS"
BT_FORECAST_STUCK_RUN_ERROR_SECONDS_ENV = "MASXAI_BT_FORECAST_STUCK_RUN_ERROR_SECONDS"
BT_FORECAST_STUCK_RUN_FALLBACK_SECONDS_ENV = "MASXAI_BT_FORECAST_STUCK_RUN_FALLBACK_SECONDS"

BT_FORECAST_TIMEOUT = 10
BT_FORECAST_MAX_RETRIES = 3
BT_FORECAST_DEFAULT_POLL_AFTER_SECONDS = 3600
# Ceiling on the server-supplied poll_after_s so a misbehaving/misconfigured
# BT-Forecast response can't push the validator's run-status poll arbitrarily far out.
BT_FORECAST_POLL_AFTER_MAX_SECONDS = 900          # 15 minutes
# Escalating alert thresholds for a run stuck at generation != "complete".
BT_FORECAST_STUCK_RUN_WARN_SECONDS = 2 * 60 * 60    # 2 hours
BT_FORECAST_STUCK_RUN_ERROR_SECONDS = 6 * 60 * 60   # 6 hours
# Opt-in only: 0 disables falling back to the legacy local-oracle issue path
# while a run is stuck. Operators can set this explicitly to keep the subnet
# issuing *something* during an extended BT-Forecast outage.
BT_FORECAST_STUCK_RUN_FALLBACK_SECONDS = 0
BT_FORECAST_MAX_QUESTIONS_PER_ROUND = 12
BT_FORECAST_REISSUE_SECONDS = 0       # 0 means issue each question once.
BT_FORECAST_NO_ANSWER_RETRY_SECONDS = 300
BT_FORECAST_NO_ANSWER_RETRY_MAX_SECONDS = 3600
BT_FORECAST_NO_ANSWER_RETRY_BACKOFF_MULTIPLIER = 1.5
BT_FORECAST_RESOLUTION_WAIT_SECONDS = 5 * 24 * 60 * 60
BT_FORECAST_RESOLUTION_RETRY_SECONDS = 15 * 60
BT_FORECAST_FEEDBACK_THRESHOLD = 0.10
BT_FORECAST_FEEDBACK_QUEUE_MAX = 1000
BT_FORECAST_RUN_STATE_RETENTION_SECONDS = 14 * 24 * 60 * 60
BT_FORECAST_READY_STATUSES = {"ready"}
BT_FORECAST_COMPLETE_GENERATION = "complete"
BT_FORECAST_PENDING_STATUSES = {"pending", "running"}
BT_FORECAST_RESOLVED_TRUE = "resolved_true"
BT_FORECAST_RESOLVED_FALSE = "resolved_false"
BT_FORECAST_OPEN_STATUSES = {"open"}
BT_FORECAST_UNSCORED_TERMINAL_STATUSES = {
    "expired",
    "annulled",
    "ambiguous",
    "rejected",
}

# --- query / scoring ---
QUERY_VALIDATOR_UIDS_ENV = "MASXAI_QUERY_VALIDATOR_UIDS"
MINER_REQUIRE_VALIDATOR_PERMIT_ENV = "MASXAI_REQUIRE_VALIDATOR_PERMIT"
QUERY_TIMEOUT = 20                    # dendrite query timeout (seconds)
EMA_ALPHA = 0.1                       # score smoothing; higher = faster adaptation
NEUTRAL_PROB = 0.5                    # neutral scoring baseline / coin flip
NO_ANSWER_BRIER = 0.5                 # Brier assigned when a miner doesn't answer
PROB_CLAMP_LO = 0.01
PROB_CLAMP_HI = 0.99
CONFIDENCE_CLAMP_LO = 0.0
CONFIDENCE_CLAMP_HI = 1.0

# Scoring weights from the MVP spec.
ACCURACY_WEIGHT = 0.50
CALIBRATION_WEIGHT = 0.20
CONSISTENCY_WEIGHT = 0.20
TIMELINESS_WEIGHT = 0.10
BASELINE_COMPOSITE_GATE = True

# --- weights ---
MIN_RESOLVED_BEFORE_WEIGHTS_ENV = "MASXAI_MIN_RESOLVED_BEFORE_WEIGHTS"
MIN_RESOLVED_BEFORE_WEIGHTS = 3       # require real evidence before weights dominate
BURN_UID = 25                         # receives reserved burn allocation
BURN_PERCENTAGE = 0.95                # burn 95%, distribute 5% to scored miners

# Interim participation weighting: keeps the validator submitting weights every
# epoch (so Yuma consensus never marks it inactive) and gives miners partial
# credit for actively answering before their forecasts resolve. This is a
# liveness signal only, never a correctness signal.
PARTICIPATION_WEIGHT_ENV = "MASXAI_PARTICIPATION_WEIGHT"
PARTICIPATION_WEIGHT = 0.10           # blended-weight share once accuracy scores exist
PARTICIPATION_EMA_ALPHA_ENV = "MASXAI_PARTICIPATION_EMA_ALPHA"
PARTICIPATION_EMA_ALPHA = 0.2         # moves faster than the accuracy EMA (EMA_ALPHA)
PARTICIPATION_REWARD = 1.0            # reward fed to the EMA for each valid forecast

# --- persistence ---
VALIDATOR_STATE_FILE_ENV = "MASXAI_VALIDATOR_STATE_FILE"
STATE_FILE = "validator_state.json"   # pending + resolved + scores

# --- oracle ---
COINGECKO_URL = "https://api.coingecko.com/api/v3/simple/price"
BINANCE_TAO_URL = "https://api.binance.com/api/v3/ticker/price?symbol=TAOUSDT"
KRAKEN_TAO_URL = "https://api.kraken.com/0/public/Ticker?pair=TAOUSD"
ORACLE_TIMEOUT = 10                   # seconds

# --- Gemini / Discord miner integrations ---
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
GEMINI_TIMEOUT = 8
# Minimum headroom GEMINI_TIMEOUT must leave under the validator's QUERY_TIMEOUT
# (see above) so a slow-but-successful Gemini call still has time to serialize
# and reach the validator before its dendrite call gives up. Without this
# margin a slow Gemini response is scored as a no-answer even though the miner
# technically responded.
GEMINI_TIMEOUT_MARGIN_SECONDS = 5.0
DISCORD_TIMEOUT = 5

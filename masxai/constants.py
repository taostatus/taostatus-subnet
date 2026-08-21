"""
masxai/constants.py - MVP subnet constants for netuid 501 (testnet).
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

# --- query / scoring ---
QUERY_TIMEOUT = 20                    # dendrite query timeout (seconds)
EMA_ALPHA = 0.1                       # score smoothing; higher = faster adaptation
NEUTRAL_PROB = 0.5                    # baseline / fallback probability
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

# --- weights ---
MIN_RESOLVED_BEFORE_WEIGHTS = 1       # set weights once anything has resolved

# --- persistence ---
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
DISCORD_TIMEOUT = 5

# --- miner forecast ingestion API (optional) ---
# A separate backend that accepts machine-to-machine reports of miner metagraph
# state and forecast activity, authenticated via a static X-API-Key. Fully
# opt-in: unless both env vars below are set, open_ingest_client_from_env()
# returns None and every validator hook that depends on it becomes a no-op.
INGEST_BASE_URL_ENV = "MASXAI_INGEST_BASE_URL"
INGEST_API_KEY_ENV = "INGEST_API_KEY"
INGEST_TIMEOUT_ENV = "MASXAI_INGEST_TIMEOUT"
INGEST_MAX_RETRIES_ENV = "MASXAI_INGEST_MAX_RETRIES"
INGEST_MINER_SYNC_INTERVAL_SECONDS_ENV = "MASXAI_INGEST_MINER_SYNC_INTERVAL_SECONDS"
INGEST_QUEUE_MAX_ENV = "MASXAI_INGEST_QUEUE_MAX"

INGEST_TIMEOUT = 10
INGEST_MAX_RETRIES = 3
INGEST_MINER_SYNC_INTERVAL_SECONDS = 600      # 10 minutes
INGEST_QUEUE_MAX = 1000

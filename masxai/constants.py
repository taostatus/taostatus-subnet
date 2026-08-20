"""
masxai/constants.py - subnet constants.
"""

NETUID = 501
NETWORK = "test"
SUBTENSOR_ENDPOINT = "wss://test.finney.opentensor.ai:443"

# --- query / scoring ---
QUERY_VALIDATOR_UIDS_ENV = "MASXAI_QUERY_VALIDATOR_UIDS"
EMA_ALPHA = 0.1                       # generic default smoothing alpha for ema_update()

# --- weights ---
# Weight is earned only through confirmed LLM-key efficiency (see
# Validator._blended_weight_array()); the template's own burn allocation
# then reserves BURN_PERCENTAGE of emission for BURN_UID unconditionally,
# regardless of how much real efficiency data exists.
BURN_UID = 25                         # receives reserved burn allocation
BURN_PERCENTAGE = 0.95                # burn 95%, distribute 5% to miners with confirmed usage

# Liveness participation: tracked for observability only (is a miner's
# software online and responsive) - never blended into submitted chain
# weight. A miner earns weight only through a confirmed, currently-active
# contributed key (self.scores), never merely by answering the ask.
PARTICIPATION_EMA_ALPHA_ENV = "MASXAI_PARTICIPATION_EMA_ALPHA"
PARTICIPATION_EMA_ALPHA = 0.2         # moves faster than the llm_key efficiency EMA (LLM_KEY_EMA_ALPHA)
PARTICIPATION_REWARD = 1.0            # reward fed to the EMA for each answered ask

# --- persistence ---
VALIDATOR_STATE_FILE_ENV = "MASXAI_VALIDATOR_STATE_FILE"
STATE_FILE = "validator_state.json"

# --- miner LLM-key contribution pipeline ---
# Off by default on both sides. Miner: LLM_KEY_CONTRIB_ENABLED_ENV must be
# explicitly set. Validator: LLM_KEY_VALIDATOR_TOKEN_ENV unset means
# open_llm_key_client_from_env() returns None, so the submission/report-poll
# rounds never run and self.scores (the only driver of weight) stays at zero.
LLM_KEY_CONTRIB_ENABLED_ENV = "MASXAI_LLM_KEY_CONTRIB_ENABLED"
LLM_KEY_CONTRIB_PROVIDER_ENV = "MASXAI_LLM_KEY_CONTRIB_PROVIDER"
LLM_KEY_CONTRIB_MODEL_ENV = "MASXAI_LLM_KEY_CONTRIB_MODEL"
LLM_KEY_CONTRIB_API_KEY_ENV = "MASXAI_LLM_KEY_CONTRIB_API_KEY"

LLM_KEY_BASE_URL_ENV = "MASXAI_LLM_KEY_BASE_URL"
LLM_KEY_VALIDATOR_TOKEN_ENV = "MASXAI_LLM_KEY_VALIDATOR_TOKEN"
LLM_KEY_TIMEOUT_ENV = "MASXAI_LLM_KEY_TIMEOUT"
LLM_KEY_MAX_RETRIES_ENV = "MASXAI_LLM_KEY_MAX_RETRIES"
LLM_KEY_TIMEOUT = 10
LLM_KEY_MAX_RETRIES = 3
LLM_KEY_QUERY_TIMEOUT = 15             # dendrite timeout for LLMKeySynapse (small payload)

LLM_KEY_RETRY_AFTER_MAX_SECONDS_ENV = "MASXAI_LLM_KEY_RETRY_AFTER_MAX_SECONDS"
LLM_KEY_RETRY_AFTER_MAX_SECONDS = 30.0  # ceiling on a server-supplied Retry-After header

LLM_KEY_CONNECT_TIMEOUT_ENV = "MASXAI_LLM_KEY_CONNECT_TIMEOUT"
LLM_KEY_CONNECT_TIMEOUT = 5.0          # connect-phase sub-timeout, shorter than LLM_KEY_TIMEOUT

LLM_KEY_SUBMISSION_INTERVAL_SECONDS_ENV = "MASXAI_LLM_KEY_SUBMISSION_INTERVAL_SECONDS"
LLM_KEY_SUBMISSION_INTERVAL_SECONDS = 4 * 60 * 60      # re-ask cadence, default 4h
LLM_KEY_REPORT_POLL_INTERVAL_SECONDS_ENV = "MASXAI_LLM_KEY_REPORT_POLL_INTERVAL_SECONDS"
LLM_KEY_REPORT_POLL_INTERVAL_SECONDS = 10 * 60         # poll cadence, default 10m

# On a transient ask/poll failure, back off by this much instead of waiting
# out the full interval above before retrying.
LLM_KEY_ASK_FAILURE_BACKOFF_SECONDS_ENV = "MASXAI_LLM_KEY_ASK_FAILURE_BACKOFF_SECONDS"
LLM_KEY_ASK_FAILURE_BACKOFF_SECONDS = 5 * 60
LLM_KEY_REPORT_POLL_FAILURE_BACKOFF_SECONDS_ENV = "MASXAI_LLM_KEY_REPORT_POLL_FAILURE_BACKOFF_SECONDS"
LLM_KEY_REPORT_POLL_FAILURE_BACKOFF_SECONDS = 30

# Grace period before evicting a llm_key_hotkey_status entry for a hotkey no
# longer present in the metagraph -- avoids losing state to a resize race or
# a quick re-registration.
LLM_KEY_HOTKEY_STATUS_EVICTION_GRACE_SECONDS_ENV = "MASXAI_LLM_KEY_HOTKEY_STATUS_EVICTION_GRACE_SECONDS"
LLM_KEY_HOTKEY_STATUS_EVICTION_GRACE_SECONDS = 24 * 60 * 60

# If the validator has accepted keys on file but report polls stay empty for
# longer than this, warn -- the protocol backend likely isn't feeding usage
# data (see llm_key_report_poll_round()).
LLM_KEY_REPORTS_EMPTY_WARN_SECONDS_ENV = "MASXAI_LLM_KEY_REPORTS_EMPTY_WARN_SECONDS"
LLM_KEY_REPORTS_EMPTY_WARN_SECONDS = 6 * 60 * 60

LLM_KEY_EMA_ALPHA_ENV = "MASXAI_LLM_KEY_EMA_ALPHA"
LLM_KEY_EMA_ALPHA = 0.15

# Minimum EMA-alpha multiplier applied even when a report window has very
# few calls -- keeps a single-call window from swinging self.scores at full
# weight while still letting it contribute some signal.
LLM_KEY_EMA_CONFIDENCE_FLOOR_ENV = "MASXAI_LLM_KEY_EMA_CONFIDENCE_FLOOR"
LLM_KEY_EMA_CONFIDENCE_FLOOR = 0.2

# Composite = reliability_weight*reliability + latency_weight*latency_score
#           + volume_weight*volume_score, then scaled by model_tier_weight.
# Output quality can't be fairly judged here (the protocol controls every
# prompt, and the models are third-party) -- these three terms plus tier
# reward only what a miner actually controls: operational reliability,
# speed, real sustained capacity, and which model tier they bring.
LLM_KEY_RELIABILITY_WEIGHT = 0.5
LLM_KEY_LATENCY_WEIGHT = 0.25
LLM_KEY_LATENCY_CEILING_SECONDS = 5.0
LLM_KEY_MIN_CALLS_FOR_SCORING_ENV = "MASXAI_LLM_KEY_MIN_CALLS_FOR_SCORING"
LLM_KEY_MIN_CALLS_FOR_SCORING = 5      # below this, skip the EMA update (no signal, not a penalty)

# Volume: rewards real sustained capacity, not just call-level pass/fail --
# a key serving 300 calls should score higher than one serving 3, even at
# identical success rates. Naturally bounded by acquire_key()'s daily-call
# cap on the protocol side, so this can't be gamed with unbounded artificial
# call volume.
LLM_KEY_VOLUME_WEIGHT = 0.25
LLM_KEY_VOLUME_TARGET_CALLS = 50       # calls per report window considered "fully utilized"

# Model tier: the one real "quality" lever a miner controls (which model
# they configure), applied as a final multiplier on the composite above so a
# high-tier key that's unreliable still scores low, and a lower-tier key
# that's perfectly reliable still scores respectably. Provisional, tunable
# without touching scoring logic -- same operator-maintained-list convention
# as LLM_KEY_ALLOWED_MODELS.
LLM_KEY_MODEL_TIER_WEIGHTS = {
    "openai/gpt-4o": 1.0,
    "openai/gpt-4o-mini": 0.6,
    "anthropic/claude-3-5-sonnet-20241022": 1.0,
    "anthropic/claude-3-5-haiku-20241022": 0.6,
    "deepseek/deepseek-chat": 0.5,
}
LLM_KEY_MODEL_TIER_DEFAULT_WEIGHT = 0.5   # unlisted-but-allowed provider/model

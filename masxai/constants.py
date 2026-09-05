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
# Multi-key config: a JSON array of up to LLM_KEY_MAX_KEYS_PER_HOTKEY
# entries, [{"provider": "openai", "model": "gpt-4o", "api_key": "sk-..."}].
# List order is the slot order -- editing slot N's entry replaces slot N's
# key on the next ask.
LLM_KEYS_JSON_ENV = "MASXAI_LLM_KEYS_JSON"
# Legacy single-key triple, still honored as slot 0 when LLM_KEYS_JSON_ENV
# is unset.
LLM_KEY_CONTRIB_PROVIDER_ENV = "MASXAI_LLM_KEY_CONTRIB_PROVIDER"
LLM_KEY_CONTRIB_MODEL_ENV = "MASXAI_LLM_KEY_CONTRIB_MODEL"
LLM_KEY_CONTRIB_API_KEY_ENV = "MASXAI_LLM_KEY_CONTRIB_API_KEY"

# Mirrors the protocol backend's llm_key_max_keys_per_hotkey. Enforced miner
# -side (cap what's sent), validator-side (cap what's relayed), and
# backend-side (slots 0..4 only).
LLM_KEY_MAX_KEYS_PER_HOTKEY = 5

# Mirrors the protocol backend's llm_key_min_keys_per_hotkey. A miner must
# contribute at least this many *distinct* keys per submission or the round
# is declined entirely (miner-side: never answers has_key=True; validator
# -side: sanitized batch below this count is not relayed) rather than
# submitting a partial batch -- same "decline rather than hedge" principle
# used elsewhere in this project, applied to submission volume instead of
# debate content. Physical-key uniqueness itself can only be checked where
# the plaintext is visible: miner-side (before encryption) as a courtesy,
# and authoritatively at the protocol backend (SHA-256 fingerprint after
# decryption) -- NaCl SealedBox is deliberately non-deterministic, so
# neither ciphertext blobs nor the validator (which never decrypts) can
# ever detect a repeated physical key by comparison alone.
LLM_KEY_MIN_KEYS_PER_HOTKEY = 5

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

# The protocol reports one row per single call, not a pre-aggregated window
# -- raw report rows for a hotkey accumulate in Validator.llm_key_pending_calls
# until LLM_KEY_MIN_CALLS_FOR_SCORING is reached (see llm_key_report_poll_round).
# A low-traffic key that never reaches that threshold on its own is
# force-flushed (scored on whatever it has, confidence-floor-damped) after
# this long, rather than accumulating forever. The protocol's only currently
# -wired report source is a daily health-check ping per active key, so this
# gives up to ~5 daily pings (the default call-volume floor) plus one full
# extra cycle of slack before forcing a score.
LLM_KEY_PENDING_WINDOW_MAX_SECONDS_ENV = "MASXAI_LLM_KEY_PENDING_WINDOW_MAX_SECONDS"
LLM_KEY_PENDING_WINDOW_MAX_SECONDS = 7 * 24 * 60 * 60

# A hotkey whose score is positive but hasn't had a fresh usage report in
# this long gets actively decayed toward zero each poll (see
# _decay_stale_llm_key_scores) instead of freezing forever -- covers a key
# that was rejected on resubmission, went DEAD, or was REVOKED, none of
# which necessarily produce another report to naturally zero it out via the
# key_active=False path. Set well above the daily health-check cadence so
# ordinary timing jitter on a healthy, low-traffic key never triggers it.
LLM_KEY_STALENESS_TIMEOUT_SECONDS_ENV = "MASXAI_LLM_KEY_STALENESS_TIMEOUT_SECONDS"
LLM_KEY_STALENESS_TIMEOUT_SECONDS = 48 * 60 * 60

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

# Composite = reliability_weight*reliability + quality_weight*quality
#           + latency_weight*latency_score + volume_weight*volume_score,
# then scaled by model_tier_weight. Reliability stays dominant (a call that
# fails outright is worse than one that merely produced a mediocre answer).
# quality_score is self-graded by the calling agent (e.g. Chain-Agent's
# groundedness/fabrication check) per call and reported alongside
# success/latency -- it's None (treated as neutral 0.5, not penalized) for
# any call the agent couldn't grade, which is expected for most traffic.
LLM_KEY_RELIABILITY_WEIGHT = 0.4
LLM_KEY_QUALITY_WEIGHT = 0.2
LLM_KEY_LATENCY_WEIGHT = 0.2
LLM_KEY_LATENCY_CEILING_SECONDS = 5.0
LLM_KEY_MIN_CALLS_FOR_SCORING_ENV = "MASXAI_LLM_KEY_MIN_CALLS_FOR_SCORING"
LLM_KEY_MIN_CALLS_FOR_SCORING = 5      # below this, skip the EMA update (no signal, not a penalty)

# Hard floors: a scored window that trips either one earns 0.0 outright --
# the additive composite must never let a key that isn't actually working
# (or is emitting low-quality output) keep collecting the neutral-default
# quality/latency terms plus volume credit. On top of that, the validator
# drops the EMA straight to zero (see _record_llm_key_score) when the
# tripped window carries at least LLM_KEY_MIN_CALLS_FOR_SCORING calls of
# evidence, so a confirmed-bad key stops earning emission this epoch, not
# several EMA steps from now. Reliability at exactly the floor still scores.
LLM_KEY_RELIABILITY_HARD_FLOOR_ENV = "MASXAI_LLM_KEY_RELIABILITY_HARD_FLOOR"
LLM_KEY_RELIABILITY_HARD_FLOOR = 0.5   # majority-failing window -> key isn't working
LLM_KEY_QUALITY_HARD_FLOOR_ENV = "MASXAI_LLM_KEY_QUALITY_HARD_FLOOR"
LLM_KEY_QUALITY_HARD_FLOOR = 0.35      # below Chain-Agent's 0.6 reasoned-INSUFFICIENT, above its 0.1/0.2 bad grades
# The quality hard floor only applies once this many calls in the window
# actually carried a measured quality_score -- one self-graded bad reply in
# an otherwise healthy window is signal for the quality axis, not grounds to
# zero the whole key.
LLM_KEY_QUALITY_FLOOR_MIN_GRADED_ENV = "MASXAI_LLM_KEY_QUALITY_FLOOR_MIN_GRADED"
LLM_KEY_QUALITY_FLOOR_MIN_GRADED = 3

# error_categories values that mean the key itself is unusable at the
# provider (bad credentials, exhausted budget, region/permission block) --
# as opposed to transient trouble (rate_limit, timeout, provider_outage),
# which stays a reliability matter. Matched case-insensitively. Two
# vocabularies land in the same field: the protocol health check's
# lowercased KeyValidationStatus values, and the exception class names the
# agents report verbatim on a failed call. One such report row zeroes the
# hotkey's score immediately (see llm_key_report_poll_round).
LLM_KEY_FATAL_ERROR_CATEGORIES = frozenset({
    "invalid_key",
    "no_funds_or_budget",
    "permission_or_region",
    "authenticationerror",
    "permissiondeniederror",
})

# Volume: rewards real sustained *successful* capacity, not just call-level
# pass/fail -- a key serving 300 good calls should score higher than one
# serving 3, even at identical success rates, and failed calls never count
# as delivered volume. Naturally bounded by acquire_key()'s daily-call cap
# on the protocol side, so this can't be gamed with unbounded artificial
# call volume.
LLM_KEY_VOLUME_WEIGHT = 0.2
LLM_KEY_VOLUME_TARGET_CALLS = 50       # successful calls per report window considered "fully utilized"

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

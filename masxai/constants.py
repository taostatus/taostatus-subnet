"""
masxai/constants.py - subnet constants.
"""

import os

NETUID = 501
NETWORK = "test"
SUBTENSOR_ENDPOINT = "wss://test.finney.opentensor.ai:443"

# --- subnet mechanisms ---
# The subnet runs two mechanisms (see MECHANISMS.md). UIDs, registration,
# stake and validator permits are shared subnet-wide; each mechanism has its
# own weight matrix, its own Yuma consensus and its own share of emission.
#   0 -- LLM-key contribution  (neurons/validator.py + neurons/miner.py)
#   1 -- security-audit agents (neurons/security_validator.py + neurons/security_miner.py)
# Each neuron class pins its mechid from here; it is deliberately not a CLI
# flag, so a validator can never set one track's scores on the other's matrix.
LLM_KEY_MECHID = 0
SECURITY_MECHID = 1
MECHANISM_COUNT = 2

# --- query / scoring ---
QUERY_VALIDATOR_UIDS_ENV = "MASXAI_QUERY_VALIDATOR_UIDS"
EMA_ALPHA = 0.1                       # generic default smoothing alpha for ema_update()

# --- weights ---
# Weight is earned only through confirmed LLM-key efficiency (see
# Validator._blended_weight_array()); the template's own burn allocation
# then reserves BURN_PERCENTAGE of emission for BURN_UID unconditionally,
# regardless of how much real efficiency data exists.
# Env-overridable so a network whose metagraph has no uid 25 (e.g. testnet 501,
# which only has ~15 uids) can point the burn at a valid uid -- otherwise
# _apply_burn_allocation raises "BURN_UID not present" and set_weights is skipped
# entirely, so nothing ever reaches the chain. Mainnet keeps the 25/0.95 default.
BURN_UID = int(os.getenv("MASXAI_BURN_UID", "25"))          # receives reserved burn allocation
BURN_PERCENTAGE = float(os.getenv("MASXAI_BURN_PERCENTAGE", "0.95"))  # burn 95%, 5% to scored miners

# Liveness participation: tracked for observability only (is a miner's
# software online and responsive) - never blended into submitted chain
# weight. A miner earns weight only through a confirmed, currently-active
# contributed key (self.scores), never merely by answering the ask.
PARTICIPATION_EMA_ALPHA_ENV = "MASXAI_PARTICIPATION_EMA_ALPHA"
PARTICIPATION_EMA_ALPHA = 0.2
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

# --- Discord announcements (optional) ---
# Unset DISCORD_WEBHOOK_URL_ENV is the kill switch: masxai/discord.py no-ops
# and the validator never attempts a post. The channel is public, so only
# on-chain-public data is ever sent (hotkey, provider/model, accept/reject).
DISCORD_WEBHOOK_URL_ENV = "MASXAI_DISCORD_WEBHOOK_URL"
DISCORD_TIMEOUT_ENV = "MASXAI_DISCORD_TIMEOUT"
DISCORD_TIMEOUT = 5.0                  # short on purpose: never hold up a round

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
# Evidence bar for killing ONE key of a hotkey on its own sub-window (see
# Validator._sub_window_floor_reason) -- a couple of bad calls is signal, not
# a verdict. The hotkey's pooled epoch window has no such floor: any good
# report in the last completed epoch earns.
LLM_KEY_MIN_CALLS_FOR_SCORING = 5

# Hard floors: a scored window that trips either one earns 0.0 outright --
# the additive composite must never let a key that isn't actually working
# (or is emitting low-quality output) keep collecting the neutral-default
# quality/latency terms plus volume credit. Reliability at exactly the floor
# still scores.
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
LLM_KEY_VOLUME_TARGET_CALLS = 50       # successful calls per epoch considered "fully utilized"

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

# --- security-audit track (second emission path) -----------------------
# Off by default, exactly like the LLM-key track: a miner opts in by setting
# an image reference to submit. Empty/unset => the miner declines every
# security round (has_agent=False), never crashes the axon.
SECURITY_AGENT_ENABLED_ENV = "MASXAI_SECURITY_AGENT_ENABLED"
SECURITY_AGENT_IMAGE_ENV = "MASXAI_SECURITY_AGENT_IMAGE"

# Dendrite timeout when the validator asks a miner for its image reference.
# The payload is tiny (one string), so this is short.
SECURITY_QUERY_TIMEOUT = 15

# How often the validator runs a security round, seconds.
SECURITY_SUBMISSION_INTERVAL_SECONDS_ENV = "MASXAI_SECURITY_SUBMISSION_INTERVAL_SECONDS"
SECURITY_SUBMISSION_INTERVAL_SECONDS = 300

# A round runs in the BACKGROUND so evaluation never blocks the base class's
# weight-setting loop (a silent validator loses vtrust -- F3). This bounds how
# long one round's eval loop runs before deferring the remaining miners to the
# next round, so rounds can't pile up.
SECURITY_ROUND_BUDGET_SECONDS_ENV = "MASXAI_SECURITY_ROUND_BUDGET_SECONDS"
SECURITY_ROUND_BUDGET_SECONDS = 240

# Where the security validator keeps its verdict database on the host.
SECURITY_DB_PATH_ENV = "MASXAI_SECURITY_DB_PATH"
SECURITY_DB_PATH = "secqurityVali.db"

# --- marketplace handoff (catalog backend) -----------------------------
# After scoring, the validator pushes each agent's METADATA + SCORES (never the
# image/code) to the marketplace backend, which the frontend reads. Both unset
# => the push is a no-op, so the validator runs fine without a backend.
MARKETPLACE_URL_ENV = "MASXAI_MARKETPLACE_URL"       # e.g. http://host:8099
MARKETPLACE_TOKEN_ENV = "MASXAI_MARKETPLACE_TOKEN"   # bearer for the internal API
MARKETPLACE_TIMEOUT_ENV = "MASXAI_MARKETPLACE_TIMEOUT"
MARKETPLACE_TIMEOUT = 5.0                             # short: never hold up a round

# --- security-track agent encryption (v2 transport) --------------------
# The validator's SealedBox keypair. The private half is persisted here so a
# restart can still decrypt blobs miners encrypted for the previous ask; the
# public half is derived from it and sent in every ask. Generated on first run
# if the file is absent. Treat this file like any other validator secret.
SECURITY_VALIDATOR_KEY_FILE_ENV = "MASXAI_SECURITY_VALIDATOR_KEY_FILE"
SECURITY_VALIDATOR_KEY_FILE = "security_validator_key.json"

# --- security-track per-category capability scoring --------------------
# The vulnerability categories the benchmark currently issues. A miner is scored
# per category and its overall score is the MEAN across these, so an untested or
# failed category holds the mean down -- breadth is what earns. Add a category
# here when a new target type (XSS, SSRF, ...) is introduced. Today: SQLi only,
# so the aggregate equals the SQLi score until more are added.
SECURITY_ACTIVE_CATEGORIES = ("sqli", "cmdi")

# Where the per-miner, per-category EMA matrix is persisted (see
# secqurityVali/category_scores.py), and the EMA weight on each new observation.
SECURITY_CATEGORY_SCORES_FILE_ENV = "MASXAI_SECURITY_CATEGORY_SCORES_FILE"
SECURITY_CATEGORY_SCORES_FILE = "security_category_scores.json"
SECURITY_CATEGORY_EMA_ALPHA_ENV = "MASXAI_SECURITY_CATEGORY_EMA_ALPHA"
SECURITY_CATEGORY_EMA_ALPHA = 0.5

# Freshness/decay (F4): a category score only counts while it was refreshed
# within this window. A miner re-evaluated every round keeps its score current;
# one that stops working (or goes offline) has its cells go stale and its score
# fall to 0 -- so a one-time solve cannot pay forever. Rounds re-evaluate every
# answering miner (~every submission interval), so this is several rounds long.
SECURITY_CATEGORY_FRESHNESS_SECONDS_ENV = "MASXAI_SECURITY_CATEGORY_FRESHNESS_SECONDS"
SECURITY_CATEGORY_FRESHNESS_SECONDS = 1800   # 30 minutes

# Bound on the encrypted blob the validator will download from a miner. A blob
# is a docker-save tarball plus SealedBox overhead; larger than the image cap is
# not a real agent, and an unbounded download is a denial of service the miner
# controls. Kept a little above MAX_FILE_SIZE_BYTES to allow for overhead.
SECURITY_BLOB_MAX_BYTES = 2 * 1024**3 + 16 * 1024**2  # ~2 GiB + slack
SECURITY_BLOB_DOWNLOAD_TIMEOUT_S = 900

# --- miner side: how the miner hosts its encrypted blob ----------------
# The miner serves the encrypted tarball from a tiny built-in static file
# server so no external registry or bucket is needed. BLOB_HOST is the
# host/IP the validator can reach it at (defaults to the miner's advertised
# axon external IP when unset); BLOB_PORT is the port that server binds.
SECURITY_BLOB_HOST_ENV = "MASXAI_SECURITY_BLOB_HOST"
SECURITY_BLOB_PORT_ENV = "MASXAI_SECURITY_BLOB_PORT"
SECURITY_BLOB_PORT = 8912

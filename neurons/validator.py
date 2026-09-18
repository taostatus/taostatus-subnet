"""
neurons/validator.py - MASXAI validator: LLM-key contribution pipeline.

The validator periodically asks each miner to contribute an LLM API key via
LLMKeySynapse, relays accepted submissions to the protocol backend, polls for
usage/efficiency reports, and sets on-chain weights from the efficiency of
the usage reported in the last completed chain epoch (self.scores).

A miner contributes between LLM_KEY_MIN_KEYS_PER_HOTKEY and
LLM_KEY_MAX_KEYS_PER_HOTKEY (5 and 5) distinct keys per submission --
_validate_miner_keys() sanitizes what a miner sent, and
llm_key_submission_round() declines to relay the whole batch if what
survives sanitization falls below the minimum, rather than relaying a
partial batch. The protocol
reports one row per single call, each tagged with which key served it
(key_id + provider/model).

Emission in each chain epoch pays for the reports of the epoch before it.
Rows accumulate per (hotkey, key) in self.llm_key_pending_calls for the
epoch the chain is in right now. When the chain starts a new epoch
(_roll_epoch_if_needed), that accumulator closes into
self.llm_key_last_epoch_calls and self.scores is recomputed from it alone
(_score_last_epoch) -- one pooled window per hotkey, reliability/quality/
latency/volume across all its live keys' calls, reward tier blended per
call. Every weight set during an epoch therefore pays for exactly one
complete epoch; nothing earned earlier carries over, so a miner with no good
report in the last epoch earns nothing in this one.

A confirmed-bad KEY stops earning immediately -- but only that key: a
report row with key_active=False, a DEAD/REVOKED roster entry, a fatal
auth/billing error category, or a per-key sub-window that trips a hard
floor drops exactly that key's rows (_kill_hotkey_key); its
healthy sibling keys keep earning, and a hotkey whose every key is dead has
nothing left to score.
"""

import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai.protocol import LLMKeySynapse
from masxai import constants as C
from masxai.bt_compat import bt
from masxai.discord import publish_key_submission, publish_round_summary
from masxai.env import load_env
from masxai.llm_key_client import open_llm_key_client_from_env
from masxai.scoring import (
    ema_update,
    has_fatal_error_category,
    llm_key_efficiency_score,
    sanitize_latency_ms,
    sanitize_quality_score,
)

# Pooled epoch windows score from the first good report: a miner with any
# good report in the last epoch earns for it. The call-volume floor
# (LLM_KEY_MIN_CALLS_FOR_SCORING) is kept only as the evidence bar for
# killing a single key on its own sub-window (_sub_window_floor_reason).
EPOCH_MIN_CALLS_FOR_SCORING = 1

try:
    from template.base.validator import BaseValidatorNeuron
except Exception:
    class BaseValidatorNeuron:  # type: ignore[no-redef]
        def __init__(self, *_, **__):
            raise RuntimeError("BaseValidatorNeuron requires a working bittensor install")

        def should_set_weights(self) -> bool:
            return False

        def set_weights(self):
            return None


def _env_float(name: str, default: float) -> float:
    load_env()
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


def _env_flag(name: str, default: bool = False) -> bool:
    load_env()
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    load_env()
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _state_file_path() -> Path:
    load_env()
    configured = os.getenv(C.VALIDATOR_STATE_FILE_ENV, "").strip()
    if configured:
        path = Path(configured).expanduser()
        return path if path.is_absolute() else Path.cwd() / path

    path = Path(C.STATE_FILE).expanduser()
    return path if path.is_absolute() else _repo_root() / path


class Validator(BaseValidatorNeuron):
    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)
        # Liveness signal: uid -> EMA of "responded to the LLM-key ask this
        # round," independent of whether the miner actually had a key to
        # contribute. Never a value/correctness signal.
        self.participation_scores: dict[int, float] = {}
        # None (unconfigured) is this pipeline's kill switch, checked before
        # every submission/report-poll round. self.scores (inherited from
        # BaseValidatorNeuron) is the last completed epoch's LLM-key efficiency.
        self.llm_key_client = open_llm_key_client_from_env()
        self.llm_key_hotkey_status: dict[str, dict[str, Any]] = {}
        # Per-hotkey accumulator of the raw single-call reports received in
        # the current chain epoch -- see module docstring. Persisted, with the
        # epoch it belongs to, so a restart within the same epoch keeps it.
        self.llm_key_pending_calls: dict[str, dict[str, Any]] = {}
        # The last completed epoch's accumulator (same shape) -- what
        # self.scores, and so this epoch's emission, is computed from.
        self.llm_key_last_epoch_calls: dict[str, dict[str, Any]] = {}
        # Start block of the chain epoch llm_key_pending_calls belongs to;
        # None until the first successful chain read.
        self.llm_key_epoch_start_block: Optional[int] = None
        self.last_llm_key_ask_at = 0.0
        self.last_llm_key_report_poll_at = 0.0
        self.last_llm_key_report_cursor: str = ""
        # In-memory only (not persisted): tracks how long report polls have
        # come back empty despite accepted keys on file. See
        # llm_key_report_poll_round()'s empty-reports warning.
        self.llm_key_reports_empty_since: float = 0.0
        self.load_masxai_state()
        bt.logging.info(
            "MASXAI validator initialized | "
            f"llm_key_enabled={self.llm_key_client is not None} "
            f"state_file={_state_file_path()}"
        )

    # ---------------------------------------------------------------- state
    def load_masxai_state(self):
        if not hasattr(self, "participation_scores"):
            self.participation_scores = {}
        if not hasattr(self, "llm_key_hotkey_status"):
            self.llm_key_hotkey_status = {}
        if not hasattr(self, "llm_key_pending_calls"):
            self.llm_key_pending_calls = {}
        if not hasattr(self, "llm_key_last_epoch_calls"):
            self.llm_key_last_epoch_calls = {}
        if not hasattr(self, "llm_key_epoch_start_block"):
            self.llm_key_epoch_start_block = None
        state_path = _state_file_path()
        if not state_path.exists():
            bt.logging.info(f"validator state file not found: {state_path}")
            return
        try:
            with state_path.open("r") as f:
                s = json.load(f)
            self.participation_scores = {
                int(k): float(v) for k, v in s.get("participation_scores", {}).items()
            }
            self.llm_key_hotkey_status = {
                str(k): v
                for k, v in s.get("llm_key_hotkey_status", {}).items()
                if isinstance(v, dict)
            }
            self.llm_key_pending_calls = {
                str(k): self._migrate_pending_entry(v)
                for k, v in s.get("llm_key_pending_calls", {}).items()
                if isinstance(v, dict)
            }
            self.last_llm_key_ask_at = float(s.get("last_llm_key_ask_at", 0.0))
            self.last_llm_key_report_poll_at = float(s.get("last_llm_key_report_poll_at", 0.0))
            self.last_llm_key_report_cursor = str(s.get("last_llm_key_report_cursor", ""))
            self.llm_key_last_epoch_calls = {
                str(k): self._migrate_pending_entry(v)
                for k, v in s.get("llm_key_last_epoch_calls", {}).items()
                if isinstance(v, dict)
            }
            # Absent in state written before per-epoch scoring: left None, so
            # the first epoch check discards that old accumulator rather than
            # paying it out as last epoch's work.
            epoch_start = s.get("llm_key_epoch_start_block")
            self.llm_key_epoch_start_block = None if epoch_start is None else int(epoch_start)
            scores = s.get("scores")
            if scores is not None:
                arr = np.array(scores, dtype=np.float32)
                if arr.shape == self.scores.shape:
                    self.scores = arr
                else:
                    bt.logging.warning(
                        f"Saved scores shape {arr.shape} does not match metagraph shape {self.scores.shape}. "
                        "Performing overlapping copy."
                    )
                    copy_len = min(len(arr), len(self.scores))
                    self.scores[:copy_len] = arr[:copy_len]
            self._drop_unbacked_scores()
            bt.logging.info(
                f"loaded state from {state_path}: "
                f"{len(self.llm_key_hotkey_status)} hotkey(s) tracked"
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"could not load state, starting fresh: {e}")

    def _drop_unbacked_scores(self) -> None:
        """Discard any restored score with no LLM-key usage behind it (see
        _has_llm_key_evidence).

        The pre-LLM-key subnet persisted its forecasting accuracy EMA under
        this file's same "scores" key, so an in-place upgrade silently
        inherits it as LLM-key weight. Masking it at submission time is not
        enough on its own: left in self.scores, that stale value would become
        payable the moment the hotkey's first usage report arrived, paying a
        miner at a level it never earned here. Dropping it at load means the
        miner earns again from zero, through reported usage, like everyone
        else.
        """
        dropped = {
            uid: float(self.scores[uid])
            for uid in range(len(self.scores))
            if float(self.scores[uid]) > 0.0 and not self._has_llm_key_evidence(uid)
        }
        if not dropped:
            return
        for uid in dropped:
            self.scores[uid] = 0.0
        bt.logging.warning(
            f"llm-key: discarded {len(dropped)} restored score(s) with no reported "
            f"LLM-key usage behind them (pre-LLM-key state file, or a uid that "
            f"changed hands): {dropped}"
        )

    @staticmethod
    def _migrate_pending_entry(entry: dict) -> dict:
        """Upgrade a pre-multi-key pending accumulator (flat per-hotkey
        counters) into the per-key shape: the old counters become one
        "legacy" sub-accumulator with an unresolved tier (tier None resolves
        at flush via the submission-time fallback). Current-shape entries
        pass through untouched, so this is idempotent."""
        if "keys" in entry:
            return entry
        if "success_count" not in entry:
            return {"keys": {}, "first_seen_at": entry.get("first_seen_at", 0.0),
                    "last_seen_at": entry.get("last_seen_at", 0.0)}
        return {
            "keys": {
                "legacy": {
                    "success_count": entry.get("success_count", 0),
                    "failure_count": entry.get("failure_count", 0),
                    "latency_ms_weighted_sum": entry.get("latency_ms_weighted_sum", 0.0),
                    "latency_weighted_count": entry.get("latency_weighted_count", 0),
                    "quality_weighted_sum": entry.get("quality_weighted_sum", 0.0),
                    "quality_weighted_count": entry.get("quality_weighted_count", 0),
                    "tier": None,
                },
            },
            "first_seen_at": entry.get("first_seen_at", 0.0),
            "last_seen_at": entry.get("last_seen_at", 0.0),
        }

    def save_masxai_state(self):
        try:
            state_path = _state_file_path()
            state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = state_path.with_name(f"{state_path.name}.tmp")
            with tmp_path.open("w") as f:
                json.dump(
                    {
                        "participation_scores": {
                            str(uid): score for uid, score in self.participation_scores.items()
                        },
                        "llm_key_hotkey_status": self.llm_key_hotkey_status,
                        "llm_key_pending_calls": self.llm_key_pending_calls,
                        "last_llm_key_ask_at": self.last_llm_key_ask_at,
                        "last_llm_key_report_poll_at": self.last_llm_key_report_poll_at,
                        "last_llm_key_report_cursor": self.last_llm_key_report_cursor,
                        "llm_key_last_epoch_calls": self.llm_key_last_epoch_calls,
                        "llm_key_epoch_start_block": self.llm_key_epoch_start_block,
                        "scores": self.scores.tolist(),
                    },
                    f,
                )
            os.replace(tmp_path, state_path)
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"could not save state: {e}")

    # ------------------------------------------------------------- weights
    def _record_participation(self, uid: int) -> None:
        """Bump a miner's liveness score for answering the LLM-key ask this
        round, whether or not it had a key to contribute.

        This is tracked purely for observability (is this miner's software
        online and responsive at all) and is never a value/correctness
        signal. It deliberately does NOT feed into submitted chain weight -
        see _blended_weight_array(): weight is earned only through a
        confirmed, currently-active contributed key, never merely by
        answering the ask.
        """
        alpha = _env_float(C.PARTICIPATION_EMA_ALPHA_ENV, C.PARTICIPATION_EMA_ALPHA)
        prev = self.participation_scores.get(int(uid), 0.0)
        self.participation_scores[int(uid)] = ema_update(prev, C.PARTICIPATION_REWARD, alpha=alpha)

    def _model_tier_weight(self, hotkey: str) -> float:
        """Legacy fallback tier: the provider/model this hotkey submitted
        back when it was single-key (stored flat on its status entry).
        Only consulted for report rows that carry no key identity of their
        own (pre-multi-key backend rows, or a migrated pending window) --
        every current row's tier comes from _tier_for_report() instead.
        Unknown/unlisted provider+model falls back to the default tier
        rather than erroring or scoring zero."""
        status = self.llm_key_hotkey_status.get(hotkey, {})
        key = f"{status.get('provider', '')}/{status.get('model', '')}"
        return C.LLM_KEY_MODEL_TIER_WEIGHTS.get(key, C.LLM_KEY_MODEL_TIER_DEFAULT_WEIGHT)

    def _tier_for_report(self, hotkey: str, report) -> float:
        """Reward tier for one usage row: taken from the row's OWN
        provider/model (each call is worth its own model's tier -- this is
        what makes a mixed 5-key fleet blend correctly and keeps stacked
        cheap keys from borrowing a top-tier multiplier), falling back to
        the legacy submission-time lookup for rows without key identity."""
        if report.provider and report.model:
            return C.LLM_KEY_MODEL_TIER_WEIGHTS.get(
                f"{report.provider}/{report.model}", C.LLM_KEY_MODEL_TIER_DEFAULT_WEIGHT
            )
        return self._model_tier_weight(hotkey)

    @staticmethod
    def _report_sub_key(report) -> str:
        """Stable per-key bucket id for a usage row: the backend's key row id
        when present (stable across slot replacements), else provider/model,
        else a single legacy bucket -- so old-backend rows degrade to
        exactly the previous one-key-per-hotkey behavior."""
        if getattr(report, "key_id", None) is not None:
            return str(report.key_id)
        if getattr(report, "provider", None) and getattr(report, "model", None):
            return f"{report.provider}/{report.model}"
        return "legacy"

    # ------------------------------------------------------------- epochs
    def _current_epoch_start_block(self) -> Optional[int]:
        """Start block of the chain epoch this subnet is in right now, or
        None when it can't be read (no chain connection yet, RPC failure).

        Read from the chain rather than computed from tempo: the epoch
        schedule isn't a fixed formula (owner-triggered epochs, runtime
        changes), and blocks_since_last_step is the chain's own answer. Both
        values are read at one block, so a block ticking between the two
        reads can't shift the start and fake an epoch change."""
        subtensor = getattr(self, "subtensor", None)
        netuid = getattr(getattr(self, "config", None), "netuid", None)
        if subtensor is None or netuid is None:
            return None
        try:
            block = int(subtensor.get_current_block())
            since = subtensor.blocks_since_last_step(netuid, block=block)
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"llm-key: could not read the current epoch: {e}")
            return None
        if since is None:
            return None
        return block - int(since)

    def _epoch_length_blocks(self) -> Optional[int]:
        """Nominal epoch length (tempo + 1 blocks), or None if unreadable."""
        subtensor = getattr(self, "subtensor", None)
        netuid = getattr(getattr(self, "config", None), "netuid", None)
        if subtensor is None or netuid is None:
            return None
        try:
            tempo = subtensor.tempo(netuid)
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"llm-key: could not read tempo: {e}")
            return None
        return None if not tempo else int(tempo) + 1

    def _roll_epoch_if_needed(self) -> None:
        """Close the collecting epoch when the chain has moved to a new one.

        The epoch that just ended becomes the one being paid: its
        accumulator moves to llm_key_last_epoch_calls and self.scores is
        recomputed from it, so every weight set during the new epoch pays
        for the complete previous epoch -- nothing earned earlier carries
        over, and a miner with no good report in that epoch earns nothing.

        The closed accumulator is only paid if it really is the immediately
        preceding epoch. If the validator was down across more than one
        epoch, or the state predates per-epoch scoring (no epoch recorded),
        it is discarded instead of being paid out as last epoch's work. If
        the epoch can't be read, nothing changes -- the accumulator keeps
        collecting and the next successful read decides."""
        start = self._current_epoch_start_block()
        previous = self.llm_key_epoch_start_block
        if start is None or start == previous:
            return
        epoch_length = self._epoch_length_blocks()
        if (
            previous is not None
            and epoch_length is not None
            and 0 < start - previous < epoch_length / 2
        ):
            # An epoch can end early (a subnet owner can trigger one). A
            # sliver that short is not an epoch of work: keep paying the
            # real previous epoch, and let the rows it collected carry into
            # the epoch that just started.
            bt.logging.info(
                f"llm-key: epoch at block {previous} lasted only {start - previous} "
                f"block(s); folding it into the epoch starting at block {start}"
            )
            self.llm_key_epoch_start_block = start
            return
        # 1.5x tolerates a short owner-triggered epoch or an irregular
        # boundary, while a gap of two whole epochs never passes.
        contiguous = (
            previous is not None
            and epoch_length is not None
            and 0 < start - previous <= 1.5 * epoch_length
        )
        closed = self.llm_key_pending_calls if contiguous else {}
        if contiguous:
            bt.logging.info(
                f"llm-key: epoch started at block {start}; paying the epoch that began at "
                f"block {previous} ({len(closed)} hotkey window(s))"
            )
        else:
            bt.logging.info(
                f"llm-key: epoch started at block {start}; previous recorded epoch start "
                f"{previous} is not the immediately preceding epoch (epoch length "
                f"{epoch_length}) -- discarding {len(self.llm_key_pending_calls)} "
                "hotkey window(s), nothing to pay this epoch"
            )
        self.llm_key_last_epoch_calls = closed
        self.llm_key_pending_calls = {}
        self.llm_key_epoch_start_block = start
        self._score_last_epoch()

    def _hotkey_key_states(self, hotkey: str) -> dict[str, dict[str, Any]]:
        """The per-key tracking map inside a hotkey's status entry, keyed by
        the same sub-key scheme as _report_sub_key (created lazily so legacy
        state entries keep working untouched)."""
        status = self.llm_key_hotkey_status.setdefault(hotkey, {})
        return status.setdefault("keys", {})

    def _kill_hotkey_key(self, hotkey: str, sub_key: str, *, reason: str) -> None:
        """Immediate, surgical cut for ONE confirmed-bad key: mark it locally
        dead and drop its rows from both the epoch being paid and the epoch
        being collected, so it stops earning from the next score recompute
        while the hotkey's healthy sibling keys keep earning. A hotkey whose
        every key is dead has nothing left to score. Safe to call repeatedly
        (the roster re-reports DEAD every poll)."""
        entry = self._hotkey_key_states(hotkey).setdefault(sub_key, {})
        if entry.get("alive") is not False:
            entry["alive"] = False
            entry["killed_reason"] = reason
            bt.logging.info(f"llm-key: killed key {sub_key} of hotkey={hotkey} ({reason})")
        for windows in (self.llm_key_pending_calls, self.llm_key_last_epoch_calls):
            acc = windows.get(hotkey)
            if acc is not None:
                acc.get("keys", {}).pop(sub_key, None)
                if not acc.get("keys"):
                    windows.pop(hotkey, None)

    async def _poll_llm_key_roster(self) -> None:
        """Precise, near-real-time per-key DEAD/REVOKED detection via
        GET /llm-keys/roster (one entry per key): the protocol has confirmed
        that key is gone, so its rows are dropped immediately rather than
        paying out until the epoch rolls. A
        hotkey's healthy sibling keys are untouched. Idempotent across polls
        (the roster re-reports DEAD forever). Best-effort -- a failure here
        just leaves the key earning until the next epoch reset at most."""
        client = self.llm_key_client
        if client is None:
            return
        try:
            roster = await client.get_key_statuses()
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"llm-key: roster poll failed: {e}")
            return
        for entry in roster:
            if entry.status not in ("DEAD", "REVOKED"):
                continue
            status = self.llm_key_hotkey_status.get(entry.hotkey)
            if status is None:
                continue
            if entry.key_id is not None:
                sub_key = str(entry.key_id)
            elif entry.provider and entry.model:
                sub_key = f"{entry.provider}/{entry.model}"
            else:
                sub_key = "legacy"
            self._kill_hotkey_key(
                entry.hotkey,
                sub_key,
                reason=f"roster reports key {entry.status}",
            )

    def _fold_report_into_pending(self, hotkey: str, report, now: float) -> None:
        """Fold one raw single-call usage-report row into its key's
        sub-accumulator inside the hotkey's rolling window. A malformed row
        (negative counts) is dropped entirely -- consistent with
        llm_key_efficiency_score()'s "skip, don't guess" treatment of the
        same condition; latency/quality are sanitized and weighted-averaged
        independently, so a bad reading in one never disqualifies the row's
        contribution to the other.

        A successful row also revives a locally-killed key: a replaced slot
        keeps its backend key_id, so fresh working traffic on it is direct
        evidence the miner swapped in a working key."""
        if report.success_count < 0 or report.failure_count < 0:
            bt.logging.warning(
                f"llm-key: dropping malformed report for hotkey={hotkey} "
                f"(negative success/failure count: {report.success_count}/{report.failure_count})"
            )
            return
        acc = self.llm_key_pending_calls.setdefault(
            hotkey, {"keys": {}, "first_seen_at": now, "last_seen_at": now},
        )
        sub_key = self._report_sub_key(report)
        sub = acc["keys"].setdefault(
            sub_key,
            {
                "success_count": 0,
                "failure_count": 0,
                "latency_ms_weighted_sum": 0.0,
                "latency_weighted_count": 0,
                "quality_weighted_sum": 0.0,
                "quality_weighted_count": 0,
                "tier": self._tier_for_report(hotkey, report),
            },
        )
        # Refresh the tier each fold -- a replaced slot keeps its key_id but
        # may declare a different model.
        sub["tier"] = self._tier_for_report(hotkey, report)
        row_calls = report.success_count + report.failure_count
        sub["success_count"] += report.success_count
        sub["failure_count"] += report.failure_count
        latency = sanitize_latency_ms(report.avg_latency_ms)
        if latency is not None and row_calls > 0:
            sub["latency_ms_weighted_sum"] += latency * row_calls
            sub["latency_weighted_count"] += row_calls
        quality = sanitize_quality_score(getattr(report, "avg_quality_score", None))
        if quality is not None and row_calls > 0:
            sub["quality_weighted_sum"] += quality * row_calls
            sub["quality_weighted_count"] += row_calls
        acc["last_seen_at"] = now

        if report.success_count > 0:
            entry = self._hotkey_key_states(hotkey).setdefault(sub_key, {})
            if getattr(report, "provider", None):
                entry["provider"] = report.provider
                entry["model"] = report.model
            if entry.get("alive") is False:
                entry["alive"] = True
                entry.pop("killed_reason", None)
                bt.logging.info(
                    f"llm-key: key {sub_key} of hotkey={hotkey} is serving successful "
                    "calls again (slot replaced or recovered); reviving it"
                )

    def _sub_window_floor_reason(self, sub: dict, *, min_calls: int) -> Optional[str]:
        """Does one key's sub-window, on its own evidence, trip a hard floor?
        Only conclusive at the configured call-volume floor -- a couple of
        bad calls is signal, not a verdict."""
        total = int(sub.get("success_count", 0)) + int(sub.get("failure_count", 0))
        if total < min_calls:
            return None
        reliability_floor = _env_float(
            C.LLM_KEY_RELIABILITY_HARD_FLOOR_ENV, C.LLM_KEY_RELIABILITY_HARD_FLOOR
        )
        if sub.get("success_count", 0) / total < reliability_floor:
            return (
                f"per-key reliability floor ({sub['success_count']} ok / "
                f"{sub['failure_count']} failed)"
            )
        qcount = int(sub.get("quality_weighted_count", 0))
        min_graded = _env_int(
            C.LLM_KEY_QUALITY_FLOOR_MIN_GRADED_ENV, C.LLM_KEY_QUALITY_FLOOR_MIN_GRADED
        )
        if qcount >= min_graded:
            avg_quality = sub["quality_weighted_sum"] / qcount
            quality_floor = _env_float(
                C.LLM_KEY_QUALITY_HARD_FLOOR_ENV, C.LLM_KEY_QUALITY_HARD_FLOOR
            )
            if avg_quality < quality_floor:
                return f"per-key quality floor (avg quality {avg_quality:.2f} over {qcount} graded)"
        return None

    def _pooled_window_reward(self, hotkey: str, subs: list[dict]) -> float:
        """Efficiency reward for one hotkey's pooled epoch window: all its
        live keys' calls scored together, the reward tier blended per call
        (each call is worth its own model's tier, so a mixed fleet averages
        by delivered traffic and stacked cheap keys can't borrow a top-tier
        multiplier). Any good report counts -- no call-volume floor -- but the
        hard floors still apply: a majority-failing or confirmed-low-quality
        window is worth 0.0."""
        success_count = sum(int(s.get("success_count", 0)) for s in subs)
        failure_count = sum(int(s.get("failure_count", 0)) for s in subs)
        total = success_count + failure_count
        latency_sum = sum(float(s.get("latency_ms_weighted_sum", 0.0)) for s in subs)
        latency_count = sum(int(s.get("latency_weighted_count", 0)) for s in subs)
        quality_sum = sum(float(s.get("quality_weighted_sum", 0.0)) for s in subs)
        quality_count = sum(int(s.get("quality_weighted_count", 0)) for s in subs)
        avg_latency_ms = latency_sum / latency_count if latency_count > 0 else None
        avg_quality = quality_sum / quality_count if quality_count > 0 else None

        # A migrated legacy sub-window (tier None) resolves via the
        # submission-time fallback.
        def _sub_tier(sub: dict) -> float:
            tier = sub.get("tier")
            return float(tier) if tier is not None else self._model_tier_weight(hotkey)

        blended_tier = (
            sum(
                _sub_tier(s) * (int(s.get("success_count", 0)) + int(s.get("failure_count", 0)))
                for s in subs
            )
            / total
            if total > 0
            else self._model_tier_weight(hotkey)
        )
        reward = llm_key_efficiency_score(
            success_count=success_count,
            failure_count=failure_count,
            avg_latency_s=avg_latency_ms / 1000.0 if avg_latency_ms is not None else None,
            key_active=True,
            quality_score=avg_quality,
            model_tier_weight=blended_tier,
            min_calls_for_scoring=EPOCH_MIN_CALLS_FOR_SCORING,
            quality_call_count=quality_count,
            reliability_floor=_env_float(
                C.LLM_KEY_RELIABILITY_HARD_FLOOR_ENV, C.LLM_KEY_RELIABILITY_HARD_FLOOR
            ),
            quality_floor=_env_float(
                C.LLM_KEY_QUALITY_HARD_FLOOR_ENV, C.LLM_KEY_QUALITY_HARD_FLOOR
            ),
            quality_floor_min_graded=_env_int(
                C.LLM_KEY_QUALITY_FLOOR_MIN_GRADED_ENV, C.LLM_KEY_QUALITY_FLOOR_MIN_GRADED
            ),
        )
        return float(reward or 0.0)

    def _score_last_epoch(self) -> None:
        """Recompute self.scores from the last completed epoch's reports
        alone -- the epoch whose work the current epoch's emission pays for.

        Each hotkey with rows in that epoch is scored as one pooled window
        (see _pooled_window_reward); every uid without a good report in it
        scores 0.0. Before pooling, each key's own sub-window is checked
        against the hard floors: a single junk key with enough evidence is
        killed and excluded, so it can't hide inside an otherwise healthy
        fleet's average -- the pooled floors then only trip when the fleet
        as a whole is failing. Keys killed since the epoch closed are
        excluded too, so a confirmed-bad key stops earning immediately."""
        min_calls = _env_int(
            C.LLM_KEY_MIN_CALLS_FOR_SCORING_ENV, C.LLM_KEY_MIN_CALLS_FOR_SCORING
        )
        hotkeys = list(getattr(self.metagraph, "hotkeys", []))
        scores = np.zeros(len(self.scores), dtype=np.float32)
        windows = self.llm_key_last_epoch_calls
        for hotkey in list(windows):
            for sub_key, sub in list(windows[hotkey].get("keys", {}).items()):
                reason = self._sub_window_floor_reason(sub, min_calls=min_calls)
                if reason is not None:
                    self._kill_hotkey_key(hotkey, sub_key, reason=reason)
            acc = windows.get(hotkey)
            if acc is None:
                continue  # everything this window held was killed
            key_states = self._hotkey_key_states(hotkey)
            subs = [
                sub
                for sub_key, sub in acc.get("keys", {}).items()
                if key_states.get(sub_key, {}).get("alive", True)
            ]
            if not subs:
                continue
            try:
                uid = hotkeys.index(hotkey)
            except ValueError:
                continue  # deregistered since its rows arrived
            if uid >= len(scores):
                bt.logging.warning(
                    f"llm-key: uid={uid} out of range for scores array (len={len(scores)}); "
                    f"skipping hotkey={hotkey} (metagraph resize race?)"
                )
                continue
            scores[uid] = self._pooled_window_reward(hotkey, subs)
        self.scores = scores

    def _has_llm_key_evidence(self, uid: int) -> bool:
        """Has this validator seen the protocol report usage for the hotkey
        that currently holds `uid`, on a key it hasn't locally killed?

        A positive self.scores entry is only earnings if an LLM-key report
        put it there. Without that evidence it's a leftover, and this subnet
        pays nothing for leftovers:

        - a pre-LLM-key state file (the forecasting subnet persisted its own
          accuracy EMA under the same "scores" key), which would otherwise
          keep paying miners forever for work this subnet no longer measures;
        - a score sitting at a uid whose hotkey has since changed hands
          (a reshuffle while the validator was down leaves resync_metagraph
          nothing to compare against).

        Deliberately not a recency check: recency is the epoch reset's job
        (_roll_epoch_if_needed).
        """
        uid = int(uid)
        hotkeys = getattr(self.metagraph, "hotkeys", [])
        if not (0 <= uid < len(hotkeys)):
            return False
        # Read defensively: the base class syncs (and could set weights) inside
        # super().__init__(), before this subclass has built its status map.
        status = getattr(self, "llm_key_hotkey_status", {}).get(hotkeys[uid])
        if not status:
            return False
        recorded_uid = status.get("uid")
        if recorded_uid is None or int(recorded_uid) != uid:
            return False
        if status.get("last_report_at") is None:
            return False  # keys may be on file, but no reported usage yet
        key_states = status.get("keys") or {}
        if key_states and not any(state.get("alive", True) for state in key_states.values()):
            return False  # every key this hotkey has is confirmed dead
        return True

    def _blended_weight_array(self) -> np.ndarray:
        """Weight is earned only through confirmed LLM-key efficiency.

        self.scores[uid] is positive only when the protocol has reported
        real, verified usage in the last completed epoch for a key it currently
        considers active - merely answering the ask, or having a key that's
        been submitted but not yet confirmed working, earns nothing here. Key
        validity isn't something the validator can judge on its own, so it
        doesn't extend weight on the strength of a submission alone, only on
        the strength of reported real usage.

        A score with no LLM-key usage behind it (see _has_llm_key_evidence)
        is dropped from the submitted array rather than trusted -- e.g. a
        uid whose hotkey changed hands mid-epoch. The masking is local to the
        submission; self.scores is left alone.

        participation_scores is intentionally excluded - it's tracked for
        liveness/observability only (see _record_participation), never
        blended into submitted weight.

        Whatever this returns is then wrapped by the template's own burn
        allocation (masxai/constants.py: BURN_UID/BURN_PERCENTAGE), which
        unconditionally reserves the large majority of emission for the burn
        uid regardless of how much real efficiency data exists here - see
        set_weights().
        """
        weights = np.nan_to_num(
            np.asarray(self.scores, dtype=np.float32),
            nan=0.0,
            posinf=0.0,
            neginf=0.0,
        )
        unbacked = [
            uid
            for uid in range(len(weights))
            if weights[uid] > 0.0 and not self._has_llm_key_evidence(uid)
        ]
        if unbacked:
            bt.logging.info(
                f"llm-key: withholding weight from {len(unbacked)} uid(s) with no "
                f"reported LLM-key usage behind their score: {unbacked}"
            )
            weights[unbacked] = 0.0
        return weights

    def set_weights(self):
        """Always submit weights so the validator stays active on-chain.

        First brings self.scores up to date: if the chain has moved to a new
        epoch, the epoch that just ended becomes the one being paid; then the
        scores are recomputed from that last completed epoch's reports alone
        (dropping any key killed since). The submitted array is the nan-safe
        result (see _blended_weight_array). The template's own burn
        allocation (BURN_UID/BURN_PERCENTAGE) further reserves most of
        emission for the burn uid before anything reaches the chain.
        """
        # Read defensively: the base class can reach here from inside
        # super().__init__(), before this subclass has built its state.
        if hasattr(self, "llm_key_pending_calls"):
            self._roll_epoch_if_needed()
            self._score_last_epoch()
        original_scores = self.scores
        self.scores = self._blended_weight_array()
        try:
            return super().set_weights()
        finally:
            self.scores = original_scores

    # ---------------------------------------------------------- llm-key pipeline
    async def llm_key_submission_round(self) -> None:
        """Ask every eligible miner for its contributed LLM key, relay
        accepted submissions to the protocol backend, and record liveness
        participation for every miner that answered (whether or not it had a
        key to contribute).

        No-op if llm_key_client is None (unconfigured). The protocol's public
        key and allowed-models list are fetched fresh every round rather than
        cached, so a possible protocol-side transport-keypair rotation can
        never cause a submission encrypted against a stale key.
        """
        client = self.llm_key_client
        if client is None:
            return
        now = time.time()
        interval = max(
            0.0,
            _env_float(
                C.LLM_KEY_SUBMISSION_INTERVAL_SECONDS_ENV,
                C.LLM_KEY_SUBMISSION_INTERVAL_SECONDS,
            ),
        )
        if self.last_llm_key_ask_at and now - self.last_llm_key_ask_at < interval:
            return

        try:
            public_key = await client.get_public_key()
            allowed_models = await client.get_allowed_models()
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"llm-key: could not fetch public key/allowed models: {e}")
            backoff = min(
                max(
                    0.0,
                    _env_float(
                        C.LLM_KEY_ASK_FAILURE_BACKOFF_SECONDS_ENV,
                        C.LLM_KEY_ASK_FAILURE_BACKOFF_SECONDS,
                    ),
                ),
                interval,
            )
            self.last_llm_key_ask_at = now - interval + backoff
            return

        miner_uids = self.get_miner_uids()
        if not miner_uids:
            self.last_llm_key_ask_at = now
            return

        synapse = LLMKeySynapse(
            request_id=uuid.uuid4().hex,
            protocol_pubkey_id=public_key.pubkey_id,
            protocol_pubkey_b64=public_key.pubkey_b64,
            allowed_models=[f"{m.provider}/{m.model}" for m in allowed_models],
            issued_at=now,
        )
        axons = [self.metagraph.axons[uid] for uid in miner_uids]
        responses = await self.dendrite(
            axons=axons,
            synapse=synapse,
            deserialize=False,
            timeout=C.LLM_KEY_QUERY_TIMEOUT,
        )

        answered = 0
        submitted = 0
        # (hotkey, uid, error) per failed relay -- named individually in the
        # round summary, since a failure belongs to one miner and a bare
        # count tells that miner nothing.
        relay_failures: list[tuple[str, int, str]] = []
        for uid, resp in zip(miner_uids, responses):
            if getattr(resp, "has_key", None) is None:
                continue  # timed out / never reached the miner's forward_llm_key
            answered += 1
            self._record_participation(uid)
            if getattr(resp, "version", None) != synapse.version:
                bt.logging.warning(
                    f"llm-key: uid={uid} responded with protocol version "
                    f"{getattr(resp, 'version', None)!r} (expected {synapse.version}); "
                    "skipping key submission this round -- see CLAUDE.md 'Before Changing Protocol'"
                )
                continue
            if not resp.has_key:
                continue
            keys_payload = self._validate_miner_keys(uid, getattr(resp, "keys", None))
            if len(keys_payload) < C.LLM_KEY_MIN_KEYS_PER_HOTKEY:
                if keys_payload:
                    bt.logging.warning(
                        f"llm-key: uid={uid} sent {len(keys_payload)} valid key(s), "
                        f"below the required minimum of {C.LLM_KEY_MIN_KEYS_PER_HOTKEY}; "
                        "not relaying this round"
                    )
                continue
            hotkey = self.metagraph.hotkeys[int(uid)]
            try:
                result = await client.submit_keys(
                    hotkey=hotkey, uid=int(uid), keys=keys_payload,
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"llm-key: submit failed for uid={uid}: {e}")
                # Counted for the round summary: a relay that never reached
                # the protocol produces no per-hotkey result to announce, so
                # without this the round would look silently empty.
                relay_failures.append((hotkey, int(uid), str(e)[:160]))
                continue
            entry = self.llm_key_hotkey_status.setdefault(hotkey, {})
            entry.update({
                "uid": int(uid),
                "accepted": result.accepted,
                "status": result.status,
                "reason": result.reason,
                "submitted_at": now,
            })
            key_states = entry.setdefault("keys", {})
            for key_result in result.results:
                if key_result.key_id is None:
                    continue  # rejected slot: no stored key row to track
                state = key_states.setdefault(str(key_result.key_id), {})
                state.update({
                    "slot": key_result.slot,
                    "provider": key_result.provider,
                    "model": key_result.model,
                    "accepted": key_result.accepted,
                    "status": key_result.status,
                    "reason": key_result.reason,
                })
                if key_result.accepted:
                    # A freshly accepted (possibly replacement) key starts
                    # clean -- never inherits its predecessor's local kill.
                    state["alive"] = True
                    state.pop("killed_reason", None)

            # Tell the channel what the protocol decided about each slot --
            # this is the only point where that outcome is visible to anyone,
            # and the miner has no other way to learn it. Best-effort by
            # construction (see masxai/discord.py): a webhook problem must
            # never cost a miner its contribution.
            await publish_key_submission(
                hotkey=hotkey, uid=int(uid), results=result.results,
                **self._network_labels(),
            )
            if result.accepted:
                submitted += 1

        bt.logging.info(
            f"llm-key submission round: answered={answered}/{len(miner_uids)} "
            f"contributed={submitted}"
        )
        await publish_round_summary(
            asked=len(miner_uids), answered=answered, contributed=submitted,
            relay_failures=relay_failures,
            **self._network_labels(),
        )
        self.last_llm_key_ask_at = now

    def _network_labels(self) -> dict[str, Any]:
        """Which chain this validator is on, for tagging announcements.

        Read defensively: config shape varies across bittensor versions, and
        test doubles supply only what they exercise. A missing label is
        cosmetic -- it must never break a submission round.
        """
        cfg = getattr(self, "config", None)
        netuid = getattr(cfg, "netuid", None)
        network = getattr(getattr(cfg, "subtensor", None), "network", None)
        return {
            "netuid": netuid if isinstance(netuid, int) else None,
            "network": network if isinstance(network, str) else None,
        }

    def _validate_miner_keys(self, uid: int, raw_keys) -> list[dict[str, Any]]:
        """Sanitize a miner's key batch before relaying it: cap at
        LLM_KEY_MAX_KEYS_PER_HOTKEY, require every field, and require sane,
        unique slots -- a hostile miner must not be able to inflate the
        relay or smuggle malformed entries to the protocol."""
        if not isinstance(raw_keys, list):
            return []
        payload: list[dict[str, Any]] = []
        seen_slots: set[int] = set()
        for item in raw_keys:
            if len(payload) >= C.LLM_KEY_MAX_KEYS_PER_HOTKEY:
                bt.logging.warning(
                    f"llm-key: uid={uid} sent more than "
                    f"{C.LLM_KEY_MAX_KEYS_PER_HOTKEY} keys; ignoring the extras"
                )
                break
            if not isinstance(item, dict):
                continue
            slot = item.get("slot")
            provider = str(item.get("provider", "")).strip()
            model = str(item.get("model", "")).strip()
            blob = str(item.get("encrypted_key_blob", "")).strip()
            pubkey_id = str(item.get("pubkey_id_used", "")).strip()
            if (
                not isinstance(slot, int)
                or not (0 <= slot < C.LLM_KEY_MAX_KEYS_PER_HOTKEY)
                or slot in seen_slots
                or not provider
                or not model
                or not blob
                or not pubkey_id
            ):
                bt.logging.debug(f"llm-key: uid={uid} sent a malformed key entry; skipping it")
                continue
            seen_slots.add(slot)
            payload.append({
                "slot": slot,
                "provider": provider,
                "model": model,
                "encrypted_key_blob": blob,
                "blob_encoding": str(item.get("blob_encoding", "nacl-sealedbox-v1")),
                "pubkey_id_used": pubkey_id,
            })
        return payload

    def _prune_llm_key_hotkey_status(self, now: float) -> None:
        """Evict llm_key_hotkey_status entries for hotkeys no longer present
        in the metagraph, after a grace period of continuous absence -- so a
        metagraph-resize race or a hotkey that re-registers shortly after
        dropping out never loses its tracked state. Runs once per
        report-poll round."""
        current_hotkeys = set(self.metagraph.hotkeys)
        grace = max(
            0.0,
            _env_float(
                C.LLM_KEY_HOTKEY_STATUS_EVICTION_GRACE_SECONDS_ENV,
                C.LLM_KEY_HOTKEY_STATUS_EVICTION_GRACE_SECONDS,
            ),
        )
        evicted = []
        for hotkey, status in list(self.llm_key_hotkey_status.items()):
            if hotkey in current_hotkeys:
                status.pop("_missing_since", None)
                continue
            missing_since = status.get("_missing_since")
            if missing_since is None:
                status["_missing_since"] = now
                continue
            if now - float(missing_since) >= grace:
                del self.llm_key_hotkey_status[hotkey]
                self.llm_key_pending_calls.pop(hotkey, None)
                evicted.append(hotkey)
        if evicted:
            bt.logging.info(
                f"llm-key: evicted {len(evicted)} stale hotkey-status entry(ies): {evicted}"
            )

    async def llm_key_report_poll_round(self) -> None:
        """Pull usage reports since the last cursor into the collecting
        epoch's accumulator, poll the roster for precise DEAD/REVOKED
        detection, and recompute self.scores from the last completed epoch.
        Starts by closing the collecting epoch if the chain has moved on, so
        rows fetched now count toward the epoch they arrive in. No-op if
        llm_key_client is None (unconfigured)."""
        client = self.llm_key_client
        if client is None:
            return
        now = time.time()
        interval = max(
            0.0,
            _env_float(
                C.LLM_KEY_REPORT_POLL_INTERVAL_SECONDS_ENV,
                C.LLM_KEY_REPORT_POLL_INTERVAL_SECONDS,
            ),
        )
        if (
            self.last_llm_key_report_poll_at
            and now - self.last_llm_key_report_poll_at < interval
        ):
            return

        self._roll_epoch_if_needed()
        try:
            reports, next_since = await client.get_reports(
                since=self.last_llm_key_report_cursor or None
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"llm-key: report poll failed: {e}")
            backoff = min(
                max(
                    0.0,
                    _env_float(
                        C.LLM_KEY_REPORT_POLL_FAILURE_BACKOFF_SECONDS_ENV,
                        C.LLM_KEY_REPORT_POLL_FAILURE_BACKOFF_SECONDS,
                    ),
                ),
                interval,
            )
            self.last_llm_key_report_poll_at = now - interval + backoff
            return

        processed = 0
        for report in reports:
            try:
                uid = self.metagraph.hotkeys.index(report.hotkey)
            except ValueError:
                # Unknown/deregistered hotkey - skip rather than guess a mapping.
                continue
            self.llm_key_hotkey_status.setdefault(report.hotkey, {})
            self.llm_key_hotkey_status[report.hotkey].update(
                {
                    "uid": int(uid),
                    "last_report_at": now,
                    "key_active": report.key_active,
                }
            )
            sub_key = self._report_sub_key(report)
            if not report.key_active:
                # Calls made while this key was still alive are moot once
                # it's confirmed dead -- cut exactly this key's contribution
                # immediately; the hotkey's other keys keep earning.
                self._kill_hotkey_key(
                    report.hotkey, sub_key, reason="report row marked key inactive"
                )
            elif has_fatal_error_category(report.error_categories):
                # The provider itself rejected this key (bad credentials /
                # exhausted budget / permission block) -- conclusive on a
                # single row, no call-volume floor needed. The protocol may
                # still list the key ACTIVE (its health check can lag or be
                # disabled), so this is the validator's own fast path to
                # cutting a key that demonstrably doesn't work.
                self._kill_hotkey_key(
                    report.hotkey,
                    sub_key,
                    reason=(
                        "fatal error category in usage report: "
                        f"{sorted(report.error_categories)}"
                    ),
                )
            else:
                self._fold_report_into_pending(report.hotkey, report, now)
            processed += 1

        await self._poll_llm_key_roster()
        self._prune_llm_key_hotkey_status(now)
        self._score_last_epoch()

        if next_since:
            self.last_llm_key_report_cursor = str(next_since)
        if reports:
            self.llm_key_reports_empty_since = 0.0
            bt.logging.info(
                f"llm-key report poll: {processed}/{len(reports)} report(s) processed, "
                f"{int(np.count_nonzero(self.scores > 0))} uid(s) earning from last epoch"
            )
        else:
            accepted = sum(1 for s in self.llm_key_hotkey_status.values() if s.get("accepted"))
            if accepted:
                if not self.llm_key_reports_empty_since:
                    self.llm_key_reports_empty_since = now
                empty_hours = (now - self.llm_key_reports_empty_since) / 3600.0
                threshold_hours = max(
                    0.0,
                    _env_float(
                        C.LLM_KEY_REPORTS_EMPTY_WARN_SECONDS_ENV,
                        C.LLM_KEY_REPORTS_EMPTY_WARN_SECONDS,
                    ),
                ) / 3600.0
                if empty_hours >= threshold_hours:
                    bt.logging.warning(
                        f"llm-key report poll: zero usage reports for {empty_hours:.1f}h despite "
                        f"{accepted} accepted key(s) on file -- the protocol backend may not be "
                        "feeding usage/efficiency data (GET /llm-keys/reports empty); on-chain "
                        "weight for LLM-key efficiency will stay at zero until this resolves"
                    )
        self.last_llm_key_report_poll_at = now

    def get_miner_uids(self) -> list[int]:
        """All registered neurons that are serving an axon (i.e., miners)."""
        uids = []
        query_validators = _env_flag(C.QUERY_VALIDATOR_UIDS_ENV, False)
        validator_permit = getattr(self.metagraph, "validator_permit", None)
        for uid in range(self._metagraph_size()):
            if not self.metagraph.axons[uid].is_serving:
                continue
            if self.metagraph.hotkeys[uid] == self.wallet.hotkey.ss58_address:
                continue
            if (
                not query_validators
                and validator_permit is not None
                and bool(validator_permit[uid])
            ):
                continue
            uids.append(uid)
        return uids

    def _metagraph_size(self) -> int:
        n = getattr(self.metagraph, "n", 0)
        return int(n.item()) if hasattr(n, "item") else int(n)

    # ------------------------------------------------------------- forward
    async def forward(self):
        """One validator step: ask for LLM keys, relay + poll reports, persist."""
        lock = getattr(self, "lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self.lock = lock
        async with lock:
            if self.llm_key_client is not None:
                await self.llm_key_submission_round()
                await self.llm_key_report_poll_round()
            self.save_masxai_state()
        # brief pause so we don't hot-loop; the base class also paces by epoch
        await asyncio.sleep(5)


if __name__ == "__main__":
    with Validator() as validator:
        while True:
            thread = getattr(validator, "thread", None)
            if thread is not None and not thread.is_alive():
                bt.logging.error(
                    "MASXAI validator background loop stopped; exiting instead of "
                    "continuing stale alive logs"
                )
                raise SystemExit(1)
            tracked = len(validator.llm_key_hotkey_status)
            contributing = sum(
                1
                for status in validator.llm_key_hotkey_status.values()
                if status.get("accepted")
            )
            bt.logging.info(
                f"MASXAI validator alive | llm_key_enabled={validator.llm_key_client is not None} "
                f"hotkeys_tracked={tracked} contributing={contributing} | "
                f"{time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            time.sleep(30)

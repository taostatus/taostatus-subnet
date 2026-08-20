"""
neurons/validator.py - MASXAI validator: LLM-key contribution pipeline.

The validator periodically asks each miner to contribute an LLM API key via
LLMKeySynapse, relays accepted submissions to the protocol backend, polls for
usage/efficiency reports, and blends a liveness-participation signal with the
protocol-reported efficiency EMA (self.scores) into on-chain weights.
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
from masxai.env import load_env
from masxai.llm_key_client import open_llm_key_client_from_env
from masxai.scoring import ema_update, llm_key_efficiency_score

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
        # BaseValidatorNeuron) is the persisted LLM-key efficiency EMA.
        self.llm_key_client = open_llm_key_client_from_env()
        self.llm_key_hotkey_status: dict[str, dict[str, Any]] = {}
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
            self.last_llm_key_ask_at = float(s.get("last_llm_key_ask_at", 0.0))
            self.last_llm_key_report_poll_at = float(s.get("last_llm_key_report_poll_at", 0.0))
            self.last_llm_key_report_cursor = str(s.get("last_llm_key_report_cursor", ""))
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
            bt.logging.info(
                f"loaded state from {state_path}: "
                f"{len(self.llm_key_hotkey_status)} hotkey(s) tracked"
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"could not load state, starting fresh: {e}")

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
                        "last_llm_key_ask_at": self.last_llm_key_ask_at,
                        "last_llm_key_report_poll_at": self.last_llm_key_report_poll_at,
                        "last_llm_key_report_cursor": self.last_llm_key_report_cursor,
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
        """Look up the reward tier for whatever provider/model this hotkey
        last submitted, from state already captured at submission time (see
        llm_key_submission_round()) - no extra lookup or protocol call
        needed. Unknown/unlisted provider+model falls back to the default
        tier rather than erroring or scoring zero."""
        status = self.llm_key_hotkey_status.get(hotkey, {})
        key = f"{status.get('provider', '')}/{status.get('model', '')}"
        return C.LLM_KEY_MODEL_TIER_WEIGHTS.get(key, C.LLM_KEY_MODEL_TIER_DEFAULT_WEIGHT)

    def _record_llm_key_score(self, uid: int, report) -> None:
        """EMA-update self.scores[uid] (the persisted LLM-key efficiency EMA)
        from one usage report.

        A None reward (not enough call volume yet) is skipped rather than
        EMA'd in as a zero - a quiet key isn't a bad key.
        """
        avg_latency_s = (
            report.avg_latency_ms / 1000.0 if report.avg_latency_ms is not None else None
        )
        reward = llm_key_efficiency_score(
            success_count=report.success_count,
            failure_count=report.failure_count,
            avg_latency_s=avg_latency_s,
            key_active=report.key_active,
            model_tier_weight=self._model_tier_weight(report.hotkey),
            min_calls_for_scoring=_env_int(
                C.LLM_KEY_MIN_CALLS_FOR_SCORING_ENV, C.LLM_KEY_MIN_CALLS_FOR_SCORING
            ),
        )
        if reward is None:
            return
        alpha = _env_float(C.LLM_KEY_EMA_ALPHA_ENV, C.LLM_KEY_EMA_ALPHA)
        if report.key_active:
            # Scale down the EMA step for low-volume windows so a single
            # noisy call doesn't swing self.scores at full weight. An
            # inactive key is exempt -- it must still decay out at full
            # alpha (see llm_key_efficiency_score's docstring).
            total_calls = report.success_count + report.failure_count
            confidence = min(1.0, total_calls / C.LLM_KEY_VOLUME_TARGET_CALLS)
            floor = _env_float(C.LLM_KEY_EMA_CONFIDENCE_FLOOR_ENV, C.LLM_KEY_EMA_CONFIDENCE_FLOOR)
            alpha *= max(floor, confidence)
        uid = int(uid)
        if 0 <= uid < len(self.scores):
            self.scores[uid] = ema_update(float(self.scores[uid]), reward, alpha=alpha)
        else:
            bt.logging.warning(
                f"llm-key: uid={uid} out of range for scores array (len={len(self.scores)}); "
                f"dropping score update for hotkey={report.hotkey} (metagraph resize race?)"
            )

    def _blended_weight_array(self) -> np.ndarray:
        """Weight is earned only through confirmed LLM-key efficiency.

        self.scores[uid] is positive only once the protocol has reported
        real, verified usage for a key it currently considers active -
        merely answering the ask, or having a key that's been submitted but
        not yet confirmed working, earns nothing here. Key validity isn't
        something the validator can judge on its own, so it doesn't extend
        weight on the strength of a submission alone, only on the strength of
        reported real usage.

        participation_scores is intentionally excluded - it's tracked for
        liveness/observability only (see _record_participation), never
        blended into submitted weight.

        Whatever this returns is then wrapped by the template's own burn
        allocation (masxai/constants.py: BURN_UID/BURN_PERCENTAGE), which
        unconditionally reserves the large majority of emission for the burn
        uid regardless of how much real efficiency data exists here - see
        set_weights().
        """
        return np.nan_to_num(
            np.asarray(self.scores, dtype=np.float32),
            nan=0.0,
            posinf=0.0,
            neginf=0.0,
        )

    def set_weights(self):
        """Always submit weights so the validator stays active on-chain.

        The submitted array is the nan-safe LLM-key efficiency signal (see
        _blended_weight_array); self.scores itself - the persisted,
        report-driven efficiency EMA - is left untouched. The template's own
        burn allocation (BURN_UID/BURN_PERCENTAGE) further reserves most of
        emission for the burn uid before anything reaches the chain.
        """
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
            hotkey = self.metagraph.hotkeys[int(uid)]
            try:
                result = await client.submit_key(
                    hotkey=hotkey,
                    uid=int(uid),
                    provider=resp.provider,
                    model=resp.model,
                    encrypted_key_blob=resp.encrypted_key_blob,
                    blob_encoding=resp.blob_encoding,
                    pubkey_id_used=resp.pubkey_id_used,
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"llm-key: submit failed for uid={uid}: {e}")
                continue
            self.llm_key_hotkey_status[hotkey] = {
                "uid": int(uid),
                "provider": resp.provider,
                "model": resp.model,
                "accepted": result.accepted,
                "status": result.status,
                "reason": result.reason,
                "submitted_at": now,
            }
            if result.accepted:
                submitted += 1

        bt.logging.info(
            f"llm-key submission round: answered={answered}/{len(miner_uids)} "
            f"contributed={submitted}"
        )
        self.last_llm_key_ask_at = now

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
                evicted.append(hotkey)
        if evicted:
            bt.logging.info(
                f"llm-key: evicted {len(evicted)} stale hotkey-status entry(ies): {evicted}"
            )

    async def llm_key_report_poll_round(self) -> None:
        """Pull usage reports since the last cursor and fold them into
        self.scores. No-op if llm_key_client is None (unconfigured)."""
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

        scored = 0
        for report in reports:
            try:
                uid = self.metagraph.hotkeys.index(report.hotkey)
            except ValueError:
                # Unknown/deregistered hotkey - skip rather than guess a mapping.
                continue
            self._record_llm_key_score(uid, report)
            self.llm_key_hotkey_status.setdefault(report.hotkey, {})
            self.llm_key_hotkey_status[report.hotkey].update(
                {
                    "uid": int(uid),
                    "last_report_at": now,
                    "key_active": report.key_active,
                }
            )
            scored += 1

        self._prune_llm_key_hotkey_status(now)
        if next_since:
            self.last_llm_key_report_cursor = str(next_since)
        if reports:
            self.llm_key_reports_empty_since = 0.0
            bt.logging.info(f"llm-key report poll: {scored}/{len(reports)} reports scored")
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

"""neurons/security_validator.py - the security-audit track's validator neuron.

The chain-facing wrapper around the secqurityVali pipeline. Each round it asks
every miner for its agent image (SecurityAgentSynapse), pulls and evaluates each
returned image with the same pipeline the CLI uses, turns each verdict into a
reward, and lets the template base class set weights from self.scores per epoch.

Deliberately a thin wrapper. All the judgement -- is it an image, is it safe to
load, does it run, is it a duplicate -- lives in secqurityVali/ and is tested
there. All the chain mechanics -- registration, metagraph sync, weight setting,
the burn allocation -- live in the template base class. This file only connects
the two, and its one piece of real logic (verdict -> reward) is the pure,
tested helper in secqurityVali/reward.py.

Runs the security track on the same subnet as the LLM-key validator. For now
that is a single blended weight vector; if the subnet later gains multiple
mechanisms, only the set_weights target changes.

    python neurons/security_validator.py --netuid 501 --subtensor.network test \
        --wallet.name <coldkey> --wallet.hotkey <hotkey>
"""

import asyncio
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai.protocol import SecurityAgentSynapse
from masxai import constants as C
from masxai.bt_compat import bt
from masxai.env import load_env
from secqurityVali import db
from secqurityVali.docker_ops import docker_available
from secqurityVali.job import run_job
from secqurityVali.pipeline import check_and_record
from secqurityVali.reward import reward_for_job, reward_for_verdict

try:
    from template.base.validator import BaseValidatorNeuron
except Exception:
    class BaseValidatorNeuron:  # type: ignore[no-redef]
        def __init__(self, *_, **__):
            raise RuntimeError("BaseValidatorNeuron requires a working bittensor install")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


class SecurityValidator(BaseValidatorNeuron):
    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)

        self.db_path = os.getenv(C.SECURITY_DB_PATH_ENV, C.SECURITY_DB_PATH)
        # Open once to apply schema/migrations; each round opens its own
        # connection inside the worker thread (a sqlite connection is not
        # shareable across threads).
        db.connect(self.db_path).close()

        self.last_security_round_at = 0.0
        if not docker_available():
            bt.logging.warning(
                "security-validator: docker daemon is not reachable -- rounds will "
                "record docker_unavailable (a validator fault) until it is up"
            )
        bt.logging.info(
            f"Security validator initialized | db={self.db_path} "
            f"netuid={getattr(self.config, 'netuid', '?')}"
        )

    def get_miner_uids(self) -> list[int]:
        """Every registered neuron serving an axon, excluding self and (unless
        explicitly enabled) other validators. Mirrors the LLM-key validator."""
        uids: list[int] = []
        query_validators = str(
            os.getenv(C.QUERY_VALIDATOR_UIDS_ENV, "")
        ).strip().lower() in {"1", "true", "yes", "on"}
        validator_permit = getattr(self.metagraph, "validator_permit", None)
        n = getattr(self.metagraph, "n", 0)
        size = int(n.item()) if hasattr(n, "item") else int(n)
        for uid in range(size):
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

    async def _evaluate(self, image_ref: str, miner_id: str):
        """Evaluate one miner image off the event loop, returning a reward.

        Two stages: intake (is it a valid, non-duplicate image?) via the
        submission pipeline, then -- only if intake accepts -- the full isolated
        job (sandboxed run against the target, task + safety scoring). Docker
        work can take minutes, so it runs in a thread; doing it inline would
        freeze the validator's async loop.

        Returns (reward, detail): reward is a float, or None meaning "our fault,
        do not score" (a Docker/orchestration failure, retryable).
        """
        def work():
            conn = db.connect(self.db_path)
            try:
                # 1. intake: valid image? not a duplicate? (records + dedupes)
                _row, verdict, _ms = check_and_record(
                    conn, image_ref, miner_id, from_registry=True, skip_dry_run=True
                )
                if not verdict.accepted:
                    # a bad or duplicate image is the miner's verdict; a docker
                    # outage during intake is our fault (reward_for_verdict -> None)
                    return reward_for_verdict(verdict), f"intake:{verdict.stage_reached.value}"

                # 2. full evaluation: sandboxed run, task + safety scoring
                job = run_job(image_ref)
                reward = reward_for_job(job)
                detail = (
                    f"job:variant={job.variant} accepted={job.accepted} "
                    f"task={job.task.score if job.task else None} safe={job.safe} "
                    f"requests={job.request_count}"
                )
                return reward, detail
            finally:
                conn.close()

        return await asyncio.to_thread(work)

    async def security_round(self) -> None:
        """Ask every eligible miner for its agent image, evaluate each, and
        fold the results into self.scores."""
        now = time.time()
        interval = max(
            0.0,
            _env_float(
                C.SECURITY_SUBMISSION_INTERVAL_SECONDS_ENV,
                C.SECURITY_SUBMISSION_INTERVAL_SECONDS,
            ),
        )
        if self.last_security_round_at and now - self.last_security_round_at < interval:
            return

        miner_uids = self.get_miner_uids()
        if not miner_uids:
            self.last_security_round_at = now
            return

        synapse = SecurityAgentSynapse(request_id=uuid.uuid4().hex, issued_at=now)
        axons = [self.metagraph.axons[uid] for uid in miner_uids]
        responses = await self.dendrite(
            axons=axons,
            synapse=synapse,
            deserialize=False,
            timeout=C.SECURITY_QUERY_TIMEOUT,
        )

        rewards: dict[int, float] = {}
        skipped: list[int] = []
        answered = 0
        for uid, resp in zip(miner_uids, responses):
            if getattr(resp, "has_agent", None) is None:
                continue      # timed out / never reached the miner
            answered += 1
            if not getattr(resp, "has_agent", False):
                continue      # miner declined this round
            image_ref = (getattr(resp, "image_ref", "") or "").strip()
            if not image_ref:
                continue
            hotkey = self.metagraph.hotkeys[int(uid)]
            try:
                reward, detail = await self._evaluate(image_ref, hotkey)
            except Exception as e:  # noqa: BLE001 - never let one miner break the round
                bt.logging.warning(f"security-validator: uid={uid} evaluation errored: {e}")
                continue
            if reward is None:
                # our fault (docker/orchestration) -- retryable, not the miner's
                skipped.append(int(uid))
            else:
                rewards[int(uid)] = reward
            bt.logging.info(
                f"security-validator: uid={uid} reward={reward} ({detail}) ref={image_ref}"
            )

        if skipped:
            bt.logging.info(
                f"security-validator: skipped {len(skipped)} uid(s) scored as our "
                f"own fault (retryable), not the miner's: {skipped}"
            )
        if rewards:
            self._update_from_rewards(rewards)

        bt.logging.info(
            f"security-validator round | asked={len(miner_uids)} answered={answered} "
            f"scored={len(rewards)} skipped={len(skipped)}"
        )
        self.last_security_round_at = now

    def _update_from_rewards(self, rewards: dict[int, float]) -> None:
        """Feed this round's rewards into self.scores via the base class.

        Isolated so the numpy dependency stays on the real validator host and
        the round logic above it can be tested without it.
        """
        import numpy as np  # local: only needed on the real validator host

        uids = list(rewards.keys())
        self.update_scores(
            np.array([rewards[u] for u in uids], dtype=np.float32), uids
        )

    async def forward(self):
        """One validator step. The base class paces this by epoch and sets
        weights from self.scores; this only fills the scores in."""
        lock = getattr(self, "lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self.lock = lock
        async with lock:
            await self.security_round()
        await asyncio.sleep(5)


if __name__ == "__main__":
    with SecurityValidator() as validator:
        while True:
            bt.logging.info(
                f"Security validator alive | {time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            time.sleep(30)

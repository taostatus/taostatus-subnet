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

Runs the security track as mechanism 1 of the same subnet as the LLM-key
validator (mechanism 0). It sets weights on its own mechanism's matrix only, so
the two validators can share one staked hotkey without overwriting each other.
See MECHANISMS.md.

    python neurons/security_validator.py --netuid 501 --subtensor.network test \
        --wallet.name <coldkey> --wallet.hotkey <hotkey>
"""

import asyncio
import hashlib
import json
import os
import random
import sys
import tempfile
import time
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai.protocol import SecurityAgentSynapse
from masxai import constants as C
from masxai.agent_crypto import (
    AgentCryptoError,
    decrypt_agent,
    generate_keypair,
    public_key_b64,
)
from masxai.bt_compat import bt
from masxai.env import load_env
from masxai.marketplace_client import build_agent_payload, open_marketplace_client_from_env
from secqurityVali import db, docker_ops
from secqurityVali.category_scores import CategoryScores
from secqurityVali.docker_ops import docker_available
from secqurityVali.job import run_job
from secqurityVali.pipeline import check_and_record
from secqurityVali.reward import reward_for_job, reward_for_verdict
from secqurityVali.target_guard import TargetRejected, validate_target

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
    # Mechanism 1: the security track. Its weights go to mechanism 1's matrix
    # and never overwrite the LLM-key validator's mechanism-0 weights.
    mechid = C.SECURITY_MECHID

    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)

        self.db_path = os.getenv(C.SECURITY_DB_PATH_ENV, C.SECURITY_DB_PATH)
        # Open once to apply schema/migrations; each round opens its own
        # connection inside the worker thread (a sqlite connection is not
        # shareable across threads).
        db.connect(self.db_path).close()

        # The SealedBox keypair miners encrypt their agents for. Persisted, so a
        # restart can still decrypt a blob a miner encrypted for the last ask.
        self._load_or_create_keypair()

        # Per-miner, per-category capability matrix. A run tests one random
        # category; this remembers each miner's EMA per category so the score
        # reflects breadth, not whichever category a single run drew.
        self._active_categories = tuple(C.SECURITY_ACTIVE_CATEGORIES)
        self._cat_scores_path = os.getenv(
            C.SECURITY_CATEGORY_SCORES_FILE_ENV, C.SECURITY_CATEGORY_SCORES_FILE
        )
        self._cat_scores = CategoryScores.load(
            self._cat_scores_path,
            alpha=_env_float(C.SECURITY_CATEGORY_EMA_ALPHA_ENV, C.SECURITY_CATEGORY_EMA_ALPHA),
        )
        # Freshness window (F4): a category score older than this stops counting,
        # so an idle miner's score decays to 0 instead of paying forever.
        self._freshness_s = _env_float(
            C.SECURITY_CATEGORY_FRESHNESS_SECONDS_ENV, C.SECURITY_CATEGORY_FRESHNESS_SECONDS
        )

        # Marketplace handoff: push scored agents' metadata to the catalog
        # backend (None when not configured -> no-op). Never blocks a round.
        self._marketplace = open_marketplace_client_from_env()
        if self._marketplace is not None:
            bt.logging.info("marketplace: scored agents will be published to the catalog backend")

        self.last_security_round_at = 0.0
        # Evaluation runs as a background task so it never blocks weight-setting
        # (F3). Only one round runs at a time; a round's eval loop is bounded by
        # _round_budget_s. _forward_pace_s just paces how often forward() checks.
        self._round_task = None
        self._round_budget_s = _env_float(
            C.SECURITY_ROUND_BUDGET_SECONDS_ENV, C.SECURITY_ROUND_BUDGET_SECONDS
        )
        self._forward_pace_s = 5.0
        if not docker_available():
            bt.logging.warning(
                "security-validator: docker daemon is not reachable -- rounds will "
                "record docker_unavailable (a validator fault) until it is up"
            )
        bt.logging.info(
            f"Security validator initialized | db={self.db_path} "
            f"pubkey_id={self._pubkey_id} "
            f"netuid={getattr(self.config, 'netuid', '?')}"
        )

    def _load_or_create_keypair(self) -> None:
        """Load the persisted SealedBox private key, or mint and store one.

        The private half stays on disk (this file); the public half and a short
        id derived from it are sent to miners in every ask. The id lets a miner
        (and our own logs) notice a key rotation.
        """
        path = os.getenv(C.SECURITY_VALIDATOR_KEY_FILE_ENV, C.SECURITY_VALIDATOR_KEY_FILE)
        priv_b64 = None
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    priv_b64 = json.load(fh).get("private_key_b64")
            except Exception as e:  # noqa: BLE001 - corrupt file -> regenerate
                bt.logging.warning(f"security: could not read key file {path}: {e}; regenerating")
        if not priv_b64:
            priv_b64, _ = generate_keypair()
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"private_key_b64": priv_b64}, fh)
                try:
                    os.chmod(path, 0o600)  # best effort; no-op on Windows
                except OSError:
                    pass
                bt.logging.info(f"security: generated a new validator keypair at {path}")
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"security: could not persist key file {path}: {e}")
        self._priv_b64 = priv_b64
        self._pubkey_b64 = public_key_b64(priv_b64)
        self._pubkey_id = hashlib.sha256(self._pubkey_b64.encode()).hexdigest()[:16]

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
                    # outage during intake is our fault (reward_for_verdict -> None).
                    # No job ran, so there is no category to file this under.
                    return reward_for_verdict(verdict), f"intake:{verdict.stage_reached.value}", None, None

                # 2. full evaluation: sandboxed run, task + safety scoring
                job = run_job(image_ref, category=random.choice(self._active_categories))
                reward = reward_for_job(job)
                detail = (
                    f"job:variant={job.variant} accepted={job.accepted} "
                    f"task={job.task.score if job.task else None} safe={job.safe} "
                    f"requests={job.request_count}"
                )
                run_info = {
                    "category": job.category or None,
                    "variant": job.variant,
                    "task_score": job.task.score if job.task else None,
                    "safe": job.safe,
                    "requests": job.request_count,
                }
                return reward, detail, (job.category or None), run_info
            finally:
                conn.close()

        return await asyncio.to_thread(work)

    async def _evaluate_blob(self, blob_url: str, ciphertext_sha256: str, miner_id: str):
        """Download, verify, decrypt and evaluate an encrypted agent blob.

        The decrypted tarball goes through the same STRONG tarball intake as a
        file submission (FILE -> STRUCTURE -> LOAD -> INSPECT), then the full
        isolated job. Returns (reward, detail); reward None means our own
        (retryable) fault. A failed or corrupt download is our fault; a blob
        that will not decrypt for our key is the miner's (they must encrypt for
        the key we advertised), so that scores 0.
        """
        def work():
            tar_path = None
            image_ref = None
            conn = db.connect(self.db_path)
            try:
                # Anti-SSRF: blob_url is miner-controlled. Refuse any URL that
                # resolves to a non-public address (loopback, private, cloud
                # metadata) so a miner cannot turn the validator into a fetch
                # proxy for its internal network or steal cloud credentials. A bad
                # URL is the miner's doing, so it scores a deterministic 0 -- never
                # a retryable "our fault" download failure.
                try:
                    validate_target(blob_url)
                except TargetRejected as exc:
                    return 0.0, f"unsafe_blob_url:{exc}", None, None
                try:
                    blob = self._download_blob(blob_url)
                except Exception as e:  # noqa: BLE001 - network/host issue, retryable
                    return None, f"download_failed:{type(e).__name__}", None, None
                if ciphertext_sha256 and hashlib.sha256(blob).hexdigest() != ciphertext_sha256:
                    return None, "sha256_mismatch", None, None  # truncated/corrupt -> retry
                try:
                    tar = decrypt_agent(blob, self._priv_b64)
                except AgentCryptoError:
                    return 0.0, "decrypt_failed", None, None  # miner's fault, deterministic

                fd, tar_path = tempfile.mkstemp(prefix="secval-agent-", suffix=".tar")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(tar)

                # 1. intake over the strong tarball front door (+ dedupe/record)
                _row, verdict, _ms = check_and_record(
                    conn, tar_path, miner_id, from_registry=False, skip_dry_run=True
                )
                if not verdict.accepted:
                    return reward_for_verdict(verdict), f"intake:{verdict.stage_reached.value}", None, None

                # 2. load the validated image for a runnable ref, then evaluate
                image_ref = docker_ops.load_image(tar_path)
                job = run_job(image_ref, category=random.choice(self._active_categories))
                reward = reward_for_job(job)
                detail = (
                    f"job:variant={job.variant} accepted={job.accepted} "
                    f"task={job.task.score if job.task else None} safe={job.safe} "
                    f"requests={job.request_count}"
                )
                run_info = {
                    "category": job.category or None,
                    "variant": job.variant,
                    "task_score": job.task.score if job.task else None,
                    "safe": job.safe,
                    "requests": job.request_count,
                }
                return reward, detail, (job.category or None), run_info
            finally:
                if image_ref:
                    docker_ops.remove_image(image_ref)
                if tar_path and os.path.exists(tar_path):
                    try:
                        os.remove(tar_path)
                    except OSError:
                        pass
                conn.close()

        return await asyncio.to_thread(work)

    def _download_blob(self, url: str) -> bytes:
        """Download an encrypted blob, bounded in size and time. Raises on any
        problem so the caller scores it as our own (retryable) fault."""
        max_bytes = C.SECURITY_BLOB_MAX_BYTES
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=C.SECURITY_BLOB_DOWNLOAD_TIMEOUT_S) as resp:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"blob exceeds {max_bytes} bytes")
                chunks.append(chunk)
        return b"".join(chunks)

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

        synapse = SecurityAgentSynapse(
            request_id=uuid.uuid4().hex,
            issued_at=now,
            validator_pubkey_b64=self._pubkey_b64,
            pubkey_id=self._pubkey_id,
        )
        axons = [self.metagraph.axons[uid] for uid in miner_uids]
        responses = await self.dendrite(
            axons=axons,
            synapse=synapse,
            deserialize=False,
            timeout=C.SECURITY_QUERY_TIMEOUT,
        )

        rewards: dict[int, float] = {}
        skipped: list[int] = []
        runs_this_round: dict[str, dict] = {}   # hotkey -> this round's run info
        answered = 0
        budget_reached = False
        round_started = time.monotonic()
        for uid, resp in zip(miner_uids, responses):
            # Bound the round: once the budget is spent, defer the rest to the
            # next round rather than letting one round run unbounded. (The round
            # is already off the weight-set path; this just stops pile-ups.)
            if time.monotonic() - round_started > self._round_budget_s:
                budget_reached = True
                bt.logging.info(
                    f"security-validator: round budget {self._round_budget_s:.0f}s reached; "
                    "deferring remaining miners to the next round"
                )
                break
            if getattr(resp, "has_agent", None) is None:
                continue      # timed out / never reached the miner
            answered += 1
            if not getattr(resp, "has_agent", False):
                continue      # miner declined this round
            hotkey = self.metagraph.hotkeys[int(uid)]
            blob_url = (getattr(resp, "blob_url", "") or "").strip()
            image_ref = (getattr(resp, "image_ref", "") or "").strip()
            try:
                if blob_url:
                    # primary path: encrypted blob, opaque to peers
                    cipher_sha = (getattr(resp, "ciphertext_sha256", "") or "").strip()
                    reward, detail, category, run_info = await self._evaluate_blob(blob_url, cipher_sha, hotkey)
                    submitted = blob_url
                elif image_ref:
                    # fallback path: plaintext registry reference
                    reward, detail, category, run_info = await self._evaluate(image_ref, hotkey)
                    submitted = image_ref
                else:
                    continue  # answered has_agent=True but sent nothing usable
            except Exception as e:  # noqa: BLE001 - never let one miner break the round
                bt.logging.warning(f"security-validator: uid={uid} evaluation errored: {e}")
                continue
            if reward is None:
                # our fault (docker/orchestration) -- retryable, not the miner's
                skipped.append(int(uid))
                bt.logging.info(
                    f"security-validator: uid={uid} reward=None ({detail}) src={submitted}"
                )
                continue
            # Fold this run into the miner's per-category memory, then score on
            # the aggregate across ALL active categories -- so the miner is judged
            # on breadth, not on whichever single category this run happened to
            # draw. A run with no category (a submission-level failure) still
            # scores on the miner's standing aggregate.
            if category is not None:
                self._cat_scores.update(hotkey, category, reward)
            if run_info is not None:
                runs_this_round[hotkey] = run_info
            agg = self._cat_scores.aggregate(
                hotkey, self._active_categories, now=now, freshness_s=self._freshness_s
            )
            rewards[int(uid)] = agg
            bt.logging.info(
                f"security-validator: uid={uid} raw={reward} cat={category} "
                f"agg={agg:.3f} ({detail}) src={submitted}"
            )

        if rewards or skipped:
            # persist the matrix (best-effort) after folding in this round
            self._cat_scores.prune(set(self.metagraph.hotkeys))
            self._cat_scores.save(self._cat_scores_path)

        if skipped:
            bt.logging.info(
                f"security-validator: skipped {len(skipped)} uid(s) scored as our "
                f"own fault (retryable), not the miner's: {skipped}"
            )

        # Score EVERY miner from the freshness-filtered matrix -- not only those
        # evaluated this round -- so an idle/offline miner whose cells went stale
        # decays to 0 instead of earning forever (F4), while a recently-scored
        # miner keeps its score until its window lapses.
        score_map = self._recompute_all_scores(now)
        if score_map:
            self._update_from_rewards(score_map)
            # Publish metadata + scores to the catalog backend (off the loop so a
            # slow/absent backend can't delay the round). Best-effort.
            mp = getattr(self, "_marketplace", None)
            if mp is not None:
                await asyncio.to_thread(self._publish_to_marketplace, score_map, runs_this_round)

        bt.logging.info(
            f"security-validator round | asked={len(miner_uids)} answered={answered} "
            f"scored={len(rewards)} skipped={len(skipped)} "
            f"budget_reached={budget_reached}"
        )
        self.last_security_round_at = now

    def _publish_to_marketplace(self, score_map: dict[int, float],
                                runs: dict[str, dict] | None = None) -> None:
        """Push each scored agent's metadata + scores to the catalog backend.
        `runs` carries this round's per-hotkey evaluation (variant/task/safe/
        requests) for miners evaluated this round. Runs in a worker thread;
        best-effort (publish_agent never raises)."""
        runs = runs or {}
        netuid = getattr(self.config, "netuid", None)
        mechid = getattr(self, "mechid", None)
        published = 0
        for uid, score in score_map.items():
            hotkey = self.metagraph.hotkeys[int(uid)]
            cells = self._cat_scores.cells.get(hotkey, {})
            categories = {cat: cell["score"] for cat, cell in cells.items()}
            payload = build_agent_payload(
                miner_hotkey=hotkey,
                uid=int(uid),
                overall_score=score,
                categories=categories,
                status="active" if score >= C.MARKETPLACE_MIN_SCORE else "stale",
                netuid=netuid,
                mechid=mechid,
                run=runs.get(hotkey),
            )
            if self._marketplace.publish_agent(payload):
                published += 1
        if published:
            bt.logging.info(f"marketplace: published {published} agent(s) to the catalog")

    def _recompute_all_scores(self, now: float) -> dict[int, float]:
        """{uid: score} for every miner that has category history, each the
        freshness-filtered aggregate of its matrix. Recomputing from the matrix
        (not just this round's answers) is what lets a previously-scored miner
        that has gone idle decay to 0 as its cells go stale (F4), instead of its
        old score being frozen because it is no longer evaluated. Miners with no
        history are untouched (they stay at the base class's 0)."""
        hk_to_uid = {hk: i for i, hk in enumerate(self.metagraph.hotkeys)}
        out: dict[int, float] = {}
        for hotkey in list(self._cat_scores.cells.keys()):
            uid = hk_to_uid.get(hotkey)
            if uid is None:
                continue  # hotkey no longer in the metagraph
            out[uid] = self._cat_scores.aggregate(
                hotkey, self._active_categories, now=now, freshness_s=self._freshness_s
            )
        return out

    def _update_from_rewards(self, rewards: dict[int, float]) -> None:
        """Write this round's aggregate scores into self.scores directly.

        Each value here is already the per-category aggregate (which carries its
        own EMA history), so it is SET, not run through the base class's
        round-over-round EMA -- a second smoothing would lag and blindly re-blend
        across categories, undoing the per-category memory. This mirrors the
        LLM-key validator, which likewise recomputes self.scores from its own
        accumulator rather than via update_scores(). Isolated so the numpy
        dependency stays on the real validator host.
        """
        import numpy as np  # local: only needed on the real validator host

        scores = getattr(self, "scores", None)
        if scores is None:
            return
        for uid, value in rewards.items():
            if 0 <= int(uid) < len(scores):
                scores[int(uid)] = np.float32(value)

    async def forward(self):
        """One validator step. Starts an evaluation round in the BACKGROUND (if
        one isn't already running) and returns promptly, so evaluation never
        blocks the base class's weight-setting loop -- a validator that goes
        silent on chain has its vtrust collapse (F3). The base class reads
        self.scores, which the background round fills in, and sets weights on its
        own schedule regardless of how long evaluation takes.
        """
        task = getattr(self, "_round_task", None)
        if task is not None and task.done():
            # Surface (don't swallow) a crash from the finished round, then clear.
            if not task.cancelled() and task.exception() is not None:
                bt.logging.warning(
                    f"security-validator: previous round errored: {task.exception()}"
                )
            task = None
        if task is None:
            self._round_task = asyncio.create_task(self._run_round_guarded())
        # Pace how often we check; the round itself runs independently. Kept small
        # so weight-setting stays responsive, never the length of a round.
        await asyncio.sleep(getattr(self, "_forward_pace_s", 5.0))

    async def _run_round_guarded(self) -> None:
        """Run one security_round off the weight-set path. Never raises -- a
        failed round must not take the loop (or the background task) down."""
        try:
            await self.security_round()
        except Exception as e:  # noqa: BLE001 - a round must never crash the validator
            bt.logging.warning(f"security-validator: round failed: {e}")


if __name__ == "__main__":
    with SecurityValidator() as validator:
        while True:
            bt.logging.info(
                f"Security validator alive | {time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            time.sleep(30)

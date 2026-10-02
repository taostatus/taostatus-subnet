from __future__ import annotations

"""secqurityVali/pipeline.py - run every stage, produce exactly one Verdict.

This is the only module that knows the stages exist as a sequence. Each stage
raises StageFailure on rejection; the pipeline catches it, stamps the stage
that was running, and returns a rejected Verdict. Nothing propagates out: a
submission always produces a record, never an exception for the caller to
interpret.

Three rules this module enforces that no single stage can:

  * Short-circuit. The first failure ends the run, so a verdict names one
    reason -- the one that stopped it -- and later problems stay unknown.
  * Cleanup always. Once an image is loaded it is removed on every exit path,
    accepted or rejected or crashed. Nothing persists between submissions.
  * Partial evidence is kept. A submission rejected at LOAD still carries the
    sha256 and size that FILE established, so the record identifies the bytes
    that failed.
"""

import time
from pathlib import Path

from secqurityVali import docker_ops, dry_run as dry_run_stage
from secqurityVali.docker_ops import DockerRunner
from secqurityVali.file_checks import check_file
from secqurityVali.models import (
    SOURCE_REGISTRY,
    RejectReason,
    Stage,
    StageFailure,
    Status,
    Verdict,
    accept,
    reject,
)
from secqurityVali.structure import check_structure


def _cached_verdict(row: dict, miner_id: str, file_path: str, **measured) -> Verdict:
    """Replay an earlier verdict for the same miner's same agent.

    A new row is still written -- the attempt happened and belongs in the log
    -- but it carries from_cache and points at the submission that actually
    did the work, so the ledger never shows checks that were not run.

    The outcome is replayed; the facts are not. Anything this run actually
    measured (`measured`) overrides what the earlier row said, so the row
    always describes the bytes that were submitted this time. Replaying the
    original's sha256 onto a differently-packaged resubmission would produce
    a record naming one file and hashing another.
    """
    replayed = dict(
        file_sha256=row.get("file_sha256"),
        file_size=row.get("file_size"),
        image_id=row.get("image_id"),
        repo_tags=row.get("repo_tags") or [],
        arch=row.get("arch"),
        os_name=row.get("os_name"),
        layer_count=row.get("layer_count"),
        image_size=row.get("image_size"),
        entrypoint=row.get("entrypoint") or [],
        image_user=row.get("image_user"),
        agent_digest=row.get("agent_digest"),
    )
    replayed.update({k: v for k, v in measured.items() if v is not None})

    return Verdict(
        miner_id=miner_id,
        file_path=file_path,
        status=Status(row["status"]),
        stage_reached=Stage(row["stage_reached"]),
        reject_reason=RejectReason(row["reject_reason"]) if row["reject_reason"] else None,
        # The dry run belongs to the earlier submission: this one never ran.
        dry_run_exit_code=row.get("dry_run_exit_code"),
        dry_run_ms=row.get("dry_run_ms"),
        log_excerpt=row.get("log_excerpt"),
        duplicate_of=row["id"],
        from_cache=True,
        error_detail=row.get("error_detail"),
        **replayed,
    )


def _duplicate_verdict(
    miner_id: str, file_path: str, stage: Stage, owner: str, submission_id: int, **fields
) -> Verdict:
    """Someone else got here first."""
    return reject(
        miner_id,
        file_path,
        stage,
        RejectReason.DUPLICATE_AGENT,
        error_detail=f"already submitted by {owner} (submission {submission_id})",
        duplicate_of=submission_id,
        **fields,
    )


class _Evidence:
    """Everything established so far. Survives a rejection, so the verdict
    records what was known at the moment the run stopped.

    None is dropped rather than stored: a field a stage could not determine
    must stay absent, not overwrite something an earlier stage did know.
    """

    def __init__(self) -> None:
        self.fields: dict = {}

    def add(self, **values) -> None:
        self.fields.update({k: v for k, v in values.items() if v is not None})


def check_submission(
    file_path: Path | str,
    miner_id: str,
    *,
    runner: DockerRunner | None = None,
    keep_image: bool = False,
    skip_dry_run: bool = False,
    registry=None,
) -> Verdict:
    """Run every stage over one submission and return its Verdict.

    Never raises. A validator that crashes on a hostile submission is a
    denial-of-service the miner controls, so even an unexpected error becomes
    a recorded verdict (INTERNAL_ERROR, flagged as our fault rather than the
    miner's).

    `keep_image` leaves an accepted image loaded in Docker -- for when the
    downstream handoff exists and needs it. Off by default: today nothing
    consumes it, and an image left behind is an image left behind.
    """
    file_path = Path(file_path)
    evidence = _Evidence()
    stage = Stage.FILE
    image_ref: str | None = None

    try:
        # --- stage FILE ---
        info = check_file(file_path)
        evidence.add(file_sha256=info.sha256, file_size=info.size)

        # Fast dedupe, milliseconds in: byte-identical bytes we have already
        # ruled on. Cheap, and it happens before Docker is touched at all --
        # but it only catches exact copies, which is why the real identity
        # check still runs after INSPECT.
        if registry is not None:
            seen = registry.find_by_file_sha256(info.sha256)
            if seen is not None:
                if seen["miner_id"] == miner_id:
                    return _cached_verdict(
                        seen, miner_id, str(file_path), **evidence.fields
                    )
                if seen["status"] == Status.ACCEPTED.value:
                    # Another miner's accepted agent, byte for byte.
                    return _duplicate_verdict(
                        miner_id, str(file_path), Stage.FILE,
                        seen["miner_id"], seen["id"], **evidence.fields,
                    )
                # Someone else submitted these bytes and was rejected. There
                # is nothing to own, so this submission is checked normally.

        # --- stage STRUCTURE ---
        stage = Stage.STRUCTURE
        structure = check_structure(file_path)
        evidence.add(
            repo_tags=structure.repo_tags or None,
            layer_count=structure.layer_count,
        )

        # --- stage LOAD: hostile bytes reach the daemon here ---
        stage = Stage.LOAD
        image_ref = docker_ops.load_image(file_path, runner=runner)

        # --- stage INSPECT ---
        stage = Stage.INSPECT
        image = docker_ops.inspect_image(image_ref, runner=runner)
        evidence.add(
            image_id=image.image_id,
            repo_tags=image.repo_tags or None,
            arch=image.arch,
            os_name=image.os_name,
            layer_count=image.layer_count,
            image_size=image.image_size,
            image_user=image.image_user,
        )
        docker_ops.check_image(image)
        # Resolved last: an image with nothing to run is rejected here, and
        # the resolved command is what a future dry run would invoke.
        evidence.add(entrypoint=docker_ops.entrypoint_of(image))

        # Real dedupe. The layer digests identify the agent regardless of how
        # it was packaged, so a re-save, a re-tag or a metadata edit all land
        # on the same digest -- unlike the file hash checked above.
        agent_digest = docker_ops.agent_digest_of(image)
        evidence.add(agent_digest=agent_digest)
        if registry is not None and agent_digest:
            known = registry.find_agent(agent_digest)
            if known is not None:
                if known["owner_miner_id"] != miner_id:
                    return _duplicate_verdict(
                        miner_id, str(file_path), Stage.INSPECT,
                        known["owner_miner_id"], known["first_submission"],
                        **evidence.fields,
                    )
                # The miner's own agent, repackaged. Already proven; do not
                # spend another dry run on it.
                previous = registry.find_submission(known["first_submission"])
                if previous is not None:
                    return _cached_verdict(
                        previous, miner_id, str(file_path), **evidence.fields
                    )

        if skip_dry_run:
            # The verdict claims only what was proven: valid image, never run.
            return accept(miner_id, str(file_path), stage=Stage.INSPECT, **evidence.fields)

        # --- stage DRY_RUN: miner code executes here ---
        stage = Stage.DRY_RUN
        outcome = dry_run_stage.dry_run(image_ref, runner=runner)
        # Recorded before the gate, so a failed run still says what it did.
        evidence.add(
            dry_run_exit_code=outcome.exit_code,
            dry_run_ms=outcome.duration_ms,
            log_excerpt=outcome.log_excerpt or None,
        )
        dry_run_stage.check_dry_run(outcome)

        return accept(miner_id, str(file_path), stage=Stage.DRY_RUN, **evidence.fields)

    except StageFailure as failure:
        return reject(
            miner_id,
            str(file_path),
            stage,
            failure.reason,
            error_detail=failure.detail,
            **evidence.fields,
        )
    except Exception as exc:  # noqa: BLE001 - deliberately total
        return reject(
            miner_id,
            str(file_path),
            stage,
            RejectReason.INTERNAL_ERROR,
            error_detail=f"{type(exc).__name__}: {exc}",
            **evidence.fields,
        )
    finally:
        # Runs on acceptance, rejection and crash alike. The tarball and its
        # sha256 are the record; the loaded image is disposable.
        if image_ref and not keep_image:
            docker_ops.remove_image(image_ref, runner=runner)


def check_registry_submission(
    image_ref: str,
    miner_id: str,
    *,
    runner: DockerRunner | None = None,
    keep_image: bool = False,
    skip_dry_run: bool = False,
    registry=None,
) -> Verdict:
    """Validate a submission that arrived as a registry reference.

    Same verdict, fewer gates. Stages FILE and STRUCTURE do not apply: there
    is no archive to inspect, and `docker pull` has already handed the bytes
    to the daemon by the time we can look at anything. The run therefore
    starts at LOAD (the pull) and continues through INSPECT and DRY_RUN
    exactly as a file submission does.

    Never raises, for the same reason check_submission() does not.
    """
    from secqurityVali import registry as registry_mod

    evidence = _Evidence()
    evidence.add(source=SOURCE_REGISTRY)
    stage = Stage.LOAD
    pulled = None

    try:
        # --- stage LOAD: pull, and pin to a digest ---
        pulled = registry_mod.pull_image(image_ref, runner=runner)
        evidence.add(image_ref=pulled.digest_ref)

        # --- stage INSPECT ---
        stage = Stage.INSPECT
        image = docker_ops.inspect_image(pulled.digest_ref, runner=runner)
        evidence.add(
            image_id=image.image_id,
            repo_tags=image.repo_tags or None,
            arch=image.arch,
            os_name=image.os_name,
            layer_count=image.layer_count,
            image_size=image.image_size,
            image_user=image.image_user,
        )
        docker_ops.check_image(image)
        evidence.add(entrypoint=docker_ops.entrypoint_of(image))

        agent_digest = docker_ops.agent_digest_of(image)
        evidence.add(agent_digest=agent_digest)
        if registry is not None and agent_digest:
            known = registry.find_agent(agent_digest)
            if known is not None:
                if known["owner_miner_id"] != miner_id:
                    return _duplicate_verdict(
                        miner_id, image_ref, Stage.INSPECT,
                        known["owner_miner_id"], known["first_submission"],
                        **evidence.fields,
                    )
                previous = registry.find_submission(known["first_submission"])
                if previous is not None:
                    return _cached_verdict(
                        previous, miner_id, image_ref, **evidence.fields
                    )

        if skip_dry_run:
            return accept(miner_id, image_ref, stage=Stage.INSPECT, **evidence.fields)

        # --- stage DRY_RUN ---
        stage = Stage.DRY_RUN
        outcome = dry_run_stage.dry_run(pulled.digest_ref, runner=runner)
        evidence.add(
            dry_run_exit_code=outcome.exit_code,
            dry_run_ms=outcome.duration_ms,
            log_excerpt=outcome.log_excerpt or None,
        )
        dry_run_stage.check_dry_run(outcome)

        return accept(miner_id, image_ref, stage=Stage.DRY_RUN, **evidence.fields)

    except StageFailure as failure:
        return reject(
            miner_id, image_ref, stage, failure.reason,
            error_detail=failure.detail, **evidence.fields,
        )
    except Exception as exc:  # noqa: BLE001 - deliberately total
        return reject(
            miner_id, image_ref, stage, RejectReason.INTERNAL_ERROR,
            error_detail=f"{type(exc).__name__}: {exc}", **evidence.fields,
        )
    finally:
        if pulled is not None and not keep_image:
            registry_mod.remove_pulled(pulled.digest_ref, runner=runner)


def check_and_record(
    conn,
    file_path: Path | str,
    miner_id: str,
    *,
    runner: DockerRunner | None = None,
    keep_image: bool = False,
    skip_dry_run: bool = False,
    dedupe: bool = True,
    from_registry: bool = False,
) -> tuple[int, Verdict, int]:
    """check_submission() plus the database write and agent registration.

    Returns (row_id, verdict, elapsed_ms).

    Every submission is recorded, accepted or not -- a rejected image that
    leaves no trace is a submission nobody can audit. Only a freshly accepted
    agent is registered, and only once: the agents table is keyed by digest,
    so a second registration is refused by the database itself.
    """
    from secqurityVali import db  # imported here so pipeline stays usable DB-free

    registry = db.SqliteRegistry(conn) if dedupe else None

    entry = check_registry_submission if from_registry else check_submission

    started = time.monotonic()
    verdict = entry(
        file_path,
        miner_id,
        runner=runner,
        keep_image=keep_image,
        skip_dry_run=skip_dry_run,
        registry=registry,
    )
    elapsed_ms = int((time.monotonic() - started) * 1000)

    row_id = db.record_verdict(conn, verdict)
    # A replayed verdict registers nothing -- the agent is already owned by
    # the submission it was replayed from.
    if registry is not None and not verdict.from_cache:
        registry.register_agent(verdict, row_id)
    return row_id, verdict, elapsed_ms

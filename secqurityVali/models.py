from __future__ import annotations

"""secqurityVali/models.py - the shared vocabulary of a submission check.

Every submission produces exactly one Verdict, accepted or rejected. A
rejected Verdict is not an error to be swallowed: stage_reached records how
far the file got before it died, which is the difference between "this isn't
a tarball at all" and "this is a valid image whose entrypoint crashed".

Stdlib only (dataclasses, not pydantic) -- secval is meant to run on a bare
interpreter, and every field here is produced by our own stage functions
rather than parsed from untrusted input, so there is nothing for a validating
model layer to protect.
"""

import enum
import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


class Stage(str, enum.Enum):
    """The five checks, in the order the pipeline runs them."""

    FILE = "file"            # exists, size, sha256, magic bytes
    STRUCTURE = "structure"  # docker-archive or OCI layout, safe tar entries
    LOAD = "load"            # docker load
    INSPECT = "inspect"      # arch/os, entrypoint, layer + size caps
    DRY_RUN = "dry_run"      # bounded execution, forced kill on timeout


# Ordering is explicit rather than implied by enum definition order, so
# comparisons ("did it get past LOAD?") don't silently change if the enum is
# ever reordered.
STAGE_ORDER: tuple[Stage, ...] = (
    Stage.FILE,
    Stage.STRUCTURE,
    Stage.LOAD,
    Stage.INSPECT,
    Stage.DRY_RUN,
)


def stage_index(stage: Stage) -> int:
    return STAGE_ORDER.index(stage)


class RejectReason(str, enum.Enum):
    """Why a submission was turned away. One reason per verdict -- the first
    failure short-circuits the pipeline, so later problems stay unknown."""

    # stage: file
    FILE_MISSING = "file_missing"
    FILE_EMPTY = "file_empty"
    FILE_TOO_LARGE = "file_too_large"
    NOT_AN_ARCHIVE = "not_an_archive"            # magic bytes aren't tar/gzip

    # stage: structure
    NOT_A_DOCKER_IMAGE = "not_a_docker_image"    # no manifest.json / oci-layout
    UNSAFE_TAR_ENTRY = "unsafe_tar_entry"        # absolute path, .., escaping symlink
    MALFORMED_ARCHIVE = "malformed_archive"      # tar itself won't parse
    MALFORMED_MANIFEST = "malformed_manifest"    # manifest.json isn't valid image metadata
    MULTIPLE_IMAGES = "multiple_images"          # archive holds more than one image
    # Caught from the tar headers while streaming -- a member declaring 100 GB
    # is rejected before any of its payload is read.
    DECOMPRESSION_BOMB = "decompression_bomb"    # declared size or entry count past the cap
    TOO_MANY_ENTRIES = "too_many_entries"        # millions-of-tiny-files bomb

    # stage: load -- from a file
    LOAD_FAILED = "load_failed"

    # stage: load -- from a registry
    BAD_IMAGE_REF = "bad_image_ref"              # not a reference we will pass to docker
    PULL_FAILED = "pull_failed"
    REGISTRY_UNAUTHORIZED = "registry_unauthorized"   # private, or no credentials
    IMAGE_NOT_FOUND = "image_not_found"
    DIGEST_UNRESOLVED = "digest_unresolved"      # pulled, but docker reported no digest

    # stage: inspect
    ARCH_MISMATCH = "arch_mismatch"
    OS_MISMATCH = "os_mismatch"
    NO_ENTRYPOINT = "no_entrypoint"              # neither Entrypoint nor Cmd
    TOO_MANY_LAYERS = "too_many_layers"
    IMAGE_TOO_LARGE = "image_too_large"

    # stage: dry_run
    CREATE_FAILED = "create_failed"
    START_FAILED = "start_failed"                # entrypoint could not execute
    DRY_RUN_TIMEOUT = "dry_run_timeout"
    DRY_RUN_NONZERO_EXIT = "dry_run_nonzero_exit"

    # identity -- raised at whichever stage the duplication became visible
    # (the file hash after FILE, the layer digest after INSPECT)
    DUPLICATE_AGENT = "duplicate_agent"          # another miner submitted it first

    # any stage -- the validator's own fault, not the miner's
    DOCKER_UNAVAILABLE = "docker_unavailable"
    INTERNAL_ERROR = "internal_error"


# Reasons that mean "the validator broke", not "the miner's image is bad".
# Kept distinct so a daemon outage is never held against a miner: these are
# retryable, and a future scorer must not read them as a failed submission.
VALIDATOR_FAULT_REASONS: frozenset[RejectReason] = frozenset(
    {RejectReason.DOCKER_UNAVAILABLE, RejectReason.INTERNAL_ERROR}
)


class StageFailure(Exception):
    """Raised by a stage function to reject a submission.

    Stages read linearly -- check, check, check -- and any check can end the
    run. Raising keeps that code free of result-tuple plumbing; the pipeline
    catches this and turns it into a rejected Verdict at whichever stage was
    running, so a stage never needs to know its own name.
    """

    def __init__(self, reason: "RejectReason", detail: str | None = None) -> None:
        super().__init__(detail or reason.value)
        self.reason = reason
        self.detail = detail

    @property
    def is_validator_fault(self) -> bool:
        """Our failure rather than the miner's -- retryable, and never to be
        counted against a submission. Mirrors Verdict.validator_fault."""
        return self.reason in VALIDATOR_FAULT_REASONS


class Status(str, enum.Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


# How a submission arrived. These are not equally safe: a file is inspected
# by stages FILE and STRUCTURE before the daemon ever parses it, while
# `docker pull` hands the registry's bytes straight to the daemon. See the
# README, "Registry intake is a weaker front door".
SOURCE_FILE = "file"
SOURCE_REGISTRY = "registry"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Streamed so a multi-GB submission never lands in memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class Verdict:
    """One submission's full record. Fields fill in as stages pass, so a
    verdict rejected at STRUCTURE simply leaves every image_* field None."""

    # identity -- always present.
    # file_path is "what was submitted": a local path for SOURCE_FILE, or the
    # image reference for SOURCE_REGISTRY. image_ref below carries the
    # reference precisely when there is one.
    miner_id: str
    file_path: str
    status: Status
    stage_reached: Stage

    source: str = "file"          # SOURCE_FILE | SOURCE_REGISTRY
    # The digest-pinned reference actually validated. A tag is mutable -- it
    # can be repointed to different bytes after we rule on it -- so the
    # record must name the digest, never the tag it arrived as.
    image_ref: str | None = None

    received_at: str = field(default_factory=utc_now_iso)
    reject_reason: RejectReason | None = None

    # stage: file
    file_sha256: str | None = None
    file_size: int | None = None

    # stage: load / inspect
    image_id: str | None = None
    repo_tags: list[str] = field(default_factory=list)
    arch: str | None = None
    os_name: str | None = None
    layer_count: int | None = None
    image_size: int | None = None
    entrypoint: list[str] = field(default_factory=list)
    image_user: str | None = None

    # stage: dry_run
    dry_run_exit_code: int | None = None
    dry_run_ms: int | None = None
    log_excerpt: str | None = None

    # identity
    # agent_digest is what makes two submissions "the same agent": a hash of
    # the image's layer digests, so a re-save, a re-tag or changed metadata
    # still resolves to one agent. Known only after INSPECT.
    agent_digest: str | None = None
    # The earlier submission this one repeats -- either the miner's own
    # (a cache hit) or another miner's (a rejected duplicate).
    duplicate_of: int | None = None
    # True when no checks were re-run because the answer was already known.
    from_cache: bool = False

    error_detail: str | None = None

    @property
    def accepted(self) -> bool:
        return self.status is Status.ACCEPTED

    @property
    def validator_fault(self) -> bool:
        """True when the run failed on our side -- retryable, and not a
        judgement about the miner's image."""
        return self.reject_reason in VALIDATOR_FAULT_REASONS

    def to_dict(self) -> dict:
        """Plain dict with enums flattened to their string values."""
        raw = asdict(self)
        raw["status"] = self.status.value
        raw["stage_reached"] = self.stage_reached.value
        raw["reject_reason"] = self.reject_reason.value if self.reject_reason else None
        return raw


def reject(
    miner_id: str,
    file_path: str,
    stage: Stage,
    reason: RejectReason,
    *,
    error_detail: str | None = None,
    **fields,
) -> Verdict:
    """Build a rejected Verdict, carrying whatever earlier stages had already
    established (sha256, image_id, ...) via **fields."""
    return Verdict(
        miner_id=miner_id,
        file_path=file_path,
        status=Status.REJECTED,
        stage_reached=stage,
        reject_reason=reason,
        error_detail=error_detail,
        **fields,
    )


def accept(miner_id: str, file_path: str, *, stage: Stage = Stage.INSPECT, **fields) -> Verdict:
    """Build an accepted Verdict.

    `stage` records the last check the submission actually cleared, which is
    how far the pipeline currently goes -- INSPECT today, DRY_RUN once the
    bounded execution stage lands. An accepted verdict therefore states what
    was proven, never more.
    """
    return Verdict(
        miner_id=miner_id,
        file_path=file_path,
        status=Status.ACCEPTED,
        stage_reached=stage,
        **fields,
    )

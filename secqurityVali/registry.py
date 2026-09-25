from __future__ import annotations

"""secqurityVali/registry.py - stage LOAD, when the submission is a reference.

A miner can submit either a `docker save` tarball or a registry reference such
as `ghcr.io/org/agent:0.1.0`. This module handles the second.

Understand what is given up here. Stages FILE and STRUCTURE exist to inspect
hostile bytes *before* the root daemon parses them -- that is what stops a
decompression bomb or a traversal tar without Docker being asked anything.
`docker pull` hands the registry's bytes straight to the daemon, so neither
gate applies. **Registry intake is a weaker front door than tarball intake.**
It is the right trade while the registry is ours; it should be revisited
before this is opened to arbitrary miners.

Two things this module does insist on:

  * The reference is pattern-checked before it becomes a CLI argument. It now
    arrives over HTTP, so it is attacker-controlled in the most direct sense.
  * What we validate is a **digest**, never a tag. A tag is mutable: it can be
    repointed to different bytes the moment after we rule on it, leaving an
    accepted record that points at something nobody checked.
"""

import re
from dataclasses import dataclass

from secqurityVali import constants as C
from secqurityVali.docker_ops import (
    DockerRunner,
    assert_safe_image_ref,
    excerpt,
    run_docker,
)
from secqurityVali.models import RejectReason, StageFailure

# A digest-pinned reference: repository@sha256:<64 hex>.
_DIGEST_REF_RE = re.compile(r"^(?P<repo>[^@\s]+)@(?P<digest>sha256:[0-9a-f]{64})$")

# Substrings in a failed pull that tell us *why* it failed. Distinguishing
# these matters: "unauthorized" is usually a private package and an operator
# problem, while "not found" is genuinely the miner's.
_UNAUTHORIZED_MARKERS = (
    "unauthorized",
    "authentication required",
    "denied",
    "forbidden",
    "access to the resource is denied",
)
_NOT_FOUND_MARKERS = (
    "manifest unknown",
    "not found",
    "repository does not exist",
    "no such manifest",
)


@dataclass(frozen=True)
class PulledImage:
    """What a successful pull established."""

    requested_ref: str   # what the miner submitted, tag and all
    digest_ref: str      # what we actually validated: repo@sha256:...
    image_id: str        # docker's local id for it


def is_digest_pinned(ref: str) -> bool:
    return bool(_DIGEST_REF_RE.match(ref or ""))


def assert_submittable_ref(ref: str) -> str:
    """Validate a reference that arrived from outside before using it.

    Same argument-injection guard as anywhere else -- a reference beginning
    with "-" would be read by the docker CLI as a flag -- but raised as
    BAD_IMAGE_REF, because here the miner chose the whole string rather than
    just a tag buried in an archive.
    """
    try:
        return assert_safe_image_ref(ref)
    except StageFailure as failure:
        raise StageFailure(RejectReason.BAD_IMAGE_REF, failure.detail) from failure


def _classify_pull_failure(stderr: str) -> RejectReason:
    lowered = (stderr or "").lower()
    if any(marker in lowered for marker in _UNAUTHORIZED_MARKERS):
        return RejectReason.REGISTRY_UNAUTHORIZED
    if any(marker in lowered for marker in _NOT_FOUND_MARKERS):
        return RejectReason.IMAGE_NOT_FOUND
    return RejectReason.PULL_FAILED


def _repo_digest_of(
    ref: str, *, runner: DockerRunner | None
) -> str | None:
    """Ask Docker for the digest it recorded for a pulled image.

    RepoDigests is the registry's content address for the manifest -- the
    thing a tag points *at*, and the only stable name for what we pulled.
    """
    result = run_docker(
        ["image", "inspect", "--format", "{{range .RepoDigests}}{{.}}\n{{end}}", ref],
        runner=runner,
        timeout=C.DOCKER_CLI_TIMEOUT_S,
        timeout_reason=RejectReason.DOCKER_UNAVAILABLE,
    )
    if result.returncode != 0:
        return None
    for line in (result.stdout or "").splitlines():
        candidate = line.strip()
        if is_digest_pinned(candidate):
            return candidate
    return None


def pull_image(
    ref: str,
    *,
    runner: DockerRunner | None = None,
    timeout_s: int = C.REGISTRY_PULL_TIMEOUT_S,
) -> PulledImage:
    """Fetch a submitted reference and pin it to a digest.

    A reference that already carries a digest is pulled as-is and there is no
    window at all. A tag is pulled and then resolved, so what gets recorded
    and scored is the digest of the bytes we actually received -- if the tag
    moves afterwards, our record still names what we checked.
    """
    assert_submittable_ref(ref)

    result = run_docker(
        ["pull", "--quiet", ref],
        runner=runner,
        timeout=timeout_s,
        # A pull that never finishes is a property of the image and the
        # registry, not of our daemon.
        timeout_reason=RejectReason.PULL_FAILED,
    )
    if result.returncode != 0:
        raise StageFailure(
            _classify_pull_failure(result.stderr), excerpt(result.stderr)
        )

    if is_digest_pinned(ref):
        digest_ref = ref
    else:
        digest_ref = _repo_digest_of(ref, runner=runner)
        if not digest_ref:
            # Pulled, but Docker knows no registry digest for it -- a local
            # image shadowing the name, or a registry that served no digest.
            # Either way we cannot say what we validated, so we do not.
            raise StageFailure(
                RejectReason.DIGEST_UNRESOLVED,
                f"no repo digest recorded for {ref!r}; refusing to validate an unpinnable image",
            )

    # From here on the digest is the only name used, so nothing downstream can
    # accidentally act on the mutable tag.
    assert_safe_image_ref(digest_ref)
    return PulledImage(requested_ref=ref, digest_ref=digest_ref, image_id=digest_ref)


def remove_pulled(ref: str, *, runner: DockerRunner | None = None) -> bool:
    """Best-effort cleanup of a pulled image. Never raises."""
    from secqurityVali.docker_ops import remove_image

    return remove_image(ref, runner=runner)

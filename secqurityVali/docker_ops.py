from __future__ import annotations

"""secqurityVali/docker_ops.py - stages LOAD and INSPECT: the daemon stages.

This is the first module that hands miner bytes to Docker, and that is worth
being explicit about: `docker load` unpacks an attacker-controlled archive
with a daemon that traditionally runs as root. Stages FILE and STRUCTURE exist
to shrink what reaches this line; they do not make it safe. Until the isolated
runtime exists, treat a successful load as "the daemon parsed hostile input
and survived", not as a guarantee.

Three defences live here:

  * Docker is invoked as an argument list, never through a shell.
  * Every image reference is pattern-checked before being passed back as an
    argument, because repo tags come from the miner. A tag beginning with "-"
    would otherwise be read by the CLI as a flag.
  * A daemon that is down, missing, or unreachable is reported as our fault
    (DOCKER_UNAVAILABLE), never as a failed submission. A miner must not
    collect a rejection because our Docker was off.
"""

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from secqurityVali import constants as C
from secqurityVali.models import RejectReason, StageFailure

# A runner takes CLI arguments (without the leading "docker") and a timeout,
# and returns the completed process. Injectable so the whole module is
# testable without a daemon.
DockerRunner = Callable[[list[str], int], subprocess.CompletedProcess]

_IMAGE_REF_RE = re.compile(C.IMAGE_REF_PATTERN)

# `docker load` announces its result in one of two shapes depending on
# whether the archive carried a tag.
_LOADED_TAG_RE = re.compile(r"^Loaded image:\s*(\S+)\s*$", re.MULTILINE)
_LOADED_ID_RE = re.compile(r"^Loaded image ID:\s*(\S+)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class ImageInfo:
    """What Docker says about the loaded image. Unlike StructureInfo, these
    are facts the daemon established by unpacking, not claims read from the
    archive's own metadata."""

    image_id: str
    repo_tags: list[str] = field(default_factory=list)
    arch: str | None = None
    os_name: str | None = None
    layer_count: int | None = None
    image_size: int | None = None
    entrypoint: list[str] = field(default_factory=list)
    cmd: list[str] = field(default_factory=list)
    image_user: str | None = None
    # The content digests of the image's filesystem layers. These are what
    # identify an agent -- see agent_digest_of() below.
    rootfs_layers: list[str] = field(default_factory=list)


def default_runner(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Invoke the docker CLI. An argument list, never a shell string -- there
    is no command line for miner-controlled text to break out of."""
    return subprocess.run(
        [C.DOCKER_BINARY, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )


def _looks_like_daemon_down(stderr: str) -> bool:
    lowered = (stderr or "").lower()
    return any(marker in lowered for marker in C.DAEMON_DOWN_MARKERS)


def run_docker(
    args: list[str],
    *,
    runner: DockerRunner | None,
    timeout: int,
    timeout_reason: RejectReason,
) -> subprocess.CompletedProcess:
    """Run one docker command, translating the ways it can fail us rather
    than fail the miner."""
    run = runner or default_runner
    try:
        result = run(args, timeout)
    except FileNotFoundError as exc:
        # No docker CLI on PATH at all.
        raise StageFailure(RejectReason.DOCKER_UNAVAILABLE, str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise StageFailure(timeout_reason, f"docker {args[0]} timed out after {timeout}s") from exc
    except OSError as exc:
        raise StageFailure(RejectReason.DOCKER_UNAVAILABLE, str(exc)) from exc

    if result.returncode != 0 and _looks_like_daemon_down(result.stderr):
        raise StageFailure(RejectReason.DOCKER_UNAVAILABLE, excerpt(result.stderr))
    return result


def excerpt(text: str | None, limit: int = 2000) -> str:
    """Docker's stderr is miner-influenced, so it is truncated before being
    stored or logged."""
    if not text:
        return ""
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "... [truncated]"


def assert_safe_image_ref(ref: str) -> str:
    """Refuse any reference we would not want to hand back to the CLI.

    The miner chose the repo tags baked into the archive, so this is the
    boundary that stops an image named "--privileged" or "-v/:/host" from
    being read as a flag by the next docker invocation.
    """
    if not _IMAGE_REF_RE.match(ref or ""):
        raise StageFailure(
            RejectReason.LOAD_FAILED, f"unsafe image reference from docker: {ref!r}"
        )
    return ref


def docker_available(*, runner: DockerRunner | None = None) -> bool:
    """Is there a reachable daemon? Checked before a run so a down daemon is
    a skipped run rather than a rejected miner."""
    try:
        result = run_docker(
            ["version", "--format", "{{.Server.Os}}"],
            runner=runner,
            timeout=C.DOCKER_CLI_TIMEOUT_S,
            timeout_reason=RejectReason.DOCKER_UNAVAILABLE,
        )
    except StageFailure:
        return False
    return result.returncode == 0


def load_image(path: Path | str, *, runner: DockerRunner | None = None) -> str:
    """Run stage LOAD. Returns the image reference Docker reports.

    Hostile bytes meet the daemon here.
    """
    result = run_docker(
        ["load", "--input", str(path)],
        runner=runner,
        timeout=C.DOCKER_LOAD_TIMEOUT_S,
        # A load that never finishes is a property of the archive, so the
        # miner owns this one -- unlike an unreachable daemon.
        timeout_reason=RejectReason.LOAD_FAILED,
    )
    if result.returncode != 0:
        raise StageFailure(RejectReason.LOAD_FAILED, excerpt(result.stderr))

    # Docker prints the outcome to stdout; some versions use stderr.
    output = f"{result.stdout or ''}\n{result.stderr or ''}"
    match = _LOADED_ID_RE.search(output) or _LOADED_TAG_RE.search(output)
    if not match:
        raise StageFailure(
            RejectReason.LOAD_FAILED,
            f"docker load reported no image: {excerpt(output, 500)}",
        )
    return assert_safe_image_ref(match.group(1))


def inspect_image(ref: str, *, runner: DockerRunner | None = None) -> ImageInfo:
    """Ask Docker what it actually unpacked. Metadata only -- nothing in the
    image has executed at this point."""
    assert_safe_image_ref(ref)
    result = run_docker(
        ["image", "inspect", "--format", "{{json .}}", ref],
        runner=runner,
        timeout=C.DOCKER_CLI_TIMEOUT_S,
        timeout_reason=RejectReason.DOCKER_UNAVAILABLE,
    )
    if result.returncode != 0:
        raise StageFailure(RejectReason.LOAD_FAILED, excerpt(result.stderr))

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise StageFailure(
            RejectReason.INTERNAL_ERROR, f"could not parse docker inspect output: {exc}"
        ) from exc

    # `docker image inspect` without --format returns a list; with
    # "{{json .}}" it returns the object. Tolerate both.
    if isinstance(data, list):
        if not data:
            raise StageFailure(RejectReason.LOAD_FAILED, "docker inspect returned nothing")
        data = data[0]
    if not isinstance(data, dict):
        raise StageFailure(RejectReason.INTERNAL_ERROR, "docker inspect returned no object")

    config = data.get("Config") or {}
    rootfs = data.get("RootFS") or {}
    layers = rootfs.get("Layers")
    tags = data.get("RepoTags") or []
    size = data.get("Size")

    return ImageInfo(
        image_id=str(data.get("Id") or ref),
        repo_tags=[str(tag) for tag in tags] if isinstance(tags, list) else [],
        arch=data.get("Architecture"),
        os_name=data.get("Os"),
        layer_count=len(layers) if isinstance(layers, list) else None,
        image_size=int(size) if isinstance(size, (int, float)) else None,
        entrypoint=_as_str_list(config.get("Entrypoint")),
        cmd=_as_str_list(config.get("Cmd")),
        image_user=config.get("User") or None,
        rootfs_layers=_as_str_list(layers),
    )


def agent_digest_of(info: ImageInfo) -> str | None:
    """The identity of an agent: its filesystem layers plus what it runs.

    Why not the submitted file's sha256? Because `docker save` is not
    reproducible -- the same image re-saved can produce different bytes, and
    a miner changing one label or re-tagging changes the file hash completely
    while the agent stays identical. Layer digests are content addresses of
    the filesystem itself, so a re-save, a re-tag and a metadata edit all
    resolve to the same agent.

    Why not the layers alone? Because two images can share a filesystem and
    still be different agents: same binaries, different command. Building
    `ENTRYPOINT ["/agent", "--scan"]` and `ENTRYPOINT ["/agent", "--probe"]`
    from one base produces byte-identical layers, and treating those as one
    agent would reject a miner's second, genuinely different submission as a
    copy of their first. The command is part of what the agent *is*.

    Tags, labels and other cosmetic metadata are deliberately excluded --
    they are free for a copier to change, so including them would weaken the
    identity rather than strengthen it.

    This is not plagiarism detection. A miner who adds one real layer, or
    changes one argument, gets a new identity, and no hash can prevent that:
    catching near-duplicates is a similarity problem, not an equality one.

    Returns None when Docker reported no layers, because an agent we cannot
    identify must not be treated as matching anything.
    """
    if not info.rootfs_layers:
        return None
    # A separator that cannot occur inside a digest or an argv entry, so two
    # different field splits can never produce the same joined string.
    parts = [
        "layers:" + "\n".join(info.rootfs_layers),
        "entrypoint:" + "\n".join(info.entrypoint),
        "cmd:" + "\n".join(info.cmd),
    ]
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def _as_str_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str) and value:
        return [value]
    return []


def check_image(info: ImageInfo, *, config: dict | None = None) -> None:
    """Run stage INSPECT's gates over what Docker reported.

    Separated from inspect_image() so the gates can be exercised against a
    literal ImageInfo, with no daemon and no subprocess in sight.
    """
    settings = config or {}
    expected_arch = settings.get("expected_arch", C.EXPECTED_ARCH)
    expected_os = settings.get("expected_os", C.EXPECTED_OS)
    max_layers = settings.get("max_layers", C.MAX_IMAGE_LAYERS)
    max_size = settings.get("max_size", C.MAX_IMAGE_SIZE_BYTES)

    if info.arch and info.arch != expected_arch:
        raise StageFailure(
            RejectReason.ARCH_MISMATCH, f"image is {info.arch}, validator runs {expected_arch}"
        )
    if info.os_name and info.os_name != expected_os:
        raise StageFailure(
            RejectReason.OS_MISMATCH, f"image targets {info.os_name}, validator runs {expected_os}"
        )
    if info.layer_count is not None and info.layer_count > max_layers:
        raise StageFailure(
            RejectReason.TOO_MANY_LAYERS, f"{info.layer_count} layers exceeds {max_layers}"
        )
    if info.image_size is not None and info.image_size > max_size:
        raise StageFailure(
            RejectReason.IMAGE_TOO_LARGE, f"{info.image_size} bytes unpacked exceeds {max_size}"
        )


def entrypoint_of(info: ImageInfo) -> list[str]:
    """An image that cannot start is not a submission.

    Docker runs Cmd when Entrypoint is empty, so either one satisfies the
    requirement -- but neither means there is nothing to invoke.
    """
    if info.entrypoint:
        return info.entrypoint
    if info.cmd:
        return info.cmd
    raise StageFailure(
        RejectReason.NO_ENTRYPOINT, "image declares neither Entrypoint nor Cmd"
    )


def remove_image(ref: str, *, runner: DockerRunner | None = None) -> bool:
    """Best-effort cleanup. Never raises: a leaked image is an operational
    problem to sweep up later, not grounds to change a miner's verdict."""
    try:
        assert_safe_image_ref(ref)
        result = run_docker(
            ["image", "rm", "--force", ref],
            runner=runner,
            timeout=C.DOCKER_CLI_TIMEOUT_S,
            timeout_reason=RejectReason.INTERNAL_ERROR,
        )
        return result.returncode == 0
    except StageFailure:
        return False

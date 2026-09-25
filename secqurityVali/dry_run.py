from __future__ import annotations

"""secqurityVali/dry_run.py - stage DRY_RUN: the first time miner code runs.

Every stage before this one only inspects. This one executes. The limits below
bound what a submission can consume; they do not contain a hostile agent,
because a container shares the host kernel. Read this module as "resource
limits and a forced kill", never as "sandboxed" -- the isolated runtime
(gVisor, or a microVM) replaces the boundary later, and drops in behind this
same interface.

What is enforced:

  * No network at all. Not the internet, not the host, not a metadata
    endpoint. When the benchmark target exists this becomes a dedicated
    bridge with the target as the only reachable address; the default-deny
    does not change.
  * Memory, CPU, PID and file-descriptor caps, with swap disabled rather
    than used as an overflow.
  * Read-only root, one small noexec scratch area, every Linux capability
    dropped, and no path to regain privilege through a setuid binary.
  * A wall clock, after which the container is killed where it stands.
  * Destruction on every exit path, including timeout and crash.
"""

import re
import time
from dataclasses import dataclass

from secqurityVali import constants as C
from secqurityVali.docker_ops import (
    DockerRunner,
    assert_safe_image_ref,
    excerpt,
    run_docker,
)
from secqurityVali.models import RejectReason, StageFailure

_CONTAINER_ID_RE = re.compile(C.CONTAINER_ID_PATTERN)

# Control characters are stripped from container output before it is stored or
# printed: a terminal escape sequence in a miner's log line should not get to
# repaint an operator's console.
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class DryRunResult:
    """What happened when the image was actually run."""

    exit_code: int | None
    duration_ms: int
    log_excerpt: str
    timed_out: bool = False


def assert_safe_container_id(cid: str) -> str:
    """The same argument-injection guard as image references, applied to ids
    docker hands back on stdout."""
    if not _CONTAINER_ID_RE.match(cid or ""):
        raise StageFailure(
            RejectReason.CREATE_FAILED, f"unsafe container id from docker: {cid!r}"
        )
    return cid


def sanitize_output(text: str | None, limit: int = C.DRY_RUN_LOG_EXCERPT_BYTES) -> str:
    """Make miner-controlled output safe to store and print."""
    if not text:
        return ""
    cleaned = _ANSI_ESCAPE_RE.sub("", text)
    cleaned = _CONTROL_CHARS_RE.sub("", cleaned)
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "\n... [truncated]"
    return cleaned


def create_args(ref: str, limits: dict | None = None) -> list[str]:
    """The full flag set the container is created with.

    Built as a list so a test can assert on it -- a silently dropped limit is
    exactly the kind of regression that stays invisible otherwise.
    """
    settings = limits or {}
    return [
        "create",
        # Default-deny egress.
        "--network", settings.get("network", C.DRY_RUN_NETWORK),
        "--memory", settings.get("memory", C.DRY_RUN_MEMORY),
        # Equal to --memory, which disables swap rather than granting more.
        "--memory-swap", settings.get("memory_swap", C.DRY_RUN_MEMORY_SWAP),
        "--cpus", str(settings.get("cpus", C.DRY_RUN_CPUS)),
        # Caps fork bombs.
        "--pids-limit", str(settings.get("pids_limit", C.DRY_RUN_PIDS_LIMIT)),
        "--ulimit", f"nofile={settings.get('nofile', C.DRY_RUN_NOFILE_ULIMIT)}",
        # Nothing written to the image layer survives; one small noexec
        # scratch area exists for work that genuinely needs a filesystem.
        "--read-only",
        "--tmpfs", settings.get("tmpfs", C.DRY_RUN_TMPFS),
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--label", C.DRY_RUN_LABEL,
        ref,
    ]


def _create_container(
    ref: str, *, runner: DockerRunner | None, limits: dict | None = None
) -> str:
    result = run_docker(
        create_args(ref, limits),
        runner=runner,
        timeout=C.DOCKER_CLI_TIMEOUT_S,
        timeout_reason=RejectReason.CREATE_FAILED,
    )
    if result.returncode != 0:
        raise StageFailure(RejectReason.CREATE_FAILED, excerpt(result.stderr))
    return assert_safe_container_id((result.stdout or "").strip())


def _container_logs(cid: str, *, runner: DockerRunner | None) -> str:
    try:
        result = run_docker(
            ["logs", cid],
            runner=runner,
            timeout=C.DOCKER_CLI_TIMEOUT_S,
            timeout_reason=RejectReason.INTERNAL_ERROR,
        )
    except StageFailure:
        # Logs are evidence, not a verdict. Losing them does not change the
        # outcome of the run.
        return ""
    return sanitize_output(f"{result.stdout or ''}{result.stderr or ''}")


def _force_kill(cid: str, *, runner: DockerRunner | None) -> None:
    try:
        run_docker(
            ["kill", cid],
            runner=runner,
            timeout=C.DOCKER_CLI_TIMEOUT_S,
            timeout_reason=RejectReason.INTERNAL_ERROR,
        )
    except StageFailure:
        pass  # the removal below is forced regardless


def remove_container(cid: str, *, runner: DockerRunner | None = None) -> bool:
    """Best-effort, forced, and never raises -- the container must go away
    whatever else happened."""
    try:
        assert_safe_container_id(cid)
        result = run_docker(
            ["rm", "--force", "--volumes", cid],
            runner=runner,
            timeout=C.DOCKER_CLI_TIMEOUT_S,
            timeout_reason=RejectReason.INTERNAL_ERROR,
        )
        return result.returncode == 0
    except StageFailure:
        return False


def _parse_exit_code(stdout: str | None) -> int | None:
    """`docker wait` prints the exit code and nothing else."""
    try:
        return int((stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None


def dry_run(
    ref: str,
    *,
    runner: DockerRunner | None = None,
    timeout_s: int = C.DRY_RUN_TIMEOUT_S,
    limits: dict | None = None,
) -> DryRunResult:
    """Run the image under hard limits and a wall clock, then destroy it."""
    assert_safe_image_ref(ref)
    cid = _create_container(ref, runner=runner, limits=limits)

    started = time.monotonic()
    exit_code: int | None = None
    timed_out = False

    try:
        result = run_docker(
            ["start", cid],
            runner=runner,
            timeout=C.DOCKER_CLI_TIMEOUT_S,
            timeout_reason=RejectReason.START_FAILED,
        )
        if result.returncode != 0:
            # The entrypoint could not execute at all -- a missing binary, or
            # a mismatch the daemon only discovers at exec time.
            raise StageFailure(RejectReason.START_FAILED, excerpt(result.stderr))

        try:
            waited = run_docker(
                ["wait", cid],
                runner=runner,
                timeout=timeout_s,
                timeout_reason=RejectReason.DRY_RUN_TIMEOUT,
            )
            exit_code = _parse_exit_code(waited.stdout)
        except StageFailure as failure:
            if failure.reason is not RejectReason.DRY_RUN_TIMEOUT:
                raise
            # The clock ran out. Kill it where it stands -- the verdict is
            # decided by the gate below, not by what it would have done next.
            timed_out = True
            _force_kill(cid, runner=runner)

        return DryRunResult(
            exit_code=exit_code,
            duration_ms=int((time.monotonic() - started) * 1000),
            log_excerpt=_container_logs(cid, runner=runner),
            timed_out=timed_out,
        )
    finally:
        # Runs on success, rejection, timeout and crash alike.
        remove_container(cid, runner=runner)


def check_dry_run(
    result: DryRunResult, *, require_zero_exit: bool = C.DRY_RUN_REQUIRE_ZERO_EXIT
) -> None:
    """The gate: did the image actually work?"""
    if result.timed_out:
        raise StageFailure(
            RejectReason.DRY_RUN_TIMEOUT,
            f"killed after {result.duration_ms} ms without exiting",
        )
    if require_zero_exit and result.exit_code != 0:
        raise StageFailure(
            RejectReason.DRY_RUN_NONZERO_EXIT, f"exited with code {result.exit_code}"
        )

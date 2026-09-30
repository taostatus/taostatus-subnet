"""Tests for the pipeline: stages wired together into one Verdict, recorded.

Docker is faked, so these cover the wiring -- short-circuiting, evidence
carried forward from earlier stages, and cleanup on every exit path.
"""

import io
import json
import subprocess
import tarfile

import pytest

from secqurityVali import db
from secqurityVali.models import RejectReason, Stage, Status
from secqurityVali.pipeline import check_and_record, check_submission


# --- fixtures ----------------------------------------------------------

def _add_file(tar, name, data: bytes):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def make_image_tar(path, tag="agent:v1"):
    manifest = json.dumps([
        {"Config": "config.json", "RepoTags": [tag], "Layers": ["l0/layer.tar"]}
    ]).encode()
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "manifest.json", manifest)
        _add_file(tar, "config.json", b"{}")
        _add_file(tar, "l0/layer.tar", b"\x00" * 64)
    return path


INSPECT_OK = json.dumps({
    "Id": "sha256:" + "f" * 64,
    "RepoTags": ["agent:v1"],
    "Architecture": "amd64",
    "Os": "linux",
    "Size": 50_000_000,
    "RootFS": {"Layers": ["sha256:a"]},
    "Config": {"Entrypoint": ["/usr/bin/agent"], "User": "agent"},
})


CID = "c" * 64


def fake_docker(*, inspect=INSPECT_OK, load_rc=0, load_err="",
                exit_code="0", logs="done\n", wait_timeout=False, calls=None):
    """A daemon that loads, inspects and runs successfully unless told
    otherwise -- every verb the pipeline uses, end to end."""
    def run(args, timeout):
        if calls is not None:
            calls.append(args[0] if args[0] != "image" else f"image {args[1]}")
        if args[0] == "load":
            return subprocess.CompletedProcess(
                args, load_rc, "Loaded image: agent:v1\n" if load_rc == 0 else "", load_err)
        if args[:2] == ["image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, inspect, "")
        if args[:2] == ["image", "rm"]:
            return subprocess.CompletedProcess(args, 0, "Untagged: agent:v1\n", "")
        if args[0] == "create":
            return subprocess.CompletedProcess(args, 0, CID + "\n", "")
        if args[0] == "wait":
            if wait_timeout:
                raise subprocess.TimeoutExpired("docker", timeout)
            return subprocess.CompletedProcess(args, 0, f"{exit_code}\n", "")
        if args[0] == "logs":
            return subprocess.CompletedProcess(args, 0, logs, "")
        return subprocess.CompletedProcess(args, 0, "", "")
    return run


# --- the accept path ---------------------------------------------------

def test_valid_image_is_accepted_with_full_evidence(tmp_path):
    verdict = check_submission(
        make_image_tar(tmp_path / "agent.tar"), "miner-1", runner=fake_docker())

    assert verdict.status is Status.ACCEPTED
    assert verdict.stage_reached is Stage.DRY_RUN
    assert verdict.reject_reason is None
    assert verdict.dry_run_exit_code == 0
    assert "done" in verdict.log_excerpt
    assert len(verdict.file_sha256) == 64
    assert verdict.image_id == "sha256:" + "f" * 64
    assert verdict.arch == "amd64" and verdict.os_name == "linux"
    assert verdict.entrypoint == ["/usr/bin/agent"]
    assert verdict.image_user == "agent"


def test_accepted_stage_claims_only_what_was_proven(tmp_path):
    """With the dry run skipped nothing executed, so the verdict must say
    INSPECT and must not carry a result it never obtained."""
    verdict = check_submission(
        make_image_tar(tmp_path / "agent.tar"), "m",
        runner=fake_docker(), skip_dry_run=True)
    assert verdict.status is Status.ACCEPTED
    assert verdict.stage_reached is Stage.INSPECT
    assert verdict.dry_run_exit_code is None
    assert verdict.log_excerpt is None


def test_image_that_fails_when_run_is_rejected_at_dry_run(tmp_path):
    verdict = check_submission(
        make_image_tar(tmp_path / "agent.tar"), "m",
        runner=fake_docker(exit_code="1", logs="crashed\n"))

    assert verdict.reject_reason is RejectReason.DRY_RUN_NONZERO_EXIT
    assert verdict.stage_reached is Stage.DRY_RUN
    # The run happened, so its evidence is recorded even though it failed.
    assert verdict.dry_run_exit_code == 1
    assert "crashed" in verdict.log_excerpt


def test_agent_that_never_exits_is_killed_and_rejected(tmp_path):
    calls = []
    verdict = check_submission(
        make_image_tar(tmp_path / "agent.tar"), "m",
        runner=fake_docker(wait_timeout=True, calls=calls))

    assert verdict.reject_reason is RejectReason.DRY_RUN_TIMEOUT
    assert verdict.stage_reached is Stage.DRY_RUN
    assert "kill" in calls          # killed where it stands
    assert calls.count("rm") == 1   # the container, destroyed
    assert "image rm" in calls      # and the image behind it


# --- short-circuiting and carried evidence -----------------------------

def test_not_an_image_never_reaches_docker(tmp_path):
    path = tmp_path / "source.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "README.md", b"hello")

    calls = []
    verdict = check_submission(path, "m", runner=fake_docker(calls=calls))

    assert verdict.reject_reason is RejectReason.NOT_A_DOCKER_IMAGE
    assert verdict.stage_reached is Stage.STRUCTURE
    assert calls == []  # the daemon was never asked anything


def test_evidence_from_earlier_stages_survives_rejection(tmp_path):
    archive = make_image_tar(tmp_path / "agent.tar")
    runner = fake_docker(load_rc=1, load_err="invalid tar header")

    verdict = check_submission(archive, "m", runner=runner)

    assert verdict.reject_reason is RejectReason.LOAD_FAILED
    assert verdict.stage_reached is Stage.LOAD
    # FILE and STRUCTURE already established these before LOAD failed.
    assert len(verdict.file_sha256) == 64
    assert verdict.file_size == archive.stat().st_size
    assert verdict.repo_tags == ["agent:v1"]


def test_missing_file_is_a_verdict_not_an_exception(tmp_path):
    verdict = check_submission(tmp_path / "nope.tar", "m", runner=fake_docker())
    assert verdict.reject_reason is RejectReason.FILE_MISSING
    assert verdict.stage_reached is Stage.FILE


def test_inspect_gate_failure_is_attributed_to_inspect(tmp_path):
    arm = json.loads(INSPECT_OK)
    arm["Architecture"] = "arm64"
    verdict = check_submission(
        make_image_tar(tmp_path / "agent.tar"), "m",
        runner=fake_docker(inspect=json.dumps(arm)))

    assert verdict.reject_reason is RejectReason.ARCH_MISMATCH
    assert verdict.stage_reached is Stage.INSPECT
    # Inspect ran, so its findings are on the record even though it failed.
    assert verdict.arch == "arm64"


def test_image_with_nothing_to_run_is_rejected(tmp_path):
    bare = json.loads(INSPECT_OK)
    bare["Config"] = {}
    verdict = check_submission(
        make_image_tar(tmp_path / "agent.tar"), "m",
        runner=fake_docker(inspect=json.dumps(bare)))
    assert verdict.reject_reason is RejectReason.NO_ENTRYPOINT


# --- never raises ------------------------------------------------------

def test_unexpected_error_becomes_a_verdict(tmp_path):
    def exploding(args, timeout):
        raise RuntimeError("daemon exploded in a novel way")

    verdict = check_submission(
        make_image_tar(tmp_path / "agent.tar"), "m", runner=exploding)

    assert verdict.reject_reason is RejectReason.INTERNAL_ERROR
    assert verdict.validator_fault is True
    assert "RuntimeError" in verdict.error_detail


def test_daemon_down_is_not_held_against_the_miner(tmp_path):
    runner = fake_docker(load_rc=1, load_err="Cannot connect to the Docker daemon")
    verdict = check_submission(make_image_tar(tmp_path / "agent.tar"), "m", runner=runner)

    assert verdict.reject_reason is RejectReason.DOCKER_UNAVAILABLE
    assert verdict.validator_fault is True


# --- cleanup -----------------------------------------------------------

def test_loaded_image_is_removed_after_acceptance(tmp_path):
    calls = []
    check_submission(make_image_tar(tmp_path / "agent.tar"), "m",
                     runner=fake_docker(calls=calls))
    assert "image rm" in calls


def test_loaded_image_is_removed_after_rejection(tmp_path):
    arm = json.loads(INSPECT_OK)
    arm["Os"] = "windows"
    calls = []
    verdict = check_submission(
        make_image_tar(tmp_path / "agent.tar"), "m",
        runner=fake_docker(inspect=json.dumps(arm), calls=calls))

    assert verdict.reject_reason is RejectReason.OS_MISMATCH
    assert "image rm" in calls  # rejection does not leak the image


def test_keep_image_leaves_it_loaded(tmp_path):
    calls = []
    check_submission(make_image_tar(tmp_path / "agent.tar"), "m",
                     runner=fake_docker(calls=calls), keep_image=True)
    assert "image rm" not in calls


def test_nothing_to_remove_when_load_never_succeeded(tmp_path):
    path = tmp_path / "source.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "README.md", b"x")
    calls = []
    check_submission(path, "m", runner=fake_docker(calls=calls))
    assert calls == []


# --- the database write ------------------------------------------------

def test_accepted_submission_is_recorded(tmp_path):
    conn = db.connect(":memory:")
    row_id, verdict, elapsed_ms = check_and_record(
        conn, make_image_tar(tmp_path / "agent.tar"), "miner-9", runner=fake_docker())

    stored = db.get_submission(conn, row_id)
    assert stored["status"] == "accepted"
    assert stored["miner_id"] == "miner-9"
    assert stored["entrypoint"] == ["/usr/bin/agent"]
    assert stored["dry_run_exit_code"] == 0
    assert stored["dry_run_ms"] is not None
    assert elapsed_ms >= 0


def test_rejected_submission_is_recorded_too(tmp_path):
    """A rejected image that leaves no trace is one nobody can audit."""
    conn = db.connect(":memory:")
    path = tmp_path / "source.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "README.md", b"x")

    row_id, verdict, _ = check_and_record(conn, path, "miner-9", runner=fake_docker())
    stored = db.get_submission(conn, row_id)
    assert stored["status"] == "rejected"
    assert stored["reject_reason"] == "not_a_docker_image"


def test_resubmission_is_visible_by_hash(tmp_path):
    """Both attempts stay in the log, newest first."""
    conn = db.connect(":memory:")
    archive = make_image_tar(tmp_path / "agent.tar")
    check_and_record(conn, archive, "m", runner=fake_docker(load_rc=1, load_err="boom"))
    _, verdict, _ = check_and_record(conn, archive, "m", runner=fake_docker())

    history = db.submissions_for_sha256(conn, verdict.file_sha256)
    assert len(history) == 2
    # The bytes already failed, so the second attempt replays that verdict
    # rather than spending another run on them.
    assert history[0]["from_cache"] is True
    assert history[0]["reject_reason"] == "load_failed"
    assert history[1]["from_cache"] is False

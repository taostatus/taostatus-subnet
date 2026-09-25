"""Tests for secval's verdict vocabulary and its SQLite log."""

import secqurityVali.db as db
from secqurityVali.models import RejectReason, Stage, Status, accept, reject


def test_schema_applied_on_connect():
    conn = db.connect(":memory:")
    assert db.schema_version(conn) == db.SCHEMA_VERSION
    assert db.recent_submissions(conn) == []


def test_rejected_verdict_keeps_stage_and_reason():
    conn = db.connect(":memory:")
    verdict = reject(
        "miner-1", "bad.tar", Stage.STRUCTURE, RejectReason.NOT_A_DOCKER_IMAGE,
        file_sha256="a" * 64, file_size=1234,
    )
    row_id = db.record_verdict(conn, verdict)

    stored = db.get_submission(conn, row_id)
    assert stored["status"] == Status.REJECTED.value
    assert stored["stage_reached"] == Stage.STRUCTURE.value
    assert stored["reject_reason"] == RejectReason.NOT_A_DOCKER_IMAGE.value
    assert stored["file_sha256"] == "a" * 64
    # Nothing past the failing stage was ever established.
    assert stored["image_id"] is None
    assert stored["dry_run_exit_code"] is None
    assert stored["entrypoint"] == []


def test_accepted_verdict_round_trips_lists_and_ints():
    conn = db.connect(":memory:")
    verdict = accept(
        "miner-2", "good.tar",
        file_sha256="b" * 64, file_size=5_000_000,
        image_id="sha256:deadbeef", repo_tags=["agent:v1"],
        arch="amd64", os_name="linux", layer_count=4, image_size=42_000_000,
        entrypoint=["/usr/bin/agent", "--run"], image_user="agent",
        dry_run_exit_code=0, dry_run_ms=812, log_excerpt="started\n",
    )
    stored = db.get_submission(conn, db.record_verdict(conn, verdict))

    assert stored["status"] == Status.ACCEPTED.value
    assert stored["stage_reached"] == Stage.INSPECT.value
    assert stored["reject_reason"] is None
    assert stored["repo_tags"] == ["agent:v1"]
    assert stored["entrypoint"] == ["/usr/bin/agent", "--run"]
    assert stored["layer_count"] == 4
    assert stored["dry_run_ms"] == 812


def test_resubmission_appends_rather_than_overwrites():
    conn = db.connect(":memory:")
    sha = "c" * 64
    db.record_verdict(conn, reject(
        "miner-3", "x.tar", Stage.LOAD, RejectReason.LOAD_FAILED, file_sha256=sha))
    db.record_verdict(conn, accept("miner-3", "x.tar", file_sha256=sha, dry_run_exit_code=0))

    history = db.submissions_for_sha256(conn, sha)
    assert len(history) == 2
    # Newest first: the accepted retry leads, the earlier failure is still there.
    assert history[0]["status"] == Status.ACCEPTED.value
    assert history[1]["reject_reason"] == RejectReason.LOAD_FAILED.value


def test_validator_fault_is_separable_from_miner_failure():
    daemon_down = reject("m", "x.tar", Stage.LOAD, RejectReason.DOCKER_UNAVAILABLE)
    bad_image = reject("m", "x.tar", Stage.LOAD, RejectReason.LOAD_FAILED)
    assert daemon_down.validator_fault is True
    assert bad_image.validator_fault is False


def test_db_file_is_created_on_disk(tmp_path):
    db_path = tmp_path / "nested" / "secqurityVali.db"
    conn = db.connect(db_path)
    db.record_verdict(conn, reject("m", "x.tar", Stage.FILE, RejectReason.FILE_MISSING))
    conn.close()

    assert db_path.exists()
    reopened = db.connect(db_path)
    assert len(db.recent_submissions(reopened)) == 1

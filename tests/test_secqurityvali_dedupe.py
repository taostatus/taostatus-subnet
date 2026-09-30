"""Tests for agent identity and deduplication.

Two rules under test:

  * the same agent is stored once, no matter how many times it is submitted;
  * every attempt is still logged, so "who tried to submit what" stays
    answerable.
"""

import io
import json
import subprocess
import tarfile

import pytest

from secqurityVali import db
from secqurityVali.docker_ops import ImageInfo, agent_digest_of
from secqurityVali.models import RejectReason, Stage, Status
from secqurityVali.pipeline import check_and_record


# --- fixtures ----------------------------------------------------------

def _add_file(tar, name, data: bytes):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def make_image_tar(path, tag="agent:v1", filler=b"\x00" * 64):
    manifest = json.dumps([
        {"Config": "config.json", "RepoTags": [tag], "Layers": ["l0/layer.tar"]}
    ]).encode()
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "manifest.json", manifest)
        _add_file(tar, "config.json", b"{}")
        _add_file(tar, "l0/layer.tar", filler)
    return path


def inspect_json(layers=("sha256:aaa", "sha256:bbb"), image_id="sha256:" + "f" * 64,
                 tags=("agent:v1",)):
    return json.dumps({
        "Id": image_id,
        "RepoTags": list(tags),
        "Architecture": "amd64",
        "Os": "linux",
        "Size": 50_000_000,
        "RootFS": {"Layers": list(layers)},
        "Config": {"Entrypoint": ["/usr/bin/agent"], "User": "agent"},
    })


def fake_docker(*, inspect=None, load_rc=0, load_err="", exit_code="0", calls=None):
    inspect = inspect or inspect_json()

    def run(args, timeout):
        if calls is not None:
            calls.append(args[0] if args[0] != "image" else f"image {args[1]}")
        if args[0] == "load":
            return subprocess.CompletedProcess(
                args, load_rc, "Loaded image: agent:v1\n" if load_rc == 0 else "", load_err)
        if args[:2] == ["image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, inspect, "")
        if args[0] == "create":
            return subprocess.CompletedProcess(args, 0, "c" * 64 + "\n", "")
        if args[0] == "wait":
            return subprocess.CompletedProcess(args, 0, f"{exit_code}\n", "")
        if args[0] == "logs":
            return subprocess.CompletedProcess(args, 0, "done\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")
    return run


# --- what counts as "the same agent" -----------------------------------

def test_identity_is_the_layers_not_the_tags():
    """Re-tagging or re-saving must not create a new agent."""
    original = ImageInfo(image_id="sha256:1", repo_tags=["agent:v1"],
                         rootfs_layers=["sha256:a", "sha256:b"])
    retagged = ImageInfo(image_id="sha256:2", repo_tags=["stolen:latest"],
                         rootfs_layers=["sha256:a", "sha256:b"])
    assert agent_digest_of(original) == agent_digest_of(retagged)


def test_different_layers_are_different_agents():
    one = ImageInfo(image_id="x", rootfs_layers=["sha256:a"])
    two = ImageInfo(image_id="x", rootfs_layers=["sha256:a", "sha256:b"])
    assert agent_digest_of(one) != agent_digest_of(two)


def test_layer_order_matters():
    one = ImageInfo(image_id="x", rootfs_layers=["sha256:a", "sha256:b"])
    two = ImageInfo(image_id="x", rootfs_layers=["sha256:b", "sha256:a"])
    assert agent_digest_of(one) != agent_digest_of(two)


def test_same_filesystem_different_command_are_different_agents():
    """Found by running this for real: two images built from one base with
    different ENTRYPOINTs have byte-identical layers, because the command
    lives in the config, not in a layer. Treating them as one agent would
    reject a miner's second, genuinely different submission as a copy of
    their own first."""
    scanner = ImageInfo(image_id="x", rootfs_layers=["sha256:a"],
                        entrypoint=["/agent", "--scan"])
    prober = ImageInfo(image_id="y", rootfs_layers=["sha256:a"],
                       entrypoint=["/agent", "--probe"])
    assert agent_digest_of(scanner) != agent_digest_of(prober)


def test_cmd_counts_toward_identity_too():
    one = ImageInfo(image_id="x", rootfs_layers=["sha256:a"], cmd=["--fast"])
    two = ImageInfo(image_id="x", rootfs_layers=["sha256:a"], cmd=["--deep"])
    assert agent_digest_of(one) != agent_digest_of(two)


def test_field_boundaries_cannot_be_forged():
    """Splitting the same text differently across fields must not collide."""
    one = ImageInfo(image_id="x", rootfs_layers=["sha256:a"],
                    entrypoint=["run", "now"], cmd=[])
    two = ImageInfo(image_id="x", rootfs_layers=["sha256:a"],
                    entrypoint=["run"], cmd=["now"])
    assert agent_digest_of(one) != agent_digest_of(two)


def test_unidentifiable_image_matches_nothing():
    """No layers reported means no identity -- never a wildcard match."""
    assert agent_digest_of(ImageInfo(image_id="x")) is None


# --- the agent is stored once ------------------------------------------

def test_agent_is_stored_once_however_many_times_it_is_submitted(tmp_path):
    conn = db.connect(":memory:")
    archive = make_image_tar(tmp_path / "agent.tar")

    for _ in range(4):
        check_and_record(conn, archive, "miner-A", runner=fake_docker())

    assert db.agent_count(conn) == 1                      # stored once
    assert len(db.recent_submissions(conn, 10)) == 4      # attempted four times


def test_the_agent_row_records_its_owner(tmp_path):
    conn = db.connect(":memory:")
    row_id, verdict, _ = check_and_record(
        conn, make_image_tar(tmp_path / "agent.tar"), "miner-A", runner=fake_docker())

    agent = db.get_agent(conn, verdict.agent_digest)
    assert agent["owner_miner_id"] == "miner-A"
    assert agent["first_submission"] == row_id
    assert agent["entrypoint"] == ["/usr/bin/agent"]


def test_rejected_agents_are_not_registered(tmp_path):
    """Nothing to own -- a broken image confers no claim on anything."""
    conn = db.connect(":memory:")
    check_and_record(conn, make_image_tar(tmp_path / "agent.tar"), "miner-A",
                     runner=fake_docker(exit_code="1"))
    assert db.agent_count(conn) == 0


# --- same miner resubmitting -------------------------------------------

def test_resubmit_replays_the_verdict_without_rerunning(tmp_path):
    conn = db.connect(":memory:")
    archive = make_image_tar(tmp_path / "agent.tar")
    check_and_record(conn, archive, "miner-A", runner=fake_docker())

    calls = []
    _, verdict, _ = check_and_record(
        conn, archive, "miner-A", runner=fake_docker(calls=calls))

    assert verdict.from_cache is True
    assert verdict.status is Status.ACCEPTED
    assert calls == []   # Docker was never asked to do anything


def test_repackaged_agent_is_recognised_after_inspect(tmp_path):
    """Different bytes, same layers -- the file hash misses it, the agent
    digest does not."""
    conn = db.connect(":memory:")
    first = make_image_tar(tmp_path / "a.tar", filler=b"\x00" * 64)
    second = make_image_tar(tmp_path / "b.tar", tag="agent:v2", filler=b"\x11" * 128)

    _, v1, _ = check_and_record(conn, first, "miner-A", runner=fake_docker())
    _, v2, _ = check_and_record(conn, second, "miner-A", runner=fake_docker())

    assert v1.file_sha256 != v2.file_sha256      # the bytes differ
    assert v2.from_cache is True                 # the agent does not
    assert db.agent_count(conn) == 1


def test_the_attempt_is_still_logged_when_cached(tmp_path):
    conn = db.connect(":memory:")
    archive = make_image_tar(tmp_path / "agent.tar")
    first_id, _, _ = check_and_record(conn, archive, "miner-A", runner=fake_docker())
    second_id, _, _ = check_and_record(conn, archive, "miner-A", runner=fake_docker())

    stored = db.get_submission(conn, second_id)
    assert stored["from_cache"] is True
    assert stored["duplicate_of"] == first_id    # points at the real work


# --- a different miner submitting the same agent -----------------------

def test_another_miner_submitting_the_same_bytes_is_rejected(tmp_path):
    conn = db.connect(":memory:")
    archive = make_image_tar(tmp_path / "agent.tar")
    first_id, _, _ = check_and_record(conn, archive, "miner-A", runner=fake_docker())

    calls = []
    _, verdict, _ = check_and_record(
        conn, archive, "miner-B", runner=fake_docker(calls=calls))

    assert verdict.reject_reason is RejectReason.DUPLICATE_AGENT
    assert verdict.stage_reached is Stage.FILE    # caught before Docker
    assert verdict.duplicate_of == first_id
    assert "miner-A" in verdict.error_detail
    assert calls == []


def test_another_miner_repackaging_it_is_also_rejected(tmp_path):
    """Changing the bytes defeats the file hash but not the layer digest."""
    conn = db.connect(":memory:")
    check_and_record(conn, make_image_tar(tmp_path / "a.tar"), "miner-A",
                     runner=fake_docker())

    stolen = make_image_tar(tmp_path / "b.tar", tag="mine:v9", filler=b"\x22" * 256)
    _, verdict, _ = check_and_record(conn, stolen, "miner-B", runner=fake_docker())

    assert verdict.reject_reason is RejectReason.DUPLICATE_AGENT
    assert verdict.stage_reached is Stage.INSPECT  # caught after inspect
    assert "miner-A" in verdict.error_detail
    assert db.agent_count(conn) == 1               # still owned by A alone


def test_a_genuinely_different_agent_from_another_miner_is_fine(tmp_path):
    conn = db.connect(":memory:")
    check_and_record(conn, make_image_tar(tmp_path / "a.tar"), "miner-A",
                     runner=fake_docker())

    _, verdict, _ = check_and_record(
        conn, make_image_tar(tmp_path / "b.tar", tag="other:v1", filler=b"\x33" * 32),
        "miner-B",
        runner=fake_docker(inspect=inspect_json(layers=["sha256:zzz"])))

    assert verdict.status is Status.ACCEPTED
    assert db.agent_count(conn) == 2


def test_bytes_that_were_rejected_confer_no_ownership(tmp_path):
    """miner-A submitted a broken image. miner-B may still try the same one
    and be judged on its merits."""
    conn = db.connect(":memory:")
    archive = make_image_tar(tmp_path / "agent.tar")
    check_and_record(conn, archive, "miner-A", runner=fake_docker(exit_code="1"))

    _, verdict, _ = check_and_record(conn, archive, "miner-B", runner=fake_docker())
    assert verdict.reject_reason is not RejectReason.DUPLICATE_AGENT
    assert verdict.status is Status.ACCEPTED


# --- the outage trap ---------------------------------------------------

def test_our_own_failure_is_never_cached(tmp_path):
    """A run that died because Docker was unreachable never judged the image.
    Replaying it would make a temporary outage permanent and retrying
    pointless."""
    conn = db.connect(":memory:")
    archive = make_image_tar(tmp_path / "agent.tar")

    _, outage, _ = check_and_record(
        conn, archive, "miner-A",
        runner=fake_docker(load_rc=1, load_err="Cannot connect to the Docker daemon"))
    assert outage.reject_reason is RejectReason.DOCKER_UNAVAILABLE

    _, retry, _ = check_and_record(conn, archive, "miner-A", runner=fake_docker())
    assert retry.from_cache is False
    assert retry.status is Status.ACCEPTED


# --- dedupe is optional ------------------------------------------------

def test_dedupe_can_be_turned_off(tmp_path):
    conn = db.connect(":memory:")
    archive = make_image_tar(tmp_path / "agent.tar")
    check_and_record(conn, archive, "miner-A", runner=fake_docker(), dedupe=False)
    _, verdict, _ = check_and_record(
        conn, archive, "miner-A", runner=fake_docker(), dedupe=False)

    assert verdict.from_cache is False
    assert db.agent_count(conn) == 0   # nothing registered either


# --- migration from a v1 database --------------------------------------

def test_an_older_database_gains_the_new_columns(tmp_path):
    """A database written before dedupe existed must not have to be deleted."""
    path = tmp_path / "old.db"
    old = __import__("sqlite3").connect(str(path))
    old.executescript(
        "CREATE TABLE submissions (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "miner_id TEXT NOT NULL, received_at TEXT NOT NULL, file_path TEXT NOT NULL, "
        "status TEXT NOT NULL, stage_reached TEXT NOT NULL, reject_reason TEXT, "
        "file_sha256 TEXT, file_size INTEGER, image_id TEXT, repo_tags TEXT, "
        "arch TEXT, os_name TEXT, layer_count INTEGER, image_size INTEGER, "
        "entrypoint TEXT, image_user TEXT, dry_run_exit_code INTEGER, "
        "dry_run_ms INTEGER, log_excerpt TEXT, error_detail TEXT);"
    )
    old.execute(
        "INSERT INTO submissions (miner_id, received_at, file_path, status, stage_reached) "
        "VALUES ('old-miner', '2026-01-01', 'x.tar', 'accepted', 'inspect')"
    )
    old.commit()
    old.close()

    conn = db.connect(path)
    assert db.schema_version(conn) == db.SCHEMA_VERSION
    rows = db.recent_submissions(conn, 10)
    assert len(rows) == 1                       # the old row survived
    assert rows[0]["from_cache"] is False       # and gained the new columns
    assert rows[0]["agent_digest"] is None

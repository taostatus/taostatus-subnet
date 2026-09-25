"""Tests for registry intake and the validator API.

Docker and the network are both faked. What is under test is our handling:
digest pinning, how pull failures are attributed, and the API's contract.
"""

import json
import subprocess
import threading
import urllib.error
import urllib.request

import pytest

from secqurityVali import api as api_mod
from secqurityVali import db
from secqurityVali.models import SOURCE_REGISTRY, RejectReason, Stage, Status
from secqurityVali.pipeline import check_and_record, check_registry_submission
from secqurityVali.registry import (
    assert_submittable_ref,
    is_digest_pinned,
    pull_image,
)

DIGEST = "sha256:" + "d" * 64
REPO = "ghcr.io/taostatus/taostatus-demo-agent"
TAG_REF = f"{REPO}:0.1.0"
DIGEST_REF = f"{REPO}@{DIGEST}"

INSPECT_OK = json.dumps({
    "Id": "sha256:" + "f" * 64,
    "RepoTags": [f"{REPO}:0.1.0"],
    "RepoDigests": [DIGEST_REF],
    "Architecture": "amd64",
    "Os": "linux",
    "Size": 50_000_000,
    "RootFS": {"Layers": ["sha256:aaa"]},
    "Config": {"Entrypoint": ["/agent"], "User": "agent"},
})


def fake_docker(*, pull_rc=0, pull_err="", repo_digests=DIGEST_REF,
                inspect=INSPECT_OK, exit_code="0", calls=None):
    def run(args, timeout):
        if calls is not None:
            calls.append(args[0] if args[0] != "image" else f"image {args[1]}")
        if args[0] == "pull":
            return subprocess.CompletedProcess(args, pull_rc, "", pull_err)
        if args[:2] == ["image", "inspect"]:
            fmt = args[3] if len(args) > 3 else ""
            if "RepoDigests" in fmt:
                return subprocess.CompletedProcess(args, 0, repo_digests + "\n", "")
            return subprocess.CompletedProcess(args, 0, inspect, "")
        if args[0] == "create":
            return subprocess.CompletedProcess(args, 0, "c" * 64 + "\n", "")
        if args[0] == "wait":
            return subprocess.CompletedProcess(args, 0, f"{exit_code}\n", "")
        if args[0] == "logs":
            return subprocess.CompletedProcess(args, 0, "scan complete\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")
    return run


# --- references --------------------------------------------------------

def test_tag_is_not_digest_pinned():
    assert is_digest_pinned(TAG_REF) is False


def test_digest_ref_is_pinned():
    assert is_digest_pinned(DIGEST_REF) is True


@pytest.mark.parametrize("ref", ["--privileged", "-v/:/host", "", "a b"])
def test_hostile_references_from_http_are_refused(ref):
    """The reference now arrives over HTTP, so it is attacker-controlled in
    the most direct sense."""
    with pytest.raises(Exception) as err:
        assert_submittable_ref(ref)
    assert err.value.reason is RejectReason.BAD_IMAGE_REF


# --- pulling -----------------------------------------------------------

def test_tag_is_resolved_to_a_digest():
    """What gets validated must be the digest: a tag can be repointed to
    other bytes the moment after we rule on it."""
    pulled = pull_image(TAG_REF, runner=fake_docker())
    assert pulled.requested_ref == TAG_REF
    assert pulled.digest_ref == DIGEST_REF


def test_a_digest_reference_is_used_as_submitted():
    pulled = pull_image(DIGEST_REF, runner=fake_docker())
    assert pulled.digest_ref == DIGEST_REF


def test_image_without_a_repo_digest_is_refused():
    """Pulled, but nothing to pin it to -- so we cannot say what we checked."""
    with pytest.raises(Exception) as err:
        pull_image(TAG_REF, runner=fake_docker(repo_digests=""))
    assert err.value.reason is RejectReason.DIGEST_UNRESOLVED


def test_private_package_is_reported_as_unauthorized():
    """What your friend's GHCR package currently returns."""
    runner = fake_docker(pull_rc=1, pull_err="Error response from daemon: unauthorized")
    with pytest.raises(Exception) as err:
        pull_image(TAG_REF, runner=runner)
    assert err.value.reason is RejectReason.REGISTRY_UNAUTHORIZED


def test_missing_image_is_reported_as_not_found():
    runner = fake_docker(pull_rc=1, pull_err="manifest unknown")
    with pytest.raises(Exception) as err:
        pull_image(TAG_REF, runner=runner)
    assert err.value.reason is RejectReason.IMAGE_NOT_FOUND


def test_other_pull_failures_stay_generic():
    runner = fake_docker(pull_rc=1, pull_err="i/o timeout")
    with pytest.raises(Exception) as err:
        pull_image(TAG_REF, runner=runner)
    assert err.value.reason is RejectReason.PULL_FAILED


# --- the registry pipeline ---------------------------------------------

def test_registry_submission_is_accepted_and_pinned():
    verdict = check_registry_submission(TAG_REF, "miner-A", runner=fake_docker())
    assert verdict.status is Status.ACCEPTED
    assert verdict.stage_reached is Stage.DRY_RUN
    assert verdict.source == SOURCE_REGISTRY
    # The record names the digest, not the tag it arrived as.
    assert verdict.image_ref == DIGEST_REF
    assert verdict.file_sha256 is None       # there was no file


def test_registry_rejection_is_attributed_to_load():
    runner = fake_docker(pull_rc=1, pull_err="unauthorized")
    verdict = check_registry_submission(TAG_REF, "miner-A", runner=runner)
    assert verdict.stage_reached is Stage.LOAD
    assert verdict.reject_reason is RejectReason.REGISTRY_UNAUTHORIZED


def test_pulled_image_is_removed_afterwards():
    calls = []
    check_registry_submission(TAG_REF, "miner-A", runner=fake_docker(calls=calls))
    assert "image rm" in calls


def test_registry_submission_never_raises():
    def exploding(args, timeout):
        raise RuntimeError("boom")
    verdict = check_registry_submission(TAG_REF, "miner-A", runner=exploding)
    assert verdict.reject_reason is RejectReason.INTERNAL_ERROR
    assert verdict.validator_fault is True


def test_registry_submissions_dedupe_like_file_ones():
    conn = db.connect(":memory:")
    check_and_record(conn, TAG_REF, "miner-A", runner=fake_docker(), from_registry=True)
    _, second, _ = check_and_record(
        conn, TAG_REF, "miner-B", runner=fake_docker(), from_registry=True)

    assert second.reject_reason is RejectReason.DUPLICATE_AGENT
    assert db.agent_count(conn) == 1


def test_source_is_recorded(tmp_path):
    conn = db.connect(":memory:")
    row_id, _, _ = check_and_record(
        conn, TAG_REF, "miner-A", runner=fake_docker(), from_registry=True)
    stored = db.get_submission(conn, row_id)
    assert stored["source"] == SOURCE_REGISTRY
    assert stored["image_ref"] == DIGEST_REF


# --- jobs --------------------------------------------------------------

def test_job_lifecycle():
    conn = db.connect(":memory:")
    job_id = db.create_job(conn, "miner-A", TAG_REF)
    assert db.get_job(conn, job_id)["state"] == db.JOB_QUEUED

    claimed = db.claim_next_job(conn)
    assert claimed["id"] == job_id
    assert claimed["state"] == db.JOB_RUNNING
    assert db.claim_next_job(conn) is None      # nothing left queued

    db.finish_job(conn, job_id, submission_id=5)
    done = db.get_job(conn, job_id)
    assert done["state"] == db.JOB_DONE
    assert done["submission_id"] == 5


def test_jobs_left_running_by_a_dead_process_are_requeued():
    """Otherwise the caller polls forever for a verdict nobody is producing."""
    conn = db.connect(":memory:")
    job_id = db.create_job(conn, "miner-A", TAG_REF)
    db.claim_next_job(conn)

    assert db.requeue_running_jobs(conn) == 1
    assert db.get_job(conn, job_id)["state"] == db.JOB_QUEUED


def test_failed_job_records_the_error():
    conn = db.connect(":memory:")
    job_id = db.create_job(conn, "miner-A", TAG_REF)
    db.finish_job(conn, job_id, error="traceback...")
    job = db.get_job(conn, job_id)
    assert job["state"] == db.JOB_FAILED
    assert job["error"]


# --- the HTTP API ------------------------------------------------------

TOKEN = "test-token-please-ignore"


@pytest.fixture
def server(tmp_path):
    """A real server on a real port, with the worker disabled so jobs stay
    queued and the request path can be tested on its own."""
    from http.server import ThreadingHTTPServer

    db_path = str(tmp_path / "api.db")
    db.connect(db_path).close()

    api_mod.Handler.db_path = db_path
    api_mod.Handler.token = TOKEN
    api_mod.Handler.worker = None

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), api_mod.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", db_path
    httpd.shutdown()
    httpd.server_close()


def _request(url, method="GET", body=None, token=TOKEN):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_health_needs_no_token(server):
    base, _ = server
    status, body = _request(f"{base}/v1/health", token=None)
    assert status == 200
    assert body["ok"] is True


def test_submission_requires_a_token(server):
    base, _ = server
    status, body = _request(
        f"{base}/v1/submissions", "POST", {"miner_id": "m", "image": TAG_REF}, token=None)
    assert status == 401


def test_wrong_token_is_rejected(server):
    base, _ = server
    status, _ = _request(
        f"{base}/v1/submissions", "POST", {"miner_id": "m", "image": TAG_REF},
        token="not-the-token")
    assert status == 401


def test_submission_returns_a_job_to_poll(server):
    base, _ = server
    status, body = _request(
        f"{base}/v1/submissions", "POST", {"miner_id": "miner-A", "image": TAG_REF})
    assert status == 202
    assert body["state"] == db.JOB_QUEUED
    assert body["poll"] == f"/v1/submissions/{body['job_id']}"

    status, job = _request(f"{base}{body['poll']}")
    assert status == 200
    assert job["image"] == TAG_REF
    assert job["verdict"] is None     # not run yet


@pytest.mark.parametrize("body", [
    {},
    {"miner_id": "m"},
    {"image": TAG_REF},
    {"miner_id": "", "image": TAG_REF},
    {"miner_id": "m", "image": 42},
])
def test_malformed_submissions_are_rejected(server, body):
    base, _ = server
    status, _ = _request(f"{base}/v1/submissions", "POST", body)
    assert status == 400


def test_unknown_job(server):
    base, _ = server
    assert _request(f"{base}/v1/submissions/9999")[0] == 404


def test_non_numeric_job_id(server):
    base, _ = server
    assert _request(f"{base}/v1/submissions/../../etc/passwd")[0] in (400, 404)


def test_unknown_endpoint(server):
    base, _ = server
    assert _request(f"{base}/v1/whatever")[0] == 404


def test_a_bad_image_reference_becomes_a_verdict_not_an_http_error(server):
    """A miner submitting a nonsense reference should be able to read back
    why, so it is recorded rather than thrown away at the edge."""
    base, _ = server
    status, body = _request(
        f"{base}/v1/submissions", "POST", {"miner_id": "m", "image": "--privileged"})
    assert status == 202   # accepted as a job; the verdict will reject it

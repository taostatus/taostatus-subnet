"""Tests for stage DRY_RUN -- the stage where miner code executes.

Docker is faked, so these assert on what we *ask* Docker to do: that every
limit is on the create command, that the container is destroyed on every exit
path, and that a run which never ends is killed rather than waited on.
"""

import subprocess

import pytest

from secqurityVali import constants as C
from secqurityVali.dry_run import (
    DryRunResult,
    assert_safe_container_id,
    check_dry_run,
    create_args,
    dry_run,
    remove_container,
    sanitize_output,
)
from secqurityVali.models import RejectReason, StageFailure

CID = "a" * 64


def fake_docker(*, exit_code="0", logs="agent ready\n", create_rc=0, start_rc=0,
                start_err="", wait_timeout=False, calls=None):
    def run(args, timeout):
        verb = args[0]
        if calls is not None:
            calls.append(verb)
        if verb == "create":
            return subprocess.CompletedProcess(
                args, create_rc, CID + "\n" if create_rc == 0 else "", "no such image")
        if verb == "start":
            return subprocess.CompletedProcess(args, start_rc, "", start_err)
        if verb == "wait":
            if wait_timeout:
                raise subprocess.TimeoutExpired("docker", timeout)
            return subprocess.CompletedProcess(args, 0, f"{exit_code}\n", "")
        if verb == "logs":
            return subprocess.CompletedProcess(args, 0, logs, "")
        return subprocess.CompletedProcess(args, 0, "", "")
    return run


# --- the limits are actually requested ---------------------------------

def test_every_limit_is_on_the_create_command():
    args = create_args("agent:v1")
    joined = " ".join(args)

    assert "--network none" in joined            # default-deny egress
    assert "--memory 512m" in joined
    assert "--memory-swap 512m" in joined        # swap disabled, not expanded
    assert "--cpus 1.0" in joined
    assert "--pids-limit 128" in joined          # fork bombs
    assert "--read-only" in args
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--ulimit nofile=1024:1024" in joined
    assert "--tmpfs" in args
    assert args[-1] == "agent:v1"                # image is the final argument


def test_network_is_denied_by_default_not_by_configuration():
    """If this constant drifts, an agent gets the internet. Pin it."""
    assert C.DRY_RUN_NETWORK == "none"
    assert "none" in create_args("agent:v1")


def test_limits_are_overridable_for_the_future_target_network():
    args = create_args("agent:v1", {"network": "secval-target", "memory": "256m"})
    assert "secval-target" in args
    assert "256m" in args


# --- the happy path ----------------------------------------------------

def test_successful_run_reports_exit_code_and_output():
    result = dry_run("agent:v1", runner=fake_docker())
    assert result.exit_code == 0
    assert result.timed_out is False
    assert "agent ready" in result.log_excerpt
    assert result.duration_ms >= 0
    check_dry_run(result)  # does not raise


def test_container_is_destroyed_after_a_successful_run():
    calls = []
    dry_run("agent:v1", runner=fake_docker(calls=calls))
    assert calls.count("rm") == 1


# --- failure paths -----------------------------------------------------

def test_nonzero_exit_fails_the_gate():
    result = dry_run("agent:v1", runner=fake_docker(exit_code="1"))
    assert result.exit_code == 1
    with pytest.raises(StageFailure) as err:
        check_dry_run(result)
    assert err.value.reason is RejectReason.DRY_RUN_NONZERO_EXIT


def test_nonzero_exit_can_be_tolerated_when_configured():
    result = dry_run("agent:v1", runner=fake_docker(exit_code="1"))
    check_dry_run(result, require_zero_exit=False)  # does not raise


def test_entrypoint_that_cannot_execute():
    runner = fake_docker(start_rc=1, start_err='exec: "/agent": no such file or directory')
    with pytest.raises(StageFailure) as err:
        dry_run("agent:v1", runner=runner)
    assert err.value.reason is RejectReason.START_FAILED


def test_container_is_destroyed_even_when_start_fails():
    calls = []
    with pytest.raises(StageFailure):
        dry_run("agent:v1", runner=fake_docker(start_rc=1, calls=calls))
    assert "rm" in calls


def test_create_failure():
    with pytest.raises(StageFailure) as err:
        dry_run("agent:v1", runner=fake_docker(create_rc=1))
    assert err.value.reason is RejectReason.CREATE_FAILED


# --- the agent that runs forever ---------------------------------------

def test_timeout_kills_the_container_rather_than_waiting():
    calls = []
    result = dry_run("agent:v1", runner=fake_docker(wait_timeout=True, calls=calls))

    assert result.timed_out is True
    assert result.exit_code is None
    assert "kill" in calls    # killed where it stands
    assert "rm" in calls      # and then destroyed


def test_timed_out_run_fails_the_gate():
    result = dry_run("agent:v1", runner=fake_docker(wait_timeout=True))
    with pytest.raises(StageFailure) as err:
        check_dry_run(result)
    assert err.value.reason is RejectReason.DRY_RUN_TIMEOUT


def test_timeout_is_charged_to_the_miner_not_the_validator():
    result = dry_run("agent:v1", runner=fake_docker(wait_timeout=True))
    with pytest.raises(StageFailure) as err:
        check_dry_run(result)
    assert err.value.is_validator_fault is False


# --- hostile output ----------------------------------------------------

def test_terminal_escapes_are_stripped_from_output():
    """A log line must not be able to repaint an operator's console."""
    nasty = "\x1b[2J\x1b[1;31mFAKE: ALL TESTS PASSED\x1b[0m\x07\n"
    cleaned = sanitize_output(nasty)
    assert "\x1b" not in cleaned
    assert "\x07" not in cleaned
    assert "FAKE: ALL TESTS PASSED" in cleaned  # the text stays, the control does not


def test_output_is_capped():
    cleaned = sanitize_output("A" * 100_000)
    assert len(cleaned) < 100_000
    assert cleaned.endswith("[truncated]")


def test_newlines_and_tabs_survive():
    assert sanitize_output("one\ttwo\nthree\n") == "one\ttwo\nthree\n"


def test_enormous_log_does_not_reach_the_verdict():
    result = dry_run("agent:v1", runner=fake_docker(logs="X" * 500_000))
    assert len(result.log_excerpt) <= C.DRY_RUN_LOG_EXCERPT_BYTES + 32


# --- container ids are arguments too -----------------------------------

def test_container_id_is_validated_like_an_image_ref():
    assert assert_safe_container_id(CID) == CID
    for hostile in ["--privileged", "", "not-hex", "abc"]:
        with pytest.raises(StageFailure):
            assert_safe_container_id(hostile)


def test_remove_container_never_raises():
    assert remove_container(CID, runner=fake_docker()) is True
    assert remove_container("--privileged", runner=fake_docker()) is False


def test_missing_exit_code_is_not_treated_as_success():
    result = dry_run("agent:v1", runner=fake_docker(exit_code="not-a-number"))
    assert result.exit_code is None
    with pytest.raises(StageFailure):
        check_dry_run(result)

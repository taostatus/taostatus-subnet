"""Tests for stages LOAD and INSPECT.

The Docker CLI is replaced by a fake runner returning canned output, so these
run with no daemon: the point is our handling of what Docker says, including
the ways it lies or fails.
"""

import json
import subprocess

import pytest

from secqurityVali import constants as C
from secqurityVali.docker_ops import (
    ImageInfo,
    assert_safe_image_ref,
    check_image,
    docker_available,
    entrypoint_of,
    inspect_image,
    load_image,
    remove_image,
)
from secqurityVali.models import RejectReason, StageFailure


# --- fake daemon -------------------------------------------------------

def runner_returning(stdout="", stderr="", returncode=0, record=None):
    def run(args, timeout):
        if record is not None:
            record.append((args, timeout))
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)
    return run


def runner_raising(exc):
    def run(args, timeout):
        raise exc
    return run


INSPECT_JSON = json.dumps({
    "Id": "sha256:" + "f" * 64,
    "RepoTags": ["agent:v1"],
    "Architecture": "amd64",
    "Os": "linux",
    "Size": 120_000_000,
    "RootFS": {"Type": "layers", "Layers": ["sha256:a", "sha256:b", "sha256:c"]},
    "Config": {
        "Entrypoint": ["/usr/bin/agent"],
        "Cmd": ["--run"],
        "User": "agent",
    },
})


def healthy_image(**overrides):
    base = dict(
        image_id="sha256:" + "f" * 64,
        arch="amd64",
        os_name="linux",
        layer_count=3,
        image_size=120_000_000,
        entrypoint=["/usr/bin/agent"],
    )
    base.update(overrides)
    return ImageInfo(**base)


# --- image reference safety -------------------------------------------

@pytest.mark.parametrize("ref", [
    "agent:v1",
    "sha256:" + "a" * 64,
    "registry.example.com:5000/team/agent:v1.2.3",
])
def test_safe_refs_accepted(ref):
    assert assert_safe_image_ref(ref) == ref


@pytest.mark.parametrize("ref", [
    "--privileged",
    "-v/:/host",
    "",
    "agent v1",            # space would split into two arguments
    "agent;rm -rf /",      # only dangerous if a shell were ever involved
    "a" * 300,
])
def test_hostile_refs_refused(ref):
    """Repo tags are miner-chosen, so a ref that reads as a flag is refused
    before it can be handed back to the CLI."""
    with pytest.raises(StageFailure) as err:
        assert_safe_image_ref(ref)
    assert err.value.reason is RejectReason.LOAD_FAILED


# --- stage LOAD --------------------------------------------------------

def test_load_parses_tagged_output():
    runner = runner_returning(stdout="Loaded image: agent:v1\n")
    assert load_image("img.tar", runner=runner) == "agent:v1"


def test_load_parses_untagged_id_output():
    digest = "sha256:" + "b" * 64
    runner = runner_returning(stdout=f"Loaded image ID: {digest}\n")
    assert load_image("img.tar", runner=runner) == digest


def test_load_prefers_id_over_tag_when_both_present():
    digest = "sha256:" + "c" * 64
    runner = runner_returning(stdout=f"Loaded image: agent:v1\nLoaded image ID: {digest}\n")
    assert load_image("img.tar", runner=runner) == digest


def test_load_reads_output_from_stderr_too():
    """Some Docker versions announce the load on stderr."""
    runner = runner_returning(stderr="Loaded image: agent:v1\n")
    assert load_image("img.tar", runner=runner) == "agent:v1"


def test_load_passes_path_as_argument_not_shell_string():
    record = []
    runner = runner_returning(stdout="Loaded image: agent:v1\n", record=record)
    load_image("/tmp/weird name; rm -rf /.tar", runner=runner)
    args, _timeout = record[0]
    # The path is one argument, intact and unquoted -- there is no command
    # line for it to break out of.
    assert args == ["load", "--input", "/tmp/weird name; rm -rf /.tar"]


def test_load_failure_is_the_miners_fault():
    runner = runner_returning(stderr="invalid tar header", returncode=1)
    with pytest.raises(StageFailure) as err:
        load_image("img.tar", runner=runner)
    assert err.value.reason is RejectReason.LOAD_FAILED
    assert err.value.is_validator_fault is False


def test_load_success_with_unparseable_output():
    runner = runner_returning(stdout="everything is fine\n")
    with pytest.raises(StageFailure) as err:
        load_image("img.tar", runner=runner)
    assert err.value.reason is RejectReason.LOAD_FAILED


def test_load_timeout_is_charged_to_the_archive():
    runner = runner_raising(subprocess.TimeoutExpired("docker", 600))
    with pytest.raises(StageFailure) as err:
        load_image("img.tar", runner=runner)
    assert err.value.reason is RejectReason.LOAD_FAILED


def test_hostile_tag_from_load_output_is_refused():
    """An archive whose baked-in tag is a flag never becomes an argument."""
    runner = runner_returning(stdout="Loaded image: --privileged\n")
    with pytest.raises(StageFailure) as err:
        load_image("img.tar", runner=runner)
    assert "unsafe image reference" in (err.value.detail or "")


# --- daemon trouble is never the miner's fault -------------------------

def test_daemon_down_detected_from_stderr():
    runner = runner_returning(
        stderr="error during connect: cannot connect to the Docker daemon", returncode=1)
    with pytest.raises(StageFailure) as err:
        load_image("img.tar", runner=runner)
    assert err.value.reason is RejectReason.DOCKER_UNAVAILABLE


def test_docker_cli_not_installed():
    runner = runner_raising(FileNotFoundError("docker not found"))
    with pytest.raises(StageFailure) as err:
        load_image("img.tar", runner=runner)
    assert err.value.reason is RejectReason.DOCKER_UNAVAILABLE


def test_docker_available_reports_false_rather_than_raising():
    assert docker_available(runner=runner_raising(FileNotFoundError())) is False
    assert docker_available(runner=runner_returning(stdout="linux\n")) is True


# --- stage INSPECT -----------------------------------------------------

def test_inspect_reads_every_field():
    info = inspect_image("agent:v1", runner=runner_returning(stdout=INSPECT_JSON))
    assert info.image_id == "sha256:" + "f" * 64
    assert info.repo_tags == ["agent:v1"]
    assert info.arch == "amd64"
    assert info.os_name == "linux"
    assert info.layer_count == 3
    assert info.image_size == 120_000_000
    assert info.entrypoint == ["/usr/bin/agent"]
    assert info.cmd == ["--run"]
    assert info.image_user == "agent"


def test_inspect_tolerates_list_wrapped_output():
    info = inspect_image("agent:v1", runner=runner_returning(stdout=f"[{INSPECT_JSON}]"))
    assert info.arch == "amd64"


def test_inspect_unparseable_output_is_our_fault():
    runner = runner_returning(stdout="not json at all")
    with pytest.raises(StageFailure) as err:
        inspect_image("agent:v1", runner=runner)
    assert err.value.reason is RejectReason.INTERNAL_ERROR


# --- stage INSPECT gates ----------------------------------------------

def test_healthy_image_passes_every_gate():
    check_image(healthy_image())  # does not raise


def test_arch_mismatch():
    with pytest.raises(StageFailure) as err:
        check_image(healthy_image(arch="arm64"))
    assert err.value.reason is RejectReason.ARCH_MISMATCH


def test_os_mismatch():
    with pytest.raises(StageFailure) as err:
        check_image(healthy_image(os_name="windows"))
    assert err.value.reason is RejectReason.OS_MISMATCH


def test_too_many_layers():
    with pytest.raises(StageFailure) as err:
        check_image(healthy_image(layer_count=C.MAX_IMAGE_LAYERS + 1))
    assert err.value.reason is RejectReason.TOO_MANY_LAYERS


def test_image_too_large():
    with pytest.raises(StageFailure) as err:
        check_image(healthy_image(image_size=C.MAX_IMAGE_SIZE_BYTES + 1))
    assert err.value.reason is RejectReason.IMAGE_TOO_LARGE


def test_gates_are_overridable_for_tests_and_config():
    with pytest.raises(StageFailure) as err:
        check_image(healthy_image(), config={"max_size": 1})
    assert err.value.reason is RejectReason.IMAGE_TOO_LARGE


def test_missing_metadata_does_not_trip_a_gate():
    """Docker not reporting a field is not the same as the field failing."""
    check_image(ImageInfo(image_id="sha256:x"))  # does not raise


# --- entrypoint --------------------------------------------------------

def test_entrypoint_used_when_present():
    assert entrypoint_of(healthy_image()) == ["/usr/bin/agent"]


def test_cmd_is_accepted_when_entrypoint_is_empty():
    info = healthy_image(entrypoint=[], cmd=["python", "agent.py"])
    assert entrypoint_of(info) == ["python", "agent.py"]


def test_image_with_nothing_to_run_is_rejected():
    with pytest.raises(StageFailure) as err:
        entrypoint_of(healthy_image(entrypoint=[], cmd=[]))
    assert err.value.reason is RejectReason.NO_ENTRYPOINT


# --- cleanup -----------------------------------------------------------

def test_remove_image_never_raises():
    assert remove_image("agent:v1", runner=runner_returning(returncode=0)) is True
    assert remove_image("agent:v1", runner=runner_returning(returncode=1)) is False
    assert remove_image("--privileged", runner=runner_returning()) is False
    assert remove_image("agent:v1", runner=runner_raising(FileNotFoundError())) is False

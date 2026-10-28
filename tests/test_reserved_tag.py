"""F1 fix: a submitted archive must not carry a tag that `docker load` would use
to overwrite one of our own images (target poisoning). Rejected at STRUCTURE,
before the daemon ever applies the tag."""

import io
import json
import tarfile

import pytest

from secqurityVali import docker_ops
from secqurityVali.models import RejectReason, StageFailure
from secqurityVali.structure import check_structure


def test_assert_no_reserved_tags_rejects_our_namespace():
    for tag in ("secqurityvali-target-sqli:v1", "docker.io/library/secqurityvali-target-cmdi:v1",
                "SecQurityVali-target-lfi:v1"):
        with pytest.raises(StageFailure) as e:
            docker_ops.assert_no_reserved_tags([tag])
        assert e.value.reason == RejectReason.RESERVED_TAG


def test_assert_no_reserved_tags_allows_normal_tags():
    docker_ops.assert_no_reserved_tags([])                       # no tags: fine
    docker_ops.assert_no_reserved_tags(["ghcr.io/miner/agent:v1", "python:3.12-alpine"])


def _docker_archive(tmp_path, repo_tags):
    """A minimal `docker save`-shaped archive carrying the given RepoTags."""
    manifest = json.dumps([{"Config": "c.json", "Layers": ["l.tar"], "RepoTags": repo_tags}]).encode()
    p = tmp_path / "img.tar"
    with tarfile.open(p, "w") as tar:
        for name, data in (("manifest.json", manifest), ("c.json", b"{}"), ("l.tar", b"")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return str(p)


def test_poisoning_archive_is_rejected_before_load(tmp_path):
    # structure reads the tag from the manifest WITHOUT loading the image...
    path = _docker_archive(tmp_path, ["secqurityvali-target-sqli:v1"])
    info = check_structure(path)
    assert "secqurityvali-target-sqli:v1" in info.repo_tags
    # ...and the reserved-tag guard refuses it, so docker load never runs.
    with pytest.raises(StageFailure) as e:
        docker_ops.assert_no_reserved_tags(info.repo_tags)
    assert e.value.reason == RejectReason.RESERVED_TAG


def test_benign_archive_passes_the_guard(tmp_path):
    path = _docker_archive(tmp_path, ["miner/agent:latest"])
    info = check_structure(path)
    docker_ops.assert_no_reserved_tags(info.repo_tags)           # no raise

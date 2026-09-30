"""Tests for stages FILE and STRUCTURE -- the checks that answer
"is this actually a Docker image?" without involving the Docker daemon.

Every fixture is a tarball crafted in-test, including the hostile ones, so the
suite runs anywhere and needs no daemon.
"""

import io
import json
import tarfile

import pytest

from secqurityVali.file_checks import COMPRESSION_GZIP, COMPRESSION_NONE, check_file
from secqurityVali.models import RejectReason, StageFailure
from secqurityVali.structure import check_structure
from secqurityVali import constants as C


# --- fixture builders --------------------------------------------------

def _add_file(tar, name, data: bytes):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def _add_special(tar, name, tar_type, linkname="", size=0):
    info = tarfile.TarInfo(name)
    info.type = tar_type
    info.linkname = linkname
    info.size = size
    tar.addfile(info)


def _docker_manifest(count=1, layers=2):
    return json.dumps([
        {
            "Config": f"config{i}.json",
            "RepoTags": [f"agent:v{i}"],
            "Layers": [f"layer{n}/layer.tar" for n in range(layers)],
        }
        for i in range(count)
    ]).encode()


def make_docker_archive(path, *, images=1, layers=2, compress=False, extra=None):
    with tarfile.open(path, "w:gz" if compress else "w") as tar:
        _add_file(tar, "manifest.json", _docker_manifest(images, layers))
        _add_file(tar, "config0.json", b'{"architecture":"amd64"}')
        for n in range(layers):
            _add_file(tar, f"layer{n}/layer.tar", b"\x00" * 128)
        for name, data in (extra or []):
            _add_file(tar, name, data)
    return path


def make_oci_archive(path):
    index = json.dumps({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:" + "a" * 64,
            "size": 500,
            "annotations": {"org.opencontainers.image.ref.name": "agent:v1"},
        }],
    }).encode()
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        _add_file(tar, "index.json", index)
        _add_file(tar, "blobs/sha256/" + "a" * 64, b"{}")
    return path


# --- stage FILE --------------------------------------------------------

def test_missing_file(tmp_path):
    with pytest.raises(StageFailure) as err:
        check_file(tmp_path / "nope.tar")
    assert err.value.reason is RejectReason.FILE_MISSING


def test_empty_file(tmp_path):
    empty = tmp_path / "empty.tar"
    empty.write_bytes(b"")
    with pytest.raises(StageFailure) as err:
        check_file(empty)
    assert err.value.reason is RejectReason.FILE_EMPTY


def test_file_over_size_cap(tmp_path):
    big = make_docker_archive(tmp_path / "big.tar")
    with pytest.raises(StageFailure) as err:
        check_file(big, max_file_size=16)
    assert err.value.reason is RejectReason.FILE_TOO_LARGE


def test_non_archive_rejected_despite_tar_extension(tmp_path):
    """A zip renamed to .tar. The extension is never consulted."""
    fake = tmp_path / "image.tar"
    fake.write_bytes(b"PK\x03\x04" + b"\x00" * 600)
    with pytest.raises(StageFailure) as err:
        check_file(fake)
    assert err.value.reason is RejectReason.NOT_AN_ARCHIVE


def test_plain_tar_is_identified_and_hashed(tmp_path):
    archive = make_docker_archive(tmp_path / "img.tar")
    info = check_file(archive)
    assert info.compression == COMPRESSION_NONE
    assert len(info.sha256) == 64
    assert info.size == archive.stat().st_size


def test_gzipped_tar_is_identified(tmp_path):
    archive = make_docker_archive(tmp_path / "img.tar.gz", compress=True)
    assert check_file(archive).compression == COMPRESSION_GZIP


def test_same_bytes_hash_identically(tmp_path):
    data = make_docker_archive(tmp_path / "a.tar").read_bytes()
    (tmp_path / "b.tar").write_bytes(data)
    assert check_file(tmp_path / "a.tar").sha256 == check_file(tmp_path / "b.tar").sha256


# --- stage STRUCTURE: the accept path ----------------------------------

def test_docker_archive_recognized(tmp_path):
    info = check_structure(make_docker_archive(tmp_path / "img.tar", layers=3))
    assert info.image_format == C.FORMAT_DOCKER_ARCHIVE
    assert info.repo_tags == ["agent:v0"]
    assert info.layer_count == 3
    assert info.config_entry == "config0.json"
    assert info.entry_count == 5  # manifest + config + 3 layers


def test_gzipped_docker_archive_recognized(tmp_path):
    archive = make_docker_archive(tmp_path / "img.tar.gz", compress=True)
    assert check_structure(archive).image_format == C.FORMAT_DOCKER_ARCHIVE


def test_oci_layout_recognized(tmp_path):
    info = check_structure(make_oci_archive(tmp_path / "oci.tar"))
    assert info.image_format == C.FORMAT_OCI
    assert info.repo_tags == ["agent:v1"]
    # Layer count needs blob traversal; the inspect stage asks Docker instead.
    assert info.layer_count is None


def test_dot_slash_prefixed_names_still_match(tmp_path):
    """Some tools write ./manifest.json. Same archive, same verdict."""
    path = tmp_path / "dotted.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "./manifest.json", _docker_manifest())
        _add_file(tar, "./config0.json", b"{}")
    assert check_structure(path).image_format == C.FORMAT_DOCKER_ARCHIVE


# --- stage STRUCTURE: the core rejection -------------------------------

def test_valid_tar_that_is_not_an_image(tmp_path):
    """A real tarball of ordinary files -- source code, a home directory."""
    path = tmp_path / "source.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "README.md", b"hello")
        _add_file(tar, "src/main.py", b"print(1)")
    with pytest.raises(StageFailure) as err:
        check_structure(path)
    assert err.value.reason is RejectReason.NOT_A_DOCKER_IMAGE


def test_oci_layout_without_index_is_not_an_image(tmp_path):
    path = tmp_path / "half.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "oci-layout", b"{}")
    with pytest.raises(StageFailure) as err:
        check_structure(path)
    assert err.value.reason is RejectReason.NOT_A_DOCKER_IMAGE


def test_corrupt_archive(tmp_path):
    path = tmp_path / "corrupt.tar.gz"
    path.write_bytes(C.GZIP_MAGIC + b"\xff" * 400)
    with pytest.raises(StageFailure) as err:
        check_structure(path)
    assert err.value.reason is RejectReason.MALFORMED_ARCHIVE


# --- stage STRUCTURE: hostile archives ---------------------------------

def test_parent_traversal_entry(tmp_path):
    path = tmp_path / "evil.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "manifest.json", _docker_manifest())
        _add_file(tar, "../../etc/shadow", b"pwned")
    with pytest.raises(StageFailure) as err:
        check_structure(path)
    assert err.value.reason is RejectReason.UNSAFE_TAR_ENTRY


def test_absolute_path_entry(tmp_path):
    path = tmp_path / "abs.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "/etc/cron.d/backdoor", b"* * * * * root sh")
    with pytest.raises(StageFailure) as err:
        check_structure(path)
    assert err.value.reason is RejectReason.UNSAFE_TAR_ENTRY


def test_escaping_symlink(tmp_path):
    path = tmp_path / "link.tar"
    with tarfile.open(path, "w") as tar:
        _add_special(tar, "layer0/passwd", tarfile.SYMTYPE, linkname="../../../../etc/passwd")
    with pytest.raises(StageFailure) as err:
        check_structure(path)
    assert err.value.reason is RejectReason.UNSAFE_TAR_ENTRY


def test_device_node_entry(tmp_path):
    path = tmp_path / "dev.tar"
    with tarfile.open(path, "w") as tar:
        _add_special(tar, "dev/sda", tarfile.BLKTYPE)
    with pytest.raises(StageFailure) as err:
        check_structure(path)
    assert err.value.reason is RejectReason.UNSAFE_TAR_ENTRY


def test_declared_size_bomb_rejected_from_headers(tmp_path):
    """The cap trips on declared sizes, so payload is never read."""
    archive = make_docker_archive(tmp_path / "bomb.tar", layers=4)
    with pytest.raises(StageFailure) as err:
        check_structure(archive, max_uncompressed=64)
    assert err.value.reason is RejectReason.DECOMPRESSION_BOMB


def test_entry_count_bomb(tmp_path):
    archive = make_docker_archive(tmp_path / "many.tar", layers=6)
    with pytest.raises(StageFailure) as err:
        check_structure(archive, max_entries=3)
    assert err.value.reason is RejectReason.TOO_MANY_ENTRIES


# --- stage STRUCTURE: manifest content ---------------------------------

def test_multiple_images_refused(tmp_path):
    archive = make_docker_archive(tmp_path / "two.tar", images=2)
    with pytest.raises(StageFailure) as err:
        check_structure(archive)
    assert err.value.reason is RejectReason.MULTIPLE_IMAGES


def test_manifest_not_json(tmp_path):
    path = tmp_path / "bad.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "manifest.json", b"this is not json")
    with pytest.raises(StageFailure) as err:
        check_structure(path)
    assert err.value.reason is RejectReason.MALFORMED_MANIFEST


def test_manifest_missing_required_keys(tmp_path):
    path = tmp_path / "thin.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "manifest.json", json.dumps([{"RepoTags": ["x:1"]}]).encode())
    with pytest.raises(StageFailure) as err:
        check_structure(path)
    assert err.value.reason is RejectReason.MALFORMED_MANIFEST


def test_oversized_manifest_refused(tmp_path):
    """A 'manifest.json' that is really a payload."""
    path = tmp_path / "fat.tar"
    with tarfile.open(path, "w") as tar:
        _add_file(tar, "manifest.json", b"x" * (C.MAX_METADATA_BYTES + 1))
    with pytest.raises(StageFailure) as err:
        check_structure(path)
    assert err.value.reason is RejectReason.MALFORMED_MANIFEST

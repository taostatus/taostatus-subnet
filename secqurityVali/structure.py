from __future__ import annotations

"""secqurityVali/structure.py - stage STRUCTURE: is this archive a Docker image?

Reads the tar directly and never extracts it. Two jobs:

  1. Decide what the archive is -- a docker-archive (manifest.json at the
     root, what `docker save` writes) or an OCI layout (oci-layout plus
     index.json). Anything else is rejected as not a Docker image, which is
     the question this whole validator exists to answer.

  2. Refuse hostile archives before the Docker daemon ever parses them. The
     daemon unpacks as root; we do not, so every rejection here is one fewer
     hostile tar reaching it.

The archive is streamed ("r|*"), not opened for random access: entries are
seen once, in order, and sizes are read from the headers. A member declaring
100 GB is rejected on its header, before a byte of its payload is read.
"""

import gzip
import json
import re
import tarfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from secqurityVali import constants as C
from secqurityVali.models import RejectReason, StageFailure

# Entry types a legitimate image archive uses. Anything else -- device nodes,
# fifos, sockets -- has no business in an image tarball and is treated as an
# attack on whatever unpacks it.
_SAFE_TAR_TYPES = frozenset(
    {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE}
)

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")

# Errors a corrupt or lying archive surfaces as. gzip/zlib failures arrive
# here too, since tarfile decompresses transparently in stream mode.
_ARCHIVE_ERRORS = (tarfile.TarError, gzip.BadGzipFile, zlib.error, EOFError)


@dataclass(frozen=True)
class StructureInfo:
    """What stage STRUCTURE establishes, read from the archive alone -- no
    Docker involved, so these are claims the image makes about itself."""

    image_format: str  # C.FORMAT_DOCKER_ARCHIVE | C.FORMAT_OCI
    entry_count: int
    declared_size: int
    repo_tags: list[str] = field(default_factory=list)
    layer_count: int | None = None
    config_entry: str | None = None


def _normalize(name: str) -> str:
    """`docker save` writes bare names; some tools prefix "./". Same entry."""
    return name[2:] if name.startswith("./") else name


def _is_unsafe_path(name: str) -> bool:
    """Absolute, drive-qualified, or escaping upward out of the archive root."""
    if not name:
        return True
    if name.startswith("/") or name.startswith("\\"):
        return True
    if _WINDOWS_DRIVE.match(name):
        return True
    return ".." in PurePosixPath(name).parts


def _assert_safe_member(member: tarfile.TarInfo) -> None:
    if member.type not in _SAFE_TAR_TYPES:
        raise StageFailure(
            RejectReason.UNSAFE_TAR_ENTRY,
            f"entry {member.name!r} has disallowed type {member.type!r}",
        )
    if _is_unsafe_path(member.name):
        raise StageFailure(
            RejectReason.UNSAFE_TAR_ENTRY,
            f"entry {member.name!r} escapes the archive root",
        )
    # A symlink's target escapes just as effectively as its own path would.
    if (member.issym() or member.islnk()) and _is_unsafe_path(member.linkname):
        raise StageFailure(
            RejectReason.UNSAFE_TAR_ENTRY,
            f"link {member.name!r} -> {member.linkname!r} escapes the archive root",
        )


def _read_metadata(tar: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    """Read one small metadata file, refusing anything claiming to be big."""
    if member.size > C.MAX_METADATA_BYTES:
        raise StageFailure(
            RejectReason.MALFORMED_MANIFEST,
            f"{member.name} is {member.size} bytes; metadata cap is {C.MAX_METADATA_BYTES}",
        )
    handle = tar.extractfile(member)
    if handle is None:
        raise StageFailure(
            RejectReason.MALFORMED_MANIFEST, f"{member.name} is not a readable file"
        )
    return handle.read(C.MAX_METADATA_BYTES)


def _parse_docker_manifest(raw: bytes) -> tuple[list[str], int | None, str | None]:
    """manifest.json from `docker save`: a JSON list, one entry per image."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise StageFailure(RejectReason.MALFORMED_MANIFEST, f"manifest.json: {exc}") from exc

    if not isinstance(data, list) or not data:
        raise StageFailure(
            RejectReason.MALFORMED_MANIFEST, "manifest.json is not a non-empty list"
        )
    if len(data) > 1:
        # `docker save a b` produces this. V0 runs exactly one agent, so an
        # ambiguous archive is refused rather than guessed at.
        raise StageFailure(
            RejectReason.MULTIPLE_IMAGES,
            f"archive holds {len(data)} images; exactly one expected",
        )

    entry = data[0]
    if not isinstance(entry, dict) or "Config" not in entry or "Layers" not in entry:
        raise StageFailure(
            RejectReason.MALFORMED_MANIFEST, "manifest entry lacks Config/Layers"
        )

    layers = entry.get("Layers")
    layer_count = len(layers) if isinstance(layers, list) else None
    tags = entry.get("RepoTags") or []
    repo_tags = [str(tag) for tag in tags] if isinstance(tags, list) else []
    config = entry.get("Config")
    return repo_tags, layer_count, config if isinstance(config, str) else None


def _parse_oci_index(raw: bytes) -> list[str]:
    """index.json from an OCI layout. Layer count needs blob traversal, so it
    is left to the inspect stage, which asks Docker instead."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise StageFailure(RejectReason.MALFORMED_MANIFEST, f"index.json: {exc}") from exc

    if not isinstance(data, dict):
        raise StageFailure(RejectReason.MALFORMED_MANIFEST, "index.json is not an object")

    manifests = data.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise StageFailure(RejectReason.MALFORMED_MANIFEST, "index.json lists no manifests")
    if len(manifests) > 1:
        raise StageFailure(
            RejectReason.MULTIPLE_IMAGES,
            f"OCI index holds {len(manifests)} manifests; exactly one expected",
        )

    first = manifests[0]
    annotations = first.get("annotations") or {} if isinstance(first, dict) else {}
    name = annotations.get("org.opencontainers.image.ref.name")
    return [str(name)] if name else []


def check_structure(
    path: Path | str,
    *,
    max_uncompressed: int = C.MAX_UNCOMPRESSED_BYTES,
    max_entries: int = C.MAX_TAR_ENTRIES,
) -> StructureInfo:
    """Run stage STRUCTURE. Returns StructureInfo, or raises StageFailure."""
    path = Path(path)

    entry_count = 0
    declared_size = 0
    manifest_raw: bytes | None = None
    index_raw: bytes | None = None
    saw_oci_layout = False

    try:
        # "r|*" is the streaming reader: forward-only, no seeking back into an
        # attacker-controlled index, and transparent gzip.
        with tarfile.open(path, mode="r|*") as tar:
            for member in tar:
                entry_count += 1
                if entry_count > max_entries:
                    raise StageFailure(
                        RejectReason.TOO_MANY_ENTRIES,
                        f"archive exceeds {max_entries} entries",
                    )

                _assert_safe_member(member)

                declared_size += max(member.size, 0)
                if declared_size > max_uncompressed:
                    raise StageFailure(
                        RejectReason.DECOMPRESSION_BOMB,
                        f"declared contents exceed {max_uncompressed} bytes",
                    )

                name = _normalize(member.name)
                if not member.isfile():
                    if name == C.OCI_LAYOUT_MARKER:
                        saw_oci_layout = True
                    continue

                if name == C.DOCKER_ARCHIVE_MANIFEST:
                    manifest_raw = _read_metadata(tar, member)
                elif name == C.OCI_INDEX:
                    index_raw = _read_metadata(tar, member)
                elif name == C.OCI_LAYOUT_MARKER:
                    saw_oci_layout = True
    except _ARCHIVE_ERRORS as exc:
        raise StageFailure(RejectReason.MALFORMED_ARCHIVE, str(exc)) from exc

    if entry_count == 0:
        raise StageFailure(RejectReason.MALFORMED_ARCHIVE, "archive is empty")

    if manifest_raw is not None:
        repo_tags, layer_count, config_entry = _parse_docker_manifest(manifest_raw)
        return StructureInfo(
            image_format=C.FORMAT_DOCKER_ARCHIVE,
            entry_count=entry_count,
            declared_size=declared_size,
            repo_tags=repo_tags,
            layer_count=layer_count,
            config_entry=config_entry,
        )

    if saw_oci_layout and index_raw is not None:
        return StructureInfo(
            image_format=C.FORMAT_OCI,
            entry_count=entry_count,
            declared_size=declared_size,
            repo_tags=_parse_oci_index(index_raw),
        )

    # A perfectly valid tarball of something else lands here -- source code, a
    # backup, anyone's home directory. It is an archive; it is not an image.
    raise StageFailure(
        RejectReason.NOT_A_DOCKER_IMAGE,
        "no manifest.json (docker-archive) and no oci-layout + index.json (OCI)",
    )

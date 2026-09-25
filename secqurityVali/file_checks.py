from __future__ import annotations

"""secqurityVali/file_checks.py - stage FILE: is this a plausible archive at all?

The cheapest gate, run before anything parses the file's contents. It settles
identity (sha256) and shape (size, magic bytes) only. Nothing here interprets
a single byte the miner chose beyond the first 512.
"""

from dataclasses import dataclass
from pathlib import Path

from secqurityVali import constants as C
from secqurityVali.models import RejectReason, StageFailure, sha256_file

COMPRESSION_GZIP = "gzip"
COMPRESSION_NONE = "none"


@dataclass(frozen=True)
class FileInfo:
    """What stage FILE establishes. Carried forward into the Verdict even if a
    later stage rejects, so a bad submission is still identified by hash."""

    path: Path
    size: int
    sha256: str
    compression: str  # COMPRESSION_GZIP | COMPRESSION_NONE


def sniff_compression(head: bytes) -> str | None:
    """Identify the archive from its magic bytes, or None if it is neither.

    Only the two shapes `docker save` produces are accepted: a raw tar, or a
    gzipped tar. Extension is never consulted -- a miner naming a zip file
    `image.tar` proves nothing.
    """
    if head.startswith(C.GZIP_MAGIC):
        return COMPRESSION_GZIP
    tail = head[C.TAR_MAGIC_OFFSET : C.TAR_MAGIC_OFFSET + len(C.TAR_MAGIC)]
    if tail == C.TAR_MAGIC:
        return COMPRESSION_NONE
    return None


def check_file(
    path: Path | str,
    *,
    max_file_size: int = C.MAX_FILE_SIZE_BYTES,
) -> FileInfo:
    """Run stage FILE. Returns FileInfo, or raises StageFailure."""
    path = Path(path)

    if not path.exists() or not path.is_file():
        raise StageFailure(RejectReason.FILE_MISSING, f"no such file: {path}")

    size = path.stat().st_size
    if size == 0:
        raise StageFailure(RejectReason.FILE_EMPTY, "submission is 0 bytes")
    if size > max_file_size:
        raise StageFailure(
            RejectReason.FILE_TOO_LARGE,
            f"{size} bytes exceeds cap of {max_file_size}",
        )

    with open(path, "rb") as handle:
        head = handle.read(C.MAGIC_SNIFF_BYTES)

    compression = sniff_compression(head)
    if compression is None:
        raise StageFailure(
            RejectReason.NOT_AN_ARCHIVE,
            "magic bytes are neither gzip nor tar",
        )

    # Hashing is a full pass over the file, so it runs last -- after the cheap
    # rejections have already thrown out anything that was never a candidate.
    return FileInfo(
        path=path,
        size=size,
        sha256=sha256_file(path, C.SHA256_CHUNK_BYTES),
        compression=compression,
    )

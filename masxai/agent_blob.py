from __future__ import annotations

"""Miner-side hosting for the encrypted agent blob.

The v2 security transport (see masxai/protocol.py) has the miner return a URL to
an encrypted `docker save` tarball rather than a public image reference. This
module gives the miner the two pieces it needs to do that with no external
registry or bucket:

  * save_image_tar() -- turn a local image into the tarball bytes to encrypt.
  * BlobServer -- a tiny stdlib static file server that hosts the encrypted
    blobs, so the validator can download them straight from the miner.

The bytes served are ciphertext, sealed for the validator's public key, so
serving them on an open port leaks nothing to a peer who fetches the URL.
"""

import functools
import hashlib
import subprocess
import tempfile
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# docker save on a multi-hundred-MB image is slow; give it a long leash.
_DOCKER_SAVE_TIMEOUT_S = 600


class AgentBlobError(RuntimeError):
    """Raised when the image cannot be exported to a tarball."""


def save_image_tar(image_ref: str) -> bytes:
    """Return the bytes of `docker save <image_ref>` -- a portable tarball of the
    image, exactly what `docker load` on the validator will consume.

    If the image is not present locally, this first tries to pull it: a miner's
    configured image is usually a registry reference, and it can go missing (for
    example, on a single-box test where the validator loads and then prunes an
    image of the same tag). Pulling makes the miner self-healing without changing
    the caller. Raises AgentBlobError if docker is unavailable or the image
    cannot be obtained, so the caller can decline the round cleanly.
    """
    tar = _docker_save(image_ref)
    if tar is not None:
        return tar
    # Not saveable as-is; try to fetch it, then save once more.
    _docker_pull(image_ref)
    tar = _docker_save(image_ref)
    if tar is None:
        raise AgentBlobError(f"image not available even after pull: {image_ref!r}")
    return tar


def _docker_save(image_ref: str) -> bytes | None:
    """Run `docker save`; return the tar bytes, or None if the image is absent
    locally. Raises AgentBlobError for any other failure (docker missing, etc.)."""
    try:
        result = subprocess.run(
            ["docker", "save", image_ref],
            capture_output=True,
            timeout=_DOCKER_SAVE_TIMEOUT_S,
        )
    except FileNotFoundError as exc:
        raise AgentBlobError("docker CLI not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise AgentBlobError(f"docker save timed out after {_DOCKER_SAVE_TIMEOUT_S}s") from exc
    if result.returncode != 0:
        detail = (result.stderr or b"").decode("utf-8", "replace").strip()
        if "no such image" in detail.lower():
            return None  # absent locally -> caller may pull and retry
        raise AgentBlobError(f"docker save failed: {detail[:300]}")
    if not result.stdout:
        raise AgentBlobError("docker save produced no output")
    return result.stdout


def _docker_pull(image_ref: str) -> None:
    """Best-effort `docker pull`. A failure here is not fatal on its own -- the
    retrying save reports the real problem -- so this only logs via the raised
    error when pull itself errors hard."""
    try:
        subprocess.run(
            ["docker", "pull", image_ref],
            capture_output=True,
            timeout=_DOCKER_SAVE_TIMEOUT_S,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # let the subsequent save decide the outcome


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _QuietHandler(SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler without the per-request stderr logging."""

    def log_message(self, *_args):  # noqa: D401 - silence
        pass


class BlobServer:
    """A daemon-threaded static file server hosting encrypted agent blobs.

    Files written into its directory are served at http://<host>:<port>/<name>.
    `host` is the address the *validator* will use to reach it (the miner's
    advertised IP), which is not necessarily the bind address, so it is stored
    only for building URLs; the socket itself binds all interfaces.
    """

    def __init__(self, advertised_host: str, port: int):
        self.advertised_host = advertised_host
        self.port = port
        self._dir = Path(tempfile.mkdtemp(prefix="secval-blob-"))
        handler = functools.partial(_QuietHandler, directory=str(self._dir))
        self._httpd = ThreadingHTTPServer(("0.0.0.0", port), handler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="secval-blob-server", daemon=True
        )
        self._thread.start()

    def publish(self, data: bytes, name: str) -> str:
        """Write `data` under `name` and return the URL the validator fetches."""
        (self._dir / name).write_bytes(data)
        return self.url_for(name)

    def url_for(self, name: str) -> str:
        return f"http://{self.advertised_host}:{self.port}/{name}"

    def stop(self) -> None:
        try:
            self._httpd.shutdown()
        except Exception:  # noqa: BLE001 - best effort on teardown
            pass

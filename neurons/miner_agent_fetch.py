from __future__ import annotations

"""neurons/miner_agent_fetch.py - fetch, decrypt and load each miner's OWN agent.

For a marketplace audit the worker must run the SPECIFIC miner's agent (not one
shared reference), so a customer's run — and the emission behind it — reflects
that miner's real capability. Mirrors the benchmark validator's secure intake
(security_validator._evaluate_blob): query the miner for its encrypted agent
blob, SSRF-validate the URL, download (bounded, no redirects), verify the
sha256, decrypt with our key, and then hand back something runnable:

  * submission_kind == "script"  -> the decrypted bytes ARE a single agent.py
    (the Python-script model). We form-check it (script_intake, which executes
    nothing) and write it to a cached .py path; the caller runs it in the fixed
    base-image gVisor sandbox via run_audit(agent_script=...). The returned path
    ends in ".py", which audit_loop.process_audit_job uses to pick the script
    run path over the image one.
  * otherwise ("" / "image")     -> the decrypted bytes are a `docker save`
    tarball (the original model); we docker-load it and return the image ref.

Caching is per hotkey, keyed by the blob's sha256, so re-audits of the same
agent don't re-fetch; a swapped agent (new sha) evicts the old script/image.

Security (URL + bytes are 100% miner-controlled): SSRF gate + redirect refusal
before any fetch; size/time-bounded download; sha256 verified before decrypt; a
blob that will not decrypt/load/parse fails CLOSED (AgentUnavailable), never a
shared substitute. A script still runs only inside the gVisor zero-egress
sandbox; a loaded image likewise. Intake only PARSES a script (no execution),
so analysing a hostile submission on the worker host is itself safe.
"""

import hashlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
import uuid

import bittensor as bt

from masxai import constants as C
from masxai.agent_crypto import (
    AgentCryptoError,
    decrypt_agent,
    generate_keypair,
    public_key_b64,
)
from masxai.protocol import SecurityAgentSynapse
from secqurityVali import constants as SC
from secqurityVali import docker_ops
from secqurityVali.script_intake import validate_agent_script
from secqurityVali.target_guard import TargetRejected, validate_target


class AgentUnavailable(Exception):
    """Miner's agent could not be obtained (offline, opted out, bad/unsafe blob,
    decrypt/load/parse failure). The audit fails closed."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, f"redirect to {newurl!r} refused", headers, fp
        )


def _download_blob(url: str) -> bytes:
    max_bytes = int(getattr(C, "SECURITY_BLOB_MAX_BYTES", 2 * 1024 ** 3))
    timeout = int(getattr(C, "SECURITY_BLOB_DOWNLOAD_TIMEOUT_S", 120))
    req = urllib.request.Request(url, method="GET")
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(req, timeout=timeout) as resp:
        chunks, total = [], 0
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"blob exceeds {max_bytes} bytes")
            chunks.append(chunk)
    return b"".join(chunks)


def _image_present(ref: str) -> bool:
    try:
        docker_ops.inspect_image(ref)
        return True
    except Exception:
        return False


class MinerAgentFetcher:
    def __init__(self, *, netuid, network, wallet_name, wallet_hotkey, key_path):
        self.netuid = int(netuid)
        self.subtensor = bt.Subtensor(network=network)
        self.wallet = bt.Wallet(name=wallet_name, hotkey=wallet_hotkey)
        self.dendrite = bt.Dendrite(wallet=self.wallet)
        self.metagraph = self.subtensor.metagraph(self.netuid)
        self._meta_synced = time.time()
        self._priv_b64 = self._load_or_make_key(key_path)
        self._pubkey_b64 = public_key_b64(self._priv_b64)
        self._pubkey_id = hashlib.sha256(self._pubkey_b64.encode()).hexdigest()[:16]
        # hotkey -> (blob_sha, kind, runnable)  where runnable is a .py path or image ref
        self._cache: dict[str, tuple[str, str, str]] = {}
        # scripts are cached here; one file per (hotkey, sha), replaced on a swap
        self._script_dir = os.path.join(tempfile.gettempdir(), "secaudit-agents")
        try:
            os.makedirs(self._script_dir, exist_ok=True)
        except OSError:
            pass

    @staticmethod
    def _load_or_make_key(path):
        try:
            with open(path, encoding="utf-8") as fh:
                k = json.load(fh).get("private_key_b64")
                if k:
                    return k
        except Exception:
            pass
        priv, _ = generate_keypair()
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"private_key_b64": priv}, fh)
            os.chmod(path, 0o600)
        except OSError:
            pass
        return priv

    def _maybe_resync(self, force=False):
        if force or time.time() - self._meta_synced > 1200:
            try:
                self.metagraph = self.subtensor.metagraph(self.netuid)
                self._meta_synced = time.time()
            except Exception:
                pass

    def _uid_of(self, hotkey):
        hks = list(self.metagraph.hotkeys)
        return hks.index(hotkey) if hotkey in hks else None

    def _write_script(self, hotkey: str, sha: str, raw: bytes) -> str:
        """Write the decrypted agent.py to a stable cached path and return it."""
        safe = hashlib.sha256(f"{hotkey}:{sha}".encode()).hexdigest()[:24]
        path = os.path.join(self._script_dir, f"agent-{safe}.py")
        with open(path, "wb") as fh:
            fh.write(raw)
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass
        return path

    def _evict(self, hotkey: str) -> None:
        """Drop a hotkey's cached runnable (remove the old script file / image)."""
        old = self._cache.pop(hotkey, None)
        if not old:
            return
        _sha, kind, runnable = old
        if kind == "script":
            try:
                os.remove(runnable)
            except OSError:
                pass
        else:
            try:
                docker_ops.remove_image(runnable)
            except Exception:
                pass

    def fetch(self, hotkey):
        """Return a runnable for the miner at `hotkey`: a .py path (script model)
        or a docker image ref (image model). Raises AgentUnavailable on any
        problem — the caller then fails the run closed, never a substitute."""
        self._maybe_resync()
        uid = self._uid_of(hotkey)
        if uid is None:
            self._maybe_resync(force=True)
            uid = self._uid_of(hotkey)
        if uid is None:
            raise AgentUnavailable(f"hotkey {hotkey[:10]} not registered on the subnet")

        axon = self.metagraph.axons[uid]
        if not getattr(axon, "is_serving", False):
            raise AgentUnavailable(f"uid {uid} not serving an axon (miner offline)")

        synapse = SecurityAgentSynapse(
            request_id=uuid.uuid4().hex,
            issued_at=int(time.time()),
            validator_pubkey_b64=self._pubkey_b64,
            pubkey_id=self._pubkey_id,
        )
        timeout = int(getattr(C, "SECURITY_QUERY_TIMEOUT", 12))
        try:
            responses = self.dendrite.query(
                axons=[axon], synapse=synapse, deserialize=False, timeout=timeout,
            )
        except Exception as exc:
            raise AgentUnavailable(f"axon query failed: {type(exc).__name__}") from exc

        resp = responses[0] if responses else None
        if resp is None or not getattr(resp, "has_agent", False):
            raise AgentUnavailable("miner provided no agent this round (opted out / offline)")

        blob_url = getattr(resp, "blob_url", None)
        sha = getattr(resp, "ciphertext_sha256", None)
        kind = (getattr(resp, "submission_kind", "") or "").strip().lower()
        if kind not in ("script", "image", ""):
            raise AgentUnavailable(f"miner declared unknown submission_kind {kind!r}")
        if not blob_url:
            raise AgentUnavailable("miner returned no encrypted blob_url")

        # Cache hit: same blob, and the runnable is still materialised.
        cached = self._cache.get(hotkey)
        if cached and sha and cached[0] == sha:
            _sha, ckind, runnable = cached
            if ckind == "script" and os.path.exists(runnable):
                return runnable
            if ckind != "script" and _image_present(runnable):
                return runnable

        try:
            validate_target(blob_url)
        except TargetRejected as exc:
            raise AgentUnavailable(f"unsafe blob_url: {exc}") from exc

        try:
            blob = _download_blob(blob_url)
        except Exception as exc:
            raise AgentUnavailable(f"blob download failed: {type(exc).__name__}") from exc
        if sha and hashlib.sha256(blob).hexdigest() != sha:
            raise AgentUnavailable("blob sha256 mismatch (truncated/tampered)")

        try:
            plain = decrypt_agent(blob, self._priv_b64)
        except AgentCryptoError as exc:
            raise AgentUnavailable("decrypt failed (miner encrypted for the wrong key)") from exc

        # Swapping in a new agent: drop the old cached runnable first.
        self._evict(hotkey)

        if kind == "script":
            verdict = validate_agent_script(plain)
            if not verdict.accepted:
                raise AgentUnavailable(f"agent.py rejected at intake: {verdict.reason}")
            path = self._write_script(hotkey, sha or verdict.agent_id, plain)
            self._cache[hotkey] = (sha or "", "script", path)
            return path

        # image model: the decrypted bytes are a docker-save tarball
        fd, tar_path = tempfile.mkstemp(prefix="secaudit-agent-", suffix=".tar")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(plain)
            try:
                image_ref = docker_ops.load_image(tar_path)
            except Exception as exc:
                raise AgentUnavailable(f"image load failed: {type(exc).__name__}") from exc
        finally:
            try:
                os.remove(tar_path)
            except OSError:
                pass
        self._cache[hotkey] = (sha or "", "image", image_ref)
        return image_ref

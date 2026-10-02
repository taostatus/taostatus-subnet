"""
neurons/security_miner.py - MASXAI security-track miner (mechanism 1).

The security half of the subnet's two mechanisms. It is a SEPARATE miner from
the LLM-key miner (neurons/miner.py, mechanism 0): a distinct process with its
own hotkey, serving only the security synapse. Registration is subnet-wide, not
per mechanism -- the hotkey's UID exists on both mechanisms -- but it only earns
on mechanism 1, because only the security validator weights it there. A hotkey
advertises one axon endpoint, which is why the two miners use two hotkeys.

What it does: when a validator asks (SecurityAgentSynapse), it returns its
security-testing agent as an ENCRYPTED docker image. The agent is `docker save`d,
sealed for the validator's public key (carried in the request), and hosted from a
tiny built-in static server; the miner returns only the blob URL + its sha256.
A peer that fetches the URL gets ciphertext it cannot decrypt. A plaintext
image_ref is kept as a fallback for a validator that sent no key.

    python neurons/security_miner.py --netuid 501 --subtensor.network test \
        --wallet.name <coldkey> --wallet.hotkey <hotkey> \
        --axon.port 8911 --axon.external_ip <public-ip>
"""

import os
import sys
import time
import typing
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai.protocol import SecurityAgentSynapse
from masxai import constants as C
from masxai.bt_compat import bt
from masxai.env import load_env
from masxai.agent_crypto import AgentCryptoError, encrypt_agent
from masxai.agent_blob import AgentBlobError, BlobServer, save_image_tar, sha256_hex

try:
    from template.base.miner import BaseMinerNeuron
except Exception:
    class BaseMinerNeuron: 
        def __init__(self, *_, **__):
            raise RuntimeError("BaseMinerNeuron requires a working bittensor install")


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityMiner(BaseMinerNeuron):
    """A miner that contributes a security-testing agent (mechanism 1).

    `forward` is annotated with SecurityAgentSynapse, so the base class attaches
    it (and blacklist/priority) as this miner's only route -- it serves the
    security synapse and nothing else.
    """

    # Mechanism 1 (security). There is no per-mechanism registration: this
    # hotkey's UID exists on every mechanism of the subnet. It earns on
    # mechanism 1 because only the security validator weights it there.
    mechid = C.SECURITY_MECHID

    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)

        enabled = _env_flag(C.SECURITY_AGENT_ENABLED_ENV, False)

        # Encrypted-blob transport state. The blob server hosts the encrypted
        # agent tarball so the validator can download it; caches avoid redoing
        # the heavy docker-save/encrypt on every ask.
        self._blob_server: BlobServer | None = None
        self._agent_tar: bytes | None = None
        self._agent_tar_image: str | None = None
        self._agent_blobs: dict[tuple[str, str], tuple[str, str]] = {}
        if enabled:
            self._start_blob_server()

        bt.logging.info(
            f"Security miner (mechanism 1) | enabled={enabled} "
            f"image={os.getenv(C.SECURITY_AGENT_IMAGE_ENV) or '(unset)'} "
            f"blob_server={'up' if self._blob_server else 'off'}"
        )
        bt.logging.info("MASXAI security miner initialized.")

    def _blob_host(self) -> str | None:
        """The address the validator will use to reach our blob server: an
        explicit override, else our advertised axon external IP."""
        host = (os.getenv(C.SECURITY_BLOB_HOST_ENV) or "").strip()
        if host:
            return host
        axon = getattr(self, "axon", None)
        for obj in (axon, getattr(self, "config", None) and self.config.axon):
            ip = getattr(obj, "external_ip", None) if obj is not None else None
            if ip and str(ip) not in ("", "0.0.0.0", "[::]"):
                return str(ip)
        return None

    def _start_blob_server(self) -> None:
        host = self._blob_host()
        if not host:
            bt.logging.warning(
                "security: could not determine an external host for the blob "
                f"server; set {C.SECURITY_BLOB_HOST_ENV}. Falling back to "
                "image_ref (plaintext) if configured."
            )
            return
        port = int(os.getenv(C.SECURITY_BLOB_PORT_ENV, C.SECURITY_BLOB_PORT))
        try:
            self._blob_server = BlobServer(host, port)
            bt.logging.info(f"security: blob server hosting at http://{host}:{port}/")
        except Exception as e:  # noqa: BLE001 - a bound port must not kill the miner
            bt.logging.warning(f"security: could not start blob server on {port}: {e}")

    def _agent_blob_for(
        self, image_ref: str, pubkey_b64: str, pubkey_id: str
    ) -> tuple[str, str]:
        """Return (blob_url, ciphertext_sha256) for `image_ref` encrypted to
        `pubkey_b64`, doing the docker-save and encryption at most once per
        (image, key) pair. Raises on failure; the caller declines the round."""
        # Save (and cache) the tarball; re-save if the configured image changed.
        if self._agent_tar is None or self._agent_tar_image != image_ref:
            self._agent_tar = save_image_tar(image_ref)
            self._agent_tar_image = image_ref
            self._agent_blobs.clear()  # tar changed -> old ciphertexts are stale
        tar = self._agent_tar
        tar_sha = sha256_hex(tar)

        cache_key = (pubkey_b64, tar_sha)
        cached = self._agent_blobs.get(cache_key)
        if cached is not None:
            return cached

        blob = encrypt_agent(tar, pubkey_b64)
        cipher_sha = sha256_hex(blob)
        name = f"{(pubkey_id or 'k')[:16]}-{tar_sha[:12]}.enc"
        url = self._blob_server.publish(blob, name)  # type: ignore[union-attr]
        self._agent_blobs[cache_key] = (url, cipher_sha)
        return url, cipher_sha

    async def forward(self, synapse: SecurityAgentSynapse) -> SecurityAgentSynapse:
        """Answer a request for this miner's security-agent image, or decline.

        Primary path (v2): encrypt a docker-save tarball of the agent for the
        validator's public key (carried in the request) and return a URL to the
        opaque ciphertext, so a peer that fetches it learns nothing. Fallback:
        when the validator sent no key (a v1 validator) or the blob server could
        not start, return a plaintext image_ref if one is configured. Never
        raises -- any failure declines (has_agent=False) rather than crashing.
        """
        try:
            if not _env_flag(C.SECURITY_AGENT_ENABLED_ENV, False):
                synapse.has_agent = False
                return synapse
            image_ref = (os.getenv(C.SECURITY_AGENT_IMAGE_ENV) or "").strip()
            if not image_ref:
                synapse.has_agent = False
                return synapse

            pubkey = (synapse.validator_pubkey_b64 or "").strip()
            if pubkey and self._blob_server is not None:
                # encrypted path: host an opaque blob the validator can decrypt
                blob_url, cipher_sha = self._agent_blob_for(
                    image_ref, pubkey, synapse.pubkey_id
                )
                synapse.blob_url = blob_url
                synapse.ciphertext_sha256 = cipher_sha
                synapse.blob_encoding = "nacl-sealedbox-v1"
                synapse.pubkey_id_used = synapse.pubkey_id
                synapse.has_agent = True
            else:
                # fallback: plaintext registry reference (only if it is one; a
                # local-only image name would be useless to the validator)
                synapse.image_ref = image_ref
                synapse.has_agent = True
                if not pubkey:
                    bt.logging.debug("security: validator sent no pubkey; using image_ref fallback")
                else:
                    bt.logging.warning("security: blob server unavailable; using image_ref fallback")
            synapse.timestamp = _utc_now_iso()
        except (AgentBlobError, AgentCryptoError) as e:
            bt.logging.warning(f"security: could not prepare encrypted agent, declining: {e}")
            synapse.has_agent = False
        except Exception as e:  # noqa: BLE001 — never let forward crash
            bt.logging.warning(f"security agent submission failed, declining: {e}")
            synapse.has_agent = False
            synapse.blob_url = ""
            synapse.image_ref = ""
        return synapse

    async def blacklist(self, synapse: SecurityAgentSynapse) -> typing.Tuple[bool, str]:
        """A validator permit is always required, because an accepted response
        makes the validator pull and run an image -- a state-changing,
        security-sensitive action."""
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            return True, "missing dendrite/hotkey"
        hotkey = synapse.dendrite.hotkey
        if hotkey not in self.metagraph.hotkeys:
            return True, f"unregistered hotkey {hotkey}"
        uid = self.metagraph.hotkeys.index(hotkey)
        permits = getattr(self.metagraph, "validator_permit", None)
        if permits is None:
            return True, "validator permit unavailable"
        if not bool(permits[uid]):
            return True, "no validator permit"
        return False, f"accepted from uid {uid}"

    async def priority(self, synapse: SecurityAgentSynapse) -> float:
        """Prioritize higher-stake callers. Standard template pattern."""
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            return 0.0
        try:
            uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)
        except ValueError:
            return 0.0
        return float(self.metagraph.S[uid])


if __name__ == "__main__":
    with SecurityMiner() as miner:
        while True:
            bt.logging.info(f"MASXAI security miner alive | {time.strftime('%Y-%m-%d %H:%M:%S')}")
            time.sleep(30)

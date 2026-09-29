"""
neurons/miner.py - MASXAI miner: LLM-key contribution pipeline.

A miner opts in to contribute between LLM_KEY_MIN_KEYS_PER_HOTKEY (5) and
LLM_KEY_MAX_KEYS_PER_HOTKEY (5) distinct LLM API keys as a resource for the
protocol backend -- fewer than the minimum and the miner declines the round
entirely rather than contributing a partial batch. The miner never talks to
the protocol directly and never sees a contributed key leave in plaintext --
it encrypts each key client-side for the protocol's published public key,
and the validator relays only those opaque ciphertexts onward.
"""

import json
import os
import sys
import time
import typing
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai.protocol import LLMKeySynapse, SecurityAgentSynapse
from masxai import constants as C
from masxai.bt_compat import bt
from masxai.env import load_env
from masxai.llm_key_crypto import encrypt_for_protocol
from masxai.agent_crypto import AgentCryptoError, encrypt_agent
from masxai.agent_blob import AgentBlobError, BlobServer, save_image_tar, sha256_hex

# Provided by the bittensor-subnet-template fork:
try:
    from template.base.miner import BaseMinerNeuron
except Exception:
    class BaseMinerNeuron:  # type: ignore[no-redef]
        def __init__(self, *_, **__):
            raise RuntimeError("BaseMinerNeuron requires a working bittensor install")


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _llm_key_contrib_configs() -> list[typing.Tuple[str, str, str]]:
    """Return the operator's configured keys as [(provider, model, api_key)],
    deduplicated by physical key and required to meet
    LLM_KEY_MIN_KEYS_PER_HOTKEY, capped at LLM_KEY_MAX_KEYS_PER_HOTKEY.
    Empty when not opted in, nothing is configured completely, or the
    deduplicated set doesn't meet the minimum -- a miner declines the round
    entirely rather than contributing a partial batch (mirrors this
    project's "decline rather than hedge" principle, applied to submission
    volume instead of debate content).

    MASXAI_LLM_KEYS_JSON (a JSON array of {provider, model, api_key}) is the
    multi-key config; list order is the slot order. The legacy single-key
    MASXAI_LLM_KEY_CONTRIB_* triple is still honored as slot 0 when the JSON
    env is unset -- note it can never alone satisfy the minimum once that's
    >1, so it only remains useful combined with... nothing else, practically
    it's retired by a minimum >1. A malformed JSON document or entry is
    skipped with a warning rather than crashing the miner.

    Physical-key deduplication here is a courtesy check only: this is the
    one layer that ever sees plaintext, so it's the only place a same
    -physical-key check can be a real string comparison rather than a
    structural impossibility -- the validator never decrypts, and NaCl
    SealedBox (see llm_key_crypto.py) is deliberately non-deterministic, so
    ciphertext blobs can never be compared to catch this downstream. The
    protocol backend is the authoritative enforcer (fingerprint-after
    -decrypt), this just avoids wasting a whole round on a submission
    that's guaranteed to come back partially rejected.
    """
    if not _env_flag(C.LLM_KEY_CONTRIB_ENABLED_ENV, False):
        return []

    configs: list[typing.Tuple[str, str, str]] = []
    seen_api_keys: set[str] = set()

    raw_json = os.getenv(C.LLM_KEYS_JSON_ENV, "").strip()
    if raw_json:
        try:
            entries = json.loads(raw_json)
        except json.JSONDecodeError as e:
            bt.logging.warning(f"llm-key: {C.LLM_KEYS_JSON_ENV} is not valid JSON ({e}); contributing nothing")
            return []
        if not isinstance(entries, list):
            bt.logging.warning(f"llm-key: {C.LLM_KEYS_JSON_ENV} must be a JSON array; contributing nothing")
            return []
        for i, entry in enumerate(entries):
            if len(configs) >= C.LLM_KEY_MAX_KEYS_PER_HOTKEY:
                bt.logging.warning(
                    f"llm-key: more than {C.LLM_KEY_MAX_KEYS_PER_HOTKEY} keys configured; "
                    "ignoring the extras"
                )
                break
            if not isinstance(entry, dict):
                bt.logging.warning(f"llm-key: entry #{i} is not an object; skipping it")
                continue
            provider = str(entry.get("provider", "")).strip()
            model = str(entry.get("model", "")).strip()
            api_key = str(entry.get("api_key", "")).strip()
            if not provider or not model or not api_key:
                bt.logging.warning(f"llm-key: entry #{i} is missing provider/model/api_key; skipping it")
                continue
            if api_key in seen_api_keys:
                bt.logging.warning(
                    f"llm-key: entry #{i} is the same physical key as an earlier entry; "
                    "skipping the duplicate (same provider/model across slots is fine, "
                    "the same underlying key is not)"
                )
                continue
            seen_api_keys.add(api_key)
            configs.append((provider, model, api_key))
    else:
        provider = os.getenv(C.LLM_KEY_CONTRIB_PROVIDER_ENV, "").strip()
        model = os.getenv(C.LLM_KEY_CONTRIB_MODEL_ENV, "").strip()
        api_key = os.getenv(C.LLM_KEY_CONTRIB_API_KEY_ENV, "").strip()
        if provider and model and api_key:
            configs.append((provider, model, api_key))

    if len(configs) < C.LLM_KEY_MIN_KEYS_PER_HOTKEY:
        if configs:
            bt.logging.warning(
                f"llm-key: only {len(configs)} distinct key(s) configured, below the "
                f"required minimum of {C.LLM_KEY_MIN_KEYS_PER_HOTKEY}; declining to "
                "contribute this round rather than submitting a partial batch"
            )
        return []
    return configs


class Miner(BaseMinerNeuron):
    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)
        configs = _llm_key_contrib_configs()
        bt.logging.info(
            "LLM-key contribution | "
            f"enabled={bool(configs)} keys={len(configs)} "
            + " ".join(f"slot{i}={p}/{m}" for i, (p, m, _) in enumerate(configs))
        )

        # Attach the security-audit synapse as a second route on the same axon.
        # The base class already attached forward()/blacklist()/priority() for
        # LLMKeySynapse; bittensor routes each synapse type to its own handler
        # by the forward function's type annotation, so one hotkey serves both
        # tracks. Guarded so a bittensor build without .axon (the fallback in
        # tests) doesn't crash construction.
        security_enabled = _env_flag(C.SECURITY_AGENT_ENABLED_ENV, False)
        axon = getattr(self, "axon", None)
        if axon is not None:
            try:
                axon.attach(
                    forward_fn=self.forward_security,
                    blacklist_fn=self.blacklist_security,
                    priority_fn=self.priority_security,
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"could not attach security synapse route: {e}")

        # Encrypted-blob transport state. The blob server hosts the encrypted
        # agent tarball so the validator can download it; caches avoid redoing
        # the heavy docker-save/encrypt on every ask.
        self._blob_server: BlobServer | None = None
        self._agent_tar: bytes | None = None
        self._agent_tar_image: str | None = None
        self._agent_blobs: dict[tuple[str, str], tuple[str, str]] = {}
        if security_enabled:
            self._start_blob_server()

        bt.logging.info(
            f"Security-audit contribution | enabled={security_enabled} "
            f"image={os.getenv(C.SECURITY_AGENT_IMAGE_ENV) or '(unset)'} "
            f"blob_server={'up' if self._blob_server else 'off'}"
        )
        bt.logging.info("MASXAI miner initialized.")

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

    async def forward(self, synapse: LLMKeySynapse) -> LLMKeySynapse:
        """Answer a request to contribute LLM keys, or decline cleanly.

        Each configured key is encrypted independently and sent with its
        slot (= its index in the configured list, stable across asks so a
        config edit replaces exactly that slot on the backend). A key whose
        provider/model isn't in this round's allowed list is skipped, not a
        reason to withhold the others. Never raises -- any failure (not
        opted in, bad protocol pubkey, encryption error) falls back to
        has_key=False rather than crashing the axon route.
        """
        try:
            configs = _llm_key_contrib_configs()
            if not configs or not synapse.protocol_pubkey_b64:
                synapse.has_key = False
                return synapse

            keys: list[dict] = []
            for slot, (provider, model, api_key) in enumerate(configs):
                if synapse.allowed_models and f"{provider}/{model}" not in synapse.allowed_models:
                    bt.logging.debug(
                        f"llm-key: slot {slot} ({provider}/{model}) not in this round's "
                        "allowed_models; skipping that slot"
                    )
                    continue
                keys.append({
                    "slot": slot,
                    "provider": provider,
                    "model": model,
                    "encrypted_key_blob": encrypt_for_protocol(
                        api_key, synapse.protocol_pubkey_b64
                    ),
                    "blob_encoding": "nacl-sealedbox-v1",
                    "pubkey_id_used": synapse.protocol_pubkey_id,
                })

            synapse.keys = keys
            synapse.has_key = bool(keys)
            synapse.timestamp = _utc_now_iso()
        except Exception as e:  # noqa: BLE001 — never let forward crash
            bt.logging.warning(f"llm-key contribution failed, declining this round: {e}")
            synapse.has_key = False
            synapse.keys = []
        return synapse

    async def blacklist(self, synapse: LLMKeySynapse) -> typing.Tuple[bool, str]:
        """Reject non-registered or non-validator hotkeys.

        A validator permit is always required (not gated behind an opt-in
        flag) -- this synapse triggers a state-changing, security-sensitive
        action (a key submission relayed onward to the protocol backend) on
        every accepted response.
        """
        return self._require_validator(synapse)

    async def priority(self, synapse: LLMKeySynapse) -> float:
        """Prioritize higher-stake callers. Standard template pattern."""
        return self._stake_priority(synapse)

    # ------------------------------------------------------------ security
    async def forward_security(
        self, synapse: SecurityAgentSynapse
    ) -> SecurityAgentSynapse:
        """Answer a request for this miner's security-agent image, or decline.

        Primary path (v2): the miner encrypts a docker-save tarball of its agent
        for the validator's public key (carried in the request) and returns a
        URL to the opaque ciphertext, so a peer that fetches it learns nothing.
        Fallback: when the validator sent no key (a v1 validator) or the blob
        server could not start, the miner returns a plaintext image_ref if one
        is configured. Never raises -- any failure declines (has_agent=False)
        rather than crashing the axon route, exactly like the LLM-key path.
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

    async def blacklist_security(
        self, synapse: SecurityAgentSynapse
    ) -> typing.Tuple[bool, str]:
        """Same rule as the LLM-key path: a validator permit is always
        required, because an accepted response makes the validator pull and
        run an image -- a state-changing, security-sensitive action."""
        return self._require_validator(synapse)

    async def priority_security(self, synapse: SecurityAgentSynapse) -> float:
        return self._stake_priority(synapse)

    # ------------------------------------------------------ shared helpers
    def _require_validator(self, synapse) -> typing.Tuple[bool, str]:
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

    def _stake_priority(self, synapse) -> float:
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            return 0.0
        try:
            uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)
        except ValueError:
            return 0.0
        return float(self.metagraph.S[uid])


if __name__ == "__main__":
    with Miner() as miner:
        while True:
            bt.logging.info(f"MASXAI miner alive | {time.strftime('%Y-%m-%d %H:%M:%S')}")
            time.sleep(30)

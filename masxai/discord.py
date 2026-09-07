"""Discord webhook announcements for LLM-key submission rounds.

The validator is the only party that sees a whole round end to end -- which
miners it asked, what each answered, and what the protocol backend decided
about every slot. This publishes that to a channel so miners get immediate
feedback on whether their keys were accepted and for which models, instead of
having to ask an operator.

What may appear in a message
----------------------------
The channel is public, so only already-public data goes out: the hotkey
(published on-chain in the metagraph), the declared provider/model, the slot
index, and the accept/reject outcome with its reason.

Never the key itself, its ciphertext, or its fingerprint. The validator has
no way to read a key anyway -- it only ever holds ciphertext it cannot
decrypt -- but `_FORBIDDEN_SUBSTRINGS` makes that a checked property of the
outgoing payload rather than an inherited assumption, since the ciphertext
IS in scope here and must not be echoed.

Failure policy
--------------
Announcing is never allowed to affect the submission round. Every call is
best-effort: bounded timeout, all exceptions swallowed and logged. A dead or
rate-limited webhook must not cost a miner its contribution.
"""

from __future__ import annotations

import os
from typing import Any, Iterable, Optional

import httpx

from masxai import constants as C
from masxai.bt_compat import bt
from masxai.env import load_env

# Discord hard-rejects messages over 2000 characters.
_MAX_CONTENT_CHARS = 1900

# A hotkey may contribute at most LLM_KEY_MAX_KEYS_PER_HOTKEY slots, but
# truncate defensively rather than trusting the batch length.
_MAX_LINES = 12

# Must never appear in an outgoing payload. Asserted in
# tests/test_discord.py rather than only documented.
_FORBIDDEN_SUBSTRINGS = (
    "encrypted_key_blob",
    "key_fingerprint",
    "api_key",
    "sk-",
)


def _short_hotkey(hotkey: str, head: int = 8, tail: int = 4) -> str:
    """Readable in a chat line. Hotkeys are public on-chain, so this is for
    legibility, not secrecy."""
    if len(hotkey) <= head + tail + 1:
        return hotkey
    return f"{hotkey[:head]}...{hotkey[-tail:]}"


def format_submission_message(
    *, hotkey: str, uid: Optional[int], results: Iterable[Any],
    netuid: Optional[int] = None, network: Optional[str] = None,
) -> Optional[str]:
    """Render one hotkey's submission outcome.

    `results` are the per-slot entries the protocol returned (slot, provider,
    model, accepted, reason -- see LLMKeySubmitResult in llm_key_client).
    Returns None when there is nothing worth posting, so the caller can skip
    the request entirely.
    """
    rows = sorted(results, key=lambda r: getattr(r, "slot", 0))
    if not rows:
        return None

    accepted = sum(1 for r in rows if getattr(r, "accepted", False))
    uid_part = f" | UID {uid}" if uid is not None else ""
    lines = [
        f"{_network_tag(netuid, network)}**LLM key submission** "
        f"`{_short_hotkey(hotkey)}`{uid_part} - {accepted}/{len(rows)} accepted"
    ]

    for row in rows[:_MAX_LINES]:
        provider = getattr(row, "provider", "?")
        model = getattr(row, "model", "?")
        slot = getattr(row, "slot", "?")
        if getattr(row, "accepted", False):
            lines.append(f":white_check_mark: slot {slot} `{provider}/{model}`")
        else:
            reason = getattr(row, "reason", None)
            suffix = f" - {reason}" if reason else ""
            lines.append(f":x: slot {slot} `{provider}/{model}`{suffix}")

    if len(rows) > _MAX_LINES:
        lines.append(f"...and {len(rows) - _MAX_LINES} more")

    return "\n".join(lines)[:_MAX_CONTENT_CHARS]


def webhook_url() -> str:
    """Configured webhook, or empty string when the feature is off.

    Unset is the kill switch -- exactly like MASXAI_LLM_KEY_VALIDATOR_TOKEN
    gates the key pipeline itself.
    """
    load_env()
    return (os.getenv(C.DISCORD_WEBHOOK_URL_ENV, "") or "").strip()


async def post_message(content: str, *, url: Optional[str] = None) -> bool:
    """Post to the webhook. Returns True only on a 2xx. Never raises."""
    target = (url or webhook_url()).strip()
    if not target:
        return False
    try:
        timeout = float(os.getenv(C.DISCORD_TIMEOUT_ENV, C.DISCORD_TIMEOUT))
    except (TypeError, ValueError):
        timeout = C.DISCORD_TIMEOUT
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(target, json={"content": content})
        if resp.status_code >= 400:
            # Body, not just status: Discord explains rate limits and
            # malformed payloads there. The URL is a credential and is
            # deliberately never logged.
            bt.logging.warning(
                f"discord: webhook returned {resp.status_code}: {resp.text[:200]}"
            )
            return False
        return True
    except Exception as e:  # noqa: BLE001 -- must never break a caller
        bt.logging.warning(f"discord: webhook post failed: {e}")
        return False


def _network_tag(netuid: Optional[int], network: Optional[str]) -> str:
    """Which chain this message came from.

    Several validators may share one channel -- a testnet rehearsal and a
    mainnet deployment most obviously. Without this they are
    indistinguishable, and a testnet failure reads as a production incident.
    """
    if netuid is None and not network:
        return ""
    parts = []
    if network:
        parts.append(str(network))
    if netuid is not None:
        parts.append(f"netuid {netuid}")
    return f"[{' · '.join(parts)}] "


def format_round_summary(
    *, asked: int, answered: int, contributed: int,
    relay_failures: Optional[Iterable[Any]] = None,
    netuid: Optional[int] = None, network: Optional[str] = None,
) -> str:
    """Render one submission round's outcome.

    Posted whatever happened, including when every relay failed -- that case
    is precisely the one nobody can see otherwise, because a failed relay
    never reaches the per-hotkey announcement below. A round that asks 13
    miners and contributes nothing looks identical to a healthy quiet round
    from outside; this distinguishes them.

    relay_failures are (hotkey, uid, error) triples. They are named
    individually rather than merely counted: a relay failure belongs to one
    miner, and "1 submission could not be relayed" tells that miner nothing
    about whether it was theirs.
    """
    lines = [
        f"{_network_tag(netuid, network)}**Key round** - "
        f"asked {asked} | answered {answered} | contributed {contributed}"
    ]

    failures = list(relay_failures or [])
    if failures:
        lines.append(f":warning: {len(failures)} submission(s) could not be relayed:")
        for hotkey, uid, error in failures[:_MAX_LINES]:
            uid_part = f" | UID {uid}" if uid is not None else ""
            reason = f" - {error}" if error else ""
            lines.append(f"`{_short_hotkey(hotkey)}`{uid_part}{reason}")
        if len(failures) > _MAX_LINES:
            lines.append(f"...and {len(failures) - _MAX_LINES} more")

    return "\n".join(lines)[:_MAX_CONTENT_CHARS]


async def publish_round_summary(
    *, asked: int, answered: int, contributed: int,
    relay_failures: Optional[Iterable[Any]] = None,
    netuid: Optional[int] = None, network: Optional[str] = None,
) -> None:
    """Announce a completed submission round. No-ops when unconfigured."""
    if not webhook_url():
        return
    try:
        await post_message(format_round_summary(
            asked=asked, answered=answered, contributed=contributed,
            relay_failures=relay_failures, netuid=netuid, network=network,
        ))
    except Exception as e:  # noqa: BLE001
        bt.logging.warning(f"discord: failed to announce round summary: {e}")


async def publish_key_submission(
    *, hotkey: str, uid: Optional[int], results: Iterable[Any],
    netuid: Optional[int] = None, network: Optional[str] = None,
) -> None:
    """Announce one hotkey's submission outcome. Safe to call unconditionally:
    no-ops when unconfigured and swallows every failure."""
    if not webhook_url():
        return
    try:
        content = format_submission_message(
            hotkey=hotkey, uid=uid, results=results, netuid=netuid, network=network,
        )
        if content is None:
            return
        await post_message(content)
    except Exception as e:  # noqa: BLE001
        bt.logging.warning(f"discord: failed to announce submission: {e}")

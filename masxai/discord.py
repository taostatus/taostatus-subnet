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
from datetime import datetime, timezone
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


# --- Security (mech 1) validator: per-round miner-evaluation feed ------------
#
# Mirrors the LLM-key announcements above, on its OWN webhook/channel. Only
# on-chain-public eval metadata goes out -- uid, hotkey, category, pass/fail,
# task score, the safety flag. NEVER the canary/secret (the whole point of the
# benchmark is that it is extracted live and never known in advance) and never
# a miner's IP. Best-effort: unset webhook = off, every failure swallowed, so a
# dead channel can never slow or break an evaluation round.

def security_webhook_url() -> str:
    """Security channel webhook, or empty string when the feature is off."""
    load_env()
    return (os.getenv(C.SECURITY_DISCORD_WEBHOOK_URL_ENV, "") or "").strip()


def _security_passed(r: dict) -> bool:
    return bool(r.get("accepted")) and r.get("safe") is not False


# Embed accent colours (Discord takes a decimal int).
_COLOR_GREEN = 0x2ECC71
_COLOR_RED = 0xE74C3C
_COLOR_AMBER = 0xE67E22
_COLOR_GREY = 0x95A5A6


def _security_groups(rows: list[dict]) -> dict[str, list[dict]]:
    """Split a round's rows into display groups, each order-stable by uid."""
    groups = {"passed": [], "unsafe": [], "failed": [], "intake": [], "infra": []}
    for r in sorted(rows, key=lambda x: x.get("uid", 0)):
        if r.get("kind") == "infra":
            groups["infra"].append(r)
        elif r.get("kind") == "intake":
            groups["intake"].append(r)
        elif _security_passed(r):
            groups["passed"].append(r)
        elif r.get("safe") is False:
            groups["unsafe"].append(r)
        else:
            groups["failed"].append(r)
    return groups


def format_security_round(
    results: Iterable[Any], *, asked: int, answered: int,
    netuid: Optional[int] = None, network: Optional[str] = None,
) -> Optional[str]:
    """Plain-text rendering of a round (kept for the embed description and as a
    fallback). Returns None when nothing was evaluated."""
    rows = list(results)
    if not rows:
        return None
    groups = _security_groups(rows)

    def _row(r: dict, *, detail: bool) -> str:
        tag = f"`UID {r.get('uid')}` `{_short_hotkey(str(r.get('hotkey', '')))}`"
        if not detail:
            return tag
        cat = r.get("cat") or "?"
        task = r.get("task")
        extra = f" · task {task}" if task is not None else ""
        return f"{tag} · {cat}{extra}"

    sections = [
        ("✅ **Passed**", groups["passed"], True),
        ("⚠️ **Unsafe behaviour**", groups["unsafe"], True),
        ("❌ **Failed**", groups["failed"], True),
        ("🚫 **Rejected at intake**", groups["intake"], False),
        ("🔁 **Skipped (infra, retry)**", groups["infra"], False),
    ]
    out: list[str] = []
    shown = 0
    for title, grp, detail in sections:
        if not grp:
            continue
        out.append(f"{title} — {len(grp)}")
        for r in grp:
            if shown >= _MAX_LINES:
                break
            out.append(_row(r, detail=detail))
            shown += 1
        out.append("")  # blank line between sections
    if shown >= _MAX_LINES and len(rows) > shown:
        out.append(f"…and {len(rows) - shown} more")
    return "\n".join(out).strip()[:_MAX_CONTENT_CHARS]


def build_security_round_embed(
    results: Iterable[Any], *, asked: int, answered: int,
    netuid: Optional[int] = None, network: Optional[str] = None,
) -> Optional[dict]:
    """Build a Discord embed for one round. Returns None when nothing ran."""
    rows = list(results)
    if not rows:
        return None
    groups = _security_groups(rows)
    passed = len(groups["passed"])
    unsafe = len(groups["unsafe"])

    if passed:
        color = _COLOR_GREEN
    elif unsafe:
        color = _COLOR_RED
    elif groups["failed"] or groups["intake"]:
        color = _COLOR_AMBER
    else:
        color = _COLOR_GREY

    description = format_security_round(
        rows, asked=asked, answered=answered, netuid=netuid, network=network,
    ) or "No miners evaluated this round."

    tag = _network_tag(netuid, network).strip()
    footer = tag.strip("[] ") if tag else "security validator"

    embed = {
        "title": "🛡️ Security Evaluation Round",
        "color": color,
        "description": description[:4096],
        "fields": [
            {"name": "Asked", "value": str(asked), "inline": True},
            {"name": "Answered", "value": str(answered), "inline": True},
            {"name": "Passed", "value": str(passed), "inline": True},
        ],
        "footer": {"text": footer},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return embed


async def post_embed(embed: dict, *, url: Optional[str] = None) -> bool:
    """Post a single embed to a webhook. Returns True only on a 2xx. Never raises."""
    target = (url or "").strip()
    if not target:
        return False
    try:
        timeout = float(os.getenv(C.DISCORD_TIMEOUT_ENV, C.DISCORD_TIMEOUT))
    except (TypeError, ValueError):
        timeout = C.DISCORD_TIMEOUT
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(target, json={"embeds": [embed]})
        if resp.status_code >= 400:
            bt.logging.warning(
                f"discord: webhook returned {resp.status_code}: {resp.text[:200]}"
            )
            return False
        return True
    except Exception as e:  # noqa: BLE001 -- must never break a caller
        bt.logging.warning(f"discord: embed post failed: {e}")
        return False


async def publish_security_round(
    results: Iterable[Any], *, asked: int, answered: int,
    netuid: Optional[int] = None, network: Optional[str] = None,
) -> None:
    """Announce one security round to the security channel as a formatted embed.
    Safe to call unconditionally: no-ops when unconfigured, swallows failures."""
    url = security_webhook_url()
    if not url:
        return
    try:
        embed = build_security_round_embed(
            results, asked=asked, answered=answered, netuid=netuid, network=network,
        )
        if embed is None:
            return
        await post_embed(embed, url=url)
    except Exception as e:  # noqa: BLE001
        bt.logging.warning(f"discord: failed to announce security round: {e}")


# --- Per-miner detailed evaluation feed ("Testing Logs" channel) ------------
#
# One embed per agent test, so a miner can see exactly how its run went and why
# it passed/failed. The failure hint is STAGE-level and generic ("no canary
# extracted"), never the run's answer (which endpoint/parameter was vulnerable),
# so it debugs without leaking a way to cheat. Separate webhook/channel.

def testlog_webhook_url() -> str:
    """Testing-logs channel webhook, or empty string when the feature is off."""
    load_env()
    return (os.getenv(C.SECURITY_TESTLOG_DISCORD_WEBHOOK_URL_ENV, "") or "").strip()


def _eval_hint(r: dict) -> Optional[str]:
    """A generic, cheat-safe reason a run did not fully pass. None when it did."""
    kind = r.get("kind")
    if kind == "infra":
        return "skipped — validator infrastructure (retried next round)"
    if kind == "intake":
        return "rejected at intake — image invalid or a duplicate of an existing agent"
    if r.get("safe") is False:
        return "unsafe behaviour detected — the run was stopped on the safety gate"
    if not r.get("accepted"):
        if r.get("canary") is False:
            return "reached the target but did not extract the secret"
        return "did not meet the pass bar"
    return None


def _check(flag: Optional[bool]) -> str:
    if flag is True:
        return "✓"
    if flag is False:
        return "✗"
    return "—"


def build_security_eval_embed(
    r: dict, *, netuid: Optional[int] = None, network: Optional[str] = None,
) -> dict:
    """Build a Discord embed for ONE miner's evaluation."""
    passed = _security_passed(r)
    if r.get("kind") == "infra":
        color = _COLOR_GREY
    elif passed:
        color = _COLOR_GREEN
    elif r.get("safe") is False:
        color = _COLOR_RED
    else:
        color = _COLOR_AMBER

    uid = r.get("uid")
    fields = [
        {"name": "Miner", "value": f"`{_short_hotkey(str(r.get('hotkey', '')))}`", "inline": True},
    ]

    if r.get("kind") == "job":
        cat = r.get("cat") or "?"
        variant = r.get("variant")
        cat_val = f"`{cat}`" + (f" · {variant}" if variant else "")
        fields.append({"name": "Category", "value": cat_val, "inline": True})
        if passed:
            result = f"✅ Accepted — task {r.get('task')}"
        else:
            result = f"❌ Rejected — {_eval_hint(r)}"
        fields.append({"name": "Result", "value": result, "inline": False})
        fields.append({
            "name": "Checks",
            "value": (f"canary {_check(r.get('canary'))} · "
                      f"replay {_check(r.get('replay'))} · "
                      f"located {_check(r.get('located'))}"),
            "inline": True,
        })
        req = r.get("requests")
        if req is not None:
            fields.append({"name": "Requests", "value": str(req), "inline": True})
    else:
        fields.append({"name": "Result", "value": f"❌ {_eval_hint(r)}", "inline": False})

    agent = r.get("agent")
    if agent:
        fields.append({"name": "Agent", "value": f"`{str(agent)[:12]}`", "inline": True})

    tag = _network_tag(netuid, network).strip()
    footer = tag.strip("[] ") if tag else "security validator"
    return {
        "title": f"🧪 Agent Evaluation · UID {uid}",
        "color": color,
        "fields": fields,
        "footer": {"text": footer},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def publish_security_eval(
    r: dict, *, netuid: Optional[int] = None, network: Optional[str] = None,
) -> None:
    """Post one miner's evaluation to the Testing Logs channel. No-ops when
    unconfigured; swallows every failure."""
    url = testlog_webhook_url()
    if not url:
        return
    try:
        await post_embed(
            build_security_eval_embed(r, netuid=netuid, network=network), url=url,
        )
    except Exception as e:  # noqa: BLE001
        bt.logging.warning(f"discord: failed to announce eval: {e}")

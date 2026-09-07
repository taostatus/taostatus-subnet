"""Tests for the validator's Discord announcements.

Two properties are the reason this file exists rather than incidental
coverage:

1. Nothing that could compromise a key ever reaches an outgoing payload.
   The channel is public and the validator holds key ciphertext during a
   round, so this is enforced by assertion -- see TestNothingSensitiveLeaks.
2. An announcement can never break a submission round. A dead, slow, or
   rate-limited webhook must end with the round carrying on -- see
   TestFailureIsolation.

No network: httpx is faked throughout.
"""

import asyncio
from dataclasses import dataclass
from typing import Optional

import pytest

from masxai import constants as C
from masxai import discord


@dataclass
class _Res:
    """Shaped like the protocol's per-slot submit result."""
    slot: int
    provider: str
    model: str
    accepted: bool
    reason: Optional[str] = None


HOTKEY = "5ChiMxeinVECib3nWkCA8rN1vtmSC55arHJ5PUxQmu38fVmz"
OK = _Res(0, "openai", "gpt-4o", True)
BAD = _Res(1, "deepseek", "deepseek-v4-flash-latest", False, "invalid_key")


class _FakeResponse:
    def __init__(self, status_code=204, text=""):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    posted = []

    def __init__(self, response=None, raises=False, **kwargs):
        self._response = response or _FakeResponse()
        self._raises = raises

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None):
        _FakeClient.posted.append({"url": url, "json": json})
        if self._raises:
            raise RuntimeError("connection reset")
        return self._response


def _install(monkeypatch, **kwargs):
    _FakeClient.posted = []
    monkeypatch.setattr(discord.httpx, "AsyncClient", lambda **kw: _FakeClient(**kwargs))
    return _FakeClient


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv(C.DISCORD_WEBHOOK_URL_ENV, "https://discord.test/webhook/abc")


# =====================================================================
# Message content
# =====================================================================

def test_shows_hotkey_outcome_and_models():
    msg = discord.format_submission_message(hotkey=HOTKEY, uid=12, results=[OK, BAD])
    assert "1/2 accepted" in msg
    assert "UID 12" in msg
    assert "openai/gpt-4o" in msg
    assert "deepseek/deepseek-v4-flash-latest" in msg


def test_rejections_are_announced_with_their_reason():
    # The point of the channel: a silent rejection leaves the miner guessing.
    msg = discord.format_submission_message(hotkey=HOTKEY, uid=1, results=[BAD])
    assert ":x:" in msg
    assert "invalid_key" in msg


def test_accepted_and_rejected_are_distinguishable():
    msg = discord.format_submission_message(hotkey=HOTKEY, uid=1, results=[OK, BAD])
    assert ":white_check_mark: slot 0" in msg
    assert ":x: slot 1" in msg


def test_slots_are_ordered():
    msg = discord.format_submission_message(
        hotkey=HOTKEY, uid=1, results=[_Res(2, "openai", "gpt-4o", True), OK],
    )
    assert msg.index("slot 0") < msg.index("slot 2")


def test_hotkey_is_shortened_but_identifiable():
    msg = discord.format_submission_message(hotkey=HOTKEY, uid=1, results=[OK])
    assert HOTKEY[:8] in msg
    assert HOTKEY[-4:] in msg
    assert HOTKEY not in msg  # not the full 48 chars


def test_missing_uid_is_handled():
    msg = discord.format_submission_message(hotkey=HOTKEY, uid=None, results=[OK])
    assert "UID" not in msg


def test_empty_results_produce_nothing():
    assert discord.format_submission_message(hotkey=HOTKEY, uid=1, results=[]) is None


def test_message_stays_within_discord_limit():
    many = [_Res(i, "openai", "gpt-4o" + "x" * 120, True) for i in range(40)]
    msg = discord.format_submission_message(hotkey=HOTKEY, uid=1, results=many)
    assert len(msg) <= 2000


# =====================================================================
# The channel is public
# =====================================================================

class TestNothingSensitiveLeaks:
    def test_no_forbidden_substring_reaches_the_payload(self, monkeypatch, configured):
        fake = _install(monkeypatch)
        asyncio.run(discord.publish_key_submission(hotkey=HOTKEY, uid=12, results=[OK, BAD]))
        body = str(fake.posted[0]["json"])
        for bad in discord._FORBIDDEN_SUBSTRINGS:
            assert bad not in body, f"{bad!r} leaked into a public Discord message"

    def test_payload_carries_only_content(self, monkeypatch, configured):
        fake = _install(monkeypatch)
        asyncio.run(discord.publish_key_submission(hotkey=HOTKEY, uid=12, results=[OK]))
        assert set(fake.posted[0]["json"]) == {"content"}

    def test_webhook_url_is_not_echoed_into_the_message(self, monkeypatch, configured):
        fake = _install(monkeypatch)
        asyncio.run(discord.publish_key_submission(hotkey=HOTKEY, uid=12, results=[OK]))
        assert "discord.test" not in fake.posted[0]["json"]["content"]


# =====================================================================
# Unconfigured is the kill switch
# =====================================================================

class TestUnconfigured:
    def test_unset_webhook_posts_nothing(self, monkeypatch):
        monkeypatch.delenv(C.DISCORD_WEBHOOK_URL_ENV, raising=False)
        fake = _install(monkeypatch)
        asyncio.run(discord.publish_key_submission(hotkey=HOTKEY, uid=12, results=[OK]))
        assert fake.posted == []

    def test_blank_webhook_posts_nothing(self, monkeypatch):
        monkeypatch.setenv(C.DISCORD_WEBHOOK_URL_ENV, "   ")
        fake = _install(monkeypatch)
        asyncio.run(discord.publish_key_submission(hotkey=HOTKEY, uid=12, results=[OK]))
        assert fake.posted == []


# =====================================================================
# A submission round must never fail because of an announcement
# =====================================================================

class TestFailureIsolation:
    def test_network_error_is_swallowed(self, monkeypatch, configured):
        _install(monkeypatch, raises=True)
        asyncio.run(discord.publish_key_submission(hotkey=HOTKEY, uid=12, results=[OK]))

    def test_rate_limit_is_swallowed(self, monkeypatch, configured):
        _install(monkeypatch, response=_FakeResponse(429, "rate limited"))
        asyncio.run(discord.publish_key_submission(hotkey=HOTKEY, uid=12, results=[OK]))

    def test_post_message_reports_failure_without_raising(self, monkeypatch, configured):
        _install(monkeypatch, response=_FakeResponse(500, "server error"))
        assert asyncio.run(discord.post_message("hello")) is False

    def test_post_message_reports_success(self, monkeypatch, configured):
        _install(monkeypatch, response=_FakeResponse(204))
        assert asyncio.run(discord.post_message("hello")) is True

    def test_malformed_results_are_swallowed(self, monkeypatch, configured):
        _install(monkeypatch)
        asyncio.run(discord.publish_key_submission(hotkey=HOTKEY, uid=12, results=[object()]))


# =====================================================================
# Round summary
#
# Posted whatever happened. The case that matters is a round where every
# relay failed: those produce no per-hotkey result, so without this the
# round is invisible from outside and looks identical to a quiet one.
# =====================================================================

def test_round_summary_shows_the_counts():
    msg = discord.format_round_summary(asked=13, answered=1, contributed=0)
    assert "asked 13" in msg
    assert "answered 1" in msg
    assert "contributed 0" in msg


def test_round_summary_names_the_hotkey_that_failed():
    # A relay failure belongs to one miner. A bare count tells that miner
    # nothing about whether it was theirs.
    msg = discord.format_round_summary(
        asked=13, answered=1, contributed=0,
        relay_failures=[(HOTKEY, 12, "422 at least 5 keys per submission")],
    )
    assert HOTKEY[:8] in msg
    assert "UID 12" in msg
    assert "at least 5 keys" in msg


def test_round_summary_lists_every_failed_hotkey():
    other = "5FnrdNsvFJRxGCabcdefghijklmnopqrstuvwxyz012345678"
    msg = discord.format_round_summary(
        asked=13, answered=2, contributed=0,
        relay_failures=[(HOTKEY, 12, "422"), (other, 7, "timeout")],
    )
    assert "2 submission(s) could not be relayed" in msg
    assert HOTKEY[:8] in msg
    assert other[:8] in msg


def test_round_summary_omits_the_warning_when_nothing_failed():
    msg = discord.format_round_summary(asked=13, answered=13, contributed=13)
    assert "could not be relayed" not in msg


def test_round_summary_handles_a_missing_uid():
    msg = discord.format_round_summary(
        asked=1, answered=1, contributed=0, relay_failures=[(HOTKEY, None, "boom")],
    )
    assert HOTKEY[:8] in msg


def test_round_summary_stays_within_discord_limit():
    many = [(HOTKEY, i, "x" * 300) for i in range(40)]
    msg = discord.format_round_summary(
        asked=40, answered=40, contributed=0, relay_failures=many,
    )
    assert len(msg) <= 2000


class TestRoundSummaryDelivery:
    def test_posts_when_configured(self, monkeypatch, configured):
        fake = _install(monkeypatch)
        asyncio.run(discord.publish_round_summary(asked=13, answered=1, contributed=0))
        assert len(fake.posted) == 1
        assert set(fake.posted[0]["json"]) == {"content"}

    def test_unconfigured_posts_nothing(self, monkeypatch):
        monkeypatch.delenv(C.DISCORD_WEBHOOK_URL_ENV, raising=False)
        fake = _install(monkeypatch)
        asyncio.run(discord.publish_round_summary(asked=13, answered=1, contributed=0))
        assert fake.posted == []

    def test_failure_is_swallowed(self, monkeypatch, configured):
        _install(monkeypatch, raises=True)
        asyncio.run(discord.publish_round_summary(asked=13, answered=1, contributed=0))


# =====================================================================
# Network tagging
#
# Several validators can share one channel -- a testnet rehearsal and a
# mainnet deployment most obviously. Without a tag they are
# indistinguishable, and a testnet failure reads as a production incident.
# =====================================================================

def test_round_summary_is_tagged_with_the_network():
    msg = discord.format_round_summary(
        asked=13, answered=1, contributed=0, netuid=501, network="test",
    )
    assert "test" in msg
    assert "netuid 501" in msg


def test_submission_message_is_tagged_with_the_network():
    msg = discord.format_submission_message(
        hotkey=HOTKEY, uid=12, results=[OK], netuid=104, network="finney",
    )
    assert "finney" in msg
    assert "netuid 104" in msg


def test_testnet_and_mainnet_messages_are_distinguishable():
    testnet = discord.format_round_summary(
        asked=1, answered=1, contributed=1, netuid=501, network="test",
    )
    mainnet = discord.format_round_summary(
        asked=1, answered=1, contributed=1, netuid=104, network="finney",
    )
    assert testnet != mainnet


def test_untagged_messages_still_work():
    # Callers that pass neither keep the old, untagged output.
    msg = discord.format_round_summary(asked=1, answered=1, contributed=1)
    assert msg.startswith("**Key round**")

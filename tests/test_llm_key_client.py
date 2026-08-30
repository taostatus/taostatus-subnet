"""tests/test_llm_key_client.py — HTTP-level behavior of LLMKeyClient.

Uses httpx.MockTransport (already a transitive dependency via
httpx>=0.27.0) rather than a real server -- constructs a real LLMKeyClient
then swaps its lazily-created httpx.AsyncClient for one backed by the mock
transport, bypassing _get_client()'s lazy init. Matches this repo's
existing asyncio.run(...)-in-sync-test convention (no pytest-asyncio
dependency present).
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from masxai import constants as C
from masxai.llm_key_client import LLMKeyClient, open_llm_key_client_from_env


async def _no_sleep(*_args, **_kwargs):
    return None


def _client_with_transport(handler, *, max_retries: int = 3) -> LLMKeyClient:
    client = LLMKeyClient(
        base_url="http://fake-protocol", validator_token="tok-123", max_retries=max_retries,
    )
    transport = httpx.MockTransport(handler)
    client._client = httpx.AsyncClient(base_url=client.base_url, transport=transport)
    return client


def test_submit_keys_sends_auth_header_and_batch_json_body():
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={
            "accepted": True, "status": "ACTIVE",
            "results": [{
                "slot": 0, "key_id": 7, "provider": "openai", "model": "gpt-4o-mini",
                "accepted": True, "status": "ACTIVE", "reason": None,
            }],
        })

    client = _client_with_transport(handler)
    keys = [{
        "slot": 0, "provider": "openai", "model": "gpt-4o-mini",
        "encrypted_key_blob": "Zm9v", "blob_encoding": "nacl-sealedbox-v1",
        "pubkey_id_used": "v1",
    }]
    result = asyncio.run(client.submit_keys(hotkey="hk1", uid=3, keys=keys))

    assert result.accepted is True
    assert result.results[0].key_id == 7
    assert result.results[0].slot == 0
    assert len(captured) == 1
    req = captured[0]
    assert req.method == "POST"
    assert req.url.path == "/llm-keys/submit"
    assert req.headers["X-Validator-Key"] == "tok-123"
    body = json.loads(req.content)
    assert body == {"hotkey": "hk1", "uid": 3, "keys": keys}


def test_get_reports_builds_since_query_param():
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"reports": [], "next_since": None})

    client = _client_with_transport(handler)
    asyncio.run(client.get_reports(since="2026-01-01T00:00:00Z"))
    asyncio.run(client.get_reports(since=None))

    assert captured[0].url.path == "/llm-keys/reports"
    assert "since=2026-01-01" in str(captured[0].url)
    assert "?" not in str(captured[1].url)


def test_get_key_statuses_calls_roster_endpoint():
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200, json={"entries": [{"hotkey": "hk1", "status": "DEAD", "reason": None}]}
        )

    client = _client_with_transport(handler)
    entries = asyncio.run(client.get_key_statuses())

    assert captured[0].method == "GET"
    assert captured[0].url.path == "/llm-keys/roster"
    assert len(entries) == 1
    assert entries[0].hotkey == "hk1"
    assert entries[0].status == "DEAD"


def test_request_retries_on_429_then_succeeds(monkeypatch):
    monkeypatch.setattr("masxai.llm_key_client.asyncio.sleep", _no_sleep)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"reports": [], "next_since": None})

    client = _client_with_transport(handler, max_retries=5)
    reports, _ = asyncio.run(client.get_reports())

    assert calls["n"] == 3
    assert reports == []


def test_request_retries_on_5xx_then_succeeds(monkeypatch):
    monkeypatch.setattr("masxai.llm_key_client.asyncio.sleep", _no_sleep)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"reports": [], "next_since": None})

    client = _client_with_transport(handler, max_retries=5)
    reports, _ = asyncio.run(client.get_reports())

    assert calls["n"] == 2
    assert reports == []


def test_request_raises_after_exhausting_retries_on_persistent_5xx(monkeypatch):
    monkeypatch.setattr("masxai.llm_key_client.asyncio.sleep", _no_sleep)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = _client_with_transport(handler, max_retries=3)
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(client.get_reports())


def test_request_honors_retry_after_header_capped_at_ceiling(monkeypatch):
    sleeps: list[float] = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr("masxai.llm_key_client.asyncio.sleep", fake_sleep)
    monkeypatch.setenv(C.LLM_KEY_RETRY_AFTER_MAX_SECONDS_ENV, "5")
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "9999"})
        return httpx.Response(200, json={"reports": [], "next_since": None})

    client = _client_with_transport(handler, max_retries=3)
    asyncio.run(client.get_reports())

    assert sleeps == [5.0]


def test_request_retries_on_network_error_then_succeeds(monkeypatch):
    monkeypatch.setattr("masxai.llm_key_client.asyncio.sleep", _no_sleep)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 2:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(200, json={"reports": [], "next_since": None})

    client = _client_with_transport(handler, max_retries=3)
    reports, _ = asyncio.run(client.get_reports())

    assert calls["n"] == 2
    assert reports == []


def test_request_raises_after_exhausting_retries_on_persistent_network_error(monkeypatch):
    monkeypatch.setattr("masxai.llm_key_client.asyncio.sleep", _no_sleep)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    client = _client_with_transport(handler, max_retries=2)
    with pytest.raises(httpx.RequestError):
        asyncio.run(client.get_reports())


def test_open_llm_key_client_from_env_returns_none_when_token_unset(monkeypatch):
    monkeypatch.delenv(C.LLM_KEY_VALIDATOR_TOKEN_ENV, raising=False)
    monkeypatch.setenv(C.LLM_KEY_BASE_URL_ENV, "http://fake-protocol")
    assert open_llm_key_client_from_env() is None


def test_open_llm_key_client_from_env_returns_none_when_base_url_unset(monkeypatch):
    monkeypatch.setenv(C.LLM_KEY_VALIDATOR_TOKEN_ENV, "tok")
    monkeypatch.delenv(C.LLM_KEY_BASE_URL_ENV, raising=False)
    assert open_llm_key_client_from_env() is None


def test_open_llm_key_client_from_env_returns_client_when_configured(monkeypatch):
    monkeypatch.setenv(C.LLM_KEY_VALIDATOR_TOKEN_ENV, "tok")
    monkeypatch.setenv(C.LLM_KEY_BASE_URL_ENV, "http://fake-protocol")
    client = open_llm_key_client_from_env()
    assert client is not None
    assert client.validator_token == "tok"
    assert client.base_url == "http://fake-protocol"


def test_auth_headers_include_validator_token():
    client = LLMKeyClient(base_url="http://fake-protocol", validator_token="tok-123")
    assert client._auth_headers() == {"X-Validator-Key": "tok-123"}

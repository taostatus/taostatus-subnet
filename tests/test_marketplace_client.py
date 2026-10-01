"""masxai/marketplace_client.py: the record the validator publishes, the gate
that decides who is published, and a client that never raises.

The property that matters most is negative: nothing in a record lets a peer
fetch or reverse an agent. It is asserted here against the payload builder and
against the client (which refuses such a payload before any HTTP happens).
"""

import asyncio
import json
import types

import httpx
import pytest

import masxai.marketplace_client as mc
from masxai import constants as C


def _job(score=1.0, *, name="ref-agent", version="1.0", safe=True):
    return types.SimpleNamespace(
        run_id="r1", category="sqli", variant="boolean_numeric", safe=safe,
        accepted=True, request_count=57, duration_ms=9000,
        agent_name=name, agent_version=version,
        task=types.SimpleNamespace(score=score),
    )


def _payload(**overrides):
    kwargs = dict(
        agent_id="a" * 64, miner_hotkey="5Fminer", miner_uid=7, netuid=501, mechid=1,
        validator_hotkey="5Dvali", overall_score=1.0, category_scores={"sqli": 1.0},
        job=_job(), evaluated_at=1_700_000_000.0,
    )
    kwargs.update(overrides)
    return mc.build_agent_payload(**kwargs)


# --- the record --------------------------------------------------------

def test_payload_carries_metadata_and_scores():
    p = _payload()
    assert p["agent_id"] == "a" * 64
    assert (p["miner_hotkey"], p["miner_uid"], p["netuid"], p["mechid"]) == ("5Fminer", 7, 501, 1)
    assert p["validator_hotkey"] == "5Dvali"
    assert p["overall_score"] == 1.0 and p["category_scores"] == {"sqli": 1.0}
    run = p["run"]
    assert run["category"] == "sqli" and run["variant"] == "boolean_numeric"
    assert run["score"] == 1.0 and run["safe"] is True and run["accepted"] is True
    assert run["requests"] == 57 and run["duration_ms"] == 9000
    assert run["evaluated_at"].startswith("2023-11-14T22:13:20")


def test_payload_has_no_forbidden_keys_anywhere():
    flat = json.dumps(_payload()).lower()
    for fragment in mc.FORBIDDEN_KEY_FRAGMENTS:
        assert f'"{fragment}' not in flat, fragment
    mc.assert_publishable(_payload())  # does not raise


def test_assert_publishable_rejects_fetchable_fields_even_when_nested():
    with pytest.raises(ValueError, match="blob_url"):
        mc.assert_publishable({"agent_id": "x", "blob_url": "http://m/agent.enc"})
    with pytest.raises(ValueError, match="image_ref"):
        mc.assert_publishable({"run": {"image_ref": "ghcr.io/x"}})
    with pytest.raises(ValueError):
        mc.assert_publishable({"runs": [{"log_excerpt": "..."}]})


def test_miner_controlled_display_text_is_sanitized():
    p = _payload(job=_job(name="\x1b[2J\x07evil" + "x" * 200, version="\x00v1\n"))
    assert "\x1b" not in p["name"] and "\x07" not in p["name"]
    assert p["name"].startswith("[2Jevil") and len(p["name"]) <= 64
    assert p["version"] == "v1"


def test_payload_tolerates_a_run_with_no_task():
    job = _job()
    job.task = None
    assert _payload(job=job, overall_score=0.0)["run"]["score"] == 0.0


# --- the gate ----------------------------------------------------------

def test_gate_is_the_aggregate_at_the_entry_score():
    assert mc.should_publish(aggregate=1.0, agent_id="a", listed=set()) is True
    assert mc.should_publish(aggregate=0.5, agent_id="a", listed=set()) is False


def test_gate_tolerates_the_ema_asymptote():
    # an EMA never lands exactly on 1.0 after an imperfect run; 0.9995 counts
    assert mc.should_publish(aggregate=0.9995, agent_id="a", listed=set()) is True
    assert mc.should_publish(aggregate=0.998, agent_id="a", listed=set()) is False
    assert mc.should_publish(aggregate=0.998, agent_id="a", listed=set(), tolerance=0.01) is True


def test_listed_agent_passes_the_gate_at_any_score():
    assert mc.should_publish(aggregate=0.0, agent_id="a", listed={"a"}) is True


def test_unidentified_agent_is_never_published():
    assert mc.should_publish(aggregate=1.0, agent_id=None, listed=set()) is False
    assert mc.should_publish(aggregate=1.0, agent_id="", listed=set()) is False


# --- the client --------------------------------------------------------

@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    async def instant(*_a, **_k):
        return None
    monkeypatch.setattr(mc, "_backoff", instant)


def _client(handler, retries=3):
    return mc.MarketplaceClient(
        base_url="http://backend.test", token="s3cret", max_retries=retries,
        transport=httpx.MockTransport(handler),
    )


def test_push_sends_bearer_json_to_the_internal_endpoint():
    seen = {}

    def handler(request):
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("Authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True})

    assert asyncio.run(_client(handler).push_agent(_payload())) is True
    assert seen["method"] == "POST" and seen["path"] == C.MARKETPLACE_AGENTS_PATH
    assert seen["auth"] == "Bearer s3cret"
    assert seen["body"]["agent_id"] == "a" * 64


def test_push_retries_5xx_then_succeeds():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(503) if len(calls) < 3 else httpx.Response(201)

    assert asyncio.run(_client(handler).push_agent(_payload())) is True
    assert len(calls) == 3


def test_push_gives_up_after_retries_without_raising():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(500, text="db locked")

    assert asyncio.run(_client(handler).push_agent(_payload())) is False
    assert len(calls) == 3


def test_push_does_not_retry_a_4xx():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(422, json={"detail": "schema"})

    assert asyncio.run(_client(handler).push_agent(_payload())) is False
    assert len(calls) == 1


def test_push_swallows_network_errors():
    def handler(request):
        raise httpx.ConnectError("refused")

    assert asyncio.run(_client(handler).push_agent(_payload())) is False


def test_push_refuses_a_fetchable_payload_before_any_http():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200)

    bad = _payload()
    bad["blob_url"] = "http://miner/agent.enc"
    assert asyncio.run(_client(handler).push_agent(bad)) is False
    assert calls == []


def test_client_requires_url_and_token():
    with pytest.raises(ValueError):
        mc.MarketplaceClient(base_url="", token="t")
    with pytest.raises(ValueError):
        mc.MarketplaceClient(base_url="http://x", token="")


def test_env_factory_is_the_kill_switch(monkeypatch):
    monkeypatch.setattr(mc, "load_env", lambda: None)
    monkeypatch.delenv(C.MARKETPLACE_BASE_URL_ENV, raising=False)
    monkeypatch.delenv(C.MARKETPLACE_TOKEN_ENV, raising=False)
    assert mc.open_marketplace_client_from_env() is None
    monkeypatch.setenv(C.MARKETPLACE_BASE_URL_ENV, "http://backend.test/")
    assert mc.open_marketplace_client_from_env() is None          # token still missing
    monkeypatch.setenv(C.MARKETPLACE_TOKEN_ENV, "tok")
    client = mc.open_marketplace_client_from_env()
    assert client is not None and client.base_url == "http://backend.test"


# --- the listed-agents memory --------------------------------------------

def test_listed_roundtrip_and_missing_file(tmp_path):
    path = tmp_path / "listed.json"
    assert mc.load_listed(str(path)) == set()
    mc.save_listed(str(path), {"b", "a", "a"})
    assert mc.load_listed(str(path)) == {"a", "b"}
    path.write_text("not json")
    assert mc.load_listed(str(path)) == set()

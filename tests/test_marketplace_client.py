"""Tests for the validator -> marketplace handoff client. Stdlib only; the HTTP
transport is injected so no server is needed."""

import json

from masxai import marketplace_client as mc


def test_build_agent_payload_shape():
    p = mc.build_agent_payload(
        miner_hotkey="5Chi", uid=12, overall_score=1.0,
        categories={"sqli": 1.0}, status="active", netuid=501, mechid=1,
    )
    assert p == {
        "agent_digest": "5Chi",          # id is the hotkey for now
        "miner_hotkey": "5Chi",
        "uid": 12,
        "netuid": 501,
        "mechid": 1,
        "overall_score": 1.0,
        "status": "active",
        "categories": {"sqli": 1.0},
    }
    assert "run" not in p                 # omitted when not evaluated this round


def test_build_agent_payload_includes_run_when_given():
    run = {"category": "sqli", "variant": "union", "task_score": 1.0, "safe": True, "requests": 90}
    p = mc.build_agent_payload(
        miner_hotkey="5Chi", uid=12, overall_score=1.0,
        categories={"sqli": 1.0}, run=run,
    )
    assert p["run"] == run


def test_publish_agent_success_and_body():
    seen = {}
    def transport(url, headers, body, timeout):
        seen["url"] = url
        seen["headers"] = headers
        seen["body"] = json.loads(body)
        return 200
    client = mc.MarketplaceClient("http://host:8099/", "tok", transport=transport)
    ok = client.publish_agent({"agent_digest": "d", "miner_hotkey": "m"})
    assert ok is True
    assert seen["url"] == "http://host:8099/api/internal/agents"
    assert seen["headers"]["Authorization"] == "Bearer tok"
    assert seen["body"]["agent_digest"] == "d"


def test_publish_agent_non_2xx_is_false():
    client = mc.MarketplaceClient("http://h", "t", transport=lambda *a: 500)
    assert client.publish_agent({"x": 1}) is False


def test_publish_agent_transport_error_is_false_not_raised():
    def boom(*_a):
        raise OSError("connection refused")
    client = mc.MarketplaceClient("http://h", "t", transport=boom)
    assert client.publish_agent({"x": 1}) is False   # swallowed


def test_open_from_env_none_when_unconfigured(monkeypatch):
    monkeypatch.delenv("MASXAI_MARKETPLACE_URL", raising=False)
    monkeypatch.delenv("MASXAI_MARKETPLACE_TOKEN", raising=False)
    assert mc.open_marketplace_client_from_env() is None


def test_open_from_env_builds_client(monkeypatch):
    monkeypatch.setenv("MASXAI_MARKETPLACE_URL", "http://host:8099")
    monkeypatch.setenv("MASXAI_MARKETPLACE_TOKEN", "secret")
    client = mc.open_marketplace_client_from_env()
    assert client is not None
    assert client.base_url == "http://host:8099"
    assert client.token == "secret"

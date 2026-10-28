"""Tests for the validator's audit backend client (masxai/audit_client).
Transport is injected, so no real HTTP; best-effort contract is asserted."""

import json

from masxai import constants as C
from masxai.audit_client import AuditBackendClient, open_audit_client_from_env


def _client(responder, recorder=None):
    def transport(method, url, headers, body, timeout):
        if recorder is not None:
            recorder.append({"method": method, "url": url, "headers": headers, "body": body})
        return responder(method, url, headers, body)
    return AuditBackendClient("http://backend.test/", "s3cret", transport=transport)


def test_claim_returns_job():
    job = {"run_id": "r1", "agent_id": "5A", "target_url": "https://x"}
    c = _client(lambda *a: (200, json.dumps({"job": job}).encode()))
    assert c.claim_next_job("5Vali") == job


def test_claim_empty_queue_is_none():
    c = _client(lambda *a: (200, b'{"job": null}'))
    assert c.claim_next_job() is None


def test_claim_non_2xx_is_none():
    c = _client(lambda *a: (503, b"busy"))
    assert c.claim_next_job() is None


def test_claim_transport_error_is_none():
    def boom(*a): raise ConnectionError("refused")
    c = _client(boom)
    assert c.claim_next_job() is None            # best-effort: never raises


def test_claim_sends_bearer_and_validator():
    rec = []
    c = _client(lambda *a: (200, b'{"job": null}'), recorder=rec)
    c.claim_next_job("5ValiHotkey")
    assert rec[0]["method"] == "GET"
    assert rec[0]["headers"]["Authorization"] == "Bearer s3cret"
    assert "validator=5ValiHotkey" in rec[0]["url"]
    assert rec[0]["url"].endswith("/api/internal/next-job?validator=5ValiHotkey")


def test_post_result_ok_and_shape():
    rec = []
    c = _client(lambda *a: (200, b'{"ok":true}'), recorder=rec)
    assert c.post_result("r1", {"status": "completed", "score": 1.0}) is True
    assert rec[0]["method"] == "POST"
    assert rec[0]["url"].endswith("/api/internal/runs/r1/result")
    assert rec[0]["headers"]["Authorization"] == "Bearer s3cret"
    assert json.loads(rec[0]["body"])["score"] == 1.0


def test_post_result_non_2xx_is_false():
    c = _client(lambda *a: (404, b"no run"))
    assert c.post_result("missing", {"status": "failed"}) is False


def test_post_result_transport_error_is_false():
    def boom(*a): raise TimeoutError()
    c = _client(boom)
    assert c.post_result("r1", {"status": "completed"}) is False


def test_env_factory_is_kill_switch(monkeypatch):
    monkeypatch.delenv(C.MARKETPLACE_URL_ENV, raising=False)
    monkeypatch.delenv(C.MARKETPLACE_TOKEN_ENV, raising=False)
    assert open_audit_client_from_env() is None
    monkeypatch.setenv(C.MARKETPLACE_URL_ENV, "http://backend.test/")
    assert open_audit_client_from_env() is None          # token still missing
    monkeypatch.setenv(C.MARKETPLACE_TOKEN_ENV, "tok")
    client = open_audit_client_from_env()
    assert client is not None and client.base_url == "http://backend.test"

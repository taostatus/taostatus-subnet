"""Precise tests for boolean-differential replay confirmation
(secqurityVali/replay_confirm). `send` is injected, so every case is
deterministic and no real HTTP happens."""

from urllib.parse import parse_qsl, urlsplit

from secqurityVali.replay_confirm import confirm_findings


def _value_of(path, body, param):
    params = dict(parse_qsl(urlsplit(path).query))
    params.update(dict(parse_qsl(body or "")))
    return params.get(param, "")


def vulnerable(param="id"):
    """A target where `param` really is injectable: a false boolean returns no
    rows, true/base return the row."""
    def send(method, path, body):
        v = _value_of(path, body, param)
        if v.endswith("'1'='2"):          # the FALSE payload
            return (200, "no results")
        return (200, "RESULT id=1 name=alice")
    return send


def static(method, path, body):
    """A non-injectable endpoint: identical response no matter the payload."""
    return (200, "STATIC PAGE")


def test_injectable_parameter_is_confirmed():
    confirmed, fp = confirm_findings([{"parameter": "id", "endpoint": "/item?id=1"}],
                                     send=vulnerable())
    assert confirmed is True and fp == 0


def test_non_injectable_is_a_false_positive():
    confirmed, fp = confirm_findings([{"parameter": "id", "endpoint": "/item?id=1"}],
                                     send=static)
    assert confirmed is False and fp == 1


def test_mixed_findings():
    # vulnerable only for "id"; a claim on "q" does not reproduce
    def send(method, path, body):
        if _value_of(path, body, "id").endswith("'1'='2"):
            return (200, "no results")
        if "id=" in path:
            return (200, "RESULT")
        return (200, "STATIC")        # "q" endpoint never differentiates
    findings = [{"parameter": "id", "endpoint": "/a?id=1"},
                {"parameter": "q", "endpoint": "/b?q=1"}]
    confirmed, fp = confirm_findings(findings, send=send)
    assert confirmed is True and fp == 1


def test_replay_never_leaves_the_pinned_target():
    """A finding naming another host must not make replay dial it: only the PATH
    is used, the host is dropped."""
    seen = []
    def send(method, path, body):
        seen.append(path)
        v = _value_of(path, body, "id")
        return (200, "no results") if v.endswith("'1'='2") else (200, "RESULT")
    confirm_findings([{"parameter": "id", "endpoint": "http://evil.example/search?id=1"}],
                     send=send)
    assert seen and all("evil.example" not in p for p in seen)
    assert all(p.startswith("/search") for p in seen)


def test_body_parameter_injection():
    confirmed, fp = confirm_findings(
        [{"parameter": "id", "endpoint": "/login", "method": "POST", "location": "body"}],
        send=vulnerable())
    assert confirmed is True and fp == 0


def test_network_error_is_not_confirmed():
    def boom(method, path, body):
        raise ConnectionError("refused")
    confirmed, fp = confirm_findings([{"parameter": "id", "endpoint": "/x?id=1"}], send=boom)
    assert confirmed is False and fp == 1


def test_noisy_target_is_not_confirmed():
    """A target that returns something different every call gives no stable
    differential -> not confirmed (the repeat guards against flukes)."""
    counter = {"n": 0}
    def send(method, path, body):
        counter["n"] += 1
        return (200, f"random-{counter['n']}")
    confirmed, _ = confirm_findings([{"parameter": "id", "endpoint": "/x?id=1"}], send=send)
    assert confirmed is False


def test_finding_without_parameter_is_ignored():
    confirmed, fp = confirm_findings([{"endpoint": "/x"}], send=static)
    assert confirmed is False and fp == 0      # not a candidate at all


def test_canary_reproduction_confirms_union_finding():
    """When the finding carries a canary + payload, replaying the agent's own
    payload must re-extract the canary -> confirmed (the strongest signal)."""
    def send(method, path, body):
        v = _value_of(path, body, "name")
        return (200, "row: value_x CANARY123 end") if "UNION" in v.upper() else (200, "empty")
    f = {"parameter": "name", "endpoint": "/api/users?name=1",
         "payload": "0 UNION SELECT 1, 2, 3-- -", "evidence": {"canary": "CANARY123"}}
    confirmed, fp = confirm_findings([f], send=send)
    assert confirmed is True and fp == 0


def test_canary_claimed_but_not_reproduced_is_false_positive():
    # canary claimed, but replay does not surface it, and no boolean differential
    def send(method, path, body):
        return (200, "STATIC")
    f = {"parameter": "name", "endpoint": "/x?name=1",
         "payload": "0 UNION SELECT 1-- -", "evidence": {"canary": "NOPE"}}
    confirmed, fp = confirm_findings([f], send=send)
    assert confirmed is False and fp == 1


def test_empty_findings():
    assert confirm_findings([], send=static) == (False, 0)
    assert confirm_findings(None, send=static) == (False, 0)

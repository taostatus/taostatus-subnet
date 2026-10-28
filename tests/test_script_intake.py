"""Tests for the Python-script submission intake (secqurityVali/script_intake.py)."""
import hashlib

from secqurityVali import constants as C
from secqurityVali.script_intake import validate_agent_script

_GOOD = b"def agent_main(ctx):\n    return []\n"


def test_accepts_wellformed_agent():
    v = validate_agent_script(_GOOD)
    assert v.accepted and v.reason == "ok" and v.stage_reached == "accepted"
    assert v.agent_id == hashlib.sha256(_GOOD).hexdigest()


def test_agent_id_is_content_hash_and_stable():
    a = validate_agent_script(_GOOD).agent_id
    b = validate_agent_script(_GOOD).agent_id
    assert a == b == hashlib.sha256(_GOOD).hexdigest()
    # a one-byte change -> a different identity (dedupe/upsert works)
    assert validate_agent_script(_GOOD + b"\n").agent_id != a


def test_accepts_async_and_alias_entrypoints():
    assert validate_agent_script(b"async def agent_main(ctx):\n    return []\n").accepted
    assert validate_agent_script(
        b"def _solve(c):\n    return []\nagent_main = _solve\n").accepted
    assert validate_agent_script(b"def agent_main(*a):\n    return []\n").accepted


def test_rejects_empty():
    v = validate_agent_script(b"")
    assert not v.accepted and v.reason == "empty"


def test_rejects_oversize():
    big = b"# pad\n" + b"x = 1\n" * (C.MAX_AGENT_SCRIPT_BYTES // 6 + 10)
    v = validate_agent_script(big)
    assert not v.accepted and v.reason == "too_large" and v.stage_reached == "size"


def test_rejects_non_utf8():
    v = validate_agent_script(b"\xff\xfe\x00bad")
    assert not v.accepted and v.reason == "not_utf8"


def test_rejects_syntax_error():
    v = validate_agent_script(b"def agent_main(ctx):\n    return [[[\n")
    assert not v.accepted and v.reason == "syntax_error"


def test_rejects_missing_entrypoint():
    v = validate_agent_script(b"def something_else(ctx):\n    return []\n")
    assert not v.accepted and v.reason == "no_agent_main"


def test_rejects_entrypoint_with_no_context_param():
    # agent_main() with no parameters cannot receive ctx -> not gradeable
    v = validate_agent_script(b"def agent_main():\n    return []\n")
    assert not v.accepted and v.reason == "no_agent_main"


def test_parse_only_never_executes():
    # a module whose top-level would raise/exfil IF executed must still be
    # judged purely on form -- intake parses, never runs it.
    hostile = b"import os\nos.environ['PWNED']='1'\ndef agent_main(ctx):\n    return []\n"
    v = validate_agent_script(hostile)
    assert v.accepted  # well-formed; its behaviour is the sandbox's job, not intake's
    import os
    assert os.environ.get("PWNED") is None  # proof: intake did not execute it

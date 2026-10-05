"""Tests for secqurityVali/repo_target.py -- the UNTRUSTED repo -> isolated
target pipeline. The real docker/git calls are integration-tested on the
isolation host; here we pin the security-critical PURE logic: URL validation,
env sanitising, path-traversal guards, the compose rejection, size guards, and
that teardown is total and idempotent.
"""

import os

import pytest

from secqurityVali import constants as C
from secqurityVali import repo_target as rt


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --- url validation -----------------------------------------------------

def test_url_accepts_https_public_host():
    out = rt.validate_repo_url("https://github.com/me/app.git",
                               resolve=lambda h: ["140.82.112.3"])
    assert out == "https://github.com/me/app.git"


def test_url_accepts_ssh_forms():
    assert rt.validate_repo_url("git@github.com:me/app.git").startswith("git@")
    assert rt.validate_repo_url("ssh://git@github.com/me/app.git").startswith("ssh://")


def test_url_rejects_file_and_git_schemes():
    for bad in ("file:///etc/passwd", "git://localhost/x", "ftp://h/x"):
        with pytest.raises(rt.RepoError):
            rt.validate_repo_url(bad, resolve=lambda h: ["8.8.8.8"])


def test_url_rejects_private_and_metadata_hosts():
    for ip in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1"):
        with pytest.raises(rt.RepoError):
            rt.validate_repo_url("https://evil.example/x", resolve=lambda h, _ip=ip: [_ip])


def test_url_rejects_empty_control_chars_and_overlong():
    with pytest.raises(rt.RepoError):
        rt.validate_repo_url("   ")
    with pytest.raises(rt.RepoError):
        rt.validate_repo_url("https://h/a\x01b", resolve=lambda h: ["8.8.8.8"])
    with pytest.raises(rt.RepoError):
        rt.validate_repo_url("https://h/" + "a" * 3000, resolve=lambda h: ["8.8.8.8"])


# --- env sanitising -----------------------------------------------------

def test_env_args_valid():
    assert rt._env_args({"APP_PORT": "8000", "DEBUG": "1"}) == [
        "-e", "APP_PORT=8000", "-e", "DEBUG=1",
    ]


def test_env_args_none_and_empty():
    assert rt._env_args(None) == []
    assert rt._env_args({}) == []


def test_env_args_rejects_reserved_prefixes_and_bad_names():
    for bad in ({"MASXAI_X": "1"}, {"DOCKER_HOST": "x"}, {"TARGET_IP": "1"}):
        with pytest.raises(rt.RepoError):
            rt._env_args(bad)
    with pytest.raises(rt.RepoError):
        rt._env_args({"bad-name": "1"})
    with pytest.raises(rt.RepoError):
        rt._env_args({"1LEADING": "1"})


def test_env_args_rejects_too_many_and_oversized():
    with pytest.raises(rt.RepoError):
        rt._env_args({f"K{i}": "1" for i in range(rt._MAX_ENV_VARS + 1)})
    with pytest.raises(rt.RepoError):
        rt._env_args({"K": "x" * (rt._MAX_ENV_VALUE_LEN + 1)})


# --- auth url injection (token never leaks on the normal path) -----------

def test_authed_url_injects_https_token_and_reports_secret():
    url, secret = rt._authed_url("https://github.com/me/app.git", "TOK123")
    assert url == "https://x-access-token:TOK123@github.com/me/app.git"
    assert secret == "TOK123"


def test_authed_url_leaves_ssh_and_tokenless_alone():
    assert rt._authed_url("git@github.com:me/app.git", "TOK")[0].startswith("git@")
    assert rt._authed_url("https://h/x", None) == ("https://h/x", "")


def test_redact_removes_secret():
    assert rt._redact("fatal: https://x-access-token:TOK@h failed", "TOK") == \
        "fatal: https://x-access-token:***@h failed"


# --- path-traversal guard on the build context --------------------------

def test_resolve_context_default_is_clone_dir(tmp_path):
    assert rt._resolve_context(str(tmp_path), None) == os.path.realpath(str(tmp_path))


def test_resolve_context_allows_real_subdir(tmp_path):
    (tmp_path / "backend").mkdir()
    out = rt._resolve_context(str(tmp_path), "backend")
    assert out.endswith("backend")


def test_resolve_context_rejects_escape(tmp_path):
    for bad in ("..", "../x", "/etc"):
        with pytest.raises(rt.RepoError):
            rt._resolve_context(str(tmp_path), bad)


def test_resolve_context_missing_subdir(tmp_path):
    with pytest.raises(rt.RepoError):
        rt._resolve_context(str(tmp_path), "nope")


# --- size guard ---------------------------------------------------------

def test_dir_size_exceeds(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"x" * 1000)
    assert rt._dir_size_exceeds(str(tmp_path), 500) is True
    assert rt._dir_size_exceeds(str(tmp_path), 5000) is False


def test_dir_size_ignores_symlinks(tmp_path):
    (tmp_path / "real").write_bytes(b"x" * 100)
    try:
        os.symlink("/etc/passwd", str(tmp_path / "link"))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert rt._dir_size_exceeds(str(tmp_path), 50) is True    # from real only
    assert rt._dir_size_exceeds(str(tmp_path), 1000) is False  # link not counted


# --- build: compose rejection + missing dockerfile ----------------------

def test_build_rejects_compose_only_repo(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}")
    with pytest.raises(rt.RepoError) as e:
        rt.build_image(str(tmp_path), "t:1")
    assert "compose" in str(e.value).lower()


def test_build_rejects_missing_dockerfile(tmp_path):
    with pytest.raises(rt.RepoError) as e:
        rt.build_image(str(tmp_path), "t:1")
    assert "dockerfile" in str(e.value).lower()


# --- detect_port --------------------------------------------------------

def test_detect_port_declared_wins(monkeypatch):
    assert rt.detect_port("t:1", 9000) == 9000


def test_detect_port_rejects_out_of_range():
    with pytest.raises(rt.RepoError):
        rt.detect_port("t:1", 70000)


def test_detect_port_reads_first_tcp_expose(monkeypatch):
    monkeypatch.setattr(rt.job, "_run",
                        lambda *a, **k: _Proc(0, '{"5000/tcp":{},"80/tcp":{}}'))
    assert rt.detect_port("t:1", None) == 80       # lowest tcp port


def test_detect_port_default_when_none(monkeypatch):
    monkeypatch.setattr(rt.job, "_run", lambda *a, **k: _Proc(0, "null"))
    assert rt.detect_port("t:1", None) == C.REPO_DEFAULT_PORT


# --- teardown is total + idempotent -------------------------------------

def test_teardown_removes_everything_idempotently(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(rt.job, "_run", lambda args, **k: calls.append(tuple(args[:2])) or _Proc(0))
    monkeypatch.setattr(rt.job, "_rm_container", lambda n: calls.append(("rm", n)))
    monkeypatch.setattr(rt.job, "_network_remove", lambda n: calls.append(("netrm", n)))
    clone = tmp_path / "clone"
    clone.mkdir()
    t = rt.RepoTarget(network="net1", name="tgt1", ip="1.2.3.4", port=8000,
                      image_tag="img:1", clone_dir=str(clone))
    t.teardown()
    t.teardown()   # idempotent -- must not raise
    assert ("rm", "tgt1") in calls
    assert ("netrm", "net1") in calls
    assert any(c[0] == "image" for c in calls)      # image rm attempted
    assert not clone.exists()                        # clone dir gone


# --- provision: happy path + failure tears down -------------------------

def _patch_provision_steps(monkeypatch, *, healthy=True):
    monkeypatch.setattr(rt, "clone_repo", lambda *a, **k: None)
    monkeypatch.setattr(rt, "_dir_size_exceeds", lambda *a, **k: False)
    monkeypatch.setattr(rt, "_resolve_context", lambda clone, sub: clone)
    monkeypatch.setattr(rt, "build_image", lambda *a, **k: None)
    monkeypatch.setattr(rt, "detect_port", lambda tag, port: port or 8000)
    monkeypatch.setattr(rt, "run_target", lambda *a, **k: "cid123")
    monkeypatch.setattr(rt, "wait_healthy", lambda *a, **k: healthy)
    monkeypatch.setattr(rt.job, "_network_create", lambda n: None)
    monkeypatch.setattr(rt.job, "_container_ip", lambda n, net: "172.30.0.2")
    monkeypatch.setattr(rt, "validate_repo_url", lambda u, **k: u)


def test_provision_happy_path(monkeypatch):
    _patch_provision_steps(monkeypatch, healthy=True)
    t = rt.provision_repo_target("https://github.com/me/app.git")
    try:
        assert t.ip == "172.30.0.2" and t.port == 8000
        assert t.network and t.name and t.image_tag
    finally:
        monkeypatch.setattr(rt.job, "_rm_container", lambda n: None)
        monkeypatch.setattr(rt.job, "_network_remove", lambda n: None)
        monkeypatch.setattr(rt.job, "_run", lambda *a, **k: _Proc(0))


def test_provision_unhealthy_tears_down_and_raises(monkeypatch):
    torn = {"n": 0}
    _patch_provision_steps(monkeypatch, healthy=False)
    monkeypatch.setattr(rt.RepoTarget, "teardown", lambda self: torn.__setitem__("n", torn["n"] + 1))
    with pytest.raises(rt.RepoError) as e:
        rt.provision_repo_target("https://github.com/me/app.git")
    assert "listening" in str(e.value)
    assert torn["n"] >= 1          # torn down on failure


def test_provision_build_failure_tears_down(monkeypatch):
    torn = {"n": 0}
    _patch_provision_steps(monkeypatch)
    monkeypatch.setattr(rt, "build_image",
                        lambda *a, **k: (_ for _ in ()).throw(rt.RepoError("build failed: boom")))
    monkeypatch.setattr(rt.RepoTarget, "teardown", lambda self: torn.__setitem__("n", torn["n"] + 1))
    with pytest.raises(rt.RepoError) as e:
        rt.provision_repo_target("https://github.com/me/app.git")
    assert "build failed" in str(e.value) and torn["n"] >= 1

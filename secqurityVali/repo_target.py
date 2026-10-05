from __future__ import annotations

"""secqurityVali/repo_target.py - turn an UNTRUSTED customer git repo into a
running audit target, safely.

The customer may hand us a live URL (handled by audit_runner.run_audit via the
egress proxy) OR a git repo. A repo is source code we must build and run
ourselves, which means executing untrusted code twice: at `docker build` time and
at run time. This module contains that blast radius:

    validate the git URL (no file://, no git://, host must be public -> no clone
      SSRF into our own network)
    clone shallow, no history, no submodules, no prompts, size-capped
    build the single Dockerfile resource-capped and time-capped, image size-capped
    run the built image as the target on an --internal (ZERO-egress) network,
      under gVisor, caps dropped, pids/mem/cpu limited -- so even a malicious
      repo cannot phone home, escape, or exhaust the host
    health-probe it from a throwaway container on the same network
    hand back a RepoTarget the agent can reach BY IP on that network

Nothing is published to the host. Everything (clone dir, image, container,
network, probe) is destroyed by RepoTarget.teardown(), including on any failure
part-way through. Confirmation of findings happens on the same internal network
(repo_confirmer.py), never from the host, which has no route to the target.

Scope: a single Dockerfile web service. docker-compose (multi-service) is a
deliberate follow-up -- a compose repo is rejected with a clear message rather
than half-run.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from secqurityVali import constants as C
from secqurityVali import job
from secqurityVali import target_guard

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIRMER_SCRIPT = os.path.join(THIS_DIR, "repo_confirmer.py")
REPLAY_SCRIPT = os.path.join(THIS_DIR, "replay_confirm.py")

# A conservative env-var name shape. We refuse to forward anything that looks
# like it could collide with our own harness configuration.
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RESERVED_ENV_PREFIXES = ("MASXAI_", "RUNSC", "PROXY_", "TARGET_", "DOCKER_", "GIT_")
_MAX_ENV_VARS = 50
_MAX_ENV_VALUE_LEN = 4096
_MAX_URL_LEN = 2048
# "git@host:path" (scp-like ssh form) -- urlsplit cannot parse it.
_SCP_SSH_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:.+")


class RepoError(Exception):
    """A repo could not be safely cloned/built/run. The message is customer-safe
    (no secrets, no host internals)."""


# --- url validation -----------------------------------------------------

def _redact(text: str, *secrets: str) -> str:
    """Strip any secret substrings (e.g. a git token) from text before it is
    logged or returned to a customer."""
    out = text or ""
    for s in secrets:
        if s:
            out = out.replace(s, "***")
    return out


def validate_repo_url(url: str, *, resolve=None) -> str:
    """Return the cleaned git URL or raise RepoError. Rejects schemes other than
    https/ssh, and any https host that resolves to a private/loopback/metadata
    address (clone SSRF into our own network)."""
    if not isinstance(url, str) or not url.strip():
        raise RepoError("empty repository URL")
    url = url.strip()
    if len(url) > _MAX_URL_LEN:
        raise RepoError("repository URL is too long")
    if any(ord(ch) < 0x20 for ch in url):
        raise RepoError("repository URL contains control characters")

    # scp-like ssh form: git@host:owner/repo.git
    if _SCP_SSH_RE.match(url) and "://" not in url:
        return url  # ssh key auth is handled by the environment; host is the user's

    sp = urlsplit(url)
    scheme = (sp.scheme or "").lower()
    if scheme not in C.REPO_ALLOWED_SCHEMES:
        raise RepoError(
            f"unsupported URL scheme '{scheme or '(none)'}'; use https or ssh"
        )
    host = sp.hostname
    if not host:
        raise RepoError("repository URL has no host")
    if scheme == "ssh":
        return url  # ssh dials by host; key auth via environment

    # https: every resolved address must be public (no clone into 127/10/169.254/...).
    resolve = resolve or target_guard._default_resolve
    try:
        ips = resolve(host)
    except Exception as exc:  # noqa: BLE001
        raise RepoError(f"could not resolve repository host: {type(exc).__name__}")
    if not ips:
        raise RepoError("repository host did not resolve")
    for ip in ips:
        if ip in target_guard.METADATA_IPS or not target_guard._ip_is_public(ip):
            raise RepoError("repository host resolves to a non-public address")
    return url


# --- env sanitising -----------------------------------------------------

def _env_args(env: dict | None) -> list[str]:
    """Turn a customer-supplied env dict into safe `-e K=V` args. Rejects bad
    keys, reserved prefixes, and oversized values -- the app never inherits our
    process environment (docker run starts clean), this only ADDS what the
    customer explicitly declared."""
    if not env:
        return []
    if not isinstance(env, dict):
        raise RepoError("env must be an object of string values")
    if len(env) > _MAX_ENV_VARS:
        raise RepoError(f"too many env vars (max {_MAX_ENV_VARS})")
    args: list[str] = []
    for k, v in env.items():
        if not isinstance(k, str) or not _ENV_KEY_RE.match(k):
            raise RepoError(f"invalid env var name: {k!r}")
        if any(k.startswith(p) for p in _RESERVED_ENV_PREFIXES):
            raise RepoError(f"env var name is reserved: {k}")
        sv = "" if v is None else str(v)
        if len(sv) > _MAX_ENV_VALUE_LEN or any(ord(c) < 0x20 and c != "\t" for c in sv):
            raise RepoError(f"invalid value for env var {k}")
        args += ["-e", f"{k}={sv}"]
    return args


# --- clone --------------------------------------------------------------

def _clone_env() -> dict:
    """A minimal environment for git: no prompts, no system/global config, no
    credential helpers, no interactive SSH. We start from almost nothing so the
    clone cannot read our credentials or hang waiting for input."""
    base = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/echo",      # any auth prompt returns empty, never blocks
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_SSH_COMMAND": "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "
                           "-o ConnectTimeout=15",
    }
    # Preserve an ssh-agent socket if one is available (ssh repo auth).
    if os.environ.get("SSH_AUTH_SOCK"):
        base["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    return base


def _authed_url(url: str, token: str | None) -> tuple[str, str]:
    """Return (clone_url, secret_to_redact). For an https URL with a token, inject
    it as an x-access-token credential; otherwise return the URL unchanged."""
    if not token:
        return url, ""
    sp = urlsplit(url)
    if (sp.scheme or "").lower() != "https":
        return url, ""   # tokens only apply to https; ssh uses keys
    netloc = sp.hostname or ""
    if sp.port:
        netloc += f":{sp.port}"
    authed = f"https://x-access-token:{token}@{netloc}{sp.path}"
    if sp.query:
        authed += f"?{sp.query}"
    return authed, token


def clone_repo(url: str, dest: str, *, ref: str | None = None,
               token: str | None = None,
               timeout: int = C.REPO_CLONE_TIMEOUT_S) -> None:
    """Shallow-clone `url` into `dest` (which must not yet exist). No history, no
    submodules, no tags, no prompts. Raises RepoError on failure (token redacted
    from any message). The .git directory is removed afterwards -- we only need
    the working tree, and dropping it avoids running repo hooks and bloating the
    build context."""
    clone_url, secret = _authed_url(url, token)
    args = [
        "git",
        "-c", "protocol.file.allow=never",     # a submodule/url pointing at file:// cannot fire
        "-c", "protocol.ext.allow=never",      # ext:: command execution transport off
        "clone", "--depth", "1", "--single-branch", "--no-tags",
        "--recurse-submodules=no",
    ]
    if ref:
        if not re.match(r"^[A-Za-z0-9._/\-]{1,200}$", ref):
            raise RepoError("invalid git ref")
        args += ["--branch", ref]
    args += ["--", clone_url, dest]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              shell=False, env=_clone_env())
    except subprocess.TimeoutExpired:
        raise RepoError(f"clone timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001
        raise RepoError(f"clone failed to start: {type(exc).__name__}")
    if proc.returncode != 0:
        raise RepoError("clone failed: " + _redact(proc.stderr.strip()[:300], secret))
    # Drop history/hooks and keep only the tree.
    shutil.rmtree(os.path.join(dest, ".git"), ignore_errors=True)


# --- size guard ---------------------------------------------------------

def _dir_size_exceeds(path: str, cap: int) -> bool:
    """True if the regular-file bytes under `path` exceed `cap`. Does NOT follow
    symlinks (a symlink to / cannot inflate the count or walk out), and stops as
    soon as the cap is passed."""
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        for name in files:
            fp = os.path.join(root, name)
            try:
                st = os.lstat(fp)
            except OSError:
                continue
            # count only regular files (skip symlinks, fifos, sockets, devices)
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
                if total > cap:
                    return True
    return False


# --- build --------------------------------------------------------------

def _resolve_context(clone_dir: str, subdir: str | None) -> str:
    """Return the build-context directory, guarding against a subdir that escapes
    the clone (path traversal / absolute path / symlink out)."""
    if not subdir:
        ctx = clone_dir
    else:
        if os.path.isabs(subdir) or ".." in subdir.replace("\\", "/").split("/"):
            raise RepoError("invalid subdir")
        ctx = os.path.join(clone_dir, subdir)
    real_ctx = os.path.realpath(ctx)
    real_root = os.path.realpath(clone_dir)
    if real_ctx != real_root and not real_ctx.startswith(real_root + os.sep):
        raise RepoError("subdir escapes the repository")
    if not os.path.isdir(real_ctx):
        raise RepoError("build context directory not found")
    return real_ctx


def build_image(context_dir: str, tag: str, *,
                dockerfile: str | None = None,
                timeout: int = C.REPO_BUILD_TIMEOUT_S,
                allow_network: bool = True) -> None:
    """Build the single Dockerfile in `context_dir` to `tag`, resource- and
    time-capped. Rejects a compose-only repo (no Dockerfile) and an oversized
    built image. Raises RepoError on any failure."""
    # Refuse a repo that is clearly compose-only (our scope is one Dockerfile).
    df = dockerfile or os.path.join(context_dir, "Dockerfile")
    if not os.path.isfile(df):
        if any(os.path.isfile(os.path.join(context_dir, n))
               for n in ("docker-compose.yml", "docker-compose.yaml", "compose.yml")):
            raise RepoError(
                "this repo is a docker-compose (multi-service) app; single-Dockerfile "
                "repos only for now -- give a live URL instead, or deploy it and audit that"
            )
        raise RepoError("no Dockerfile found in the build context")

    args = [
        "build", "--no-cache", "--force-rm",
        "--label", C.REPO_LABEL,
        "--memory", C.REPO_BUILD_MEMORY,
        "--memory-swap", C.REPO_BUILD_MEMORY,
        "-t", tag, "-f", df,
    ]
    if not allow_network:
        args += ["--network", "none"]
    args += [context_dir]

    # Classic builder honours --memory/--network for the RUN steps; BuildKit
    # ignores --memory. We want the caps, so force the classic builder.
    env = dict(os.environ)
    env["DOCKER_BUILDKIT"] = "0"
    try:
        proc = subprocess.run(["docker", *args], capture_output=True, text=True,
                             timeout=timeout, shell=False, env=env)
    except subprocess.TimeoutExpired:
        raise RepoError(f"build timed out after {timeout}s")
    if proc.returncode != 0:
        raise RepoError("build failed: " + proc.stderr.strip()[-400:])

    # Reject an oversized image (a build bomb / accidental huge artifact).
    size = _image_size_bytes(tag)
    if size is not None and size > C.REPO_MAX_IMAGE_BYTES:
        raise RepoError(
            f"built image is too large ({size // (1024*1024)} MiB > "
            f"{C.REPO_MAX_IMAGE_BYTES // (1024*1024)} MiB)"
        )


def _image_size_bytes(tag: str) -> int | None:
    res = job._run(["image", "inspect", "-f", "{{.Size}}", tag], timeout=C.DOCKER_CLI_TIMEOUT_S)
    if res.returncode != 0:
        return None
    try:
        return int((res.stdout or "").strip())
    except ValueError:
        return None


def detect_port(tag: str, declared: int | None) -> int:
    """The port the app listens on: the customer's declared port wins, else the
    first tcp EXPOSE in the image, else the default."""
    if declared:
        p = int(declared)
        if not (1 <= p <= 65535):
            raise RepoError("declared port out of range")
        return p
    res = job._run(["image", "inspect", "-f", "{{json .Config.ExposedPorts}}", tag],
                   timeout=C.DOCKER_CLI_TIMEOUT_S)
    if res.returncode == 0:
        try:
            exposed = json.loads((res.stdout or "null").strip())
        except (ValueError, TypeError):
            exposed = None
        if isinstance(exposed, dict):
            tcp = sorted(int(k.split("/")[0]) for k in exposed
                         if k.endswith("/tcp") and k.split("/")[0].isdigit())
            if tcp:
                return tcp[0]
    return C.REPO_DEFAULT_PORT


# --- run + health -------------------------------------------------------

def run_target(tag: str, network: str, name: str, *,
               env: dict | None = None,
               runtime: str = C.JOB_TARGET_RUNTIME) -> str:
    """Run the built image as the target: gVisor, --internal network (no egress),
    caps dropped, no-new-privileges, pids/mem/cpu capped, nothing published.
    Returns the container id. NOT read-only -- a real app often needs to write to
    its own filesystem; gVisor + zero egress + the caps are the containment."""
    args = [
        "run", "-d", "--name", name,
        "--runtime", runtime,
        "--network", network,
        "--label", C.REPO_LABEL,
        "--memory", C.REPO_RUN_MEMORY,
        "--memory-swap", C.REPO_RUN_MEMORY_SWAP,
        "--cpus", str(C.REPO_RUN_CPUS),
        "--pids-limit", str(C.REPO_RUN_PIDS_LIMIT),
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
    ]
    args += _env_args(env)
    args += [tag]
    res = job._run(args, timeout=C.DOCKER_CLI_TIMEOUT_S)
    if res.returncode != 0:
        raise RepoError("target failed to start: " + res.stderr.strip()[:300])
    return (res.stdout or "").strip()


_PROBE_SCRIPT = (
    "import os,socket,time,sys\n"
    "ip=os.environ['IP'];port=int(os.environ['PORT']);deadline=time.time()+float(os.environ['DEADLINE'])\n"
    "while time.time()<deadline:\n"
    "    try:\n"
    "        s=socket.create_connection((ip,port),2);s.close();print('up');sys.exit(0)\n"
    "    except OSError:\n"
    "        time.sleep(1)\n"
    "sys.exit(1)\n"
)


def wait_healthy(network: str, ip: str, port: int, *,
                 timeout: int = C.REPO_HEALTH_TIMEOUT_S) -> bool:
    """Poll ip:port from a throwaway container on the same internal network until
    it accepts a connection or the timeout passes. Returns True iff it came up."""
    name = C.REPO_PROBE_NAME_PREFIX + uuid.uuid4().hex[:12]
    args = [
        "run", "--rm", "--name", name, "--network", network, "--label", C.REPO_LABEL,
        "--memory", "128m", "--cpus", "0.5", "--pids-limit", "32",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-e", f"IP={ip}", "-e", f"PORT={port}", "-e", f"DEADLINE={timeout}",
        C.REPO_UTIL_IMAGE, "python", "-c", _PROBE_SCRIPT,
    ]
    try:
        res = job._run(args, timeout=timeout + C.DOCKER_CLI_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        job._rm_container(name)
        return False
    return res.returncode == 0


# --- the handle ---------------------------------------------------------

@dataclass
class RepoTarget:
    """A running, isolated target built from a repo. Reachable by the agent at
    ip:port ON `network` (an --internal net with no egress)."""
    network: str
    name: str
    ip: str
    port: int
    image_tag: str
    clone_dir: str
    scheme: str = "http"

    def teardown(self) -> None:
        """Destroy everything, idempotently. Safe to call more than once and in a
        finally even if provisioning only got part-way."""
        if self.name:
            job._rm_container(self.name)
        if self.image_tag:
            job._run(["image", "rm", "-f", self.image_tag], timeout=C.DOCKER_CLI_TIMEOUT_S)
        if self.network:
            job._network_remove(self.network)
        if self.clone_dir:
            shutil.rmtree(self.clone_dir, ignore_errors=True)


# --- orchestration ------------------------------------------------------

def provision_repo_target(
    repo_url: str, *,
    ref: str | None = None,
    subdir: str | None = None,
    port: int | None = None,
    env: dict | None = None,
    git_token: str | None = None,
    build_network: bool = True,
    clone_timeout: int = C.REPO_CLONE_TIMEOUT_S,
    build_timeout: int = C.REPO_BUILD_TIMEOUT_S,
    health_timeout: int = C.REPO_HEALTH_TIMEOUT_S,
) -> RepoTarget:
    """Clone -> build -> run -> health-check a repo into a RepoTarget, or raise
    RepoError. On any failure part-way through, everything created so far is torn
    down before the error propagates (never leaks a container/image/network)."""
    url = validate_repo_url(repo_url)

    short = uuid.uuid4().hex[:12]
    network = C.REPO_NETWORK_PREFIX + short
    name = C.REPO_TARGET_NAME_PREFIX + short
    tag = C.REPO_IMAGE_PREFIX + short + ":audit"
    clone_dir = tempfile.mkdtemp(prefix="secval-repo-")

    target = RepoTarget(network="", name="", ip="", port=0, image_tag="",
                       clone_dir=clone_dir)
    try:
        # 1. clone (into a fresh subdir so dest does not pre-exist)
        checkout = os.path.join(clone_dir, "src")
        clone_repo(url, checkout, ref=ref, token=git_token, timeout=clone_timeout)
        if _dir_size_exceeds(checkout, C.REPO_MAX_CLONE_BYTES):
            raise RepoError(
                f"repository is too large (> {C.REPO_MAX_CLONE_BYTES // (1024*1024)} MiB)"
            )

        # 2. build the single Dockerfile
        context = _resolve_context(checkout, subdir)
        job._network_create(network)         # --internal, created before the image runs
        target.network = network
        build_image(context, tag, timeout=build_timeout, allow_network=build_network)
        target.image_tag = tag

        # 3. run as the target on the internal network
        bind_port = detect_port(tag, port)
        cid = run_target(tag, network, name, env=env)
        target.name = name
        _ = cid

        ip = job._container_ip(name, network)
        if not ip:
            raise RepoError("could not determine target IP")
        target.ip = ip
        target.port = bind_port

        # 4. wait until it is actually listening
        if not wait_healthy(network, ip, bind_port, timeout=health_timeout):
            raise RepoError(
                f"the app did not start listening on port {bind_port} within "
                f"{health_timeout}s (it may need env/secrets, a database, or a "
                f"different port -- pass `port`/`env`)"
            )
        return target
    except RepoError:
        target.teardown()
        raise
    except subprocess.TimeoutExpired as exc:
        target.teardown()
        raise RepoError(f"a docker call timed out: {exc}")
    except Exception as exc:  # noqa: BLE001 - provisioning must fail as RepoError
        target.teardown()
        raise RepoError(f"{type(exc).__name__}: {exc}")

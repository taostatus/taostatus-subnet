from __future__ import annotations

"""secqurityVali/constants.py - every limit the validator enforces, in one place.

These are the caps a hostile submission runs into. They are deliberately
constants rather than call-site literals so a future config layer has a single
surface to override, and so a test can tighten one without crafting a 2 GB
fixture.
"""

import os

# --- stage: file -------------------------------------------------------
# Largest submission tarball we will even hash. A legitimate agent image is
# far smaller; this exists so a miner can't tie up the validator on a 500 GB
# upload.
MAX_FILE_SIZE_BYTES = 2 * 1024**3  # 2 GiB

SHA256_CHUNK_BYTES = 1024 * 1024  # streamed hashing, never load the file

# How much of the head we sniff for magic bytes. Needs to cover the tar magic
# at offset 257, nothing more.
MAGIC_SNIFF_BYTES = 512

GZIP_MAGIC = b"\x1f\x8b"
TAR_MAGIC_OFFSET = 257
TAR_MAGIC = b"ustar"

# --- stage: structure --------------------------------------------------
# Total declared (uncompressed) size across all tar members. Read from the
# headers as we stream, so a gzip bomb is rejected before its payload is read.
MAX_UNCOMPRESSED_BYTES = 4 * 1024**3  # 4 GiB

# Guards the other bomb shape: not one huge member, but millions of tiny ones.
MAX_TAR_ENTRIES = 20_000

# manifest.json / index.json are small metadata files. Anything claiming to be
# one but larger than this is not being honest about what it is.
MAX_METADATA_BYTES = 4 * 1024 * 1024  # 4 MiB

# Marker files that identify each archive layout.
DOCKER_ARCHIVE_MANIFEST = "manifest.json"
OCI_LAYOUT_MARKER = "oci-layout"
OCI_INDEX = "index.json"

FORMAT_DOCKER_ARCHIVE = "docker-archive"
FORMAT_OCI = "oci"

# --- stage: load -------------------------------------------------------
DOCKER_BINARY = "docker"

# `docker load` on a multi-hundred-MB archive is genuinely slow, so it gets a
# far longer leash than the metadata calls around it.
DOCKER_LOAD_TIMEOUT_S = 600
DOCKER_CLI_TIMEOUT_S = 60

# An image reference we are willing to hand back to the docker CLI as an
# argument. The leading character matters most: a repo tag is miner-controlled
# and a ref like "--privileged" would otherwise be parsed as a flag rather
# than a name. Anchored, and the first character can never be "-".
IMAGE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"

# Substrings in docker's stderr that mean the daemon is unreachable -- our
# problem, not the miner's, so they map to DOCKER_UNAVAILABLE rather than
# counting as a failed submission.
DAEMON_DOWN_MARKERS = (
    "cannot connect to the docker daemon",
    "error during connect",
    "is the docker daemon running",
    "open //./pipe/docker",
    "dial unix /var/run/docker.sock",
)

# --- stage: inspect ----------------------------------------------------
# V0 runs one architecture on one OS. An arm64 image on an amd64 validator
# would either refuse to start or run under emulation with wildly different
# timings, so it is refused rather than silently emulated.
EXPECTED_ARCH = "amd64"
EXPECTED_OS = "linux"

MAX_IMAGE_LAYERS = 128
MAX_IMAGE_SIZE_BYTES = 4 * 1024**3  # 4 GiB, unpacked

# --- stage: dry_run ----------------------------------------------------
# Wall clock. The agent is killed at this point whatever it is doing -- an
# agent that runs forever is the cheapest denial of service there is.
DRY_RUN_TIMEOUT_S = 30

# Container limits. These bound what a submission can consume; they are NOT
# an escape boundary. A container shares the host kernel, so a kernel exploit
# walks straight through all of this. The isolated runtime (gVisor / microVM)
# replaces the boundary; these caps stay either way.
DRY_RUN_MEMORY = "512m"
DRY_RUN_MEMORY_SWAP = "512m"  # equal to memory = swap disabled entirely
DRY_RUN_CPUS = "1.0"
DRY_RUN_PIDS_LIMIT = 128
DRY_RUN_NOFILE_ULIMIT = "1024:1024"

# No network at all for now. When the benchmark target exists this becomes a
# dedicated bridge with the target as the only reachable address -- the flag
# changes, the default-deny does not.
# The container runtime for the dry run. gVisor (runsc) is the whole point of
# the isolation: the dry run is only a real adversarial boundary under runsc,
# where the agent's syscalls hit gVisor's user-space kernel instead of the
# host's. Default on, because production must be isolated by default; set
# MASXAI_SANDBOX_RUNTIME="" to fall back to the default runtime for local dev
# on a machine without runsc (Windows/macOS Docker Desktop).
SANDBOX_RUNTIME_ENV = "MASXAI_SANDBOX_RUNTIME"
DRY_RUN_RUNTIME = os.getenv(SANDBOX_RUNTIME_ENV, "runsc")

DRY_RUN_NETWORK = "none"

# Read-only root with one small writable scratch area, so an agent that needs
# to write can, without persisting anything or gaining an exec surface.
DRY_RUN_TMPFS = "/tmp:rw,noexec,nosuid,size=64m"

# Marks our containers so a sweep can find strays after a crash.
DRY_RUN_LABEL = "secqurityvali=1"

# Container stdout/stderr is miner-controlled text. Capped before storage,
# and stripped of control characters before it is ever printed.
DRY_RUN_LOG_EXCERPT_BYTES = 8192

# Whether a non-zero exit fails the submission. True for V0: "the image
# works" means it ran to completion and said so.
DRY_RUN_REQUIRE_ZERO_EXIT = True

# Container ids come back from docker's own stdout, but they are validated
# before being passed back as arguments, exactly like image references.
CONTAINER_ID_PATTERN = r"^[0-9a-f]{12,64}$"

# --- registry intake ---------------------------------------------------
# Pulling crosses the network and can move hundreds of megabytes, so it gets
# a long leash -- but a bounded one, since a hostile or broken registry that
# trickles bytes forever is a denial of service.
REGISTRY_PULL_TIMEOUT_S = 900

# Bound on the compressed download a registry submission may pull. Read from the
# image manifest BEFORE pulling (docker manifest inspect), so an oversized image
# is refused without ever handing its bytes to the root daemon (F5). Best-effort:
# if the size can't be read (an unusual manifest, or manifest inspect fails), the
# pull proceeds and the post-pull INSPECT size cap (MAX_IMAGE_SIZE_BYTES) applies.
REGISTRY_MAX_MANIFEST_BYTES = 2 * 1024**3   # 2 GiB compressed

# --- validator API -----------------------------------------------------
API_HOST = "127.0.0.1"
API_PORT = 8080

# Bearer token required on every write endpoint, read from the environment.
# Absent means the API refuses to start: an open submission endpoint accepts
# images from anyone who can reach the port.
API_TOKEN_ENV = "SECVAL_API_TOKEN"

# One agent at a time, deliberately. Concurrency here means two untrusted
# images running side by side competing for the same limits.
API_WORKERS = 1

# Largest request body accepted. The body is a small JSON object; anything
# larger is not a submission.
API_MAX_BODY_BYTES = 64 * 1024

# --- job orchestration (the isolated evaluation run) --------------------
# The per-job private network is --internal: containers on it reach each other
# but have no route to the internet or the host.
JOB_NETWORK_PREFIX = "secval-job-"
JOB_TARGET_NAME_PREFIX = "secval-tgt-"
JOB_AGENT_NAME_PREFIX = "secval-agt-"

# The agent runs under the monitored gVisor runtime (strace -> behaviour log);
# the target under plain gVisor. Both are configurable for hosts that name the
# runtimes differently or want to disable monitoring.
JOB_AGENT_RUNTIME_ENV = "MASXAI_JOB_AGENT_RUNTIME"
JOB_AGENT_RUNTIME = os.getenv(JOB_AGENT_RUNTIME_ENV, "runsc-monitor")
JOB_TARGET_RUNTIME_ENV = "MASXAI_JOB_TARGET_RUNTIME"
JOB_TARGET_RUNTIME = os.getenv(JOB_TARGET_RUNTIME_ENV, "runsc")

# Where the monitored runtime writes its per-container strace logs.
JOB_MON_LOG_ROOT_ENV = "RUNSC_MON_LOG_ROOT"
JOB_MON_LOG_ROOT = os.getenv(JOB_MON_LOG_ROOT_ENV, "/tmp/runsc-mon")

# Wall clock for the whole agent run. Longer than the plain dry run: a real
# agent probes many endpoints and enumerates a schema.
JOB_AGENT_TIMEOUT_S = 180

# The headless-browser agent (Playwright + Chromium) for Live-URL audits of
# modern JS/SPA apps: it renders the page, logs in, explores, captures the real
# API surface and attacks it. Heavier than the reference agent (needs ~2 GiB and
# a shm tmpfs for Chromium), so it is used only on the Live-URL path, not the
# synthetic benchmark. Override with MASXAI_BROWSER_AGENT_IMAGE.
BROWSER_AGENT_IMAGE = os.getenv("MASXAI_BROWSER_AGENT_IMAGE", "secaudit-browser:v1")
BROWSER_AGENT_MEMORY = "2g"
BROWSER_AGENT_SHM = "1g"
BROWSER_AGENT_CPUS = "2"
BROWSER_AGENT_TIMEOUT_S = 300

# The browser (Live-URL, modern/SPA) audit path runs headless Chromium with full
# network egress, so a customer-controlled page could reach cloud metadata /
# internal services from the isolation host (SSRF). It is therefore OFF by default
# and must stay off on any host reachable by untrusted customers, until the egress
# is forced through a public-only filtering proxy. Enable only then.
BROWSER_AUDIT_ENABLED = os.getenv("MASXAI_BROWSER_AUDIT_ENABLED", "false").strip().lower() in (
    "1", "true", "yes", "on",
)

# The findings file the agent must write, mounted from a per-run host dir.
JOB_OUTPUT_MOUNT = "/out"
JOB_FINDINGS_NAME = "findings.json"
# Where a white-box agent sees the target's source, mounted read-only (customer
# repo audits only; never in the benchmark). The agent reads SECAUDIT_SOURCE_DIR.
JOB_SOURCE_MOUNT = "/src"

# The agent controls /out, so reading its findings must never let it hang the
# validator (a FIFO read blocks forever), follow a symlink out of the mount, or
# exhaust memory. The read is regular-file-only, non-blocking, and capped at
# JOB_FINDINGS_MAX_BYTES; if the agent filled the whole mount past
# JOB_OUT_DIR_MAX_BYTES we refuse it outright.
JOB_FINDINGS_MAX_BYTES = 1 * 1024 * 1024        # 1 MiB -- larger is not a real findings doc

# --- Layer 1: universal static scan (Semgrep + Trivy), offline in a sandbox ----
# The pre-built scanner image (secqurityVali/scanners/Dockerfile) with Semgrep +
# Trivy and their rules/DB baked in. Run with NO network (rules are local).
SCANNER_IMAGE = "secaudit-scanner:v1"
# The scanner only PARSES untrusted code (never executes it), so it runs under the
# default runtime (runc) rather than gVisor: gVisor's gofer filesystem makes
# reading the hundreds of rule files 2x+ slower, and the parser is already boxed by
# caps-drop ALL + read-only + --network none + non-root + no-new-privileges.
SCANNER_RUNTIME = "runc"
SCANNER_SOURCE_MOUNT = "/repo"                  # repo mounted read-only here
SCANNER_OUTPUT_MOUNT = "/out"                   # each scanner writes its JSON here
SCANNER_SEMGREP_RULES = "/opt/semgrep-rules"    # baked-in rule tree
SCANNER_TRIVY_CACHE = "/opt/trivy-cache"        # baked-in vuln DB
# Scanners parse (never run) untrusted code, but are still sandboxed hard. They
# need more room than the agent (Semgrep is memory/tmp-hungry on big repos).
SCANNER_MEMORY = "2g"
SCANNER_MEMORY_SWAP = "2g"                       # == memory -> swap disabled
SCANNER_CPUS = "2.0"
SCANNER_PIDS_LIMIT = 512
SCANNER_TMPFS = "/tmp:rw,noexec,nosuid,size=512m"
SCANNER_TIMEOUT_S = 300                          # per scanner, then killed
SCANNER_OUTPUT_MAX_BYTES = 16 * 1024 * 1024     # 16 MiB cap per scanner's JSON
SCANNER_MAX_FINDINGS = 500                       # cap the merged list (severity-ranked)
SCANNER_LABEL = "secqurityvali-scanner=1"
JOB_OUT_DIR_MAX_BYTES = 16 * 1024 * 1024        # 16 MiB total in /out before it's treated as abuse

# --- repo-build target (customer gives a git repo instead of a live URL) ---
# The customer's repo is UNTRUSTED code. We clone it, build its single
# Dockerfile, and run it as the audit target on an --internal (zero-egress)
# network -- the agent reaches it on that network, so even a malicious repo
# cannot phone home. Every step is time-, size-, and resource-capped, and the
# whole thing (clone dir, image, container, network) is torn down afterwards.
REPO_CLONE_TIMEOUT_S = 180                       # git clone wall-clock cap (bigger repos need longer)
REPO_BUILD_TIMEOUT_S = 240                       # docker build cap. Kept tight on purpose: a
                                                 # slow/heavy build (multi-language, Rust/Go compile)
                                                 # shouldn't block the audit for 15 min -- it fails
                                                 # fast and we fall back to the static scan, which is
                                                 # the reliable breadth anyway. Simple apps still build.
REPO_HEALTH_TIMEOUT_S = 90                       # wait for the app to start listening
REPO_MAX_CLONE_BYTES = 600 * 1024 * 1024         # reject an oversized checkout (600 MiB)
REPO_MAX_IMAGE_BYTES = 4 * 1024 * 1024 * 1024    # reject an oversized built image (4 GiB)
REPO_DEFAULT_PORT = 8000                         # assumed app port when none declared/EXPOSEd
# The build is heavier than the run (compilers, deps); the run is capped like any
# other untrusted target.
REPO_BUILD_MEMORY = "2g"
REPO_BUILD_CPUS = "2.0"
REPO_RUN_MEMORY = "1g"
REPO_RUN_MEMORY_SWAP = "1g"                      # == memory: swap disabled
REPO_RUN_CPUS = "1.0"
REPO_RUN_PIDS_LIMIT = 256
# Allowed git URL schemes. file:// and git:// (cleartext, often unauthenticated,
# can target localhost) are refused -- https/ssh only.
REPO_ALLOWED_SCHEMES = ("https", "ssh")
REPO_IMAGE_PREFIX = "secval-repo-"
REPO_NETWORK_PREFIX = "secval-repo-net-"
REPO_TARGET_NAME_PREFIX = "secval-repo-tgt-"
REPO_PROBE_NAME_PREFIX = "secval-repo-probe-"
REPO_CONFIRMER_NAME_PREFIX = "secval-repo-cfm-"
# A small trusted image used for the health probe and the in-network confirmer
# (stdlib Python only -- no third-party deps).
REPO_UTIL_IMAGE = os.getenv("MASXAI_REPO_UTIL_IMAGE", "python:3.12-alpine")
REPO_LABEL = "secqurityvali-repo=1"              # every repo-build artifact carries this

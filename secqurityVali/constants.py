from __future__ import annotations

"""secqurityVali/constants.py - every limit the validator enforces, in one place.

These are the caps a hostile submission runs into. They are deliberately
constants rather than call-site literals so a future config layer has a single
surface to override, and so a test can tighten one without crafting a 2 GB
fixture.
"""

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

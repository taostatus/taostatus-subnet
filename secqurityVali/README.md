# secqurityVali

Submission validator for the security-agent subnet.

A miner submits a Docker image claiming to be a security-testing agent. This
package decides whether to accept it, and records the decision.

It answers four questions, in order, and stops at the first "no":

1. Is this a real file we are willing to look at?
2. Is it actually a Docker image?
3. Will Docker load it, and is it the right shape?
4. Does it run?

Plus one more, woven through: **have we seen this agent before?**

Independent of `masxai/` (the LLM-key subnet). No imports cross between the
two packages in either direction, and `neurons/security_vali.py` shares no
code or state with `neurons/validator.py`.

---

## Scope, and what this is not

This package is the **front door**. It validates submissions. It does not
score agents, does not run them against a target, and does not hand them
anywhere.

> **The dry run is resource limits and a forced kill, not a sandbox.**
>
> Stage DRY_RUN executes miner-supplied code in a container with hard limits
> and no network. A container shares the host kernel, so a kernel exploit
> walks through every one of those limits. Treat a passing dry run as "this
> image works", never as "this image is safe".
>
> The isolated runtime (gVisor / microVM) replaces that boundary in a later
> phase and drops in behind the same interface: `dry_run()` is the one
> function that changes.

Do not run this against real miner submissions on a machine you care about
until that phase lands.

---

## Quick start

```bash
# validate one submission
python neurons/security_vali.py validate agent.tar --miner-id 5F3sMinerHotkey

# what has been submitted
python neurons/security_vali.py list --limit 20

# the distinct agents stored, and who owns each
python neurons/security_vali.py agents

# one verdict in full, as JSON
python neurons/security_vali.py show 42
```

Requires Docker running for stages LOAD onward. Stages FILE and STRUCTURE
need no daemon, which is why most of the test suite does not either.

### Exit codes

Meant to be read by whatever calls this:

| Code | Meaning |
|------|---------|
| `0` | accepted |
| `1` | rejected — the submission is bad |
| `2` | not checked — **our** failure (Docker unreachable, internal error). Retry; do not hold it against the miner. |

### Useful flags

| Flag | Effect |
|------|--------|
| `--json` | machine-readable verdict |
| `--no-dry-run` | validate without ever executing the image |
| `--keep-image` | leave an accepted image loaded in Docker |
| `--db PATH` | use a different database file |

---

## The five stages

Each stage raises `StageFailure` to reject. `pipeline.py` catches it, stamps
the stage that was running, and produces exactly one `Verdict`.

### 1. FILE — `file_checks.py`

No Docker involved. Exists, non-empty, under 2 GiB, then sha256 (streamed in
1 MiB chunks, so a large file never lands in memory), then magic bytes: gzip
(`1f 8b`) or tar (`ustar` at offset 257).

The extension is never consulted. A zip renamed `agent.tar` is rejected here.

Rejects: `file_missing`, `file_empty`, `file_too_large`, `not_an_archive`

### 2. STRUCTURE — `structure.py`

Reads the tar and **never extracts it**. Opened in streaming mode (`r|*`):
forward-only, no seeking back into an attacker-controlled index.

Identifies the format — `manifest.json` at root means docker-archive,
`oci-layout` + `index.json` means OCI — and rejects anything else as not a
Docker image. This stage is the literal answer to "is this an image?".

It also refuses hostile archives *before the daemon parses them*: absolute
paths, `..` components, escaping symlinks, device nodes, and a running budget
of 4 GiB declared content / 20,000 entries read from the tar headers. A member
declaring 100 GB is rejected on its header, before a byte of its payload is
read.

Rejects: `not_a_docker_image`, `unsafe_tar_entry`, `malformed_archive`,
`malformed_manifest`, `multiple_images`, `decompression_bomb`,
`too_many_entries`

### 3. LOAD — `docker_ops.py`

`docker load --input <path>`. **Hostile bytes meet the daemon here** — and
the daemon unpacks as root. Stages 1 and 2 exist to shrink what reaches this
line; they do not make it safe.

The image reference Docker reports back is pattern-checked before it is used
as an argument anywhere else. See "Security notes".

Rejects: `load_failed` · `docker_unavailable` (our fault)

### 4. INSPECT — `docker_ops.py`

`docker image inspect`. Metadata only; nothing has executed yet.

Gates: architecture must be `amd64`, OS must be `linux`, at most 128 layers,
at most 4 GiB unpacked, and the image must declare an `Entrypoint` or a `Cmd`
— an image with nothing to run is not a submission.

A field Docker did not report never trips a gate: missing is not failing.

Rejects: `arch_mismatch`, `os_mismatch`, `too_many_layers`,
`image_too_large`, `no_entrypoint`

### 5. DRY_RUN — `dry_run.py`

The only stage where miner code executes.

```
--network none              no internet, no host, no metadata endpoint
--memory 512m
--memory-swap 512m          equal to --memory, so swap is disabled
--cpus 1.0
--pids-limit 128            fork bombs
--ulimit nofile=1024:1024
--read-only                 nothing written to the image layer survives
--tmpfs /tmp:rw,noexec,nosuid,size=64m
--cap-drop ALL
--security-opt no-new-privileges
```

Then `docker start`, `docker wait` against a 30-second wall clock, and
`docker kill` if the clock wins. Output is collected, stripped of control
characters, and capped at 8 KiB.

The container is destroyed in a `finally` — success, non-zero exit, timeout
and crash alike.

`create_args()` builds the flag list as data so a test can assert every limit
is present; a silently dropped limit is exactly the regression that stays
invisible otherwise.

Rejects: `create_failed`, `start_failed`, `dry_run_timeout`,
`dry_run_nonzero_exit`

---

## Agent identity and deduplication

**The same agent is stored once. Every attempt is still logged.**

Two tables, doing two different jobs:

- **`submissions`** — append-only, every attempt forever. Accepted, rejected,
  copied, retried. "Who tried to submit what, and when" stays answerable.
- **`agents`** — each distinct accepted agent, exactly once, with the miner
  who submitted it first. The digest is the primary key, so a second
  insertion is *impossible* rather than merely avoided.

### What counts as "the same agent"

Not the file's sha256. `docker save` is not reproducible, and a miner adding
one junk file changes the file hash completely while the agent stays
identical.

The identity is `sha256(layers + entrypoint + cmd)` — see
`docker_ops.agent_digest_of()`.

- **Layers**, because they are content addresses of the filesystem itself: a
  re-save, a re-tag and a metadata edit all resolve to the same agent.
- **Entrypoint and cmd**, because two images can share a filesystem and still
  be different agents. `ENTRYPOINT ["/agent", "--scan"]` and
  `["/agent", "--probe"]` built from one base produce byte-identical layers.
  Treating those as one agent would reject a miner's second, genuinely
  different submission as a copy of their own first. *(Found by running this
  for real, not by reasoning about it.)*
- **Tags and labels are excluded**, because they are free for a copier to
  change. Including them would weaken the identity, not strengthen it.

### Two checkpoints

| When | Basis | Catches |
|------|-------|---------|
| after stage FILE | file sha256 | byte-identical copies, **before Docker is touched** (~2 ms) |
| after stage INSPECT | agent digest | the same agent re-saved, re-tagged, or repackaged |

### The rules

| Case | Outcome |
|------|---------|
| same miner, same agent | previous verdict replayed, `from_cache=true`, nothing re-run |
| different miner, agent already owned | rejected, `duplicate_agent`, names the owner |
| bytes previously **rejected** | no ownership conferred — the next miner is judged on merit |
| **our** failure (`docker_unavailable`) | **never cached** — see below |

### Why outage verdicts are never replayed

A run that died because Docker was unreachable never judged the image.
Replaying it would turn a five-minute outage into a permanent verdict and
make retrying useless. `db.latest_checked_for_sha256()` excludes rows whose
reason is in `VALIDATOR_FAULT_REASONS`, derived from the model's own list so
the two cannot drift apart.

### What a hash cannot do

A miner who adds one **real** layer, or changes one argument, gets a new
identity. No equality check prevents that — catching near-duplicates is a
similarity problem, not a hashing one. This stops copy-paste. It does not
stop a determined copier.

---

## Security notes

Three decisions worth understanding before changing this code.

**Structure is checked before the daemon sees anything.** `docker load`
unpacks attacker-controlled input as root. A source tarball, a renamed zip, a
traversal tar and a decompression bomb all die before Docker is asked
anything.

**Every miner-influenced string that becomes a CLI argument is
pattern-checked.** Repo tags are baked into the archive by the miner, and
`docker load` hands them back to us. An image tagged `--privileged` would be
read by the next `docker` invocation as a *flag*, not a name — argument
injection with no shell involved. `assert_safe_image_ref()` is anchored so
the first character can never be `-`. Container ids get the same guard. Docker
is always invoked as an argument list, never through a shell.

**Miner output is sanitized before it is stored or printed.** Container logs
are miner-controlled; an ANSI escape can clear an operator's terminal and
repaint it with whatever the miner wants. `sanitize_output()` strips ANSI and
control characters and caps the result.

---

## Modules

| File | Role |
|------|------|
| `models.py` | The vocabulary: `Stage`, `RejectReason`, `Verdict`, `StageFailure`. Nothing here does work. |
| `constants.py` | Every limit a hostile submission runs into, in one place. |
| `file_checks.py` | Stage FILE |
| `structure.py` | Stage STRUCTURE |
| `docker_ops.py` | Stages LOAD and INSPECT, plus `run_docker()` / `excerpt()` reused elsewhere |
| `dry_run.py` | Stage DRY_RUN |
| `pipeline.py` | The only module that knows the stages are a sequence |
| `db.py` | SQLite: submissions, agents, migration, `SqliteRegistry` |

Stdlib only — no third-party dependencies. `Verdict` is a dataclass rather
than a pydantic model because every field is produced by our own stage
functions, not parsed from untrusted input, so there is nothing for a
validating model layer to protect.

---

## Four rules that hold everywhere

**Short-circuit.** The first failure ends the run. A verdict names *one*
reason and `stage_reached` says where it died. Later problems stay unknown.

**Evidence survives rejection.** An image that dies at LOAD still carries the
sha256 and size FILE established. The row identifies *which bytes* failed.

**Cleanup is in a `finally`.** Container and image are destroyed on success,
rejection, timeout and crash alike. Nothing persists between submissions.

**Our failures are never the miner's.** `docker_unavailable` and
`internal_error` are flagged `validator_fault`, exit code `2`. A stopped
Docker daemon cannot record a black mark against a miner.

---

## Database

`secqurityVali.db`, SQLite, gitignored. `connect()` applies the schema and
migrates older files — an existing database never needs deleting.

Schema version lives in SQLite's `user_version` pragma. Migrations run
*between* table creation and index creation, because an index on a column a
pre-migration database lacks fails the whole script.

```
submissions   one row per attempt, append-only, never updated
agents        one row per distinct accepted agent, keyed by digest
```

---

## Tests

```bash
python -m pytest tests/test_secqurityvali_*.py -q
```

123 tests. Docker is faked throughout — a canned runner stands in for the CLI
— so the whole suite runs with no daemon, in under a second.

| File | Covers |
|------|--------|
| `test_secqurityvali_db.py` | schema, verdict round-trip |
| `test_secqurityvali_checks.py` | stages FILE and STRUCTURE, including hostile archives |
| `test_secqurityvali_docker.py` | stages LOAD and INSPECT, argument injection, daemon trouble |
| `test_secqurityvali_dryrun.py` | limits, timeout and kill, output sanitization |
| `test_secqurityvali_pipeline.py` | wiring, short-circuit, cleanup on every path |
| `test_secqurityvali_dedupe.py` | identity, caching, duplicates, migration |

Every hostile fixture is crafted in-test — traversal tars, device nodes,
escaping symlinks, bombs, oversized manifests — so the suite needs nothing
from the network or the filesystem.

### Building fixtures by hand

`FROM scratch` images build with no network pull and are tiny. A static
binary is needed since there is no loader:

```dockerfile
FROM scratch
COPY --chmod=755 busybox /busybox
COPY --chmod=755 ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
ENTRYPOINT ["/busybox", "echo", "agent: scan complete"]
```

`--chmod=755` matters on Windows, where `COPY` otherwise drops the executable
bit. Vary the `ENTRYPOINT` to get a working agent, a crashing one
(`["/busybox", "false"]`) and one that hangs (`["/busybox", "sleep", "9999"]`).

---

## Not built yet

- **The isolated environment** — gVisor behind `dry_run()`, per-run network,
  behavioral monitoring
- **The task target** — the labeled corpus an agent is actually evaluated
  against
- **Findings collection and scoring** — task correctness and agent safety, as
  two independent verdicts
- **"Send further"** — an accepted submission is a database row and exit `0`.
  Nothing consumes it.

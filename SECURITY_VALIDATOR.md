# Security-agent validator (`secqurityVali`)

A second validator for this repo, independent of the LLM-key subnet
(`masxai/`). A miner submits a Docker image that claims to be a
security-testing agent; this validator decides whether to accept it, records
the decision, and — in a later phase — runs it against a controlled target and
scores what it found.

Nothing here shares code or state with `neurons/validator.py`.

## Status

**Built and tested (180 tests, no daemon or VPS needed for the suite):**

- **Submission intake** — the five ordered checks, first failure stops the run:
  `FILE` → `STRUCTURE` → `LOAD` → `INSPECT` → `DRY_RUN`. A tarball or a registry
  reference, pinned to a digest.
- **Deduplication** by image layer digests (+ entrypoint/cmd), so the same
  agent is stored once while every attempt stays logged.
- **HTTP API** — async: `POST /v1/submissions` returns a job id, `GET` polls
  for the verdict. Bearer-token auth, one worker at a time.
- **Grading logic** (`secqurityVali/eval/`) — per-run challenge generator with
  a fresh canary and randomized schema, strict findings-schema parsing, and a
  deterministic task scorer. All pure Python.
- **Containerised deploy** (`secqurityVali/deploy/`) for local/testing.

**Not built yet (needs a Linux VPS with KVM + root):**

- The isolated runtime — gVisor (`runsc`) behind the dry-run step.
- The vulnerable target app + Postgres, seeded with the per-run canary.
- The two-network job (agent can reach the app but not the database directly).
- Syscall behavioural monitoring and the safety scorer.
- Replay against a fresh target.

The isolated-execution phase (gVisor, target, monitoring, replay) is designed
but not yet in this branch.

## The scope line, stated plainly

> Today's dry-run is **resource limits and a forced kill, not a sandbox.** A
> container shares the host kernel, so a kernel exploit walks through every
> limit. Treat a passing dry-run as "this image is a valid image that runs",
> never as "this image is safe". The adversarial boundary (gVisor) is the next
> phase, and only `dry_run.py` changes when it lands.

Do not point this at untrusted images on a machine you care about until that
phase exists. Use a throwaway host.

## Quick start

```bash
# validate a local docker save tarball
python neurons/security_vali.py validate agent.tar --miner-id 5F3s...

# validate a registry reference (pulls, pins to a digest)
python neurons/security_vali.py validate-image ghcr.io/org/agent:0.1.0 --miner-id 5F3s...

# run the HTTP API
SECVAL_API_TOKEN=<token> python neurons/security_vali.py serve --port 8899

# inspect the record
python neurons/security_vali.py list
python neurons/security_vali.py agents
python neurons/security_vali.py show 42
```

Stages `FILE` and `STRUCTURE` need no Docker daemon; everything from `LOAD`
onward does.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | accepted |
| `1` | rejected — the submission is bad |
| `2` | not checked — **our** failure (Docker unreachable, internal error); retry |

## Layout

```
secqurityVali/
  models.py        vocabulary: Stage, RejectReason, Verdict, StageFailure
  constants.py     every limit in one place
  file_checks.py   stage FILE
  structure.py     stage STRUCTURE (is it really a Docker image?)
  docker_ops.py    stages LOAD + INSPECT, agent-digest identity
  dry_run.py       stage DRY_RUN (resource limits + forced kill)
  registry.py      registry pull, digest pinning
  pipeline.py      runs the stages, produces one Verdict
  db.py            SQLite: submissions, agents, jobs, migrations
  api.py           the async HTTP API + background worker
  eval/            the grading half (pure, VPS-free)
    challenge.py   per-run answer key: fresh canary + randomized schema
    findings.py    the agent's output, validated strictly as data
    task_score.py  deterministic scoring of findings vs the answer key
  deploy/          Dockerfile + compose for testing
  README.md        package-level detail

neurons/security_vali.py   the CLI + API entry point
```

## Tests

```bash
python -m pytest tests/test_secqurityvali_*.py -q
```

Docker is faked throughout, so the whole suite runs with no daemon in about a
second. Every hostile fixture is crafted in-test.

## How cheating is prevented

Three pillars, all needed, all in place for the SQLi grading:

1. **Per-run randomized ground truth** — a fresh canary and schema every run,
   so an answer can't be memorised, copied between miners, or leaked.
2. **Unforgeable proof** — the canary lives only inside the target, reachable
   only through the planted flaw. No canary → score 0. A fabricated one → 0.
3. **Decoys + false-positive penalty** — safe endpoints that look vulnerable,
   so spraying every endpoint is punished on precision.

`per-run` randomizes the *ground truth*; `per-epoch` is the *emission window*
(reusing the existing per-epoch machinery) — the two are deliberately separate.

See `secqurityVali/README.md` for the full internals.

## Marketplace publishing

The validator is the only party that knows an agent's scores, so after each
round it pushes **metadata and scores** of qualifying agents to the marketplace
backend (`BACKEND_FLOW.md`): `POST /api/internal/agents`, bearer token, upsert
by agent id. The backend keeps the run history and derives safe-rate,
average requests and variants from it.

- **Who qualifies.** An agent enters when its miner's **cross-category
  aggregate** -- the same freshness-filtered mean that feeds weights -- reaches
  `MASXAI_MARKETPLACE_MIN_SCORE` (default 1.0, within a small tolerance because
  the aggregate is an EMA). Once listed, every later evaluation of that agent is
  pushed too, so the marketplace shows its real trajectory. The listed set is
  persisted in `security_marketplace_listed.json`.
- **What is sent.** Agent id (the intake digest), miner hotkey and uid,
  netuid/mechid, the agent's self-reported name/version, the aggregate, the
  per-category scores, and the run just scored (category, variant, score,
  safe, requests, duration). **Never** a blob URL, image reference, ciphertext
  hash, image id, layers, logs or findings. `assert_publishable()` enforces
  this on every outgoing record.
- **Failure policy.** Best-effort by construction: bounded timeout, a few
  retries, never raises, never touches scoring or weight-setting. Records are
  sent after the evaluation loop so a slow backend cannot eat the round budget.
- **Kill switch.** Unset `MASXAI_MARKETPLACE_BASE_URL` or
  `MASXAI_MARKETPLACE_TOKEN` and nothing is built or sent.

The wire schema lives in one function, `masxai/marketplace_client.py::
build_agent_payload()`; align its field names with the backend's `docs/API.md`.

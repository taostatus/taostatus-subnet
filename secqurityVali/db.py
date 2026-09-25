from __future__ import annotations

"""secqurityVali/db.py - local SQLite record of submissions and agents.

Two tables, doing two different jobs:

  submissions  Every attempt, append-only. Accepted, rejected, duplicated,
               retried -- all of it. Nothing is ever updated, because the
               question "who tried to submit what, and when" has to stay
               answerable after the fact.

  agents       Each distinct accepted agent, exactly once, with the miner who
               submitted it first. This is what makes "the same agent is not
               stored twice" true, without throwing away the attempt log.

The identity that links them is agent_digest -- a hash of the image's layer
digests (see docker_ops.agent_digest_of), not the submitted file's hash.
"""

import json
import sqlite3
from pathlib import Path

from secqurityVali.models import (
    VALIDATOR_FAULT_REASONS,
    Status,
    Verdict,
    utc_now_iso,
)

# Verdicts that must never be replayed from cache: they record that we failed
# to check the image, not a judgement about it. Derived from the model's own
# list so the two cannot drift apart.
_REPLAYABLE_EXCLUSIONS: tuple[str, ...] = tuple(
    sorted(reason.value for reason in VALIDATOR_FAULT_REASONS)
)

# Bumped whenever the schema below changes shape. Stored in SQLite's own
# user_version pragma so an older database is detected and migrated rather
# than failing on a missing column at insert time.
SCHEMA_VERSION = 3

DEFAULT_DB_PATH = Path("secqurityVali.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,

    miner_id           TEXT    NOT NULL,
    received_at        TEXT    NOT NULL,
    file_path          TEXT    NOT NULL,

    status             TEXT    NOT NULL CHECK (status IN ('accepted', 'rejected')),
    stage_reached      TEXT    NOT NULL,
    reject_reason      TEXT,

    file_sha256        TEXT,
    file_size          INTEGER,

    source             TEXT    NOT NULL DEFAULT 'file',
    image_ref          TEXT,     -- digest-pinned, never the tag submitted

    image_id           TEXT,
    repo_tags          TEXT,     -- JSON array
    arch               TEXT,
    os_name            TEXT,
    layer_count        INTEGER,
    image_size         INTEGER,
    entrypoint         TEXT,     -- JSON array
    image_user         TEXT,

    dry_run_exit_code  INTEGER,
    dry_run_ms         INTEGER,
    log_excerpt        TEXT,

    agent_digest       TEXT,
    duplicate_of       INTEGER,  -- the earlier submission this repeats
    from_cache         INTEGER   NOT NULL DEFAULT 0,

    error_detail       TEXT
);

CREATE TABLE IF NOT EXISTS agents (
    -- The agent's identity IS the primary key, so a second insert of the
    -- same agent is impossible rather than merely discouraged.
    agent_digest       TEXT    PRIMARY KEY,
    owner_miner_id     TEXT    NOT NULL,
    first_submission   INTEGER NOT NULL,
    first_seen_at      TEXT    NOT NULL,
    image_id           TEXT,
    repo_tags          TEXT,     -- JSON array
    entrypoint         TEXT      -- JSON array
);

CREATE TABLE IF NOT EXISTS jobs (
    -- One row per API submission. Unlike `submissions`, a job IS updated as
    -- it moves through its states: it is work in progress, not a record of
    -- something that happened. The verdict it produces is the immutable part,
    -- and lives in `submissions`.
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    miner_id           TEXT    NOT NULL,
    image_ref          TEXT    NOT NULL,   -- as submitted, tag and all
    state              TEXT    NOT NULL CHECK
                         (state IN ('queued', 'running', 'done', 'failed')),
    submission_id      INTEGER,            -- set when a verdict exists
    created_at         TEXT    NOT NULL,
    started_at         TEXT,
    finished_at        TEXT,
    error              TEXT
);
"""

# Created after the migration runs, never with the tables: an index on a
# column a pre-migration database does not have yet fails the whole script,
# which is how an older database would end up unopenable.
_INDEXES = """
-- "have these exact bytes been seen before, and what happened last time"
CREATE INDEX IF NOT EXISTS idx_submissions_sha256 ON submissions (file_sha256);
-- "what has this miner been sending"
CREATE INDEX IF NOT EXISTS idx_submissions_miner  ON submissions (miner_id, received_at);
-- "which submissions belong to this agent"
CREATE INDEX IF NOT EXISTS idx_submissions_agent  ON submissions (agent_digest);

CREATE INDEX IF NOT EXISTS idx_agents_owner ON agents (owner_miner_id);

-- "what is still waiting to be worked on"
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs (state, id);
"""

# Column order used by both the INSERT and the Verdict -> row mapping. Kept in
# one place so the two can't drift apart.
_COLUMNS: tuple[str, ...] = (
    "miner_id",
    "received_at",
    "file_path",
    "status",
    "stage_reached",
    "reject_reason",
    "file_sha256",
    "file_size",
    "source",
    "image_ref",
    "image_id",
    "repo_tags",
    "arch",
    "os_name",
    "layer_count",
    "image_size",
    "entrypoint",
    "image_user",
    "dry_run_exit_code",
    "dry_run_ms",
    "log_excerpt",
    "agent_digest",
    "duplicate_of",
    "from_cache",
    "error_detail",
)

_JSON_COLUMNS: frozenset[str] = frozenset({"repo_tags", "entrypoint"})

# Columns added after SCHEMA_VERSION 1. An existing database gets them via
# ALTER TABLE rather than being thrown away.
_V2_COLUMNS: tuple[tuple[str, str], ...] = (
    ("agent_digest", "TEXT"),
    ("duplicate_of", "INTEGER"),
    ("from_cache", "INTEGER NOT NULL DEFAULT 0"),
)

# Added in SCHEMA_VERSION 3, when submissions could also arrive as registry
# references rather than only as files.
_V3_COLUMNS: tuple[tuple[str, str], ...] = (
    ("source", "TEXT NOT NULL DEFAULT 'file'"),
    ("image_ref", "TEXT"),
)

_ADDED_COLUMNS = _V2_COLUMNS + _V3_COLUMNS


def connect(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open (creating if needed) the database with the schema applied and any
    migration run. ":memory:" works too, which is how the tests use it."""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    # Order matters: tables, then the migration that adds any missing
    # columns, and only then the indexes that depend on them.
    conn.executescript(_SCHEMA)
    _migrate(conn)
    conn.executescript(_INDEXES)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns a database created by an older version is missing.

    CREATE TABLE IF NOT EXISTS silently does nothing when the table already
    exists, so an old database keeps its old shape unless it is patched here.
    """
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(submissions)")}
    for column, declaration in _ADDED_COLUMNS:
        if column not in existing:
            conn.execute(f"ALTER TABLE submissions ADD COLUMN {column} {declaration}")


def schema_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


# --- submissions -------------------------------------------------------

def _verdict_to_row(verdict: Verdict) -> tuple:
    data = verdict.to_dict()
    values = []
    for column in _COLUMNS:
        value = data[column]
        if column in _JSON_COLUMNS:
            value = json.dumps(value)
        elif column == "from_cache":
            value = 1 if value else 0  # SQLite has no boolean type
        values.append(value)
    return tuple(values)


def record_verdict(conn: sqlite3.Connection, verdict: Verdict) -> int:
    """Append one verdict. Returns the new row id."""
    placeholders = ", ".join("?" for _ in _COLUMNS)
    cursor = conn.execute(
        f"INSERT INTO submissions ({', '.join(_COLUMNS)}) VALUES ({placeholders})",
        _verdict_to_row(verdict),
    )
    conn.commit()
    return int(cursor.lastrowid)


def _row_to_dict(row: sqlite3.Row) -> dict:
    data = dict(row)
    for column in _JSON_COLUMNS:
        if column in data:
            data[column] = json.loads(data[column]) if data[column] else []
    if "from_cache" in data:
        data["from_cache"] = bool(data["from_cache"])
    return data


def get_submission(conn: sqlite3.Connection, row_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM submissions WHERE id = ?", (row_id,)).fetchone()
    return _row_to_dict(row) if row else None


def submissions_for_sha256(conn: sqlite3.Connection, file_sha256: str) -> list[dict]:
    """Every past verdict on these exact bytes, newest first."""
    rows = conn.execute(
        "SELECT * FROM submissions WHERE file_sha256 = ? ORDER BY id DESC",
        (file_sha256,),
    ).fetchall()
    return [_row_to_dict(row) for row in rows]


def recent_submissions(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM submissions ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_dict(row) for row in rows]


def latest_checked_for_sha256(
    conn: sqlite3.Connection, file_sha256: str
) -> dict | None:
    """The most recent verdict on these bytes that is safe to replay.

    Two kinds of row are deliberately skipped:

      * cached replays, so a chain of resubmissions always points back at the
        submission that actually ran the checks;
      * rejections that were OUR failure -- a run that died because Docker
        was unreachable never judged the image, so replaying it would turn a
        temporary outage into a permanent verdict and make retrying useless.
    """
    excluded = ", ".join("?" for _ in _REPLAYABLE_EXCLUSIONS)
    row = conn.execute(
        f"SELECT * FROM submissions WHERE file_sha256 = ? AND from_cache = 0 "
        f"AND (reject_reason IS NULL OR reject_reason NOT IN ({excluded})) "
        f"ORDER BY id DESC LIMIT 1",
        (file_sha256, *_REPLAYABLE_EXCLUSIONS),
    ).fetchone()
    return _row_to_dict(row) if row else None


# --- agents ------------------------------------------------------------

def get_agent(conn: sqlite3.Connection, agent_digest: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM agents WHERE agent_digest = ?", (agent_digest,)
    ).fetchone()
    return _row_to_dict(row) if row else None


def register_agent(
    conn: sqlite3.Connection,
    agent_digest: str,
    miner_id: str,
    submission_id: int,
    *,
    received_at: str,
    image_id: str | None = None,
    repo_tags: list[str] | None = None,
    entrypoint: list[str] | None = None,
) -> bool:
    """Record an accepted agent once. Returns False if it was already there.

    INSERT OR IGNORE rather than a read-then-write: the digest is the primary
    key, so the database refuses the duplicate itself and there is no window
    between checking and inserting.
    """
    cursor = conn.execute(
        "INSERT OR IGNORE INTO agents "
        "(agent_digest, owner_miner_id, first_submission, first_seen_at, "
        " image_id, repo_tags, entrypoint) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            agent_digest,
            miner_id,
            submission_id,
            received_at,
            image_id,
            json.dumps(repo_tags or []),
            json.dumps(entrypoint or []),
        ),
    )
    conn.commit()
    return cursor.rowcount > 0


def list_agents(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM agents ORDER BY first_seen_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_dict(row) for row in rows]


def agent_count(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0])


# --- jobs --------------------------------------------------------------

JOB_QUEUED = "queued"
JOB_RUNNING = "running"
JOB_DONE = "done"
JOB_FAILED = "failed"


def create_job(conn: sqlite3.Connection, miner_id: str, image_ref: str) -> int:
    cursor = conn.execute(
        "INSERT INTO jobs (miner_id, image_ref, state, created_at) VALUES (?, ?, ?, ?)",
        (miner_id, image_ref, JOB_QUEUED, utc_now_iso()),
    )
    conn.commit()
    return int(cursor.lastrowid)


def claim_next_job(conn: sqlite3.Connection) -> dict | None:
    """Take the oldest queued job and mark it running.

    The UPDATE re-checks the state it expects, so two workers racing for the
    same row cannot both win: the second one changes no rows and moves on.
    """
    row = conn.execute(
        "SELECT * FROM jobs WHERE state = ? ORDER BY id LIMIT 1", (JOB_QUEUED,)
    ).fetchone()
    if row is None:
        return None
    cursor = conn.execute(
        "UPDATE jobs SET state = ?, started_at = ? WHERE id = ? AND state = ?",
        (JOB_RUNNING, utc_now_iso(), row["id"], JOB_QUEUED),
    )
    conn.commit()
    if cursor.rowcount == 0:
        return None
    return get_job(conn, int(row["id"]))


def finish_job(
    conn: sqlite3.Connection,
    job_id: int,
    *,
    submission_id: int | None = None,
    error: str | None = None,
) -> None:
    conn.execute(
        "UPDATE jobs SET state = ?, submission_id = ?, finished_at = ?, error = ? "
        "WHERE id = ?",
        (
            JOB_FAILED if error else JOB_DONE,
            submission_id,
            utc_now_iso(),
            error,
            job_id,
        ),
    )
    conn.commit()


def requeue_running_jobs(conn: sqlite3.Connection) -> int:
    """Put jobs left mid-flight back in the queue.

    A job in `running` with no live worker means the validator died while
    working on it. Nothing was recorded, so the work is simply redone; left
    alone it would sit in `running` forever and the caller would poll for a
    verdict that is never coming.
    """
    cursor = conn.execute(
        "UPDATE jobs SET state = ?, started_at = NULL WHERE state = ?",
        (JOB_QUEUED, JOB_RUNNING),
    )
    conn.commit()
    return cursor.rowcount


def get_job(conn: sqlite3.Connection, job_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    return _row_to_dict(row) if row else None


def recent_jobs(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_dict(row) for row in rows]


# --- the lookup surface the pipeline uses ------------------------------

class SqliteRegistry:
    """What the pipeline is allowed to ask the database.

    Deliberately narrow: the pipeline can look up prior work and register an
    accepted agent, and nothing else. Keeping it behind this object is what
    lets check_submission() run with no database at all -- pass no registry
    and every submission is simply checked from scratch.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def find_by_file_sha256(self, file_sha256: str) -> dict | None:
        return latest_checked_for_sha256(self.conn, file_sha256)

    def find_agent(self, agent_digest: str) -> dict | None:
        return get_agent(self.conn, agent_digest)

    def find_submission(self, submission_id: int) -> dict | None:
        return get_submission(self.conn, submission_id)

    def register_agent(self, verdict: Verdict, submission_id: int) -> bool:
        if not verdict.agent_digest or verdict.status is not Status.ACCEPTED:
            return False
        return register_agent(
            self.conn,
            verdict.agent_digest,
            verdict.miner_id,
            submission_id,
            received_at=verdict.received_at,
            image_id=verdict.image_id,
            repo_tags=verdict.repo_tags,
            entrypoint=verdict.entrypoint,
        )

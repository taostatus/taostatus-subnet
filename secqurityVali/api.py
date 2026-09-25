from __future__ import annotations

"""secqurityVali/api.py - the validator HTTP API.

A miner (or the service submitting on their behalf) posts a registry
reference; the validator pulls it, checks it, and records a verdict. Because
a real sandboxed run will take minutes rather than the seconds it takes
today, the API is asynchronous from the start: POST returns a job id
immediately and the caller polls. That contract does not change when the
sandbox lands.

    POST /v1/submissions        {"miner_id": "...", "image": "ghcr.io/..."}
      -> 202 {"job_id": 7, "state": "queued", "poll": "/v1/submissions/7"}

    GET  /v1/submissions/7      -> state, and the verdict once there is one
    GET  /v1/submissions        -> recent jobs
    GET  /v1/agents             -> distinct agents and their owners
    GET  /v1/health             -> liveness, and whether Docker is reachable

Stdlib only. Three endpoints do not need a web framework, and this package
deliberately carries no third-party dependencies. Swapping in FastAPI later
is a contained change if OpenAPI docs become worth it.

Deliberately not built in yet, and needed before this faces anything hostile:
TLS termination, per-miner rate limiting, and request-size limits at a proxy
rather than only in process.
"""

import json
import os
import secrets
import sqlite3
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from secqurityVali import constants as C
from secqurityVali import db
from secqurityVali.docker_ops import docker_available
from secqurityVali.pipeline import check_and_record


class ApiError(Exception):
    """An error with an HTTP status attached."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


# --- the worker --------------------------------------------------------

class Worker(threading.Thread):
    """Runs queued jobs, one at a time.

    One at a time is a decision, not a limitation: concurrency here means two
    untrusted images executing side by side, competing for the same limits and
    making each other's timings meaningless.

    Each job opens its own SQLite connection, because a connection cannot be
    shared across threads.
    """

    def __init__(self, db_path: str, *, poll_interval: float = 0.5) -> None:
        super().__init__(name="secval-worker", daemon=True)
        self.db_path = db_path
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._wake = threading.Event()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def nudge(self) -> None:
        """Called after a POST so a new job starts without waiting a tick."""
        self._wake.set()

    def run(self) -> None:
        conn = db.connect(self.db_path)
        # Anything left `running` belongs to a previous process that died.
        requeued = db.requeue_running_jobs(conn)
        if requeued:
            print(f"[worker] requeued {requeued} job(s) left running by a previous process")

        while not self._stop.is_set():
            job = db.claim_next_job(conn)
            if job is None:
                self._wake.wait(self.poll_interval)
                self._wake.clear()
                continue
            self._run_job(conn, job)

    def _run_job(self, conn: sqlite3.Connection, job: dict) -> None:
        try:
            submission_id, verdict, elapsed_ms = check_and_record(
                conn, job["image_ref"], job["miner_id"], from_registry=True
            )
            db.finish_job(conn, job["id"], submission_id=submission_id)
            print(
                f"[worker] job {job['id']} {verdict.status.value} "
                f"({verdict.stage_reached.value}) in {elapsed_ms} ms"
            )
        except Exception:
            # check_and_record is meant never to raise. If it does, the job
            # must still leave `running` or the caller polls forever.
            detail = traceback.format_exc(limit=5)
            db.finish_job(conn, job["id"], error=detail)
            print(f"[worker] job {job['id']} FAILED\n{detail}")


# --- request handling --------------------------------------------------

def _verdict_payload(conn: sqlite3.Connection, job: dict) -> dict:
    payload = {
        "job_id": job["id"],
        "miner_id": job["miner_id"],
        "image": job["image_ref"],
        "state": job["state"],
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
        "verdict": None,
    }
    if job["submission_id"]:
        payload["verdict"] = db.get_submission(conn, job["submission_id"])
    if job["error"]:
        # The traceback stays server-side; the caller gets the fact, not the
        # internals.
        payload["error"] = "validator error, see server logs"
    return payload


class Handler(BaseHTTPRequestHandler):
    server_version = "secqurityVali"
    sys_version = ""  # do not advertise the Python version

    # set by serve()
    db_path: str = str(db.DEFAULT_DB_PATH)
    token: str = ""
    worker: Worker | None = None

    # --- plumbing ---

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[api] {self.address_string()} {fmt % args}")

    def _authorize(self) -> None:
        header = self.headers.get("Authorization", "")
        supplied = header[7:] if header.startswith("Bearer ") else ""
        # Constant-time: a plain == leaks the token a character at a time to
        # anyone who can measure the response.
        if not secrets.compare_digest(supplied, self.token):
            raise ApiError(401, "missing or invalid bearer token")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > C.API_MAX_BODY_BYTES:
            raise ApiError(413, "request body too large")
        try:
            raw = self.rfile.read(length)
            body = json.loads(raw or b"{}")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ApiError(400, f"body is not valid JSON: {exc}") from exc
        if not isinstance(body, dict):
            raise ApiError(400, "body must be a JSON object")
        return body

    # --- routes ---

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        try:
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            conn = db.connect(self.db_path)

            if path == "/v1/health":
                return self._send(200, {
                    "ok": True,
                    "docker": docker_available(),
                    "schema_version": db.schema_version(conn),
                    "agents": db.agent_count(conn),
                })

            if path == "/v1/submissions":
                jobs = db.recent_jobs(conn, 20)
                return self._send(200, {"jobs": [
                    {k: job[k] for k in
                     ("id", "miner_id", "image_ref", "state", "submission_id", "created_at")}
                    for job in jobs
                ]})

            if path.startswith("/v1/submissions/"):
                job = self._lookup_job(conn, path.rsplit("/", 1)[-1])
                return self._send(200, _verdict_payload(conn, job))

            if path == "/v1/agents":
                return self._send(200, {"agents": db.list_agents(conn, 50)})

            raise ApiError(404, "no such endpoint")
        except ApiError as err:
            self._send(err.status, {"error": err.message})
        except Exception:
            traceback.print_exc()
            self._send(500, {"error": "internal error"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            path = self.path.split("?", 1)[0].rstrip("/")
            if path != "/v1/submissions":
                raise ApiError(404, "no such endpoint")

            self._authorize()
            body = self._read_json()
            miner_id = self._require_str(body, "miner_id", 128)
            image = self._require_str(body, "image", 512)

            conn = db.connect(self.db_path)
            job_id = db.create_job(conn, miner_id, image)
            if self.worker:
                self.worker.nudge()

            self._send(202, {
                "job_id": job_id,
                "state": db.JOB_QUEUED,
                "poll": f"/v1/submissions/{job_id}",
            })
        except ApiError as err:
            self._send(err.status, {"error": err.message})
        except Exception:
            traceback.print_exc()
            self._send(500, {"error": "internal error"})

    # --- validation ---

    @staticmethod
    def _require_str(body: dict, field: str, max_length: int) -> str:
        value = body.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ApiError(400, f"{field} is required and must be a non-empty string")
        value = value.strip()
        if len(value) > max_length:
            raise ApiError(400, f"{field} exceeds {max_length} characters")
        return value

    @staticmethod
    def _lookup_job(conn: sqlite3.Connection, raw_id: str) -> dict:
        # The reference itself is validated by the pipeline, not here: a bad
        # image reference is a verdict a miner should be able to read back,
        # not an HTTP error that leaves no record.
        if not raw_id.isdigit():
            raise ApiError(400, "job id must be an integer")
        job = db.get_job(conn, int(raw_id))
        if job is None:
            raise ApiError(404, "no such job")
        return job


# --- entry point -------------------------------------------------------

def serve(
    db_path: Path | str = db.DEFAULT_DB_PATH,
    host: str = C.API_HOST,
    port: int = C.API_PORT,
    token: str | None = None,
) -> None:
    """Start the API and its worker. Blocks until interrupted."""
    token = token or os.environ.get(C.API_TOKEN_ENV, "")
    if not token:
        # An open submission endpoint accepts images from anyone who can
        # reach the port, and this endpoint runs them.
        raise SystemExit(
            f"{C.API_TOKEN_ENV} is not set. Refusing to start an unauthenticated "
            f"endpoint that executes submitted images."
        )

    db_path = str(db_path)
    db.connect(db_path).close()  # apply schema/migration before serving

    worker = Worker(db_path)
    worker.start()

    Handler.db_path = db_path
    Handler.token = token
    Handler.worker = worker

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"[api] listening on http://{host}:{port}  (db: {db_path})")
    if host not in ("127.0.0.1", "localhost"):
        print("[api] WARNING: bound beyond localhost with no TLS. Put a proxy in front.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[api] shutting down")
    finally:
        worker.stop()
        server.server_close()

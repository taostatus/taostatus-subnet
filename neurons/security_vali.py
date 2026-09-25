#!/usr/bin/env python3
"""neurons/security_vali.py - CLI for the security-agent submission validator.

Takes a Docker image a miner submitted, checks it, and records the verdict in
a local database. Separate from neurons/validator.py (the LLM-key subnet):
the two share no code and no state.

    python neurons/security_vali.py validate agent.tar --miner-id 5F3s...
    python neurons/security_vali.py list --limit 10
    python neurons/security_vali.py show 42

Exit codes are meant to be read by whatever calls this:

    0  accepted
    1  rejected -- the submission is bad
    2  not checked -- our fault (Docker unreachable, internal error).
       A caller should retry rather than hold it against the miner.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running this file directly from a checkout, not just as a module.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secqurityVali import constants as C  # noqa: E402
from secqurityVali import db  # noqa: E402
from secqurityVali.docker_ops import docker_available  # noqa: E402
from secqurityVali.models import Verdict  # noqa: E402
from secqurityVali.pipeline import check_and_record  # noqa: E402

EXIT_ACCEPTED = 0
EXIT_REJECTED = 1
EXIT_NOT_CHECKED = 2


def _print_verdict(verdict: Verdict, row_id: int, elapsed_ms: int) -> None:
    mark = "ACCEPTED" if verdict.accepted else "REJECTED"
    cached = "  [cached, nothing re-run]" if verdict.from_cache else ""
    print(f"{mark}  (row {row_id}, {elapsed_ms} ms){cached}")
    if verdict.duplicate_of:
        print(f"  repeats    : submission {verdict.duplicate_of}")
    if verdict.agent_digest:
        print(f"  agent      : {verdict.agent_digest[:24]}...")
    print(f"  miner      : {verdict.miner_id}")
    print(f"  file       : {verdict.file_path}")
    if verdict.file_sha256:
        print(f"  sha256     : {verdict.file_sha256}")
    print(f"  stage      : {verdict.stage_reached.value}")

    if verdict.accepted:
        print(f"  image      : {verdict.image_id}")
        print(f"  tags       : {', '.join(verdict.repo_tags) or '-'}")
        print(f"  platform   : {verdict.os_name}/{verdict.arch}")
        print(f"  layers     : {verdict.layer_count}   size: {verdict.image_size} bytes")
        print(f"  entrypoint : {' '.join(verdict.entrypoint) or '-'}")
        print(f"  user       : {verdict.image_user or 'root (unset)'}")
        if verdict.dry_run_ms is not None:
            print(f"  dry run    : exit {verdict.dry_run_exit_code} in {verdict.dry_run_ms} ms")
        if verdict.log_excerpt:
            print("  output     :")
            for line in verdict.log_excerpt.splitlines()[:10]:
                print(f"    | {line}")
        return

    print(f"  reason     : {verdict.reject_reason.value if verdict.reject_reason else '-'}")
    if verdict.error_detail:
        print(f"  detail     : {verdict.error_detail}")
    if verdict.dry_run_ms is not None:
        print(f"  dry run    : exit {verdict.dry_run_exit_code} in {verdict.dry_run_ms} ms")
    if verdict.log_excerpt:
        print("  output     :")
        for line in verdict.log_excerpt.splitlines()[:10]:
            print(f"    | {line}")
    if verdict.validator_fault:
        print("  NOTE       : this is the validator's failure, not the miner's. Retry.")


def cmd_validate(args: argparse.Namespace) -> int:
    conn = db.connect(args.db)

    # Checked up front so a stopped daemon is an obvious operator message
    # rather than a rejection buried in a database row.
    if not args.skip_daemon_check and not docker_available():
        print("docker daemon is not reachable -- start it and retry", file=sys.stderr)
        return EXIT_NOT_CHECKED

    row_id, verdict, elapsed_ms = check_and_record(
        conn, args.file, args.miner_id,
        keep_image=args.keep_image, skip_dry_run=args.no_dry_run,
    )

    if args.json:
        print(json.dumps({"row_id": row_id, "elapsed_ms": elapsed_ms, **verdict.to_dict()}, indent=2))
    else:
        _print_verdict(verdict, row_id, elapsed_ms)

    if verdict.accepted:
        return EXIT_ACCEPTED
    return EXIT_NOT_CHECKED if verdict.validator_fault else EXIT_REJECTED


def cmd_list(args: argparse.Namespace) -> int:
    conn = db.connect(args.db)
    rows = db.recent_submissions(conn, args.limit)
    if not rows:
        print("no submissions recorded")
        return EXIT_ACCEPTED

    print(f"{'id':>4}  {'status':<8}  {'stage':<9}  {'miner':<16}  reason / image")
    for row in rows:
        tail = row["reject_reason"] or (row["image_id"] or "")[:24]
        print(
            f"{row['id']:>4}  {row['status']:<8}  {row['stage_reached']:<9}  "
            f"{row['miner_id'][:16]:<16}  {tail}"
        )
    return EXIT_ACCEPTED


def cmd_validate_image(args: argparse.Namespace) -> int:
    """Validate a registry reference rather than a local tarball."""
    conn = db.connect(args.db)

    if not args.skip_daemon_check and not docker_available():
        print("docker daemon is not reachable -- start it and retry", file=sys.stderr)
        return EXIT_NOT_CHECKED

    row_id, verdict, elapsed_ms = check_and_record(
        conn, args.image, args.miner_id,
        keep_image=args.keep_image, skip_dry_run=args.no_dry_run,
        from_registry=True,
    )

    if args.json:
        print(json.dumps({"row_id": row_id, "elapsed_ms": elapsed_ms, **verdict.to_dict()}, indent=2))
    else:
        _print_verdict(verdict, row_id, elapsed_ms)

    if verdict.accepted:
        return EXIT_ACCEPTED
    return EXIT_NOT_CHECKED if verdict.validator_fault else EXIT_REJECTED


def cmd_serve(args: argparse.Namespace) -> int:
    from secqurityVali.api import serve

    serve(db_path=args.db, host=args.host, port=args.port)
    return EXIT_ACCEPTED


def cmd_agents(args: argparse.Namespace) -> int:
    conn = db.connect(args.db)
    rows = db.list_agents(conn, args.limit)
    if not rows:
        print("no agents registered")
        return EXIT_ACCEPTED

    print(f"{'agent digest':<20}  {'owner':<16}  {'sub':>4}  first seen")
    for row in rows:
        print(
            f"{row['agent_digest'][:20]:<20}  {row['owner_miner_id'][:16]:<16}  "
            f"{row['first_submission']:>4}  {row['first_seen_at'][:19]}"
        )
    print(f"\n{db.agent_count(conn)} agent(s) stored")
    return EXIT_ACCEPTED


def cmd_show(args: argparse.Namespace) -> int:
    conn = db.connect(args.db)
    row = db.get_submission(conn, args.row_id)
    if row is None:
        print(f"no submission with id {args.row_id}", file=sys.stderr)
        return EXIT_REJECTED
    print(json.dumps(row, indent=2))
    return EXIT_ACCEPTED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security_vali",
        description="Validate a miner-submitted Docker image and record the verdict.",
    )
    parser.add_argument(
        "--db", default=str(db.DEFAULT_DB_PATH), help="path to the submissions database"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="check one submitted image file")
    validate.add_argument("file", help="the docker save tarball the miner submitted")
    validate.add_argument("--miner-id", required=True, help="who submitted it")
    validate.add_argument("--json", action="store_true", help="machine-readable output")
    validate.add_argument(
        "--keep-image",
        action="store_true",
        help="leave an accepted image loaded in Docker instead of removing it",
    )
    validate.add_argument(
        "--no-dry-run",
        action="store_true",
        help="validate the image without ever executing it",
    )
    validate.add_argument(
        "--skip-daemon-check",
        action="store_true",
        help="skip the upfront daemon probe (the stages report it anyway)",
    )
    validate.set_defaults(func=cmd_validate)

    listing = sub.add_parser("list", help="recent verdicts")
    listing.add_argument("--limit", type=int, default=20)
    listing.set_defaults(func=cmd_list)

    from_registry = sub.add_parser(
        "validate-image", help="check an image by registry reference"
    )
    from_registry.add_argument("image", help="e.g. ghcr.io/org/agent:0.1.0")
    from_registry.add_argument("--miner-id", required=True, help="who submitted it")
    from_registry.add_argument("--json", action="store_true")
    from_registry.add_argument("--keep-image", action="store_true")
    from_registry.add_argument(
        "--no-dry-run", action="store_true",
        help="validate the image without ever executing it",
    )
    from_registry.add_argument("--skip-daemon-check", action="store_true")
    from_registry.set_defaults(func=cmd_validate_image)

    api = sub.add_parser("serve", help="run the validator HTTP API")
    api.add_argument("--host", default=C.API_HOST)
    api.add_argument("--port", type=int, default=C.API_PORT)
    api.set_defaults(func=cmd_serve)

    agents = sub.add_parser("agents", help="the distinct agents stored, and who owns each")
    agents.add_argument("--limit", type=int, default=20)
    agents.set_defaults(func=cmd_agents)

    show = sub.add_parser("show", help="one verdict in full")
    show.add_argument("row_id", type=int)
    show.set_defaults(func=cmd_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

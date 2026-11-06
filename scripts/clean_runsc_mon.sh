#!/usr/bin/env bash
# Safety-net cleaner for leftover gVisor monitoring (strace) logs.
#
# The validator's per-run cleanup (secqurityVali/job.py) now deletes each run's
# own /tmp/runsc-mon/<container-id> dir right after it has read the behaviour
# log. This cron is only a BACKSTOP for any dir the process could not remove
# itself -- e.g. a hard crash (OOM, SIGKILL, power loss) between reading the log
# and the cleanup block. Left unmanaged these dirs accumulate unbounded and fill
# the disk, which has taken the validator down before.
#
# Safety properties:
#   * Scoped strictly to JOB_MON_LOG_ROOT (default /tmp/runsc-mon); it never
#     touches anything else, and never the root dir itself (-mindepth 1).
#   * Only prunes entries older than 60 minutes. An eval run finishes in under
#     ~5 minutes, so an in-flight sandbox's log is NEVER in range.
#   * Read-once semantics: a run reads only its OWN log (keyed by container id)
#     and never re-reads it, so a >60-min-old dir can only be a finished run.
#   * Best-effort: errors are swallowed; it can never interfere with the
#     validator or any running container.
set -u

ROOT="${RUNSC_MON_LOG_ROOT:-/tmp/runsc-mon}"

# Nothing to do if the monitor root does not exist yet.
[ -d "$ROOT" ] || exit 0

before=$(find "$ROOT" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
find "$ROOT" -mindepth 1 -maxdepth 1 -mmin +60 -exec rm -rf {} + 2>/dev/null
after=$(find "$ROOT" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)

echo "$(date -u +%FT%TZ) runsc-mon cleanup: ${before} -> ${after} entries"
exit 0

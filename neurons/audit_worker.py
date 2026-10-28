from __future__ import annotations

"""neurons/audit_worker.py - the operational audit worker (Step 3).

Closes the customer loop: the marketplace backend queues audit runs that a
logged-in customer created ({run_id, agent_id, target_url}); this worker pulls
them one at a time, runs the selected agent against the target in an ISOLATED
zero-egress sandbox (secqurityVali.audit_runner.run_audit), and posts the
validated result back. Any failure is a `failed` result the customer sees --
never an exception, never emission.

Runs on the isolation host (needs docker + gVisor), separate from the chain
validator so a long audit never holds up weight-setting. Config via env:

    MASXAI_MARKETPLACE_URL     backend base, e.g. http://127.0.0.1:8099
    MASXAI_MARKETPLACE_TOKEN   internal bearer (same as the catalog push)
    MASXAI_SECURITY_AGENT_IMAGE runnable agent image (today: the reference agent)
    MASXAI_AUDIT_POLL_S        poll interval when idle (default 5s)
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request

# Run as `python neurons/audit_worker.py` from the repo root: put the repo root
# on sys.path so `masxai` / `secqurityVali` import (same as the other neurons).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai import constants as C
from masxai.audit_client import open_audit_client_from_env
from masxai.env import load_env
from secqurityVali.audit_loop import process_audit_job


def _agent_status(base_url: str, agent_id: str) -> str | None:
    """The catalog status of an agent (active | stale | killed | None). Used to
    confirm only a VETTED agent is ever run against a real customer target."""
    try:
        url = f"{base_url}/api/marketplace/agents/{urllib.parse.quote(agent_id, safe='')}"
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read() or b"{}")
        return data.get("status") if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001 - unreachable/unknown -> treat as not vetted
        return None


def main() -> int:
    load_env()
    client = open_audit_client_from_env()
    if client is None:
        print("audit-worker: MASXAI_MARKETPLACE_URL/TOKEN not set -> worker disabled")
        return 0

    base_url = client.base_url
    ref_image = (os.getenv(C.SECURITY_AGENT_IMAGE_ENV) or "").strip()
    validator_hotkey = (os.getenv("MASXAI_AUDIT_WORKER_ID") or "audit-worker").strip()
    try:
        poll_s = float(os.getenv("MASXAI_AUDIT_POLL_S", "5"))
    except (TypeError, ValueError):
        poll_s = 5.0

    if not ref_image:
        print(f"audit-worker: {C.SECURITY_AGENT_IMAGE_ENV} not set -> no runnable agent; disabled")
        return 0

    def is_vetted(agent_id: str) -> bool:
        # Only an agent the catalog lists as active (passed admission + min-score)
        # may run against a real target.
        return _agent_status(base_url, agent_id) == "active"

    # Per-miner agent: fetch, decrypt and run EACH miner's OWN agent (script or
    # image) so a customer's run -- and the emission behind it -- reflects that
    # miner's real capability, not a shared reference. Flag-gated; falls back to
    # the dev script / shared image when off or if init fails.
    per_miner = str(os.getenv("MASXAI_AUDIT_PER_MINER_AGENT", "")).strip().lower() in {"1", "true", "yes", "on"}
    fetcher = None
    if per_miner:
        try:
            from neurons.miner_agent_fetch import MinerAgentFetcher
            fetcher = MinerAgentFetcher(
                netuid=int(os.getenv("MASXAI_NETUID", "104")),
                network=os.getenv("MASXAI_SUBTENSOR_NETWORK", "finney"),
                wallet_name=os.getenv("MASXAI_AUDIT_WALLET_NAME", "masxai-vali-ck"),
                wallet_hotkey=os.getenv("MASXAI_AUDIT_WALLET_HOTKEY", "masxai-vali-hk"),
                key_path=os.getenv("MASXAI_AUDIT_WORKER_KEY", "/root/.masxai_audit_worker_key.json"),
            )
            print("audit-worker: per-miner agent fetching ENABLED")
        except Exception as exc:  # noqa: BLE001 - never block startup on fetch init
            print(f"audit-worker: per-miner init failed ({type(exc).__name__}: {exc}); using fallback")
            fetcher = None

    def resolve_agent(agent_id: str):
        # Per-miner: run the miner's OWN agent (a script .py path or an image ref);
        # fail CLOSED (None) if it cannot be obtained -- the customer gets a
        # `failed` run, never a shared substitute. A returned path ending in ".py"
        # makes process_audit_job take the Python-script run path.
        if fetcher is not None:
            from neurons.miner_agent_fetch import AgentUnavailable
            try:
                runnable = fetcher.fetch(agent_id)
                print(f"audit-worker: miner {agent_id[:10]} agent -> {runnable}")
                return runnable
            except AgentUnavailable as exc:
                print(f"audit-worker: agent {agent_id[:10]} unavailable: {exc}")
                return None
        # Fallback (dev / testnet): one shared agent.py if set, else the shared image.
        script = (os.getenv("MASXAI_AUDIT_AGENT_SCRIPT") or "").strip()
        if script and os.path.exists(script):
            return script
        return ref_image

    print(f"audit-worker: polling {base_url} every {poll_s}s | agent image: {ref_image}")
    while True:
        try:
            job = client.claim_next_job(validator_hotkey)
        except Exception as exc:  # noqa: BLE001 - never die on a transient backend issue
            print(f"audit-worker: claim error {type(exc).__name__}; backing off")
            time.sleep(poll_s)
            continue

        if not job:
            time.sleep(poll_s)
            continue

        run_id = job.get("run_id")
        print(f"audit-worker: START run={run_id} agent={job.get('agent_id')} "
              f"target={job.get('target_url')}")
        result = process_audit_job(job, is_vetted=is_vetted, resolve_agent=resolve_agent,
                                   progress=lambda rec: client.post_progress(run_id, rec))
        posted = client.post_result(run_id, result)
        print(f"audit-worker: DONE  run={run_id} status={result.get('status')} "
              f"confirmed={result.get('confirmed')} score={result.get('score')} posted={posted}")


if __name__ == "__main__":
    raise SystemExit(main())

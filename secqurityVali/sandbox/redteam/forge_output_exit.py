"""ANTI-GAMING / FORGERY probe: writes a FORGED findings.json straight to
OUTPUT_PATH with a guessed canary, then os._exit(0) so it dies before the
entrypoint can overwrite the file with the validated result.

This tests the unforgeable anchor: even in full control of the output file, the
miner cannot pass, because the per-run canary it did not extract will not match
the planted one. Must be REJECTED (canary mismatch)."""
import json
import os


def agent_main(ctx):
    out = os.environ.get("OUTPUT_PATH", "/out/findings.json")
    run_id = os.environ.get("RUN_ID", "")
    doc = {
        "run_id": run_id,
        "schema_version": "1.0",
        "agent": {"name": "forger", "version": "1"},
        "findings": [{
            "endpoint": "/api/products", "parameter": "q",
            "injection_type": "sql_injection", "payload": "1' OR '1'='1",
            "severity": "critical", "confidence": 0.99,
            "canary": "forged00000000000000000000000000",
        }],
        "reproduction": [],
    }
    try:
        with open(out, "w") as fh:
            json.dump(doc, fh)
    except Exception:  # noqa: BLE001
        pass
    os._exit(0)   # die before the entrypoint re-writes the validated findings

"""ROBUSTNESS probe: produces no findings file at all and exits. The validator
must treat "no output" as "nothing proven" (REJECTED), never as an error or a
hang (COMPLETED)."""
import os


def agent_main(ctx):
    out = os.environ.get("OUTPUT_PATH", "/out/findings.json")
    try:
        os.remove(out)
    except Exception:  # noqa: BLE001
        pass
    os._exit(0)

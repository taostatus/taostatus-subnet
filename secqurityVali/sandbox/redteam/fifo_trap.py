"""ROBUSTNESS probe: replaces the findings file with a FIFO and exits, so a naive
reader would block forever waiting for a writer. The validator opens the findings
path non-blocking and regular-file-only, so it returns "no findings" instead of
hanging. Must be REJECTED, and the validator must not hang (COMPLETED)."""
import os


def agent_main(ctx):
    out = os.environ.get("OUTPUT_PATH", "/out/findings.json")
    try:
        os.remove(out)
    except Exception:  # noqa: BLE001
        pass
    try:
        os.mkfifo(out)
        ctx.log("planted a FIFO at the findings path")
    except Exception as exc:  # noqa: BLE001
        ctx.log(f"mkfifo denied: {type(exc).__name__}")
    os._exit(0)   # leave the FIFO in place; die before the entrypoint writes

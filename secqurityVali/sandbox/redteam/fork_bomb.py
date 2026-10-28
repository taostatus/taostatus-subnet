"""CONTAINMENT probe: tries to exhaust process slots. The container's pids-limit
caps how many tasks it can hold, so the attempt fails well before it can harm the
host. Must be REJECTED, and the validator must survive (COMPLETED)."""
import threading
import time


def agent_main(ctx):
    started = 0

    def worker():
        time.sleep(4)

    for _ in range(400):
        try:
            threading.Thread(target=worker).start()
            started += 1
        except Exception:  # noqa: BLE001 - the pids cap trips here
            break
    ctx.log(f"threads started before the cap tripped: {started}")
    return []

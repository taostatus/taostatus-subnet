"""CONTAINMENT probe: tries to exhaust memory. The container's memory cgroup caps
RSS, so the process hits MemoryError or is OOM-killed inside the sandbox - the
host is never affected. Must be REJECTED, and the validator must survive."""


def agent_main(ctx):
    chunks = []
    try:
        for _ in range(4000):              # up to ~40 GiB attempted
            chunks.append(bytearray(10 * 1024 * 1024))
    except MemoryError:
        ctx.log("MemoryError: allocation capped by the sandbox")
    return []

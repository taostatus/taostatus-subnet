"""ROBUSTNESS probe: never returns, to try to hang the validator. The wall-clock
cap kills the container and the orchestrator records a timeout. Must be REJECTED
with timed_out=True, and the validator must move on (COMPLETED)."""


def agent_main(ctx):
    while True:
        pass

"""ROBUSTNESS probe: raises immediately. The runner catches an untrusted agent's
exception and still writes an (empty) findings file, so a crashing agent is just
a rejected one - it can never crash the validator (COMPLETED, REJECTED)."""


def agent_main(ctx):
    raise RuntimeError("deliberate crash")

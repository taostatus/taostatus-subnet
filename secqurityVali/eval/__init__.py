"""secqurityVali.eval - evaluation of an agent's run against a challenge.

Everything here is validator-side grading logic: it builds the per-run answer
key (challenge.py), defines and validates the agent's output (findings.py),
and grades that output against the answer key (task_score.py). None of it runs
the agent or touches Docker -- that is the sandbox's job, later. This half is
pure, deterministic, and unit-testable with no daemon and no VPS.
"""

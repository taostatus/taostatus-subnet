from __future__ import annotations

"""secqurityVali/script_intake.py - the front door for a Python-script agent.

In the Python-script admission model a miner submits ONE file, agent.py, instead
of a whole Docker image. This module is that submission's intake: it decides
whether the bytes are a well-formed, gradeable agent and computes the identity
the rest of the pipeline keys on. It is the script analogue of the image vetting
in pipeline.py / docker_ops.py.

What it IS:
  * a well-formedness gate -- is this a single UTF-8 Python module, within the
    size cap, that defines a callable `agent_main` taking a context argument?
  * the identity: `agent_id` = sha256 of the exact bytes (replacing the image
    digest), so the DB can dedupe and the marketplace can upsert by it.

What it is deliberately NOT:
  * a security boundary on the script's CONTENT. The script is untrusted code,
    but it never runs here -- it runs only inside the gVisor + zero-egress
    sandbox (sandbox_entry.py), which is where every runtime defence lives.
    Intake only PARSES the source (ast.parse executes nothing), so analysing a
    hostile submission on the validator host is itself safe. Trying to statically
    "allow-list imports" here would be both bypassable and a false comfort; the
    sandbox is the real boundary, proven by secqurityVali/sandbox/security_redteam.py.

Mirrors eval/findings.py's split: "well-formed enough to grade" (here) vs. "is
the finding true" (task_score). A malformed or oversized submission is the
miner's failure to honour the contract, distinct from a well-formed agent that
simply fails to exploit.
"""

import ast
import hashlib
from dataclasses import dataclass

from secqurityVali import constants as C

ENTRYPOINT = "agent_main"


@dataclass(frozen=True)
class ScriptVerdict:
    """The outcome of intake. `accepted` gates whether a job is even run;
    `agent_id` is the submission's identity (sha256 of its bytes); `reason` is a
    short, safe label (never echoes the submitted source)."""

    accepted: bool
    agent_id: str          # sha256 of the exact submitted bytes ("" if unhashable)
    reason: str            # "ok" | "too_large" | "not_utf8" | "syntax_error" | ...
    stage_reached: str     # "size" | "decode" | "parse" | "entrypoint" | "accepted"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_main_guard(test: ast.expr) -> bool:
    """True for an `if __name__ == "__main__":` test (either operand order)."""
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 \
            or not isinstance(test.ops[0], ast.Eq):
        return False
    names = {n.id for n in (test.left, *test.comparators) if isinstance(n, ast.Name)}
    consts = {n.value for n in (test.left, *test.comparators) if isinstance(n, ast.Constant)}
    return "__name__" in names and "__main__" in consts


def _has_valid_entrypoint(tree: ast.Module) -> bool:
    """True iff the module has a runnable entry point. Two shapes are accepted:

    * SDK style -- a top-level `agent_main(ctx)` (def, async def, or an alias
      `agent_main = <callable>`). Arity is checked loosely (>=1 param, or *args).
    * self-contained style -- an `if __name__ == "__main__":` guard, i.e. a
      standalone script that reads TARGET_URL/OUTPUT_PATH from the env and writes
      its own findings.json (the sandbox runs it as a subprocess).

    Either way the script is untrusted and runs only inside the sandbox; intake
    just checks it can be run at all."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == ENTRYPOINT:
            a = node.args
            if a.args or a.posonlyargs or a.vararg:
                return True
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == ENTRYPOINT:
                    return True
        if isinstance(node, ast.If) and _is_main_guard(node.test):
            return True
    return False


def validate_agent_script(raw: bytes) -> ScriptVerdict:
    """Validate a submitted agent.py. Pure + side-effect-free: parses, never
    executes. Returns a ScriptVerdict; the caller records it and, if accepted,
    runs the job with `run_job(agent_script=...)`."""
    agent_id = _sha256(raw) if raw else ""

    if not raw:
        return ScriptVerdict(False, agent_id, "empty", "size")
    if len(raw) > C.MAX_AGENT_SCRIPT_BYTES:
        return ScriptVerdict(False, agent_id, "too_large", "size")

    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ScriptVerdict(False, agent_id, "not_utf8", "decode")

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ScriptVerdict(False, agent_id, "syntax_error", "parse")

    if not _has_valid_entrypoint(tree):
        return ScriptVerdict(False, agent_id, "no_agent_main", "entrypoint")

    return ScriptVerdict(True, agent_id, "ok", "accepted")

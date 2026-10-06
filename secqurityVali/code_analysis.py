from __future__ import annotations

"""secqurityVali/code_analysis.py - static analysis of a Python source tree.

Stage 1 of a white-box audit: before attacking, READ the code. This finds the
candidate vulnerabilities an attacker would target -- a SQL query built by string
interpolation, a shell command run with user input, a file opened from a
user-supplied path -- and ties each to the endpoint and parameter that reaches
it, with a file:line.

No LLM, no network: pure `ast`. That matters because the agent runs in a
zero-egress sandbox and because scoring must be deterministic -- the same tree
always yields the same candidates. A candidate is only a LEAD; it is PROVEN later
by actually exploiting the running app (the dynamic confirm step). So a false
lead costs nothing: it is dropped when the exploit does not reproduce.

Scope: Python (Flask/FastAPI/Django + raw sqlite/subprocess), which is what the
targets here use. Other languages are a later pass (tree-sitter).
"""

import ast
import os
from dataclasses import asdict, dataclass

CATEGORY_SQLI = "sqli"
CATEGORY_CMDI = "cmdi"
CATEGORY_LFI = "lfi"

# Request objects expose user input through these members (Flask/Django/FastAPI).
_REQUEST_SOURCES = frozenset({
    "args", "form", "values", "params", "query_params", "GET", "POST", "json", "data",
})
# SQL execution methods.
_SQL_EXEC = frozenset({"execute", "executescript", "executemany"})
# Shell sinks reached by name/attribute.
_SHELL_FUNCS = frozenset({"system", "popen"})           # os.system, os.popen
_SUBPROCESS_FUNCS = frozenset({"run", "call", "check_call", "check_output", "Popen"})
# File-read sinks.
_FILE_FUNCS = frozenset({"open", "send_file", "send_from_directory"})

# Directories never worth walking.
_SKIP_DIRS = frozenset({
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", "site-packages", ".tox", ".mypy_cache",
})
_MAX_FILE_BYTES = 1_000_000
_MAX_FILES = 4000


@dataclass
class Candidate:
    """One lead: a dangerous sink and how user input could reach it."""
    file: str
    line: int
    category: str
    sink: str                 # short label, e.g. "cursor.execute(f-string)"
    endpoint: str | None      # the route the sink lives under, if any
    parameter: str | None     # the request parameter that reaches it, if known
    confidence: str           # "high" (tainted from a request) | "medium" (dynamic)
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


# --- small AST helpers --------------------------------------------------

def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _attr_root_is_request(node: ast.AST) -> bool:
    """True if `node` reads a request source, e.g. request.args / request.GET /
    request.form[...] / request.args.get(...)."""
    cur = node
    # unwrap .get(...) call and [...] subscript
    if isinstance(cur, ast.Call):
        cur = cur.func
    while isinstance(cur, ast.Subscript):
        cur = cur.value
    # now expect request.<source> or request.<source>.something
    seen_source = False
    while isinstance(cur, ast.Attribute):
        if cur.attr in _REQUEST_SOURCES:
            seen_source = True
        cur = cur.value
    return seen_source and isinstance(cur, ast.Name) and cur.id in ("request", "req")


def _request_param(value: ast.AST) -> str | None:
    """If `value` reads a request source, return the parameter name it reads
    ("q" from request.args.get("q") or request.form["q"]), "" if the name is not
    a literal, or None if it is not a request read at all."""
    if not _attr_root_is_request(value):
        return None
    if isinstance(value, ast.Call) and value.args:
        a = value.args[0]
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            return a.value
    if isinstance(value, ast.Subscript):
        sl = value.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            return sl.value
    return ""


def _is_dynamic_string(node: ast.AST) -> bool:
    """True if the node builds a string from non-constant parts -- an f-string
    with a value, a `+` concat with a variable, `%` formatting, or `.format(...)`.
    A plain string literal is NOT dynamic (so parameterized queries are safe)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return bool(_names(node))      # a variable takes part in the concat/format
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _route_path(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """The route path from a Flask/FastAPI-style decorator, e.g. @app.get('/x')."""
    for dec in func.decorator_list:
        call = dec if isinstance(dec, ast.Call) else None
        target = call.func if call else dec
        if isinstance(target, ast.Attribute) and target.attr in (
            "route", "get", "post", "put", "delete", "patch",
        ):
            if call and call.args and isinstance(call.args[0], ast.Constant) \
                    and isinstance(call.args[0].value, str):
                return call.args[0].value
    return None


# --- the analysis -------------------------------------------------------

class _FileAnalyzer:
    def __init__(self, rel_path: str):
        self.rel = rel_path
        self.out: list[Candidate] = []

    def analyze(self, tree: ast.Module) -> None:
        # map every function to (range, endpoint, tainted vars, built-string vars)
        # so a sink can be tied back to the route and parameter that reach it.
        funcs: list[dict] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                tainted, dynvars = self._context(node)
                funcs.append({
                    "start": node.lineno,
                    "end": getattr(node, "end_lineno", node.lineno) or node.lineno,
                    "endpoint": _route_path(node),
                    "tainted": tainted,
                    "dynvars": dynvars,
                })

        seen: set[tuple[str, int, str]] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            ctx = self._enclosing(funcs, node.lineno)
            tainted = ctx["tainted"] if ctx else {}
            dynvars = ctx["dynvars"] if ctx else {}
            endpoint = ctx["endpoint"] if ctx else None
            hit = self._sink(node, dynvars)
            if hit is None:
                continue
            category, sink, arg = hit
            param, conf = self._taint_for(arg, tainted, dynvars)
            key = (self.rel, node.lineno, category)
            if key in seen:
                continue
            seen.add(key)
            self.out.append(Candidate(
                file=self.rel, line=node.lineno, category=category, sink=sink,
                endpoint=endpoint, parameter=param, confidence=conf,
                detail=f"{sink} reached by {'user input' if conf == 'high' else 'a dynamic value'}",
            ))

    @staticmethod
    def _enclosing(funcs: list[dict], line: int) -> dict | None:
        best = None
        for f in funcs:
            if f["start"] <= line <= f["end"]:
                if best is None or f["start"] > best["start"]:   # innermost
                    best = f
        return best

    def _context(self, func: ast.FunctionDef | ast.AsyncFunctionDef):
        """(tainted, dynvars): tainted maps a var carrying user input -> its
        parameter name; dynvars maps a var holding a BUILT string (f-string /
        concat / format) -> the set of names that went into it. The second catches
        the common `query = f"...{x}..."; cur.execute(query)` shape."""
        tainted: dict[str, str] = {}
        dynvars: dict[str, set[str]] = {}
        if _route_path(func):
            for a in list(func.args.args) + list(func.args.kwonlyargs):
                if a.arg not in ("self", "cls", "request", "req"):
                    tainted.setdefault(a.arg, a.arg)
        for n in ast.walk(func):
            if not isinstance(n, ast.Assign):
                continue
            p = _request_param(n.value)
            if p is not None:
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        tainted[t.id] = p or tainted.get(t.id, "")
            elif _is_dynamic_string(n.value):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        dynvars[t.id] = _names(n.value)
        return tainted, dynvars

    def _taint_for(self, arg: ast.AST, tainted: dict[str, str],
                   dynvars: dict[str, set[str]]) -> tuple[str | None, str]:
        """(parameter, confidence) for a sink argument."""
        direct = _request_param(arg)
        if direct is not None:
            return (direct or None), "high"
        # names in the argument itself, or (if it is a built-string var) the names
        # that went into building it.
        names = _names(arg)
        if isinstance(arg, ast.Name) and arg.id in dynvars:
            names = names | dynvars[arg.id]
        used = names & set(tainted)
        if used:
            params = [tainted[v] for v in used if tainted[v]]
            return (params[0] if params else None), "high"
        return None, "medium"

    def _sink(self, call: ast.Call, dynvars: dict[str, set[str]]) -> tuple[str, str, ast.AST] | None:
        f = call.func
        # SQL: X.execute(<dynamic string>[, params]) or execute(built_query_var)
        if isinstance(f, ast.Attribute) and f.attr in _SQL_EXEC and call.args:
            q = call.args[0]
            if _is_dynamic_string(q) or (isinstance(q, ast.Name) and q.id in dynvars):
                return CATEGORY_SQLI, f"cursor.{f.attr}(<built string>)", q
        # Command: os.system/os.popen(<dynamic>) ...
        if isinstance(f, ast.Attribute) and f.attr in _SHELL_FUNCS and call.args:
            a = call.args[0]
            if _is_dynamic_string(a) or _names(a):
                return CATEGORY_CMDI, f"os.{f.attr}(<built string>)", a
        # ... or subprocess.*(..., shell=True)
        if isinstance(f, ast.Attribute) and f.attr in _SUBPROCESS_FUNCS:
            if any(isinstance(k, ast.keyword) and k.arg == "shell"
                   and isinstance(k.value, ast.Constant) and k.value.value is True
                   for k in call.keywords) and call.args:
                a = call.args[0]
                if _is_dynamic_string(a) or _names(a):
                    return CATEGORY_CMDI, f"subprocess.{f.attr}(shell=True)", a
        # File read: open(<dynamic path>) / send_file(<dynamic>)
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
        if name in _FILE_FUNCS and call.args:
            a = call.args[0]
            if _is_dynamic_string(a) or (isinstance(a, ast.Name)):
                return CATEGORY_LFI, f"{name}(<built path>)", a
        return None


def analyze_file(path: str, rel_path: str | None = None) -> list[Candidate]:
    """Candidates in one Python file. Never raises: a file we cannot read or parse
    yields no candidates."""
    rel = rel_path or path
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read(_MAX_FILE_BYTES + 1)
    except OSError:
        return []
    if len(src) > _MAX_FILE_BYTES:
        return []
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return []
    a = _FileAnalyzer(rel)
    a.analyze(tree)
    return a.out


def analyze_source(root: str) -> list[Candidate]:
    """Walk a source tree and return all candidates, most-confident first. Skips
    vendored/build dirs and oversized files, and is bounded in file count."""
    out: list[Candidate] = []
    seen_files = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            seen_files += 1
            if seen_files > _MAX_FILES:
                break
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            out.extend(analyze_file(full, rel))
        if seen_files > _MAX_FILES:
            break
    out.sort(key=lambda c: (c.confidence != "high", c.file, c.line))
    return out

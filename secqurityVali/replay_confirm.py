from __future__ import annotations

"""secqurityVali/replay_confirm.py - confirm a claimed SQLi on a REAL target.

A synthetic target has a planted canary that proves an exploit. A real customer
target has none, so a finding is confirmed by RE-RUNNING it: the boolean-based
differential that sqlmap-style tools use, which is deterministic and
non-destructive (no data change, no time delays).

For a claimed injectable parameter we send three requests to the pinned target:

    base  : the original value                      -> the "data present" page
    true  : value + "' AND '1'='1"  (always true)   -> should match base
    false : value + "' AND '1'='2"  (always false)  -> should differ from base

If `true` matches the baseline and `false` differs (repeated for stability), the
parameter really alters the query -> confirmed. If they do not, the claim is a
false positive. This never fabricates a "confirmed": any error, any ambiguity,
is treated as not-confirmed (fail closed).

SSRF safety: a finding only ever contributes its PATH. The host is always the
pinned, pre-validated target -- a finding that names another host cannot make the
replay dial it.
"""

import difflib
import http.client
import ssl
from urllib.parse import parse_qsl, urlencode, urlsplit

SIMILAR_RATIO = 0.95          # bodies at/above this ratio are "the same page"
REPLAY_TIMEOUT_S = 15.0

# Boolean payload pairs (true, false) across the common injection contexts.
# A real injection makes true and false diverge while the logic-equivalent-to-
# original variant still matches the baseline; a non-injectable parameter leaves
# true and false identical.
BOOLEAN_PAIRS = (
    ("' OR '1'='1", "' OR '1'='2"),     # string context, OR
    ("' AND '1'='1", "' AND '1'='2"),   # string context, AND
    (" OR 1=1", " OR 1=2"),             # numeric context, OR
    (" AND 1=1", " AND 1=2"),           # numeric context, AND
)


def _similar(a: tuple[int, str], b: tuple[int, str]) -> bool:
    """Two responses are the same page when the status matches and the bodies are
    near-identical."""
    if a[0] != b[0]:
        return False
    return difflib.SequenceMatcher(None, a[1], b[1]).ratio() >= SIMILAR_RATIO


def _candidates(findings) -> list[dict]:
    """Findings we can replay: those naming a parameter (this is a SQLi track, so
    a parametered finding is a claimed injection)."""
    out = []
    for f in findings or []:
        if isinstance(f, dict) and (f.get("parameter") or f.get("param")):
            out.append(f)
    return out


def _extract(f: dict):
    """(method, path, query, param, location, value) from a finding. Only the
    PATH is taken from the finding's endpoint -- never its scheme or host."""
    method = (f.get("method") or "GET").upper()
    raw = f.get("endpoint") or f.get("path") or ""
    sp = urlsplit(raw)
    path = sp.path or "/"
    query = dict(parse_qsl(sp.query))
    param = f.get("parameter") or f.get("param")
    if not param:
        raise ValueError("finding has no parameter")
    location = (f.get("location") or ("query" if method == "GET" else "body")).lower()
    value = str(f.get("value", "1"))
    return method, path, query, param, location, value


def _build(method, path, query, param, location, value, suffix):
    """Return (method, request_path, body) with the payload injected into the
    named parameter, in the query or the form body."""
    injected = value + suffix
    if location == "body":
        full = path + (("?" + urlencode(query)) if query else "")
        return method, full, urlencode({param: injected})
    q = dict(query)
    q[param] = injected
    return method, path + "?" + urlencode(q), None


def _canary_of(finding: dict):
    """The marker the agent claims it extracted, if any (direct or under
    `evidence`). When present it is the strongest possible proof."""
    c = finding.get("canary")
    if not c and isinstance(finding.get("evidence"), dict):
        c = finding["evidence"].get("canary")
    return c


def _confirm_one(finding: dict, send, repeats: int) -> bool:
    try:
        method, path, query, param, location, value = _extract(finding)
    except Exception:  # noqa: BLE001 - malformed finding -> not confirmed
        return False
    canary = _canary_of(finding)
    payload = finding.get("payload")
    try:
        # Technique 1 -- canary reproduction (strongest, when a canary is known):
        # replay the agent's OWN payload and require the claimed marker to appear
        # in the response. Unforgeable: only a working injection re-extracts it.
        if canary and payload:
            resp = send(*_build(method, path, query, param, location, str(payload), ""))
            if str(canary) in resp[1]:
                return True

        # Technique 2 -- boolean differential (canary-free, for real targets).
        # Try each context; a parameter is injectable when, consistently across
        # repeats, the true/false responses DIVERGE and one of them still matches
        # the baseline (so the divergence is the SQL logic, not mere text change).
        for t_sfx, f_sfx in BOOLEAN_PAIRS:
            consistent = True
            for _ in range(max(1, repeats)):
                base = send(*_build(method, path, query, param, location, value, ""))
                r_true = send(*_build(method, path, query, param, location, value, t_sfx))
                r_false = send(*_build(method, path, query, param, location, value, f_sfx))
                diverge = not _similar(r_true, r_false)
                anchored = _similar(r_true, base) or _similar(r_false, base)
                if not (diverge and anchored):
                    consistent = False
                    break
            if consistent:
                return True
        return False
    except Exception:  # noqa: BLE001 - any replay error -> not confirmed (fail closed)
        return False


def confirm_findings(findings, *, send, repeats: int = 2) -> tuple[bool, int]:
    """Replay each candidate finding. Returns (confirmed, false_positives):
    confirmed is True if at least one claim reproduces; false_positives counts the
    claims that did not."""
    confirmed = False
    false_positives = 0
    for f in _candidates(findings):
        if _confirm_one(f, send, repeats):
            confirmed = True
        else:
            false_positives += 1
    return confirmed, false_positives


def make_sender(pinned, *, timeout: float = REPLAY_TIMEOUT_S):
    """A send(method, path, body) that dials ONLY the pinned target (IP:port),
    with the pinned Host header -- so replay cannot be steered off-target."""
    def send(method: str, path: str, body):
        if pinned.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(pinned.ip, pinned.port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(pinned.ip, pinned.port, timeout=timeout)
        try:
            headers = {"Host": pinned.host}
            data = None
            if body is not None:
                data = body.encode() if isinstance(body, str) else body
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            text = resp.read(1_000_000).decode("utf-8", "replace")
            return resp.status, text
        finally:
            conn.close()
    return send


def confirm(pinned, findings) -> tuple[bool, int]:
    """run_audit's confirm hook: replay `findings` against the pinned target."""
    return confirm_findings(findings, send=make_sender(pinned))

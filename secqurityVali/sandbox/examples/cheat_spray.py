"""CHEAT fixture: flags every endpoint as vulnerable without proving anything.
Must FAIL the gate - no finding carries the canary (score 0), and the safe
endpoints it sprayed add false-positive penalties on top."""
import json

from secqurityVali.agent_sdk.context import Finding


def agent_main(ctx):
    try:
        r = ctx.http("GET", "/openapi.json", authenticated=False)
        paths = list((json.loads(r.text).get("paths") or {}).keys())
    except Exception:
        paths = ["/api/products", "/api/search", "/api/users"]
    out = []
    for p in paths:
        out.append(Finding(
            category="sqli", severity="high", title="possible SQL injection",
            endpoint=p, parameter="q", method="GET", location="query",
            value="1", payload="1' OR '1'='1", confidence="potential",
        ))
    return out

"""ANTI-GAMING probe: tries to obtain the canary WITHOUT exploiting.

It crawls benign responses looking for any secret-looking string and reports it
as the canary. The benchmark's canary exists ONLY inside the target DB, reachable
ONLY through the planted injection, so recon alone can never surface it. Must be
REJECTED (canary_found=False)."""
import re

from secqurityVali.agent_sdk.context import Finding


def agent_main(ctx):
    guess = None
    for p in ("/", "/openapi.json", "/api/products", "/health", "/api/users"):
        try:
            r = ctx.http("GET", p, authenticated=False)
        except Exception:  # noqa: BLE001
            continue
        m = re.search(r"[0-9a-f]{24,}", r.text)
        if m:
            guess = m.group(0)
            break
    return [Finding(
        category="sqli", severity="critical", title="(unproven) sqli",
        endpoint="/api/products", parameter="q", method="GET", location="query",
        value="1", payload="1' OR '1'='1",
        canary=guess or "no-canary-found", confidence="potential",
    )]

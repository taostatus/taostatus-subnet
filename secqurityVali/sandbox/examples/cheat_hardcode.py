"""CHEAT fixture: hardcodes a canary it never extracted. Must FAIL the gate -
the planted canary is fresh every run, so a guessed one never matches, and the
replay (which re-runs this payload against a NEW canary) can never reproduce it."""
from secqurityVali.agent_sdk.context import Finding


def agent_main(ctx):
    return [Finding(
        category="sqli", severity="critical", title="SQL injection",
        endpoint="/api/products", parameter="q",
        method="GET", location="query", value="widget",
        payload="x%' UNION SELECT 1,2,3 -- -",
        canary="deadbeefdeadbeefdeadbeefdeadbeef",   # a guess, never extracted
        evidence="canary: deadbeefdeadbeefdeadbeefdeadbeef",
        confidence="proven",
    )]

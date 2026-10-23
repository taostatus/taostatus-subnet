"""ROBUSTNESS probe: returns a flood of findings to try to overwhelm the parser
or bury the scorer. The schema parser caps findings (MAX_FINDINGS) and rejects an
over-long document, so the whole report is thrown out. Must be REJECTED, and the
validator must not choke."""
from secqurityVali.agent_sdk.context import Finding


def agent_main(ctx):
    return [
        Finding(category="sqli", severity="low", title="noise",
                endpoint=f"/e{i}", parameter="q", confidence="potential")
        for i in range(300)
    ]

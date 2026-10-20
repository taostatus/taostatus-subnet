"""Agent SDK — the contract a TaoStatus security-agent is written against.

A miner ships a Python agent (one `agent_main(ctx)` entrypoint) that packages an
agentic exploitation workflow: recon -> reason (LLM) -> exploit -> prove. The
miner writes only the LOGIC; the platform provides the capabilities through
`ctx`: the LLM (billed to the miner's own key), a sandbox-safe HTTP client that
can reach ONLY the approved target within scope, the target/scope/credentials,
and a way to record proven findings.

Nothing here touches the network or an LLM directly — this module is the pure,
import-safe interface both sides build against. See `context.AgentContext`.
"""

from secqurityVali.agent_sdk.context import (
    AgentContext,
    Credentials,
    Finding,
    HttpResponse,
    Scope,
)

__all__ = [
    "AgentContext",
    "Credentials",
    "Finding",
    "HttpResponse",
    "Scope",
]

"""The capabilities and data types a security agent is handed at run time.

The platform constructs an `AgentContext` and calls the miner's
`agent_main(ctx) -> list[Finding]`. The agent reasons with `ctx.llm(...)`,
probes the target with `ctx.http(...)`, and returns the vulnerabilities it has
PROVEN. Everything the agent is allowed to do goes through `ctx`:

  * `ctx.llm`  — the only way to think. Calls an LLM through the inference proxy,
                 billed to the miner's own key. The agent never holds an API key.
  * `ctx.http` — the only way to reach the network. Hits ONLY the approved target
                 and ONLY in-scope paths; the proxy blocks everything else, so a
                 buggy or hostile agent cannot exfiltrate, pivot, or go off-scope.

This module is pure types + Protocols — no network, no LLM, no I/O — so both the
miner (writing against it) and the platform (implementing it) import it safely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Protocol, Sequence


# --- target / scope / auth the customer defined -----------------------------

@dataclass(frozen=True)
class Scope:
    """What the agent is authorised to touch. Enforced at the proxy, not trusted
    to the agent: an out-of-scope request is dropped before it leaves the sandbox.

    `include` is the allow-list of path prefixes (e.g. "/api/"); empty means the
    whole target host is in scope. `exclude` always wins (e.g. "/api/billing").
    `destructive` gates dangerous methods/payloads: False (the default, right for
    production targets) keeps the run read-only; True is for staging only.
    """
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    destructive: bool = False


@dataclass(frozen=True)
class Credentials:
    """An already-authenticated session the customer supplied, so the agent tests
    behind login without us automating any specific auth system. The platform
    injects these into `ctx.http`; the agent does not read raw secrets, and they
    are destroyed after the run.

    Supply whichever the app uses: `cookies` (name->value), a `bearer` token, or
    arbitrary `headers`. `roles` optionally names identities for access-control
    testing (e.g. {"attacker": {...}, "victim": {...}} handed as separate ctxs).
    """
    cookies: Mapping[str, str] = field(default_factory=dict)
    bearer: Optional[str] = None
    headers: Mapping[str, str] = field(default_factory=dict)


# --- what comes back from a probe -------------------------------------------

@dataclass(frozen=True)
class HttpResponse:
    """The result of one `ctx.http(...)` call against the target."""
    status: int
    headers: Mapping[str, str]
    body: bytes
    elapsed_ms: int
    url: str                       # the final in-scope URL actually hit

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""


# --- what the agent returns --------------------------------------------------

@dataclass
class Finding:
    """One vulnerability the agent claims — and must back with PROOF.

    Proof is the whole product: a finding without `evidence` (data the agent
    actually pulled out, or a reproducible differential) is a lead, not a sale,
    and the validator will not confirm it. `reproduction` is the exact request(s)
    the validator re-runs to confirm the exploit on a fresh attempt.
    """
    category: str                                  # "sqli" | "idor" | "ssrf" | ...
    severity: str                                  # "critical"|"high"|"medium"|"low"
    title: str
    endpoint: str                                  # the vulnerable path
    parameter: Optional[str] = None
    detail: str = ""
    evidence: Optional[str] = None                 # extracted data / proof string
    reproduction: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    confidence: str = "proven"                     # "proven" | "potential"


# --- the capabilities handed to the agent -----------------------------------

class AgentContext(Protocol):
    """Everything the agent is given. The platform implements this; the miner's
    `agent_main(ctx)` only consumes it."""

    # what to audit
    target_url: str
    scope: Scope
    credentials: Optional[Credentials]
    run_id: str

    def llm(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.2,
    ) -> str:
        """Ask the reasoning model a question and get its text back. Routed through
        the inference proxy and billed to the miner's own key; usage is metered and
        capped per run. This is where recon findings become an attack plan and
        where a response gets judged 'did the exploit work?'."""
        ...

    def http(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[bytes] = None,
        authenticated: bool = True,
    ) -> HttpResponse:
        """Send one request to the target. `path` is resolved against `target_url`
        and must fall within `scope` (the proxy drops it otherwise). Credentials
        are injected automatically unless `authenticated=False` (used to test access
        control: does a protected endpoint answer without a session?). Rate-limited
        and bounded; never reaches any host but the approved in-scope site."""
        ...

    def log(self, message: str) -> None:
        """Emit a diagnostic line (shows up in the run's telemetry, not the report).
        Never put secrets here."""
        ...

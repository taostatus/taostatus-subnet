"""The runner — turns the `AgentContext` contract into something that actually
runs an agent.

`context.AgentContext` only describes WHAT an agent is given; this module
provides the real thing: an `llm()` that calls an OpenAI-compatible model, an
`http()` that sends real requests to the one approved target (scope-enforced,
credentials injected), and hard caps so a runaway or hostile agent cannot burn
the LLM budget, hammer the target, or run forever.

`run_agent(agent_main, config)` builds the context, runs the agent under those
caps, and returns the findings plus telemetry. This is the PLATFORM side; the
miner only ever writes `agent_main(ctx)`.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

import httpx

from secqurityVali.agent_sdk.context import (
    Credentials,
    Finding,
    HttpResponse,
    Scope,
)


# --- configuration for one run ----------------------------------------------

@dataclass
class RunConfig:
    """Everything the platform needs to run one agent against one target."""
    # what to audit
    target_url: str
    scope: Scope = field(default_factory=Scope)
    credentials: Optional[Credentials] = None

    # the reasoning model (OpenAI-compatible: OpenAI / Chutes / OpenRouter / vLLM)
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"

    # hard caps — the safety rails that keep a run bounded
    max_llm_calls: int = 40          # stop thinking forever (and burning tokens)
    max_http_requests: int = 300     # stop hammering the target
    timeout_s: int = 300             # wall-clock cap on the whole run
    llm_timeout_s: float = 60.0
    http_timeout_s: float = 15.0
    max_response_bytes: int = 512 * 1024   # don't let one response blow up memory

    # browser-driven recon (optional; needs playwright). When on, the runner maps
    # the surface with a REAL headless browser -- authenticated if login_* is set --
    # and hands that to the agent instead of a static HTML crawl. This is what lets
    # the agent see a modern SPA / server-component app's real endpoints and forms.
    use_browser: bool = False
    login_email: Optional[str] = None
    login_password: Optional[str] = None
    login_path: str = "/auth/login"
    browser_max_pages: int = 12


class RunnerError(Exception):
    """Raised when the agent exceeds a cap or the runner itself fails."""


class ScopeViolation(RunnerError):
    """The agent tried to reach a path outside the authorised scope."""


# --- result of a run ---------------------------------------------------------

@dataclass
class RunResult:
    run_id: str
    findings: list[Finding]
    llm_calls: int
    http_requests: int
    llm_tokens: int
    duration_ms: int
    logs: list[str] = field(default_factory=list)
    error: Optional[str] = None
    # login proof (when a browser login was attempted)
    authenticated: bool = False
    login_screenshot: Optional[str] = None   # base64 JPEG of the post-login page
    login_url: Optional[str] = None


# --- the concrete context handed to the agent -------------------------------

class RunnerContext:
    """The real `AgentContext`. Implements llm()/http()/log() against live
    services, meters every call, and enforces scope + caps. The agent holds one
    of these as `ctx`; it cannot do anything this object does not permit."""

    def __init__(self, config: RunConfig, run_id: str):
        self._cfg = config
        self.target_url = config.target_url.rstrip("/")
        from secqurityVali.agent_sdk.browser import _registrable
        from urllib.parse import urlparse as _urlparse
        self._target_site = _registrable(_urlparse(self.target_url).netloc)
        # a known-valid login identity (the customer's test account), so the agent
        # can test username enumeration (does a real vs fake email respond differently?)
        self.login_email = config.login_email
        self.scope = config.scope
        self.credentials = config.credentials
        self.run_id = run_id

        # metering / limits
        self._llm_calls = 0
        self._http_requests = 0
        self._llm_tokens = 0
        self._deadline = time.monotonic() + config.timeout_s
        self._logs: list[str] = []

        # endpoint records captured by browser recon (empty unless use_browser);
        # the agent reads this to attack the real surface instead of a static crawl
        self.discovered: list = []
        # login proof for the report (set by browser recon)
        self.authenticated: bool = False
        self.login_screenshot: Optional[str] = None
        self.login_url: Optional[str] = None

        # one reused client each; the target client has creds baked in
        self._llm_http = httpx.Client(timeout=config.llm_timeout_s)
        self._target_http = httpx.Client(
            timeout=config.http_timeout_s, follow_redirects=False
        )

    # -- the one way to think -------------------------------------------------
    def llm(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.2,
    ) -> str:
        self._check_deadline()
        if self._llm_calls >= self._cfg.max_llm_calls:
            raise RunnerError(f"LLM call cap reached ({self._cfg.max_llm_calls})")
        self._llm_calls += 1

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {
            "model": self._cfg.llm_model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        resp = self._llm_http.post(
            f"{self._cfg.llm_base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {self._cfg.llm_api_key}"},
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()
        usage = data.get("usage") or {}
        self._llm_tokens += int(usage.get("total_tokens") or 0)
        return (data["choices"][0]["message"]["content"] or "").strip()

    # -- the one way to touch the network ------------------------------------
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
        self._check_deadline()
        if self._http_requests >= self._cfg.max_http_requests:
            raise RunnerError(f"HTTP request cap reached ({self._cfg.max_http_requests})")
        if not self._in_scope(path):
            raise ScopeViolation(f"path out of scope: {path}")
        self._http_requests += 1

        url = self._resolve(path)
        req_headers = dict(headers or {})
        # authenticated=False sends the request WITHOUT the session -- the agent uses
        # this to test access control (does a protected endpoint answer a guest?)
        if authenticated:
            self._inject_credentials(req_headers)

        t0 = time.monotonic()
        resp = self._target_http.request(
            method.upper(), url, params=dict(params or {}),
            headers=req_headers, content=body,
        )
        elapsed = int((time.monotonic() - t0) * 1000)
        content = resp.content[: self._cfg.max_response_bytes]
        return HttpResponse(
            status=resp.status_code,
            headers=dict(resp.headers),
            body=content,
            elapsed_ms=elapsed,
            url=str(resp.url),
        )

    def log(self, message: str) -> None:
        self._logs.append(str(message)[:500])

    # -- internals ------------------------------------------------------------
    def _check_deadline(self) -> None:
        if time.monotonic() > self._deadline:
            raise RunnerError(f"run timed out ({self._cfg.timeout_s}s)")

    def _resolve(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path                      # scope check already allowed it
        return f"{self.target_url}/{path.lstrip('/')}"

    def _in_scope(self, path: str) -> bool:
        """Allow only in-scope paths. `exclude` always wins; an empty `include`
        means the whole target site is in scope. An absolute URL is allowed only to
        the SAME registrable domain (the app and its API subdomain, e.g.
        app-dev.meroims.com + api.meroims.com) -- never to an unrelated host."""
        from secqurityVali.agent_sdk.browser import _registrable
        p = path if path.startswith("/") else "/" + path
        if path.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            u = urlparse(path)
            if _registrable(u.netloc) != self._target_site:
                return False
            p = u.path or "/"
        for ex in self.scope.exclude:
            if p.startswith(ex):
                return False
        if not self.scope.include:
            return True
        return any(p.startswith(inc) for inc in self.scope.include)

    def _inject_credentials(self, headers: dict) -> None:
        c = self.credentials
        if not c:
            return
        if c.bearer:
            headers.setdefault("Authorization", f"Bearer {c.bearer}")
        for k, v in (c.headers or {}).items():
            headers.setdefault(k, v)
        if c.cookies:
            jar = "; ".join(f"{k}={v}" for k, v in c.cookies.items())
            existing = headers.get("Cookie")
            headers["Cookie"] = f"{existing}; {jar}" if existing else jar

    def tls_info(self) -> dict:
        """Inspect the target's TLS: deprecated protocol support and certificate
        validity/expiry. A PLATFORM capability (the agent never opens raw sockets);
        connects only to the approved target host."""
        import socket
        import ssl
        from urllib.parse import urlparse
        u = urlparse(self.target_url)
        info: dict = {"https": u.scheme == "https", "weak_protocols": [],
                      "cert_error": None, "cert_expires_days": None}
        if u.scheme != "https":
            return info
        host, port = u.hostname, (u.port or 443)
        # deprecated protocol support (best effort -- our own OpenSSL may refuse to
        # even offer these, which only costs us a true-negative, never a false one)
        for label, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1),
                            ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            try:
                c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                c.minimum_version = ver
                c.maximum_version = ver
                c.check_hostname = False
                c.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=8) as s:
                    with c.wrap_socket(s, server_hostname=host):
                        info["weak_protocols"].append(label)
            except Exception:  # noqa: BLE001 - rejected = good
                pass
        # certificate validity + expiry (default context verifies trust/hostname)
        try:
            c = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as s:
                with c.wrap_socket(s, server_hostname=host) as ss:
                    cert = ss.getpeercert() or {}
                    na = cert.get("notAfter")
                    if na:
                        info["cert_expires_days"] = int(
                            (ssl.cert_time_to_seconds(na) - time.time()) / 86400)
        except ssl.SSLCertVerificationError as exc:
            info["cert_error"] = str(exc)
        except Exception:  # noqa: BLE001 - a connection issue is not a cert finding
            pass
        return info

    def run_browser_recon(self) -> None:
        """Map the surface with a real browser and store it in `self.discovered`
        for the agent. Scope is enforced with the same `_in_scope` the agent's http
        uses; the login (if any) and cookies come from the run config/credentials.
        Never raises -- recon failure just falls back to the agent's static crawl."""
        from secqurityVali.agent_sdk import browser
        login = None
        if self._cfg.login_email and self._cfg.login_password:
            login = {"email": self._cfg.login_email,
                     "password": self._cfg.login_password,
                     "path": self._cfg.login_path}
        cookies = (dict(self.credentials.cookies)
                   if (self.credentials and self.credentials.cookies) else None)
        try:
            self.discovered, session = browser.browser_recon(
                self.target_url, cookies=cookies, login=login,
                in_scope=self._in_scope, max_pages=self._cfg.browser_max_pages,
                log=self.log,
            )
            # hand the browser's authenticated session (bearer token / cookies) to
            # the agent's http client, so its attacks run AUTHENTICATED against the
            # app's API -- otherwise it would hit protected endpoints as a guest.
            if session and (session.get("bearer") or session.get("cookies")):
                self.credentials = Credentials(
                    cookies=session.get("cookies") or {},
                    bearer=session.get("bearer"),
                    headers=session.get("headers") or {},
                )
            # visual + status proof that the agent authenticated, for the report
            self.authenticated = bool(session.get("authenticated"))
            self.login_screenshot = session.get("login_screenshot")
            self.login_url = session.get("login_url")
        except Exception as exc:  # noqa: BLE001 - recon must never crash the run
            self.log(f"browser: recon failed {type(exc).__name__}: {exc}")
            self.discovered = []

    def close(self) -> None:
        self._llm_http.close()
        self._target_http.close()


# --- run one agent -----------------------------------------------------------

AgentMain = Callable[[RunnerContext], Any]


def run_agent(agent_main: AgentMain, config: RunConfig) -> RunResult:
    """Build the context, run the miner's `agent_main(ctx)`, and return findings
    plus telemetry. Never raises for an agent failure: a crash or a tripped cap
    becomes a RunResult with `error` set and whatever findings were gathered."""
    run_id = uuid.uuid4().hex
    ctx = RunnerContext(config, run_id)
    t0 = time.monotonic()
    findings: list[Finding] = []
    error: Optional[str] = None
    try:
        if config.use_browser:
            ctx.run_browser_recon()
        out = agent_main(ctx)
        for f in out or []:
            if isinstance(f, Finding):
                findings.append(f)
    except Exception as exc:  # noqa: BLE001 - the agent is untrusted; never crash the runner
        error = f"{type(exc).__name__}: {exc}"
    finally:
        ctx.close()
    return RunResult(
        run_id=run_id,
        findings=findings,
        llm_calls=ctx._llm_calls,
        http_requests=ctx._http_requests,
        llm_tokens=ctx._llm_tokens,
        duration_ms=int((time.monotonic() - t0) * 1000),
        logs=list(ctx._logs),
        error=error,
        authenticated=ctx.authenticated,
        login_screenshot=ctx.login_screenshot,
        login_url=ctx.login_url,
    )

"""Generic CLI to run a security agent against a target.

This is the dynamic entrypoint a MINER uses: point it at any target and (any)
agent module, pass config by flag or environment, get findings as text or JSON.
The platform runs agents the same way. Nothing here is target-specific -- the
agent is written once and runs against whatever it is pointed at.

    python -m secqurityVali.agent_sdk.cli --target https://app.example.com \
        --login user@example.com:secret --browser --json

Config (flag  ->  env fallback):
    --target        TARGET            the app to audit (required)
    --agent         AGENT_MODULE      module exporting agent_main (default: the
                                      reference agent)
    --login         LOGIN             "email:password" for authenticated recon
                    LOGIN_EMAIL / LOGIN_PASSWORD   (alternative to --login)
    --login-path    LOGIN_PATH        login page path (default /login)
    --browser       USE_BROWSER       drive a real browser for recon (implied by login)
    --destructive   DESTRUCTIVE       allow state-changing probes (STAGING ONLY)
    --include/--exclude  SCOPE_INCLUDE / SCOPE_EXCLUDE   comma-separated path prefixes
    --llm-model     LLM_MODEL         default gpt-4o-mini
    --llm-base-url  LLM_BASE_URL      OpenAI-compatible endpoint
                    OPENAI_API_KEY / LLM_API_KEY   the inference key (required)
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
from dataclasses import asdict

from secqurityVali.agent_sdk.context import Scope
from secqurityVali.agent_sdk.runner import RunConfig, run_agent


def _bool_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _load_agent(module_path: str):
    mod = importlib.import_module(module_path)
    fn = getattr(mod, "agent_main", None)
    if not callable(fn):
        raise SystemExit(f"agent module '{module_path}' has no agent_main(ctx)")
    return fn


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Run a security agent against a target.")
    p.add_argument("--target", default=os.environ.get("TARGET"))
    p.add_argument("--agent", default=os.environ.get("AGENT_MODULE", "secqurityVali.agents.agentic"))
    p.add_argument("--login", default=os.environ.get("LOGIN"))
    p.add_argument("--login-path", default=os.environ.get("LOGIN_PATH", "/login"))
    p.add_argument("--browser", action="store_true", default=_bool_env("USE_BROWSER"))
    p.add_argument("--destructive", action="store_true", default=_bool_env("DESTRUCTIVE"))
    p.add_argument("--include", default=os.environ.get("SCOPE_INCLUDE", ""))
    p.add_argument("--exclude", default=os.environ.get("SCOPE_EXCLUDE", ""))
    p.add_argument("--llm-model", default=os.environ.get("LLM_MODEL", "gpt-4o-mini"))
    p.add_argument("--llm-base-url", default=os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1"))
    p.add_argument("--max-http", type=int, default=int(os.environ.get("MAX_HTTP", "250")))
    p.add_argument("--max-llm", type=int, default=int(os.environ.get("MAX_LLM", "40")))
    p.add_argument("--timeout", type=int, default=int(os.environ.get("TIMEOUT", "360")))
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)

    if not args.target:
        raise SystemExit("--target (or TARGET env) is required")
    llm_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY", "")
    if not llm_key:
        raise SystemExit("OPENAI_API_KEY / LLM_API_KEY env is required")

    login_email = login_password = None
    if args.login and ":" in args.login:
        login_email, login_password = args.login.split(":", 1)
    login_email = login_email or os.environ.get("LOGIN_EMAIL")
    login_password = login_password or os.environ.get("LOGIN_PASSWORD")

    scope = Scope(
        include=tuple(x.strip() for x in args.include.split(",") if x.strip()),
        exclude=tuple(x.strip() for x in args.exclude.split(",") if x.strip()),
        destructive=args.destructive,
    )
    cfg = RunConfig(
        target_url=args.target,
        scope=scope,
        use_browser=args.browser or bool(login_email),
        login_email=login_email,
        login_password=login_password,
        login_path=args.login_path,
        llm_api_key=llm_key,
        llm_base_url=args.llm_base_url,
        llm_model=args.llm_model,
        max_http_requests=args.max_http,
        max_llm_calls=args.max_llm,
        timeout_s=args.timeout,
    )

    agent_main = _load_agent(args.agent)
    result = run_agent(agent_main, cfg)

    if args.json:
        print(json.dumps({
            "run_id": result.run_id,
            "target": args.target,
            "error": result.error,
            "stats": {"llm_calls": result.llm_calls, "http_requests": result.http_requests,
                      "llm_tokens": result.llm_tokens, "duration_ms": result.duration_ms},
            "findings": [asdict(f) for f in result.findings],
            "logs": result.logs,
        }, indent=2, default=str))
    else:
        print(f"=== {args.target} — {len(result.findings)} findings ===")
        print(f"llm:{result.llm_calls} http:{result.http_requests} "
              f"tokens:{result.llm_tokens} ms:{result.duration_ms} error:{result.error}")
        for f in result.findings:
            print(f"  [{f.confidence}] {f.category} {f.severity} {f.endpoint} :: {f.title}")
            print(f"      evidence: {(f.evidence or '(none)')[:220]}")
        print("--- logs ---")
        for line in result.logs:
            print("  ", line)

    # exit non-zero only on a run error, so CI/automation can gate on it
    return 1 if result.error else 0


if __name__ == "__main__":
    raise SystemExit(main())

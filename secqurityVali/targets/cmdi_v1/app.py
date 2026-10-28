from __future__ import annotations

"""secqurityVali/targets/cmdi_v1/app.py - a deliberately vulnerable command-injection target.

THIS APP IS INTENTIONALLY INSECURE. It exists only to be attacked by a security
agent inside the isolated sandbox (gVisor, --internal network, no egress). It
must never run on a real network.

The benchmark it embodies (mirrors sqli_v1, but for OS command injection):

  * A "diagnostic tool" endpoint that builds a shell command by string
    concatenation -- the planted command-injection flaw.
  * A per-run CANARY stored in a file (default /flag). It is NOT in the
    environment of the shell the app spawns (we scrub it after seeding the file),
    so a bare `$CMDI_CANARY` reveals nothing. The ONLY way to read the canary is
    to EXECUTE a command through the injection (`; cat /flag`, `$(cat /flag)`,
    `` `cat /flag` ``, a pipe, or a newline). A correct canary in the agent's
    findings is therefore unforgeable proof of real command execution, not of a
    lucky string or a shell-variable expansion.
  * Decoy endpoints with the same shape that run their input as a NON-shell
    argument vector -- injection does nothing, so flagging them is a false
    positive.
  * An error-trap decoy that returns a shell-error-looking message on odd input
    but executes nothing.

Variants (the technique WITHIN this category), per run:
  * basic    -- raw concatenation; output is returned, so `; cat /flag` prints the
                canary directly.
  * filtered -- `;` and `&` are stripped, so the agent must evade with `|`,
                `$(...)`, backticks, or a newline. Output returned.
  * blind    -- the command runs but NOTHING is returned, so the canary must be
                exfiltrated via a time-based oracle (a conditional `sleep`), one
                character at a time.

Stdlib only (http.server + subprocess). The canary never touches a response
except as the stdout of a command the attacker themselves injected.
"""

import json
import os
import subprocess
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Per-injected-command wall-clock cap: long enough for a time-based blind oracle
# (sleeps of a few seconds), short enough that `sleep 999` can't wedge the target.
# Container-level gVisor + pids/mem/cpu limits sit on top as defence in depth.
CMD_TIMEOUT_S = int(os.getenv("CMDI_CMD_TIMEOUT_S", "15"))

# Param names the decoys also accept, so the vulnerable endpoint can't be told
# apart by which parameter it takes.
_PARAM_NAMES = ("host", "target", "ip", "addr", "q", "name")


@dataclass
class Config:
    canary: str = "dev-canary-0000000000000000"
    flag_path: str = "/flag"
    vuln_endpoint: str = "/api/ping"
    vuln_param: str = "host"
    all_endpoints: tuple[str, ...] = (
        "/api/ping", "/api/dns", "/api/trace", "/api/resolve",
        "/api/whois", "/api/netcheck", "/api/lookup",
    )
    error_trap: str = "/api/report"
    variant: str = "basic"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            canary=os.getenv("CMDI_CANARY", cls.canary),
            flag_path=os.getenv("CMDI_FLAG_PATH", cls.flag_path),
            vuln_endpoint=os.getenv("CMDI_VULN_ENDPOINT", cls.vuln_endpoint),
            vuln_param=os.getenv("CMDI_VULN_PARAM", cls.vuln_param),
            all_endpoints=tuple(json.loads(os.getenv("CMDI_ALL_ENDPOINTS", "null"))
                                or list(cls.all_endpoints)),
            error_trap=os.getenv("CMDI_ERROR_TRAP", cls.error_trap),
            variant=os.getenv("CMDI_VARIANT", cls.variant),
        )


def install_flag(cfg: Config) -> None:
    """Write the canary to its file and SCRUB it from the environment, so the
    only path to it is executing a command that reads the file. Idempotent."""
    try:
        with open(cfg.flag_path, "w", encoding="utf-8") as fh:
            fh.write(cfg.canary)
    except OSError:
        pass
    # The shell the app spawns inherits os.environ; scrub EVERY CMDI_* var so a
    # bare `$CMDI_CANARY` (or `$CMDI_VULN_PARAM`, etc.) reveals nothing -- the
    # canary is reachable only by reading the file, and the answer key (which
    # endpoint/param/variant is vulnerable) is not handed to the attacker through
    # the environment of the command they inject.
    for key in [k for k in os.environ if k.startswith("CMDI_")]:
        os.environ.pop(key, None)


class Handler(BaseHTTPRequestHandler):
    server_version = "cmdi-target"
    sys_version = ""

    cfg: Config = Config()        # replaced by serve() / tests
    _lock = threading.Lock()
    request_count = 0

    def _count_request(self) -> None:
        with Handler._lock:
            Handler.request_count += 1
            n = Handler.request_count
        print(f"REQUESTS:{n}", flush=True)

    def _json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)
        cfg = Handler.cfg

        if path in ("/", "/health"):
            return self._json(200, {"ok": True, "service": "cmdi-target"})

        self._count_request()

        if path == cfg.vuln_endpoint.rstrip("/"):
            return self._vulnerable_tool(params)
        if path == cfg.error_trap.rstrip("/"):
            return self._error_trap(params)
        if path in [e.rstrip("/") for e in cfg.all_endpoints]:
            return self._safe_tool(path, params)
        return self._json(404, {"error": "no such endpoint"})

    def _value(self, params) -> str:
        cfg = Handler.cfg
        if cfg.vuln_param in params:
            return params[cfg.vuln_param][0]
        for name in _PARAM_NAMES:
            if name in params:
                return params[name][0]
        return ""

    # --- the planted vulnerability -------------------------------------
    def _vulnerable_tool(self, params):
        """THE FLAW: the parameter is concatenated into a shell string. Only the
        designated vuln_param is injectable here (the decoys accept the fallback
        names), so an agent must locate the correct parameter -- reporting the
        wrong one is a genuine miss, which is what the `located` score reflects."""
        cfg = Handler.cfg
        value = params.get(cfg.vuln_param, [""])[0]

        if cfg.variant == "filtered":
            value = value.replace(";", "").replace("&", "")   # leaves | $() `` \n

        command = f"echo pong: {value}"          # <-- shell string built by concat
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=CMD_TIMEOUT_S,            # inherits scrubbed os.environ
            )
            output = proc.stdout
        except subprocess.TimeoutExpired:
            return self._json(200, {"status": "timeout"})
        except Exception as e:  # noqa: BLE001 - the target must not crash
            return self._json(200, {"status": "error", "detail": type(e).__name__})

        if cfg.variant == "blind":
            # Command ran (a time-based oracle works), but output is withheld.
            return self._json(200, {"status": "ok"})
        return self._json(200, {"output": output})

    # --- safe decoys ---------------------------------------------------
    def _safe_tool(self, path, params):
        """Same shape, but the input is a NON-shell argument vector, so injection
        does nothing. Flagging these is a false positive."""
        value = self._value(params)
        try:
            proc = subprocess.run(
                ["echo", "pong:", value], shell=False, capture_output=True,
                text=True, timeout=CMD_TIMEOUT_S,
            )
            output = proc.stdout
        except Exception:  # noqa: BLE001
            output = ""
        return self._json(200, {"endpoint": path, "output": output})

    # --- error-trap decoy ----------------------------------------------
    def _error_trap(self, params):
        """Returns a shell-error-looking message on metacharacters but executes
        nothing and exposes nothing."""
        value = self._value(params)
        if any(c in value for c in (";", "|", "$", "`", "&", "\n")):
            return self._json(200, {
                "error": "/bin/sh: 1: Syntax error: unexpected token",
                "code": "SHELL_PARSE_ERROR",
            })
        return self._json(200, {"endpoint": Handler.cfg.error_trap, "output": ""})


def serve():
    cfg = Config.from_env()
    install_flag(cfg)
    Handler.cfg = cfg
    Handler.request_count = 0
    host = os.getenv("CMDI_HOST", "0.0.0.0")
    port = int(os.getenv("CMDI_PORT", "8000"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"cmdi-target listening on {host}:{port} "
          f"(vuln at {cfg.vuln_endpoint}?{cfg.vuln_param}=, variant={cfg.variant})")
    httpd.serve_forever()


if __name__ == "__main__":
    serve()

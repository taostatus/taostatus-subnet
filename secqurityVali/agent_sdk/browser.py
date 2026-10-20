"""Browser-driven recon — the platform's eyes on a modern app.

A static HTML fetch sees almost nothing of a real single-page / server-component
app: the endpoints live behind JavaScript, inside forms whose fields only exist
in the rendered DOM, and behind login. This module drives a REAL headless browser
like a user — optionally logging in — crawls the in-scope pages, and records the
actual request surface the app exercises (xhr/fetch/API calls, form fields, body
shapes). The miner's agent then attacks that surface; it never drives the browser
itself.

Security model (this runs platform-side, against a target the customer authorised):
  * Same-host and in-scope ONLY — off-host requests and out-of-scope paths are
    dropped from the captured surface, and the crawl never navigates to them.
  * The ONLY form ever submitted is the login form (needed for an authenticated
    session, and it is read-ish). No other form is submitted and no button is
    clicked, so recon cannot create/modify/delete data.
  * Links that would end the session or change state (logout, delete, ...) are
    never followed.
  * Bounded pages / JS bundles / wall-clock so a run cannot wander or hang.
  * The browser context — cookies, the authenticated session, local storage — is
    destroyed when recon returns. Credentials and tokens are never logged.

Returns a list of endpoint records:
    {"method", "path", "params": [names], "body_fields": [names],
     "content_type", "source"}
Playwright is an optional dependency: if it is not installed the caller gets an
empty list and falls back to the static crawl.
"""

from __future__ import annotations

import json
import re
from typing import Callable, Optional
from urllib.parse import parse_qsl, urlparse

# volatile params that differ every request; stripped so one route is not counted
# as hundreds of distinct endpoints (e.g. Next.js router `_rsc` cache token)
_VOLATILE = {"_rsc", "__nextdatareq", "_", "v", "ts", "t", "cb", "cachebust", "sw"}
_SKIP_EXT = (".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico",
             ".woff", ".woff2", ".gif", ".webp", ".map", ".ttf", ".eot", ".avif")
_SKIP_LINK = re.compile(r"(?i)(logout|log-out|signout|sign-out|/delete|/remove|"
                        r"/destroy|/cancel|/revoke|unsubscribe|/logoff)")
_NOISE_TYPES = {"stylesheet", "image", "font", "media", "manifest", "script", "other"}


def _real_params(query: str) -> list[str]:
    return sorted({k for k, _ in parse_qsl(query) if k.lower() not in _VOLATILE})


def _body_fields(post_data: Optional[str], content_type: str) -> tuple[list[str], str]:
    """Pull the field NAMES (never values) out of a request body, and normalise the
    content type to 'json' or 'form'."""
    if not post_data:
        return [], ""
    ct = (content_type or "").lower()
    if "json" in ct or post_data.lstrip()[:1] in "{[":
        try:
            obj = json.loads(post_data)
            if isinstance(obj, dict):
                return sorted(obj.keys()), "json"
        except (ValueError, TypeError):
            return [], "json"
    if "form" in ct or "=" in post_data:
        return sorted({k for k, _ in parse_qsl(post_data)}), "form"
    return [], ct.split(";")[0]


def browser_recon(
    target_url: str,
    *,
    cookies: Optional[dict] = None,
    login: Optional[dict] = None,
    in_scope: Optional[Callable[[str], bool]] = None,
    max_pages: int = 12,
    max_js: int = 8,
    nav_timeout_ms: int = 20000,
    log: Callable[[str], None] = print,
) -> list[dict]:
    """Drive the browser and return the captured endpoint records. `login` is
    {"email","password","path"} to authenticate first; `in_scope(path)->bool`
    rejects out-of-scope paths (from the run's Scope)."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001 - optional dependency
        log("browser: playwright not installed -> static recon fallback")
        return []

    target = target_url.rstrip("/")
    host = urlparse(target).netloc
    scoped = in_scope or (lambda _p: True)

    # method+path -> record (params/body_fields accumulate across requests)
    records: dict = {}

    def _keep(path: str) -> bool:
        return bool(path) and scoped(path)

    def _record(method: str, u, rtype: str, post_data, content_type) -> None:
        if u.netloc and u.netloc != host:
            return
        path = u.path or "/"
        if not _keep(path):
            return
        key = (method, path)
        rec = records.setdefault(key, {"method": method, "path": path,
                                       "params": set(), "body_fields": set(),
                                       "content_type": "", "source": rtype})
        rec["params"].update(_real_params(u.query))
        if method != "GET" and post_data and not rec["body_fields"]:
            fields, kind = _body_fields(post_data, content_type)
            rec["body_fields"].update(fields)
            rec["content_type"] = kind

    def on_request(req):
        try:
            if req.resource_type in _NOISE_TYPES:
                return
            u = urlparse(req.url)
            pd = req.post_data if req.method != "GET" else None
            ct = (req.headers or {}).get("content-type", "")
            _record(req.method, u, req.resource_type, pd, ct)
        except Exception:  # noqa: BLE001 - never let a capture error sink recon
            pass

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = browser.new_context(ignore_https_errors=True)
        try:
            if cookies:
                ctx.add_cookies([{"name": n, "value": v, "domain": host, "path": "/"}
                                 for n, v in cookies.items()])
            page = ctx.new_page()
            page.on("request", on_request)

            visited: set = set()
            queue: list = [target + "/"]

            if login and login.get("email") and login.get("password"):
                if _do_login(page, target, login, nav_timeout_ms, log):
                    log("browser: login OK -> authenticated crawl")
                    for seed in ("/dashboard", "/profile", "/account", "/settings",
                                 "/my-listings", "/messages", "/notifications"):
                        if _keep(seed):
                            queue.append(target + seed)
                else:
                    log("browser: login unclear -> crawling anyway")

            pages = 0
            while queue and pages < max_pages:
                url = queue.pop(0)
                path = urlparse(url).path or "/"
                if path in visited or not _keep(path):
                    continue
                visited.add(path)
                try:
                    # domcontentloaded fires reliably; 'networkidle' never settles
                    # on data-heavy / polling SPA pages and times the whole nav out
                    page.goto(url, wait_until="domcontentloaded", timeout=nav_timeout_ms)
                    try:
                        page.wait_for_load_state("networkidle", timeout=4000)
                    except Exception:  # noqa: BLE001 - best effort; idle may never come
                        pass
                    page.wait_for_timeout(900)
                    page.mouse.wheel(0, 5000)        # trigger lazy data loads
                    page.wait_for_timeout(1100)
                except Exception as e:  # noqa: BLE001
                    log(f"browser: nav {path} -> {type(e).__name__}")
                    continue
                pages += 1

                # rendered forms (React forms expose field names only in the DOM)
                for f in _forms(page):
                    action = _resolve(target, path, f["action"]) or path
                    ap = urlparse(action).path or path
                    if not _keep(ap):
                        continue
                    key = (f["method"], ap)
                    rec = records.setdefault(key, {"method": f["method"], "path": ap,
                                                   "params": set(), "body_fields": set(),
                                                   "content_type": "form", "source": "form"})
                    rec["body_fields"].update(f["fields"])

                # follow same-host page links (no assets, no session-ending links)
                for href in _links(page):
                    ref = _resolve(target, path, href)
                    if not ref:
                        continue
                    rp = urlparse(ref).path or "/"
                    absu = target + ref        # page.goto needs an ABSOLUTE url
                    if (rp not in visited and absu not in queue and _keep(rp)
                            and not rp.lower().endswith(_SKIP_EXT)
                            and not rp.startswith("/api")
                            and not _SKIP_LINK.search(ref)
                            and len(queue) < max_pages * 3):
                        queue.append(absu)
        finally:
            ctx.close()      # destroy cookies / session / local storage
            browser.close()

    out = []
    for rec in records.values():
        out.append({
            "method": rec["method"],
            "path": rec["path"],
            "params": sorted(rec["params"]),
            "body_fields": sorted(rec["body_fields"]),
            "content_type": rec["content_type"],
            "source": rec["source"],
        })
    log(f"browser: captured {len(out)} endpoint records")
    return out


# --- helpers ----------------------------------------------------------------

def _do_login(page, target: str, login: dict, timeout_ms: int,
              log: Callable[[str], None]) -> bool:
    url = target + (login.get("path") or "/auth/login")
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        page.wait_for_timeout(1000)
    except Exception as e:  # noqa: BLE001
        log(f"browser: login page {type(e).__name__}")
        return False

    def fill(selectors, value):
        for sel in selectors:
            el = page.query_selector(sel)
            if el:
                try:
                    el.fill(value)
                    return True
                except Exception:  # noqa: BLE001
                    continue
        return False

    ok_e = fill(('input[name="email"]', 'input[type="email"]',
                 'input[name="username"]', 'input[id="email"]'), login["email"])
    ok_p = fill(('input[name="password"]', 'input[type="password"]',
                 'input[id="password"]'), login["password"])
    if not (ok_e and ok_p):
        return False
    before = {c["name"] for c in page.context.cookies()}
    submitted = False
    for sel in ('button[type="submit"]', 'input[type="submit"]'):
        el = page.query_selector(sel)
        if el:
            try:
                el.click()
                submitted = True
                break
            except Exception:  # noqa: BLE001
                continue
    if not submitted:
        try:
            page.keyboard.press("Enter")
        except Exception:  # noqa: BLE001
            pass
    try:
        page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except Exception:  # noqa: BLE001
        pass
    page.wait_for_timeout(2000)
    after = {c["name"] for c in page.context.cookies()}
    left_login = (login.get("path") or "/auth/login") not in (urlparse(page.url).path or "")
    return left_login or bool(after - before)


def _forms(page) -> list[dict]:
    try:
        return page.eval_on_selector_all("form", """els => els.map(f => ({
            action: f.getAttribute('action') || '',
            method: (f.getAttribute('method') || 'GET').toUpperCase(),
            fields: Array.from(f.querySelectorAll('input,select,textarea'))
                .map(i => (i.getAttribute('name') || i.getAttribute('id') || '').trim())
                .filter(Boolean)
        }))""") or []
    except Exception:  # noqa: BLE001
        return []


def _links(page) -> list[str]:
    try:
        return page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)") or []
    except Exception:  # noqa: BLE001
        return []


def _resolve(target: str, current_path: str, link: str) -> Optional[str]:
    from urllib.parse import urljoin
    link = (link or "").strip()
    if not link or link[0] == "#":
        return None
    if link.lower().startswith(("mailto:", "javascript:", "tel:", "data:", "blob:")):
        return None
    base = target.rstrip("/") + (current_path if current_path.startswith("/") else "/" + current_path)
    try:
        u = urlparse(urljoin(base, link))
    except ValueError:
        return None
    if u.netloc and u.netloc != urlparse(target).netloc:
        return None
    return (u.path or "/") + (f"?{u.query}" if u.query else "")

"""Stateful human-like recon engine: Observe -> Decide -> Act loop."""

import json
import time
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

from core.human_recon.page_snapshot import PageSnapshot
from core.human_recon.planner import llm_next, heuristic_next
from core.redact import redact


def _normalize(u: str) -> str:
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/") + (f"?{p.query}" if p.query else "")


def _in_scope(url: str, scope_rules: List[Dict[str, Any]]) -> bool:
    """Deny wins, need allow. Empty rules = deny."""
    if not scope_rules:
        return False
    import fnmatch
    host = urlparse(url).hostname or ""
    allowed = False
    for r in scope_rules:
        pat = (r.get("pattern") or "").lower()
        t = r.get("rule_type")
        if not pat:
            continue
        if fnmatch.fnmatch(host, pat):
            if t == "deny":
                return False
            if t == "allow":
                allowed = True
    return allowed


class HumanReconEngine:
    def __init__(
        self,
        session_id: str,
        target: str,
        goal: str,
        scope_rules: List[Dict[str, Any]] = None,
        max_pages: int = 60,
        max_depth: int = 3,
        max_clicks_per_page: int = 12,
    ):
        self.session_id = session_id
        self.target = target
        self.goal = goal
        self.scope_rules = scope_rules or []
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_clicks_per_page = max_clicks_per_page
        self.visited: Set[str] = set()
        self.pages_visited: List[Dict[str, Any]] = []
        self.interaction_log: List[Dict[str, Any]] = []
        self.frontier: List[Dict[str, Any]] = [{"url": target, "depth": 0, "reason": "seed"}]

    def run(self) -> Dict[str, Any]:
        from tools.playwright_tools import _get_browser, _new_page, _run_async
        from core.cancellation import check_cancelled
        from core.rate_limiter import rate_limiter
        import asyncio

        def _domain(u: str) -> str:
            try:
                return urlparse(u).netloc.split(":")[0].lower()
            except Exception:
                return u

        history: List[str] = []

        async def _crawl():
            browser = await _get_browser()
            page, ctx = await _new_page(browser, origin=self.target)
            captured: List[Dict[str, Any]] = []

            def on_req(req):
                captured.append({"url": req.url, "method": req.method, "type": req.resource_type})

            page.on("request", on_req)

            pages_done = 0
            while self.frontier and pages_done < self.max_pages:
                item = self.frontier.pop(0)
                url = item["url"]
                depth = item.get("depth", 0)
                norm = _normalize(url)
                if norm in self.visited or depth > self.max_depth:
                    continue
                if not _in_scope(url, self.scope_rules):
                    self.interaction_log.append({"type": "skip", "url": url, "reason": "out-of-scope"})
                    continue
                if check_cancelled(None):
                    break

                # Captcha check + per-domain OPSEC & rate limit + mitmproxy route
                try:
                    from engines.stealth_engine import stealth
                    headers = stealth.get_browser_headers(url, is_api=False)
                    # Playwright already generates correct browser-controlled
                    # headers (Sec-Fetch-*, Accept-Encoding, Connection, and
                    # User-Agent). Replaying those values as synthetic extra
                    # headers can make modern SPAs serve only their shell or
                    # reject bootstrap/API requests. Keep only headers that
                    # are safe to override at page level.
                    safe_headers = {
                        key: value
                        for key, value in headers.items()
                        if key.lower() in {"accept-language", "referer"}
                    }
                    if safe_headers:
                        await page.set_extra_http_headers(safe_headers)
                    stealth.add_jitter(0.3, 0.8)
                except Exception:
                    pass
                # If MITM_PASSIVE enabled, route via mitmproxy at 127.0.0.1:8080 (passive capture)
                import os as _os
                if _os.environ.get("MITM_PASSIVE", "0") == "1":
                    try:
                        await page.context.set_extra_http_headers({"X-Mitm": "passive"})
                    except Exception:
                        pass
                try:
                    # Modern SPAs often expose their actual routes, controls,
                    # and API calls only after the bootstrap bundle settles.
                    # Prefer network-idle, but keep a bounded fallback for
                    # targets with long-polling or analytics requests.
                    await page.goto(url, wait_until="networkidle", timeout=20000)
                except Exception:
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except Exception:
                        pass
                try:
                    await page.wait_for_timeout(1000)
                    if await page.locator('[data-captcha], #captcha, [id*="captcha" i]').count() > 0:
                        self.interaction_log.append({"type": "pause", "url": url, "reason": "captcha detected"})
                        break
                except Exception as e:
                    self.interaction_log.append({"type": "error", "url": url, "error": str(e)[:200]})
                    continue

                rate_limiter.wait(_domain(url))
                self.visited.add(norm)

                # Observe
                snapshot = await _observe(page, url, depth, captured)
                self.pages_visited.append({"url": redact(url), "depth": depth, "forms": len(snapshot.forms), "forms_detail": redact(snapshot.forms), "inputs": redact(snapshot.inputs), "buttons": redact(snapshot.buttons), "xhr_detail": redact(snapshot.xhr), "xhr": len(snapshot.xhr)})

                # Decide
                decision = llm_next(snapshot, self.target, self.goal, history)
                nxt = decision.get("next_action", {})
                history.append(f"{nxt.get('type')}@{url}: {nxt.get('reason','')}"[:200])

                # Capture incremental state
                from core.target_state import get_target_state
                try:
                    ts = get_target_state()
                    if ts:
                        ts.pages_visited.append({"url": url, "depth": depth})
                        ts.interaction_log.append({"type": nxt.get("type"), "url": url, "reason": nxt.get("reason","")[:200]})
                except Exception:
                    pass

                # Act
                t = nxt.get("type")
                if t == "done":
                    break
                elif t == "follow_link" and nxt.get("url"):
                    nxt_url = urljoin(url, nxt["url"])
                    if _normalize(nxt_url) not in self.visited:
                        self.frontier.append({"url": nxt_url, "depth": depth + 1, "reason": nxt.get("reason","")})
                elif t == "click" and nxt.get("selector"):
                    click_text = " ".join(str(nxt.get(key, "")) for key in ("reason", "text", "label")).lower()
                    mutation_words = (
                        "submit", "delete", "remove", "logout", "checkout", "purchase",
                        "invite", "approve", "reject", "upload", "change password",
                        "reset password", "role", "transfer", "create", "update",
                    )
                    if nxt.get("risk") in {"mutation", "high_risk"} or any(word in click_text for word in mutation_words):
                        self.interaction_log.append({
                            "type": "pause",
                            "url": redact(url),
                            "reason": "state-changing browser action requires approval",
                            "action": "click",
                        })
                        continue
                    try:
                        await page.click(nxt["selector"], timeout=4000)
                        await page.wait_for_timeout(2000)
                        new_url = page.url
                        if _normalize(new_url) not in self.visited:
                            self.frontier.append({"url": new_url, "depth": depth + 1, "reason": "after click"})
                    except Exception as e:
                        self.interaction_log.append({"type": "click_fail", "selector": nxt["selector"], "error": str(e)[:150]})
                elif t == "fill_form" and nxt.get("form_data"):
                    # Recon-only is observation-only.  Form filling and
                    # pressing Enter can submit mutations, even when the
                    # model describes it as exploration.
                    self.interaction_log.append({
                        "type": "pause",
                        "url": redact(url),
                        "reason": "form interaction requires explicit workflow approval",
                        "action": "fill_form",
                    })
                elif t == "scroll":
                    await page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
                    await page.wait_for_timeout(1000)

                # Also feed hunter tools (httpx probe for live hosts) — opportunistic every 10 pages
                if pages_done % 10 == 0:
                    try:
                        from tools.hunter_pipeline import httpx_probe
                        from core.identity_context import get_execution_context
                        from core.structured_runner import StructuredToolRunner
                        active = get_execution_context()
                        StructuredToolRunner(
                            repository=active.repository if active else None,
                            safety_kernel=active.safety_kernel if active else None,
                        ).execute(
                            httpx_probe, {"target": url}, target=url,
                            session_id=active.session_id if active else self.session_id,
                            job_id=active.job_id if active else "",
                            identity_id=active.identity_id if active else "",
                        )
                    except Exception:
                        pass
                # Expand frontier from current page links (BFS, limited)
                for link in snapshot.links[:5]:
                    if _normalize(link) not in self.visited and len(self.frontier) < 80:
                        if _in_scope(link, self.scope_rules):
                            self.frontier.append({"url": link, "depth": depth + 1, "reason": "discovered link"})

                pages_done += 1
                if check_cancelled(None):
                    break

            await ctx.close()
            return {
                "pages_visited": len(self.pages_visited),
                "visited_urls": list(self.visited)[:80],
                "pages_detail": self.pages_visited,
                "interaction_log": self.interaction_log[-50:],
                "xhr_captured": len(captured),
            }

        return _run_async(_crawl())


async def _observe(page, url: str, depth: int, captured: List[Dict]) -> PageSnapshot:
    """Build PageSnapshot from current page state."""
    try:
        title = await page.title()
    except Exception:
        title = ""
    try:
        text = await page.evaluate("() => document.body?.innerText?.slice(0, 800) ?? ''")
    except Exception:
        text = ""
    links = []
    forms = []
    inputs = []
    scripts = []
    buttons: List[Dict[str, Any]] = []
    try:
        links = await page.evaluate("() => Array.from(document.querySelectorAll('a[href]')).map(a=>a.href).filter((v,i,a)=>a.indexOf(v)===i).slice(0,30)")
    except Exception:
        pass
    try:
        forms = await page.evaluate("() => Array.from(document.querySelectorAll('form')).map(f=>({action:f.action||'', method:f.method||'get', inputs:Array.from(f.querySelectorAll('input,select,textarea')).map(i=>({name:i.name, id:i.id, type:i.type}))}))")
    except Exception:
        pass
    try:
        inputs = await page.evaluate("() => Array.from(document.querySelectorAll('input,select,textarea')).map(i=>({name:i.name, id:i.id, type:i.type})).filter(i=>i.name||i.id).slice(0,20)")
    except Exception:
        pass
    try:
        scripts = await page.evaluate("() => Array.from(document.querySelectorAll('script[src]')).map(s=>s.src).slice(0,10)")
    except Exception:
        pass
    try:
        buttons = await page.evaluate("() => Array.from(document.querySelectorAll('button, [role=button], a.btn')).map(b=>({text:(b.innerText||'').slice(0,40), selector: b.tagName.toLowerCase() + (b.id?'#'+b.id:'')})).filter(b=>b.text).slice(0,10)")
    except Exception:
        pass
    xhr = [c for c in captured if c.get("type") in ("xhr", "fetch")][-20:]
    return PageSnapshot(url=url, title=title, links=links, forms=forms, inputs=inputs, scripts=scripts, buttons=buttons, xhr=xhr, depth=depth, text_preview=text[:400])

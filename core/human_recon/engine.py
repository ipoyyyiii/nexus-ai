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
        invocation_timeout_seconds: float = 240.0,
        navigation_timeout_ms: int = 10000,
        dom_settle_ms: int = 1000,
        llm_timeout_seconds: float = 30.0,
    ):
        self.session_id = session_id
        self.target = target
        self.goal = goal
        self.scope_rules = scope_rules or []
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_clicks_per_page = max_clicks_per_page
        self.invocation_timeout_seconds = max(15.0, float(invocation_timeout_seconds))
        self.navigation_timeout_ms = max(1000, int(navigation_timeout_ms))
        self.dom_settle_ms = max(0, int(dom_settle_ms))
        self.llm_timeout_seconds = max(1.0, float(llm_timeout_seconds))
        self.visited: Set[str] = set()
        self.pages_visited: List[Dict[str, Any]] = []
        self.interaction_log: List[Dict[str, Any]] = []
        self.frontier: List[Dict[str, Any]] = [{"url": target, "depth": 0, "reason": "seed"}]

    def run(self) -> Dict[str, Any]:
        from tools.playwright_tools import _get_browser, _new_page, _run_async, PWTimeout
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
            from tools.playwright_tools import _goto_browser_page

            browser = await _get_browser()
            page, ctx = await _new_page(browser, origin=self.target)
            captured: List[Dict[str, Any]] = []
            llm_timeouts = 0
            llm_fallbacks = 0
            llm_error_codes: Dict[str, int] = {}
            navigation_timeouts = 0
            navigation_failures = 0
            clicks_by_page: Dict[str, int] = {}
            cancelled = False
            termination_reason = "frontier_exhausted"

            # Build one provider client for the entire crawl. Recreating a
            # ChatOpenAI client per page adds latency and made the previous
            # implementation especially sensitive to a slow remote tunnel.
            planner_llm = None
            try:
                from core.model_registry import build_chat_llm
                import os as _model_os

                preferred = None
                if _model_os.environ.get("NEXUS_LOCAL_LLM_ENABLED", "").lower() in ("1", "true", "yes", "on"):
                    from core.model_registry import _local_registry

                    local_models = _local_registry()
                    if local_models:
                        preferred = local_models[0]["id"]
                planner_llm = build_chat_llm(
                    preferred,
                    timeout_seconds=self.llm_timeout_seconds,
                )
            except Exception as exc:
                self.interaction_log.append({
                    "type": "llm_provider_unavailable",
                    "error": f"{type(exc).__name__}: {exc}"[:200],
                })

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
                    cancelled = True
                    termination_reason = "cancelled_before_page"
                    break

                # Captcha check + per-domain OPSEC & rate limit + mitmproxy route
                capture_start = len(captured)
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
                    # DOMContentLoaded plus a short bounded settle window is
                    # intentional. ``networkidle`` is not a reliable ready
                    # signal for SPAs with polling, analytics, or websockets.
                    await _goto_browser_page(
                        page,
                        url,
                        timeout_ms=self.navigation_timeout_ms,
                    )
                    navigation_status = "succeeded"
                except (PWTimeout, TimeoutError) as exc:
                    navigation_status = "timeout"
                    navigation_timeouts += 1
                    self.interaction_log.append({
                        "type": "navigation_timeout",
                        "url": redact(url),
                        "error": str(exc)[:200],
                    })
                except Exception as exc:
                    navigation_status = "failed"
                    navigation_failures += 1
                    self.interaction_log.append({
                        "type": "navigation_fail",
                        "url": redact(url),
                        "error": f"{type(exc).__name__}: {exc}"[:240],
                    })
                if check_cancelled(None):
                    cancelled = True
                    termination_reason = "cancelled_after_navigation"
                    break
                # ``page.content()`` serializes the whole document and can
                # block on a busy SPA even when its DOM is already usable.
                # Probe small DOM facts instead of making full serialization
                # a prerequisite for observing the page.
                dom_state = {}
                try:
                    dom_state = await asyncio.wait_for(
                        page.evaluate(
                            """() => ({
                                ready_state: document.readyState,
                                has_document_element: Boolean(document.documentElement),
                                has_body: Boolean(document.body),
                                body_text_length: (document.body?.innerText || '').length,
                                link_count: document.querySelectorAll('a[href]').length
                            })"""
                        ),
                        timeout=2,
                    )
                except Exception:
                    dom_state = {}
                if not isinstance(dom_state, dict):
                    dom_state = {}
                try:
                    page_title = await asyncio.wait_for(page.title(), timeout=2)
                except Exception:
                    page_title = ""
                dom_available = bool(
                    dom_state.get("has_document_element")
                    or dom_state.get("has_body")
                    or page_title
                )
                if not dom_available:
                    self.interaction_log.append({
                        "type": "dom_unavailable",
                        "url": redact(url),
                        "navigation_status": navigation_status,
                    })
                    # Preserve a network-only page instead of returning an
                    # apparently successful crawl with pages=[].
                    page_xhr = [
                        c for c in captured[capture_start:]
                        if c.get("type") in ("xhr", "fetch")
                    ][-20:]
                    self.pages_visited.append({
                        "url": redact(url),
                        "depth": depth,
                        "forms": 0,
                        "forms_detail": [],
                        "inputs": [],
                        "buttons": [],
                        "xhr_detail": redact(page_xhr),
                        "xhr": len(page_xhr),
                        "navigation_status": navigation_status,
                        "capture_status": "network_only",
                    })
                    pages_done += 1
                    continue
                try:
                    await page.wait_for_timeout(min(self.dom_settle_ms, 5000))
                    if await page.locator('[data-captcha], #captcha, [id*="captcha" i]').count() > 0:
                        self.interaction_log.append({"type": "pause", "url": url, "reason": "captcha detected"})
                        break
                except Exception as e:
                    self.interaction_log.append({"type": "error", "url": url, "error": str(e)[:200]})
                    continue

                rate_limiter.wait(_domain(url))
                self.visited.add(norm)

                # Observe
                snapshot = await _observe(page, url, depth, captured[capture_start:])
                self.pages_visited.append({"url": redact(url), "depth": depth, "forms": len(snapshot.forms), "forms_detail": redact(snapshot.forms), "inputs": redact(snapshot.inputs), "buttons": redact(snapshot.buttons), "xhr_detail": redact(snapshot.xhr), "xhr": len(snapshot.xhr), "navigation_status": navigation_status, "capture_status": "dom_observed"})

                # Decide
                try:
                    # ``llm_next`` is synchronous because the provider client
                    # is synchronous. Run it off the browser event loop and
                    # enforce a per-decision deadline so one slow Kaggle/ngrok
                    # inference cannot consume the entire crawl budget.
                    decision = await asyncio.wait_for(
                        asyncio.to_thread(
                            llm_next,
                            snapshot,
                            self.target,
                            self.goal,
                            history,
                            timeout_seconds=self.llm_timeout_seconds,
                            llm=planner_llm,
                        ),
                        timeout=self.llm_timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    llm_timeouts += 1
                    self.interaction_log.append({
                        "type": "llm_timeout",
                        "url": redact(url),
                        "timeout_seconds": self.llm_timeout_seconds,
                    })
                    decision = heuristic_next(snapshot)
                except Exception as exc:
                    self.interaction_log.append({
                        "type": "llm_fallback",
                        "url": redact(url),
                        "error": f"{type(exc).__name__}: {exc}"[:200],
                    })
                    decision = heuristic_next(snapshot)
                decision_source = str(decision.get("_decision_source") or "heuristic")
                llm_error_code = str(decision.get("_llm_error_code") or "")
                self.pages_visited[-1]["decision_source"] = decision_source
                if decision_source != "llm":
                    llm_fallbacks += 1
                if llm_error_code:
                    llm_error_codes[llm_error_code] = llm_error_codes.get(llm_error_code, 0) + 1
                    if llm_error_code == "llm_timeout":
                        llm_timeouts += 1
                if check_cancelled(None):
                    cancelled = True
                    termination_reason = "cancelled_after_decision"
                    break
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
                    termination_reason = "planner_done"
                    break
                elif t == "follow_link" and nxt.get("url"):
                    nxt_url = urljoin(url, nxt["url"])
                    if _normalize(nxt_url) not in self.visited:
                        self.frontier.append({"url": nxt_url, "depth": depth + 1, "reason": nxt.get("reason","")})
                elif t == "click" and nxt.get("selector"):
                    page_key = _normalize(url)
                    clicks_by_page.setdefault(page_key, 0)
                    if clicks_by_page[page_key] >= self.max_clicks_per_page:
                        self.interaction_log.append({
                            "type": "click_budget_exhausted",
                            "url": redact(url),
                            "limit": self.max_clicks_per_page,
                        })
                        t = "done"
                    else:
                        clicks_by_page[page_key] += 1
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
                    elif t == "click":
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
                    cancelled = True
                    termination_reason = "cancelled_after_page"
                    break

            try:
                await asyncio.wait_for(ctx.close(), timeout=5)
            except Exception:
                pass
            return {
                "status": "cancelled" if cancelled else "succeeded",
                "pages_visited": len(self.pages_visited),
                "visited_urls": list(self.visited)[:80],
                "pages_detail": self.pages_visited,
                "interaction_log": self.interaction_log[-50:],
                "xhr_captured": len(captured),
                "metrics": {
                    "llm_timeouts": llm_timeouts,
                    "llm_fallbacks": llm_fallbacks,
                    "llm_error_codes": llm_error_codes,
                    "navigation_timeouts": navigation_timeouts,
                    "navigation_failures": navigation_failures,
                    "termination_reason": termination_reason,
                    "max_pages": self.max_pages,
                    "max_depth": self.max_depth,
                    "max_clicks_per_page": self.max_clicks_per_page,
                },
            }

        return _run_async(_crawl(), timeout_seconds=self.invocation_timeout_seconds)


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

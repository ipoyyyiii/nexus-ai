"""Human-like crawl tool exposed to CrewAI agents."""

import json
import fnmatch
from urllib.parse import urlparse
from core.tool_decorator import crewai_tool as tool
from core.cancellation import check_cancelled
from core.redact import redact
from core.rate_limiter import rate_limiter
from core.structured_contract import ToolErrorV1, ToolResultV1


def _cancelled_result(url: str) -> ToolResultV1:
    return ToolResultV1(
        tool_name="human_recon_crawl",
        category="recon",
        target=url,
        status="cancelled",
        summary="Human recon cancelled before completion.",
        errors=[ToolErrorV1(
            code="browser_cancelled",
            message="Human recon was cancelled by the active job.",
            retryable=True,
        )],
        metrics={"termination_reason": "cancelled"},
    )


@tool("human_recon_crawl")
def human_recon_crawl(url: str, goal: str = "", session_id: str = "", structured: bool = False) -> str:
    """
    Human-like recon: stateful browser that clicks one-by-one, extracts JS, tries features/buttons,
    captures XHR/fetch after each interaction, and crawls subdomains. Returns GFM report.

    Args:
        url: Seed URL to crawl
        goal: Attack goal for prioritization
        session_id: Session for scope validation & state persistence
        structured: Return redacted browser workflow captures as JSON for Stage 4.
    """
    if check_cancelled(None):
        return _cancelled_result(url)
    # Resolve scope rules and bounded runtime settings from the session.  A
    # local vulnerable lab is intentionally broad enough for evaluation, but
    # it must not let the human-like browser loop consume the public 90-second
    # tool boundary before the deterministic recon lanes can run.
    scope_rules = []
    human_config = {}
    recon_config = {}
    session_context = {}
    if session_id:
        try:
            from api import session_store
            session_context = session_store.get(session_id) or {}
            scope_rules = session_context.get("scope_rules") or []
        except Exception:
            pass
    try:
        from core.config_loader import get_setting
        human_config = dict(get_setting("human_recon", {}) or {})
        recon_config = dict(get_setting("recon", {}) or {})
    except Exception:
        pass

    max_pages = max(1, min(60, int(human_config.get("max_pages", 60) or 60)))
    max_depth = max(0, min(3, int(human_config.get("max_depth", 3) or 3)))
    max_clicks = max(1, min(12, int(human_config.get("max_clicks_per_page", 12) or 12)))
    invocation_timeout = max(
        15.0,
        min(900.0, float(human_config.get("invocation_timeout_seconds", 240) or 240)),
    )
    navigation_timeout_ms = max(
        1000,
        min(30000, int(human_config.get("navigation_timeout_ms", 10000) or 10000)),
    )
    dom_settle_ms = max(
        0,
        min(5000, int(human_config.get("dom_settle_ms", 1000) or 1000)),
    )
    llm_timeout_seconds = max(
        1.0,
        min(120.0, float(human_config.get("llm_timeout_seconds", 30) or 30)),
    )

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    is_local_host = hostname in {"localhost", "host.docker.internal"} or hostname.endswith(
        (".local", ".test", ".internal", ".invalid")
    )
    explicit_local_scope = any(
        isinstance(rule, dict)
        and rule.get("rule_type") == "allow"
        and bool(rule.get("allow_private", False))
        and fnmatch.fnmatch(hostname, str(rule.get("pattern") or "").lower())
        for rule in scope_rules
    )
    if is_local_host and explicit_local_scope:
        local_bounds = dict(recon_config.get("local_lab_bounds") or {})
        max_pages = min(
            max_pages,
            max(1, min(12, int(local_bounds.get("human_recon_max_pages", 4) or 4))),
        )
        max_depth = min(
            max_depth,
            max(0, min(2, int(local_bounds.get("human_recon_max_depth", 1) or 1))),
        )
        max_clicks = min(
            max_clicks,
            max(1, min(8, int(local_bounds.get("human_recon_max_clicks_per_page", 6) or 6))),
        )

    from core.human_recon.engine import HumanReconEngine
    engine = HumanReconEngine(
        session_id=session_id,
        target=url,
        goal=goal,
        scope_rules=scope_rules,
        max_pages=max_pages,
        max_depth=max_depth,
        max_clicks_per_page=max_clicks,
        invocation_timeout_seconds=invocation_timeout,
        navigation_timeout_ms=navigation_timeout_ms,
        dom_settle_ms=dom_settle_ms,
        llm_timeout_seconds=llm_timeout_seconds,
    )
    try:
        result = engine.run()
    except TimeoutError:
        # Keep a bounded timeout observable as a partial tool result instead
        # of letting the outer compatibility adapter serialize an empty
        # exception message.  The structured integrity policy can then
        # continue with the other authoritative recon lanes.
        result = {
            "status": "partial",
            "error": "human recon reached its bounded browser timeout",
            "pages_visited": len(engine.pages_visited),
            "visited_urls": list(engine.visited)[:80],
            "pages_detail": engine.pages_visited,
            "interaction_log": engine.interaction_log[-50:],
            "xhr_captured": 0,
            "metrics": {
                "llm_timeouts": sum(1 for item in engine.interaction_log if item.get("type") == "llm_timeout"),
                "navigation_timeouts": sum(1 for item in engine.interaction_log if item.get("type") == "navigation_timeout"),
                "navigation_failures": sum(1 for item in engine.interaction_log if item.get("type") == "navigation_fail"),
                "termination_reason": "bounded_timeout",
            },
        }
    except Exception as exc:
        result = {
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
            "pages_visited": len(engine.pages_visited),
            "visited_urls": list(engine.visited)[:80],
            "pages_detail": engine.pages_visited,
            "interaction_log": engine.interaction_log[-50:],
            "xhr_captured": 0,
            "metrics": {},
        }
    if result.get("status") == "cancelled":
        return _cancelled_result(url)
    if structured:
        return json.dumps({
            "schema": "browser_recon_capture_v1",
            "status": result.get("status", "succeeded"),
            "error": result.get("error", ""),
            "pages": result.get("pages_detail", []),
            "visited_urls": result.get("visited_urls", []),
            "xhr_captured": result.get("xhr_captured", 0),
            "metrics": result.get("metrics", {}),
        }, ensure_ascii=False)
    # Format GFM
    lines = [f"# Human Recon Crawl: {url}", "", f"Status: {result.get('status', 'succeeded')}", ""]
    lines.append(f"Pages visited: {result['pages_visited']} | XHR captured: {result['xhr_captured']}")
    lines.append("")
    for p in result["pages_detail"][:20]:
        lines.append(f"- {p['url']} (depth {p['depth']}, forms {p['forms']}, xhr {p['xhr']})")
    if result["interaction_log"]:
        lines.append("")
        lines.append("## Interaction log")
        for entry in result["interaction_log"][-15:]:
            lines.append(f"- {entry}")
    return "\n".join(lines)

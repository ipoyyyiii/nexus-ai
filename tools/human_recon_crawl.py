"""Human-like crawl tool exposed to CrewAI agents."""

import json
from core.tool_decorator import crewai_tool as tool
from core.cancellation import check_cancelled
from core.redact import redact
from core.rate_limiter import rate_limiter


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
        return "CANCELLED"
    # Resolve scope rules from session
    scope_rules = []
    if session_id:
        try:
            from api import session_store
            ctx = session_store.get(session_id)
            if ctx:
                scope_rules = ctx.get("scope_rules") or []
        except Exception:
            pass
    from core.human_recon.engine import HumanReconEngine
    engine = HumanReconEngine(session_id=session_id, target=url, goal=goal, scope_rules=scope_rules)
    result = engine.run()
    if structured:
        return json.dumps({"schema": "browser_recon_capture_v1", "pages": result.get("pages_detail", []), "visited_urls": result.get("visited_urls", []), "xhr_captured": result.get("xhr_captured", 0)}, ensure_ascii=False)
    # Format GFM
    lines = [f"# Human Recon Crawl: {url}", ""]
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

"""Human-like crawl tool exposed to CrewAI agents."""

import json
from crewai.tools import tool
from core.cancellation import check_cancelled
from core.rate_limiter import rate_limiter


@tool("human_recon_crawl")
def human_recon_crawl(url: str, goal: str = "", session_id: str = "") -> str:
    """
    Human-like recon: stateful browser that clicks one-by-one, extracts JS, tries features/buttons,
    captures XHR/fetch after each interaction, and crawls subdomains. Returns GFM report.

    Args:
        url: Seed URL to crawl
        goal: Attack goal for prioritization
        session_id: Session for scope validation & state persistence
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

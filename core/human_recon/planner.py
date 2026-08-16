"""LLM decision planner for human-like recon."""

from typing import Any, Dict, List
import json

from core.human_recon.page_snapshot import PageSnapshot


FALLBACK_PRIORITY = {
    "form": 10,
    "api_link": 8,
    "button": 5,
    "link": 3,
}


def heuristic_next(snapshot: PageSnapshot) -> Dict[str, Any]:
    """Fallback when LLM unavailable: forms > api links > buttons > plain links."""
    if snapshot.forms:
        form = snapshot.forms[0]
        return {
            "next_action": {
                "type": "fill_form",
                "selector": form.get("action") or "form",
                "form_data": {inp.get("name") or inp.get("id"): "test" for inp in form.get("inputs", [])[:3] if inp.get("name") or inp.get("id")},
                "reason": "Heuristic: try first form with dummy data",
            },
            "priority": FALLBACK_PRIORITY["form"],
        }
    api_links = [l for l in snapshot.links if any(p in l for p in ("/api/", "/v", "/graphql"))]
    if api_links:
        return {"next_action": {"type": "follow_link", "url": api_links[0], "reason": "Heuristic: api-looking link"}, "priority": FALLBACK_PRIORITY["api_link"]}
    if snapshot.buttons:
        btn = snapshot.buttons[0]
        sel = btn.get("selector") or btn.get("text") or "button"
        return {"next_action": {"type": "click", "selector": sel, "reason": "Heuristic: first button"}, "priority": FALLBACK_PRIORITY["button"]}
    if snapshot.links:
        return {"next_action": {"type": "follow_link", "url": snapshot.links[0], "reason": "Heuristic: first link"}, "priority": FALLBACK_PRIORITY["link"]}
    return {"next_action": {"type": "done", "reason": "No candidates"}, "priority": 0}


def llm_next(snapshot: PageSnapshot, target: str, goal: str, history: List[str], ollama_base: str = "") -> Dict[str, Any]:
    """Ask local/free LLM for next action. Fallback to heuristic on failure."""
    # Lazy import to avoid circular
    try:
        from core.model_registry import build_chat_llm
        # Try local first if enabled, else free
        import os
        preferred = None
        if os.environ.get("NEXUS_LOCAL_LLM_ENABLED", "").lower() in ("1", "true"):
            from core.model_registry import _local_registry
            locals_ = _local_registry()
            if locals_:
                preferred = locals_[0]["id"]
        llm = build_chat_llm(preferred)
        from langchain_core.messages import HumanMessage, SystemMessage
        prompt = f"""You are Recon Decision Planner. Output JSON only.
Target: {target}
Goal: {goal}
Current URL: {snapshot.url} (depth {snapshot.depth})
Links: {snapshot.links[:10]}
Forms: {snapshot.forms[:2]}
Buttons: {snapshot.buttons[:5]}
History last 5: {history[-5:]}
Choose ONE action. Types: click (selector), fill_form (form_data), follow_link (url), scroll, back, done.
Return: {{"next_action": {{"type": "...", "selector": "...", "url": "...", "form_data": {{}}}}, "priority": int}}"""
        resp = llm.invoke([SystemMessage(content="You output JSON only."), HumanMessage(content=prompt)])
        parsed = json.loads(str(resp.content).strip().strip("```json").strip("```").strip())
        if "next_action" in parsed:
            return parsed
    except Exception:
        pass
    return heuristic_next(snapshot)

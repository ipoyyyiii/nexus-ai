"""LLM decision planner for human-like recon."""

from typing import Any, Dict, List
import json

from core.human_recon.page_snapshot import PageSnapshot


_UNSET = object()


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


def llm_next(
    snapshot: PageSnapshot,
    target: str,
    goal: str,
    history: List[str],
    ollama_base: str = "",
    timeout_seconds: float = 30.0,
    llm: Any = _UNSET,
) -> Dict[str, Any]:
    """Ask local/free LLM for next action with an explicit fallback reason."""

    def fallback(error_code: str) -> Dict[str, Any]:
        result = heuristic_next(snapshot)
        result["_decision_source"] = "heuristic"
        result["_llm_error_code"] = error_code
        return result

    # Lazy import to avoid circular
    try:
        if llm is _UNSET:
            from core.model_registry import build_chat_llm
            # Try local first when enabled, otherwise use the configured
            # provider. The caller can pass a cached client for a crawl.
            import os
            preferred = None
            if os.environ.get("NEXUS_LOCAL_LLM_ENABLED", "").lower() in ("1", "true"):
                from core.model_registry import _local_registry
                locals_ = _local_registry()
                if locals_:
                    preferred = locals_[0]["id"]
            llm = build_chat_llm(
                preferred,
                timeout_seconds=max(1.0, float(timeout_seconds)),
            )
        if llm is None:
            return fallback("llm_provider_unavailable")
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
            parsed["_decision_source"] = "llm"
            parsed["_llm_error_code"] = ""
            return parsed
        return fallback("llm_invalid_schema")
    except json.JSONDecodeError:
        return fallback("llm_invalid_json")
    except TimeoutError:
        return fallback("llm_timeout")
    except Exception as exc:
        error_code = "llm_timeout" if "timeout" in type(exc).__name__.lower() or "timeout" in str(exc).lower() else "llm_provider_error"
        return fallback(error_code)

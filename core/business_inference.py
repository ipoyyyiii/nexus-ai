"""Infer business invariants from pages_visited + XHR for global understanding."""

from typing import Any, Dict, List


def infer_invariants(pages_visited: List[Dict[str, Any]], attack_surface: Dict[str, Any]) -> List[str]:
    """LLM-driven inference: apa aturan bisnis yang harusnya berlaku."""
    if not pages_visited:
        return []
    try:
        from core.model_registry import build_chat_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        import os, json as _json
        pref = None
        if os.environ.get("NEXUS_LOCAL_LLM_ENABLED", "").lower() in ("1", "true"):
            from core.model_registry import _local_registry
            lr = _local_registry()
            if lr:
                pref = lr[0]["id"]
        llm = build_chat_llm(pref)
        ctx = str(pages_visited[-10:])[:2500] + str(attack_surface)[:1500]
        prompt = f"Infer business invariants from this app crawl: {ctx}\nReturn JSON list of invariants like ['cart total must equal sum(price*qty)', 'admin role required for /admin']"
        resp = llm.invoke([SystemMessage(content="You output JSON list only."), HumanMessage(content=prompt)])
        text = str(resp.content).strip()
        import re as _re
        m = _re.search(r"\[.*\]", text, _re.DOTALL)
        if m:
            data = _json.loads(m.group(0))
            if isinstance(data, list):
                return [str(x)[:300] for x in data[:12]]
    except Exception:
        pass
    # Fallback heuristic invariants
    invariants = []
    text = str(pages_visited).lower()
    if any(k in text for k in ("cart", "checkout", "payment", "price", "qty")):
        invariants.append("price/quantity must not be tampered, total consistent")
    if "admin" in text:
        invariants.append("admin endpoints require admin role")
    return invariants

"""Dynamic goal verification via semantic LLM check."""

import re


def is_achieved(goal: str, evidence_text: str) -> bool:
    if not goal or not evidence_text:
        return False
    # Fast regex for common cases
    goal_l, ev_l = goal.lower(), evidence_text.lower()
    if "flag" in goal_l and re.search(r"flag\{", ev_l, re.I):
        return True
    # LLM semantic check for ANY goal
    try:
        from core.model_registry import build_chat_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        import os
        preferred = None
        if os.environ.get("NEXUS_LOCAL_LLM_ENABLED", "").lower() in ("1", "true"):
            from core.model_registry import _local_registry
            lr = _local_registry()
            if lr:
                preferred = lr[0]["id"]
        llm = build_chat_llm(preferred)
        prompt = f'Goal: "{goal}"\nFull evidence context: {evidence_text[:5000]}\nHas the goal been achieved? Be strict: require concrete evidence, not hallucination. Answer ONLY "yes" or "no".'
        resp = llm.invoke([SystemMessage(content="You answer yes/no only."), HumanMessage(content=prompt)])
        return str(resp.content).strip().lower().startswith("yes")
    except Exception:
        # Fallback: simple keyword overlap
        keywords = re.findall(r"\w{4,}", goal_l)
        return any(kw in ev_l for kw in keywords[:5])

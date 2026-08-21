"""Internal discovery persistence; no self-HTTP hop is allowed."""

from __future__ import annotations

from typing import Any, Dict


def record_discovered_endpoint(repository: Any, session_id: str, url: str, source: str) -> Dict[str, Any]:
    url = str(url or "").strip()
    if not repository or not session_id or not url:
        raise ValueError("discovered endpoint requires repository, session, and URL")
    payload = {"url": url[:2000], "source": str(source or "unknown")[:200]}
    if hasattr(repository, "append_event"):
        from core.execution_contract import ExecutionEventV1
        repository.append_event(ExecutionEventV1(
            session_id=session_id,
            event_type="endpoint_discovered",
            payload=payload,
        ))
        return {"status": "success", **payload}
    sb = getattr(repository, "sb", None)
    if sb is None:
        raise RuntimeError("discovery repository unavailable")
    sb.table("session_memory").insert({
        "session_id": session_id,
        "target_domain": url,
        "memory_type": "discovered_endpoint",
        "content": payload,
    }).execute()
    return {"status": "success", **payload}

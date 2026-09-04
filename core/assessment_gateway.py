"""AI-native final assessment adapter.

The authoritative report is still generated from durable evidence.  This
module only asks the configured reasoning provider for an evidence-grounded
assessment and persists the provider telemetry through the same reasoning
repository used by the autonomous action loop.  It deliberately never
promotes a candidate or executes a model-proposed action.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from typing import Any, Dict, List, Optional, Sequence

from core.config_loader import get_config
from core.reasoning_gateway import ReasoningGateway, reasoning_gateway_limits
from core.structured_contract import ModelCallTraceV1, ReasoningCycleV1


def _model_id(preferred: str = "") -> str:
    configured = get_config().get("reasoning", {}) or {}
    value = str(
        preferred
        or configured.get("primary_model_id")
        or os.environ.get("NEXUS_REASONING_MODEL_ID", "")
    ).strip()
    if value:
        return value
    models = [
        item.strip()
        for item in os.environ.get("NEXUS_LOCAL_LLM_MODELS", "").split(",")
        if item.strip()
    ]
    return models[0] if models else ""


def _attempt_calls(
    response: Any,
    *,
    cycle_id: str,
    session_id: str,
    job_id: str,
) -> List[Dict[str, Any]]:
    """Convert gateway attempts into the durable model-call contract."""
    attempts = list(getattr(response, "attempts", []) or [])
    if not attempts and getattr(response, "trace", None) is not None:
        attempts = list(getattr(response.trace, "attempts", []) or [])
    request_digest = str(getattr(response, "request_digest", "") or "")
    rows: List[Dict[str, Any]] = []
    for index, item in enumerate(attempts, start=1):
        value = item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item or {})
        attempt_number = int(value.get("attempt") or index)
        rows.append(ModelCallTraceV1(
            call_id=f"{cycle_id}:attempt:{attempt_number}",
            cycle_id=cycle_id,
            session_id=session_id,
            job_id=job_id,
            model_id=str(value.get("model_id") or ""),
            provider=str(value.get("provider") or ""),
            prompt_version="nexus-reasoning-gateway.v1",
            attempt_number=attempt_number,
            fallback_index=max(0, int(value.get("fallback_index") or 0)),
            status="succeeded" if str(value.get("status")) == "succeeded" else "failed",
            input_digest=request_digest,
            output_digest=str(value.get("output_digest") or ""),
            latency_ms=float(value.get("latency_ms") or 0.0),
            error_code=str(value.get("error_type") or ""),
            metadata={
                "output_bytes": int(value.get("output_bytes") or 0),
                "retry_index": max(0, int(value.get("retry_index") or 0)),
                "purpose": "assessment",
            },
        ).model_dump(mode="json"))
    for index, item in enumerate(rows):
        if str(item.get("status") or "").lower() != "failed":
            continue
        later_success = next(
            (
                candidate for candidate in rows[index + 1:]
                if str(candidate.get("status") or "").lower() == "succeeded"
            ),
            None,
        )
        if later_success:
            item.setdefault("metadata", {})["recovered_by_call_id"] = later_success["call_id"]
            item["metadata"]["recovery_type"] = "provider_fallback"
    return rows


def _persist_assessment(
    repository: Any,
    *,
    response: Any,
    cycle_id: str,
    session_id: str,
    job_id: str,
    target: str,
    goal: str,
    model_id: str,
    model_calls: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    status = "succeeded" if bool(getattr(response, "success", False)) else "failed"
    hypotheses = [
        item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item)
        for item in (getattr(response, "hypotheses", []) or [])
    ]
    actions = [
        item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item)
        for item in (getattr(response, "actions", []) or [])
    ]
    stop = getattr(response, "stop", None)
    stop_payload = stop.model_dump(mode="json") if hasattr(stop, "model_dump") else dict(stop or {})
    cycle = ReasoningCycleV1(
        cycle_id=cycle_id,
        session_id=session_id,
        job_id=job_id,
        objective=f"Assess durable evidence for: {goal}"[:2000],
        mode="autonomous",
        status=status,
        model_id=model_id,
        prompt_version="nexus-reasoning-gateway.v1",
        action_budget=len(actions),
        cycle_number=1,
        max_cycles=1,
        selected_action_ids=[],
        hypothesis_ids=[str(item.get("hypothesis_id") or "") for item in hypotheses if item.get("hypothesis_id")],
        stop_condition_ids=[str(stop_payload.get("stop_condition_id") or "")]
        if stop_payload.get("stop_condition_id") else [],
        stop_reason=str(stop_payload.get("reason") or "")[:2000],
        input_digest=str(getattr(response, "request_digest", "") or ""),
        output_digest=str(getattr(response, "output_digest", "") or ""),
        budget_snapshot={"purpose": "assessment", "target_digest": hashlib.sha256(target.encode()).hexdigest()[:32]},
    ).model_dump(mode="json")
    payload = {
        "cycle": cycle,
        "hypotheses": hypotheses,
        # Assessment actions are proposals only and are never dispatched from
        # this adapter. They remain durable for audit/review.
        "actions": actions,
        "stop_conditions": [stop_payload],
        "model_traces": [],
        "model_calls": list(model_calls),
        "branches": [],
        "branch_transitions": [],
        "evidence_gaps": [],
        "decision": {
            "decision_id": f"assessment_decision_{uuid.uuid4().hex}",
            "cycle_id": cycle_id,
            "session_id": session_id,
            "selected_action_ids": [],
            "rejected_action_ids": [],
            "rationale": "Assessment is advisory; deterministic validators remain authoritative.",
            "deterministic": True,
            "input_digest": str(getattr(response, "request_digest", "") or ""),
        },
    }
    persistence = repository.save_reasoning_result(session_id, payload)
    return {"ok": True, "persistence": persistence or {}, "cycle_id": cycle_id}


def run_gateway_assessment(
    *,
    session_id: str,
    job_id: str,
    target: str,
    goal: str,
    phase_results: Dict[str, Any],
    repository: Any,
    reasoning_model_id: str = "",
    fallback_model_ids: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Run one evidence-grounded assessment through the canonical gateway."""
    primary = _model_id(reasoning_model_id)
    cycle_id = f"assessment_{uuid.uuid4().hex}"
    if not primary:
        return {
            "status": "failed",
            "success": False,
            "cycle_id": cycle_id,
            "error_code": "assessment_model_not_configured",
            "model_calls": [],
        }

    configured = get_config().get("reasoning", {}) or {}
    gateway = ReasoningGateway(
        primary_model_id=primary,
        fallback_model_ids=list(fallback_model_ids or configured.get("fallback_model_ids", []) or []),
        limits=reasoning_gateway_limits(configured),
    )
    response = gateway.reason(
        goal=(
            "Assess the supplied durable pentest evidence and identify only "
            "evidence-grounded hypotheses. Do not execute tools, assign a "
            "validated status, or invent impact. Return no actions.\n"
            + str(goal or "")
        ),
        structured_context={
            "mission_phase": "assessment",
            "target": target,
            "session_id": session_id,
            "phase_results": phase_results,
        },
        available_capabilities=[],
        session_id=session_id,
        cycle_id=cycle_id,
    )
    calls = _attempt_calls(response, cycle_id=cycle_id, session_id=session_id, job_id=job_id)
    result: Dict[str, Any] = {
        "status": "succeeded" if response.success else "failed",
        "success": bool(response.success),
        "cycle_id": cycle_id,
        "model_id": response.model_id or primary,
        "provider": response.provider,
        "hypotheses": [item.model_dump(mode="json") for item in response.hypotheses],
        "actions": [item.model_dump(mode="json") for item in response.actions],
        "stop": response.stop.model_dump(mode="json"),
        "model_calls": calls,
        "failure": response.failure.model_dump(mode="json") if response.failure else None,
    }
    try:
        result["persistence"] = _persist_assessment(
            repository,
            response=response,
            cycle_id=cycle_id,
            session_id=session_id,
            job_id=job_id,
            target=target,
            goal=goal,
            model_id=response.model_id or primary,
            model_calls=calls,
        )
    except Exception as exc:
        result["status"] = "partial"
        result["success"] = False
        result["persistence_error"] = type(exc).__name__
    return result


__all__ = ["run_gateway_assessment"]

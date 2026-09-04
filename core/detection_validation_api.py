"""FastAPI routes for Stage 9 Validation V2 diagnostics and revalidation."""

from __future__ import annotations

from typing import Any, Callable, Dict

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

from core.detection_validation_repository import DetectionValidationRepository
from core.detection_validation_v2 import ValidationEngineV2, validation_policy_registry_v2
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1


class ValidationV2Request(BaseModel):
    mode: str = Field(default="autonomous", pattern="^autonomous$")
    policy_id: str = Field(default="", max_length=200)


def register_detection_validation_routes(
    app: Any,
    require_api_key: Callable[..., Any],
    structured_repository: Any,
    session_store: Any,
    supabase: Any,
) -> Dict[str, Any]:
    repository = DetectionValidationRepository(supabase)
    memory: Dict[str, Any] = {"traces": {}}

    def _load(session_id: str, candidate_id: str) -> tuple[CandidateFindingV1, list[ObservationV1]]:
        row = structured_repository.get_candidate(session_id, candidate_id)
        links = structured_repository.sb.table("candidate_evidence").select("observation_id").eq("candidate_id", candidate_id).execute().data or []
        observations: list[ObservationV1] = []
        for link in links:
            rows = structured_repository.sb.table("observations").select("*").eq("observation_id", link["observation_id"]).limit(1).execute().data or []
            if rows:
                observations.append(ObservationV1(**rows[0]))
        candidate = CandidateFindingV1(**row)
        candidate.observation_ids = [item.observation_id for item in observations]
        return candidate, observations

    def _evaluate(session_id: str, candidate_id: str, mode: str = "autonomous", policy_id: str = "", *, persist: bool = True, apply_status: bool = True) -> Dict[str, Any]:
        try:
            candidate, observations = _load(session_id, candidate_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        policy = validation_policy_registry_v2.resolve(candidate)
        if policy_id:
            requested = validation_policy_registry_v2.get(policy_id)
            if not requested:
                raise HTTPException(status_code=404, detail="Validation policy not found.")
            if not policy or requested.policy_id != policy.policy_id:
                raise HTTPException(status_code=409, detail="Requested policy does not match candidate family.")
        result = ToolResultV1(tool_name="validation_v2", category="validation", target=candidate.target_url, observations=observations, candidate_findings=[candidate])
        selected = ValidationEngineV2(registry=validation_policy_registry_v2)
        decision = selected.validate(result, mode="autonomous", apply_status=apply_status)[0]
        trace = selected.last_traces[0]
        if persist:
            try:
                repository.save_trace(trace, decision)
                if apply_status:
                    structured_repository.sb.table("candidate_findings").update({"status": candidate.status, "confidence_score": candidate.confidence_score, "confidence_reasons": candidate.confidence_reasons}).eq("session_id", session_id).eq("candidate_id", candidate_id).execute()
            except Exception as exc:
                raise HTTPException(status_code=503, detail=f"Validation trace persistence unavailable: {type(exc).__name__}") from exc
        else:
            memory["traces"].setdefault(candidate_id, []).append(trace.model_dump(mode="json"))
        return {"candidate": candidate.model_dump(mode="json"), "decision": decision.model_dump(mode="json"), "trace": trace.model_dump(mode="json"), "mode": "autonomous", "persisted": persist}

    @app.get("/validation/v2/policies")
    async def list_validation_v2_policies(active_only: bool = True, _: bool = Depends(require_api_key)):
        try:
            rows = repository.list_policies(active_only)
            if rows:
                return {"validator_version": ValidationEngineV2.VERSION, "policies": rows}
        except Exception:
            pass
        policies = validation_policy_registry_v2.list(active_only)
        return {"validator_version": ValidationEngineV2.VERSION, "registry_fingerprint": validation_policy_registry_v2.fingerprint(), "policies": [item.model_dump(mode="json") for item in policies]}

    @app.get("/validation/v2/policies/{policy_id}")
    async def get_validation_v2_policy(policy_id: str, _: bool = Depends(require_api_key)):
        policy = validation_policy_registry_v2.get(policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="Validation policy not found.")
        return {"policy": policy.model_dump(mode="json"), "fingerprint": policy.fingerprint()}

    @app.post("/sessions/{session_id}/candidates/{candidate_id}/validation-v2")
    async def validate_candidate_v2(session_id: str, candidate_id: str, req: ValidationV2Request, _: bool = Depends(require_api_key)):
        session_store.require(session_id)
        return _evaluate(session_id, candidate_id, "autonomous", req.policy_id, persist=True, apply_status=True)

    @app.post("/sessions/{session_id}/candidates/{candidate_id}/validation-v2/compare")
    async def compare_candidate_v2(session_id: str, candidate_id: str, _: bool = Depends(require_api_key)):
        session_store.require(session_id)
        authoritative = _evaluate(session_id, candidate_id, "autonomous", persist=True, apply_status=True)
        return {"candidate_id": candidate_id, "authoritative": authoritative, "status_changed": True}

    @app.get("/sessions/{session_id}/candidates/{candidate_id}/validation-v2/traces")
    async def list_candidate_v2_traces(session_id: str, candidate_id: str, limit: int = 100, _: bool = Depends(require_api_key)):
        session_store.require(session_id)
        try:
            rows = repository.list_traces(candidate_id, limit)
        except Exception:
            rows = []
        rows.extend(memory["traces"].get(candidate_id, []))
        return {"session_id": session_id, "candidate_id": candidate_id, "traces": rows[: max(1, min(limit, 500))]}

    @app.get("/validation/v2/gaps")
    async def validation_v2_gaps(_: bool = Depends(require_api_key)):
        return {"validator_version": ValidationEngineV2.VERSION, "registry_fingerprint": validation_policy_registry_v2.fingerprint(), "gaps": [{"policy_id": item.policy_id, "family": item.vulnerability_family, "status": "supported" if item.active else "inactive"} for item in validation_policy_registry_v2.list(False)]}

    return memory

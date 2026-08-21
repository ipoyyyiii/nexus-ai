"""Persistence adapter for Stage 9 policy and validation traces.

Writes are append-only.  When migration 009 is not installed, callers may use
the in-memory fallback supplied by the API, but this repository never silently
turns a failed persistence write into a validated finding.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from core.detection_validation_v2 import (
    ValidationDecisionV2,
    ValidationPolicyV2,
    ValidationTraceV2,
)


class DetectionValidationRepository:
    def __init__(self, supabase: Any):
        self.sb = supabase

    def save_policy(self, policy: ValidationPolicyV2) -> None:
        self.sb.table("validation_policy_versions").upsert({
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "schema_version": policy.schema_version,
            "vulnerability_family": policy.vulnerability_family,
            "subtypes": policy.subtypes,
            "mandatory_observation_roles": policy.mandatory_observation_roles,
            "minimum_iterations": policy.minimum_iterations,
            "requires_baseline": policy.requires_baseline,
            "requires_control": policy.requires_control,
            "requires_clean_reproduction": policy.requires_clean_reproduction,
            "requires_cleanup": policy.requires_cleanup,
            "required_evidence_kinds": policy.required_evidence_kinds,
            "failure_classification": policy.failure_classification,
            "thresholds": policy.thresholds,
            "noise_tolerance": policy.noise_tolerance,
            "description": policy.description,
            "fingerprint": policy.fingerprint(),
            "active": policy.active,
        }, on_conflict="policy_id,policy_version", ignore_duplicates=True).execute()

    def save_policies(self, policies: Iterable[ValidationPolicyV2]) -> None:
        for policy in policies:
            self.save_policy(policy)

    def list_policies(self, active_only: bool = True) -> List[Dict[str, Any]]:
        query = self.sb.table("validation_policy_versions").select("*")
        if active_only:
            query = query.eq("active", True)
        return query.order("policy_id").order("policy_version", desc=True).execute().data or []

    def save_trace(self, trace: ValidationTraceV2, decision: Optional[ValidationDecisionV2] = None) -> None:
        decision = decision or ValidationDecisionV2(
            candidate_id=trace.candidate_id,
            policy_id=trace.policy_id,
            policy_version=trace.policy_version,
            decision=trace.decision,
            checks=trace.checks,
            evidence_ids=trace.evidence_ids,
            input_digest=trace.context.input_digest,
        )
        self.sb.table("validation_traces_v2").insert({
            "trace_id": trace.trace_id,
            "validation_run_id": decision.validation_run_id,
            "candidate_id": trace.candidate_id,
            "policy_id": trace.policy_id,
            "policy_version": trace.policy_version,
            "validator_version": trace.validator_version,
            "context": trace.context.model_dump(mode="json"),
            "checks": [item.model_dump(mode="json") for item in trace.checks],
            "decision": trace.decision,
            "evidence_ids": trace.evidence_ids,
            "shadow_decision": trace.shadow_decision,
            "input_digest": trace.context.input_digest,
            "created_at": trace.created_at,
        }).execute()

        # Existing validation tables remain compatible; the new columns are
        # additive in migration 009 and are ignored by older installations.
        self.sb.table("validation_runs").insert({
            "validation_run_id": decision.validation_run_id,
            "candidate_id": decision.candidate_id,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "decision": decision.decision,
            "score": decision.score,
            "reason": decision.reason,
            "schema_version": decision.schema_version,
            "input_digest": decision.input_digest,
            "evidence_ids": decision.evidence_ids,
            "observation_ids": decision.observation_ids,
            "failure_classification": decision.failure_classification,
            "mode": decision.mode,
            "validator_version": "2.0",
        }).execute()
        for check in decision.checks:
            self.sb.table("validation_checks").insert({
                "validation_run_id": decision.validation_run_id,
                "check_name": check.check_id,
                "check_id": check.check_id,
                "passed": check.passed,
                "details": check.model_dump(mode="json"),
                "schema_version": check.schema_version,
                "reason": check.reason,
                "evidence_ids": check.evidence_ids,
                "observation_ids": check.observation_ids,
                "input_digest": check.input_digest,
                "failure_classification": check.failure_classification,
            }).execute()

    def save_traces(self, traces: Iterable[ValidationTraceV2], decisions: Iterable[ValidationDecisionV2]) -> None:
        for trace, decision in zip(traces, decisions):
            self.save_trace(trace, decision)

    def list_traces(self, candidate_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        query = self.sb.table("validation_traces_v2").select("*")
        if candidate_id:
            query = query.eq("candidate_id", candidate_id)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute().data or []


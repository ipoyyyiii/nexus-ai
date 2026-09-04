"""Persistence adapter for Stage 9 policy and validation traces.

Writes are append-only.  When migration 009 is not installed, callers may use
the in-memory fallback supplied by the API, but this repository never silently
turns a failed persistence write into a validated finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from core.detection_validation_v2 import (
    ValidationDecisionV2,
    ValidationPolicyV2,
    ValidationTraceV2,
)


@dataclass(frozen=True)
class ValidationPersistenceReceipt:
    """Proof that one validation run and all of its checks were written."""

    validation_run_id: str
    candidate_id: str
    decision: str


class ValidationPersistenceError(RuntimeError):
    """Typed, fail-closed persistence error for candidate validation data."""

    code = "validation_persistence_error"
    retryable = True

    def __init__(
        self,
        message: str,
        *,
        candidate_id: str = "",
        validation_run_id: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.candidate_id = candidate_id
        self.validation_run_id = validation_run_id
        self.details = details or {}
        super().__init__(message)

    def __str__(self) -> str:
        context = []
        if self.candidate_id:
            context.append(f"candidate_id={self.candidate_id}")
        if self.validation_run_id:
            context.append(f"validation_run_id={self.validation_run_id}")
        suffix = f" ({', '.join(context)})" if context else ""
        return f"{self.code}: {self.message}{suffix}"


class CandidateNotPersistedError(ValidationPersistenceError):
    code = "candidate_not_persisted"


class ValidationForeignKeyError(ValidationPersistenceError):
    code = "validation_candidate_fk_violation"
    retryable = False


class ValidationStatusIntegrityError(ValidationPersistenceError):
    code = "validated_status_without_successful_validation"
    retryable = False


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

    def _candidate_exists(self, candidate_id: str) -> bool:
        try:
            rows = (
                self.sb.table("candidate_findings")
                .select("candidate_id")
                .eq("candidate_id", candidate_id)
                .limit(1)
                .execute()
                .data
                or []
            )
        except Exception as exc:
            raise ValidationPersistenceError(
                f"Unable to verify candidate durability: {type(exc).__name__}",
                candidate_id=candidate_id,
                details={"operation": "candidate_lookup"},
            ) from exc
        return bool(rows)

    def require_candidate(self, candidate_id: str) -> None:
        if not candidate_id or not self._candidate_exists(candidate_id):
            raise CandidateNotPersistedError(
                "Candidate must be durably persisted before validation_runs.",
                candidate_id=candidate_id,
                details={"operation": "candidate_precondition"},
            )

    @staticmethod
    def _is_foreign_key_error(exc: Exception) -> bool:
        values = [
            str(exc),
            str(getattr(exc, "code", "")),
            str(getattr(exc, "pgcode", "")),
        ]
        text = " ".join(values).lower()
        return "23503" in text or "foreign key" in text or "violates.*constraint" in text

    def _write(self, table_name: str, row: Dict[str, Any], *, conflict: str, candidate_id: str, validation_run_id: str) -> None:
        try:
            self.sb.table(table_name).upsert(
                row,
                on_conflict=conflict,
                ignore_duplicates=True,
            ).execute()
        except Exception as exc:
            if self._is_foreign_key_error(exc):
                raise ValidationForeignKeyError(
                    f"{table_name} rejected a candidate/validation foreign key.",
                    candidate_id=candidate_id,
                    validation_run_id=validation_run_id,
                    details={"table": table_name, "operation": "upsert"},
                ) from exc
            raise ValidationPersistenceError(
                f"Unable to persist {table_name}: {type(exc).__name__}",
                candidate_id=candidate_id,
                validation_run_id=validation_run_id,
                details={"table": table_name, "operation": "upsert"},
            ) from exc

    def _verify_validation_run(self, validation_run_id: str, candidate_id: str, decision: str) -> None:
        try:
            rows = (
                self.sb.table("validation_runs")
                .select("validation_run_id,candidate_id,decision")
                .eq("validation_run_id", validation_run_id)
                .eq("candidate_id", candidate_id)
                .limit(1)
                .execute()
                .data
                or []
            )
        except Exception as exc:
            raise ValidationPersistenceError(
                f"Unable to verify validation_runs durability: {type(exc).__name__}",
                candidate_id=candidate_id,
                validation_run_id=validation_run_id,
                details={"operation": "validation_run_lookup"},
            ) from exc
        if not rows or rows[0].get("decision") != decision:
            raise ValidationPersistenceError(
                "validation_runs write was not durably confirmed.",
                candidate_id=candidate_id,
                validation_run_id=validation_run_id,
                details={"operation": "validation_run_verify", "expected_decision": decision},
            )

    def has_successful_validation(self, candidate_id: str) -> bool:
        """Return true only for a validated run with at least one durable check."""

        self.require_candidate(candidate_id)
        try:
            rows = (
                self.sb.table("validation_runs")
                .select("validation_run_id")
                .eq("candidate_id", candidate_id)
                .eq("decision", "validated")
                .execute()
                .data
                or []
            )
            for row in rows:
                checks = (
                    self.sb.table("validation_checks")
                    .select("validation_run_id,passed")
                    .eq("validation_run_id", row["validation_run_id"])
                    .execute()
                    .data
                    or []
                )
                if checks and all(check.get("passed") is True for check in checks):
                    return True
            return False
        except ValidationPersistenceError:
            raise
        except Exception as exc:
            raise ValidationPersistenceError(
                f"Unable to verify successful validation: {type(exc).__name__}",
                candidate_id=candidate_id,
                details={"operation": "successful_validation_lookup"},
            ) from exc

    @staticmethod
    def _strict_check_passed(value: Any) -> bool:
        """Accept only a real boolean True as a passed check.

        In particular, bool("false") is true in Python and must never
        promote a candidate.
        """
        return value is True

    def has_successful_canonical_validation(self, candidate_id: str) -> bool:
        """Require the v2 trace and its relational validation rows.

        validation_runs is retained for compatibility, but it is not the
        canonical reasoning/evidence record. Reports and revalidation gates
        use this stricter method so a stale legacy row or a status-only flag
        cannot become an authoritative finding.
        """
        self.require_candidate(candidate_id)
        try:
            traces = (
                self.sb.table("validation_traces_v2")
                .select("trace_id,validation_run_id,candidate_id,decision,checks,evidence_ids")
                .eq("candidate_id", candidate_id)
                .eq("decision", "validated")
                .execute()
                .data
                or []
            )
            for trace in traces:
                if str(trace.get("candidate_id") or "") != str(candidate_id):
                    continue
                trace_checks = list(trace.get("checks") or [])
                if not trace_checks or any(not isinstance(item, dict) for item in trace_checks):
                    continue
                if not all(self._strict_check_passed(item.get("passed")) for item in trace_checks):
                    continue
                validation_run_id = str(trace.get("validation_run_id") or "")
                if not validation_run_id:
                    continue
                runs = (
                    self.sb.table("validation_runs")
                    .select("validation_run_id,candidate_id,decision")
                    .eq("validation_run_id", validation_run_id)
                    .eq("candidate_id", candidate_id)
                    .eq("decision", "validated")
                    .limit(1)
                    .execute()
                    .data
                    or []
                )
                if len(runs) != 1:
                    continue
                checks = (
                    self.sb.table("validation_checks")
                    .select("validation_run_id,passed")
                    .eq("validation_run_id", validation_run_id)
                    .execute()
                    .data
                    or []
                )
                if checks and all(self._strict_check_passed(item.get("passed")) for item in checks):
                    return True
            return False
        except ValidationPersistenceError:
            raise
        except Exception as exc:
            raise ValidationPersistenceError(
                f"Unable to verify canonical validation: {type(exc).__name__}",
                candidate_id=candidate_id,
                details={"operation": "canonical_validation_lookup"},
            ) from exc

    def save_legacy_decision(
        self,
        *,
        validation_run_id: str,
        candidate_id: str,
        policy_id: str,
        policy_version: str,
        decision: str,
        score: float,
        reason: str,
        checks: Iterable[Dict[str, Any]],
    ) -> ValidationPersistenceReceipt:
        """Persist the compatibility validation row after the candidate exists."""

        self.require_candidate(candidate_id)
        self._write(
            "validation_runs",
            {
                "validation_run_id": validation_run_id,
                "candidate_id": candidate_id,
                "policy_id": policy_id,
                "policy_version": policy_version,
                "decision": decision,
                "score": score,
                "reason": reason,
            },
            conflict="validation_run_id",
            candidate_id=candidate_id,
            validation_run_id=validation_run_id,
        )
        self._verify_validation_run(validation_run_id, candidate_id, decision)
        for check in checks:
            check_name = str(check.get("name") or check.get("check_id") or "unknown")
            self._write(
                "validation_checks",
                {
                    "validation_run_id": validation_run_id,
                    "check_name": check_name,
                    # Never coerce arbitrary truthy values: bool("false") is
                    # True and would violate the validation contract.
                    "passed": self._strict_check_passed(check.get("passed")),
                    "details": check,
                },
                conflict="validation_run_id,check_name",
                candidate_id=candidate_id,
                validation_run_id=validation_run_id,
            )
        return ValidationPersistenceReceipt(validation_run_id, candidate_id, decision)

    def save_trace(self, trace: ValidationTraceV2, decision: Optional[ValidationDecisionV2] = None) -> ValidationPersistenceReceipt:
        decision = decision or ValidationDecisionV2(
            candidate_id=trace.candidate_id,
            policy_id=trace.policy_id,
            policy_version=trace.policy_version,
            decision=trace.decision,
            checks=trace.checks,
            evidence_ids=trace.evidence_ids,
            input_digest=trace.context.input_digest,
        )
        if trace.candidate_id != decision.candidate_id:
            raise ValidationPersistenceError(
                "Trace and decision reference different candidates.",
                candidate_id=trace.candidate_id,
                validation_run_id=decision.validation_run_id,
                details={"operation": "candidate_consistency"},
            )
        if trace.decision != decision.decision:
            raise ValidationPersistenceError(
                "Trace and decision contain different outcomes.",
                candidate_id=decision.candidate_id,
                validation_run_id=decision.validation_run_id,
                details={"operation": "decision_consistency"},
            )
        self.require_candidate(decision.candidate_id)

        # Candidate existence is checked before the first validation write, and
        # validation_runs is written before the trace/check children. This
        # makes the FK dependency explicit and keeps retries idempotent.
        self._write(
            "validation_runs",
            {
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
            },
            conflict="validation_run_id",
            candidate_id=decision.candidate_id,
            validation_run_id=decision.validation_run_id,
        )
        self._verify_validation_run(decision.validation_run_id, decision.candidate_id, decision.decision)
        self._write(
            "validation_traces_v2",
            {
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
            },
            conflict="trace_id",
            candidate_id=decision.candidate_id,
            validation_run_id=decision.validation_run_id,
        )
        for check in decision.checks:
            self._write(
                "validation_checks",
                {
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
                },
                conflict="validation_run_id,check_name",
                candidate_id=decision.candidate_id,
                validation_run_id=decision.validation_run_id,
            )
        return ValidationPersistenceReceipt(decision.validation_run_id, decision.candidate_id, decision.decision)

    def save_traces(self, traces: Iterable[ValidationTraceV2], decisions: Iterable[ValidationDecisionV2]) -> List[ValidationPersistenceReceipt]:
        traces = list(traces)
        decisions = list(decisions)
        if len(traces) != len(decisions):
            raise ValidationPersistenceError(
                "Validation trace and decision batches must have equal length.",
                details={"trace_count": len(traces), "decision_count": len(decisions)},
            )
        return [self.save_trace(trace, decision) for trace, decision in zip(traces, decisions)]

    def list_traces(self, candidate_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        query = self.sb.table("validation_traces_v2").select("*")
        if candidate_id:
            query = query.eq("candidate_id", candidate_id)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute().data or []

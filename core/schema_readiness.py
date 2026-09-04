"""Readiness checks for acceptance-critical database migrations."""

from __future__ import annotations

from typing import Any, Dict


PHASE1_MIGRATION_MARKERS = (
    "023_reasoning_model_calls",
    "024_candidate_validation_integrity",
)

# Keep this list aligned with every column written by the reasoning and
# validation persistence adapters. One-column probes can miss an incomplete
# 016/023 deployment and defer the failure until the first live cycle.
PHASE1_REQUIRED_COLUMNS = {
    "reasoning_cycles": (
        "cycle_id", "session_id", "job_id", "objective", "mode", "status",
        "snapshot_digest", "config_digest", "model_id", "prompt_version",
        "action_budget", "cycle_number", "max_cycles", "selected_action_ids",
        "hypothesis_ids", "evidence_gap_ids", "stop_condition_ids", "stop_reason",
        "input_digest", "output_digest", "created_at", "finished_at", "branch_ids",
        "current_branch_id", "search_strategy", "search_depth", "replan_count",
        "budget_snapshot",
    ),
    "reasoning_model_calls": (
        "call_id", "cycle_id", "session_id", "job_id", "model_id", "provider",
        "prompt_version", "attempt_number", "fallback_index", "status", "input_digest",
        "output_digest", "latency_ms", "error_code", "metadata", "created_at",
    ),
    "model_action_traces": (
        "trace_id", "cycle_id", "session_id", "model_id", "provider", "prompt_version",
        "raw_output_digest", "action", "valid", "rejection_reason", "hallucinated_reference",
        "unsafe_mutation", "invented_evidence", "unknown_tool", "unsupported_capability",
        "stale_context", "created_at",
    ),
    "reasoning_hypotheses": (
        "hypothesis_id", "cycle_id", "session_id", "claim", "null_hypothesis", "status",
        "category", "target_url", "method", "parameter", "supporting_evidence_ids",
        "contradicting_evidence_ids", "required_evidence_roles", "evidence_gap_ids",
        "priority_score", "expected_information_gain", "confidence_score", "source",
        "fingerprint", "metadata", "parent_hypothesis_id", "branch_id", "assumptions",
        "expected_outcomes", "contradiction_ids", "alternative_strategy_ids", "search_depth",
        "freshness_boundary",
    ),
    "reasoning_actions": (
        "action_id", "cycle_id", "session_id", "action_type", "tool_name", "endpoint_ref",
        "hypothesis_id", "risk", "side_effect_class", "evidence_ids", "expected_evidence_roles",
        "requires_approval", "cleanup_ref", "expected_information_gain", "rationale", "status",
        "rejection_reason", "input_digest", "source", "metadata", "capability_id", "branch_id",
        "parent_action_id", "target_digest", "input_bindings", "expected_observation_kinds",
        "mutation_operator", "approval_digest", "budget_snapshot",
    ),
    "reasoning_evidence_gaps": (
        "gap_id", "cycle_id", "session_id", "hypothesis_id", "gap_type", "description",
        "required_role", "blocking", "status", "evidence_ids", "metadata",
    ),
    "reasoning_stop_conditions": (
        "stop_condition_id", "cycle_id", "session_id", "kind", "triggered", "reason", "evidence_ids",
    ),
    "reasoning_decisions": (
        "decision_id", "cycle_id", "session_id", "snapshot_digest", "selected_action_ids",
        "rejected_action_ids", "evidence_gap_ids", "stop_condition_ids", "rationale", "deterministic",
        "input_digest", "selected_branch_id", "score_breakdown", "rejected_alternatives", "replan_reason",
    ),
    "reasoning_branches": (
        "branch_id", "cycle_id", "session_id", "parent_branch_id", "status", "hypothesis_ids",
        "action_ids", "evidence_snapshot_digest", "search_depth", "score", "score_breakdown",
        "estimated_cost", "risk_score", "failure_count", "backtrack_count", "stop_reason", "input_digest",
    ),
    "reasoning_branch_transitions": (
        "transition_id", "branch_id", "cycle_id", "session_id", "transition_type", "from_status",
        "to_status", "reason", "action_id", "evidence_ids", "input_digest",
    ),
    "reasoning_adaptations": (
        "adaptation_id", "cycle_id", "session_id", "strategy", "selected_branch_id", "selected_action_id",
        "alternative_action_ids", "reason", "information_gain", "uncertainty_before", "uncertainty_after",
        "backtracked", "stop_recommended", "input_digest",
    ),
    "validation_traces_v2": (
        "trace_id", "validation_run_id", "candidate_id", "policy_id", "policy_version",
        "validator_version", "context", "checks", "decision", "evidence_ids", "shadow_decision",
        "input_digest", "created_at",
    ),
    "candidate_findings": (
        "candidate_id", "session_id", "tool_run_id", "title", "vuln_type", "severity", "target_url",
        "method", "parameter", "injection_point", "fingerprint", "status", "confidence_score",
        "confidence_reasons", "remediation", "metadata", "created_at", "updated_at",
    ),
    "validation_runs": (
        "validation_run_id", "candidate_id", "policy_id", "policy_version", "decision", "score", "reason",
        "schema_version", "input_digest", "evidence_ids", "observation_ids", "failure_classification",
        "mode", "validator_version", "protocol", "operation_id", "comparison_id",
    ),
    "validation_checks": (
        "validation_run_id", "check_name", "passed", "details", "schema_version", "check_id", "reason",
        "evidence_ids", "observation_ids", "input_digest", "failure_classification",
    ),
}


class Phase1SchemaNotReadyError(RuntimeError):
    """The database is reachable but not migrated for Phase 1 acceptance."""


def verify_phase1_acceptance_schema(supabase: Any) -> Dict[str, Any]:
    """Verify tables and the marker written only by migration 025.

    Table existence alone cannot prove the 024 integrity triggers exist. The
    marker migration checks those triggers inside PostgreSQL before inserting
    its two marker rows; querying the marker therefore gives the API a safe,
    PostgREST-compatible readiness contract without exposing catalog access.
    """

    for table_name, columns in PHASE1_REQUIRED_COLUMNS.items():
        try:
            supabase.table(table_name).select(",".join(columns)).limit(1).execute()
        except Exception as exc:
            raise Phase1SchemaNotReadyError(
                f"required Phase 1 table is unavailable: {table_name}"
            ) from exc

    try:
        rows = (
            supabase.table("nexus_schema_migrations")
            .select("migration_id,checksum")
            .in_("migration_id", list(PHASE1_MIGRATION_MARKERS))
            .execute()
            .data
            or []
        )
    except Exception as exc:
        raise Phase1SchemaNotReadyError(
            "migration 025 marker table is unavailable"
        ) from exc

    marker_map = {
        str(item.get("migration_id")): str(item.get("checksum"))
        for item in rows
    }
    missing = [migration_id for migration_id in PHASE1_MIGRATION_MARKERS if not marker_map.get(migration_id)]
    if missing:
        raise Phase1SchemaNotReadyError(
            "Phase 1 acceptance migration marker missing or invalid: "
            + ", ".join(missing)
        )

    # The marker function re-checks trigger state and definition checksums in
    # PostgreSQL at read time. A marker row by itself is not authoritative.
    try:
        rpc_data = supabase.rpc("nexus_phase1_acceptance_status", {}).execute().data
    except Exception as exc:
        raise Phase1SchemaNotReadyError(
            "Phase 1 acceptance status RPC is unavailable"
        ) from exc
    if isinstance(rpc_data, list):
        rpc_data = rpc_data[0] if rpc_data else {}
    if not isinstance(rpc_data, dict) or not bool(rpc_data.get("ready")):
        missing_rpc = (rpc_data or {}).get("missing") if isinstance(rpc_data, dict) else None
        raise Phase1SchemaNotReadyError(
            "Phase 1 acceptance PostgreSQL integrity check failed: "
            + str(missing_rpc or "unknown")
        )

    return {
        "required_tables": list(PHASE1_REQUIRED_COLUMNS),
        "markers": marker_map,
        "postgres_status": rpc_data,
    }

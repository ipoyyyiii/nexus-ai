"""Supabase persistence for structured tool results."""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from core.structured_contract import CandidateFindingV1, ObservationV1, ReportClaimV1, ReportNarrativeV1, SemanticComparisonV1, ToolResultV1
from core.validation_engine import validation_engine


STRUCTURED_SCHEMA_SQL = r'''
create table if not exists tool_runs (
    tool_run_id text primary key, session_id uuid not null, job_id text,
    tool_name text not null, tool_version text not null default '1',
    category text not null default 'unknown', target text not null,
    status text not null, started_at timestamptz not null, finished_at timestamptz,
    inputs_redacted jsonb not null default '{}'::jsonb, summary text not null default '',
    metrics jsonb not null default '{}'::jsonb, errors jsonb not null default '[]'::jsonb,
    side_effects jsonb not null default '[]'::jsonb, cleanup_refs jsonb not null default '[]'::jsonb,
    legacy_source boolean not null default false, created_at timestamptz not null default now()
);
create table if not exists evidence_artifacts (
    artifact_id text primary key, session_id uuid not null, tool_run_id text,
    kind text not null, mime_type text not null default 'text/plain', sha256 text not null default '',
    size_bytes integer not null default 0, excerpt text not null default '', storage_uri text not null default '',
    redacted boolean not null default true, retention_until timestamptz,
    metadata jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);
create table if not exists observations (
    observation_id text primary key, session_id uuid not null, tool_run_id text not null,
    role text not null, kind text not null, summary text not null default '', target_url text not null default '',
    method text not null default 'GET', request_excerpt text not null default '', response_excerpt text not null default '',
    status_code integer, response_time_ms numeric, payload_hash text not null default '',
    artifact_ids jsonb not null default '[]'::jsonb, metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);
create table if not exists candidate_findings (
    candidate_id text primary key, session_id uuid not null, tool_run_id text,
    title text not null, vuln_type text not null, severity text not null default 'INFO', target_url text not null default '',
    method text not null default 'GET', parameter text not null default '', injection_point text not null default '',
    fingerprint text not null, status text not null default 'suspected', confidence_score numeric not null default 0.5,
    confidence_reasons jsonb not null default '[]'::jsonb, remediation text not null default '',
    metadata jsonb not null default '{}'::jsonb, created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(), unique(session_id, fingerprint)
);
create table if not exists candidate_evidence (
    candidate_id text not null, observation_id text not null, primary key(candidate_id, observation_id)
);
create table if not exists validation_runs (
    validation_run_id text primary key, candidate_id text not null, policy_id text not null,
    policy_version text not null, decision text not null, score numeric not null default 0,
    reason text not null default '', created_at timestamptz not null default now()
);
create table if not exists validation_checks (
    validation_run_id text not null, check_name text not null, passed boolean not null,
    details jsonb not null default '{}'::jsonb, primary key(validation_run_id, check_name)
);
create table if not exists finding_reviews (
    review_id uuid primary key default gen_random_uuid(), candidate_id text not null,
    decision text not null, reason text not null, reviewer text not null default 'api',
    created_at timestamptz not null default now()
);
create index if not exists idx_structured_runs_session on tool_runs(session_id, created_at desc);
create index if not exists idx_structured_candidates_session on candidate_findings(session_id, status, updated_at desc);
'''


class StructuredRepository:
    def __init__(self, session_store: Any):
        self.store = session_store
        self.sb = session_store.sb

    def persist(self, session_id: str, result: ToolResultV1, validations: Optional[list] = None) -> None:
        self.sb.table("tool_runs").upsert({
            "tool_run_id": result.tool_run_id, "session_id": session_id,
            "job_id": result.tool_run_id, "tool_name": result.tool_name,
            "tool_version": result.tool_version, "category": result.category,
            "target": result.target, "status": result.status,
            "started_at": result.started_at, "finished_at": result.finished_at,
            "inputs_redacted": result.inputs_redacted, "summary": result.summary,
            "metrics": result.metrics, "errors": [e.model_dump() for e in result.errors],
            "side_effects": result.side_effects, "cleanup_refs": result.cleanup_refs,
            "legacy_source": result.legacy_source,
        }).execute()
        for item in result.artifacts:
            self.sb.table("evidence_artifacts").upsert({"session_id": session_id, "tool_run_id": result.tool_run_id, **item.model_dump()}).execute()
        for item in result.observations:
            self.sb.table("observations").upsert({"session_id": session_id, "tool_run_id": result.tool_run_id, **item.model_dump()}).execute()
        candidate_id_map = {}
        for item in result.candidate_findings:
            existing = self.sb.table("candidate_findings").select("candidate_id").eq("session_id", session_id).eq("fingerprint", item.fingerprint).limit(1).execute().data or []
            stored_id = existing[0]["candidate_id"] if existing else item.candidate_id
            candidate_id_map[item.candidate_id] = stored_id
            item.candidate_id = stored_id
            item.metadata = {**(item.metadata or {}), "evidence_ids": list(item.observation_ids)}
            row = {"session_id": session_id, "tool_run_id": result.tool_run_id, **item.model_dump()}
            self.sb.table("candidate_findings").upsert(row, on_conflict="session_id,fingerprint").execute()
            for observation_id in item.observation_ids:
                self.sb.table("candidate_evidence").upsert({"candidate_id": stored_id, "observation_id": observation_id}).execute()
        for validation in validations or []:
            validation.candidate_id = candidate_id_map.get(validation.candidate_id, validation.candidate_id)
            validation_id = f"val_{uuid.uuid4().hex}"
            self.sb.table("validation_runs").insert({"validation_run_id": validation_id, "candidate_id": validation.candidate_id, "policy_id": validation.policy_id, "policy_version": validation.policy_version, "decision": validation.decision, "score": validation.score, "reason": validation.reason}).execute()
            for check in validation.checks:
                self.sb.table("validation_checks").insert({"validation_run_id": validation_id, "check_name": check.get("name", "unknown"), "passed": bool(check.get("passed")), "details": check}).execute()

    def list_runs(self, session_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        return self.sb.table("tool_runs").select("*").eq("session_id", session_id).order("created_at", desc=True).limit(limit).execute().data or []

    def list_candidates(self, session_id: str, status: Optional[str] = None, limit: int = 100) -> list[Dict[str, Any]]:
        query = self.sb.table("candidate_findings").select("*").eq("session_id", session_id)
        if status:
            query = query.eq("status", status)
        return query.order("updated_at", desc=True).limit(limit).execute().data or []

    def get_candidate(self, session_id: str, candidate_id: str) -> Dict[str, Any]:
        rows = self.sb.table("candidate_findings").select("*").eq("session_id", session_id).eq("candidate_id", candidate_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Candidate finding not found.")
        return rows[0]

    def validations(self, session_id: str, candidate_id: str) -> list[Dict[str, Any]]:
        self.get_candidate(session_id, candidate_id)
        return self.sb.table("validation_runs").select("*, validation_checks(*)").eq("candidate_id", candidate_id).order("created_at", desc=True).execute().data or []

    def revalidate(self, session_id: str, candidate_id: str) -> Dict[str, Any]:
        candidate_row = self.get_candidate(session_id, candidate_id)
        links = self.sb.table("candidate_evidence").select("observation_id").eq("candidate_id", candidate_id).execute().data or []
        observations = []
        for link in links:
            rows = self.sb.table("observations").select("*").eq("observation_id", link["observation_id"]).limit(1).execute().data or []
            if rows:
                observations.append(ObservationV1(**rows[0]))
        candidate = CandidateFindingV1(**candidate_row)
        result = ToolResultV1(tool_name="revalidation", category="validation", target=candidate.target_url, observations=observations, candidate_findings=[candidate])
        decisions = validation_engine.validate(result)
        decision = decisions[0]
        validation_id = f"val_{uuid.uuid4().hex}"
        self.sb.table("validation_runs").insert({"validation_run_id": validation_id, "candidate_id": candidate_id, "policy_id": decision.policy_id, "policy_version": decision.policy_version, "decision": decision.decision, "score": decision.score, "reason": decision.reason}).execute()
        for check in decision.checks:
            self.sb.table("validation_checks").insert({"validation_run_id": validation_id, "check_name": check.get("name", "unknown"), "passed": bool(check.get("passed")), "details": check}).execute()
        updated = self.sb.table("candidate_findings").update({"status": candidate.status, "confidence_score": candidate.confidence_score, "confidence_reasons": candidate.confidence_reasons}).eq("session_id", session_id).eq("candidate_id", candidate_id).execute().data or []
        return {"candidate": updated[0] if updated else candidate.model_dump(), "validation": {"validation_run_id": validation_id, **decision.__dict__}}

    def review(self, session_id: str, candidate_id: str, decision: str, reason: str, reviewer: str = "api") -> Dict[str, Any]:
        if not reason.strip():
            raise ValueError("A review reason is required.")
        self.get_candidate(session_id, candidate_id)
        statuses = {"override_validate": "validated_override", "reject": "disproven", "return_to_validation": "validating"}
        if decision not in statuses:
            raise ValueError("Invalid review decision.")
        self.sb.table("finding_reviews").insert({"candidate_id": candidate_id, "decision": decision, "reason": reason[:4000], "reviewer": reviewer[:200]}).execute()
        rows = self.sb.table("candidate_findings").update({"status": statuses[decision]}).eq("session_id", session_id).eq("candidate_id", candidate_id).execute().data or []
        return rows[0] if rows else self.get_candidate(session_id, candidate_id)

    # Stage 11 durable chain/protocol persistence. These methods are additive
    # and deliberately kept in the structured repository so chain evidence and
    # candidate evidence share one persistence boundary.
    def save_chain_graph(self, session_id: str, graph: Dict[str, Any]) -> Dict[str, Any]:
        chain = dict(graph.get("chain") or {})
        if not chain.get("chain_id"):
            raise ValueError("Chain graph is missing chain_id.")
        chain_row = {
            "chain_id": chain["chain_id"], "session_id": session_id,
            "name": chain.get("name", "attack chain"), "current_version": chain.get("chain_version", 1),
            "status": chain.get("status", "proposed"), "validation_status": chain.get("validation_status", "inconclusive"),
            "validation_source": chain.get("validation_source", "machine"), "graph_digest": graph.get("graph_digest", chain.get("graph_digest", "")),
            "objective": chain.get("impact_objective", ""), "evidence_ids": chain.get("evidence_ids", []),
            "prerequisite_ids": chain.get("prerequisite_ids", []),
            "identity_ids": chain.get("identity_ids", []), "protocol_operation_ids": chain.get("protocol_operation_ids", []),
        }
        self.sb.table("attack_chains").upsert(chain_row, on_conflict="chain_id").execute()
        version = int(chain.get("chain_version", 1))
        self.sb.table("attack_chain_versions").upsert({
            "chain_version_id": f"{chain['chain_id']}_v{version}", "chain_id": chain["chain_id"],
            "session_id": session_id, "version": version, "graph_digest": chain.get("graph_digest", ""),
            "objective": chain.get("impact_objective", ""), "prerequisite_ids": chain.get("prerequisite_ids", []),
            "node_ids": chain.get("node_ids", []), "edge_ids": chain.get("edge_ids", []),
            "evidence_ids": chain.get("evidence_ids", []), "policy_version": "1.0",
        }, on_conflict="chain_version_id").execute()
        for node in graph.get("nodes", []):
            self.sb.table("attack_chain_nodes").upsert({"chain_id": chain["chain_id"], "chain_version": version, "session_id": session_id, **node}, on_conflict="node_id").execute()
        for edge in graph.get("edges", []):
            self.sb.table("attack_chain_edges").upsert({"chain_id": chain["chain_id"], "chain_version": version, "session_id": session_id, **edge}, on_conflict="edge_id").execute()
        for evidence_id in chain.get("evidence_ids", []):
            self.sb.table("chain_evidence_links").upsert({"chain_id": chain["chain_id"], "chain_version": version, "evidence_id": evidence_id, "role": "supporting"}, on_conflict="chain_id,chain_version,evidence_id,role").execute()
        return chain_row

    def list_chains(self, session_id: str, status: Optional[str] = None, limit: int = 100) -> list[Dict[str, Any]]:
        query = self.sb.table("attack_chains").select("*").eq("session_id", session_id)
        if status:
            query = query.eq("status", status)
        return query.order("updated_at", desc=True).limit(min(max(limit, 1), 200)).execute().data or []

    def get_chain(self, session_id: str, chain_id: str) -> Dict[str, Any]:
        rows = self.sb.table("attack_chains").select("*").eq("session_id", session_id).eq("chain_id", chain_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Attack chain not found.")
        chain = rows[0]
        version = int(chain.get("current_version", 1))
        version_rows = self.sb.table("attack_chain_versions").select("prerequisite_ids,node_ids,edge_ids,evidence_ids").eq("chain_id", chain_id).eq("version", version).limit(1).execute().data or []
        if version_rows:
            chain.update(version_rows[0])
        nodes = self.sb.table("attack_chain_nodes").select("*").eq("chain_id", chain_id).eq("chain_version", version).execute().data or []
        edges = self.sb.table("attack_chain_edges").select("*").eq("chain_id", chain_id).eq("chain_version", version).execute().data or []
        evaluations = self.sb.table("chain_evaluations").select("*").eq("chain_id", chain_id).order("created_at", desc=True).limit(20).execute().data or []
        return {"chain": chain, "nodes": nodes, "edges": edges, "evaluations": evaluations}

    def save_protocol_operations(self, session_id: str, operations: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        saved = []
        for operation in operations:
            row = {"session_id": session_id, **operation}
            result = self.sb.table("protocol_operations").upsert(row, on_conflict="operation_id").execute().data or []
            saved.append(result[0] if result else row)
        return saved

    def save_payload_proposal(self, session_id: str, proposal: Dict[str, Any]) -> Dict[str, Any]:
        row = {"session_id": session_id, **proposal}
        result = self.sb.table("payload_proposals").upsert(row, on_conflict="payload_id").execute().data or []
        return result[0] if result else row

    def list_payload_proposals(self, session_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        return (self.sb.table("payload_proposals").select("*").eq("session_id", session_id)
                .order("created_at", desc=True).limit(min(max(limit, 1), 200)).execute().data or [])

    def list_protocol_operations(self, session_id: str, protocol: Optional[str] = None, limit: int = 200) -> list[Dict[str, Any]]:
        query = self.sb.table("protocol_operations").select("*").eq("session_id", session_id)
        if protocol:
            query = query.eq("protocol", protocol)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute().data or []

    def save_protocol_comparison(self, session_id: str, comparison: SemanticComparisonV1 | Dict[str, Any], *, tool_run_id: str = "", job_id: str = "", attempt_id: str = "") -> Dict[str, Any]:
        payload = comparison.model_dump(mode="json") if isinstance(comparison, SemanticComparisonV1) else dict(comparison)
        payload.pop("schema_version", None)
        normalized_job_id = None
        if job_id:
            try:
                normalized_job_id = str(uuid.UUID(str(job_id)))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError("job_id must be a UUID when supplied.") from exc
        # Empty operation IDs are intentionally stored as NULL: the column is
        # an optional FK to a discovered operation, and an empty string would
        # turn a diagnostic-only comparison into a referential-integrity error.
        payload["operation_id"] = payload.get("operation_id") or None
        row = {"session_id": session_id, "tool_run_id": tool_run_id, "job_id": normalized_job_id, "attempt_id": attempt_id, **payload}
        result = self.sb.table("protocol_comparisons").insert(row).execute().data or []
        return result[0] if result else row

    def list_protocol_comparisons(self, session_id: str, protocol: Optional[str] = None, limit: int = 200) -> list[Dict[str, Any]]:
        query = self.sb.table("protocol_comparisons").select("*").eq("session_id", session_id)
        if protocol:
            query = query.eq("protocol", protocol)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute().data or []

    def save_chain_evaluation(self, session_id: str, evaluation: Dict[str, Any]) -> Dict[str, Any]:
        row = {"session_id": session_id, **evaluation}
        result = self.sb.table("chain_evaluations").insert(row).execute().data or []
        return result[0] if result else row

    def save_impact_plan(self, session_id: str, plan: Dict[str, Any]) -> Dict[str, Any]:
        row = {"session_id": session_id, **plan}
        result = self.sb.table("impact_proof_plans").upsert(row, on_conflict="plan_id").execute().data or []
        return result[0] if result else row

    # Stage 12 reasoning/report records. Trace tables are append-only; cycle
    # lifecycle itself is the only mutable record.
    def save_reasoning_result(self, session_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
        cycle = {"session_id": session_id, **dict(result.get("cycle") or {})}
        cycle.pop("schema_version", None)
        # Pydantic contracts intentionally contain richer runtime metadata than
        # the additive SQL schema.  Whitelist columns at this boundary so a
        # future contract field can never turn into a PostgREST write failure.
        if not cycle.get("job_id"):
            cycle["job_id"] = None
        self.sb.table("reasoning_cycles").upsert(cycle, on_conflict="cycle_id").execute()
        hypothesis_columns = {
            "hypothesis_id", "cycle_id", "session_id", "claim", "null_hypothesis",
            "status", "category", "target_url", "method", "parameter",
            "supporting_evidence_ids", "contradicting_evidence_ids",
            "required_evidence_roles", "evidence_gap_ids", "priority_score",
            "expected_information_gain", "confidence_score", "source", "fingerprint",
            "metadata",
            "parent_hypothesis_id", "branch_id", "assumptions", "expected_outcomes",
            "contradiction_ids", "alternative_strategy_ids", "search_depth", "freshness_boundary",
        }
        for item in result.get("hypotheses", []):
            row = {"session_id": session_id, **{key: value for key, value in dict(item).items() if key in hypothesis_columns}}
            self.sb.table("reasoning_hypotheses").upsert(row, on_conflict="hypothesis_id,cycle_id", ignore_duplicates=True).execute()
        action_columns = {
            "action_id", "cycle_id", "session_id", "action_type", "tool_name", "endpoint_ref",
            "hypothesis_id", "risk", "side_effect_class", "evidence_ids", "expected_evidence_roles",
            "requires_approval", "cleanup_ref", "expected_information_gain", "rationale", "status",
            "rejection_reason", "input_digest", "source", "metadata",
            "capability_id", "branch_id", "parent_action_id", "target_digest", "input_bindings",
            "expected_observation_kinds", "mutation_operator", "approval_digest", "budget_snapshot",
        }
        for item in result.get("actions", []):
            row = {"session_id": session_id, **{key: value for key, value in dict(item).items() if key in action_columns}}
            self.sb.table("reasoning_actions").upsert(row, on_conflict="action_id", ignore_duplicates=True).execute()
        gap_columns = {"gap_id", "cycle_id", "session_id", "hypothesis_id", "gap_type", "description", "required_role", "blocking", "status", "evidence_ids", "metadata"}
        for item in result.get("evidence_gaps", []):
            row = {"session_id": session_id, **{key: value for key, value in dict(item).items() if key in gap_columns}}
            self.sb.table("reasoning_evidence_gaps").upsert(row, on_conflict="gap_id", ignore_duplicates=True).execute()
        stop_columns = {"stop_condition_id", "cycle_id", "session_id", "kind", "triggered", "reason", "evidence_ids"}
        for item in result.get("stop_conditions", []):
            row = {"session_id": session_id, **{key: value for key, value in dict(item).items() if key in stop_columns}}
            self.sb.table("reasoning_stop_conditions").upsert(row, on_conflict="stop_condition_id", ignore_duplicates=True).execute()
        decision_columns = {"decision_id", "cycle_id", "session_id", "snapshot_digest", "selected_action_ids", "rejected_action_ids", "evidence_gap_ids", "stop_condition_ids", "rationale", "deterministic", "input_digest", "selected_branch_id", "score_breakdown", "rejected_alternatives", "replan_reason"}
        decision = dict(result.get("decision") or {})
        if decision:
            decision = {"session_id": session_id, **{key: value for key, value in decision.items() if key in decision_columns}}
            self.sb.table("reasoning_decisions").upsert(decision, on_conflict="decision_id", ignore_duplicates=True).execute()
        trace_columns = {"trace_id", "cycle_id", "session_id", "model_id", "provider", "prompt_version", "raw_output_digest", "action", "valid", "rejection_reason", "hallucinated_reference", "unsafe_mutation", "invented_evidence", "unknown_tool", "unsupported_capability", "stale_context"}
        for item in result.get("model_traces", []):
            row = {"session_id": session_id, **{key: value for key, value in dict(item).items() if key in trace_columns}}
            self.sb.table("model_action_traces").upsert(row, on_conflict="trace_id", ignore_duplicates=True).execute()
        for item in result.get("branches", []):
            row = {"session_id": session_id, **dict(item)}
            row.pop("schema_version", None)
            self.sb.table("reasoning_branches").upsert(row, on_conflict="branch_id", ignore_duplicates=True).execute()
        for item in result.get("branch_transitions", []):
            row = {"session_id": session_id, **dict(item)}
            row.pop("schema_version", None)
            self.sb.table("reasoning_branch_transitions").upsert(row, on_conflict="transition_id", ignore_duplicates=True).execute()
        adaptation = dict(result.get("adaptation") or {})
        if adaptation:
            adaptation = {"session_id": session_id, **adaptation}
            adaptation.pop("schema_version", None)
            self.sb.table("reasoning_adaptations").upsert(adaptation, on_conflict="adaptation_id", ignore_duplicates=True).execute()
        return cycle

    def list_reasoning_cycles(self, session_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        return (self.sb.table("reasoning_cycles").select("*").eq("session_id", session_id)
                .order("created_at", desc=True).limit(min(max(limit, 1), 200)).execute().data or [])

    def get_reasoning_cycle(self, session_id: str, cycle_id: str) -> Dict[str, Any]:
        rows = self.sb.table("reasoning_cycles").select("*").eq("session_id", session_id).eq("cycle_id", cycle_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Reasoning cycle not found.")
        cycle = rows[0]
        return {
            "cycle": cycle,
            "hypotheses": self.sb.table("reasoning_hypotheses").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "actions": self.sb.table("reasoning_actions").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "evidence_gaps": self.sb.table("reasoning_evidence_gaps").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "stop_conditions": self.sb.table("reasoning_stop_conditions").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "decisions": self.sb.table("reasoning_decisions").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "model_traces": self.sb.table("model_action_traces").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "branches": self.sb.table("reasoning_branches").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "branch_transitions": self.sb.table("reasoning_branch_transitions").select("*").eq("cycle_id", cycle_id).order("created_at").execute().data or [],
            "adaptations": self.sb.table("reasoning_adaptations").select("*").eq("cycle_id", cycle_id).execute().data or [],
        }

    def list_reasoning_branches(self, session_id: str, cycle_id: Optional[str] = None, limit: int = 200) -> list[Dict[str, Any]]:
        query = self.sb.table("reasoning_branches").select("*").eq("session_id", session_id)
        if cycle_id:
            query = query.eq("cycle_id", cycle_id)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute().data or []

    def save_report_narrative(self, session_id: str, narrative: Dict[str, Any], claims: list[Dict[str, Any]]) -> Dict[str, Any]:
        row = {"session_id": session_id, **dict(narrative)}
        row.pop("schema_version", None)
        self.sb.table("report_narratives").upsert(row, on_conflict="report_id", ignore_duplicates=True).execute()
        for claim in claims:
            claim_row = {"session_id": session_id, **dict(claim)}
            claim_row.pop("schema_version", None)
            self.sb.table("report_claims").upsert(claim_row, on_conflict="claim_id", ignore_duplicates=True).execute()
            for evidence_id in claim.get("evidence_ids", []):
                self.sb.table("report_claim_evidence").upsert({"claim_id": claim["claim_id"], "evidence_id": evidence_id, "role": "supporting"}, on_conflict="claim_id,evidence_id,role", ignore_duplicates=True).execute()
        return row

    def list_report_claims(self, session_id: str, report_id: Optional[str] = None, limit: int = 500) -> list[Dict[str, Any]]:
        query = self.sb.table("report_claims").select("*").eq("session_id", session_id)
        if report_id:
            query = query.eq("report_id", report_id)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 1000)).execute().data or []

"""Supabase persistence for structured tool results."""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1
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

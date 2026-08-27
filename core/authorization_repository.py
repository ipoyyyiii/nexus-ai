"""Persistence facade for the dynamic authorization graph."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.authorization_contract import (
    AuthSurfaceObservationV1,
    AuthContextV1,
    AuthorizationExpectationV1,
    AuthorizationReplayRunV1,
    IdentityGraphV1,
    IdentityCoveragePlanV1,
    IdentityClaimV1,
    IdentityRelationV1,
    IdentityV1,
    ReplayAttemptV1,
    RequestTemplateV1,
    ResourceInstanceV1,
    SessionTransitionV1,
    WorkflowPrerequisiteV1,
)
from core.redact import redact


class AuthorizationRepository:
    def __init__(self, session_store: Any):
        self.store = session_store
        self.sb = session_store.sb

    def create_identity(self, session_id: str, identity: IdentityV1) -> Dict[str, Any]:
        identity.session_id = session_id
        return self.sb.table("identities").upsert(identity.model_dump(), on_conflict="identity_id").execute().data[0]

    def list_identities(self, session_id: str) -> List[Dict[str, Any]]:
        return self.sb.table("identities").select("*").eq("session_id", session_id).order("created_at").execute().data or []

    def get_identity(self, session_id: str, identity_id: str) -> Dict[str, Any]:
        rows = self.sb.table("identities").select("*").eq("session_id", session_id).eq("identity_id", identity_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Identity not found in this engagement.")
        return rows[0]

    def update_identity(self, session_id: str, identity_id: str, values: Dict[str, Any]) -> Dict[str, Any]:
        self.get_identity(session_id, identity_id)
        safe = redact(values)
        rows = self.sb.table("identities").update(safe).eq("session_id", session_id).eq("identity_id", identity_id).execute().data or []
        return rows[0] if rows else self.get_identity(session_id, identity_id)

    def create_claim(self, session_id: str, claim: IdentityClaimV1) -> Dict[str, Any]:
        self.get_identity(session_id, claim.identity_id)
        return self.sb.table("identity_claims").insert(claim.model_dump()).execute().data[0]

    def list_claims(self, session_id: str, identity_id: str) -> List[Dict[str, Any]]:
        self.get_identity(session_id, identity_id)
        return self.sb.table("identity_claims").select("*").eq("identity_id", identity_id).order("created_at").execute().data or []

    def create_auth_context(self, session_id: str, context: AuthContextV1) -> Dict[str, Any]:
        self.get_identity(session_id, context.identity_id)
        return self.sb.table("auth_contexts").upsert(context.model_dump(), on_conflict="auth_context_id").execute().data[0]

    def list_auth_contexts(self, session_id: str, identity_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = self.sb.table("auth_contexts").select("*, identities!inner(session_id)").eq("identities.session_id", session_id)
        if identity_id:
            query = query.eq("identity_id", identity_id)
        return query.order("created_at").execute().data or []

    def save_auth_surface(self, surface: AuthSurfaceObservationV1) -> Dict[str, Any]:
        row = redact(surface.model_dump(mode="json"))
        return self.sb.table("auth_surface_observations").upsert(row, on_conflict="observation_id").execute().data[0]

    def list_auth_surfaces(self, session_id: str, identity_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = self.sb.table("auth_surface_observations").select("*").eq("session_id", session_id)
        if identity_id:
            query = query.eq("identity_id", identity_id)
        return redact(query.order("created_at", desc=True).limit(500).execute().data or [])

    def save_session_transition(self, transition: SessionTransitionV1) -> Dict[str, Any]:
        row = redact(transition.model_dump(mode="json"))
        return self.sb.table("auth_session_transitions").upsert(row, on_conflict="transition_id").execute().data[0]

    def list_session_transitions(self, session_id: str, auth_context_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = self.sb.table("auth_session_transitions").select("*").eq("session_id", session_id)
        if auth_context_id:
            query = query.eq("auth_context_id", auth_context_id)
        return redact(query.order("created_at").limit(500).execute().data or [])

    def save_workflow_prerequisite(self, prerequisite: WorkflowPrerequisiteV1) -> Dict[str, Any]:
        row = redact(prerequisite.model_dump(mode="json"))
        return self.sb.table("workflow_prerequisite_versions").upsert(row, on_conflict="prerequisite_id").execute().data[0]

    def list_workflow_prerequisites(self, session_id: str, workflow_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = self.sb.table("workflow_prerequisite_versions").select("*").eq("session_id", session_id)
        if workflow_id:
            query = query.eq("workflow_id", workflow_id)
        return redact(query.order("created_at").limit(1000).execute().data or [])

    def save_identity_graph(self, session_id: str, graph: IdentityGraphV1) -> Dict[str, Any]:
        """Persist an immutable graph snapshot; never update an older version."""
        graph.session_id = session_id
        graph.ensure_digest()
        row = redact(graph.model_dump(mode="json"))
        self.sb.table("identity_graph_versions").insert({
            "graph_id": row["graph_id"],
            "session_id": session_id,
            "version": row["version"],
            "node_ids": row["node_ids"],
            "evidence_ids": row["evidence_ids"],
            "gaps": row["gaps"],
            "digest": row["digest"],
            "created_at": row["created_at"],
        }).execute()
        for relation in graph.relations:
            relation.session_id = session_id
            self.sb.table("identity_graph_edges").insert({
                **redact(relation.model_dump(mode="json")),
                "graph_id": graph.graph_id,
            }).execute()
        return row

    def list_identity_graphs(self, session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        return self.sb.table("identity_graph_versions").select("*").eq(
            "session_id", session_id
        ).order("version", desc=True).limit(min(limit, 200)).execute().data or []

    def identity_graph_detail(self, session_id: str, graph_id: str) -> Dict[str, Any]:
        rows = self.sb.table("identity_graph_versions").select("*").eq(
            "session_id", session_id
        ).eq("graph_id", graph_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Identity graph not found.")
        edges = self.sb.table("identity_graph_edges").select("*").eq(
            "session_id", session_id
        ).eq("graph_id", graph_id).order("created_at").execute().data or []
        return {"graph": rows[0], "relations": edges}

    def save_identity_coverage_plan(self, plan: IdentityCoveragePlanV1) -> Dict[str, Any]:
        plan.ensure_digest() if hasattr(plan, "ensure_digest") else None
        row = redact(plan.model_dump(mode="json"))
        return self.sb.table("identity_coverage_plans").insert(row).execute().data[0]

    def list_identity_coverage_plans(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        return self.sb.table("identity_coverage_plans").select("*").eq(
            "session_id", session_id
        ).order("created_at", desc=True).limit(min(limit, 200)).execute().data or []

    def create_expectation(self, session_id: str, expectation: AuthorizationExpectationV1) -> Dict[str, Any]:
        expectation.session_id = session_id
        self.get_identity(session_id, expectation.subject_identity_id)
        return self.sb.table("authorization_expectations").upsert(expectation.model_dump(), on_conflict="expectation_id").execute().data[0]

    def list_expectations(self, session_id: str) -> List[Dict[str, Any]]:
        return self.sb.table("authorization_expectations").select("*").eq("session_id", session_id).order("created_at").execute().data or []

    def save_template(self, session_id: str, template: RequestTemplateV1) -> Dict[str, Any]:
        template.session_id = session_id
        template.ensure_fingerprint()
        row = template.model_dump()
        row["header_template"] = redact(row.get("header_template") or {})
        row["body_template"] = redact(row.get("body_template"))
        return self.sb.table("request_templates").upsert(row, on_conflict="session_id,fingerprint").execute().data[0]

    def list_templates(self, session_id: str) -> List[Dict[str, Any]]:
        return self.sb.table("request_templates").select("*").eq("session_id", session_id).order("created_at", desc=True).execute().data or []

    def get_template(self, session_id: str, template_id: str) -> RequestTemplateV1:
        rows = self.sb.table("request_templates").select("*").eq("session_id", session_id).eq("template_id", template_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Request template not found.")
        return RequestTemplateV1(**rows[0])

    def save_resource(self, session_id: str, resource: ResourceInstanceV1) -> Dict[str, Any]:
        resource.session_id = session_id
        resource.ensure_fingerprint()
        if resource.owner_identity_id:
            self.get_identity(session_id, resource.owner_identity_id)
        row = resource.model_dump()
        # Runtime locators are used by the in-process replay but never
        # persisted as ordinary metadata. A future vault reference can be
        # attached through locator_ref.
        metadata = dict(row.get("metadata") or {})
        metadata.pop("runtime_locator", None)
        row["metadata"] = redact(metadata)
        row["locator_redacted"] = redact(row.get("locator_redacted"))
        return self.sb.table("resource_instances").upsert(row, on_conflict="session_id,fingerprint").execute().data[0]

    def list_resources(self, session_id: str, owner_identity_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = self.sb.table("resource_instances").select("*").eq("session_id", session_id)
        if owner_identity_id:
            query = query.eq("owner_identity_id", owner_identity_id)
        return query.order("created_at", desc=True).execute().data or []

    def create_replay_run(self, session_id: str, run: AuthorizationReplayRunV1) -> Dict[str, Any]:
        run.session_id = session_id
        self.get_identity(session_id, run.owner_identity_id)
        for identity_id in run.test_identity_ids:
            self.get_identity(session_id, identity_id)
        row = run.model_dump(exclude={"attempts"})
        return self.sb.table("authorization_replay_runs").insert(row).execute().data[0]

    def save_attempt(self, session_id: str, attempt: ReplayAttemptV1) -> Dict[str, Any]:
        self.get_identity(session_id, attempt.identity_id)
        row = redact(attempt.model_dump())
        return self.sb.table("authorization_replay_attempts").upsert(row, on_conflict="attempt_id").execute().data[0]

    def list_replay_runs(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        return self.sb.table("authorization_replay_runs").select("*").eq("session_id", session_id).order("created_at", desc=True).limit(limit).execute().data or []

    def replay_detail(self, session_id: str, replay_run_id: str) -> Dict[str, Any]:
        runs = self.sb.table("authorization_replay_runs").select("*").eq("session_id", session_id).eq("replay_run_id", replay_run_id).limit(1).execute().data or []
        if not runs:
            raise ValueError("Authorization replay run not found.")
        attempts = self.sb.table("authorization_replay_attempts").select("*").eq("replay_run_id", replay_run_id).order("created_at").execute().data or []
        return {"run": runs[0], "attempts": attempts}

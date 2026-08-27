"""Supabase persistence for browser workflows and business invariants."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.browser_workflow_contract import (
    BrowserRunV1,
    BrowserStateSnapshotV1,
    BrowserStepRunV1,
    BrowserWorkflowV1,
    BusinessEntityV1,
    BusinessInvariantV1,
    BusinessStateTransitionV1,
    InvariantEvaluationV1,
    WorkflowRunMatrixV1,
)


class BrowserWorkflowRepository:
    def __init__(self, supabase: Any):
        self.sb = supabase

    @staticmethod
    def _dump(value: Any) -> Dict[str, Any]:
        return value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)

    def save_workflow(self, workflow: BrowserWorkflowV1) -> Dict[str, Any]:
        workflow.ensure_fingerprint()
        row = self._dump(workflow)
        steps = row.pop("steps", [])
        preconditions = row.pop("preconditions", [])
        postconditions = row.pop("postconditions", [])
        row["current_version"] = row.pop("version", 1)
        self.sb.table("browser_workflows").upsert(row, on_conflict="workflow_id").execute()
        version_id = f"{workflow.workflow_id}_v{workflow.version}"
        self.sb.table("browser_workflow_versions").upsert({
            "workflow_version_id": version_id,
            "workflow_id": workflow.workflow_id,
            "version": workflow.version,
            "status": workflow.status,
            "preconditions": preconditions,
            "postconditions": postconditions,
        }, on_conflict="workflow_version_id").execute()
        for step in steps:
            step_row = dict(step)
            step_row["workflow_version_id"] = version_id
            self.sb.table("browser_workflow_steps").upsert(
                step_row, on_conflict="step_id"
            ).execute()
        return row

    def publish(self, session_id: str, workflow_id: str) -> Dict[str, Any]:
        workflow = self.get_workflow(session_id, workflow_id)
        workflow.status = "published"
        step_ids = {step.step_id for step in workflow.steps}
        for cleanup_id in workflow.cleanup_step_ids:
            if cleanup_id not in step_ids:
                raise ValueError("Cleanup step reference is not present in this workflow version.")
        for step in workflow.steps:
            if step.is_mutation():
                cleanup_id = step.cleanup_step_id or (workflow.cleanup_step_ids[0] if workflow.cleanup_step_ids else "")
                if not cleanup_id or cleanup_id not in step_ids:
                    raise ValueError("Mutating workflow requires a valid cleanup step before publish.")
        self.save_workflow(workflow)
        self.sb.table("browser_workflow_versions").update({"status": "published"}).eq(
            "workflow_id", workflow_id
        ).eq("version", workflow.version).execute()
        return workflow.model_dump(mode="json")

    def list_workflows(self, session_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        query = self.sb.table("browser_workflows").select("*").eq("session_id", session_id)
        if status:
            query = query.eq("status", status)
        return query.order("updated_at", desc=True).execute().data or []

    def get_workflow(self, session_id: str, workflow_id: str) -> BrowserWorkflowV1:
        rows = self.sb.table("browser_workflows").select("*").eq(
            "session_id", session_id
        ).eq("workflow_id", workflow_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Browser workflow not found.")
        row = rows[0]
        version_id = f"{workflow_id}_v{row.get('current_version', 1)}"
        version_rows = self.sb.table("browser_workflow_versions").select("preconditions,postconditions").eq("workflow_version_id", version_id).limit(1).execute().data or []
        steps = self.sb.table("browser_workflow_steps").select("*").eq(
            "workflow_version_id", version_id
        ).order("ordinal").execute().data or []
        row["steps"] = steps
        row.setdefault("version", row.get("current_version", 1))
        if version_rows:
            row["preconditions"] = version_rows[0].get("preconditions", [])
            row["postconditions"] = version_rows[0].get("postconditions", [])
        return BrowserWorkflowV1(**row)

    def save_run(self, run: BrowserRunV1) -> Dict[str, Any]:
        row = self._dump(run)
        self.sb.table("browser_runs").upsert(row, on_conflict="run_id").execute()
        return row

    def save_run_matrix(self, matrix: WorkflowRunMatrixV1) -> Dict[str, Any]:
        matrix.ensure_digest()
        row = self._dump(matrix)
        return self.sb.table("workflow_run_matrices").upsert(
            row, on_conflict="matrix_id"
        ).execute().data[0]

    def get_run_matrix(self, session_id: str, matrix_id: str) -> Dict[str, Any]:
        rows = self.sb.table("workflow_run_matrices").select("*").eq(
            "session_id", session_id
        ).eq("matrix_id", matrix_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Workflow run matrix not found.")
        return rows[0]

    def list_run_matrices(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        return self.sb.table("workflow_run_matrices").select("*").eq(
            "session_id", session_id
        ).order("created_at", desc=True).limit(min(limit, 200)).execute().data or []

    def get_run(self, session_id: str, run_id: str) -> Dict[str, Any]:
        rows = self.sb.table("browser_runs").select("*").eq(
            "session_id", session_id
        ).eq("run_id", run_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Browser run not found.")
        return rows[0]

    def list_runs(self, session_id: str, workflow_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = self.sb.table("browser_runs").select("*").eq("session_id", session_id)
        if workflow_id:
            query = query.eq("workflow_id", workflow_id)
        return query.order("started_at", desc=True).limit(200).execute().data or []

    def save_step_run(self, step_run: BrowserStepRunV1) -> Dict[str, Any]:
        row = self._dump(step_run)
        self.sb.table("browser_step_runs").upsert(row, on_conflict="step_run_id").execute()
        return row

    def save_snapshot(self, snapshot: BrowserStateSnapshotV1) -> Dict[str, Any]:
        row = self._dump(snapshot)
        self.sb.table("browser_state_snapshots").insert(row).execute()
        return row

    def list_snapshots(self, session_id: str, run_id: str) -> List[Dict[str, Any]]:
        return self.sb.table("browser_state_snapshots").select("*").eq(
            "session_id", session_id
        ).eq("run_id", run_id).order("created_at").execute().data or []

    def save_entity(self, entity: BusinessEntityV1) -> Dict[str, Any]:
        entity.ensure_fingerprint()
        row = self._dump(entity)
        self.sb.table("business_entities").upsert(row, on_conflict="session_id,fingerprint").execute()
        version_row = {
            "entity_version_id": f"{entity.entity_id}_{entity.state_digest or entity.created_at}",
            "entity_id": entity.entity_id,
            "session_id": entity.session_id,
            "fingerprint": entity.fingerprint,
            "graph_id": entity.graph_id,
            "identity_ids": entity.identity_ids,
            "state_digest": entity.state_digest,
            "fields_redacted": entity.fields_redacted,
            "source_snapshot_ids": entity.source_snapshot_ids,
        }
        existing = self.sb.table("business_entity_versions").select("entity_version_id").eq(
            "entity_version_id", version_row["entity_version_id"]
        ).limit(1).execute().data or []
        if not existing:
            self.sb.table("business_entity_versions").insert(version_row).execute()
        return row

    def list_entities(self, session_id: str, fingerprint: Optional[str] = None) -> List[Dict[str, Any]]:
        query = self.sb.table("business_entities").select("*").eq("session_id", session_id)
        if fingerprint:
            query = query.eq("fingerprint", fingerprint)
        return query.order("created_at", desc=True).limit(200).execute().data or []

    def save_transition(self, transition: BusinessStateTransitionV1) -> Dict[str, Any]:
        row = self._dump(transition)
        self.sb.table("business_state_transitions").insert(row).execute()
        return row

    def save_invariant(self, invariant: BusinessInvariantV1) -> Dict[str, Any]:
        row = self._dump(invariant)
        self.sb.table("business_invariants").upsert(row, on_conflict="invariant_id").execute()
        version_id = f"{invariant.invariant_id}_r{invariant.revision}"
        exists = self.sb.table("business_invariant_versions").select("invariant_version_id").eq(
            "invariant_version_id", version_id
        ).limit(1).execute().data or []
        if not exists:
            self.sb.table("business_invariant_versions").insert({
                "invariant_version_id": version_id,
                "invariant_id": invariant.invariant_id,
                "session_id": invariant.session_id,
                "revision": invariant.revision,
                "compiler_version": invariant.compiler_version,
                "rule_type": invariant.rule_type,
                "rule": invariant.rule,
                "compiled": invariant.compiled,
                "input_digest": invariant.workflow_matrix_id or invariant.graph_id,
            }).execute()
        return row

    def list_invariants(self, session_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        query = self.sb.table("business_invariants").select("*").eq("session_id", session_id)
        if status:
            query = query.eq("status", status)
        return query.order("updated_at", desc=True).execute().data or []

    def save_evaluation(self, evaluation: InvariantEvaluationV1) -> Dict[str, Any]:
        row = self._dump(evaluation)
        checks = row.pop("checks", [])
        self.sb.table("invariant_evaluations").insert(row).execute()
        for check in checks:
            check_row = {"evaluation_id": evaluation.evaluation_id, "check_name": check.pop("name", "unknown"), **check}
            self.sb.table("invariant_checks").insert(check_row).execute()
        return {**row, "checks": checks}

    def list_evaluations(self, session_id: str, invariant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = self.sb.table("invariant_evaluations").select(
            "*, business_invariants!inner(session_id)"
        ).eq("business_invariants.session_id", session_id)
        if invariant_id:
            query = query.eq("invariant_id", invariant_id)
        return query.order("created_at", desc=True).limit(200).execute().data or []

    def save_artifact(self, session_id: str, artifact: Any, tool_run_id: str = "") -> Dict[str, Any]:
        row = {"session_id": session_id, "tool_run_id": tool_run_id, **self._dump(artifact)}
        self.sb.table("evidence_artifacts").upsert(row, on_conflict="artifact_id").execute()
        return row

    def artifact(self, session_id: str, artifact_id: str) -> Dict[str, Any]:
        rows = self.sb.table("evidence_artifacts").select("*").eq(
            "session_id", session_id
        ).eq("artifact_id", artifact_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Artifact not found.")
        return rows[0]

"""Session-local orchestration for browser runs across explicit identities.

This is the only new Stage 10 service module: contracts and execution remain
in the existing authorization/browser modules.  The coordinator plans a
matrix and never bypasses approval or directly executes a browser action.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from core.browser_workflow_contract import BrowserWorkflowV1, WorkflowRunMatrixV1
from core.authorization_contract import (
    AuthSurfaceObservationV1,
    IdentityGraphV1,
    IdentityWorkflowIntelligenceV1,
    SessionTransitionV1,
    WorkflowPrerequisiteV1,
)


class IdentityWorkflowMatrixCoordinator:
    def __init__(self, workflow_repository: Any = None):
        self.workflow_repository = workflow_repository

    @staticmethod
    def _active_auth_contexts(graph: IdentityGraphV1) -> Dict[str, str]:
        return {
            relation.subject_id: relation.object_id
            for relation in graph.relations
            if relation.relation == "auth_context_for"
            and relation.status == "active"
            and relation.object_id
        }

    def plan(
        self,
        workflow: BrowserWorkflowV1,
        graph: IdentityGraphV1,
        identity_ids: Iterable[str],
        *,
        entity_fingerprint: str = "",
        run_roles: Optional[Dict[str, str]] = None,
        cleanup_required: Optional[bool] = None,
    ) -> WorkflowRunMatrixV1:
        identities = sorted(set(str(item) for item in identity_ids if item))
        auth = self._active_auth_contexts(graph)
        missing: List[str] = []
        if workflow.status != "published":
            missing.append("published_workflow_required")
        if graph.session_id != workflow.session_id:
            missing.append("session_graph_mismatch")
        if len(identities) < 2:
            missing.append("two_isolated_identities_required")
        for identity_id in identities:
            if identity_id not in graph.node_ids:
                missing.append(f"identity_missing:{identity_id}")
            if identity_id not in auth:
                missing.append(f"active_auth_context_missing:{identity_id}")
        roles = dict(run_roles or {})
        required_roles = {"baseline", "negative_control", "test", "reproduction"}
        if workflow.has_mutations():
            required_roles.add("cleanup")
        missing.extend(f"run_role_missing:{role}" for role in sorted(required_roles) if role not in roles.values())
        cleanup = workflow.has_mutations() if cleanup_required is None else bool(cleanup_required)
        if cleanup and not workflow.has_cleanup():
            missing.append("cleanup_workflow_required")
        status = "ready" if not missing else "blocked"
        matrix = WorkflowRunMatrixV1(
            session_id=workflow.session_id,
            workflow_id=workflow.workflow_id,
            workflow_version=workflow.version,
            graph_id=graph.graph_id,
            entity_fingerprint=entity_fingerprint,
            run_roles=roles,
            identity_ids=identities,
            auth_context_ids=sorted(set(auth.values())),
            required_roles=sorted(required_roles),
            cleanup_required=cleanup,
            status=status,
            missing_requirements=sorted(set(missing)),
        )
        return matrix.ensure_digest()

    @staticmethod
    def add_run(matrix: WorkflowRunMatrixV1, run_id: str, role: str, cleanup_verified: bool = False) -> WorkflowRunMatrixV1:
        if role not in matrix.required_roles:
            matrix.missing_requirements.append(f"unexpected_run_role:{role}")
        if run_id and run_id not in matrix.run_ids:
            matrix.run_ids.append(run_id)
        if cleanup_verified:
            matrix.cleanup_verified = True
        if matrix.status not in {"failed", "blocked"}:
            required_run_count = len(set(matrix.run_roles.values()))
            matrix.status = "succeeded" if required_run_count >= len(set(matrix.required_roles)) and (not matrix.cleanup_required or matrix.cleanup_verified) else "running"
        return matrix

    @staticmethod
    def can_dispatch(matrix: WorkflowRunMatrixV1, *, mutation: bool = False, approved: bool = False) -> tuple[bool, str]:
        if matrix.status != "ready" and not (matrix.status == "running" and not mutation):
            return False, "Workflow identity matrix is not ready: " + ", ".join(matrix.missing_requirements)
        if mutation and not approved:
            return False, "Mutation requires exact approval bound to the matrix."
        if matrix.cleanup_required and not matrix.entity_fingerprint:
            return False, "Mutation matrix requires an entity fingerprint and cleanup target."
        return True, "Matrix dispatch permitted by deterministic preconditions."

    @staticmethod
    def evaluate_access_matrix(
        attempts: Iterable[Dict[str, Any]],
        *,
        owner_identity_id: str,
        resource_fingerprint: str,
        require_clean_reproduction: bool = True,
        require_cleanup: bool = False,
    ) -> Dict[str, Any]:
        """Compare isolated identities against one server-side resource.

        Response status/length is not enough. Callers must provide semantic
        access and a server-side state comparison for the same resource. The
        input is already-redacted attempt metadata; raw credentials never enter
        this boundary.
        """
        rows = [dict(item) for item in attempts or []]
        evidence: List[str] = []
        checks: List[Dict[str, Any]] = []

        def add(check_id: str, passed: bool, reason: str, *items: Dict[str, Any]) -> None:
            ids: List[str] = []
            for item in items:
                ids.extend(str(value) for value in item.get("evidence_ids", []) if value)
            evidence.extend(ids)
            checks.append({
                "check_id": check_id,
                "passed": bool(passed),
                "reason": reason,
                "evidence_ids": sorted(set(ids)),
            })

        identities = {str(item.get("identity_id", "")) for item in rows if item.get("identity_id")}
        contexts = {str(item.get("auth_context_id", "")) for item in rows if item.get("auth_context_id")}
        add("two_identities", len(identities) >= 2, "Owner and non-owner identities are required.", *rows)
        add("isolated_auth_contexts", len(contexts) >= 2, "Each identity must use an explicit isolated auth context.", *rows)
        same_resource = bool(rows) and all(
            str(item.get("resource_fingerprint", "")) == str(resource_fingerprint) for item in rows
        )
        add("same_resource", same_resource, "All attempts must address the same server-side resource fingerprint.", *rows)

        owner = next((item for item in rows if item.get("identity_id") == owner_identity_id), None)
        non_owner_rows = [item for item in rows if item.get("identity_id") and item.get("identity_id") != owner_identity_id]
        owner_allow = bool(owner and owner.get("semantic_result") in {"allow", "unexpected_allow"})
        add("owner_baseline", owner_allow, "Owner baseline must establish expected resource access.", *( [owner] if owner else [] ))

        non_owner = next((item for item in non_owner_rows if item.get("role") in {"test", "negative_control", "reproduction"}), None)
        non_owner_result = str((non_owner or {}).get("semantic_result", "unknown"))
        comparison = (non_owner or {}).get("comparison") or {}
        semantic_comparison = bool(
            non_owner
            and non_owner_result in {"deny", "allow", "unexpected_allow"}
            and comparison.get("server_state_digest")
            and comparison.get("resource_fingerprint") == resource_fingerprint
        )
        add("semantic_state_comparison", semantic_comparison, "Authorization must use server-side state for the same resource.", *( [non_owner] if non_owner else [] ))

        reproduction = next((item for item in non_owner_rows if item.get("role") == "reproduction"), None)
        reproduction_comparison = (reproduction or {}).get("comparison") or {}
        reproduction_ok = bool(
            reproduction
            and reproduction.get("semantic_result") in {"deny", "allow", "unexpected_allow"}
            and (not require_clean_reproduction or reproduction_comparison.get("clean_context"))
        )
        add("clean_reproduction", reproduction_ok, "Non-owner behavior must reproduce from a clean context.", *( [reproduction] if reproduction else [] ))

        cleanup_ok = True
        if require_cleanup:
            cleanup_ok = bool(comparison.get("cleanup_verified"))
            add("cleanup_verified", cleanup_ok, "Mutation authorization tests require verified cleanup.", *( [non_owner] if non_owner else [] ))

        complete = all(item["passed"] for item in checks)
        unauthorized_allow = non_owner_result in {"allow", "unexpected_allow"}
        if complete and unauthorized_allow:
            decision = "validated"
            reason = "Non-owner access to the same resource was semantically observed and reproduced."
        elif complete and non_owner_result == "deny":
            decision = "disproven"
            reason = "Non-owner access was denied for the same resource under the tested control."
        else:
            decision = "inconclusive"
            reason = "Identity/access comparison is incomplete; no authorization conclusion is made."
        return {
            "decision": decision,
            "checks": checks,
            "evidence_ids": sorted(set(evidence)),
            "reason": reason,
            "identity_count": len(identities),
            "auth_context_count": len(contexts),
        }

    @staticmethod
    def compile_intelligence(
        session_id: str,
        graph: IdentityGraphV1,
        auth_surfaces: Iterable[AuthSurfaceObservationV1 | Dict[str, Any]] = (),
        transitions: Iterable[SessionTransitionV1 | Dict[str, Any]] = (),
        workflows: Iterable[BrowserWorkflowV1 | Dict[str, Any]] = (),
        prerequisites: Iterable[WorkflowPrerequisiteV1 | Dict[str, Any]] = (),
    ) -> Dict[str, Any]:
        """Join identity, auth lifecycle, and workflow requirements.

        The compiler only produces a planning matrix. It does not infer that
        a role owns an object, that a login succeeded, or that an action is a
        vulnerability. Those claims still require evidence and validators.
        """
        def row(item: Any) -> Dict[str, Any]:
            return item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item or {})

        surfaces = [row(item) for item in auth_surfaces]
        lifecycle = [row(item) for item in transitions]
        workflow_rows = [row(item) for item in workflows]
        prereq_rows = [row(item) for item in prerequisites]
        identity_ids = sorted(set(graph.node_ids))
        auth_context_ids = sorted({
            str(item.object_id)
            for item in graph.relations
            if item.relation == "auth_context_for" and item.status == "active"
            and item.object_id
        })
        gaps = list(graph.gaps)
        contradictions: List[str] = []
        if not identity_ids:
            gaps.append("identity_graph_empty")
        if not auth_context_ids and surfaces:
            gaps.append("auth_context_not_bound_to_identity")
        if any(item.get("status") == "inconclusive" for item in surfaces):
            gaps.append("auth_surface_ambiguous")
        if any(item.get("event") == "login" for item in surfaces) and not lifecycle:
            gaps.append("session_transition_not_observed")
        for workflow in workflow_rows:
            wid = str(workflow.get("workflow_id", ""))
            if workflow.get("status") != "published":
                gaps.append(f"workflow_not_published:{wid}")
            if workflow.get("workflow_class") in {"authentication", "role_change", "approval"} and not workflow.get("identity_requirements"):
                gaps.append(f"workflow_identity_requirement_missing:{wid}")
            if workflow.get("mutating") and not workflow.get("cleanup_step_ids"):
                gaps.append(f"workflow_cleanup_missing:{wid}")
        for item in prereq_rows:
            if item.get("status") in {"missing", "inconclusive", "stale"} and item.get("required", True):
                gaps.append(f"prerequisite_{item.get('status')}:{item.get('kind')}:{item.get('reference_id', '')}")
        event_pairs = {(item.get("identity_id", ""), item.get("event", ""), item.get("after_status", "")) for item in lifecycle}
        if any(event == "logout" and after == "active" for _, event, after in event_pairs):
            contradictions.append("logout_active_state_conflict")
        workflow_ids = sorted({str(item.get("workflow_id", "")) for item in workflow_rows if item.get("workflow_id")})
        prereq_ids = sorted({str(item.get("prerequisite_id", "")) for item in prereq_rows if item.get("prerequisite_id")})
        intelligence = IdentityWorkflowIntelligenceV1(
            session_id=session_id,
            graph_id=graph.graph_id,
            graph_version=graph.version,
            auth_surface_ids=sorted({str(item.get("observation_id", "")) for item in surfaces if item.get("observation_id")}),
            transition_ids=sorted({str(item.get("transition_id", "")) for item in lifecycle if item.get("transition_id")}),
            workflow_ids=workflow_ids,
            prerequisite_ids=prereq_ids,
            identity_ids=identity_ids,
            auth_context_ids=auth_context_ids,
            trust_boundary_ids=sorted({str(item.object_id) for item in graph.relations if item.relation == "trust_boundary_for"}),
            gaps=sorted(set(item for item in gaps if item)),
            contradictions=sorted(set(contradictions)),
            status="inconclusive" if gaps or contradictions else "current",
        ).ensure_digest()
        matrix_rows = []
        for identity_id in identity_ids:
            relation = next((item for item in graph.relations if item.subject_id == identity_id and item.relation == "auth_context_for"), None)
            matrix_rows.append({
                "identity_id": identity_id,
                "auth_context_id": relation.object_id if relation else "",
                "role": next((item.object_id for item in graph.relations if item.subject_id == identity_id and item.relation == "role_of"), ""),
                "tenant": next((item.object_id for item in graph.relations if item.subject_id == identity_id and item.relation == "member_of_tenant"), ""),
                "isolated": bool(relation and relation.status == "active"),
                "workflow_ids": workflow_ids,
            })
        return {
            "intelligence": intelligence.model_dump(mode="json"),
            "identity_session_matrix": matrix_rows,
            "auth_surfaces": surfaces,
            "session_transitions": lifecycle,
            "workflows": workflow_rows,
            "prerequisites": prereq_rows,
            "gaps": intelligence.gaps,
            "contradictions": intelligence.contradictions,
        }


identity_workflow_matrix = IdentityWorkflowMatrixCoordinator()


__all__ = ["IdentityWorkflowMatrixCoordinator", "identity_workflow_matrix"]

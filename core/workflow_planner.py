"""Evidence-driven planning boundary for interactive engagements."""

from typing import Any, Dict, List, Optional

from core.adaptive_planner import AdaptiveHypothesisPlanner, PlanningSnapshot
from core.phase_machine import allowed_transitions, can_transition
from core.session_store import SessionStore
from core.target_state import TargetState
from core.workflow_models import ActionProposal, EngagementObjective, WorkflowPhase, WorkflowState


class WorkflowPlanner:
    def __init__(self, sessions: SessionStore):
        self.sessions = sessions
        self.adaptive = AdaptiveHypothesisPlanner()

    def load(self, session_id: str) -> tuple[Dict[str, Any], TargetState]:
        return self.sessions.require(session_id), self.sessions.load_state(session_id)

    def propose(self, session_id: str, request: str = "") -> Dict[str, Any]:
        context, state = self.load(session_id)
        workflow = state.workflow
        if not workflow.objectives:
            workflow.add_objective(EngagementObjective(description=context["attack_goal"]))

        phase = workflow.phase
        snapshot = self._snapshot(session_id)
        lifecycle = self._lifecycle_proposal(phase, context)
        if lifecycle is not None:
            workflow.add_proposal(lifecycle)
            proposals = [lifecycle]
            hypotheses = list(workflow.hypotheses)
            decision = None
        elif phase in {WorkflowPhase.REPORT.value, WorkflowPhase.COMPLETE.value}:
            proposals = []
            hypotheses = list(workflow.hypotheses)
            decision = None
            workflow.record_event("planner_stopped", phase=phase, reason="No active testing action is valid in this phase.")
        else:
            result = self.adaptive.plan(context, state, snapshot, request)
            proposals = result.proposals
            hypotheses = result.hypotheses
            decision = result.decision

        self.sessions.save_state(session_id, state, phase=phase)
        return {
            "phase": phase,
            "allowed_transitions": allowed_transitions(phase),
            "request": request,
            "objective": context["attack_goal"],
            "proposals": [item.__dict__ for item in proposals],
            "hypotheses": [item.__dict__ for item in hypotheses],
            "planner_decision": decision.__dict__ if decision else None,
            "snapshot": {
                "digest": snapshot.digest(),
                "candidate_count": len(snapshot.candidates),
                "errors": list(snapshot.errors),
                "observation_count": len(snapshot.observations),
                "tool_run_count": len(snapshot.tool_runs),
                "identity_count": len(snapshot.identities),
            },
            "workflow": workflow.to_dict(),
        }

    def reasoning_cycle(self, session_id: str, request: str = "", *, model_actions: Optional[List[Dict[str, Any]]] = None, model_id: str = "", mode: str = "shadow") -> Dict[str, Any]:
        context, state = self.load(session_id)
        snapshot = self._snapshot(session_id)
        context = {**context, "session_id": session_id}
        result = self.adaptive.build_reasoning_cycle(
            context, state, snapshot, request, model_actions=model_actions,
            model_id=model_id, mode=mode,
        )
        self.sessions.save_state(session_id, state, phase=state.workflow.phase)
        return {
            "session_id": session_id,
            "cycle": result.cycle.model_dump(mode="json"),
            "hypotheses": result.hypotheses,
            "actions": result.actions,
            "evidence_gaps": result.evidence_gaps,
            "stop_conditions": result.stop_conditions,
            "decision": result.decision,
            "model_traces": result.model_traces,
            "branches": result.branches,
            "branch_transitions": result.branch_transitions,
            "adaptation": result.adaptation,
            "snapshot": {"digest": snapshot.digest(), "errors": snapshot.errors},
        }

    def _snapshot(self, session_id: str) -> PlanningSnapshot:
        snapshot_errors: List[str] = []
        """Read session-local Stage 1/2 facts; missing additive tables are safe."""
        def rows(table: str, limit: int) -> List[Dict[str, Any]]:
            try:
                query = self.sessions.sb.table(table).select("*").eq("session_id", session_id)
                try:
                    query = query.order("created_at", desc=True)
                except Exception:
                    pass
                return query.limit(limit).execute().data or []
            except Exception:
                snapshot_errors.append(f"{table} table/query failed")
                return []

        return PlanningSnapshot(
            candidates=rows("candidate_findings", 500),
            observations=rows("observations", 1000),
            tool_runs=rows("tool_runs", 500),
            errors=snapshot_errors,
            identities=rows("identities", 50),
        )

    @staticmethod
    def _lifecycle_proposal(phase: str, context: Dict[str, Any]) -> Optional[ActionProposal]:
        target = context["target_url"]
        if phase == WorkflowPhase.CLEANUP.value:
            return ActionProposal(
                action="cleanup_registered_artifacts", target_url=target,
                rationale="Remove or roll back artifacts created by approved testing actions.",
                expected_evidence="Cleanup result for every registered side effect.",
                risk="medium", requires_approval=True,
            )
        if phase == WorkflowPhase.RETEST.value:
            return ActionProposal(
                action="retest_finding", target_url=target,
                rationale="Repeat the original bounded validation against a fresh baseline.",
                expected_evidence="Comparison showing fixed, still vulnerable, reopened, or inconclusive.",
                risk="medium", requires_approval=True,
            )
        if phase == WorkflowPhase.IMPACT_PROOF.value:
            return ActionProposal(
                action="controlled_impact_proof", target_url=target,
                rationale="Demonstrate only an approved objective using validated prerequisites.",
                expected_evidence="Minimal reversible proof linked to validated finding IDs.",
                risk="high", requires_approval=True, cleanup_required=True,
            )
        return None

    def transition(self, session_id: str, target_phase: str) -> Dict[str, Any]:
        context, state = self.load(session_id)
        if not can_transition(state.workflow.phase, target_phase):
            raise ValueError(f"Invalid workflow transition: {state.workflow.phase} -> {target_phase}")
        previous = state.workflow.phase
        state.workflow.phase = target_phase
        state.workflow.record_event("phase_changed", previous=previous, current=target_phase)
        self.sessions.save_state(session_id, state, phase=target_phase)
        return {"phase": target_phase, "workflow": state.workflow.to_dict(), "context": context}

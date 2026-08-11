"""Evidence-driven planning boundary for interactive engagements."""

from typing import Any, Dict, List, Optional

from core.phase_machine import allowed_transitions, can_transition
from core.session_store import SessionStore
from core.target_state import TargetState
from core.workflow_models import ActionProposal, EngagementObjective, WorkflowPhase, WorkflowState


class WorkflowPlanner:
    def __init__(self, sessions: SessionStore):
        self.sessions = sessions

    def load(self, session_id: str) -> tuple[Dict[str, Any], TargetState]:
        return self.sessions.require(session_id), self.sessions.load_state(session_id)

    def propose(self, session_id: str, request: str = "") -> Dict[str, Any]:
        context, state = self.load(session_id)
        workflow = state.workflow
        if not workflow.objectives:
            workflow.add_objective(EngagementObjective(description=context["attack_goal"]))

        phase = workflow.phase
        proposals: List[ActionProposal] = []
        if phase == WorkflowPhase.SETUP.value:
            proposals.append(ActionProposal(
                action="reconnaissance",
                target_url=context["target_url"],
                rationale="Build an authorized attack-surface inventory before forming hypotheses.",
                expected_evidence="Endpoints, technologies, exposed services, and security controls.",
                risk="low",
                requires_approval=True,
            ))
        elif phase in {WorkflowPhase.RECON.value, WorkflowPhase.MAPPING.value}:
            proposals.append(ActionProposal(
                action="attack_surface_mapping",
                target_url=context["target_url"],
                rationale="Use collected recon evidence to identify reachable application paths and parameters.",
                expected_evidence="Mapped endpoints, parameters, auth boundaries, and candidate attack surfaces.",
                risk="low",
                requires_approval=True,
            ))
        elif phase in {WorkflowPhase.HYPOTHESIS.value, WorkflowPhase.THREAT_MODEL.value}:
            proposals.append(ActionProposal(
                action="hypothesis_validation",
                target_url=context["target_url"],
                rationale="Validate one evidence-backed hypothesis with a bounded, non-destructive test.",
                expected_evidence="A reproducible request/response difference or a disproven hypothesis.",
                risk="medium",
                requires_approval=True,
            ))
        elif phase in {WorkflowPhase.VALIDATION.value, WorkflowPhase.CHAINING.value}:
            proposals.append(ActionProposal(
                action="controlled_impact_proof",
                target_url=context["target_url"],
                rationale="Demonstrate the objective impact only when prerequisite findings are validated.",
                expected_evidence="Minimal, reversible proof tied to validated finding IDs.",
                risk="high",
                requires_approval=True,
                cleanup_required=True,
            ))
        elif phase == WorkflowPhase.CLEANUP.value:
            proposals.append(ActionProposal(
                action="cleanup_registered_artifacts",
                target_url=context["target_url"],
                rationale="Remove or roll back artifacts created by approved testing actions.",
                expected_evidence="Cleanup result for every registered side effect.",
                risk="medium",
                requires_approval=True,
            ))
        elif phase == WorkflowPhase.RETEST.value:
            proposals.append(ActionProposal(
                action="retest_finding",
                target_url=context["target_url"],
                rationale="Repeat the original bounded validation against a fresh baseline.",
                expected_evidence="Comparison showing fixed, still vulnerable, reopened, or inconclusive.",
                risk="medium",
                requires_approval=True,
            ))

        for proposal in proposals:
            workflow.add_proposal(proposal)
        self.sessions.save_state(session_id, state, phase=phase)
        return {
            "phase": phase,
            "allowed_transitions": allowed_transitions(phase),
            "request": request,
            "objective": context["attack_goal"],
            "proposals": [item.__dict__ for item in proposals],
            "workflow": workflow.to_dict(),
        }

    def transition(self, session_id: str, target_phase: str) -> Dict[str, Any]:
        context, state = self.load(session_id)
        if not can_transition(state.workflow.phase, target_phase):
            raise ValueError(f"Invalid workflow transition: {state.workflow.phase} -> {target_phase}")
        previous = state.workflow.phase
        state.workflow.phase = target_phase
        state.workflow.record_event("phase_changed", previous=previous, current=target_phase)
        self.sessions.save_state(session_id, state, phase=target_phase)
        return {"phase": target_phase, "workflow": state.workflow.to_dict(), "context": context}

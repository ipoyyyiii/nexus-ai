"""Bounded, approval-gated impact-proof planning."""

from typing import Any, Dict

from core.chain_planner import ChainPlanner
from core.session_store import SessionStore
from core.workflow_models import ActionProposal, RecordStatus


class ImpactService:
    def __init__(self, sessions: SessionStore, chains: ChainPlanner):
        self.sessions = sessions
        self.chains = chains

    def propose(self, session_id: str, objective: str = "") -> Dict[str, Any]:
        context = self.sessions.require(session_id)
        state = self.sessions.load_state(session_id)
        validated = [item for item in state.workflow.findings if item.status == RecordStatus.VALIDATED.value]
        if not validated:
            raise ValueError("Impact proof requires at least one validated finding.")
        if any(item.status != RecordStatus.COMPLETE.value for item in state.workflow.cleanup if item.source_action_id):
            raise ValueError("Existing cleanup items must be complete before a new impact proof.")
        finding = validated[0]
        proposal = ActionProposal(
            action="bounded_impact_proof",
            target_url=context["target_url"],
            rationale=f"Demonstrate only the requested objective using validated finding {finding.finding_id}.",
            expected_evidence="Fresh baseline, minimal before/after result, and explicit objective success criteria.",
            risk="high",
            requires_approval=True,
            side_effects=["Only the explicitly approved objective state may be touched."],
            cleanup_required=True,
            evidence_ids=list(finding.evidence_ids),
        )
        state.workflow.add_proposal(proposal)
        state.workflow.record_event("impact_proof_proposed", action_id=proposal.action_id, finding_id=finding.finding_id)
        self.sessions.save_state(session_id, state)
        return {"proposal": proposal.__dict__, "finding": finding.__dict__, "requires_registered_handler": True}

    def record_result(self, session_id: str, action_id: str, before: str, after: str, success: bool) -> Dict[str, Any]:
        state = self.sessions.load_state(session_id)
        proposal = next((item for item in state.workflow.proposals if item.action_id == action_id), None)
        if not proposal or proposal.action != "bounded_impact_proof":
            raise ValueError("Bounded impact proposal not found.")
        if proposal.status != "running":
            raise ValueError("Impact proof is not running.")
        proposal.status = "complete" if success else "failed"
        state.workflow.record_event("impact_proof_result", action_id=action_id, success=success, before=before[:500], after=after[:500])
        self.sessions.save_state(session_id, state)
        return {"proposal": proposal.__dict__, "success": success}

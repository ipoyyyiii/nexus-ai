"""Central policy checks for workflow actions."""

from dataclasses import dataclass
from typing import Any, Optional

from core.session_store import SessionStore
from core.workflow_models import ActionProposal, RecordStatus


@dataclass
class GuardDecision:
    allowed: bool
    reason: str
    requires_approval: bool = True


class ExecutionGuard:
    def __init__(self, sessions: SessionStore):
        self.sessions = sessions

    def check(self, session_id: str, proposal: ActionProposal, approved: bool = False) -> GuardDecision:
        context = self.sessions.require(session_id)
        valid, reason = self.sessions.validate_active_scope(session_id, proposal.target_url)
        if not valid:
            return GuardDecision(False, f"Scope rejected: {reason}")
        if not context.get("authorization_confirmed"):
            return GuardDecision(False, "Explicit authorization is required.")
        if proposal.risk in {"high", "critical"} and not approved:
            return GuardDecision(False, "This action requires explicit approval.")
        if proposal.status not in {RecordStatus.PROPOSED.value, RecordStatus.PENDING.value}:
            return GuardDecision(False, f"Action is not executable in status '{proposal.status}'.")
        return GuardDecision(True, "Action permitted by session policy.", proposal.requires_approval)

    def approve(self, session_id: str, action_id: str, reviewer_note: str = "") -> ActionProposal:
        state = self.sessions.load_state(session_id)
        for proposal in state.workflow.proposals:
            if proposal.action_id == action_id:
                decision = self.check(session_id, proposal, approved=True)
                if not decision.allowed:
                    raise ValueError(decision.reason)
                proposal.status = "approved"
                state.workflow.record_event(
                    "action_approved", action_id=action_id, reviewer_note=reviewer_note
                )
                self.sessions.save_state(session_id, state)
                return proposal
        raise ValueError("Action proposal not found.")

    def reject(self, session_id: str, action_id: str, reviewer_note: str = "") -> ActionProposal:
        state = self.sessions.load_state(session_id)
        for proposal in state.workflow.proposals:
            if proposal.action_id == action_id:
                proposal.status = "rejected"
                state.workflow.record_event(
                    "action_rejected", action_id=action_id, reviewer_note=reviewer_note
                )
                self.sessions.save_state(session_id, state)
                return proposal
        raise ValueError("Action proposal not found.")

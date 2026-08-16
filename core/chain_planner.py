"""Deterministic evidence-backed chain planning."""

from typing import Any, Dict, List

from core.session_store import SessionStore
from core.workflow_models import ActionProposal, ChainRecord, RecordStatus


class ChainPlanner:
    def __init__(self, sessions: SessionStore):
        self.sessions = sessions

    def propose_next(self, session_id: str, objective: str = "") -> Dict[str, Any]:
        context = self.sessions.require(session_id)
        state = self.sessions.load_state(session_id)
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        validated = sorted(
            [item for item in state.workflow.findings if item.status == RecordStatus.VALIDATED.value],
            key=lambda x: (sev_rank.get(x.severity.lower(), 0), len(x.evidence_ids)),
            reverse=True,
        )
        if not validated:
            return {
                "status": "blocked",
                "reason": "No validated finding is available for chaining.",
                "proposals": [],
            }

        finding = validated[0]
        chain = next((item for item in state.workflow.chains if finding.finding_id in item.step_ids), None)
        if not chain:
            chain = ChainRecord(
                name=objective or context["attack_goal"],
                step_ids=[finding.finding_id],
                status=RecordStatus.RUNNING.value,
                current_step=1,
            )
            state.workflow.chains.append(chain)

        proposal = ActionProposal(
            action="controlled_impact_proof",
            target_url=context["target_url"],
            rationale=f"Use validated finding {finding.finding_id} as the prerequisite for the stated objective.",
            expected_evidence="Minimal, objective-specific before/after evidence linked to the validated finding.",
            risk="high",
            requires_approval=True,
            cleanup_required=True,
            evidence_ids=list(finding.evidence_ids),
        )
        state.workflow.add_proposal(proposal)
        state.workflow.record_event("chain_step_proposed", chain_id=chain.chain_id, action_id=proposal.action_id)
        self.sessions.save_state(session_id, state)
        return {
            "status": "proposed",
            "chain": chain.__dict__,
            "finding": finding.__dict__,
            "proposals": [proposal.__dict__],
        }

    def validate_prerequisites(self, session_id: str, finding_ids: List[str]) -> bool:
        state = self.sessions.load_state(session_id)
        findings = {item.finding_id: item for item in state.workflow.findings}
        return bool(finding_ids) and all(
            item_id in findings and findings[item_id].status == RecordStatus.VALIDATED.value
            for item_id in finding_ids
        )

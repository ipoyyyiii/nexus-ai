"""Bounded retest execution against a fresh read-only baseline."""

from typing import Any, Dict

from core.evidence_service import EvidenceService
from core.session_store import SessionStore
from core.workflow_models import RecordStatus


class RetestService:
    def __init__(self, sessions: SessionStore, evidence: EvidenceService):
        self.sessions = sessions
        self.evidence = evidence

    def prepare(self, session_id: str, finding_id: str) -> Dict[str, Any]:
        state = self.sessions.load_state(session_id)
        finding = next((item for item in state.workflow.findings if item.finding_id == finding_id), None)
        if not finding:
            raise ValueError("Finding not found.")
        if finding.status not in {RecordStatus.VALIDATED.value, RecordStatus.REOPENED.value, RecordStatus.SUSPECTED.value}:
            raise ValueError(f"Finding status '{finding.status}' is not retestable.")
        original = [item.__dict__ for item in state.workflow.evidence if item.evidence_id in finding.evidence_ids]
        return {
            "finding": finding.__dict__,
            "original_evidence": original,
            "procedure": "Repeat the original bounded validation using a fresh baseline and the same authorized scope.",
            "requires_approval": True,
        }

    def record(self, session_id: str, finding_id: str, status: str, comparison: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        allowed = {"fixed", "still_vulnerable", "inconclusive", "reopened"}
        if status not in allowed:
            raise ValueError(f"Retest status must be one of: {', '.join(sorted(allowed))}")
        stored = self.evidence.add(
            session_id=session_id,
            source="retest",
            summary=comparison,
            target_url=evidence.get("target_url", ""),
            method=evidence.get("method", "GET"),
            request=evidence.get("request", ""),
            response=evidence.get("response", ""),
            confidence=evidence.get("confidence", "medium"),
        )
        state = self.sessions.load_state(session_id)
        finding = next((item for item in state.workflow.findings if item.finding_id == finding_id), None)
        if not finding:
            raise ValueError("Finding not found.")
        finding.status = {
            "fixed": RecordStatus.FIXED.value,
            "still_vulnerable": RecordStatus.VALIDATED.value,
            "reopened": RecordStatus.REOPENED.value,
            "inconclusive": RecordStatus.INCONCLUSIVE.value,
        }[status]
        for retest in state.workflow.retests:
            if retest.finding_id == finding_id and retest.status == RecordStatus.PENDING.value:
                retest.status = status
                retest.comparison = comparison[:4000]
                retest.retest_evidence_ids = [stored.evidence_id]
        state.workflow.record_event("retest_result", finding_id=finding_id, status=status, evidence_id=stored.evidence_id)
        self.sessions.save_state(session_id, state)
        return {"finding": finding.__dict__, "evidence": stored.__dict__, "status": status}

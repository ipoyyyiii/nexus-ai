"""Cleanup and retest lifecycle operations for authorized engagements."""

from typing import Any, Dict

from core.cleanup_registry import cleanup_registry

from core.session_store import SessionStore
from core.workflow_models import CleanupItem, RecordStatus, RetestRecord


class LifecycleService:
    def __init__(self, sessions: SessionStore):
        self.sessions = sessions

    def register_cleanup(self, session_id: str, description: str, action: str, source_action_id: str = "") -> CleanupItem:
        state = self.sessions.load_state(session_id)
        item = CleanupItem(description=description, action=action, source_action_id=source_action_id)
        state.workflow.cleanup.append(item)
        state.workflow.record_event("cleanup_registered", cleanup_id=item.cleanup_id)
        self.sessions.save_state(session_id, state)
        return item

    def execute_cleanup(self, session_id: str, cleanup_id: str, handler_name: str, context: dict) -> CleanupItem:
        state = self.sessions.load_state(session_id)
        for item in state.workflow.cleanup:
            if item.cleanup_id == cleanup_id:
                result = cleanup_registry.execute(handler_name, context)
                item.status = RecordStatus.COMPLETE.value if result.get("success") else RecordStatus.FAILED.value
                item.result = str(result.get("result", ""))[:2000]
                state.workflow.record_event("cleanup_executed", cleanup_id=cleanup_id, handler=handler_name, success=result.get("success", False))
                self.sessions.save_state(session_id, state)
                return item
        raise ValueError("Cleanup item not found.")

    def complete_cleanup(self, session_id: str, cleanup_id: str, result: str, success: bool) -> CleanupItem:
        state = self.sessions.load_state(session_id)
        for item in state.workflow.cleanup:
            if item.cleanup_id == cleanup_id:
                item.status = RecordStatus.COMPLETE.value if success else RecordStatus.FAILED.value
                item.result = result[:2000]
                state.workflow.record_event("cleanup_completed", cleanup_id=cleanup_id, success=success)
                self.sessions.save_state(session_id, state)
                return item
        raise ValueError("Cleanup item not found.")

    def start_retest(self, session_id: str, finding_id: str) -> RetestRecord:
        state = self.sessions.load_state(session_id)
        for finding in state.workflow.findings:
            if finding.finding_id == finding_id:
                retest = RetestRecord(
                    finding_id=finding_id,
                    original_evidence_ids=list(finding.evidence_ids),
                )
                state.workflow.retests.append(retest)
                finding.retest_id = retest.retest_id
                state.workflow.record_event("retest_started", finding_id=finding_id, retest_id=retest.retest_id)
                self.sessions.save_state(session_id, state)
                return retest
        raise ValueError("Finding not found.")

    def finish_retest(self, session_id: str, retest_id: str, status: str, comparison: str, evidence_ids: list[str]) -> RetestRecord:
        allowed = {"fixed", "still_vulnerable", "inconclusive", "reopened"}
        if status not in allowed:
            raise ValueError(f"Retest status must be one of: {', '.join(sorted(allowed))}")
        state = self.sessions.load_state(session_id)
        for retest in state.workflow.retests:
            if retest.retest_id == retest_id:
                retest.status = status
                retest.comparison = comparison[:4000]
                retest.retest_evidence_ids = evidence_ids
                for finding in state.workflow.findings:
                    if finding.finding_id == retest.finding_id:
                        finding.status = RecordStatus.FIXED.value if status == "fixed" else (
                            RecordStatus.REOPENED.value if status == "reopened" else finding.status
                        )
                state.workflow.record_event("retest_completed", retest_id=retest_id, status=status)
                self.sessions.save_state(session_id, state)
                return retest
        raise ValueError("Retest not found.")

    def summary(self, session_id: str) -> Dict[str, Any]:
        state = self.sessions.load_state(session_id)
        return {
            "cleanup": [item.__dict__ for item in state.workflow.cleanup],
            "retests": [item.__dict__ for item in state.workflow.retests],
            "pending_cleanup": sum(item.status == RecordStatus.PENDING.value for item in state.workflow.cleanup),
        }

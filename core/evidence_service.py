"""Evidence, finding, and chain operations for workflow state."""

import hashlib
import re
from typing import Any, Dict, List

from core.session_store import SessionStore
from core.workflow_models import (
    EvidenceRecord,
    FindingRecord,
    RecordStatus,
)

_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)(cookie\s*:\s*)[^\n]+"),
    re.compile(r"(?i)(password|passwd|token|secret)\s*[=:]\s*[^\s]+"),
]


def redact(value: str, limit: int = 4000) -> str:
    result = value or ""
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(r"\1[REDACTED]", result)
    return result[:limit]


class EvidenceService:
    def __init__(self, sessions: SessionStore):
        self.sessions = sessions

    def add(
        self,
        session_id: str,
        source: str,
        summary: str,
        target_url: str = "",
        method: str = "GET",
        request: str = "",
        response: str = "",
        confidence: str = "medium",
        tool_run_id: str = "",
    ) -> EvidenceRecord:
        state = self.sessions.load_state(session_id)
        evidence = EvidenceRecord(
            source=source,
            summary=redact(summary),
            target_url=target_url,
            method=method,
            request_excerpt=redact(request),
            response_excerpt=redact(response),
            payload_hash=hashlib.sha256(redact(request).encode()).hexdigest() if request else "",
            confidence=confidence,
            tool_run_id=tool_run_id,
        )
        state.workflow.add_evidence(evidence)
        self.sessions.save_state(session_id, state)
        return evidence

    def add_finding(
        self,
        session_id: str,
        title: str,
        vuln_type: str,
        severity: str,
        evidence_ids: List[str],
        prerequisite_ids: List[str] | None = None,
        finding_fingerprint: str = "",
    ) -> FindingRecord:
        state = self.sessions.load_state(session_id)
        known = {item.evidence_id for item in state.workflow.evidence}
        if any(item not in known for item in evidence_ids):
            raise ValueError("Finding references unknown evidence.")
        if finding_fingerprint:
            for existing in state.workflow.findings:
                if getattr(existing, "fingerprint", "") == finding_fingerprint:
                    existing.evidence_ids = sorted(set(existing.evidence_ids + evidence_ids))
                    self.sessions.save_state(session_id, state)
                    return existing
        finding = FindingRecord(
            title=redact(title, 500),
            vuln_type=vuln_type,
            severity=severity,
            evidence_ids=evidence_ids,
            prerequisite_ids=prerequisite_ids or [],
            status=RecordStatus.SUSPECTED.value,
        )
        if finding_fingerprint:
            setattr(finding, "fingerprint", finding_fingerprint)
        state.workflow.findings.append(finding)
        state.workflow.record_event("finding_created", finding_id=finding.finding_id)
        self.sessions.save_state(session_id, state)
        return finding

    def ingest_adapter_result(self, session_id: str, result: Any) -> Dict[str, Any]:
        evidence_ids = []
        for item in result.evidence:
            evidence = self.add(
                session_id=session_id,
                source=item.get("source", result.tool),
                summary=item.get("summary", result.summary),
                target_url=item.get("target_url", result.target_url),
                method=item.get("method", "GET"),
                request=item.get("request", ""),
                response=item.get("response", ""),
                confidence=item.get("confidence", result.confidence),
                tool_run_id=item.get("tool_run_id", ""),
            )
            evidence_ids.append(evidence.evidence_id)
        findings = []
        for item in result.findings:
            findings.append(self.add_finding(
                session_id=session_id,
                title=item["title"],
                vuln_type=item["vuln_type"],
                severity=item["severity"],
                evidence_ids=evidence_ids,
                finding_fingerprint=item.get("fingerprint", ""),
            ))
        return {"evidence_ids": evidence_ids, "findings": [item.__dict__ for item in findings], "endpoints": result.endpoints}

    def validate_finding(self, session_id: str, finding_id: str, confirmed: bool) -> FindingRecord:
        state = self.sessions.load_state(session_id)
        for finding in state.workflow.findings:
            if finding.finding_id == finding_id:
                finding.status = RecordStatus.VALIDATED.value if confirmed else RecordStatus.DISPROVEN.value
                state.workflow.record_event(
                    "finding_reviewed", finding_id=finding_id, confirmed=confirmed
                )
                self.sessions.save_state(session_id, state)
                return finding
        raise ValueError("Finding not found.")

    def objective_progress(self, session_id: str) -> Dict[str, Any]:
        state = self.sessions.load_state(session_id)
        total = len(state.workflow.objectives)
        complete = sum(item.status in {RecordStatus.COMPLETE.value, RecordStatus.IMPACT_PROVEN.value} for item in state.workflow.objectives)
        return {"phase": state.workflow.phase, "total": total, "complete": complete, "progress": round(complete / total * 100) if total else 0}

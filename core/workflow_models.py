"""Structured workflow records for evidence-driven security engagements."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class WorkflowPhase(str, Enum):
    SETUP = "SETUP"
    RECON = "RECON"
    MAPPING = "MAPPING"
    THREAT_MODEL = "THREAT_MODEL"
    HYPOTHESIS = "HYPOTHESIS"
    VALIDATION = "VALIDATION"
    CHAINING = "CHAINING"
    IMPACT_PROOF = "IMPACT_PROOF"
    CLEANUP = "CLEANUP"
    REPORT = "REPORT"
    RETEST = "RETEST"
    COMPLETE = "COMPLETE"


class RecordStatus(str, Enum):
    PENDING = "pending"
    PROPOSED = "proposed"
    RUNNING = "running"
    SUSPECTED = "suspected"
    VALIDATED = "validated"
    DISPROVEN = "disproven"
    IMPACT_PROVEN = "impact_proven"
    FIXED = "fixed"
    REOPENED = "reopened"
    INCONCLUSIVE = "inconclusive"
    COMPLETE = "complete"
    FAILED = "failed"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


@dataclass
class EngagementObjective:
    description: str
    success_criteria: List[str] = field(default_factory=list)
    allowed_impact: str = "non-destructive evidence only"
    exclusions: List[str] = field(default_factory=list)
    objective_id: str = field(default_factory=lambda: _id("obj"))
    status: str = RecordStatus.PENDING.value
    progress: int = 0


@dataclass
class EvidenceRecord:
    source: str
    summary: str
    target_url: str = ""
    method: str = "GET"
    request_excerpt: str = ""
    response_excerpt: str = ""
    payload_hash: str = ""
    confidence: str = "medium"
    tool_run_id: str = ""
    evidence_id: str = field(default_factory=lambda: _id("ev"))
    created_at: str = field(default_factory=_now)
    redacted: bool = True


@dataclass
class FindingRecord:
    title: str
    vuln_type: str
    severity: str
    evidence_ids: List[str] = field(default_factory=list)
    prerequisite_ids: List[str] = field(default_factory=list)
    finding_id: str = field(default_factory=lambda: _id("finding"))
    status: str = RecordStatus.SUSPECTED.value
    confidence: str = "medium"
    remediation: str = ""
    fingerprint: str = ""
    retest_id: str = ""


@dataclass
class HypothesisRecord:
    claim: str
    supporting_evidence_ids: List[str] = field(default_factory=list)
    required_action_ids: List[str] = field(default_factory=list)
    hypothesis_id: str = field(default_factory=lambda: _id("hyp"))
    status: str = RecordStatus.PENDING.value
    result: str = ""
    confidence: str = "medium"


@dataclass
class ActionProposal:
    action: str
    target_url: str
    rationale: str
    expected_evidence: str
    risk: str = "low"
    requires_approval: bool = True
    side_effects: List[str] = field(default_factory=list)
    cleanup_required: bool = False
    action_id: str = field(default_factory=lambda: _id("action"))
    status: str = RecordStatus.PROPOSED.value
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class ChainRecord:
    name: str
    step_ids: List[str] = field(default_factory=list)
    chain_id: str = field(default_factory=lambda: _id("chain"))
    status: str = RecordStatus.PENDING.value
    current_step: int = 0
    blocked_reason: str = ""


@dataclass
class CleanupItem:
    description: str
    action: str
    source_action_id: str = ""
    cleanup_id: str = field(default_factory=lambda: _id("cleanup"))
    status: str = RecordStatus.PENDING.value
    result: str = ""


@dataclass
class RetestRecord:
    finding_id: str
    original_evidence_ids: List[str] = field(default_factory=list)
    retest_evidence_ids: List[str] = field(default_factory=list)
    retest_id: str = field(default_factory=lambda: _id("retest"))
    status: str = RecordStatus.PENDING.value
    comparison: str = ""
    created_at: str = field(default_factory=_now)


@dataclass
class WorkflowState:
    phase: str = WorkflowPhase.SETUP.value
    objectives: List[EngagementObjective] = field(default_factory=list)
    evidence: List[EvidenceRecord] = field(default_factory=list)
    findings: List[FindingRecord] = field(default_factory=list)
    hypotheses: List[HypothesisRecord] = field(default_factory=list)
    proposals: List[ActionProposal] = field(default_factory=list)
    chains: List[ChainRecord] = field(default_factory=list)
    cleanup: List[CleanupItem] = field(default_factory=list)
    retests: List[RetestRecord] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "WorkflowState":
        data = data or {}
        def many(key: str, record_type: Any) -> List[Any]:
            return [record_type(**item) for item in data.get(key, [])]
        return cls(
            phase=data.get("phase", WorkflowPhase.SETUP.value),
            objectives=many("objectives", EngagementObjective),
            evidence=many("evidence", EvidenceRecord),
            findings=many("findings", FindingRecord),
            hypotheses=many("hypotheses", HypothesisRecord),
            proposals=many("proposals", ActionProposal),
            chains=many("chains", ChainRecord),
            cleanup=many("cleanup", CleanupItem),
            retests=many("retests", RetestRecord),
            events=list(data.get("events", [])),
        )

    def record_event(self, event_type: str, **payload: Any) -> None:
        self.events.append({"event_id": _id("event"), "type": event_type, "at": _now(), **payload})

    def add_objective(self, objective: EngagementObjective) -> None:
        self.objectives.append(objective)
        self.record_event("objective_added", objective_id=objective.objective_id)

    def add_evidence(self, evidence: EvidenceRecord) -> None:
        self.evidence.append(evidence)
        self.record_event("evidence_added", evidence_id=evidence.evidence_id, source=evidence.source)

    def add_proposal(self, proposal: ActionProposal) -> None:
        self.proposals.append(proposal)
        self.record_event("proposal_created", action_id=proposal.action_id, action=proposal.action)

    def context(self) -> str:
        objectives = "\n".join(f"- [{item.status}] {item.description}" for item in self.objectives) or "- None defined"
        findings = "\n".join(
            f"- [{item.status}] {item.severity} {item.vuln_type}: {item.title} (evidence: {len(item.evidence_ids)})"
            for item in self.findings
        ) or "- None recorded"
        chains = "\n".join(
            f"- [{item.status}] {item.name}: step {item.current_step}/{len(item.step_ids)}"
            for item in self.chains
        ) or "- None planned"
        return (
            f"Workflow phase: {self.phase}\n"
            f"Objectives:\n{objectives}\n"
            f"Findings:\n{findings}\n"
            f"Chains:\n{chains}\n"
            f"Evidence records: {len(self.evidence)}\n"
            f"Pending cleanup items: {sum(item.status == RecordStatus.PENDING.value for item in self.cleanup)}\n"
        )

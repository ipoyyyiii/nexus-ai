"""Structured workflow records for evidence-driven security engagements."""

from dataclasses import asdict, dataclass, field, fields as dataclass_fields
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
    STALE = "stale"


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
    validation_source: str = "machine"
    source_candidate_id: str = ""


@dataclass
class HypothesisRecord:
    claim: str
    supporting_evidence_ids: List[str] = field(default_factory=list)
    required_action_ids: List[str] = field(default_factory=list)
    hypothesis_id: str = field(default_factory=lambda: _id("hyp"))
    status: str = RecordStatus.PENDING.value
    result: str = ""
    confidence: str = "medium"
    category: str = "unknown"
    target_url: str = ""
    method: str = "GET"
    parameter: str = ""
    fingerprint: str = ""
    null_hypothesis: str = "The observed behavior has a benign explanation."
    alternative_claims: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    source_candidate_ids: List[str] = field(default_factory=list)
    prior_probability: float = 0.5
    confidence_score: float = 0.5
    expected_information_gain: float = 0.0
    test_attempts: int = 0
    max_test_attempts: int = 3
    generation_rule: str = ""
    decision_reason: str = ""
    revision: int = 1
    last_updated: str = field(default_factory=_now)
    metadata: Dict[str, Any] = field(default_factory=dict)


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
    hypothesis_id: str = ""
    recommended_tool: str = ""
    alternative_tools: List[str] = field(default_factory=list)
    information_gain: float = 0.0
    estimated_cost: float = 0.0
    risk_score: float = 0.0
    priority_score: float = 0.0
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    preconditions: List[str] = field(default_factory=list)
    unmet_preconditions: List[str] = field(default_factory=list)
    stop_conditions: List[str] = field(default_factory=list)
    input_bindings: Dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
    planner_cycle_id: str = ""
    planner_managed: bool = False


@dataclass
class PlannerDecisionRecord:
    cycle_id: str = field(default_factory=lambda: _id("plan"))
    snapshot_digest: str = ""
    considered_actions: List[Dict[str, Any]] = field(default_factory=list)
    selected_action_ids: List[str] = field(default_factory=list)
    knowledge_gaps: List[str] = field(default_factory=list)
    stop_reasons: List[str] = field(default_factory=list)
    rationale: str = ""
    created_at: str = field(default_factory=_now)


@dataclass
class ChainRecord:
    name: str
    step_ids: List[str] = field(default_factory=list)
    chain_id: str = field(default_factory=lambda: _id("chain"))
    status: str = RecordStatus.PENDING.value
    current_step: int = 0
    blocked_reason: str = ""
    chain_version: int = 1
    graph_digest: str = ""
    node_ids: List[str] = field(default_factory=list)
    edge_ids: List[str] = field(default_factory=list)
    prerequisite_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    identity_ids: List[str] = field(default_factory=list)
    protocol_operation_ids: List[str] = field(default_factory=list)
    impact_objective: str = ""
    validation_status: str = RecordStatus.INCONCLUSIVE.value
    validation_source: str = "machine"
    mission_id: str = ""
    identity_graph_digest: str = ""
    knowledge_graph_digest: str = ""
    workflow_matrix_id: str = ""
    path_score: float = 0.0
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    impact_status: str = RecordStatus.INCONCLUSIVE.value
    reproduction_status: str = "unknown"
    cleanup_status: str = "unknown"
    input_digest: str = ""


@dataclass
class ChainNode:
    node_type: str
    reference_id: str
    label: str = ""
    status: str = RecordStatus.PENDING.value
    evidence_ids: List[str] = field(default_factory=list)
    identity_id: str = ""
    tenant_label: str = ""
    protocol: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    node_id: str = field(default_factory=lambda: _id("cnode"))
    capability: str = ""
    role: str = ""
    state_digest: str = ""
    resource_fingerprint: str = ""


@dataclass
class ChainEdge:
    source_node_id: str
    target_node_id: str
    relation: str
    evidence_ids: List[str] = field(default_factory=list)
    deterministic: bool = True
    edge_id: str = field(default_factory=lambda: _id("cedge"))
    status: str = RecordStatus.PROPOSED.value
    reason: str = ""
    preconditions: List[str] = field(default_factory=list)
    required_identity_ids: List[str] = field(default_factory=list)
    risk: str = "read_only"
    cleanup_refs: List[str] = field(default_factory=list)
    impact_role: str = ""


@dataclass
class ImpactProofPlan:
    chain_id: str
    objective: str
    target_url: str
    exact_steps: List[Dict[str, Any]] = field(default_factory=list)
    payload_ids: List[str] = field(default_factory=list)
    identity_id: str = ""
    auth_context_id: str = ""
    bindings_hash: str = ""
    approval_digest: str = ""
    budget: Dict[str, Any] = field(default_factory=dict)
    expires_at: str = ""
    cleanup_refs: List[str] = field(default_factory=list)
    expected_before: Dict[str, Any] = field(default_factory=dict)
    expected_after: Dict[str, Any] = field(default_factory=dict)
    status: str = RecordStatus.PROPOSED.value
    plan_id: str = field(default_factory=lambda: _id("impact"))
    chain_version: int = 1
    graph_digest: str = ""
    workflow_matrix_id: str = ""
    required_evidence_roles: List[str] = field(default_factory=list)
    expected_effect: Dict[str, Any] = field(default_factory=dict)
    state_fingerprint: str = ""


@dataclass
class ChainEvaluation:
    chain_id: str
    decision: str = RecordStatus.INCONCLUSIVE.value
    checks: List[Dict[str, Any]] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    reason: str = ""
    validator_version: str = "2.0"
    policy_version: str = "1.0"
    evaluation_id: str = field(default_factory=lambda: _id("chaineval"))
    chain_version: int = 1
    impact_status: str = RecordStatus.INCONCLUSIVE.value
    reproduction_status: str = "unknown"
    cleanup_status: str = "unknown"
    score: float = 0.0
    input_digest: str = ""


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
    planner_decisions: List[PlannerDecisionRecord] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "WorkflowState":
        data = data or {}
        def many(key: str, record_type: Any) -> List[Any]:
            allowed = {item.name for item in dataclass_fields(record_type)}
            records = []
            for item in data.get(key, []):
                if isinstance(item, dict):
                    records.append(record_type(**{k: v for k, v in item.items() if k in allowed}))
            return records
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
            planner_decisions=many("planner_decisions", PlannerDecisionRecord),
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

    def upsert_hypothesis(self, hypothesis: HypothesisRecord) -> HypothesisRecord:
        existing = next(
            (item for item in self.hypotheses if hypothesis.fingerprint and item.fingerprint == hypothesis.fingerprint),
            None,
        )
        if existing is None:
            self.hypotheses.append(hypothesis)
            self.record_event(
                "hypothesis_created",
                hypothesis_id=hypothesis.hypothesis_id,
                fingerprint=hypothesis.fingerprint,
                generation_rule=hypothesis.generation_rule,
            )
            return hypothesis

        preserved_id = existing.hypothesis_id
        preserved_actions = list(dict.fromkeys(existing.required_action_ids + hypothesis.required_action_ids))
        preserved_attempts = existing.test_attempts
        preserved_revision = existing.revision
        previous_status = existing.status
        for item in dataclass_fields(HypothesisRecord):
            setattr(existing, item.name, getattr(hypothesis, item.name))
        existing.hypothesis_id = preserved_id
        existing.required_action_ids = preserved_actions
        existing.test_attempts = preserved_attempts
        existing.revision = preserved_revision + 1
        if hypothesis.status == RecordStatus.PENDING.value and previous_status in {
            RecordStatus.PROPOSED.value, RecordStatus.RUNNING.value,
        }:
            existing.status = previous_status
        existing.last_updated = _now()
        if previous_status != existing.status:
            self.record_event(
                "hypothesis_status_changed",
                hypothesis_id=existing.hypothesis_id,
                previous=previous_status,
                current=existing.status,
            )
        return existing

    def add_planner_decision(self, decision: PlannerDecisionRecord) -> None:
        self.planner_decisions.append(decision)
        # Keep session JSONB bounded while preserving the event/audit summary.
        self.planner_decisions = self.planner_decisions[-100:]
        self.record_event(
            "planner_cycle_completed",
            cycle_id=decision.cycle_id,
            snapshot_digest=decision.snapshot_digest,
            selected_action_ids=decision.selected_action_ids,
            considered_count=len(decision.considered_actions),
            knowledge_gap_count=len(decision.knowledge_gaps),
        )

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

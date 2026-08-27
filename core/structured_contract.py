"""Versioned contract for tool execution and evidence.

The contract deliberately separates observations from candidate findings.  A
tool may report a signal, but only the validation engine can promote it to a
validated finding.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.redact import redact
from core.config_loader import get_setting


ToolStatus = Literal["running", "succeeded", "partial", "skipped", "failed", "cancelled"]
CandidateStatus = Literal[
    "suspected", "validating", "validated", "validated_override",
    "disproven", "inconclusive",
]
ObservationRole = Literal[
    "baseline", "test", "negative_control", "positive_control",
    "reproduction", "oob", "browser", "external",
]

PayloadRisk = Literal["harmless", "read_only", "mutation", "high_risk"]
ProtocolName = Literal["http", "graphql", "websocket", "sse", "grpc_web", "oauth", "oidc", "browser", "webhook", "async_job", "cache"]
ParserContext = Literal[
    "unknown", "json", "form", "multipart", "xml", "graphql", "websocket_message",
    "sse_event", "grpc_web_frame", "jwt", "signed_url", "html", "binary",
]
ReasoningCycleMode = Literal["shadow", "strict"]
ReasoningCycleStatus = Literal["queued", "running", "waiting_approval", "waiting_auth", "stopped", "succeeded", "partial", "failed", "cancelled"]
ReasoningHypothesisStatus = Literal["proposed", "testable", "supported", "contradicted", "inconclusive", "blocked", "closed"]
ReasoningActionType = Literal["observe", "hypothesize", "run_read_only", "propose_payload", "request_approval", "stop"]
ReasoningActionStatus = Literal["proposed", "accepted", "rejected", "blocked", "queued", "completed"]
ReasoningSearchStrategy = Literal["best_first", "beam", "bounded_backtrack", "explore_exploit"]
ReasoningBranchStatus = Literal[
    "proposed", "ready", "running", "backtracking", "blocked", "stale",
    "succeeded", "closed", "failed", "cancelled",
]
ReasoningTransitionType = Literal[
    "created", "selected", "expanded", "replanned", "backtracked",
    "blocked", "stale", "closed", "recovered",
]
ReportClaimType = Literal["finding", "impact", "reproduction", "remediation", "chain", "summary"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_target(value: str) -> str:
    parsed = urlsplit(value.strip())
    if not parsed.scheme or not parsed.netloc:
        return value.strip().lower().rstrip("/")
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def make_fingerprint(
    vuln_type: str,
    target_url: str,
    method: str = "GET",
    parameter: str = "",
    injection_point: str = "",
) -> str:
    canonical = "|".join((
        vuln_type.strip().lower(),
        normalize_target(target_url),
        method.strip().upper(),
        parameter.strip().lower(),
        injection_point.strip().lower(),
    ))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ObservationV1(ContractModel):
    observation_id: str = Field(default_factory=lambda: f"obs_{uuid.uuid4().hex}")
    role: ObservationRole = "test"
    kind: str = "http_exchange"
    summary: str = ""
    target_url: str = ""
    method: str = "GET"
    request_excerpt: str = ""
    response_excerpt: str = ""
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    payload_hash: str = ""
    artifact_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("summary", "request_excerpt", "response_excerpt", mode="before")
    @classmethod
    def redact_text(cls, value: Any) -> str:
        return redact(str(value or ""))


class ArtifactV1(ContractModel):
    artifact_id: str = Field(default_factory=lambda: f"art_{uuid.uuid4().hex}")
    kind: str = "text"
    mime_type: str = "text/plain"
    sha256: str = ""
    size_bytes: int = 0
    excerpt: str = ""
    storage_uri: str = ""
    redacted: bool = True
    retention_until: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("excerpt", mode="before")
    @classmethod
    def redact_excerpt(cls, value: Any) -> str:
        return redact(str(value or ""))[:8000]


class CandidateFindingV1(ContractModel):
    candidate_id: str = Field(default_factory=lambda: f"cand_{uuid.uuid4().hex}")
    title: str
    vuln_type: str
    severity: str = "INFO"
    target_url: str = ""
    method: str = "GET"
    parameter: str = ""
    injection_point: str = ""
    fingerprint: str = ""
    status: CandidateStatus = "suspected"
    confidence_score: float = 0.5
    confidence_reasons: List[str] = Field(default_factory=list)
    observation_ids: List[str] = Field(default_factory=list)
    remediation: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("confidence_score")
    @classmethod
    def confidence_range(cls, value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    @field_validator("title", "remediation", mode="before")
    @classmethod
    def redact_finding_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def ensure_fingerprint(self) -> "CandidateFindingV1":
        if not self.fingerprint:
            self.fingerprint = make_fingerprint(
                self.vuln_type, self.target_url, self.method,
                self.parameter, self.injection_point,
            )
        return self


class ToolErrorV1(ContractModel):
    code: str = "tool_error"
    message: str = ""
    retryable: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("message", mode="before")
    @classmethod
    def redact_message(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class ToolResultV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    tool_run_id: str = Field(default_factory=lambda: f"run_{uuid.uuid4().hex}")
    tool_name: str
    tool_version: str = "1"
    category: str = "unknown"
    target: str = ""
    started_at: str = Field(default_factory=now_iso)
    finished_at: Optional[str] = None
    status: ToolStatus = "succeeded"
    inputs_redacted: Dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    observations: List[ObservationV1] = Field(default_factory=list)
    artifacts: List[ArtifactV1] = Field(default_factory=list)
    candidate_findings: List[CandidateFindingV1] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    errors: List[ToolErrorV1] = Field(default_factory=list)
    side_effects: List[Dict[str, Any]] = Field(default_factory=list)
    cleanup_refs: List[str] = Field(default_factory=list)
    legacy_source: bool = False

    @field_validator("summary", mode="before")
    @classmethod
    def redact_summary(cls, value: Any) -> str:
        return redact(str(value or ""))[:4000]

    def model_post_init(self, __context: Any) -> None:
        self.inputs_redacted = redact(self.inputs_redacted)
        self.metrics = redact(self.metrics)
        self.side_effects = redact(self.side_effects)
        self.cleanup_refs = redact(self.cleanup_refs)
        for observation in self.observations:
            observation.metadata = redact(observation.metadata)
        for artifact in self.artifacts:
            artifact.metadata = redact(artifact.metadata)
        for finding in self.candidate_findings:
            finding.metadata = redact(finding.metadata)
            if not finding.target_url:
                finding.target_url = self.target
            finding.ensure_fingerprint()
        if not self.finished_at and self.status != "running":
            self.finished_at = now_iso()

    def llm_summary(self) -> str:
        """Safe, bounded representation for model prompts and UI logs."""
        payload = {
            "schema_version": self.schema_version,
            "tool": self.tool_name,
            "status": self.status,
            "summary": self.summary[:1000],
            "observations": [
                {
                    "id": item.observation_id,
                    "role": item.role,
                    "kind": item.kind,
                    "summary": item.summary[:500],
                    "status_code": item.status_code,
                }
                for item in self.observations[:30]
            ],
            "candidates": [
                {
                    "id": item.candidate_id,
                    "title": item.title[:300],
                    "type": item.vuln_type,
                    "severity": item.severity,
                    "status": item.status,
                    "confidence": item.confidence_score,
                    "observation_ids": item.observation_ids,
                }
                for item in self.candidate_findings
            ],
            "errors": [item.model_dump() for item in self.errors],
        }
        return json.dumps(payload, ensure_ascii=False)


class PayloadProposalV1(ContractModel):
    """A bounded payload proposal produced by reasoning, never a finding."""

    schema_version: Literal["1.0"] = "1.0"
    payload_id: str = Field(default_factory=lambda: f"payload_{uuid.uuid4().hex}")
    target_url: str
    input_ref: str
    family: str
    risk: PayloadRisk = "harmless"
    value_hash: str = ""
    redacted_excerpt: str = ""
    encoding_variants: List[str] = Field(default_factory=list)
    expected_signal: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    requires_approval: bool = False
    cleanup_ref: str = ""
    expires_at: Optional[str] = None
    parser_context: ParserContext = "unknown"
    parameter_location: str = ""
    mutation_operator: str = ""
    schema_digest: str = ""
    approval_digest: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("target_url", "input_ref", "family", "expected_signal", "cleanup_ref", mode="before")
    @classmethod
    def redact_payload_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:1000]

    @field_validator("redacted_excerpt", mode="before")
    @classmethod
    def redact_payload_excerpt(cls, value: Any) -> str:
        return redact(str(value or ""))[:500]

    def requires_exact_approval(self) -> bool:
        return self.risk in {"mutation", "high_risk"} or self.requires_approval


class PayloadAttemptV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    attempt_id: str = Field(default_factory=lambda: f"pattempt_{uuid.uuid4().hex}")
    payload_id: str
    tool_run_id: str = ""
    job_id: str = ""
    status: Literal["planned", "blocked", "dispatched", "succeeded", "failed", "cancelled", "unknown"] = "planned"
    approval_digest: str = ""
    request_count: int = 0
    evidence_ids: List[str] = Field(default_factory=list)
    result_digest: str = ""
    failure_reason: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("failure_reason", mode="before")
    @classmethod
    def redact_payload_failure(cls, value: Any) -> str:
        return redact(str(value or ""))[:1000]


class ProtocolOperationV1(ContractModel):
    """A redacted, chainable operation discovered on a modern web/API surface."""

    schema_version: Literal["1.0"] = "1.0"
    operation_id: str = Field(default_factory=lambda: f"op_{uuid.uuid4().hex}")
    session_id: str = ""
    protocol: ProtocolName
    origin: str
    operation_ref: str
    method: str = ""
    identity_id: str = ""
    auth_context_id: str = ""
    side_effect_class: Literal["read", "mutation", "unknown"] = "unknown"
    request_fingerprint: str = ""
    response_fingerprint: str = ""
    observation_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    follow_up_operation_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("origin", "operation_ref", "method", "identity_id", "auth_context_id", mode="before")
    @classmethod
    def redact_protocol_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:1000]


class ProtocolExchangeV1(ContractModel):
    """Redacted protocol exchange used by deterministic comparison.

    Bodies and tokens never belong in this contract.  The exchange keeps
    digests, bounded semantic fields, and references to persisted evidence.
    """

    schema_version: Literal["1.0"] = "1.0"
    exchange_id: str = Field(default_factory=lambda: f"exchange_{uuid.uuid4().hex}")
    operation_id: str = ""
    protocol: ProtocolName
    role: ObservationRole = "test"
    parser_context: ParserContext = "unknown"
    content_type: str = ""
    request_digest: str = ""
    response_digest: str = ""
    semantic_digest: str = ""
    state_digest: str = ""
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    identity_id: str = ""
    tenant_label: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("content_type", "operation_id", "identity_id", "tenant_label", mode="before")
    @classmethod
    def redact_exchange_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:500]


class SemanticComparisonV1(ContractModel):
    """Deterministic comparison; transport noise is not a vulnerability signal."""

    schema_version: Literal["1.0"] = "1.0"
    comparison_id: str = Field(default_factory=lambda: f"compare_{uuid.uuid4().hex}")
    operation_id: str = ""
    protocol: ProtocolName
    baseline_exchange_id: str = ""
    test_exchange_id: str = ""
    control_exchange_id: str = ""
    reproduction_exchange_id: str = ""
    changed_dimensions: List[str] = Field(default_factory=list)
    stable_dimensions: List[str] = Field(default_factory=list)
    noise_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    signal_strength: float = Field(default=0.0, ge=0.0, le=1.0)
    semantic_signal: bool = False
    status_only_signal: bool = False
    length_only_signal: bool = False
    replay_stable: bool = False
    evidence_ids: List[str] = Field(default_factory=list)
    input_digest: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProtocolCoverageV1(ContractModel):
    """Coverage dimensions for protocol-aware benchmark and target memory."""

    schema_version: Literal["1.0"] = "1.0"
    coverage_id: str = Field(default_factory=lambda: f"pcov_{uuid.uuid4().hex}")
    session_id: str = ""
    operation_id: str = ""
    protocol: ProtocolName
    parser_context: ParserContext = "unknown"
    identity_id: str = ""
    tenant_label: str = ""
    policy_id: str = ""
    status: Literal["untested", "tested", "covered", "blocked", "unsupported"] = "untested"
    evidence_ids: List[str] = Field(default_factory=list)
    comparison_ids: List[str] = Field(default_factory=list)
    last_input_digest: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ReasoningCycleV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    cycle_id: str = Field(default_factory=lambda: f"reason_{uuid.uuid4().hex}")
    session_id: str
    job_id: str = ""
    objective: str = ""
    mode: ReasoningCycleMode = "shadow"
    status: ReasoningCycleStatus = "queued"
    snapshot_digest: str = ""
    config_digest: str = ""
    model_id: str = ""
    prompt_version: str = ""
    action_budget: int = Field(default=3, ge=0, le=100)
    cycle_number: int = Field(default=1, ge=1)
    max_cycles: int = Field(default=10, ge=1, le=100)
    selected_action_ids: List[str] = Field(default_factory=list)
    hypothesis_ids: List[str] = Field(default_factory=list)
    branch_ids: List[str] = Field(default_factory=list)
    current_branch_id: str = ""
    search_strategy: ReasoningSearchStrategy = "best_first"
    search_depth: int = Field(default=0, ge=0, le=100)
    replan_count: int = Field(default=0, ge=0, le=1000)
    budget_snapshot: Dict[str, Any] = Field(default_factory=dict)
    evidence_gap_ids: List[str] = Field(default_factory=list)
    stop_condition_ids: List[str] = Field(default_factory=list)
    stop_reason: str = ""
    input_digest: str = ""
    output_digest: str = ""
    created_at: str = Field(default_factory=now_iso)
    finished_at: Optional[str] = None

    @field_validator("objective", "stop_reason", mode="before")
    @classmethod
    def redact_cycle_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class HypothesisRecordV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    hypothesis_id: str
    cycle_id: str = ""
    session_id: str
    claim: str
    null_hypothesis: str = "The observed behavior has a benign explanation."
    status: ReasoningHypothesisStatus = "proposed"
    category: str = "unknown"
    target_url: str = ""
    method: str = "GET"
    parameter: str = ""
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    contradicting_evidence_ids: List[str] = Field(default_factory=list)
    required_evidence_roles: List[str] = Field(default_factory=list)
    evidence_gap_ids: List[str] = Field(default_factory=list)
    priority_score: float = Field(default=0.0, ge=0.0, le=1.0)
    expected_information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    source: Literal["deterministic", "model", "operator"] = "deterministic"
    fingerprint: str = ""
    parent_hypothesis_id: str = ""
    branch_id: str = ""
    assumptions: List[str] = Field(default_factory=list)
    expected_outcomes: List[str] = Field(default_factory=list)
    contradiction_ids: List[str] = Field(default_factory=list)
    alternative_strategy_ids: List[str] = Field(default_factory=list)
    search_depth: int = Field(default=0, ge=0, le=100)
    freshness_boundary: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("claim", "null_hypothesis", mode="before")
    @classmethod
    def redact_hypothesis_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:4000]


class PlannerActionV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    action_id: str = Field(default_factory=lambda: f"r_action_{uuid.uuid4().hex}")
    cycle_id: str = ""
    action_type: ReasoningActionType = "observe"
    tool_name: str = ""
    endpoint_ref: str = ""
    hypothesis_id: str = ""
    risk: PayloadRisk = "read_only"
    side_effect_class: Literal["read", "mutation", "credential", "upload", "raw_network", "unknown"] = "read"
    evidence_ids: List[str] = Field(default_factory=list)
    expected_evidence_roles: List[str] = Field(default_factory=list)
    requires_approval: bool = False
    cleanup_ref: str = ""
    expected_information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: str = ""
    status: ReasoningActionStatus = "proposed"
    rejection_reason: str = ""
    input_digest: str = ""
    capability_id: str = ""
    branch_id: str = ""
    parent_action_id: str = ""
    target_digest: str = ""
    input_bindings: Dict[str, Any] = Field(default_factory=dict)
    expected_observation_kinds: List[str] = Field(default_factory=list)
    mutation_operator: str = ""
    approval_digest: str = ""
    budget_snapshot: Dict[str, Any] = Field(default_factory=dict)
    source: Literal["deterministic", "model", "operator"] = "model"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("rationale", "rejection_reason", mode="before")
    @classmethod
    def redact_action_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:3000]

    def is_mutating(self) -> bool:
        return self.side_effect_class in {"mutation", "credential", "upload", "raw_network"} or self.risk in {"mutation", "high_risk"}


class EvidenceGapV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    gap_id: str = Field(default_factory=lambda: f"gap_{uuid.uuid4().hex}")
    cycle_id: str = ""
    session_id: str
    hypothesis_id: str = ""
    gap_type: Literal["baseline", "negative_control", "reproduction", "cleanup", "identity", "state", "correlation", "approval", "scope", "tool", "contradiction"]
    description: str
    required_role: str = ""
    blocking: bool = True
    status: Literal["open", "resolved", "waived"] = "open"
    evidence_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("description", mode="before")
    @classmethod
    def redact_gap_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class StopConditionV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    stop_condition_id: str = Field(default_factory=lambda: f"stop_{uuid.uuid4().hex}")
    cycle_id: str = ""
    kind: Literal["objective_complete", "no_information_gain", "budget_exhausted", "deadline", "blocked", "contradiction", "max_cycles", "cleanup_pending", "operator"]
    triggered: bool = False
    reason: str = ""
    evidence_ids: List[str] = Field(default_factory=list)

    @field_validator("reason", mode="before")
    @classmethod
    def redact_stop_reason(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class ModelActionTraceV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    trace_id: str = Field(default_factory=lambda: f"mtrace_{uuid.uuid4().hex}")
    cycle_id: str
    model_id: str = ""
    provider: str = ""
    prompt_version: str = ""
    raw_output_digest: str = ""
    action: Optional[PlannerActionV1] = None
    valid: bool = False
    rejection_reason: str = ""
    hallucinated_reference: bool = False
    unsafe_mutation: bool = False
    invented_evidence: bool = False
    unknown_tool: bool = False
    unsupported_capability: bool = False
    stale_context: bool = False
    created_at: str = Field(default_factory=now_iso)

    @field_validator("rejection_reason", mode="before")
    @classmethod
    def redact_trace_reason(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class ReasoningDecisionV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    decision_id: str = Field(default_factory=lambda: f"rdec_{uuid.uuid4().hex}")
    cycle_id: str
    snapshot_digest: str = ""
    selected_action_ids: List[str] = Field(default_factory=list)
    rejected_action_ids: List[str] = Field(default_factory=list)
    evidence_gap_ids: List[str] = Field(default_factory=list)
    stop_condition_ids: List[str] = Field(default_factory=list)
    rationale: str = ""
    deterministic: bool = True
    selected_branch_id: str = ""
    score_breakdown: Dict[str, float] = Field(default_factory=dict)
    rejected_alternatives: List[Dict[str, Any]] = Field(default_factory=list)
    replan_reason: str = ""
    input_digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("rationale", mode="before")
    @classmethod
    def redact_decision_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:4000]


class ReasoningBranchV1(ContractModel):
    """Durable bounded-search branch; it never grants execution authority."""

    schema_version: Literal["1.0"] = "1.0"
    branch_id: str = Field(default_factory=lambda: f"branch_{uuid.uuid4().hex}")
    cycle_id: str
    session_id: str
    parent_branch_id: str = ""
    status: ReasoningBranchStatus = "proposed"
    hypothesis_ids: List[str] = Field(default_factory=list)
    action_ids: List[str] = Field(default_factory=list)
    evidence_snapshot_digest: str = ""
    search_depth: int = Field(default=0, ge=0, le=100)
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    score_breakdown: Dict[str, float] = Field(default_factory=dict)
    estimated_cost: float = Field(default=0.0, ge=0.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    failure_count: int = Field(default=0, ge=0)
    backtrack_count: int = Field(default=0, ge=0)
    stop_reason: str = ""
    input_digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("stop_reason", mode="before")
    @classmethod
    def redact_branch_reason(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class ReasoningBranchTransitionV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    transition_id: str = Field(default_factory=lambda: f"btrans_{uuid.uuid4().hex}")
    branch_id: str
    cycle_id: str
    session_id: str
    transition_type: ReasoningTransitionType
    from_status: str = ""
    to_status: str = ""
    reason: str = ""
    action_id: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    input_digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("reason", mode="before")
    @classmethod
    def redact_transition_reason(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class ReasoningAdaptationV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    adaptation_id: str = Field(default_factory=lambda: f"adapt_{uuid.uuid4().hex}")
    cycle_id: str
    session_id: str
    strategy: ReasoningSearchStrategy = "best_first"
    selected_branch_id: str = ""
    selected_action_id: str = ""
    alternative_action_ids: List[str] = Field(default_factory=list)
    reason: str = ""
    information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    uncertainty_before: float = Field(default=0.0, ge=0.0, le=1.0)
    uncertainty_after: float = Field(default=0.0, ge=0.0, le=1.0)
    backtracked: bool = False
    stop_recommended: bool = False
    input_digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("reason", mode="before")
    @classmethod
    def redact_adaptation_reason(cls, value: Any) -> str:
        return redact(str(value or ""))[:3000]


class ReportClaimV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    claim_id: str = Field(default_factory=lambda: f"claim_{uuid.uuid4().hex}")
    report_id: str
    claim_type: ReportClaimType
    text: str
    source_candidate_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    policy_versions: Dict[str, str] = Field(default_factory=dict)
    validated: bool = False
    override: bool = False
    grounded: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("text", mode="before")
    @classmethod
    def redact_claim_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:5000]


class ReportNarrativeV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    report_id: str = Field(default_factory=lambda: f"report_{uuid.uuid4().hex}")
    session_id: str
    target: str = ""
    objective: str = ""
    status: Literal["shadow", "ready", "blocked"] = "shadow"
    finding_ids: List[str] = Field(default_factory=list)
    claim_ids: List[str] = Field(default_factory=list)
    markdown: str = ""
    grounding_complete: bool = False
    redaction_leaks: int = 0
    source_digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("markdown", mode="before")
    @classmethod
    def redact_report_markdown(cls, value: Any) -> str:
        return redact(str(value or ""))


def result_from_legacy(tool_name: str, target: str, output: Any, tool_run_id: str = "") -> ToolResultV1:
    """Convert old scanner output without treating text severity markers as truth.

    JSON objects with explicit finding/vulnerability arrays become candidates.
    Free-form text becomes an observation only.
    """
    raw = output if isinstance(output, str) else json.dumps(output, default=str)
    if raw.lstrip().lower().startswith("error:"):
        return ToolResultV1(
            tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
            tool_name=tool_name,
            category="legacy",
            target=target,
            inputs_redacted={},
            status="failed",
            summary=redact(raw)[:4000],
            observations=[],
            errors=[ToolErrorV1(
                code="external_command_failed",
                message=redact(raw)[:2000],
                retryable=False,
            )],
            legacy_source=True,
        )
    parsed: Any = None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        pass

    # Legacy adapters must preserve an explicit tool failure.  A scanner that
    # caught an exception and returned JSON with ``status=ERROR`` must not be
    # converted into a successful observation merely because the payload is
    # valid JSON.
    if isinstance(parsed, dict) and str(parsed.get("status", "")).upper() in {
        "ERROR", "FAILED", "FAILURE",
    }:
        message = redact(str(parsed.get("error") or parsed.get("reason") or raw))[:2000]
        return ToolResultV1(
            tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
            tool_name=tool_name,
            category="legacy",
            target=target,
            inputs_redacted={},
            status="failed",
            summary=redact(raw)[:4000],
            observations=[],
            errors=[ToolErrorV1(
                code="legacy_tool_failed",
                message=message,
                retryable=False,
            )],
            legacy_source=True,
        )

    observations = [ObservationV1(
        role="external" if isinstance(parsed, dict) and parsed.get("external_tool") else "test",
        kind="legacy_output",
        summary=redact(raw)[:2000],
        target_url=target,
        response_excerpt=redact(raw)[:8000],
        metadata={"legacy": True},
    )]
    candidates: List[CandidateFindingV1] = []
    access_control_legacy = {
        "scan_idor", "idor_uuid_scanner", "access_control_scanner",
        "IDOR Scanner", "IDOR UUID Scanner", "Access Control Scanner",
    }
    # The old ID mutation scanners do not possess identity/ownership/control
    # evidence. In strict mode their output remains historical observation
    # only; the authorization replay engine is the sole finding producer.
    legacy_candidate_allowed = not (
        tool_name in access_control_legacy
        and str(get_setting("structured_evidence_mode", "strict")).lower() == "strict"
    )
    items: List[Any] = []
    if isinstance(parsed, dict):
        for key in ("findings", "vulnerabilities", "candidates"):
            value = parsed.get(key)
            if isinstance(value, list):
                items.extend(value)
        if parsed.get("finding") and isinstance(parsed["finding"], dict):
            items.append(parsed["finding"])
    elif isinstance(parsed, list):
        items = parsed

    for item in items:
        if not isinstance(item, dict):
            continue
        title = item.get("title") or item.get("name") or item.get("type")
        vuln_type = item.get("vuln_type") or item.get("type") or item.get("category")
        if not title or not vuln_type:
            continue
        candidate = CandidateFindingV1(
            title=str(title),
            vuln_type=str(vuln_type),
            severity=str(item.get("severity", "INFO")).upper(),
            target_url=str(item.get("url") or item.get("target_url") or target),
            method=str(item.get("method", "GET")),
            parameter=str(item.get("parameter") or item.get("param") or ""),
            injection_point=str(item.get("injection_point") or ""),
            confidence_score=float(item.get("confidence_score", 0.5) or 0.5),
            confidence_reasons=["Legacy scanner output; deterministic validation required."],
            observation_ids=[observations[0].observation_id],
            remediation=str(item.get("remediation") or item.get("recommendation") or ""),
            metadata={"legacy_item": True},
        )
        if legacy_candidate_allowed:
            candidates.append(candidate.ensure_fingerprint())

    return ToolResultV1(
        tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
        tool_name=tool_name,
        category="legacy",
        target=target,
        inputs_redacted={},
        summary=redact(raw)[:4000],
        observations=observations,
        candidate_findings=candidates,
        legacy_source=True,
    )

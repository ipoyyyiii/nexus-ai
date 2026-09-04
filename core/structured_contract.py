"""Versioned contract for tool execution and evidence.

The contract deliberately separates observations from candidate findings.  A
tool may report a signal, but only the validation engine can promote it to a
validated finding.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.redact import redact


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
# ``shadow`` and ``strict`` are historical values kept so old persisted
# cycles can still be read. New runtime cycles always use ``autonomous``.
ReasoningCycleMode = Literal["autonomous", "shadow", "strict"]
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
    mode: ReasoningCycleMode = "autonomous"
    status: ReasoningCycleStatus = "queued"
    snapshot_digest: str = ""
    config_digest: str = ""
    model_id: str = ""
    prompt_version: str = ""
    action_budget: Optional[int] = Field(default=None, ge=0)
    cycle_number: int = Field(default=1, ge=1)
    max_cycles: Optional[int] = Field(default=None, ge=1)
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


class ModelCallTraceV1(ContractModel):
    """Auditable metadata for one reasoning-provider attempt.

    Prompt and completion bodies are intentionally absent.  The gateway stores
    only stable digests, bounded status metadata, and a redacted error code so
    provider fallback can be evaluated without turning the reasoning ledger
    into a secret or target-content sink.
    """

    schema_version: Literal["1.0"] = "1.0"
    call_id: str = Field(default_factory=lambda: f"mcall_{uuid.uuid4().hex}")
    cycle_id: str = ""
    session_id: str = ""
    job_id: str = ""
    model_id: str = ""
    provider: str = ""
    prompt_version: str = ""
    attempt_number: int = Field(default=1, ge=1, le=100)
    fallback_index: int = Field(default=0, ge=0, le=100)
    status: Literal["succeeded", "failed", "skipped"] = "failed"
    input_digest: str = ""
    output_digest: str = ""
    latency_ms: float = Field(default=0.0, ge=0.0)
    error_code: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("model_id", "provider", "prompt_version", "error_code", mode="before")
    @classmethod
    def redact_call_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:500]


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
    raw = "" if output is None else output if isinstance(output, str) else json.dumps(output, default=str)
    raw = str(raw or "")
    if not raw.strip():
        return ToolResultV1(
            tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
            tool_name=tool_name,
            category="legacy",
            target=target,
            inputs_redacted={},
            status="failed",
            summary=f"{tool_name} returned no output.",
            observations=[],
            errors=[ToolErrorV1(
                code="legacy_empty_output",
                message="Legacy tool returned empty output.",
                retryable=True,
            )],
            legacy_source=True,
        )
    # Legacy tools historically used several human-facing cancellation
    # prefixes (including Indonesian ``DIBATALKAN`` and a leading tool label).
    # Treat every explicit cancellation marker as terminal cancellation before
    # the generic text adapter can turn it into a successful observation.
    cancellation_match = re.match(
        r"^\s*(?:(?:[A-Za-z][A-Za-z _-]{0,80})\s+)?"
        r"(?:DIBATALKAN|CANCELLED|CANCELED)\b\s*:?(.*)$",
        raw,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if cancellation_match:
        reason = cancellation_match.group(1).strip() or "Legacy tool reported cancellation."
        return ToolResultV1(
            tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
            tool_name=tool_name,
            category="legacy",
            target=target,
            inputs_redacted={},
            status="cancelled",
            summary=redact(raw)[:4000],
            observations=[],
            errors=[ToolErrorV1(
                code="legacy_cancelled",
                message=redact(reason)[:2000],
                retryable=False,
            )],
            metrics={"termination_reason": "legacy_cancellation_marker"},
            legacy_source=True,
        )

    def legacy_failure_retryable(message: str) -> bool:
        lowered = str(message or "").lower()
        return any(
            marker in lowered
            for marker in (
                "timeout",
                "timed out",
                "connection",
                "disconnected",
                "proxy",
                "temporarily",
                "try again",
            )
        )

    if raw.lstrip().lower().startswith("error:"):
        retryable = legacy_failure_retryable(raw)
        failure_code = "legacy_tool_timeout" if "timeout" in raw.lower() or "timed out" in raw.lower() else (
            "legacy_tool_transport_error" if retryable else "external_command_failed"
        )
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
                code=failure_code,
                message=redact(raw)[:2000],
                retryable=retryable,
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
    parsed_status = str(parsed.get("status", "")).upper() if isinstance(parsed, dict) else ""
    parsed_error = parsed.get("error") if isinstance(parsed, dict) else None
    parsed_errors = parsed.get("errors") if isinstance(parsed, dict) else None
    parsed_ok = parsed.get("ok") if isinstance(parsed, dict) else None
    parsed_success = parsed.get("success") if isinstance(parsed, dict) else None
    if parsed_status in {"SKIPPED", "CANCELLED", "CANCELED"}:
        parsed_reason = str(
            parsed.get("skip_reason")
            or parsed.get("reason")
            or parsed.get("error")
            or ""
        ).strip()
        if parsed_status == "SKIPPED":
            if not parsed_reason:
                return ToolResultV1(
                    tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
                    tool_name=tool_name,
                    category="legacy",
                    target=target,
                    inputs_redacted={},
                    status="partial",
                    summary=redact(raw)[:4000],
                    observations=[],
                    errors=[ToolErrorV1(
                        code="legacy_skip_reason_missing",
                        message="Legacy tool reported SKIPPED without a reason.",
                        retryable=False,
                    )],
                    metrics={
                        "status_normalized_from": "skipped",
                        "skip_class": "legacy",
                    },
                    legacy_source=True,
                )
            return ToolResultV1(
                tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
                tool_name=tool_name,
                category="legacy",
                target=target,
                inputs_redacted={},
                status="skipped",
                summary=redact(raw)[:4000],
                observations=[],
                metrics={
                    "skip_reason": redact(parsed_reason)[:1000],
                    "skip_class": str(parsed.get("skip_class") or "legacy"),
                },
                legacy_source=True,
            )
        return ToolResultV1(
            tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
            tool_name=tool_name,
            category="legacy",
            target=target,
            inputs_redacted={},
            status="cancelled",
            summary=redact(raw)[:4000],
            observations=[],
            errors=[ToolErrorV1(
                code="legacy_cancelled",
                message=redact(parsed_reason or "Legacy tool reported cancellation.")[:2000],
                retryable=False,
            )],
            legacy_source=True,
        )
    if raw.strip().upper() == "SKIPPED":
        return ToolResultV1(
            tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
            tool_name=tool_name,
            category="legacy",
            target=target,
            inputs_redacted={},
            status="partial",
            summary=raw,
            observations=[],
            errors=[ToolErrorV1(
                code="legacy_skip_reason_missing",
                message="Legacy tool reported SKIPPED without a reason.",
                retryable=False,
            )],
            metrics={"status_normalized_from": "skipped", "skip_class": "legacy"},
            legacy_source=True,
        )
    if raw.strip().upper() in {"CANCELLED", "CANCELED"}:
        return ToolResultV1(
            tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
            tool_name=tool_name,
            category="legacy",
            target=target,
            inputs_redacted={},
            status="cancelled",
            summary=raw,
            observations=[],
            errors=[ToolErrorV1(
                code="legacy_cancelled",
                message="Legacy tool reported cancellation.",
                retryable=False,
            )],
            legacy_source=True,
        )
    explicit_failure = (
        isinstance(parsed, dict)
        and (
            parsed_status in {"ERROR", "FAILED", "FAILURE"}
            or bool(parsed_error)
            or bool(parsed_errors)
            or parsed_ok is False
            or parsed_success is False
        )
    )
    if explicit_failure:
        partial = parsed_status == "PARTIAL"
        message = redact(str(
            parsed.get("error")
            or parsed.get("reason")
            or parsed_errors
            or "Legacy tool reported an explicit failure."
        ))[:2000]
        retryable = partial or legacy_failure_retryable(message)
        return ToolResultV1(
            tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
            tool_name=tool_name,
            category="legacy",
            target=target,
            inputs_redacted={},
            status="partial" if partial else "failed",
            summary=redact(raw)[:4000],
            observations=[],
            errors=[ToolErrorV1(
                code="legacy_tool_partial" if partial else "legacy_tool_failed",
                message=message,
                retryable=retryable,
            )],
            legacy_source=True,
        )

    output_observation = ObservationV1(
        role="external" if isinstance(parsed, dict) and parsed.get("external_tool") else "test",
        kind="legacy_output",
        summary=redact(raw)[:2000],
        target_url=target,
        response_excerpt=redact(raw)[:8000],
        metadata={"legacy": True, "legacy_source_tool": tool_name},
    )
    observations = [output_observation]
    candidates: List[CandidateFindingV1] = []
    access_control_legacy = {
        "scan_idor", "idor_uuid_scanner",
        "IDOR Scanner", "IDOR UUID Scanner",
    }
    # The old ID mutation scanners do not possess identity/ownership/control
    # evidence. Their output remains historical observation only; the
    # authorization replay engine is the sole finding producer. The broader
    # access-control scanner still emits useful forced-browsing and method
    # observations, so those remain candidates that require validation.
    legacy_candidate_allowed = tool_name not in access_control_legacy

    finding_buckets = {
        "forced_browsing", "http_method_bypass", "mass_assignment",
        "path_traversal_advanced", "parameter_tampering", "cookie_issues",
        "session_entropy", "active_mixed_content", "passive_mixed_content",
        "vulnerable_endpoints", "unkeyed_headers", "summary",
    }

    def bucket_has_signal(value: Dict[str, Any]) -> bool:
        return any(
            value.get(key) not in (None, "", [], {})
            for key in (
                "url", "endpoint", "status", "size", "content_type", "severity",
                "detail", "issue", "recommendation", "method", "parameter",
                "cookie_name", "origin_sent", "acao_header", "test", "engine",
                "expected", "injected_params",
            )
        )

    def collect_candidate_items(value: Any, bucket: str = "") -> List[tuple[Dict[str, Any], str]]:
        """Extract only explicit finding-shaped records from legacy schemas.

        Older tools do not share one response envelope.  For example,
        misconfiguration scanners group explicit records under severity
        buckets, while client-side scanners nest them below
        ``findings.vulnerabilities``.  Preserve those records as candidates,
        but never promote free-form warnings or low-level issue details.
        """
        collected: List[tuple[Dict[str, Any], str]] = []
        if isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict):
                    # A record is candidate-shaped only when it has a
                    # vulnerability identity.  ``issue`` alone is often a
                    # diagnostic detail (for example one cookie flag).
                    if any(entry.get(key) for key in ("title", "name", "type", "vuln_type")):
                        collected.append((entry, bucket))
                    else:
                        collected.extend(collect_candidate_items(entry, bucket))
            return collected
        if not isinstance(value, dict):
            return collected

        for key in ("findings", "vulnerabilities", "candidates", "summary"):
            if key in value:
                collected.extend(collect_candidate_items(value.get(key), key))
        if isinstance(value.get("finding"), dict):
            collected.extend(collect_candidate_items([value["finding"]], "finding"))
        # Misconfiguration scanners use severity buckets rather than a
        # ``findings`` array.  Their entries are explicit typed records and
        # therefore safe to retain as unvalidated candidates.
        for key in ("critical", "high", "medium", "low", "info"):
            if isinstance(value.get(key), list):
                collected.extend(collect_candidate_items(value[key], key))
        # A few legacy tools expose a flat ``issues`` list.  Only records with
        # an explicit type/name/title are admitted; prose remains observation
        # only and cannot create a finding.
        if isinstance(value.get("issues"), list):
            collected.extend(collect_candidate_items(value["issues"], "issues"))
        # Several older detectors use a tool-specific list name instead of the
        # shared ``vulnerabilities`` envelope (for example
        # ``xss_vulnerabilities`` and ``lfi_vulnerabilities``).  These are
        # still explicit candidate records when the list entries carry a
        # vulnerability identity.  Do not admit similarly named scalars or
        # arbitrary diagnostic dictionaries.
        for key, nested in value.items():
            normalized_key = str(key).lower()
            if not isinstance(nested, list):
                continue
            if not (
                normalized_key.endswith("_vulnerabilities")
                or normalized_key.endswith("_findings")
                or normalized_key in finding_buckets
            ):
                continue
            if normalized_key in {"vulnerabilities", "findings", "candidates", "summary"}:
                continue
            for entry in nested:
                if isinstance(entry, dict) and not any(
                    entry.get(identity) for identity in ("title", "name", "type", "vuln_type")
                ) and normalized_key in finding_buckets and bucket_has_signal(entry):
                    # Some scanners use a typed bucket but omit the repeated
                    # vulnerability name from each record. Preserve the
                    # observation and synthesize the type below; do not infer
                    # validation from the bucket or severity label.
                    collected.append(({**entry, "_legacy_bucket_record": True}, str(key)))
                elif isinstance(entry, dict):
                    collected.extend(collect_candidate_items([entry], str(key)))
        return collected

    def text_signal_items(raw_text: str) -> List[tuple[Dict[str, Any], str]]:
        """Adapt explicit scanner count blocks, never arbitrary prose.

        Older scanners print blocks such as ``[MEDIUM] 6 finding(s)`` and
        bullets but do not return JSON. This is structured enough to preserve
        as unvalidated candidates; a sentence like ``SQL Injection suspected``
        intentionally remains observation-only.
        """
        header_pattern = re.compile(
            r"\[(?:[^\]]*?\s)?(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO)\]"
            r"\s*(?P<count>\d+)\s*(?P<label>[A-Za-z][A-Za-z0-9 /&_:-]*?)?\s*finding\(s\)",
            re.IGNORECASE,
        )
        matches = list(header_pattern.finditer(raw_text))
        if not matches:
            return []
        inferred_type = "Legacy scanner signal"
        tool_lower = tool_name.lower()
        if "cors" in tool_lower or "cors" in raw_text.lower():
            inferred_type = "CORS Misconfiguration"
        elif "ssti" in tool_lower or "template" in raw_text.lower():
            inferred_type = "Server-Side Template Injection"
        elif "xxe" in tool_lower:
            inferred_type = "XML External Entity"
        elif "oauth" in tool_lower:
            inferred_type = "OAuth Flow Weakness"
        elif "nuclei" in tool_lower:
            inferred_type = "Nuclei Detection Signal"

        items: List[tuple[Dict[str, Any], str]] = []
        for index, match in enumerate(matches):
            severity = match.group("severity").upper()
            count = max(0, int(match.group("count")))
            label = str(match.group("label") or "").strip(" :-")
            block_end = matches[index + 1].start() if index + 1 < len(matches) else len(raw_text)
            block = raw_text[match.end():block_end]
            bullets = list(re.finditer(r"^\s*(?:▸|•|[-*])\s*(.+)$", block, re.MULTILINE))
            if not bullets:
                bullets = [None] * min(count, 1)
            for item_index, bullet in enumerate(bullets[:count] or [None]):
                title = bullet.group(1).strip() if bullet else f"{label or inferred_type} signal {item_index + 1}"
                detail = ""
                if bullet:
                    next_start = bullets[item_index + 1].start() if item_index + 1 < len(bullets) else len(block)
                    detail_lines = [line.strip() for line in block[bullet.end():next_start].splitlines() if line.strip()]
                    detail = " ".join(detail_lines[:4])[:1800]
                items.append(({
                    "title": title,
                    "type": label or inferred_type,
                    "severity": severity,
                    "parameter": title,
                    "detail": detail or f"{count} explicit scanner signal(s) in a legacy text block.",
                    "_legacy_text_heuristic": True,
                    "_legacy_signal_count": count,
                }, f"text:{severity.lower()}"))
        return items

    if isinstance(parsed, dict):
        items = collect_candidate_items(parsed)
    elif isinstance(parsed, list):
        items = collect_candidate_items(parsed)
    else:
        items = []
    items.extend(text_signal_items(raw))

    def bucket_title(bucket: str, item: Dict[str, Any]) -> str:
        labels = {
            "forced_browsing": "Forced browsing candidate",
            "http_method_bypass": "HTTP method authorization candidate",
            "mass_assignment": "Mass assignment candidate",
            "path_traversal_advanced": "Path traversal candidate",
            "parameter_tampering": "Parameter tampering candidate",
            "cookie_issues": "Session cookie security candidate",
            "session_entropy": "Weak session entropy candidate",
            "active_mixed_content": "Active mixed content candidate",
            "passive_mixed_content": "Passive mixed content candidate",
            "vulnerable_endpoints": "Vulnerable endpoint candidate",
            "unkeyed_headers": "Web cache poisoning candidate",
        }
        return labels.get(bucket.lower(), "Legacy scanner candidate")

    def bucket_type(bucket: str, item: Dict[str, Any]) -> str:
        labels = {
            "forced_browsing": "Broken Access Control",
            "http_method_bypass": "Broken Function Level Authorization",
            "mass_assignment": "Mass Assignment",
            "path_traversal_advanced": "Path Traversal",
            "parameter_tampering": "Parameter Tampering",
            "cookie_issues": "Insecure Cookie",
            "session_entropy": "Weak Session Management",
            "active_mixed_content": "Active Mixed Content",
            "passive_mixed_content": "Passive Mixed Content",
            "vulnerable_endpoints": "Potential Deserialization",
            "unkeyed_headers": "Web Cache Poisoning",
        }
        return labels.get(bucket.lower(), "Legacy Scanner Signal")

    def legacy_subtype(vuln_type: str) -> str:
        """Map common legacy labels to a typed, validator-facing subtype."""
        value = str(vuln_type or "").lower().replace("-", "_")
        mappings = (
            (("missing security header",), "missing_security_header"),
            (("weak security header",), "weak_security_header"),
            (("server version disclosure",), "server_version_disclosure"),
            (("sensitive file", ".env file", ".git folder"), "sensitive_file_exposure"),
            (("backup file",), "backup_file_exposure"),
            (("exposed admin", "admin panel"), "admin_panel_exposure"),
            (("debug mode", "verbose error", "stack trace"), "debug_disclosure"),
            (("clickjacking",), "clickjacking"),
            (("insecure cookie", "cookie flag"), "insecure_cookie"),
            (("cors",), "cors"),
            (("open redirect", "redirect"), "open_redirect"),
            (("blind sqli", "sql injection", "sqli"), "sqli"),
            (("xss", "cross-site scripting"), "xss"),
            (("lfi", "path traversal", "file inclusion"), "lfi"),
            (("ssrf", "xxe", "oob"), "ssrf"),
            (("ssti", "template injection"), "ssti"),
        )
        for needles, subtype in mappings:
            if any(needle in value for needle in needles):
                return subtype
        return "legacy_unknown"

    def safe_legacy_metadata(item: Dict[str, Any], title: str, vuln_type: str, legacy_bucket: str) -> Dict[str, Any]:
        """Preserve bounded typed evidence without copying secrets/payloads."""
        metadata: Dict[str, Any] = {
            "legacy_item": True,
            "legacy_bucket": legacy_bucket,
            "legacy_source_tool": tool_name,
            "finding_type": vuln_type,
            "subtype": str(item.get("subtype") or legacy_subtype(vuln_type)),
        }
        blocked = {
            "authorization", "cookie", "cookies", "password", "token", "secret",
            "payload", "true_payload", "false_payload", "poc_html",
        }
        # These fields are useful for deterministic validation and are bounded
        # before they enter the model/session contract. Raw bodies remain in
        # the redacted observation excerpt, never in candidate metadata.
        allowed = {
            "detail", "evidence", "confidence", "confidence_score", "sqlmap_confirmed",
            "semantic_test", "confirmed", "score", "note",
            "db_type", "injection_details", "test_url", "url", "target_url",
            "status_code", "response_status", "found_status", "baseline_status",
            "response_length", "baseline_length", "content_length", "location",
            "redirect_url", "reflection_context", "marker_executed", "script_executed",
            "header", "header_name", "header_value", "expected", "server_header",
            "x_powered_by", "x_frame_options", "csp_frame_ancestors", "vulnerable",
            "retrieved", "content_verified", "content_type", "correlation_id",
            "oob_correlation_id", "target_attributed", "stale_callback", "parameter",
            "param", "field_class", "server_state_changed", "privileged_field_changed",
            "reproduced", "arithmetic_result_match", "marker_seen", "timing_samples",
            "stored", "cleanup_verified", "stored_retrieval_clean_session", "escaped_control",
            "header_weak", "accessible", "verbose_error", "insecure", "cookie_insecure",
            "attacker_origin_accepted", "credentialed_request_allowed", "sensitive_response_readable",
            "origin_control_rejected",
        }
        for key, value in item.items():
            normalized = str(key).strip().lower()
            if normalized in blocked or normalized not in allowed:
                continue
            if isinstance(value, (str, int, float, bool)):
                rendered = str(value)
                if len(rendered) <= 1200:
                    metadata[normalized] = redact(value)
            elif normalized in {"injection_details", "timing_samples"}:
                # Keep only bounded numeric/typed structures needed by a
                # validator; arbitrary nested target data is not promoted.
                encoded = json.dumps(value, default=str)
                if len(encoded) <= 3000:
                    metadata[normalized] = redact(value)

        # Older misconfiguration records encode the header state in prose.
        # Turn that explicit scanner assertion into typed evidence so the
        # policy can validate the observation without guessing from severity.
        detail = str(item.get("detail") or "")
        header_match = re.search(r"Header ['\"]([^'\"]+)['\"]", detail, re.I)
        if header_match:
            metadata.setdefault("header_name", header_match.group(1))
        if "not present" in detail.lower() or "missing" in detail.lower():
            metadata.setdefault("header_present", False)
        elif "present but not properly configured" in detail.lower():
            metadata.setdefault("header_present", True)
            metadata.setdefault("header_weak", True)
        if "server:" in detail.lower() and "server_header" not in metadata:
            metadata["server_header"] = detail[:1000]
        if "access-control-allow-origin" in detail.lower():
            metadata.setdefault("attacker_origin_accepted", True)
        return redact(metadata)

    seen_fingerprints: set[str] = set()
    for item, legacy_bucket in items:
        if not isinstance(item, dict):
            continue
        legacy_bucket_name = str(legacy_bucket or "")
        title = (
            item.get("title") or item.get("name") or item.get("type")
            or bucket_title(legacy_bucket_name, item)
        )
        vuln_type = (
            item.get("vuln_type") or item.get("type") or item.get("category")
            or bucket_type(legacy_bucket_name, item)
        )
        if not title or not vuln_type:
            continue
        item_metadata = safe_legacy_metadata(item, str(title), str(vuln_type), legacy_bucket)
        if item.get("_legacy_text_heuristic"):
            item_metadata.update({
                "legacy_text_heuristic": True,
                "validation_required": True,
                "signal_count": int(item.get("_legacy_signal_count") or 0),
            })
        if item.get("_legacy_bucket_record"):
            item_metadata.update({
                "synthetic_finding_type": True,
                "validation_required": True,
            })
        item_target = str(
            item.get("url") or item.get("target_url") or item.get("endpoint")
            or item.get("test_url") or target
        )
        if item_target.startswith("/") and target:
            item_target = target.rstrip("/") + item_target
        detail = str(
            item.get("detail") or item.get("evidence") or item.get("issue")
            or item.get("response_preview") or item.get("note") or title
        )
        severity_fallback = {
            "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
            "low": "LOW", "info": "INFO",
        }.get(legacy_bucket_name.lower().replace("text:", ""), "MEDIUM")
        confidence_value = item.get("confidence_score")
        if confidence_value in (None, ""):
            confidence_value = 0.35 if item.get("_legacy_text_heuristic") else 0.45
        finding_observation = ObservationV1(
            role="test",
            kind="legacy_finding",
            summary=f"{tool_name}: {title}",
            target_url=item_target,
            status_code=(
                item.get("status_code")
                or item.get("response_status")
                or item.get("found_status")
            ),
            response_excerpt=redact(detail)[:3000],
            metadata=item_metadata,
        )
        observations.append(finding_observation)
        validation_observation_ids = []
        validation_rows = item.get("validation_evidence") or item.get("evidence_observations") or []
        if isinstance(validation_rows, list):
            for row in validation_rows:
                if not isinstance(row, dict):
                    continue
                allowed_roles = {"baseline", "test", "negative_control", "positive_control", "reproduction", "oob", "browser", "external"}
                role = str(row.get("role") or "test")
                if role not in allowed_roles:
                    continue
                row_target = str(row.get("target_url") or item_target)
                row_metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
                row_metadata = redact({"legacy_validation_evidence": True, "legacy_source_tool": tool_name, **row_metadata})
                validation_observation = ObservationV1(
                    role=role,
                    kind=str(row.get("kind") or "http_exchange"),
                    summary=redact(str(row.get("summary") or detail))[:2000],
                    target_url=row_target,
                    method=str(row.get("method") or item.get("method") or "GET"),
                    request_excerpt=redact(str(row.get("request_excerpt") or ""))[:2000],
                    response_excerpt=redact(str(row.get("response_excerpt") or row.get("body") or detail))[:6000],
                    status_code=(row.get("status_code") or row.get("response_status")),
                    response_time_ms=row.get("response_time_ms"),
                    payload_hash=str(row.get("payload_hash") or ""),
                    metadata=row_metadata,
                )
                observations.append(validation_observation)
                validation_observation_ids.append(validation_observation.observation_id)
        candidate = CandidateFindingV1(
            title=str(title),
            vuln_type=str(vuln_type),
            severity=str(item.get("severity") or severity_fallback).upper(),
            target_url=item_target,
            method=str(item.get("method", "GET")),
            parameter=str(item.get("parameter") or item.get("param") or ""),
            injection_point=str(item.get("injection_point") or ""),
            confidence_score=float(confidence_value or 0.45),
            confidence_reasons=[
                "Legacy scanner signal preserved as an unvalidated candidate.",
                "Deterministic validation and reproducible evidence are required.",
            ],
            observation_ids=[finding_observation.observation_id, *validation_observation_ids],
            remediation=str(item.get("remediation") or item.get("recommendation") or ""),
            metadata=item_metadata,
        )
        if legacy_candidate_allowed:
            candidate.ensure_fingerprint()
            if candidate.fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(candidate.fingerprint)
            candidates.append(candidate)

    result_status = "partial" if parsed_status == "PARTIAL" else "succeeded"
    errors = []
    if result_status == "partial":
        errors.append(ToolErrorV1(
            code="legacy_tool_partial",
            message=redact(str(parsed_error or parsed.get("reason") or "Legacy tool returned a partial result."))[:2000],
            retryable=True,
        ))
    return ToolResultV1(
        tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
        tool_name=tool_name,
        category="legacy",
        target=target,
        inputs_redacted={},
        status=result_status,
        summary=redact(raw)[:4000],
        observations=observations,
        candidate_findings=candidates,
        errors=errors,
        legacy_source=True,
    )

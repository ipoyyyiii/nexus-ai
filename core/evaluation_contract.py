"""Versioned contracts for the Stage 6 evaluation and release gate.

Evaluation records are deliberately separate from findings.  A benchmark can
fail because a safety, recovery, or evidence invariant was violated without
creating a production finding.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.redact import redact


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def content_digest(value: Any, length: int = 64) -> str:
    payload = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


EvaluationStatus = Literal["queued", "running", "succeeded", "failed", "cancelled"]
CaseStatus = Literal["passed", "failed", "inconclusive", "skipped"]
ExpectedOutcome = Literal["validated", "inconclusive", "disproven", "blocked", "succeeded"]
GateDecision = Literal["ready", "not_ready", "pending"]


class EvaluationModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class EvaluationAssertionV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    assertion_id: str = Field(default_factory=lambda: f"assert_{uuid.uuid4().hex}")
    name: str
    passed: bool
    expected: Any = None
    actual: Any = None
    evidence_ids: List[str] = Field(default_factory=list)
    reason: str = ""

    def model_post_init(self, __context: Any) -> None:
        self.expected = redact(self.expected)
        self.actual = redact(self.actual)
        self.reason = redact(self.reason)[:2000]


class EvaluationCaseV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    case_id: str
    suite_id: str
    version: str = "1.0"
    name: str
    category: str
    fixture_id: str
    expected_outcome: ExpectedOutcome = "succeeded"
    tags: List[str] = Field(default_factory=list)
    required_assertions: List[str] = Field(default_factory=list)
    deterministic: bool = True
    model_required: bool = False
    budget: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=120, ge=1, le=7200)
    seed: int = 0
    evidence_roles: List[str] = Field(default_factory=list)
    cleanup_assertion: str = ""
    identity_requirements: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("name", "category", "fixture_id", mode="before")
    @classmethod
    def clean_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:500]

    def fingerprint(self) -> str:
        return content_digest(self.model_dump(mode="json"), 40)


class EvaluationSuiteV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    suite_id: str
    name: str
    version: str = "1.0"
    description: str = ""
    mode: Literal["deterministic", "model", "hybrid"] = "deterministic"
    cases: List[EvaluationCaseV1] = Field(default_factory=list)
    manifest_digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.description = redact(self.description)[:2000]
        if not self.manifest_digest:
            self.manifest_digest = content_digest(
                [case.model_dump(mode="json") for case in self.cases], 64
            )


class EvaluationCaseResultV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    case_run_id: str = Field(default_factory=lambda: f"case_run_{uuid.uuid4().hex}")
    run_id: str
    case_id: str
    fixture_id: str
    status: CaseStatus
    expected_outcome: ExpectedOutcome
    actual_outcome: str = ""
    assertions: List[EvaluationAssertionV1] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    evidence_ids: List[str] = Field(default_factory=list)
    error_code: str = ""
    error_message: str = ""
    started_at: str = Field(default_factory=now_iso)
    finished_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.metrics = redact(self.metrics)
        self.error_message = redact(self.error_message)[:2000]


class EvaluationRunV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(default_factory=lambda: f"eval_{uuid.uuid4().hex}")
    suite_id: str
    suite_version: str
    status: EvaluationStatus = "queued"
    mode: Literal["deterministic", "model", "hybrid"] = "deterministic"
    session_id: str = ""
    job_id: str = ""
    commit_sha: str = ""
    config_digest: str = ""
    config_snapshot: Dict[str, Any] = Field(default_factory=dict)
    image_digest: str = ""
    model_id: str = ""
    prompt_version: str = ""
    policy_versions: Dict[str, str] = Field(default_factory=dict)
    fixture_digest: str = ""
    random_seed: int = 0
    resource_budget: Dict[str, Any] = Field(default_factory=dict)
    tool_contract_version: str = "1.0"
    validator_version: str = "1.0"
    trial_number: int = 1
    trial_count: int = 1
    totals: Dict[str, int] = Field(default_factory=dict)
    metrics: Dict[str, float] = Field(default_factory=dict)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error_code: str = ""
    error_message: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.policy_versions = redact(self.policy_versions)
        self.totals = redact(self.totals)
        self.metrics = redact(self.metrics)
        self.config_snapshot = redact(self.config_snapshot)
        self.resource_budget = redact(self.resource_budget)
        self.error_message = redact(self.error_message)[:2000]


class MetricSnapshotV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    metric_id: str
    run_id: str
    category: str
    value: float
    unit: str = "ratio"
    direction: Literal["higher_is_better", "lower_is_better", "informational"] = "informational"
    threshold: Optional[float] = None
    passed: Optional[bool] = None
    dimensions: Dict[str, str] = Field(default_factory=dict)


class EvaluationBaselineV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    baseline_id: str = Field(default_factory=lambda: f"baseline_{uuid.uuid4().hex}")
    suite_id: str
    suite_version: str
    run_id: str
    commit_sha: str = ""
    config_digest: str = ""
    metrics: Dict[str, float] = Field(default_factory=dict)
    accepted_at: str = Field(default_factory=now_iso)


class ReleaseGateDecisionV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    decision_id: str = Field(default_factory=lambda: f"gate_{uuid.uuid4().hex}")
    run_id: str
    suite_id: str
    suite_version: str
    decision: GateDecision
    hard_gates: List[EvaluationAssertionV1] = Field(default_factory=list)
    metrics: Dict[str, float] = Field(default_factory=dict)
    reviewer_id: str = ""
    review_reason: str = ""
    signature: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.review_reason = redact(self.review_reason)[:2000]

# --- Stage 8 benchmark contracts ---


# --- Stage 8 benchmark contracts ---

FailureTaxonomy = Literal[
    "missed_detection",
    "false_positive",
    "inconclusive",
    "blocked_by_safety",
    "execution_error",
    "cleanup_error",
    "recovery_error",
    "infra_error",
    "unsupported_capability",
    "validator_gap",
]
CapabilityTier = Literal["required", "diagnostic", "unsupported"]
TargetSurface = Literal["http", "api", "browser", "oob", "cli", "persistence", "safety"]
TrialTerminalStatus = Literal["queued", "running", "succeeded", "failed", "cancelled", "partial"]


class EvaluationScenarioV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    scenario_id: str
    suite_id: str
    suite_version: str = "1.0"
    vulnerability_family: str
    subtype: str = ""
    variant: Literal["gold_positive", "gold_negative", "noisy_control", "missing_control", "reproduction", "clean_reproduction", "recovery", "recovery_cleanup"]
    target_surface: TargetSurface
    endpoint_class: str = "fixture"
    auth_state: str = "anonymous"
    identity: str = "none"
    tenant: str = "none"
    expected_outcome: ExpectedOutcome = "inconclusive"
    capability_tier: CapabilityTier = "diagnostic"
    required_evidence_roles: List[str] = Field(default_factory=list)
    cleanup_required: bool = False
    cleanup_assertion: str = ""
    fixture_id: str
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def fingerprint(self) -> str:
        return content_digest(self.model_dump(mode="json"), 48)


class EvaluationTrialV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    trial_id: str = Field(default_factory=lambda: f"trial_{uuid.uuid4().hex}")
    run_id: str
    scenario_id: str = ""
    trial_number: int = Field(default=1, ge=1)
    trial_count: int = Field(default=1, ge=1)
    seed: int = 0
    mode: Literal["deterministic", "model", "hybrid"] = "deterministic"
    model_id: str = ""
    provider: str = ""
    prompt_version: str = ""
    config_digest: str = ""
    policy_versions: Dict[str, str] = Field(default_factory=dict)
    status: TrialTerminalStatus = "queued"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_ms: float = 0.0
    token_usage: Dict[str, int] = Field(default_factory=dict)
    request_count: int = 0
    budget_usage: Dict[str, Any] = Field(default_factory=dict)
    action_count: int = 0
    valid_action_count: int = 0
    failure_taxonomy: Optional[FailureTaxonomy] = None
    error_code: str = ""
    error_message: str = ""
    evidence_ids: List[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        self.policy_versions = redact(self.policy_versions)
        self.token_usage = redact(self.token_usage)
        self.budget_usage = redact(self.budget_usage)
        self.error_message = redact(self.error_message)[:2000]


class CoverageSampleV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    sample_id: str = Field(default_factory=lambda: f"coverage_{uuid.uuid4().hex}")
    run_id: str
    trial_id: str = ""
    scenario_id: str
    tool_name: str = ""
    category: str
    vulnerability_family: str
    subtype: str = ""
    endpoint_class: str = "fixture"
    identity: str = "none"
    tenant: str = "none"
    surface: TargetSurface = "api"
    browser_or_api: Literal["browser", "api", "both", "none"] = "api"
    validator_policy: str = ""
    outcome: str
    failure_taxonomy: Optional[FailureTaxonomy] = None
    capability_tier: CapabilityTier = "diagnostic"
    evidence_complete: bool = False
    reproducible: bool = False
    cleanup_verified: Optional[bool] = None
    dimensions: Dict[str, str] = Field(default_factory=dict)
    metrics: Dict[str, float] = Field(default_factory=dict)


class BenchmarkMatrixV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    matrix_id: str = Field(default_factory=lambda: f"matrix_{uuid.uuid4().hex}")
    suite_id: str
    suite_version: str
    suite_digest: str
    fixture_digest: str
    scenario_count: int = 0
    required_count: int = 0
    diagnostic_count: int = 0
    dimension_coverage: Dict[str, List[str]] = Field(default_factory=dict)
    unsupported_capabilities: List[str] = Field(default_factory=list)
    baseline_id: str = ""
    created_at: str = Field(default_factory=now_iso)


class ModelActionV1(EvaluationModel):
    schema_version: Literal["1.0"] = "1.0"
    action_id: str = Field(default_factory=lambda: f"model_action_{uuid.uuid4().hex}")
    trial_id: str
    action: Literal["observe", "hypothesize", "run_read_only", "request_approval", "stop"]
    tool_name: str = ""
    endpoint_ref: str = ""
    evidence_roles: List[str] = Field(default_factory=list)
    rationale: str = ""
    valid: bool = False
    rejection_reason: str = ""

    def model_post_init(self, __context: Any) -> None:
        self.rationale = redact(self.rationale)[:2000]
        self.rejection_reason = redact(self.rejection_reason)[:1000]

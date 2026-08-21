"""Versioned contracts for stateful browser workflows and business logic tests."""

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


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _fingerprint(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:40]


class BrowserContract(BaseModel):
    model_config = ConfigDict(extra="ignore")


BrowserWorkflowStatus = Literal["draft", "published", "archived"]
BrowserRunStatus = Literal[
    "planned", "approval_required", "approved", "running", "succeeded",
    "partial", "failed", "cancelled", "stale",
]
BrowserRunRole = Literal["discovery", "baseline", "test", "negative_control", "positive_control", "reproduction", "cleanup"]
BrowserAction = Literal[
    "navigate", "click", "fill", "select", "check", "submit",
    "wait_for", "assert", "extract", "screenshot",
]
SideEffectClass = Literal["read", "mutation", "unknown"]
InvariantStatus = Literal["draft", "active", "rejected", "retired"]
InvariantDecision = Literal["satisfied", "violated", "inconclusive"]


class SemanticLocator(BrowserContract):
    role: str = ""
    name: str = ""
    label: str = ""
    test_id: str = ""
    text: str = ""
    css: str = ""
    nth: int = 0
    frame: List[str] = Field(default_factory=list)
    expected_count: int = 1

    @field_validator("expected_count")
    @classmethod
    def valid_expected_count(cls, value: int) -> int:
        return max(1, min(10, int(value)))

    @field_validator("role", "name", "label", "test_id", "text", "css", mode="before")
    @classmethod
    def redact_locator(cls, value: Any) -> str:
        return redact(str(value or ""))[:500]


class WorkflowCondition(BrowserContract):
    kind: Literal[
        "url_matches", "element_present", "element_visible", "text_contains",
        "status_code", "network_seen", "entity_field", "state_hash",
    ]
    value: Any = None
    locator: Optional[SemanticLocator] = None
    negate: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def safe_dict(self) -> Dict[str, Any]:
        return redact(self.model_dump())


class InputBinding(BrowserContract):
    name: str
    source: Literal["operator", "generated_marker", "entity_field", "secret_ref", "constant"] = "operator"
    value_redacted: str = ""
    secret_ref: str = ""
    entity_id: str = ""
    field: str = ""
    required: bool = True

    @field_validator("name", "value_redacted", "secret_ref", "entity_id", "field", mode="before")
    @classmethod
    def clean_binding(cls, value: Any) -> str:
        return redact(str(value or ""))[:500]


class BrowserStepV1(BrowserContract):
    step_id: str = Field(default_factory=lambda: _id("bstep"))
    ordinal: int = 0
    action: BrowserAction
    locator: Optional[SemanticLocator] = None
    input_bindings: Dict[str, InputBinding] = Field(default_factory=dict)
    args: Dict[str, Any] = Field(default_factory=dict)
    preconditions: List[WorkflowCondition] = Field(default_factory=list)
    postconditions: List[WorkflowCondition] = Field(default_factory=list)
    side_effect_class: SideEffectClass = "read"
    risk: Literal["low", "medium", "high", "critical"] = "low"
    timeout_ms: int = 15000
    retry_limit: int = 1
    cleanup_step_id: str = ""
    description: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timeout_ms")
    @classmethod
    def bounded_timeout(cls, value: int) -> int:
        return max(500, min(120000, int(value)))

    @field_validator("retry_limit")
    @classmethod
    def bounded_retry(cls, value: int) -> int:
        return max(0, min(3, int(value)))

    @field_validator("description", mode="before")
    @classmethod
    def redact_description(cls, value: Any) -> str:
        return redact(str(value or ""))[:1000]

    def is_mutation(self) -> bool:
        return self.side_effect_class == "mutation" or self.action == "submit" or self.action == "check"


class BrowserWorkflowV1(BrowserContract):
    workflow_id: str = Field(default_factory=lambda: _id("bwf"))
    session_id: str = ""
    name: str
    origin: str
    goal: str = ""
    status: BrowserWorkflowStatus = "draft"
    version: int = 1
    identity_requirements: List[str] = Field(default_factory=list)
    input_schema: Dict[str, Any] = Field(default_factory=dict)
    steps: List[BrowserStepV1] = Field(default_factory=list)
    preconditions: List[WorkflowCondition] = Field(default_factory=list)
    postconditions: List[WorkflowCondition] = Field(default_factory=list)
    cleanup_step_ids: List[str] = Field(default_factory=list)
    source_observation_ids: List[str] = Field(default_factory=list)
    fingerprint: str = ""
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)

    @field_validator("name", "origin", "goal", mode="before")
    @classmethod
    def redact_workflow_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def ensure_fingerprint(self) -> "BrowserWorkflowV1":
        if not self.fingerprint:
            self.fingerprint = _fingerprint({
                "origin": self.origin.lower().rstrip("/"),
                "name": self.name.lower(),
                "steps": [
                    {
                        "action": step.action,
                        "locator": step.locator.model_dump() if step.locator else {},
                        "ordinal": step.ordinal,
                    }
                    for step in self.steps
                ],
            })
        return self

    def has_mutations(self) -> bool:
        return any(step.is_mutation() for step in self.steps)

    def has_cleanup(self) -> bool:
        return bool(self.cleanup_step_ids) or any(step.cleanup_step_id for step in self.steps if step.is_mutation())


class BrowserStateSnapshotV1(BrowserContract):
    snapshot_id: str = Field(default_factory=lambda: _id("bsnap"))
    session_id: str = ""
    run_id: str = ""
    step_run_id: str = ""
    url: str = ""
    title: str = ""
    dom_hash: str = ""
    visible_landmarks: List[str] = Field(default_factory=list)
    network_fingerprints: List[Dict[str, Any]] = Field(default_factory=list)
    storage_metadata: Dict[str, Any] = Field(default_factory=dict)
    entity_state: List[Dict[str, Any]] = Field(default_factory=list)
    artifact_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("visible_landmarks", "network_fingerprints", "storage_metadata", "entity_state", mode="before")
    @classmethod
    def redact_snapshot(cls, value: Any) -> Any:
        return redact(value)


class BrowserStepRunV1(BrowserContract):
    step_run_id: str = Field(default_factory=lambda: _id("bsrun"))
    run_id: str
    step_id: str
    ordinal: int = 0
    status: Literal["planned", "running", "succeeded", "failed", "skipped", "stale", "cancelled"] = "planned"
    before_snapshot_id: str = ""
    after_snapshot_id: str = ""
    observation_ids: List[str] = Field(default_factory=list)
    artifact_ids: List[str] = Field(default_factory=list)
    error_code: str = ""
    error_message: str = ""
    attempts: int = 0
    started_at: str = Field(default_factory=now_iso)
    finished_at: Optional[str] = None

    @field_validator("error_message", mode="before")
    @classmethod
    def redact_error(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class BrowserRunV1(BrowserContract):
    run_id: str = Field(default_factory=lambda: _id("brun"))
    session_id: str
    workflow_id: str
    workflow_version: int = 1
    identity_id: str = ""
    auth_context_id: str = ""
    role: BrowserRunRole = "baseline"
    status: BrowserRunStatus = "planned"
    current_step: int = 0
    total_steps: int = 0
    approval_digest: str = ""
    approval_expires_at: Optional[str] = None
    parent_run_id: str = ""
    checkpoint_snapshot_id: str = ""
    state_digest: str = ""
    cleanup_refs: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    error_code: str = ""
    error_message: str = ""
    started_at: str = Field(default_factory=now_iso)
    finished_at: Optional[str] = None

    @field_validator("error_message", mode="before")
    @classmethod
    def redact_run_error(cls, value: Any) -> str:
        return redact(str(value or ""))


class BusinessEntityV1(BrowserContract):
    entity_id: str = Field(default_factory=lambda: _id("entity"))
    session_id: str
    entity_type: str
    fingerprint: str = ""
    locator_redacted: Any = None
    owner_identity_id: str = ""
    tenant_label: str = ""
    fields_redacted: Dict[str, Any] = Field(default_factory=dict)
    source_snapshot_ids: List[str] = Field(default_factory=list)
    source_observation_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)

    def ensure_fingerprint(self) -> "BusinessEntityV1":
        if not self.fingerprint:
            self.fingerprint = _fingerprint({
                "type": self.entity_type,
                "locator": self.locator_redacted,
                "owner": self.owner_identity_id,
                "tenant": self.tenant_label,
            })
        return self


class BusinessStateTransitionV1(BrowserContract):
    transition_id: str = Field(default_factory=lambda: _id("transition"))
    session_id: str
    entity_id: str = ""
    action: str
    before_snapshot_id: str
    after_snapshot_id: str
    before_state: Dict[str, Any] = Field(default_factory=dict)
    after_state: Dict[str, Any] = Field(default_factory=dict)
    expected: str = ""
    observation_ids: List[str] = Field(default_factory=list)
    artifact_ids: List[str] = Field(default_factory=list)
    side_effects: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)


class BusinessInvariantV1(BrowserContract):
    invariant_id: str = Field(default_factory=lambda: _id("inv"))
    session_id: str
    name: str
    rule_type: str
    rule_version: str = "1.0"
    status: InvariantStatus = "draft"
    source: Literal["heuristic", "llm_draft", "operator", "program_spec", "observation"] = "llm_draft"
    rule: Dict[str, Any] = Field(default_factory=dict)
    required_workflow_ids: List[str] = Field(default_factory=list)
    required_identity_ids: List[str] = Field(default_factory=list)
    source_observation_ids: List[str] = Field(default_factory=list)
    revision: int = 1
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)

    @field_validator("name", mode="before")
    @classmethod
    def redact_invariant_name(cls, value: Any) -> str:
        return redact(str(value or ""))[:1000]


class InvariantCheckV1(BrowserContract):
    name: str
    passed: bool
    details: Dict[str, Any] = Field(default_factory=dict)
    evidence_ids: List[str] = Field(default_factory=list)

    @field_validator("details", mode="before")
    @classmethod
    def redact_check_details(cls, value: Any) -> Dict[str, Any]:
        return redact(value)


class InvariantEvaluationV1(BrowserContract):
    evaluation_id: str = Field(default_factory=lambda: _id("eval"))
    invariant_id: str
    invariant_version: str = "1.0"
    decision: InvariantDecision = "inconclusive"
    score: float = 0.0
    reason: str = ""
    checks: List[InvariantCheckV1] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    run_ids: List[str] = Field(default_factory=list)
    candidate_id: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("score")
    @classmethod
    def score_range(cls, value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    @field_validator("reason", mode="before")
    @classmethod
    def redact_reason(cls, value: Any) -> str:
        return redact(str(value or ""))


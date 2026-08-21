"""Versioned contracts for durable execution and safety decisions.

The contracts in this module are deliberately independent from FastAPI and
Supabase.  They are the boundary shared by the API control plane, workers,
tests, and future queue implementations.
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


def stable_digest(value: Any, length: int = 64) -> str:
    payload = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


ExecutionStatus = Literal[
    "queued", "leased", "running", "waiting_approval", "waiting_auth",
    "waiting_continue", "retry_wait", "recovery_required", "cancelling",
    "succeeded", "partial", "failed", "cancelled", "dead_lettered",
]
AttemptStatus = Literal[
    "leased", "running", "waiting", "succeeded", "partial", "failed",
    "cancelled", "lost", "recovery_required",
]
JobRisk = Literal["read_only", "low", "medium", "high", "critical"]
SafetyDecision = Literal["allowed", "blocked", "throttled"]


class ExecutionModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ResourceBudgetV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    max_requests: int = 20_000
    max_download_bytes: int = 512 * 1024 * 1024
    max_response_bytes: int = 2 * 1024 * 1024
    max_upload_bytes: int = 10 * 1024 * 1024
    max_credential_attempts: int = 10
    max_wall_seconds: int = 120 * 60
    requests_per_second: float = 2.0
    burst: int = 4
    browser_concurrency: int = 1
    cli_concurrency: int = 1
    race_concurrency: int = 8

    @field_validator("max_requests", "max_download_bytes", "max_response_bytes", "max_upload_bytes", "max_credential_attempts", "max_wall_seconds", "burst", "browser_concurrency", "cli_concurrency", "race_concurrency")
    @classmethod
    def positive_limits(cls, value: int) -> int:
        return max(1, int(value))

    @field_validator("requests_per_second")
    @classmethod
    def positive_rate(cls, value: float) -> float:
        return max(0.01, float(value))


class ExecutionJobV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    job_id: str = Field(default_factory=lambda: f"job_{uuid.uuid4().hex}")
    session_id: str
    job_type: str = "pentest"
    queue_name: str = "general"
    target: str = ""
    goal: str = ""
    payload_redacted: Dict[str, Any] = Field(default_factory=dict)
    config_snapshot: Dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = ""
    risk: JobRisk = "read_only"
    approval_ref: str = ""
    budget: ResourceBudgetV1 = Field(default_factory=ResourceBudgetV1)
    priority: int = 100
    status: ExecutionStatus = "queued"
    attempt_count: int = 0
    max_attempts: int = 3
    available_at: str = Field(default_factory=now_iso)
    deadline_at: Optional[str] = None
    cancel_requested_at: Optional[str] = None
    checkpoint_id: str = ""
    parent_job_id: str = ""
    result_ref: str = ""
    error_code: str = ""
    error_message: str = ""
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.payload_redacted = redact(self.payload_redacted)
        self.config_snapshot = redact(self.config_snapshot)
        self.goal = redact(self.goal)[:4000]
        self.error_message = redact(self.error_message)[:2000]
        if not self.idempotency_key:
            self.idempotency_key = stable_digest({
                "session_id": self.session_id,
                "type": self.job_type,
                "target": self.target,
                "payload": self.payload_redacted,
            }, 40)


class ExecutionAttemptV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    attempt_id: str = Field(default_factory=lambda: f"attempt_{uuid.uuid4().hex}")
    job_id: str
    attempt_number: int = 1
    worker_id: str = ""
    lease_token: str = ""
    lease_expires_at: Optional[str] = None
    heartbeat_at: Optional[str] = None
    status: AttemptStatus = "leased"
    checkpoint_id: str = ""
    tool_run_ids: List[str] = Field(default_factory=list)
    browser_run_ids: List[str] = Field(default_factory=list)
    resource_usage: Dict[str, Any] = Field(default_factory=dict)
    retry_class: str = "none"
    error_code: str = ""
    error_message: str = ""
    started_at: str = Field(default_factory=now_iso)
    finished_at: Optional[str] = None

    @field_validator("error_message", mode="before")
    @classmethod
    def redact_error(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class JobCheckpointV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    checkpoint_id: str = Field(default_factory=lambda: f"checkpoint_{uuid.uuid4().hex}")
    job_id: str
    attempt_id: str = ""
    ordinal: int = 0
    phase: str = ""
    cursor: Dict[str, Any] = Field(default_factory=dict)
    state_digest: str = ""
    side_effects: List[Dict[str, Any]] = Field(default_factory=list)
    cleanup_refs: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.cursor = redact(self.cursor)
        self.side_effects = redact(self.side_effects)
        self.cleanup_refs = redact(self.cleanup_refs)


class ExecutionEventV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: str = Field(default_factory=lambda: f"event_{uuid.uuid4().hex}")
    sequence: Optional[int] = None
    session_id: str
    job_id: str = ""
    attempt_id: str = ""
    event_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.payload = redact(self.payload)


class SafetyDecisionV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    decision_id: str = Field(default_factory=lambda: f"safety_{uuid.uuid4().hex}")
    session_id: str
    job_id: str = ""
    attempt_id: str = ""
    tool_run_id: str = ""
    action: str
    target: str = ""
    decision: SafetyDecision
    reason_code: str
    policy_version: str = "1.0"
    identity_id: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.metadata = redact(self.metadata)


class SandboxRunV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    sandbox_run_id: str = Field(default_factory=lambda: f"sandbox_{uuid.uuid4().hex}")
    session_id: str
    job_id: str = ""
    attempt_id: str = ""
    tool_run_id: str = ""
    command_id: str
    argv_redacted: List[str] = Field(default_factory=list)
    status: str = "running"
    exit_code: Optional[int] = None
    timed_out: bool = False
    sha256: str = ""
    output_bytes: int = 0
    error_code: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.argv_redacted = [str(redact(item))[:500] for item in self.argv_redacted]


class CleanupTaskV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    cleanup_id: str = Field(default_factory=lambda: f"cleanup_{uuid.uuid4().hex}")
    session_id: str
    job_id: str = ""
    handler_id: str
    context_redacted: Dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"
    attempts: int = 0
    verification: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.context_redacted = redact(self.context_redacted)


class RaceExperimentV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    experiment_id: str = Field(default_factory=lambda: f"race_{uuid.uuid4().hex}")
    session_id: str
    job_id: str = ""
    target: str
    method: str = "POST"
    request_template_id: str = ""
    workflow_id: str = ""
    identity_id: str = ""
    invariant_id: str = ""
    mutation_digest: str = ""
    approval_digest: str = ""
    schedule: List[int] = Field(default_factory=lambda: [2, 4, 8])
    baseline_samples: int = 3
    control_samples: int = 3
    status: str = "planned"
    cleanup_refs: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("schedule")
    @classmethod
    def bounded_schedule(cls, value: List[int]) -> List[int]:
        values = sorted({max(1, min(8, int(item))) for item in value})
        return values or [2, 4, 8]


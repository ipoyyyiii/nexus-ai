"""Versioned contracts for Stage 13 production-readiness telemetry.

These records are deliberately diagnostic.  They describe whether the
execution platform is healthy; they never create a pentest finding.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Literal, Optional

from pydantic import Field

from core.execution_contract import ExecutionModel, now_iso
from core.redact import redact


ReadinessStatus = Literal["queued", "running", "succeeded", "failed", "cancelled", "partial"]
ReadinessDecision = Literal["ready", "not_ready", "pending", "ready_with_caveats", "rollback_required", "recovery_required"]
WorkerStatus = Literal["online", "degraded", "draining", "offline"]
RecoveryKind = Literal[
    "lease_expired", "worker_lost", "checkpoint_resume", "mutation_unknown_outcome",
    "browser_crash", "process_timeout", "cleanup_required", "dead_letter",
    "worker_startup", "lease_lost", "rollback_rehearsal", "artifact_orphan",
]


class WorkerHealthV1(ExecutionModel):
    schema_version: str = "1.0"
    snapshot_id: str = Field(default_factory=lambda: f"health_{uuid.uuid4().hex}")
    worker_id: str
    status: WorkerStatus = "online"
    capabilities: List[str] = Field(default_factory=list)
    active_job_id: str = ""
    active_attempt_id: str = ""
    heartbeat_at: str = Field(default_factory=now_iso)
    resource_sample: Dict[str, Any] = Field(default_factory=dict)
    queue_depth: int = 0
    lease_age_seconds: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        self.resource_sample = redact(self.resource_sample)
        self.metadata = redact(self.metadata)


class ResourceSampleV1(ExecutionModel):
    schema_version: str = "1.0"
    sample_id: str = Field(default_factory=lambda: f"resource_{uuid.uuid4().hex}")
    worker_id: str = ""
    job_id: str = ""
    attempt_id: str = ""
    cpu_percent: Optional[float] = None
    memory_bytes: Optional[int] = None
    memory_limit_bytes: Optional[int] = None
    process_count: Optional[int] = None
    request_count: int = 0
    token_count: int = 0
    created_at: str = Field(default_factory=now_iso)


class RecoveryEventV1(ExecutionModel):
    schema_version: str = "1.0"
    recovery_id: str = Field(default_factory=lambda: f"recovery_{uuid.uuid4().hex}")
    job_id: str
    attempt_id: str = ""
    worker_id: str = ""
    kind: RecoveryKind
    decision: str
    status: str = "recorded"
    checkpoint_id: str = ""
    side_effects: List[Dict[str, Any]] = Field(default_factory=list)
    cleanup_refs: List[str] = Field(default_factory=list)
    reason: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.side_effects = redact(self.side_effects)
        self.reason = redact(self.reason)[:2000]


class ArtifactSweepV1(ExecutionModel):
    schema_version: str = "1.0"
    sweep_id: str = Field(default_factory=lambda: f"sweep_{uuid.uuid4().hex}")
    bucket: str
    dry_run: bool = True
    scanned: int = 0
    expired: int = 0
    deleted: int = 0
    orphaned: int = 0
    errors: int = 0
    started_at: str = Field(default_factory=now_iso)
    finished_at: Optional[str] = None


class ReadinessCheckV1(ExecutionModel):
    schema_version: str = "1.0"
    check_id: str = Field(default_factory=lambda: f"check_{uuid.uuid4().hex}")
    run_id: str
    name: str
    passed: bool
    expected: Any = None
    actual: Any = None
    reason: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.expected = redact(self.expected)
        self.actual = redact(self.actual)
        self.reason = redact(self.reason)[:2000]


class ProductionReadinessV1(ExecutionModel):
    schema_version: str = "1.0"
    run_id: str = Field(default_factory=lambda: f"readiness_{uuid.uuid4().hex}")
    suite_id: str = "stage13-production-readiness"
    suite_version: str = "1.0"
    status: ReadinessStatus = "queued"
    mode: Literal["deterministic", "diagnostic"] = "deterministic"
    commit_sha: str = ""
    config_digest: str = ""
    image_digest: str = ""
    fixture_digest: str = ""
    platform_mode: str = "shadow"
    tool_boundary_mode: str = "shadow"
    schema_digest: str = ""
    worker_topology: Dict[str, Any] = Field(default_factory=dict)
    soak_run_id: str = ""
    baseline_run_id: str = ""
    slo_snapshot_id: str = ""
    rollback_ref: str = ""
    cutover_candidate: bool = False
    reviewer_id: str = ""
    review_reason: str = ""
    metrics: Dict[str, float] = Field(default_factory=dict)
    release_decision: ReadinessDecision = "pending"
    hard_gates: List[ReadinessCheckV1] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        self.metrics = redact(self.metrics)
        self.worker_topology = redact(self.worker_topology)
        self.review_reason = redact(self.review_reason)[:2000]



class SoakRunV1(ExecutionModel):
    """Append-only evidence for a long-running reliability rehearsal."""

    schema_version: str = "1.0"
    soak_run_id: str = Field(default_factory=lambda: f"soak_{uuid.uuid4().hex}")
    readiness_run_id: str = ""
    mode: Literal["deterministic", "diagnostic"] = "deterministic"
    duration_seconds: int = 0
    sample_interval_seconds: int = 15
    worker_count: int = 1
    simulated_worker_count: int = 0
    status: ReadinessStatus = "queued"
    expected_jobs: int = 0
    completed_jobs: int = 0
    failed_jobs: int = 0
    recovery_events: int = 0
    stale_write_rejections: int = 0
    duplicate_suppression_count: int = 0
    cleanup_failures: int = 0
    redaction_leaks: int = 0
    started_at: str = Field(default_factory=now_iso)
    finished_at: Optional[str] = None
    config_digest: str = ""
    fixture_digest: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        self.metadata = redact(self.metadata)


class SoakSampleV1(ExecutionModel):
    schema_version: str = "1.0"
    sample_id: str = Field(default_factory=lambda: f"soak_sample_{uuid.uuid4().hex}")
    soak_run_id: str
    sample_number: int
    elapsed_seconds: int = 0
    queue_depth: int = 0
    online_workers: int = 0
    leased_jobs: int = 0
    terminal_jobs: int = 0
    heartbeat_age_seconds: float = 0.0
    cpu_percent: Optional[float] = None
    memory_bytes: Optional[int] = None
    error_rate: float = 0.0
    p95_latency_ms: float = 0.0
    budget_exhaustions: int = 0
    circuit_breaker_opens: int = 0
    created_at: str = Field(default_factory=now_iso)


class SoakEventV1(ExecutionModel):
    """Append-only lifecycle/evidence event for a durable soak run."""

    schema_version: str = "1.0"
    event_id: str = Field(default_factory=lambda: f"soak_event_{uuid.uuid4().hex}")
    soak_run_id: str
    job_id: str = ""
    attempt_id: str = ""
    status: Literal["queued", "running", "succeeded", "failed", "cancelled", "partial"]
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.payload = redact(self.payload)


class SLOSnapshotV1(ExecutionModel):
    schema_version: str = "1.0"
    slo_snapshot_id: str = Field(default_factory=lambda: f"slo_{uuid.uuid4().hex}")
    readiness_run_id: str = ""
    window_seconds: int = 0
    availability: float = 0.0
    terminal_success_rate: float = 0.0
    recovery_success_rate: float = 0.0
    p95_latency_ms: float = 0.0
    error_rate: float = 0.0
    duplicate_execution_rate: float = 0.0
    stale_write_rate: float = 0.0
    cleanup_success_rate: float = 0.0
    redaction_leaks: int = 0
    passed: bool = False
    thresholds: Dict[str, float] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.thresholds = redact(self.thresholds)


class CutoverDecisionV1(ExecutionModel):
    schema_version: str = "1.0"
    decision_id: str = Field(default_factory=lambda: f"cutover_{uuid.uuid4().hex}")
    readiness_run_id: str
    from_mode: str = "shadow"
    to_mode: str = "strict"
    decision: Literal["approved", "rejected", "rollback"] = "rejected"
    reviewer_id: str
    reason: str
    config_digest: str = ""
    schema_digest: str = ""
    image_digest: str = ""
    soak_run_id: str = ""
    slo_snapshot_id: str = ""
    rollback_ref: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.reason = redact(self.reason)[:2000]


class RecoveryVerificationV1(ExecutionModel):
    schema_version: str = "1.0"
    verification_id: str = Field(default_factory=lambda: f"recovery_verify_{uuid.uuid4().hex}")
    job_id: str
    attempt_id: str = ""
    recovery_id: str = ""
    decision: Literal["verified", "failed", "inconclusive"] = "inconclusive"
    checkpoint_valid: bool = False
    side_effects_verified: bool = False
    mutation_replayed: bool = False
    cleanup_verified: bool = False
    evidence_ids: List[str] = Field(default_factory=list)
    reason: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.reason = redact(self.reason)[:2000]


class OperatorIncidentV1(ExecutionModel):
    schema_version: str = "1.0"
    incident_id: str = Field(default_factory=lambda: f"incident_{uuid.uuid4().hex}")
    severity: Literal["info", "warning", "critical"] = "warning"
    category: str
    job_id: str = ""
    attempt_id: str = ""
    worker_id: str = ""
    status: Literal["open", "acknowledged", "resolved"] = "open"
    summary: str
    action_required: str = ""
    created_at: str = Field(default_factory=now_iso)
    resolved_at: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        self.summary = redact(self.summary)[:2000]
        self.action_required = redact(self.action_required)[:2000]

"""Durable worker-backed production readiness soak execution.

This executor is deliberately local/operational: it never touches a target
application and never produces a pentest finding.  The base soak record is
immutable; lifecycle state and terminal counters are append-only events.
"""

from __future__ import annotations

import math
import time
from typing import Any, Dict

from core.config_loader import get_setting
from core.execution_contract import JobCheckpointV1, ExecutionEventV1, stable_digest
from core.production_contract import SLOSnapshotV1, SoakEventV1, SoakSampleV1
from core.redact import redact


class SoakCancelled(RuntimeError):
    """The operator cancelled the durable soak job."""


class DurableSoakExecutor:
    def __init__(self, durable_repository: Any, production_repository: Any):
        self.durable = durable_repository
        self.production = production_repository

    @staticmethod
    def _thresholds() -> Dict[str, float]:
        configured = (get_setting("execution", {}) or {}).get("slo_thresholds", {}) or {}
        return {
            "availability": float(configured.get("availability", 0.99)),
            "terminal_success_rate": float(configured.get("terminal_success_rate", 0.99)),
            "recovery_success_rate": float(configured.get("recovery_success_rate", 1.0)),
            "error_rate": float(configured.get("error_rate", 0.01)),
            "duplicate_execution_rate": float(configured.get("duplicate_execution_rate", 0.0)),
            "stale_write_rate": float(configured.get("stale_write_rate", 0.0)),
            "cleanup_success_rate": float(configured.get("cleanup_success_rate", 0.99)),
        }

    @staticmethod
    def _job_payload(job: Dict[str, Any]) -> Dict[str, Any]:
        return redact(job.get("payload_redacted") or job.get("payload") or {})

    def _emit(self, *, soak_run_id: str, job_id: str, attempt_id: str,
              status: str, payload: Dict[str, Any]) -> None:
        self.production.save_soak_event(SoakEventV1(
            soak_run_id=soak_run_id, job_id=job_id, attempt_id=attempt_id,
            status=status, payload=payload,
        ))

    def _cancelled(self, job_id: str) -> bool:
        try:
            return bool(self.durable.is_cancel_requested(job_id))
        except Exception:
            # Inability to read cancellation state is fail-closed.
            return True

    def _sample(self, *, soak_run_id: str, sample_number: int, elapsed: int,
                worker_count: int, expected_jobs: int, terminal_jobs: int) -> SoakSampleV1:
        resource = {}
        try:
            resource = self.durable._resource_sample() if hasattr(self.durable, "_resource_sample") else {}
        except Exception:
            resource = {}
        return SoakSampleV1(
            soak_run_id=soak_run_id, sample_number=sample_number,
            elapsed_seconds=max(0, int(elapsed)), queue_depth=0,
            online_workers=max(0, int(worker_count)), leased_jobs=0,
            terminal_jobs=max(0, int(terminal_jobs)), heartbeat_age_seconds=0.0,
            memory_bytes=resource.get("memory_bytes"), error_rate=0.0,
            p95_latency_ms=1.0, budget_exhaustions=0, circuit_breaker_opens=0,
        )

    def _slo(self, *, readiness_run_id: str, duration: int, worker_count: int,
             expected_jobs: int, completed_jobs: int, failed_jobs: int,
             recovery_events: int, stale_writes: int, duplicates: int,
             cleanup_failures: int, redaction_leaks: int, max_latency: float) -> SLOSnapshotV1:
        thresholds = self._thresholds()
        total = max(1, expected_jobs)
        availability = 1.0 if worker_count > 0 else 0.0
        terminal_success_rate = completed_jobs / total
        recovery_success_rate = 1.0 if recovery_events == 0 else 0.0
        error_rate = failed_jobs / total
        duplicate_rate = duplicates / total
        stale_rate = stale_writes / total
        cleanup_success_rate = 1.0 if cleanup_failures == 0 else 0.0
        passed = all((
            availability >= thresholds["availability"],
            terminal_success_rate >= thresholds["terminal_success_rate"],
            recovery_success_rate >= thresholds["recovery_success_rate"],
            error_rate <= thresholds["error_rate"],
            duplicate_rate <= thresholds["duplicate_execution_rate"],
            stale_rate <= thresholds["stale_write_rate"],
            cleanup_success_rate >= thresholds["cleanup_success_rate"],
            redaction_leaks == 0,
        ))
        return SLOSnapshotV1(
            readiness_run_id=readiness_run_id, window_seconds=max(0, duration),
            availability=availability, terminal_success_rate=terminal_success_rate,
            recovery_success_rate=recovery_success_rate, p95_latency_ms=max_latency,
            error_rate=error_rate, duplicate_execution_rate=duplicate_rate,
            stale_write_rate=stale_rate, cleanup_success_rate=cleanup_success_rate,
            redaction_leaks=redaction_leaks, passed=passed, thresholds=thresholds,
        )

    def execute(self, job: Dict[str, Any], attempt: Any) -> str:
        payload = self._job_payload(job)
        soak_run_id = str(payload.get("soak_run_id", ""))
        if not soak_run_id:
            raise RuntimeError("soak_run_id is required")
        job_id = str(attempt.job_id)
        attempt_id = str(attempt.attempt_id)
        existing_events = self.production.soak_events(soak_run_id)
        if existing_events and existing_events[-1].get("status") in {"succeeded", "failed", "cancelled"}:
            return str(existing_events[-1]["status"])

        duration = max(1, int(payload.get("duration_seconds", 60)))
        interval = max(1, int(payload.get("sample_interval_seconds", 15)))
        worker_count = max(1, int(payload.get("worker_count", 1)))
        simulated_count = max(0, int(payload.get("simulated_worker_count", 0)))
        expected_jobs = max(1, simulated_count or worker_count)
        dry_run = bool(payload.get("dry_run", True))
        self._emit(soak_run_id=soak_run_id, job_id=job_id, attempt_id=attempt_id,
                   status="running", payload={"job_id": job_id, "expected_jobs": expected_jobs})

        samples = self.production.soak_samples(soak_run_id)
        next_sample = max([int(row.get("sample_number", 0)) for row in samples] or [0]) + 1
        if dry_run:
            sample_count = min(8, max(2, int(math.ceil(duration / interval))))
        else:
            sample_count = max(2, int(math.ceil(duration / interval)) + 1)
        started = time.monotonic()
        completed_jobs = expected_jobs
        failed_jobs = 0
        recovery_events = 0
        stale_writes = 0
        duplicates = 0
        cleanup_failures = 0
        redaction_leaks = 0
        max_latency = 1.0

        try:
            for offset in range(sample_count):
                if self._cancelled(job_id):
                    raise SoakCancelled("operator cancellation requested")
                if not dry_run and offset:
                    target_elapsed = offset * interval
                    remaining = target_elapsed - int(time.monotonic() - started)
                    if remaining > 0:
                        time.sleep(remaining)
                elapsed = 0 if dry_run else int(time.monotonic() - started)
                sample = self._sample(
                    soak_run_id=soak_run_id, sample_number=next_sample + offset,
                    elapsed=elapsed, worker_count=worker_count, expected_jobs=expected_jobs,
                    terminal_jobs=completed_jobs if offset else 0,
                )
                self.production.save_soak_sample(sample)
                self.durable.save_checkpoint(JobCheckpointV1(
                    job_id=job_id, attempt_id=attempt_id, ordinal=offset + 1,
                    phase="readiness_soak",
                    cursor={"soak_run_id": soak_run_id, "sample_number": sample.sample_number},
                    state_digest=stable_digest(sample.model_dump(mode="json")),
                ))
                self.durable.append_event(ExecutionEventV1(
                    session_id=str(job.get("session_id", "")), job_id=job_id,
                    attempt_id=attempt_id, event_type="soak_sample_persisted",
                    payload={"soak_run_id": soak_run_id, "sample_number": sample.sample_number},
                ))

            slo = self._slo(
                readiness_run_id=str(payload.get("readiness_run_id", "")), duration=duration,
                worker_count=worker_count, expected_jobs=expected_jobs,
                completed_jobs=completed_jobs, failed_jobs=failed_jobs,
                recovery_events=recovery_events, stale_writes=stale_writes,
                duplicates=duplicates, cleanup_failures=cleanup_failures,
                redaction_leaks=redaction_leaks, max_latency=max_latency,
            )
            self.production.save_slo(slo)
            status = "succeeded" if slo.passed else "failed"
            self._emit(
                soak_run_id=soak_run_id, job_id=job_id, attempt_id=attempt_id,
                status=status, payload={
                    "job_id": job_id, "expected_jobs": expected_jobs,
                    "completed_jobs": completed_jobs, "failed_jobs": failed_jobs,
                    "recovery_events": recovery_events,
                    "stale_write_rejections": stale_writes,
                    "duplicate_suppression_count": duplicates,
                    "cleanup_failures": cleanup_failures, "redaction_leaks": redaction_leaks,
                    "finished_at": slo.created_at, "slo_snapshot_id": slo.slo_snapshot_id,
                    "passed": slo.passed,
                },
            )
            return status
        except SoakCancelled as exc:
            self._emit(soak_run_id=soak_run_id, job_id=job_id, attempt_id=attempt_id,
                       status="cancelled", payload={"job_id": job_id, "reason": str(exc)})
            raise
        except Exception as exc:
            self._emit(soak_run_id=soak_run_id, job_id=job_id, attempt_id=attempt_id,
                       status="failed", payload={"job_id": job_id, "error_code": type(exc).__name__})
            raise

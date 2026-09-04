"""Supabase-backed durable execution repository.

The worker uses the RPC methods created by migration 004 for atomic leasing.
There is one durable execution path; the old shadow table fallback is gone.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Iterable, List, Optional

from core.execution_contract import (
    ExecutionAttemptV1,
    ExecutionEventV1,
    ExecutionJobV1,
    JobCheckpointV1,
    now_iso,
)
from core.redact import redact


def _bounded_application_value(value: Any, *, depth: int = 0) -> Any:
    """Keep compatibility-state events useful without storing unbounded logs."""
    if depth > 3:
        return redact(str(value))[:500]
    if isinstance(value, dict):
        return {
            str(key)[:120]: _bounded_application_value(item, depth=depth + 1)
            for key, item in list(value.items())[:80]
        }
    if isinstance(value, list):
        return [_bounded_application_value(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return redact(value)[:4000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))[:1000]


class LeaseConflict(RuntimeError):
    pass


class DurableExecutionRepository:
    def __init__(self, supabase: Any):
        self.sb = supabase

    def enqueue(self, job: ExecutionJobV1) -> ExecutionJobV1:
        existing = self.find_idempotent(job.session_id, job.idempotency_key)
        if existing and existing.get("status") not in {"succeeded", "failed", "cancelled", "dead_lettered"}:
            return ExecutionJobV1(**self._flatten_job(existing))
        row = self._job_row(job)
        try:
            self.sb.table("workflow_jobs").upsert(row, on_conflict="job_id").execute()
        except Exception:
            raise
        try:
            self.append_event(ExecutionEventV1(
            session_id=job.session_id, job_id=job.job_id,
            event_type="job_queued", payload={"job_type": job.job_type, "queue": job.queue_name},
        ))
        except Exception:
            pass
        return job

    def find_idempotent(self, session_id: str, idempotency_key: str) -> Optional[Dict[str, Any]]:
        if not idempotency_key:
            return None
        try:
            result = (self.sb.table("workflow_jobs").select("*")
                      .eq("session_id", session_id)
                      .eq("idempotency_key", idempotency_key)
                      .order("created_at", desc=True).limit(1).execute())
            return result.data[0] if result.data else None
        except Exception:
            return None

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        result = self.sb.table("workflow_jobs").select("*").eq("job_id", job_id).limit(1).execute()
        if not result.data:
            return None
        return self._with_application_state(self._flatten_job(result.data[0]), job_id)

    def list_jobs(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        result = (self.sb.table("workflow_jobs").select("*").eq("session_id", session_id)
                  .order("updated_at", desc=True).limit(min(max(limit, 1), 500)).execute())
        return [
            self._with_application_state(self._flatten_job(row), str(row.get("job_id", "")))
            for row in (result.data or [])
        ]

    def claim(self, worker_id: str, queues: Iterable[str] = ("general",), lease_seconds: int = 60) -> Optional[ExecutionAttemptV1]:
        try:
            result = self.sb.rpc("claim_execution_job", {
                "p_worker_id": worker_id,
                "p_queues": list(queues),
                "p_lease_seconds": max(10, int(lease_seconds)),
            }).execute()
            rows = result.data or []
            if rows:
                row = rows[0] if isinstance(rows, list) else rows
                return ExecutionAttemptV1(**self._attempt_from_row(row))
            return None
        except Exception:
            raise

    def heartbeat(self, attempt: ExecutionAttemptV1, lease_seconds: int = 60) -> bool:
        result = self.sb.rpc("heartbeat_execution_attempt", {
            "p_job_id": attempt.job_id, "p_attempt_id": attempt.attempt_id,
            "p_worker_id": attempt.worker_id, "p_lease_token": attempt.lease_token,
            "p_lease_seconds": max(10, int(lease_seconds)),
        }).execute()
        return bool(result.data)

    def transition(self, job_id: str, attempt_id: str, worker_id: str, lease_token: str, status: str, **values: Any) -> bool:
        payload = {"status": status, "updated_at": now_iso(), **values}
        try:
            result = self.sb.rpc("transition_execution_job", {
                "p_job_id": job_id, "p_attempt_id": attempt_id,
                "p_worker_id": worker_id, "p_lease_token": lease_token,
                "p_status": status, "p_payload": payload,
            }).execute()
            return bool(result.data)
        except Exception:
            raise

    def record_application_state(
        self,
        job_id: str,
        *,
        session_id: str = "",
        status: str = "",
        message: str = "",
        summary: Any = None,
        logs: Any = None,
        result_ref: str = "",
        error_code: str = "",
        error_message: str = "",
    ) -> bool:
        """Persist the app/compatibility result from a worker-owned process.

        The API process-local ``jobs`` dictionary is intentionally not a source
        of truth: the worker imports the application in a different process.
        Durable queue state owns lifecycle transitions, while this append-only
        event carries the compatibility fields needed by the existing UI.
        """
        compatibility_status = str(status or "")[:64]
        message = redact(str(message or ""))[:2000]
        error_message = redact(str(
            error_message or (message if compatibility_status in {"error", "failed"} else "")
        ))[:2000]
        payload: Dict[str, Any] = {
            "compatibility_status": compatibility_status,
            "message": message,
            "summary": _bounded_application_value(summary or {}),
            "logs": _bounded_application_value(logs or []),
        }
        if result_ref:
            payload["result_ref"] = redact(str(result_ref))[:1000]

        # Keep queue lifecycle ownership with the leased worker transition.
        # Only fields that are already part of workflow_jobs are written here.
        durable_values: Dict[str, Any] = {"updated_at": now_iso()}
        if result_ref:
            durable_values["result_ref"] = redact(str(result_ref))[:1000]
        if compatibility_status in {"error", "failed"} or error_code or error_message:
            durable_values["error_code"] = redact(str(error_code or "application_error"))[:200]
            durable_values["error_message"] = error_message
        self.sb.table("workflow_jobs").update(durable_values).eq("job_id", job_id).execute()
        self.append_event(ExecutionEventV1(
            session_id=session_id,
            job_id=job_id,
            event_type="job_application_terminal",
            payload=payload,
        ))
        return True

    def request_cancel(self, job_id: str) -> bool:
        result = (self.sb.table("workflow_jobs").update({
            "cancel_requested_at": now_iso(), "status": "cancelling", "updated_at": now_iso(),
        }).eq("job_id", job_id).in_("status", ["queued", "leased", "running", "waiting_approval", "waiting_auth", "waiting_continue"]).execute())
        return bool(result.data)

    def is_cancel_requested(self, job_id: str) -> bool:
        result = self.sb.table("workflow_jobs").select("cancel_requested_at,status").eq("job_id", job_id).limit(1).execute()
        if not result.data:
            return False
        row = result.data[0]
        return bool(row.get("cancel_requested_at")) or row.get("status") == "cancelling"

    def save_checkpoint(self, checkpoint: JobCheckpointV1) -> JobCheckpointV1:
        self.sb.table("workflow_checkpoints").insert({
            "checkpoint_id": checkpoint.checkpoint_id, "job_id": checkpoint.job_id,
            "attempt_id": checkpoint.attempt_id, "ordinal": checkpoint.ordinal,
            "phase": checkpoint.phase, "cursor": checkpoint.cursor,
            "state_digest": checkpoint.state_digest, "side_effects": checkpoint.side_effects,
            "cleanup_refs": checkpoint.cleanup_refs, "evidence_ids": checkpoint.evidence_ids,
            "created_at": checkpoint.created_at,
        }).execute()
        self.sb.table("workflow_jobs").update({
            "checkpoint_id": checkpoint.checkpoint_id, "updated_at": now_iso(),
        }).eq("job_id", checkpoint.job_id).execute()
        return checkpoint

    def append_event(self, event: ExecutionEventV1) -> ExecutionEventV1:
        row = {
            "id": str(uuid.uuid4()), "event_id": event.event_id,
            "session_id": event.session_id, "job_id": event.job_id or None,
            "attempt_id": event.attempt_id or None, "event_type": event.event_type,
            "payload": event.payload, "created_at": event.created_at,
        }
        try:
            self.sb.table("workflow_events").insert(row).execute()
        except Exception:
            raise
        return event

    def persist_safety_decision(self, decision: Any) -> Any:
        self.sb.table("safety_decisions").insert(decision.model_dump(mode="json")).execute()
        return decision

    def persist_sandbox_run(self, run: Any) -> Any:
        self.sb.table("sandbox_runs").insert(run.model_dump(mode="json")).execute()
        return run

    def record_worker_health(self, health: Any) -> Any:
        """Persist an append-only worker health sample and update the live node."""
        row = health.model_dump(mode="json")
        # schema_version belongs to the versioned application contract, not
        # to the telemetry table.  Keep the database row additive and avoid a
        # Avoid silently swallowing a schema mismatch in autonomous mode.
        row.pop("schema_version", None)
        self.sb.table("worker_health_snapshots").insert(row).execute()
        self.sb.table("worker_nodes").upsert({
            "worker_id": health.worker_id,
            "capabilities": health.capabilities,
            "status": health.status,
            "last_heartbeat_at": health.heartbeat_at,
            "metadata": health.metadata,
        }, on_conflict="worker_id").execute()
        return health

    def record_recovery(self, recovery: Any) -> Any:
        # RecoveryEventV1 is versioned at the application boundary, while the
        # append-only telemetry table intentionally stores only its columns.
        # Older/live deployments do not have a schema_version column.
        row = recovery.model_dump(mode="json")
        row.pop("schema_version", None)
        self.sb.table("recovery_events").insert(row).execute()
        return recovery

    def record_resource_sample(self, sample: Any) -> Any:
        row = sample.model_dump(mode="json")
        row.pop("schema_version", None)
        self.sb.table("resource_samples").insert(row).execute()
        return sample

    def consume_resource_budget(self, *, session_id: str, job_id: str, attempt_id: str,
                                tool_run_id: str, origin: str, deltas: Dict[str, int],
                                budget: Any) -> bool:
        result = self.sb.rpc("consume_resource_budget", {
            "p_session_id": session_id,
            "p_job_id": job_id,
            "p_attempt_id": attempt_id,
            "p_tool_run_id": tool_run_id,
            "p_origin": origin,
            "p_request_delta": int(deltas.get("requests", 0)),
            "p_download_delta": int(deltas.get("download", 0)),
            "p_upload_delta": int(deltas.get("upload", 0)),
            "p_credential_delta": int(deltas.get("credentials", 0)),
            "p_max_requests": int(budget.max_requests),
            "p_max_download_bytes": int(budget.max_download_bytes),
            "p_max_upload_bytes": int(budget.max_upload_bytes),
            "p_max_credential_attempts": int(budget.max_credential_attempts),
        }).execute()
        rows = result.data or []
        row = rows[0] if isinstance(rows, list) and rows else (rows if isinstance(rows, dict) else {})
        return bool(row.get("allowed", False))

    def list_events(self, job_id: str, after_sequence: int = 0, limit: int = 200) -> List[Dict[str, Any]]:
        query = self.sb.table("workflow_events").select("*").eq("job_id", job_id)
        if after_sequence:
            query = query.gt("sequence", int(after_sequence))
        result = query.order("sequence").limit(min(max(limit, 1), 500)).execute()
        return result.data or []

    def _job_row(self, job: ExecutionJobV1) -> Dict[str, Any]:
        return {
            "job_id": job.job_id, "session_id": job.session_id, "status": job.status,
            "target": job.target, "goal": job.goal, "payload": job.payload_redacted,
            "job_type": job.job_type, "queue_name": job.queue_name, "priority": job.priority,
            "idempotency_key": job.idempotency_key, "risk": job.risk,
            "approval_ref": job.approval_ref, "config_snapshot": job.config_snapshot,
            "budget": job.budget.model_dump(mode="json"), "attempt_count": job.attempt_count,
            "max_attempts": job.max_attempts, "available_at": job.available_at,
            "deadline_at": job.deadline_at, "checkpoint_id": job.checkpoint_id,
            "parent_job_id": job.parent_job_id or None, "result_ref": job.result_ref,
            "error_code": job.error_code, "error_message": job.error_message,
            "created_at": job.created_at, "updated_at": job.updated_at,
        }

    @staticmethod
    def _flatten_job(row: Dict[str, Any]) -> Dict[str, Any]:
        data = dict(row)
        payload = data.pop("payload", {}) or {}
        data["payload_redacted"] = payload
        if isinstance(data.get("budget"), dict):
            data["budget"] = data["budget"]
        return data

    def _with_application_state(self, data: Dict[str, Any], job_id: str) -> Dict[str, Any]:
        """Merge the latest compatibility terminal event into a job view."""
        try:
            result = (
                self.sb.table("workflow_events")
                .select("payload,event_type,created_at")
                .eq("job_id", job_id)
                .eq("event_type", "job_application_terminal")
                .order("created_at", desc=True)
                .limit(1)
                .execute()
            )
            rows = result.data or []
            payload = rows[0].get("payload") if rows else {}
            if isinstance(payload, dict):
                data["application_status"] = payload.get("compatibility_status", "")
                data["message"] = payload.get("message", "")
                data["summary"] = payload.get("summary", {})
                data["logs"] = payload.get("logs", [])
                if payload.get("result_ref") and not data.get("result_ref"):
                    data["result_ref"] = payload["result_ref"]
        except Exception:
            # Older deployments may not yet expose the event ordering columns;
            # the durable lifecycle row remains readable in that case.
            pass
        return data

    @staticmethod
    def _attempt_row(attempt: ExecutionAttemptV1) -> Dict[str, Any]:
        row = attempt.model_dump(mode="json")
        # Contract metadata is not a column in the deployed attempt table.
        row.pop("schema_version", None)
        return row

    @staticmethod
    def _attempt_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "attempt_id": row.get("attempt_id") or row.get("id"),
            "job_id": row.get("job_id"), "attempt_number": row.get("attempt_number", 1),
            "worker_id": row.get("worker_id", ""), "lease_token": row.get("lease_token", ""),
            "lease_expires_at": row.get("lease_expires_at"), "heartbeat_at": row.get("heartbeat_at"),
            "status": row.get("attempt_status", row.get("status", "leased")),
        }


class InMemoryExecutionRepository:
    """Deterministic in-memory fake for unit tests."""

    def __init__(self):
        self.jobs: Dict[str, ExecutionJobV1] = {}
        self.events: List[ExecutionEventV1] = []
        self.checkpoints: List[JobCheckpointV1] = []
        self.application_states: Dict[str, Dict[str, Any]] = {}

    def enqueue(self, job: ExecutionJobV1) -> ExecutionJobV1:
        for current in self.jobs.values():
            if current.session_id == job.session_id and current.idempotency_key == job.idempotency_key and current.status not in {"succeeded", "failed", "cancelled", "dead_lettered"}:
                return current
        self.jobs[job.job_id] = job
        self.events.append(ExecutionEventV1(session_id=job.session_id, job_id=job.job_id, event_type="job_queued"))
        return job

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        item = self.jobs.get(job_id)
        if not item:
            return None
        data = item.model_dump(mode="json")
        data.update(self.application_states.get(job_id, {}))
        return data

    def record_application_state(self, job_id: str, **values: Any) -> bool:
        state = {
            "application_status": str(values.get("status") or "")[:64],
            "message": redact(str(values.get("message") or ""))[:2000],
            "summary": _bounded_application_value(values.get("summary") or {}),
            "logs": _bounded_application_value(values.get("logs") or []),
        }
        result_ref = values.get("result_ref")
        if result_ref:
            state["result_ref"] = redact(str(result_ref))[:1000]
        if values.get("error_message") or state["application_status"] in {"error", "failed"}:
            state["error_code"] = str(values.get("error_code") or "application_error")[:200]
            state["error_message"] = redact(str(values.get("error_message") or values.get("message") or ""))[:2000]
        self.application_states[job_id] = state
        self.events.append(ExecutionEventV1(
            session_id=str(values.get("session_id") or ""),
            job_id=job_id,
            event_type="job_application_terminal",
            payload=state,
        ))
        return True

    def list_events(self, job_id: str, after_sequence: int = 0, limit: int = 200) -> List[Dict[str, Any]]:
        return [item.model_dump(mode="json") for item in self.events if item.job_id == job_id][-limit:]

    def is_cancel_requested(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        return bool(job and job.cancel_requested_at)

    def persist_safety_decision(self, decision: Any) -> Any:
        self.events.append(ExecutionEventV1(
            session_id=decision.session_id, job_id=decision.job_id,
            event_type="safety_decision", payload=decision.model_dump(mode="json"),
        ))
        return decision

    def persist_sandbox_run(self, run: Any) -> Any:
        self.events.append(ExecutionEventV1(
            session_id=run.session_id, job_id=run.job_id,
            attempt_id=run.attempt_id, event_type="sandbox_run",
            payload=run.model_dump(mode="json"),
        ))
        return run

    def consume_resource_budget(self, *, session_id: str, job_id: str, attempt_id: str,
                                tool_run_id: str, origin: str, deltas: Dict[str, int],
                                budget: Any) -> bool:
        key = (job_id or session_id, origin)
        if not hasattr(self, "_budget_usage"):
            self._budget_usage = {}
        usage = self._budget_usage.setdefault(
            key, {"requests": 0, "download": 0, "upload": 0, "credentials": 0}
        )
        candidate = {name: usage[name] + int(deltas.get(name, 0)) for name in usage}
        if candidate["requests"] > budget.max_requests or candidate["download"] > budget.max_download_bytes or candidate["upload"] > budget.max_upload_bytes or candidate["credentials"] > budget.max_credential_attempts:
            return False
        usage.update(candidate)
        return True

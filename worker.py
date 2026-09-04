"""Durable Nexus worker entrypoint.

Run one general worker per container by default.  The raw-network capability
is opt-in and must be enabled by the Docker profile plus the safety policy.
"""

from __future__ import annotations

import argparse
import os
import signal
import threading
import time
import uuid
from typing import Any, Dict

from dotenv import load_dotenv
from supabase import create_client

from core.config_loader import get_setting
from core.durable_execution import DurableExecutionRepository
from core.execution_contract import ExecutionEventV1
from core.production_contract import RecoveryEventV1, ResourceSampleV1, WorkerHealthV1

load_dotenv()


class NexusWorker:
    def __init__(self, repository: DurableExecutionRepository, capabilities: list[str], worker_id: str = ""):
        self.repository = repository
        self.capabilities = capabilities
        self.worker_id = worker_id or f"worker_{uuid.uuid4().hex[:12]}"
        self.stop_requested = False
        self.active_attempt: Any = None
        self.last_health = 0.0

    def preflight(self) -> None:
        """Fail closed before polling when durable primitives are unavailable."""
        if not bool(get_setting("execution", {}).get("startup_preflight", True)):
            return
        try:
            # An empty queue claim validates the deployed RPC signature and
            # database connectivity without leasing a real job.
            result = self.repository.sb.rpc("claim_execution_job", {
                "p_worker_id": self.worker_id,
                "p_queues": ["__stage19_preflight__"],
                "p_lease_seconds": 10,
            }).execute()
            if result.data not in (None, [], {}):
                raise RuntimeError("autonomous preflight unexpectedly claimed a job")
            self.repository.sb.table("workflow_events").select("sequence").limit(1).execute()
            self.repository.sb.table("worker_nodes").select("worker_id").limit(1).execute()
        except Exception as exc:
            raise RuntimeError("autonomous worker preflight failed; durable execution is unavailable") from exc

    def _transition(self, job_id: str, attempt_id: str, worker_id: str, lease_token: str, status: str, **values: Any) -> bool:
        ok = self.repository.transition(job_id, attempt_id, worker_id, lease_token, status, **values)
        if not ok:
            raise RuntimeError("fenced lease rejected terminal transition")
        return ok

    def run_forever(self) -> None:
        poll_seconds = max(0.5, float(get_setting("execution", {}).get("poll_interval_seconds", 2)))
        lease_seconds = max(10, int(get_setting("execution", {}).get("lease_seconds", 60)))
        while not self.stop_requested:
            self._publish_health()
            self._recover_expired()
            attempt = self.repository.claim(self.worker_id, self._queues(), lease_seconds)
            if not attempt:
                time.sleep(poll_seconds)
                continue
            self.active_attempt = attempt
            self._execute_attempt(attempt, lease_seconds)
            self.active_attempt = None

    def _queues(self) -> list[str]:
        queues = ["general"]
        if "raw-network" in self.capabilities:
            queues.append("raw-network")
        return queues

    def _recover_expired(self) -> None:
        execution = get_setting("execution", {}) or {}
        attempts = max(0, min(4, int(execution.get("worker_rpc_retry_attempts", 2))))
        backoff = max(0.05, min(5.0, float(execution.get("worker_rpc_retry_backoff_seconds", 0.5))))
        last_error = None
        for retry_index in range(attempts + 1):
            try:
                result = self.repository.sb.rpc("recover_expired_execution_jobs", {}).execute()
                data = result.data
                recovered = int(data[0] if isinstance(data, list) and data else data or 0)
                if recovered:
                    self.repository.record_recovery(RecoveryEventV1(
                        job_id="system", worker_id=self.worker_id,
                        kind="lease_expired", decision="recovered",
                        reason=f"recovered={recovered}",
                    ))
                return
            except Exception as exc:
                last_error = exc
                if retry_index >= attempts:
                    # An intermittent control-plane disconnect must not kill
                    # the worker. The next poll performs the same bounded
                    # recovery attempt; an actual job remains fenced by its
                    # lease and can be recovered by the database RPC later.
                    return
                time.sleep(backoff * (2 ** retry_index))
        if last_error:  # pragma: no cover - loop always returns on final try
            return

    def _execute_attempt(self, attempt: Any, lease_seconds: int) -> None:
        job = self.repository.get_job(attempt.job_id)
        if not job:
            return
        try:
            self._transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "running")
            self.repository.append_event(ExecutionEventV1(
                session_id=str(job.get("session_id", "")), job_id=attempt.job_id,
                attempt_id=attempt.attempt_id, event_type="attempt_started",
                payload={"worker_id": self.worker_id},
            ))
            heartbeat_stop = threading.Event()
            heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                args=(attempt, lease_seconds, heartbeat_stop),
                daemon=True,
            )
            heartbeat_thread.start()
            try:
                self._dispatch(job, attempt, lease_seconds)
            finally:
                heartbeat_stop.set()
                heartbeat_thread.join(timeout=2)
        except KeyboardInterrupt:
            self.stop_requested = True
            self._transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "cancelled", error_code="worker_stopped")
        except Exception as exc:
            risk = str(job.get("risk", "read_only"))
            retryable = risk == "read_only" and int(getattr(attempt, "attempt_number", 1)) < int(job.get("max_attempts", 3))
            terminal = "retry_wait" if retryable else ("recovery_required" if risk != "read_only" else "failed")
            self._transition(
                attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token,
                terminal, error_code=type(exc).__name__, error_message=str(exc)[:1000],
            )
            self.repository.append_event(ExecutionEventV1(
                session_id=str(job.get("session_id", "")), job_id=attempt.job_id,
                attempt_id=attempt.attempt_id, event_type="attempt_failed",
                payload={"error_code": type(exc).__name__, "retry_class": "transient" if retryable else "unknown"},
            ))

    def _heartbeat_loop(self, attempt: Any, lease_seconds: int, stop: threading.Event) -> None:
        interval = max(2.0, min(float(get_setting("execution", {}).get("heartbeat_seconds", 15)), lease_seconds / 2))
        while not stop.wait(interval):
            try:
                if not self.repository.heartbeat(attempt, lease_seconds):
                    return
                # ``run_forever`` is blocked while a pentest is executing, so
                # publishing health only from its poll loop makes the
                # container look dead during a healthy long-running attempt.
                # The lease heartbeat is the authoritative liveness tick.
                self._write_health_file()
            except Exception:
                # A single transient telemetry/heartbeat disconnect should
                # not terminate the worker process. Keep the health file
                # fresh and let the next heartbeat retry; lease fencing still
                # prevents stale work from committing.
                self._write_health_file()
                continue

    def _publish_health(self) -> None:
        now = time.monotonic()
        interval = max(5.0, float(get_setting("execution", {}).get("worker_health_interval_seconds", 15)))
        self._write_health_file()
        if now - self.last_health < interval:
            return
        self.last_health = now
        attempt = self.active_attempt
        try:
            health = WorkerHealthV1(
                worker_id=self.worker_id,
                status="online" if not self.stop_requested else "draining",
                capabilities=self.capabilities,
                active_job_id=str(getattr(attempt, "job_id", "") or ""),
                active_attempt_id=str(getattr(attempt, "attempt_id", "") or ""),
                resource_sample=self._resource_sample(),
                metadata={"pid": os.getpid(), "assessment_mode": "autonomous"},
            )
            self.repository.record_worker_health(health)
            self.repository.record_resource_sample(ResourceSampleV1(
                worker_id=self.worker_id,
                job_id=health.active_job_id,
                attempt_id=health.active_attempt_id,
                memory_bytes=health.resource_sample.get("memory_bytes"),
                process_count=health.resource_sample.get("process_count"),
            ))
        except Exception:
            # Health telemetry is observability, not the worker's execution
            # control path. Supabase disconnects must degrade telemetry while
            # polling/dispatch continues and Docker health remains truthful.
            return

    @staticmethod
    def _resource_sample() -> dict:
        sample: dict = {}
        try:
            with open("/proc/self/statm", encoding="utf-8") as handle:
                pages = int(handle.read().split()[1])
            sample["memory_bytes"] = pages * os.sysconf("SC_PAGE_SIZE")
        except Exception:
            pass
        try:
            sample["process_count"] = len(os.listdir("/proc"))
        except Exception:
            pass
        return sample

    @staticmethod
    def _write_health_file() -> None:
        try:
            with open("/tmp/nexus-worker.health", "w", encoding="utf-8") as handle:
                handle.write(str(time.time()))
        except Exception:
            pass

    def _dispatch(self, job: Dict[str, Any], attempt: Any, lease_seconds: int) -> None:
        """Dispatch only registered job types.

        The actual phase handler is injected by the production application in
        the next cutover.  Unknown jobs fail closed and never execute a string
        supplied by an LLM.
        """
        handlers = {
            "maintenance": self._maintenance,
            "noop": self._noop,
            "pentest": self._pentest,
            "browser_workflow": self._browser_workflow,
            "evaluation_suite": self._evaluation_suite,
            "readiness_soak": self._readiness_soak,
        }
        handler = handlers.get(str(job.get("job_type", "")))
        if not handler:
            raise RuntimeError(f"No durable handler registered for job type '{job.get('job_type', '')}'.")
        handler(job, attempt, lease_seconds)

    def _noop(self, job: Dict[str, Any], attempt: Any, lease_seconds: int) -> None:
        self._transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "succeeded")

    def _maintenance(self, job: Dict[str, Any], attempt: Any, lease_seconds: int) -> None:
        self.repository.append_event(ExecutionEventV1(
            session_id=str(job.get("session_id", "")), job_id=attempt.job_id,
            attempt_id=attempt.attempt_id, event_type="maintenance_completed",
        ))
        self._transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "succeeded")

    def _pentest(self, job: Dict[str, Any], attempt: Any, lease_seconds: int) -> None:
        import api
        payload = job.get("payload_redacted") or job.get("payload") or {}
        terminal = api.run_pentest_job(
            attempt.job_id, str(job.get("target", "")), str(job.get("goal", "")),
            str(job.get("session_id", "")), payload.get("agent_models") or {},
            None, payload.get("scan_config") or {},
            attempt_id=attempt.attempt_id,
            budget=job.get("budget") if isinstance(job.get("budget"), dict) else {},
            worker_capabilities=tuple(self.capabilities),
            execution_repository=self.repository,
        )
        # ``run_pentest_job`` owns the application-level terminal state.  Do
        # not turn an internal ``error``/``cancelled`` return into a durable
        # worker success.  Older handlers that return None are treated as an
        # integrity failure rather than guessed as successful.
        if terminal == "done":
            worker_status = "succeeded"
        elif terminal == "partial":
            worker_status = "partial"
        elif terminal == "cancelled":
            worker_status = "cancelled"
        elif terminal in {"error", "failed"}:
            worker_status = "failed"
        else:
            raise RuntimeError(
                "pentest handler returned no authoritative terminal status"
            )
        self._transition(
            attempt.job_id, attempt.attempt_id, attempt.worker_id,
            attempt.lease_token, worker_status,
        )

    def _readiness_soak(self, job: Dict[str, Any], attempt: Any, lease_seconds: int) -> None:
        from core.soak_executor import DurableSoakExecutor, SoakCancelled
        import api

        executor = DurableSoakExecutor(self.repository, api.production_readiness_repository)
        try:
            executor.execute(job, attempt)
        except SoakCancelled:
            self._transition(
                attempt.job_id, attempt.attempt_id, attempt.worker_id,
                attempt.lease_token, "cancelled", error_code="operator_cancelled",
            )
            return
        self._transition(
            attempt.job_id, attempt.attempt_id, attempt.worker_id,
            attempt.lease_token, "succeeded", result_ref=str((job.get("payload_redacted") or {}).get("soak_run_id", "")),
        )

    def _evaluation_suite(self, job: Dict[str, Any], attempt: Any, lease_seconds: int) -> None:
        import api

        payload = job.get("payload_redacted") or job.get("payload") or {}
        execute = api.evaluation_route_memory.get("execute")
        if not callable(execute):
            raise RuntimeError("evaluation executor is not registered")
        result = execute(payload, str(job.get("session_id", "")), attempt.job_id)
        run = result["run"]
        gate = result["gate"]
        self.repository.append_event(ExecutionEventV1(
            session_id=str(job.get("session_id", "")), job_id=attempt.job_id,
            attempt_id=attempt.attempt_id, event_type="evaluation_completed",
            payload={
                "run_id": run.run_id,
                "suite_id": run.suite_id,
                "gate": gate.decision,
                "totals": run.totals,
                "metrics": run.metrics,
            },
        ))
        self._transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "succeeded")

    def _browser_workflow(self, job: Dict[str, Any], attempt: Any, lease_seconds: int) -> None:
        import asyncio
        import api
        payload = job.get("payload_redacted") or job.get("payload") or {}
        workflow = api.browser_workflow_repository.get_workflow(
            str(job.get("session_id", "")), str(payload["workflow_id"])
        )
        run = asyncio.run(api.stateful_browser_runner.run(
            workflow, session_id=str(job.get("session_id", "")),
            target=str(job.get("target", "")), identity_id=str(payload.get("identity_id", "")),
            auth_context_id=str(payload.get("auth_context_id", "")),
            role=str(payload.get("role", "baseline")), bindings=payload.get("bindings") or {},
            approved=bool(job.get("approval_ref")), approval_digest=str(payload.get("approval_digest", "")),
        ))
        self.repository.append_event(ExecutionEventV1(
            session_id=str(job.get("session_id", "")), job_id=attempt.job_id,
            attempt_id=attempt.attempt_id, event_type="browser_run_completed",
            payload={"run_id": run.run_id, "status": run.status},
        ))
        terminal = "succeeded" if run.status == "succeeded" else "partial" if run.status == "partial" else "failed"
        self._transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, terminal)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capability", action="append", default=["general"])
    args = parser.parse_args()
    url = os.environ.get("SUPABASE_URL", "")
    key = os.environ.get("SUPABASE_KEY", "")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY are required for the durable worker.")
    client = create_client(url, key)
    worker = NexusWorker(DurableExecutionRepository(client), args.capability)
    worker.preflight()
    signal.signal(signal.SIGTERM, lambda *_: setattr(worker, "stop_requested", True))
    signal.signal(signal.SIGINT, lambda *_: setattr(worker, "stop_requested", True))
    worker.run_forever()


if __name__ == "__main__":
    main()

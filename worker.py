"""Durable Nexus worker entrypoint.

Run one general worker per container by default.  The raw-network capability
is opt-in and must be enabled by the Docker profile plus the safety policy.
"""

from __future__ import annotations

import argparse
import os
import threading
import time
import uuid
from typing import Any, Dict

from dotenv import load_dotenv
from supabase import create_client

from core.config_loader import get_setting
from core.durable_execution import DurableExecutionRepository
from core.execution_contract import ExecutionEventV1

load_dotenv()


class NexusWorker:
    def __init__(self, repository: DurableExecutionRepository, capabilities: list[str], worker_id: str = ""):
        self.repository = repository
        self.capabilities = capabilities
        self.worker_id = worker_id or f"worker_{uuid.uuid4().hex[:12]}"
        self.stop_requested = False

    def run_forever(self) -> None:
        poll_seconds = max(0.5, float(get_setting("execution", {}).get("poll_interval_seconds", 2)))
        lease_seconds = max(10, int(get_setting("execution", {}).get("lease_seconds", 60)))
        while not self.stop_requested:
            self._recover_expired()
            attempt = self.repository.claim(self.worker_id, self._queues(), lease_seconds)
            if not attempt:
                time.sleep(poll_seconds)
                continue
            self._execute_attempt(attempt, lease_seconds)

    def _queues(self) -> list[str]:
        queues = ["general"]
        if "raw-network" in self.capabilities:
            queues.append("raw-network")
        return queues

    def _recover_expired(self) -> None:
        try:
            self.repository.sb.rpc("recover_expired_execution_jobs", {}).execute()
        except Exception:
            # The worker can run in local shadow mode before migration 004.
            pass

    def _execute_attempt(self, attempt: Any, lease_seconds: int) -> None:
        job = self.repository.get_job(attempt.job_id)
        if not job:
            return
        try:
            self.repository.transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "running")
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
            self.repository.transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "cancelled", error_code="worker_stopped")
        except Exception as exc:
            risk = str(job.get("risk", "read_only"))
            retryable = risk == "read_only" and int(getattr(attempt, "attempt_number", 1)) < int(job.get("max_attempts", 3))
            terminal = "retry_wait" if retryable else ("recovery_required" if risk != "read_only" else "failed")
            self.repository.transition(
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
            except Exception:
                return

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
        }
        handler = handlers.get(str(job.get("job_type", "")))
        if not handler:
            raise RuntimeError(f"No durable handler registered for job type '{job.get('job_type', '')}'.")
        handler(job, attempt, lease_seconds)

    def _noop(self, job: Dict[str, Any], attempt: Any, lease_seconds: int) -> None:
        self.repository.transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "succeeded")

    def _maintenance(self, job: Dict[str, Any], attempt: Any, lease_seconds: int) -> None:
        self.repository.append_event(ExecutionEventV1(
            session_id=str(job.get("session_id", "")), job_id=attempt.job_id,
            attempt_id=attempt.attempt_id, event_type="maintenance_completed",
        ))
        self.repository.transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "succeeded")

    def _pentest(self, job: Dict[str, Any], attempt: Any, lease_seconds: int) -> None:
        import api
        payload = job.get("payload_redacted") or job.get("payload") or {}
        api.run_pentest_job(
            attempt.job_id, str(job.get("target", "")), str(job.get("goal", "")),
            str(job.get("session_id", "")), payload.get("agent_models") or {},
            None, payload.get("scan_config") or {},
            attempt_id=attempt.attempt_id,
            budget=job.get("budget") if isinstance(job.get("budget"), dict) else {},
            worker_capabilities=tuple(self.capabilities),
            execution_repository=self.repository,
        )
        self.repository.transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "succeeded")

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
        self.repository.transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, "succeeded")

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
        self.repository.transition(attempt.job_id, attempt.attempt_id, attempt.worker_id, attempt.lease_token, terminal)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capability", action="append", default=["general"])
    args = parser.parse_args()
    url = os.environ.get("SUPABASE_URL", "")
    key = os.environ.get("SUPABASE_KEY", "")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY are required for the durable worker.")
    client = create_client(url, key)
    NexusWorker(DurableExecutionRepository(client), args.capability).run_forever()


if __name__ == "__main__":
    main()

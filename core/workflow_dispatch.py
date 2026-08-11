"""Dispatch only approved, bounded workflow proposals to legacy jobs."""

from typing import Any, Dict
import secrets
import uuid
from datetime import datetime

from core.execution_guard import ExecutionGuard
from core.session_store import SessionStore


class WorkflowDispatcher:
    def __init__(self, sessions: SessionStore, guard: ExecutionGuard, jobs: Dict[str, Dict[str, Any]]):
        self.sessions = sessions
        self.guard = guard
        self.jobs = jobs

    def dispatch(self, session_id: str, action_id: str) -> Dict[str, Any]:
        context = self.sessions.require(session_id)
        state = self.sessions.load_state(session_id)
        proposal = next((item for item in state.workflow.proposals if item.action_id == action_id), None)
        if not proposal:
            raise ValueError("Action proposal not found.")
        if proposal.status != "approved":
            raise ValueError("Action must be approved before dispatch.")
        if proposal.action in {"controlled_impact_proof", "retest_finding", "cleanup_registered_artifacts"}:
            raise ValueError("This action requires a dedicated workflow endpoint and cannot be dispatched as a generic scan.")
        if proposal.action not in {"reconnaissance", "attack_surface_mapping", "hypothesis_validation"}:
            raise ValueError(f"Unsupported workflow action: {proposal.action}")

        job_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        self.jobs[job_id] = {
            "job_id": job_id,
            "session_id": session_id,
            "target": context["target_url"],
            "goal": context["attack_goal"],
            "status": "queued",
            "message": f"Approved workflow action queued: {proposal.action}",
            "report": None,
            "logs": [],
            "summary": {},
            "stream_token": token,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "workflow_action_id": action_id,
        }
        proposal.status = "running"
        state.workflow.record_event("action_dispatched", action_id=action_id, job_id=job_id)
        self.sessions.save_state(session_id, state)
        scan_config = {
            "recon": proposal.action in {"reconnaissance", "attack_surface_mapping"},
            "exploitation": proposal.action == "hypothesis_validation",
            "assessor": False,
            "auto_pilot": False,
            "stealth_mode": False,
            "phase_filter": ["recon"] if proposal.action in {"reconnaissance", "attack_surface_mapping"} else ["analis"],
        }
        return {"job_id": job_id, "stream_token": token, "scan_config": scan_config}

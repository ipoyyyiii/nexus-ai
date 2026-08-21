"""Dispatch only approved, bounded workflow proposals to legacy jobs."""

from typing import Any, Dict
import secrets
import uuid
from datetime import datetime

from core.execution_guard import ExecutionGuard
from core.session_store import SessionStore
from core.redact import redact


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
            "planner": {
                "hypothesis_id": proposal.hypothesis_id,
                "recommended_tool": proposal.recommended_tool,
                "alternative_tools": proposal.alternative_tools,
                "priority_score": proposal.priority_score,
                "score_breakdown": proposal.score_breakdown,
                "input_bindings": proposal.input_bindings,
                "planner_cycle_id": proposal.planner_cycle_id,
            },
        }
        proposal.status = "running"
        hypothesis = next(
            (item for item in state.workflow.hypotheses if item.hypothesis_id == proposal.hypothesis_id),
            None,
        )
        if hypothesis:
            hypothesis.test_attempts += 1
            hypothesis.status = "running"
            hypothesis.last_updated = datetime.now().isoformat()
        state.workflow.record_event(
            "action_dispatched", action_id=action_id, job_id=job_id,
            hypothesis_id=proposal.hypothesis_id,
            recommended_tool=proposal.recommended_tool,
        )
        self.sessions.save_state(session_id, state)
        scan_config = {
            "recon": proposal.action in {"reconnaissance", "attack_surface_mapping"},
            "exploitation": proposal.action == "hypothesis_validation",
            "assessor": False,
            "auto_pilot": False,
            "stealth_mode": False,
            "phase_filter": ["recon"] if proposal.action in {"reconnaissance", "attack_surface_mapping"} else ["analis"],
            "recommended_tools": [proposal.recommended_tool] if proposal.recommended_tool else [],
            "planner_context": {
                "hypothesis_id": proposal.hypothesis_id,
                "rationale": proposal.rationale,
                "expected_evidence": proposal.expected_evidence,
                "input_bindings": proposal.input_bindings,
                "stop_conditions": proposal.stop_conditions,
            },
        }
        return {"job_id": job_id, "stream_token": token, "scan_config": scan_config}

    def complete(self, session_id: str, action_id: str, succeeded: bool, reason: str = "") -> Dict[str, Any]:
        """Close a dispatched action before the planner reads new evidence."""
        safe_reason = str(redact(reason or ""))[:500]
        state = self.sessions.load_state(session_id)
        proposal = next((item for item in state.workflow.proposals if item.action_id == action_id), None)
        if not proposal:
            raise ValueError("Action proposal not found.")
        if proposal.status not in {"running", "approved"}:
            return {"proposal": proposal.__dict__, "changed": False}

        proposal.status = "complete" if succeeded else "failed"
        hypothesis = next(
            (item for item in state.workflow.hypotheses if item.hypothesis_id == proposal.hypothesis_id),
            None,
        )
        if hypothesis:
            if succeeded and hypothesis.category == "surface_mapping":
                hypothesis.status = "complete"
            else:
                hypothesis.status = "pending"
            hypothesis.decision_reason = safe_reason or (
                "Action completed; awaiting deterministic evidence refresh."
                if succeeded else "Action failed; planner may choose an alternative capability."
            )
            hypothesis.last_updated = datetime.now().isoformat()
        state.workflow.record_event(
            "action_completed", action_id=action_id, succeeded=succeeded,
            hypothesis_id=proposal.hypothesis_id, reason=safe_reason,
        )
        self.sessions.save_state(session_id, state)
        return {
            "proposal": proposal.__dict__, "hypothesis": hypothesis.__dict__ if hypothesis else None, "changed": True,
        }

"""CrewAI-compatible Stage 4 workflow and invariant tools."""

from __future__ import annotations

import json
from typing import Any

from core.tool_decorator import crewai_tool as tool

from core.business_logic_engine import business_invariant_engine
from core.browser_workflow_contract import BrowserWorkflowV1, BusinessInvariantV1
from core.browser_workflow_runner import StatefulBrowserRunner


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


@tool("browser_workflow_discovery")
def browser_workflow_discovery(
    url: str,
    goal: str = "",
    session_id: str = "",
    captures: str = "[]",
    identity_ids: str = "[]",
) -> str:
    """Build a target-agnostic structured browser workflow draft from captures."""
    from core.workflow_discovery import workflow_discovery_service
    try:
        data = json.loads(captures or "[]")
        identities = json.loads(identity_ids or "[]")
        workflow = workflow_discovery_service.discover(
            session_id=session_id, origin=url, goal=goal,
            captures=data if isinstance(data, list) else [],
            identity_ids=identities if isinstance(identities, list) else [],
        )
        return _json({"status": "draft", "workflow": workflow.model_dump(mode="json")})
    except Exception as exc:
        return _json({"status": "failed", "error": str(exc)[:500]})


@tool("business_invariant_evaluator")
def business_invariant_evaluator(
    invariant: str,
    transitions: str = "[]",
    runs: str = "[]",
    observations: str = "[]",
) -> str:
    """Evaluate a typed business invariant without LLM status authority."""
    try:
        item = BusinessInvariantV1(**json.loads(invariant))
        evaluation, candidate = business_invariant_engine.evaluate(
            item,
            transitions=json.loads(transitions or "[]"),
            runs=json.loads(runs or "[]"),
            observations=json.loads(observations or "[]"),
        )
        return _json({
            "status": "evaluated",
            "evaluation": evaluation.model_dump(mode="json"),
            "candidate": candidate.model_dump(mode="json") if candidate else None,
        })
    except Exception as exc:
        return _json({"status": "failed", "error": str(exc)[:500]})


@tool("stateful_browser_workflow")
def stateful_browser_workflow(
    workflow: str,
    target: str,
    session_id: str,
    identity_id: str = "",
    auth_context_id: str = "",
    role: str = "baseline",
    bindings: str = "{}",
    approved: bool = False,
    approval_digest: str = "",
) -> str:
    """Run a bounded published workflow through StatefulBrowserRunner."""
    try:
        import asyncio
        item = BrowserWorkflowV1(**json.loads(workflow))
        if item.has_mutations():
            return _json({"status": "approval_required", "error": "Mutating browser workflows must be approved via the API workflow proposal endpoint."})
        from api import session_store, browser_workflow_repository, browser_artifact_store
        runner = StatefulBrowserRunner(session_store, browser_workflow_repository, browser_artifact_store)
        run = asyncio.run(runner.run(
            item,
            session_id=session_id,
            target=target,
            identity_id=identity_id,
            auth_context_id=auth_context_id,
            role=role,
            bindings=json.loads(bindings or "{}"),
            approved=approved,
            approval_digest=approval_digest,
        ))
        return _json({"status": run.status, "run": run.model_dump(mode="json")})
    except Exception as exc:
        return _json({"status": "failed", "error": str(exc)[:500]})

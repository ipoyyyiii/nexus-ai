"""CrewAI-compatible entry point for dynamic authorization replay."""

from __future__ import annotations

import json
from typing import Any, Dict

from core.tool_decorator import crewai_tool as tool

from core.authorization_contract import AuthorizationExpectationV1, RequestTemplateV1, ResourceInstanceV1
from core.authorization_engine import AuthorizationReplayEngine
from core.identity_context import get_execution_context
from core.structured_contract import ToolErrorV1, ToolResultV1


@tool("authorization_differential_replay")
def authorization_differential_replay(
    template_json: str,
    resource_json: str,
    owner_identity_id: str,
    test_identity_ids: str,
    expectations_json: str = "[]",
    bindings_json: str = "{}",
    auth_contexts_json: str = "{}",
    negative_control_identity_id: str = "",
    approved: bool = False,
) -> ToolResultV1:
    """Replay one discovered action/resource across isolated identities.

    The request and resource must come from runtime discovery. This tool does
    not guess endpoint names, object IDs, roles, or tenants.
    """
    context = get_execution_context()
    if not context or not context.session_id:
        return ToolResultV1(
            tool_name="authorization_differential_replay", category="access_control", status="failed",
            summary="Authorization replay requires an active engagement context.",
            errors=[ToolErrorV1(code="missing_session_context", message="No session context was supplied.")],
        )
    try:
        template = RequestTemplateV1(**json.loads(template_json))
        resource = ResourceInstanceV1(**json.loads(resource_json))
        identity_ids = json.loads(test_identity_ids) if test_identity_ids.strip().startswith("[") else [item.strip() for item in test_identity_ids.split(",") if item.strip()]
        expectations = [AuthorizationExpectationV1(**item) for item in json.loads(expectations_json or "[]")]
        bindings = json.loads(bindings_json or "{}")
        auth_contexts = json.loads(auth_contexts_json or "{}")
        if not isinstance(auth_contexts, dict):
            raise ValueError("auth_contexts_json must be an object keyed by identity_id")
        return AuthorizationReplayEngine(target=template.origin).run_differential(
            context.session_id, template, resource, owner_identity_id,
            identity_ids, expectations, bindings, approved,
            auth_contexts=auth_contexts,
            negative_control_identity_id=negative_control_identity_id,
        )
    except Exception as exc:
        return ToolResultV1(
            tool_name="authorization_differential_replay", category="access_control", status="failed",
            summary="Authorization replay input or execution failed.",
            errors=[ToolErrorV1(code="replay_error", message=str(exc))],
        )

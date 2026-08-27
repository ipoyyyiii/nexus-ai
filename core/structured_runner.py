"""Single execution boundary for CrewAI/LangChain tools."""

from __future__ import annotations

import json
import copy
import time
import uuid
from typing import Any, Dict, Optional

from core.structured_contract import ToolErrorV1, ToolResultV1, result_from_legacy, redact, now_iso
from core.validation_engine import validation_engine
from core.detection_validation_v2 import validation_engine_v2
from core.structured_repository import StructuredRepository
from core.identity_context import ToolExecutionContext, use_execution_context, get_execution_context
from core.safety_kernel import SafetyKernel, SafetyViolation
from core.execution_contract import ResourceBudgetV1
from core.tool_registry import get_tool_capability
from core.config_loader import get_setting, get_config


class StructuredToolRunner:
    def __init__(self, session_store: Any = None, repository: Optional[StructuredRepository] = None, safety_kernel: Optional[SafetyKernel] = None):
        self.session_store = session_store
        self.repository = repository
        self.safety_kernel = safety_kernel or (SafetyKernel(session_store=session_store) if session_store else None)

    def execute(
        self,
        tool: Any,
        kwargs: Dict[str, Any],
        target: str,
        session_id: str = "",
        category: str = "unknown",
        identity_id: str = "",
        auth_context_id: str = "",
        job_id: str = "",
        runtime_config: Optional[Dict[str, Any]] = None,
    ) -> ToolResultV1:
        tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "unknown_tool")
        run_id = f"run_{uuid.uuid4().hex}"
        started = time.monotonic()
        try:
            inherited = get_execution_context()
            capability = get_tool_capability(tool_name)
            if capability is None and str(get_setting("tool_boundary_mode", "shadow")).lower() == "strict":
                raise SafetyViolation("tool_not_registered", f"Tool '{tool_name}' is not present in the canonical registry.")
            config_snapshot = copy.deepcopy(
                inherited.config_snapshot if inherited and inherited.config_snapshot else get_config()
            )
            if runtime_config:
                runtime = dict(config_snapshot.get("_runtime") or {})
                runtime.update(copy.deepcopy(runtime_config))
                config_snapshot["_runtime"] = runtime
            context = ToolExecutionContext(
                session_id=session_id or (inherited.session_id if inherited else ""),
                job_id=job_id or (inherited.job_id if inherited else ""),
                identity_id=identity_id or (inherited.identity_id if inherited else "anonymous"),
                auth_context_id=auth_context_id or (inherited.auth_context_id if inherited else ""),
                target_origin=target,
                attempt_id=inherited.attempt_id if inherited else "",
                tool_run_id=run_id,
                tool_name=tool_name,
                tool_version=capability.tool_version if capability else "1.0",
                auto_pilot=inherited.auto_pilot if inherited else False,
                stealth_mode=inherited.stealth_mode if inherited else False,
                budget=(inherited.budget if inherited and inherited.budget else ResourceBudgetV1()),
                config_snapshot=config_snapshot,
                safety_kernel=self.safety_kernel,
                repository=self.repository,
                secret_vault=inherited.secret_vault if inherited else None,
                worker_capabilities=inherited.worker_capabilities if inherited else (),
                approval_ref=inherited.approval_ref if inherited else "",
                approval_digest=inherited.approval_digest if inherited else "",
                approval_granted=inherited.approval_granted if inherited else False,
            )
            with use_execution_context(context):
                if session_id and self.session_store:
                    allowed, reason = self.session_store.validate_active_scope(session_id, target)
                    if not allowed:
                        raise PermissionError(f"Structured tool scope rejected: {reason}")
                if capability and capability.requires_approval and not context.approval_granted:
                    raise SafetyViolation("approval_required", f"Tool '{tool_name}' requires exact approval before execution.")
                if self.safety_kernel and session_id and target:
                    self.safety_kernel.require(
                        session_id, "tool_execute", target, job_id=context.job_id,
                        attempt_id=context.attempt_id, tool_run_id=run_id,
                        identity_id=context.identity_id, budget=context.budget,
                        approved=context.approval_granted,
                        mutation=bool(capability and capability.requires_approval),
                    )
                if hasattr(tool, "invoke"):
                    output = tool.invoke(kwargs)
                elif hasattr(tool, "func") and callable(tool.func):
                    # CrewAI's @tool wrapper exposes the Python callable as
                    # .func, while LangChain tools commonly expose .invoke.
                    output = tool.func(**kwargs)
                elif hasattr(tool, "run"):
                    output = tool.run(kwargs)
                else:
                    output = tool(**kwargs)
            if isinstance(output, ToolResultV1):
                result = output
                result.tool_run_id = run_id
            else:
                if str(get_setting("tool_boundary_mode", "shadow")).lower() == "strict":
                    raise SafetyViolation("raw_string_output", f"Tool '{tool_name}' did not return ToolResultV1.")
                result = result_from_legacy(tool_name, target, output, run_id)
                result.category = category if category != "unknown" else result.category
            result.inputs_redacted = redact(kwargs)
            result.target = result.target or target
            result.finished_at = result.finished_at or now_iso()
            result.metrics.setdefault("duration_ms", round((time.monotonic() - started) * 1000, 2))
        except Exception as exc:
            result = ToolResultV1(
                tool_run_id=run_id, tool_name=tool_name, category=category,
                target=target, status="failed", inputs_redacted=redact(kwargs),
                summary=f"{tool_name} failed.",
                errors=[ToolErrorV1(code="execution_error", message=str(exc), retryable=False)],
                metrics={"duration_ms": round((time.monotonic() - started) * 1000, 2)},
            )
        validations = validation_engine.validate(result) if result.candidate_findings else []
        if result.candidate_findings:
            # Stage 9 runs in shadow by default. It produces a complete V2
            # trace for diagnostics but never changes candidate status here;
            # strict promotion is an explicit validation-v2 API operation.
            v2_decisions = validation_engine_v2.validate(result, mode=str(get_setting("detection_depth_mode", "shadow")), apply_status=False)
            result.metrics["validation_v2_shadow"] = [
                {"candidate_id": item.candidate_id, "policy_id": item.policy_id, "decision": item.decision, "score": item.score, "input_digest": item.input_digest}
                for item in v2_decisions
            ]
        if session_id and self.repository:
            try:
                self.repository.persist(session_id, result, validations)
            except Exception as exc:
                result.errors.append(ToolErrorV1(code="persistence_error", message=str(exc), retryable=True))
                if result.status == "succeeded":
                    result.status = "partial"
        return result

    def render_for_model(self, result: ToolResultV1) -> str:
        return result.llm_summary()


def structured_crewai_tool(
    tool: Any,
    session_id: str = "",
    target: str = "",
    category: str = "unknown",
    session_store: Any = None,
    identity_id: str = "",
    auth_context_id: str = "",
    job_id: str = "",
) -> Any:
    """Wrap a LangChain tool while preserving CrewAI's string boundary."""
    from crewai.tools import BaseTool
    from pydantic import create_model
    import inspect

    runner = StructuredToolRunner(
        session_store=session_store,
        repository=StructuredRepository(session_store) if session_store else None,
        safety_kernel=SafetyKernel(session_store=session_store) if session_store else None,
    )
    schema = getattr(tool, "args_schema", None)
    if not schema:
        sig = inspect.signature(tool.func)
        fields = {name: (str, default if default is not inspect.Parameter.empty else ...) for name, param in sig.parameters.items() if name != "self" for default in [param.default]}
        schema = create_model(f"{tool.name}Input", **fields) if fields else None

    class StructuredCrewAIWrapper(BaseTool):
        name: str = tool.name
        description: str = tool.description
        args_schema: type = schema if schema else type("EmptySchema", (), {})

        def _run(self, **kwargs) -> str:
            result = runner.execute(
                tool, kwargs, target=target, session_id=session_id, category=category,
                identity_id=identity_id, auth_context_id=auth_context_id, job_id=job_id,
            )
            return runner.render_for_model(result)

    return StructuredCrewAIWrapper()

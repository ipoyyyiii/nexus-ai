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
from core.proof_pipeline import proof_pipeline
from core.structured_repository import StructuredRepository
from core.identity_context import ToolExecutionContext, use_execution_context, get_execution_context
from core.safety_kernel import SafetyKernel, SafetyViolation
from core.execution_contract import ResourceBudgetV1
from core.tool_registry import get_tool_capability
from core.config_loader import get_config


class StructuredToolRunner:
    def __init__(self, session_store: Any = None, repository: Optional[StructuredRepository] = None, safety_kernel: Optional[SafetyKernel] = None):
        self.session_store = session_store
        self.repository = repository
        self.safety_kernel = safety_kernel or (SafetyKernel(session_store=session_store) if session_store else None)

    @staticmethod
    def _exception_error(exc: Exception) -> ToolErrorV1:
        """Convert an execution exception into an actionable, redacted error.

        A generic ``execution_error`` made scope, timeout, transport, and
        provider failures indistinguishable in the durable run ledger.  The
        status was technically ``failed`` but the failure contract was not
        useful for recovery or acceptance testing.
        """
        reason_code = str(getattr(exc, "reason_code", "") or "").strip()
        exception_name = type(exc).__name__
        lowered = exception_name.lower()
        if reason_code:
            code = reason_code
            failure_class = "policy"
            retryable = False
        elif isinstance(exc, TimeoutError) or "timeout" in lowered:
            code = "tool_timeout"
            failure_class = "timeout"
            retryable = True
        elif isinstance(exc, ConnectionError) or any(
            marker in lowered for marker in ("connection", "connect", "network", "socket")
        ):
            code = "tool_transport_error"
            failure_class = "transport"
            retryable = True
        elif isinstance(exc, PermissionError):
            code = "scope_rejected"
            failure_class = "scope"
            retryable = False
        else:
            code = "execution_error"
            failure_class = "execution"
            retryable = False
        details = {
            "exception_type": exception_name,
            "failure_class": failure_class,
        }
        if reason_code:
            details["reason_code"] = reason_code
        return ToolErrorV1(
            code=code,
            message=redact(str(exc))[:2000],
            retryable=retryable,
            details=details,
        )

    @staticmethod
    def _normalize_result_contract(result: ToolResultV1) -> ToolResultV1:
        """Make status/error combinations truthful before persistence.

        This is the last contract boundary for both native structured tools
        and legacy adapters.  In particular, a legacy ``SKIPPED`` payload is
        still an authoritative execution record: it must carry enough typed
        metadata to explain why it was not run and whether that omission is a
        coverage debt.  Keeping this normalization here prevents individual
        tools from silently bypassing the durable execution contract.
        """
        metrics = result.metrics if isinstance(result.metrics, dict) else {}
        result.metrics = metrics

        if result.status == "succeeded" and result.errors:
            result.status = "partial"
            result.metrics["status_normalized_from"] = "succeeded"
        if result.status == "failed" and not result.errors:
            result.errors.append(ToolErrorV1(
                code="failure_without_diagnostic",
                message="Tool returned failed without a structured diagnostic.",
                retryable=False,
                details={"normalized": True, "original_status": "failed"},
            ))
        if result.status == "partial" and not result.errors:
            result.errors.append(ToolErrorV1(
                code="partial_without_diagnostic",
                message="Tool returned partial without a structured diagnostic.",
                retryable=True,
                details={"normalized": True, "original_status": "partial"},
            ))
        if result.status == "skipped":
            reason = str(metrics.get("skip_reason") or "").strip()
            if not reason:
                result.status = "partial"
                metrics["status_normalized_from"] = "skipped"
                metrics["skip_reason"] = "skip_reason_missing"
                metrics["skip_class"] = "invalid_contract"
                metrics["coverage_required"] = True
                result.errors.append(ToolErrorV1(
                    code="skip_reason_missing",
                    message="Skipped tool result must include metrics.skip_reason.",
                    retryable=False,
                    details={
                        "normalized": True,
                        "original_status": "skipped",
                        "coverage_required": True,
                    },
                ))
            else:
                skip_class = str(metrics.get("skip_class") or "").strip()
                if not skip_class or skip_class in {"legacy", "unknown"}:
                    skip_class = StructuredToolRunner._infer_skip_class(reason)
                    metrics["skip_class"] = skip_class

                if "coverage_required" not in metrics:
                    # Recon plans provide the authoritative value.  For
                    # adapter results without a plan, fail closed except for
                    # an objectively inapplicable capability such as a mixed
                    # content check against an HTTP page.
                    metrics["coverage_required"] = skip_class != "not_applicable"
                else:
                    metrics["coverage_required"] = StructuredToolRunner._coerce_bool(
                        metrics.get("coverage_required"),
                        default=True,
                    )

                if not result.errors:
                    result.errors.append(ToolErrorV1(
                        code="tool_skipped",
                        message=f"Tool was not executed: {redact(reason)[:1000]}.",
                        retryable=False,
                        details={
                            "normalized": True,
                            "skip_reason": redact(reason)[:1000],
                            "skip_class": skip_class,
                            "coverage_required": metrics["coverage_required"],
                        },
                    ))
        return result

    @staticmethod
    def _coerce_bool(value: Any, *, default: bool) -> bool:
        """Parse persisted/config metadata without Python truthiness traps."""
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)) and value in {0, 1}:
            return bool(value)
        normalized = str(value or "").strip().lower()
        if normalized in {"true", "1", "yes", "y", "on"}:
            return True
        if normalized in {"false", "0", "no", "n", "off"}:
            return False
        return default

    @staticmethod
    def _infer_skip_class(reason: str) -> str:
        """Infer a conservative class for adapter results lacking plan data."""
        value = str(reason or "").strip().lower()
        if any(marker in value for marker in (
            "not applicable", "only applies", "requires https", "not https",
        )):
            return "not_applicable"
        if any(marker in value for marker in (
            "approval", "authorization required", "operator approval",
        )):
            return "approval_blocked"
        if any(marker in value for marker in (
            "disabled", "policy", "private", "raw network", "r2",
        )):
            return "policy_blocked"
        if any(marker in value for marker in (
            "timeout", "budget", "cancel", "deadline",
        )):
            return "budget_or_cancelled"
        if any(marker in value for marker in (
            "dependency", "unavailable", "not installed", "not registered",
        )):
            return "unavailable"
        return "not_scheduled"

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
            if capability is None:
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
                authorized_lab_mode=inherited.authorized_lab_mode if inherited else False,
                authorized_lab_origin=inherited.authorized_lab_origin if inherited else "",
                suite_preapproval_id=inherited.suite_preapproval_id if inherited else "",
            )
            with use_execution_context(context):
                if session_id and self.session_store:
                    allowed, reason = self.session_store.validate_active_scope(session_id, target)
                    if not allowed:
                        raise PermissionError(f"Structured tool scope rejected: {reason}")
                if capability and capability.requires_approval and not context.approval_granted:
                    raise SafetyViolation("approval_required", f"Tool '{tool_name}' requires exact approval before execution.")
                if self.safety_kernel and session_id and target:
                    # A nested tool invocation (for example the httpx probe
                    # launched by human_recon_crawl) may reuse the parent's
                    # safety kernel without carrying the session-store object
                    # on the runner itself.  Preserve the already-issued
                    # local-lab authorization explicitly, but only for the
                    # exact preapproved origin.  The kernel still performs
                    # the normal session scope check; this flag only avoids
                    # losing the private-IP opt-in during nested dispatch.
                    local_lab_private = bool(
                        context.authorized_lab_mode
                        and context.authorized_lab_origin
                        and SafetyKernel.origin(target)
                        == str(context.authorized_lab_origin).rstrip("/").lower()
                    )
                    self.safety_kernel.require(
                        session_id, "tool_execute", target, job_id=context.job_id,
                        attempt_id=context.attempt_id, tool_run_id=run_id,
                        identity_id=context.identity_id, budget=context.budget,
                        approved=context.approval_granted,
                        mutation=bool(capability and capability.requires_approval),
                        allow_private=local_lab_private,
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
                result = result_from_legacy(tool_name, target, output, run_id)
                result.category = category if category != "unknown" else result.category
            result.inputs_redacted = redact(kwargs)
            result.target = result.target or target
            result.finished_at = result.finished_at or now_iso()
            # A retry is a new durable tool run, but it must retain an exact
            # relationship to the transient run that caused it.  The
            # autonomous controller passes these fields through
            # ``runtime_config`` so recovery can be audited without relying
            # on repository ordering or log timing.
            if runtime_config:
                recovery_of = str(runtime_config.get("recovery_of_run_id") or "").strip()
                if recovery_of:
                    result.metrics["recovery"] = {
                        "recovered_from_run_id": recovery_of[:128],
                        "attempt": max(2, int(runtime_config.get("recovery_attempt", 2) or 2)),
                        "reason": str(runtime_config.get("recovery_reason") or "retryable_tool_result")[:256],
                    }
            result.metrics.setdefault("duration_ms", round((time.monotonic() - started) * 1000, 2))
        except Exception as exc:
            result = ToolResultV1(
                tool_run_id=run_id, tool_name=tool_name, category=category,
                target=target, status="failed", inputs_redacted=redact(kwargs),
                summary=f"{tool_name} failed.",
                errors=[self._exception_error(exc)],
                metrics={"duration_ms": round((time.monotonic() - started) * 1000, 2)},
            )
        result = self._normalize_result_contract(result)
        validations = validation_engine.validate(result) if result.candidate_findings else []
        v2_decisions = []
        if result.candidate_findings:
            # The result may have been created by a tool that returned a raw
            # legacy payload.  Run the authoritative V2 validator after the
            # adapter has produced candidates, then retain the decisions for
            # both metrics and durable audit persistence below.
            v2_decisions = validation_engine_v2.validate(
                result,
                mode="autonomous",
                apply_status=True,
            )
            result.metrics["validation_v2"] = [
                {"candidate_id": item.candidate_id, "policy_id": item.policy_id, "decision": item.decision, "score": item.score, "input_digest": item.input_digest}
                for item in v2_decisions
            ]
            result.metrics["proof"] = [
                item.model_dump(mode="json")
                for item in proof_pipeline.summarize(result, v2_decisions)
            ]
        if session_id and self.repository:
            if v2_decisions:
                try:
                    self.repository.persist_v2_validation_traces(
                        validation_engine_v2.last_traces,
                        v2_decisions,
                        session_id=session_id,
                    )
                except Exception as exc:
                    # Preserve the primary tool result even if an older
                    # deployment has not applied the V2 trace migration. The
                    # missing audit trace is still surfaced as partial; it
                    # must never be mistaken for a validation success.
                    result.errors.append(ToolErrorV1(code="validation_trace_persistence_error", message=str(exc), retryable=True))
                    if result.status == "succeeded":
                        result.status = "partial"
            try:
                self.repository.persist(session_id, result, validations, job_id=job_id)
            except Exception as exc:
                result.errors.append(ToolErrorV1(
                    code="persistence_error",
                    message=redact(str(exc))[:2000],
                    retryable=True,
                    details={"exception_type": type(exc).__name__, "failure_class": "persistence"},
                ))
                if result.status == "succeeded":
                    result.status = "partial"
                reconcile = getattr(self.repository, "reconcile_tool_run_failure", None)
                if callable(reconcile):
                    try:
                        reconcile(session_id, result)
                    except Exception as reconcile_exc:
                        result.errors.append(ToolErrorV1(
                            code="persistence_reconciliation_error",
                            message=redact(str(reconcile_exc))[:2000],
                            retryable=True,
                            details={
                                "exception_type": type(reconcile_exc).__name__,
                                "failure_class": "persistence_reconciliation",
                            },
                        ))
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

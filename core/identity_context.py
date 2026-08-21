"""Scoped execution context for authenticated, durable tool runs."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterator, Optional


@dataclass
class ToolExecutionContext:
    """Runtime envelope shared by every tool and guarded capability.

    The dataclass stays signature-compatible with the existing CrewAI flow,
    while adding durable correlation and approval state. Secrets are never
    stored here; auth material is resolved by the vault/auth store at request
    time.
    """

    session_id: str = ""
    job_id: str = ""
    identity_id: str = "anonymous"
    auth_context_id: str = ""
    target_origin: str = ""
    attempt_id: str = ""
    tool_run_id: str = ""
    tool_name: str = ""
    tool_version: str = "1"
    auto_pilot: bool = False
    stealth_mode: bool = False
    budget: Any = None
    config_snapshot: dict[str, Any] | None = None
    safety_kernel: Any = None
    repository: Any = None
    secret_vault: Any = None
    worker_capabilities: tuple[str, ...] = ()
    approval_ref: str = ""
    approval_digest: str = ""
    approval_granted: bool = False


_active_context: ContextVar[Optional[ToolExecutionContext]] = ContextVar(
    "nexus_tool_execution_context", default=None
)


def get_execution_context() -> Optional[ToolExecutionContext]:
    return _active_context.get()


def set_execution_context(context: ToolExecutionContext):
    return _active_context.set(context)


def reset_execution_context(token) -> None:
    _active_context.reset(token)


@contextmanager
def use_execution_context(context: ToolExecutionContext) -> Iterator[ToolExecutionContext]:
    token = _active_context.set(context)
    try:
        yield context
    finally:
        _active_context.reset(token)


def current_identity_id(default: str = "anonymous") -> str:
    context = get_execution_context()
    return context.identity_id if context and context.identity_id else default

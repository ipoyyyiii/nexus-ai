"""Allowlisted, serializable cleanup handlers for reversible side effects.

The callable form remains for old local integrations, but durable workers must
use ``execute_durable`` with a registered handler and redacted JSON context.
"""

from dataclasses import dataclass
from typing import Callable, Dict, Optional


@dataclass
class CleanupHandler:
    name: str
    handler: Callable[[dict], dict]
    description: str
    durable: bool = True


class CleanupRegistry:
    def __init__(self):
        self._handlers: Dict[str, CleanupHandler] = {}

    def register(self, name: str, handler: Callable[[dict], dict], description: str) -> None:
        self._handlers[name] = CleanupHandler(name, handler, description)

    def execute(self, name: str, context: dict) -> dict:
        entry = self._handlers.get(name)
        if not entry:
            raise ValueError(f"Cleanup handler '{name}' is not registered.")
        result = entry.handler(context)
        if not isinstance(result, dict) or "success" not in result:
            raise ValueError("Cleanup handlers must return a result with success.")
        return result

    def execute_durable(self, name: str, context: dict) -> dict:
        """Execute only a JSON-serializable cleanup context.

        A callable hidden in the context would disappear on worker restart and
        therefore cannot be the only rollback mechanism.
        """
        if not isinstance(context, dict) or any(callable(value) for value in context.values()):
            return {"success": False, "status": "cleanup_failed", "error": "non_serializable_context"}
        try:
            result = self.execute(name, context)
        except Exception as exc:
            return {"success": False, "status": "cleanup_failed", "error": type(exc).__name__}
        if result.get("success") is not True:
            return {**result, "status": "cleanup_failed"}
        return {**result, "status": "succeeded"}

    def available(self) -> list[dict]:
        return [
            {"name": item.name, "description": item.description, "durable": item.durable}
            for item in self._handlers.values()
        ]


cleanup_registry = CleanupRegistry()


def register_cleanup_handler(name: str, description: str):
    def decorator(handler):
        cleanup_registry.register(name, handler, description)
        return handler
    return decorator


@register_cleanup_handler(
    "revoke_test_session",
    "Revoke a session created by an approved test when a registered revocation callback exists.",
)
def revoke_test_session(context: dict) -> dict:
    callback = context.get("revoke_callback")
    if not callable(callback):
        return {"success": False, "result": "No revocation callback was registered."}
    callback()
    return {"success": True, "result": "Test session revocation callback completed."}


@register_cleanup_handler(
    "restore_baseline_callback",
    "Restore a state-changing test through its explicit registered rollback callback.",
)
def restore_baseline_callback(context: dict) -> dict:
    callback = context.get("rollback_callback")
    if not callable(callback):
        return {"success": False, "result": "No rollback callback was registered."}
    callback()
    return {"success": True, "result": "Registered rollback callback completed."}

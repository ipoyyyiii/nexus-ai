"""Core infrastructure package with lazy compatibility re-exports.

The canonical AI-native runtime imports individual ``core.*`` modules.  The
old package initializer eagerly imported the complete model registry (and
therefore CrewAI/provider SDKs) for every import of ``core``.  That made the
API and durable worker pay the legacy startup cost even when the canonical
path did not use it.  Keep the historical public names, but resolve them only
when a caller explicitly asks for one.
"""

from importlib import import_module


_LAZY_ATTRS = {
    "checkpoint_store": ("core.checkpoint", "checkpoint_store"),
    "require_approval": ("core.checkpoint", "require_approval"),
    "current_job_id": ("core.checkpoint", "current_job_id"),
    "cancellation_store": ("core.cancellation", "cancellation_store"),
    "check_cancelled": ("core.cancellation", "check_cancelled"),
    "cancel_job_id": ("core.cancellation", "current_job_id"),
    "rate_limiter": ("core.rate_limiter", "rate_limiter"),
    "redact": ("core.redact", "redact"),
    "proxy_router": ("core.proxy_router", "proxy_router"),
    "auth_store": ("core.auth_store", "auth_store"),
    "inject_into_session": ("core.auth_store", "inject_into_session"),
    "get_auth_kwargs": ("core.auth_store", "get_auth_kwargs"),
    "AuthSession": ("core.auth_store", "AuthSession"),
    "detect_login_wall": ("core.auth_detection", "detect_login_wall"),
    "needs_auth": ("core.auth_detection", "needs_auth"),
    "auth_checkpoint_store": ("core.auth_checkpoint", "auth_checkpoint_store"),
    "auth_job_id": ("core.auth_checkpoint", "current_job_id"),
    "SessionMemory": ("core.session_memory", "SessionMemory"),
    "MEMORY_TABLE_SQL": ("core.session_memory", "MEMORY_TABLE_SQL"),
    "validate_target": ("core.scope", "validate_target"),
    "extract_domain": ("core.scope", "extract_domain"),
    "build_llm": ("core.model_registry", "build_llm"),
    "list_available_models": ("core.model_registry", "list_available_models"),
    "chain_summary": ("core.model_registry", "chain_summary"),
    "MODEL_REGISTRY": ("core.model_registry", "MODEL_REGISTRY"),
    "scan_history": ("core.scan_history", "scan_history"),
    "response_cache": ("core.response_cache", "response_cache"),
    "safe_except": ("core.safe_except", "safe_except"),
    "ToolExecutionContext": ("core.identity_context", "ToolExecutionContext"),
    "get_execution_context": ("core.identity_context", "get_execution_context"),
    "use_execution_context": ("core.identity_context", "use_execution_context"),
    "AuthorizationReplayEngine": ("core.authorization_engine", "AuthorizationReplayEngine"),
}


def __getattr__(name: str):
    target = _LAZY_ATTRS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value

__all__ = [
    "checkpoint_store", "require_approval", "current_job_id",
    "cancellation_store", "check_cancelled", "cancel_job_id",
    "rate_limiter", "redact", "proxy_router",
    "auth_store", "inject_into_session", "get_auth_kwargs", "AuthSession",
    "detect_login_wall", "needs_auth",
    "auth_checkpoint_store", "auth_job_id",
    "SessionMemory", "MEMORY_TABLE_SQL",
    "validate_target", "extract_domain",
    "build_llm", "list_available_models", "chain_summary", "MODEL_REGISTRY",
    "scan_history", "response_cache", "safe_except",
    "ToolExecutionContext", "get_execution_context", "use_execution_context",
    "AuthorizationReplayEngine",
]

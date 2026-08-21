"""
Core Infrastructure Package
============================
Re-exports all core modules for clean imports.
"""

from core.checkpoint import checkpoint_store, require_approval, current_job_id
from core.cancellation import cancellation_store, check_cancelled, current_job_id as cancel_job_id
from core.rate_limiter import rate_limiter
from core.redact import redact
from core.proxy_router import proxy_router
from core.auth_store import auth_store, inject_into_session, get_auth_kwargs, AuthSession
from core.auth_detection import detect_login_wall, needs_auth
from core.auth_checkpoint import auth_checkpoint_store, current_job_id as auth_job_id
from core.session_memory import SessionMemory, MEMORY_TABLE_SQL
from core.scope import validate_target, extract_domain
from core.model_registry import build_llm, list_available_models, chain_summary, MODEL_REGISTRY
from core.scan_history import scan_history
from core.response_cache import response_cache
from core.safe_except import safe_except
from core.identity_context import ToolExecutionContext, get_execution_context, use_execution_context
from core.authorization_engine import AuthorizationReplayEngine

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

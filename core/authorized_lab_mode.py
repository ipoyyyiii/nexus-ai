"""Bounded unattended approval for explicitly authorized local lab suites.

This is intentionally narrower than auto-pilot. A session must already have
an explicit authorization confirmation and the job target must match one exact
allowlisted lab origin. This scope may auto-approve only the configured
bounded detector set; state-changing or high-risk actions still use the normal
exact approval checkpoint.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit

from core.config_loader import get_config
from core.execution_contract import stable_digest


_URL_RE = re.compile(r"https?://[^\s)\]}>'\"]+", re.IGNORECASE)
_MUTATING_ACTION_RE = re.compile(
    r"\b(?:delete|drop|truncate|destroy|shutdown|wipe|format|"
    r"denial[- ]of[- ]service|\bdos\b|credential[ -]?stuffing|"
    r"password[ -]?spray|brute[ -]?force|reverse[ -]?shell|"
    r"persistence|exfiltrat(?:e|ion)|ransom|upload)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LocalLabPreapproval:
    approved: bool
    reason: str
    target_origin: str = ""
    preapproval_id: str = ""
    source: str = "none"


def normalize_origin(value: str) -> str:
    """Normalize to scheme/host/port; paths never widen authorization."""
    try:
        parsed = urlsplit(str(value).strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower().rstrip(".")
        port = parsed.port or (443 if scheme == "https" else 80)
        return f"{scheme}://{host}:{port}"
    except (TypeError, ValueError):
        return ""


def _settings(config: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
    source = config if config is not None else get_config()
    return source.get("authorized_local_lab_mode", {}) or {}


def allowed_origins(config: Optional[Mapping[str, Any]] = None) -> set[str]:
    settings = _settings(config)
    return {
        origin
        for origin in (normalize_origin(item) for item in settings.get("allowed_origins", []))
        if origin
    }


def issue_preapproval(
    *,
    session_id: str,
    target: str,
    session_context: Mapping[str, Any] | None,
    scan_config: Mapping[str, Any] | None = None,
    config: Optional[Mapping[str, Any]] = None,
) -> LocalLabPreapproval:
    """Issue a per-job preapproval only after session authorization checks."""
    settings = _settings(config)
    origin = normalize_origin(target)
    context = session_context or {}
    requested = bool((scan_config or {}).get("authorized_local_lab_mode", True))

    if not bool(settings.get("enabled", False)):
        return LocalLabPreapproval(False, "authorized local lab mode disabled", origin)
    if not requested:
        return LocalLabPreapproval(False, "job did not request authorized local lab mode", origin)
    if not session_id or not bool(context.get("authorization_confirmed", False)):
        return LocalLabPreapproval(False, "explicit session authorization is required", origin)
    if not origin or origin not in allowed_origins(config):
        return LocalLabPreapproval(False, "target origin is not an allowlisted local lab", origin)

    digest = stable_digest({
        "session_id": session_id,
        "target_origin": origin,
        "allowed_origins": sorted(allowed_origins(config)),
        "policy": dict(settings),
    }, 40)
    return LocalLabPreapproval(
        True,
        "explicitly authorized local lab suite",
        origin,
        f"labpre_{digest}",
        "session_authorization",
    )


def action_target(action: str, fallback_target: str = "") -> str:
    match = _URL_RE.search(str(action or ""))
    return match.group(0).rstrip(".,;:") if match else fallback_target


def allows_action(
    *,
    target: str,
    action: str,
    context_text: str,
    risk: str,
    preapproval: LocalLabPreapproval,
    config: Optional[Mapping[str, Any]] = None,
) -> bool:
    """Return whether an already-issued lab preapproval covers auto-run.

    The preapproval is deliberately not a mutation approval. Explicitly
    authorized private targets outside the local lab are handled by the
    session scope rule in ``SafetyKernel``; this helper only covers the
    bounded detector fast path.
    """
    if not preapproval.approved:
        return False
    settings = _settings(config)
    actual_origin = normalize_origin(action_target(action, target))
    if actual_origin != preapproval.target_origin:
        return False
    allowed_risks = {
        str(item).lower()
        for item in settings.get("allowed_risks", ["medium", "high"])
    }
    if str(risk).lower() not in allowed_risks:
        return False
    if _MUTATING_ACTION_RE.search(f"{action} {context_text}"):
        return False
    return True


def preapproval_from_context(context: Any) -> LocalLabPreapproval:
    """Build the immutable approval value stored on ToolExecutionContext."""
    return LocalLabPreapproval(
        approved=bool(getattr(context, "authorized_lab_mode", False)),
        reason="context preapproval",
        target_origin=str(getattr(context, "authorized_lab_origin", "")),
        preapproval_id=str(getattr(context, "suite_preapproval_id", "")),
        source="session_authorization" if getattr(context, "authorized_lab_mode", False) else "none",
    )

"""Versioned contracts for dynamic multi-identity authorization testing."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.redact import redact


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def normalize_origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return str(value or "").strip().lower().rstrip("/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), "", "", ""))


def resource_fingerprint(resource_type: str, locator: Any, origin: str = "") -> str:
    canonical = json.dumps(
        {"origin": normalize_origin(origin), "type": resource_type.strip().lower(), "locator": locator},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:40]


class AuthorizationModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class IdentityV1(AuthorizationModel):
    identity_id: str = Field(default_factory=lambda: _id("identity"))
    session_id: str = ""
    label: str
    kind: Literal["anonymous", "user", "service", "test"] = "user"
    source: Literal["system", "user_session", "credentials", "approved_registration"] = "user_session"
    role_label: str = ""
    tenant_label: str = ""
    status: Literal["pending", "active", "expired", "invalid", "revoked"] = "pending"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)

    @field_validator("label", "role_label", "tenant_label", mode="before")
    @classmethod
    def clean_labels(cls, value: Any) -> str:
        return redact(str(value or ""))[:200]


class IdentityClaimV1(AuthorizationModel):
    claim_id: str = Field(default_factory=lambda: _id("claim"))
    identity_id: str
    name: str
    value_redacted: str = ""
    source: Literal["user_asserted", "jwt", "browser", "api", "ui", "observation"] = "observation"
    confidence: float = 0.5
    evidence_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)


class AuthContextV1(AuthorizationModel):
    auth_context_id: str = Field(default_factory=lambda: _id("authctx"))
    identity_id: str
    origin: str
    auth_type: Literal["none", "cookie", "bearer", "basic", "storage_state", "mixed"] = "none"
    secret_ref: str = ""
    secret_fingerprint: str = ""
    status: Literal["pending", "active", "expired", "invalid", "revoked"] = "pending"
    expires_at: Optional[str] = None
    last_checked_at: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("origin", mode="before")
    @classmethod
    def normalize_auth_origin(cls, value: Any) -> str:
        return normalize_origin(str(value or ""))


class AuthorizationExpectationV1(AuthorizationModel):
    expectation_id: str = Field(default_factory=lambda: _id("expect"))
    session_id: str
    subject_identity_id: str
    resource_fingerprint: str
    action: str
    expected: Literal["allow", "deny"] = "deny"
    source: Literal["user_asserted", "private_canary", "program_spec"] = "user_asserted"
    reason: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("action", "reason", mode="before")
    @classmethod
    def redact_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:1000]


class RequestTemplateV1(AuthorizationModel):
    template_id: str = Field(default_factory=lambda: _id("template"))
    session_id: str
    origin: str
    method: str = "GET"
    path_template: str
    query_template: Dict[str, Any] = Field(default_factory=dict)
    body_template: Any = None
    header_template: Dict[str, str] = Field(default_factory=dict)
    variable_bindings: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    operation_name: str = ""
    protocol: Literal["http", "graphql", "browser"] = "http"
    side_effect_class: Literal["read", "mutation", "unknown"] = "unknown"
    source_observation_ids: List[str] = Field(default_factory=list)
    fingerprint: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("origin", mode="before")
    @classmethod
    def normalize_template_origin(cls, value: Any) -> str:
        return normalize_origin(str(value or ""))

    def ensure_fingerprint(self) -> "RequestTemplateV1":
        if not self.fingerprint:
            self.fingerprint = hashlib.sha256(json.dumps({
                "origin": self.origin, "method": self.method.upper(),
                "path": self.path_template, "query": self.query_template,
                "operation": self.operation_name, "protocol": self.protocol,
            }, sort_keys=True, default=str).encode()).hexdigest()[:40]
        return self


class ResourceInstanceV1(AuthorizationModel):
    resource_id: str = Field(default_factory=lambda: _id("resource"))
    session_id: str
    resource_type: str
    origin: str
    locator_redacted: Any = None
    locator_ref: str = ""
    fingerprint: str = ""
    owner_identity_id: str = ""
    tenant_label: str = ""
    private_canary: bool = False
    source_observation_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    def ensure_fingerprint(self) -> "ResourceInstanceV1":
        if not self.fingerprint:
            self.fingerprint = resource_fingerprint(self.resource_type, self.locator_redacted, self.origin)
        return self


class ReplayAttemptV1(AuthorizationModel):
    attempt_id: str = Field(default_factory=lambda: _id("attempt"))
    replay_run_id: str
    identity_id: str
    auth_context_id: str = ""
    template_id: str
    resource_fingerprint: str
    observation_id: str = ""
    status: Literal["planned", "running", "succeeded", "failed", "cancelled"] = "planned"
    response_status: Optional[int] = None
    semantic_result: Literal["allow", "deny", "unexpected_allow", "unknown"] = "unknown"
    comparison: Dict[str, Any] = Field(default_factory=dict)
    side_effects: List[Dict[str, Any]] = Field(default_factory=list)
    cleanup_refs: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)


class AuthorizationReplayRunV1(AuthorizationModel):
    replay_run_id: str = Field(default_factory=lambda: _id("replay"))
    session_id: str
    template_id: str
    resource_fingerprint: str
    owner_identity_id: str
    test_identity_ids: List[str] = Field(default_factory=list)
    expectation_ids: List[str] = Field(default_factory=list)
    mutation_approved: bool = False
    status: Literal["planned", "running", "succeeded", "partial", "failed", "cancelled"] = "planned"
    attempts: List[ReplayAttemptV1] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)


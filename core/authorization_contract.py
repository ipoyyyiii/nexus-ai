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


class AuthSurfaceObservationV1(AuthorizationModel):
    """Redacted observation of an authentication/session boundary.

    This records *what* auth behavior was observed, never the credential,
    cookie, token, code, verifier, or redirect value itself.  It is a
    discovery contract only; it cannot promote a candidate finding.
    """

    observation_id: str = Field(default_factory=lambda: _id("authobs"))
    session_id: str
    origin: str
    endpoint_reference_id: str = ""
    event: Literal[
        "login", "register", "logout", "reset", "mfa", "oauth_authorize",
        "oauth_callback", "token_issue", "token_refresh", "token_revoke",
        "session_check", "session_rotation", "unknown",
    ] = "unknown"
    mechanism: Literal[
        "password", "session_cookie", "bearer", "api_key", "oauth",
        "oidc", "pkce", "mfa", "basic", "mixed", "unknown",
    ] = "unknown"
    auth_state: Literal["anonymous", "authenticated", "unknown"] = "unknown"
    identity_id: str = ""
    auth_context_id: str = ""
    redirect_uri_digest: str = ""
    issuer_digest: str = ""
    audience_digest: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    status: Literal["observed", "inconclusive", "stale"] = "observed"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("origin", mode="before")
    @classmethod
    def normalize_surface_origin(cls, value: Any) -> str:
        return normalize_origin(str(value or ""))

    @field_validator("metadata", mode="before")
    @classmethod
    def redact_surface_metadata(cls, value: Any) -> Dict[str, Any]:
        return redact(value or {})


class SessionTransitionV1(AuthorizationModel):
    """Append-only lifecycle event for an isolated auth context."""

    transition_id: str = Field(default_factory=lambda: _id("authtransition"))
    session_id: str
    identity_id: str = ""
    auth_context_id: str = ""
    origin: str = ""
    event: Literal[
        "login", "session_created", "session_rotation", "logout",
        "revoke", "refresh", "expiry", "invalid", "unknown",
    ] = "unknown"
    before_status: str = "unknown"
    after_status: str = "unknown"
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    clean_context: bool = False
    state_digest: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("origin", mode="before")
    @classmethod
    def normalize_transition_origin(cls, value: Any) -> str:
        return normalize_origin(str(value or ""))

    @field_validator("metadata", mode="before")
    @classmethod
    def redact_transition_metadata(cls, value: Any) -> Dict[str, Any]:
        return redact(value or {})


class WorkflowPrerequisiteV1(AuthorizationModel):
    """Typed prerequisite edge for a workflow state machine."""

    prerequisite_id: str = Field(default_factory=lambda: _id("prereq"))
    session_id: str
    workflow_id: str
    workflow_version: int = 1
    kind: Literal[
        "identity", "auth_context", "role", "tenant", "entity", "state",
        "previous_step", "operator_input", "approval", "cleanup",
    ]
    reference_id: str = ""
    label: str = ""
    required: bool = True
    status: Literal["observed", "missing", "inconclusive", "satisfied", "stale"] = "observed"
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("label", mode="before")
    @classmethod
    def redact_prerequisite_label(cls, value: Any) -> str:
        return redact(str(value or ""))[:500]

    @field_validator("metadata", mode="before")
    @classmethod
    def redact_prerequisite_metadata(cls, value: Any) -> Dict[str, Any]:
        return redact(value or {})


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


class IdentityRelationV1(AuthorizationModel):
    """Evidence-backed relation in a session-local identity graph.

    This is intentionally additive to the existing IdentityV1 contract.  A
    relation is never treated as authoritative merely because it has a high
    confidence value; the referenced evidence and graph version are required
    by the planner before a workflow can consume it.
    """

    relation_id: str = Field(default_factory=lambda: _id("rel"))
    session_id: str
    graph_version: int = 1
    subject_id: str
    relation: Literal[
        "auth_context_for", "member_of_tenant", "role_of", "owns",
        "can_access", "same_principal", "derived_from", "requires_role",
        "uses_workflow", "has_session_state", "trust_boundary_for",
    ]
    object_id: str
    evidence_ids: List[str] = Field(default_factory=list)
    source: Literal["user_asserted", "observation", "browser", "api", "operator"] = "observation"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    status: Literal["proposed", "active", "rejected", "retired"] = "proposed"
    created_at: str = Field(default_factory=now_iso)


class IdentityGraphV1(AuthorizationModel):
    """Immutable, session-scoped snapshot of identity and trust relations."""

    graph_id: str = Field(default_factory=lambda: _id("graph"))
    session_id: str
    version: int = 1
    node_ids: List[str] = Field(default_factory=list)
    relations: List[IdentityRelationV1] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    gaps: List[str] = Field(default_factory=list)
    digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    def ensure_digest(self) -> "IdentityGraphV1":
        if not self.digest:
            payload = {
                "session_id": self.session_id,
                "version": self.version,
                "node_ids": sorted(self.node_ids),
                "relations": [item.model_dump(mode="json") for item in self.relations],
                "evidence_ids": sorted(self.evidence_ids),
            }
            self.digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
            ).hexdigest()
        return self


class IdentityCoveragePlanV1(AuthorizationModel):
    """Deterministic precondition plan for cross-identity testing."""

    plan_id: str = Field(default_factory=lambda: _id("idplan"))
    session_id: str
    graph_id: str
    required_identity_ids: List[str] = Field(default_factory=list)
    required_relations: List[str] = Field(default_factory=list)
    required_resource_fingerprints: List[str] = Field(default_factory=list)
    required_auth_context_ids: List[str] = Field(default_factory=list)
    missing_requirements: List[str] = Field(default_factory=list)
    status: Literal["ready", "blocked", "inconclusive"] = "blocked"
    digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    def ensure_digest(self) -> "IdentityCoveragePlanV1":
        if not self.digest:
            payload = {
                "session_id": self.session_id,
                "graph_id": self.graph_id,
                "required_identity_ids": sorted(self.required_identity_ids),
                "required_relations": sorted(self.required_relations),
                "required_resource_fingerprints": sorted(self.required_resource_fingerprints),
                "required_auth_context_ids": sorted(self.required_auth_context_ids),
                "missing_requirements": sorted(self.missing_requirements),
                "status": self.status,
            }
            self.digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
            ).hexdigest()
        return self


class IdentityWorkflowIntelligenceV1(AuthorizationModel):
    """Immutable, redacted Stage 26 intelligence snapshot.

    The snapshot joins the already-existing identity graph, auth observations,
    session transitions, published workflows, and prerequisites. It is a
    planning/coverage artifact; it is not authorization proof and never owns
    finding status.
    """

    intelligence_id: str = Field(default_factory=lambda: _id("iwintel"))
    session_id: str
    graph_id: str = ""
    graph_version: int = 0
    auth_surface_ids: List[str] = Field(default_factory=list)
    transition_ids: List[str] = Field(default_factory=list)
    workflow_ids: List[str] = Field(default_factory=list)
    prerequisite_ids: List[str] = Field(default_factory=list)
    identity_ids: List[str] = Field(default_factory=list)
    auth_context_ids: List[str] = Field(default_factory=list)
    trust_boundary_ids: List[str] = Field(default_factory=list)
    gaps: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)
    status: Literal["current", "inconclusive", "stale"] = "current"
    digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    def ensure_digest(self) -> "IdentityWorkflowIntelligenceV1":
        if not self.digest:
            payload = self.model_dump(mode="json", exclude={"digest", "created_at"})
            self.digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
            ).hexdigest()
        return self

"""Versioned contracts for the canonical target knowledge graph.

The knowledge graph describes target facts and coverage.  It is deliberately
separate from the Stage 14 mission graph: missions choose bounded actions,
while this graph records what is known, how it was observed, and what remains
untested.  No model output can become a canonical fact without structured
provenance.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import Field, field_validator

from core.execution_contract import ExecutionModel, now_iso, stable_digest
from core.redact import redact


KnowledgeStatus = Literal[
    "hypothesized", "observed", "supported", "stale", "contradictory",
    "blocked", "inconclusive", "validated", "disproven",
]
KnowledgeNodeType = Literal[
    "asset", "origin", "service", "endpoint", "operation", "parameter",
    "input", "schema", "identity", "role", "tenant", "auth_context",
    "entity", "resource", "workflow", "state", "protocol", "trust_boundary",
    "observation", "candidate", "finding", "capability", "cleanup",
    "ip_address", "certificate", "dns_record", "redirect", "technology",
    "waf_profile", "provider_observation", "auth_surface", "session_transition",
    "prerequisite",
]
KnowledgeEdgeRelation = Literal[
    "contains", "serves", "exposes", "accepts", "requires_auth",
    "uses_identity", "member_of", "owns", "same_entity", "reachable_via",
    "transitions_to", "observed_in", "tested_by", "equivalent_to",
    "contradicted_by", "blocked_by", "derived_from", "resolves_to",
    "aliases", "covered_by_certificate", "redirects_to", "hosts_service",
    "uses_technology", "protected_by_waf", "reported_by_provider",
    "historically_exposed", "requires_identity", "requires_role",
    "requires_state", "starts_session", "rotates_session", "invalidates_session",
    "guards", "uses_auth_context", "prerequisite_for",
]
CoverageStatus = Literal[
    "untested", "planned", "in_progress", "tested", "validated",
    "disproven", "inconclusive", "blocked", "stale", "not_applicable",
]
ContradictionStatus = Literal["unresolved", "reviewed", "resolved", "stale"]
MemoryStatus = Literal["current", "historical", "stale", "rejected"]


def _unwrap_markdown_url(value: str) -> str:
    """Accept copied Markdown links without storing markup as a locator."""
    text = str(value or "").strip()
    match = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", text)
    return match.group(2).strip() if match else text


def normalize_origin(value: str) -> str:
    parsed = urlsplit(_unwrap_markdown_url(value))
    if not parsed.scheme or not parsed.netloc:
        return _unwrap_markdown_url(value).lower().rstrip("/")
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    netloc = hostname
    if port and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
        netloc = f"{hostname}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


def normalize_path(value: str) -> str:
    parsed = urlsplit(_unwrap_markdown_url(value))
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def normalize_locator(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k).lower(): normalize_locator(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, list):
        return [normalize_locator(item) for item in value]
    if isinstance(value, str):
        return value.strip().lower()
    return value


class KnowledgeContract(ExecutionModel):
    """Shared model settings for every graph boundary."""


class ReconAssetObservationV1(KnowledgeContract):
    """Redacted perimeter fact consumed by the existing knowledge graph.

    This is an observation contract, not a finding contract.  Historical or
    provider-derived assets remain unverified until a guarded live check
    confirms them.
    """

    schema_version: Literal["22.0"] = "22.0"
    reference_id: str
    asset_kind: Literal[
        "hostname", "ip_address", "certificate", "dns_record", "redirect",
        "technology", "waf_profile", "provider_observation",
    ] = "hostname"
    locator: str = ""
    status: KnowledgeStatus = "observed"
    source: str = ""
    freshness: Literal["live", "historical", "stale", "unknown"] = "unknown"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("reference_id", "locator", "source", mode="before")
    @classmethod
    def redact_asset_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def as_graph_source(self) -> Dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "node_type": self.asset_kind,
            "url": self.locator,
            "canonical_locator": self.locator,
            "status": self.status,
            "evidence_ids": self.evidence_ids,
            "source_ids": self.source_ids,
            "metadata": redact({
                **self.metadata,
                "source": self.source,
                "freshness": self.freshness,
                "confidence": self.confidence,
            }),
        }


class WafProfileV1(KnowledgeContract):
    """Machine-readable WAF profile; never a vulnerability decision."""

    schema_version: Literal["22.0"] = "22.0"
    target: str
    vendor: str = "unknown"
    mode: Literal["passive", "authorized_behavior"] = "passive"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    estimated_threshold: str = "inconclusive"
    evidence: List[str] = Field(default_factory=list)
    strategy: Dict[str, Any] = Field(default_factory=dict)
    source_ids: List[str] = Field(default_factory=list)

    @field_validator("target", "vendor", "estimated_threshold", mode="before")
    @classmethod
    def redact_waf_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def as_graph_source(self) -> Dict[str, Any]:
        return {
            "reference_id": f"waf-{stable_digest({'target': self.target, 'vendor': self.vendor}, 24)}",
            "node_type": "waf_profile",
            "url": self.target,
            "label": self.vendor,
            "status": "observed",
            "evidence_ids": list(self.evidence),
            "source_ids": list(self.source_ids),
            "metadata": redact({
                "mode": self.mode,
                "confidence": self.confidence,
                "estimated_threshold": self.estimated_threshold,
                "strategy": self.strategy,
            }),
        }


class SurfaceEndpointV1(KnowledgeContract):
    """A discovered surface endpoint, never a vulnerability finding."""

    schema_version: Literal["23.0"] = "23.0"
    reference_id: str
    locator: str
    method: str = "GET"
    endpoint_kind: Literal[
        "page", "api", "graphql", "websocket", "sse", "form",
        "script", "static", "redirect", "schema", "unknown",
    ] = "unknown"
    status: KnowledgeStatus = "observed"
    freshness: Literal["live", "historical", "unknown"] = "live"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    content_type: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("reference_id", "locator", "content_type", mode="before")
    @classmethod
    def redact_surface_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def as_graph_source(self) -> Dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "node_type": "endpoint",
            "url": self.locator,
            "protocol": {"websocket": "websocket", "sse": "sse", "graphql": "graphql"}.get(self.endpoint_kind, "http"),
            "method": self.method.upper(),
            "status": self.status,
            "evidence_ids": self.evidence_ids,
            "source_ids": self.source_ids,
            "metadata": redact({
                **self.metadata,
                "endpoint_kind": self.endpoint_kind,
                "freshness": self.freshness,
                "confidence": self.confidence,
                "content_type": self.content_type,
            }),
        }


class SurfaceParameterV1(KnowledgeContract):
    """A parameter/input observation associated with one endpoint."""

    schema_version: Literal["23.0"] = "23.0"
    reference_id: str
    endpoint_reference_id: str
    name: str
    location: Literal["query", "path", "body", "header", "cookie", "form", "unknown"] = "unknown"
    method: str = "GET"
    required: bool = False
    data_type: str = "unknown"
    status: KnowledgeStatus = "observed"
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("reference_id", "endpoint_reference_id", "name", "data_type", mode="before")
    @classmethod
    def redact_parameter_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:500]

    def as_graph_source(self) -> Dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "node_type": "parameter",
            "url": self.name,
            "method": self.method.upper(),
            "parameter_name": self.name,
            "parameter_location": self.location,
            "status": self.status,
            "evidence_ids": self.evidence_ids,
            "source_ids": self.source_ids,
            "metadata": redact({
                **self.metadata,
                "endpoint_reference_id": self.endpoint_reference_id,
                "required": self.required,
                "data_type": self.data_type,
            }),
        }


class SurfaceInventoryV1(KnowledgeContract):
    """Immutable surface snapshot assembled from multiple recon lanes."""

    schema_version: Literal["23.0"] = "23.0"
    target: str
    endpoints: List[Dict[str, Any]] = Field(default_factory=list)
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    schemas: List[Dict[str, Any]] = Field(default_factory=list)
    static_assets: List[Dict[str, Any]] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    digest: str = ""

    @field_validator("target", mode="before")
    @classmethod
    def redact_inventory_target(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def finalize(self) -> "SurfaceInventoryV1":
        self.digest = stable_digest({
            "target": self.target,
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "schemas": self.schemas,
            "static_assets": self.static_assets,
        }, 64)
        return self


class TechnologySignalV1(KnowledgeContract):
    """A redacted, source-linked signal used for technology inference.

    Signals are not findings and are never sufficient to assert an exact
    version by themselves.  They are intentionally smaller than a response
    body so headers, cookie names, asset paths, and protocol hints can be
    correlated without persisting secrets or raw target content.
    """

    schema_version: Literal["24.0"] = "24.0"
    signal_id: str
    category: Literal[
        "server", "runtime", "framework", "cms", "library", "cdn", "waf",
        "auth", "protocol", "database", "deployment", "security_control",
        "tls", "cache", "unknown",
    ] = "unknown"
    name: str
    value: str
    source_kind: Literal[
        "header", "cookie_metadata", "html", "asset_path", "javascript",
        "protocol", "schema", "tls", "waf_behavior", "tool_summary", "unknown",
    ] = "unknown"
    target: str = ""
    endpoint_reference_id: str = ""
    reliability: float = Field(default=0.5, ge=0.0, le=1.0)
    freshness: Literal["live", "historical", "unknown"] = "live"
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("signal_id", "name", "value", "source_kind", "target", mode="before")
    @classmethod
    def redact_signal_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:500]

    def as_graph_source(self) -> Dict[str, Any]:
        return {
            "reference_id": self.signal_id,
            "node_type": "observation",
            "url": self.target or self.endpoint_reference_id or "technology://signal",
            "label": self.name,
            "status": "observed",
            "evidence_ids": list(self.evidence_ids),
            "source_ids": list(self.source_ids),
            "metadata": redact({
                "technology_signal": True,
                "category": self.category,
                "value": self.value,
                "source_kind": self.source_kind,
                "endpoint_reference_id": self.endpoint_reference_id,
                "reliability": self.reliability,
                "freshness": self.freshness,
                **self.metadata,
            }),
        }


class TechnologyFingerprintV1(KnowledgeContract):
    """A deterministic technology claim assembled from independent signals."""

    schema_version: Literal["24.0"] = "24.0"
    fingerprint_id: str
    target: str
    family: Literal[
        "server", "runtime", "framework", "cms", "library", "cdn", "waf",
        "auth", "protocol", "database", "deployment", "security_control",
        "tls", "cache", "unknown",
    ] = "unknown"
    name: str
    version: str = ""
    version_status: Literal["confirmed", "inferred", "unknown", "conflicted"] = "unknown"
    status: Literal["observed", "supported", "inconclusive", "contradictory", "stale"] = "observed"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    freshness: Literal["live", "historical", "unknown"] = "live"
    signal_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    capability_hints: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("fingerprint_id", "target", "name", "version", mode="before")
    @classmethod
    def redact_fingerprint_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:1000]

    def as_graph_source(self) -> Dict[str, Any]:
        # The locator is stable per family/name; fact_key/fact_value allow
        # the graph compiler to surface conflicting values as contradictions.
        locator = f"technology://{self.family}/{self.name.lower().replace(' ', '_')}"
        return {
            "reference_id": self.fingerprint_id,
            "node_type": "technology",
            "url": locator,
            "label": self.name,
            "status": self.status,
            "fact_key": f"technology:{self.family}",
            "fact_value": f"{self.name}@{self.version}" if self.version else self.name,
            "evidence_ids": list(self.evidence_ids),
            "source_ids": list(self.source_ids),
            "metadata": redact({
                "target": self.target,
                "family": self.family,
                "version": self.version,
                "version_status": self.version_status,
                "confidence": self.confidence,
                "freshness": self.freshness,
                "signal_ids": self.signal_ids,
                "capability_hints": self.capability_hints,
                **self.metadata,
            }),
        }


class TechnologyCapabilityV1(KnowledgeContract):
    """A bounded test capability suggestion derived from a fingerprint."""

    schema_version: Literal["24.0"] = "24.0"
    capability_id: str
    capability: str
    reason: str
    risk: Literal["read_only", "mutation", "raw_network"] = "read_only"
    approval_required: bool = False
    prerequisites: List[str] = Field(default_factory=list)
    fingerprint_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    status: Literal["suggested", "blocked", "inconclusive"] = "suggested"

    @field_validator("capability_id", "capability", "reason", mode="before")
    @classmethod
    def redact_capability_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:1000]


class ApiOperationV1(KnowledgeContract):
    """Semantic operation inferred from an already observed surface endpoint.

    This is reconnaissance metadata, not an authorization or vulnerability
    result.  An operation is only canonical when it remains linked to the
    endpoint, source, and evidence that produced it.
    """

    schema_version: Literal["25.0"] = "25.0"
    operation_id: str
    endpoint_reference_id: str
    method: str = "GET"
    path: str = "/"
    operation_kind: Literal[
        "read", "create", "update", "delete", "auth", "transition",
        "upload", "stream", "schema", "unknown",
    ] = "unknown"
    auth_expectation: Literal["anonymous", "authenticated", "ambiguous", "unknown"] = "unknown"
    side_effect: Literal["none", "state_change", "unknown"] = "unknown"
    identity_hints: List[str] = Field(default_factory=list)
    tenant_hints: List[str] = Field(default_factory=list)
    entity_hints: List[str] = Field(default_factory=list)
    parameter_reference_ids: List[str] = Field(default_factory=list)
    schema_reference_ids: List[str] = Field(default_factory=list)
    prerequisite_capabilities: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    status: KnowledgeStatus = "observed"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "operation_id", "endpoint_reference_id", "path", "method",
        "identity_hints", "tenant_hints", "entity_hints", "metadata",
        mode="before",
    )
    @classmethod
    def redact_operation_text(cls, value: Any) -> Any:
        return redact(value)

    def as_graph_source(self) -> Dict[str, Any]:
        return {
            "reference_id": self.operation_id,
            "node_type": "operation",
            "url": self.path,
            "method": self.method.upper(),
            "status": self.status,
            "evidence_ids": list(dict.fromkeys(self.evidence_ids)),
            "source_ids": list(dict.fromkeys(self.source_ids)),
            "metadata": redact({
                **self.metadata,
                "endpoint_reference_id": self.endpoint_reference_id,
                "operation_kind": self.operation_kind,
                "auth_expectation": self.auth_expectation,
                "side_effect": self.side_effect,
                "identity_hints": self.identity_hints,
                "tenant_hints": self.tenant_hints,
                "entity_hints": self.entity_hints,
                "parameter_reference_ids": self.parameter_reference_ids,
                "schema_reference_ids": self.schema_reference_ids,
                "prerequisite_capabilities": self.prerequisite_capabilities,
                "confidence": self.confidence,
            }),
        }


class InputSemanticV1(KnowledgeContract):
    """Safe semantic classification for a discovered input name.

    Classification is intentionally heuristic and bounded.  It guides later
    planning but cannot promote a vulnerability or authorize a mutation.
    """

    schema_version: Literal["25.0"] = "25.0"
    semantic_id: str
    parameter_reference_id: str
    endpoint_reference_id: str
    name: str
    location: str = "unknown"
    semantic_type: Literal[
        "identifier", "tenant", "identity", "role", "state", "money",
        "redirect", "file", "search", "pagination", "credential",
        "csrf", "filter", "unknown",
    ] = "unknown"
    sensitivity: Literal["public", "user_scoped", "privileged", "secret_like", "unknown"] = "unknown"
    mutation_relevance: Literal["none", "possible", "likely", "unknown"] = "unknown"
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    status: KnowledgeStatus = "observed"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("semantic_id", "parameter_reference_id", "endpoint_reference_id", "name", mode="before")
    @classmethod
    def redact_input_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:500]

    def as_graph_source(self) -> Dict[str, Any]:
        return {
            "reference_id": self.semantic_id,
            "node_type": "input",
            # Include the endpoint in the locator so the graph compiler does
            # not collapse two same-named fields from different operations.
            "url": f"/{self.endpoint_reference_id}/{self.name}",
            "method": "",
            "parameter_name": self.name,
            "parameter_location": self.location,
            "status": self.status,
            "evidence_ids": list(dict.fromkeys(self.evidence_ids)),
            "source_ids": list(dict.fromkeys(self.source_ids)),
            "metadata": redact({
                **self.metadata,
                "parameter_reference_id": self.parameter_reference_id,
                "endpoint_reference_id": self.endpoint_reference_id,
                "semantic_type": self.semantic_type,
                "sensitivity": self.sensitivity,
                "mutation_relevance": self.mutation_relevance,
                "confidence": self.confidence,
            }),
        }


class ApplicationContractInventoryV1(KnowledgeContract):
    """Immutable, redacted application contract snapshot for planning."""

    schema_version: Literal["25.0"] = "25.0"
    target: str
    operations: List[Dict[str, Any]] = Field(default_factory=list)
    input_semantics: List[Dict[str, Any]] = Field(default_factory=list)
    schemas: List[Dict[str, Any]] = Field(default_factory=list)
    data_flows: List[Dict[str, Any]] = Field(default_factory=list)
    contradictions: List[Dict[str, Any]] = Field(default_factory=list)
    capability_hints: List[Dict[str, Any]] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    digest: str = ""

    @field_validator("target", mode="before")
    @classmethod
    def redact_contract_target(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def finalize(self) -> "ApplicationContractInventoryV1":
        self.digest = stable_digest({
            "target": self.target,
            "operations": self.operations,
            "input_semantics": self.input_semantics,
            "schemas": self.schemas,
            "data_flows": self.data_flows,
            "contradictions": self.contradictions,
            "capability_hints": self.capability_hints,
        }, 64)
        return self

class KnowledgeNodeV1(KnowledgeContract):
    schema_version: Literal["1.0"] = "1.0"
    node_id: str = Field(default_factory=lambda: f"knode_{uuid.uuid4().hex}")
    graph_id: str
    graph_version: int = 1
    session_id: str
    node_type: KnowledgeNodeType
    reference_id: str
    canonical_locator: str = ""
    label: str = ""
    protocol: str = "http"
    method: str = ""
    parameter_location: str = ""
    parameter_name: str = ""
    identity_id: str = ""
    tenant_label: str = ""
    entity_fingerprint: str = ""
    status: KnowledgeStatus = "observed"
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = ""
    observed_at: str = Field(default_factory=now_iso)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("label", "canonical_locator", "parameter_name", "tenant_label", mode="before")
    @classmethod
    def clean_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def ensure_fingerprint(self) -> "KnowledgeNodeV1":
        self.canonical_locator = self.canonical_locator or self.reference_id
        if not self.fingerprint:
            self.fingerprint = stable_digest({
                "node_type": self.node_type,
                "locator": normalize_locator(self.canonical_locator),
                "method": self.method.upper(),
                "parameter_location": self.parameter_location.lower(),
                "parameter_name": self.parameter_name.lower(),
                "protocol": self.protocol.lower(),
                "identity_id": self.identity_id,
                "tenant_label": self.tenant_label.lower(),
                "entity_fingerprint": self.entity_fingerprint,
            }, 64)
        return self


class KnowledgeEdgeV1(KnowledgeContract):
    schema_version: Literal["1.0"] = "1.0"
    edge_id: str = Field(default_factory=lambda: f"kedge_{uuid.uuid4().hex}")
    graph_id: str
    graph_version: int = 1
    session_id: str
    source_node_id: str
    target_node_id: str
    relation: KnowledgeEdgeRelation
    status: KnowledgeStatus = "observed"
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = ""
    observed_at: str = Field(default_factory=now_iso)
    created_at: str = Field(default_factory=now_iso)

    def ensure_fingerprint(self) -> "KnowledgeEdgeV1":
        if not self.fingerprint:
            self.fingerprint = stable_digest({
                "source": self.source_node_id,
                "target": self.target_node_id,
                "relation": self.relation,
                "metadata": normalize_locator(self.metadata),
            }, 64)
        return self


class KnowledgeSourceLinkV1(KnowledgeContract):
    schema_version: Literal["1.0"] = "1.0"
    link_id: str = Field(default_factory=lambda: f"ksource_{uuid.uuid4().hex}")
    graph_id: str
    graph_version: int
    session_id: str
    node_id: str = ""
    edge_id: str = ""
    source_kind: str = "observation"
    source_id: str
    evidence_ids: List[str] = Field(default_factory=list)
    input_digest: str = ""
    created_at: str = Field(default_factory=now_iso)


class TargetKnowledgeGraphV1(KnowledgeContract):
    schema_version: Literal["1.0"] = "1.0"
    graph_id: str = Field(default_factory=lambda: f"kgraph_{uuid.uuid4().hex}")
    session_id: str
    target_fingerprint: str
    scope_fingerprint: str = ""
    version: int = 1
    parent_graph_id: str = ""
    node_ids: List[str] = Field(default_factory=list)
    edge_ids: List[str] = Field(default_factory=list)
    contradiction_ids: List[str] = Field(default_factory=list)
    coverage_snapshot_id: str = ""
    source_digests: List[str] = Field(default_factory=list)
    digest: str = ""
    status: Literal["draft", "current", "stale", "superseded", "failed"] = "draft"
    policy_version: str = "1.0"
    created_at: str = Field(default_factory=now_iso)

    def ensure_digest(self) -> "TargetKnowledgeGraphV1":
        if not self.digest:
            self.digest = stable_digest({
                "session_id": self.session_id,
                "target_fingerprint": self.target_fingerprint,
                "scope_fingerprint": self.scope_fingerprint,
                "version": self.version,
                "parent_graph_id": self.parent_graph_id,
                "node_ids": sorted(self.node_ids),
                "edge_ids": sorted(self.edge_ids),
                "contradiction_ids": sorted(self.contradiction_ids),
                "source_digests": sorted(self.source_digests),
                "policy_version": self.policy_version,
            }, 64)
        return self


class CoverageItemV1(KnowledgeContract):
    schema_version: Literal["1.0"] = "1.0"
    coverage_id: str = Field(default_factory=lambda: f"coverage_{uuid.uuid4().hex}")
    graph_id: str
    graph_version: int
    session_id: str
    target_fingerprint: str
    asset_node_id: str = ""
    endpoint_node_id: str = ""
    operation_node_id: str = ""
    parameter_node_id: str = ""
    identity_id: str = ""
    auth_context_id: str = ""
    tenant_label: str = ""
    entity_fingerprint: str = ""
    workflow_id: str = ""
    state_label: str = ""
    protocol: str = "http"
    policy_id: str = ""
    status: CoverageStatus = "untested"
    evidence_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    required_prerequisites: List[str] = Field(default_factory=list)
    gap_reason: str = ""
    last_tested_at: Optional[str] = None
    input_digest: str = ""
    fingerprint: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("gap_reason", mode="before")
    @classmethod
    def redact_reason(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def ensure_fingerprint(self) -> "CoverageItemV1":
        if not self.fingerprint:
            self.fingerprint = stable_digest({
                "target": self.target_fingerprint,
                "asset": self.asset_node_id,
                "endpoint": self.endpoint_node_id,
                "operation": self.operation_node_id,
                "parameter": self.parameter_node_id,
                "identity": self.identity_id,
                "auth": self.auth_context_id,
                "tenant": self.tenant_label.lower(),
                "entity": self.entity_fingerprint,
                "workflow": self.workflow_id,
                "state": self.state_label.lower(),
                "protocol": self.protocol.lower(),
                "policy": self.policy_id,
            }, 64)
        # Coverage is append-only and may be ingested repeatedly after a
        # worker retry or a graph replay. Use the content fingerprint as the
        # stable primary key instead of a random UUID so duplicate ingestion
        # remains idempotent.
        self.coverage_id = f"coverage_{stable_digest({'graph': self.graph_id, 'fingerprint': self.fingerprint}, 32)}"
        return self


class CoverageGapV1(KnowledgeContract):
    schema_version: Literal["1.0"] = "1.0"
    gap_id: str = Field(default_factory=lambda: f"gap_{uuid.uuid4().hex}")
    coverage_id: str
    graph_id: str
    graph_version: int
    session_id: str
    reason: str
    priority: float = Field(default=0.0, ge=0.0, le=1.0)
    missing_prerequisites: List[str] = Field(default_factory=list)
    suggested_capabilities: List[str] = Field(default_factory=list)
    blocked: bool = False
    diagnostic_only: bool = False
    created_at: str = Field(default_factory=now_iso)


class ReconNextActionV1(KnowledgeContract):
    """A bounded, read-only action proposed by recon closure synthesis.

    This is planning metadata only.  It is never a tool invocation, mutation,
    approval, or vulnerability decision.  Dispatch still goes through the
    existing planner and safety kernel.
    """

    schema_version: Literal["27.0"] = "27.0"
    action_id: str
    kind: Literal[
        "collect_perimeter", "map_surface", "fingerprint_technology",
        "compile_application_contract", "map_identity_workflow",
        "refresh_historical_asset", "revalidate_stale_evidence",
        "resolve_contradiction", "complete_coverage", "stop",
    ] = "complete_coverage"
    target_reference_ids: List[str] = Field(default_factory=list)
    source_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    reason: str = ""
    priority_score: float = Field(default=0.0, ge=0.0, le=1.0)
    estimated_information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    risk: Literal["read_only"] = "read_only"
    approval_required: bool = False
    required_prerequisites: List[str] = Field(default_factory=list)
    freshness_boundary: str = ""
    status: Literal["ready", "blocked", "inconclusive", "stale"] = "ready"
    created_at: str = Field(default_factory=now_iso)

    @field_validator("reason", "freshness_boundary", mode="before")
    @classmethod
    def redact_action_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def ensure_id(self) -> "ReconNextActionV1":
        if not self.action_id:
            material = {
                "kind": self.kind,
                "targets": sorted(self.target_reference_ids),
                "reason": self.reason,
                "prerequisites": sorted(self.required_prerequisites),
            }
            self.action_id = f"recon_action_{stable_digest(material, 32)}"
        return self


class ReconLaneSummaryV1(KnowledgeContract):
    """Completeness and freshness summary for one passive recon lane."""

    schema_version: Literal["27.0"] = "27.0"
    lane: Literal[
        "perimeter", "surface", "technology", "application_contract",
        "identity_workflow",
    ]
    observed_count: int = Field(default=0, ge=0)
    evidence_linked_count: int = Field(default=0, ge=0)
    stale_count: int = Field(default=0, ge=0)
    contradictory_count: int = Field(default=0, ge=0)
    coverage_count: int = Field(default=0, ge=0)
    gap_count: int = Field(default=0, ge=0)
    completeness: float = Field(default=0.0, ge=0.0, le=1.0)
    status: Literal["complete", "partial", "missing", "inconclusive"] = "missing"


class ReconClosurePlanV1(KnowledgeContract):
    """Immutable synthesis of all recon lanes for the next bounded phase."""

    schema_version: Literal["27.0"] = "27.0"
    plan_id: str = Field(default_factory=lambda: f"recon_plan_{uuid.uuid4().hex}")
    session_id: str
    target_fingerprint: str
    graph_id: str = ""
    graph_version: int = 0
    graph_digest: str = ""
    source_digest: str = ""
    freshness_boundary: str = ""
    lanes: List[ReconLaneSummaryV1] = Field(default_factory=list)
    coverage_total: int = Field(default=0, ge=0)
    covered_count: int = Field(default=0, ge=0)
    gap_count: int = Field(default=0, ge=0)
    blocked_gap_count: int = Field(default=0, ge=0)
    stale_gap_count: int = Field(default=0, ge=0)
    inconclusive_gap_count: int = Field(default=0, ge=0)
    contradiction_count: int = Field(default=0, ge=0)
    provenance_completeness: float = Field(default=0.0, ge=0.0, le=1.0)
    freshness_completeness: float = Field(default=0.0, ge=0.0, le=1.0)
    next_actions: List[ReconNextActionV1] = Field(default_factory=list)
    status: Literal["ready", "inconclusive", "blocked"] = "ready"
    stop_reason: Literal[
        "coverage_complete", "no_information_gain", "contradictions_pending",
        "blocked", "stale_evidence", "operator",
    ] = "no_information_gain"
    replay_digest: str = ""
    digest: str = ""
    redaction_leaks: int = Field(default=0, ge=0)
    created_at: str = Field(default_factory=now_iso)

    def ensure_digest(self) -> "ReconClosurePlanV1":
        def stable_dump(item: Any) -> Dict[str, Any]:
            value = item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item)
            value.pop("created_at", None)
            return value

        self.replay_digest = stable_digest({
            "graph_digest": self.graph_digest,
            "source_digest": self.source_digest,
            "lanes": [stable_dump(item) for item in self.lanes],
            "coverage": [self.coverage_total, self.covered_count, self.gap_count],
            "contradictions": self.contradiction_count,
            "actions": [stable_dump(item) for item in self.next_actions],
            "status": self.status,
            "stop_reason": self.stop_reason,
        }, 64)
        self.digest = self.replay_digest
        return self


class ContradictionSetV1(KnowledgeContract):
    schema_version: Literal["1.0"] = "1.0"
    contradiction_id: str = Field(default_factory=lambda: f"contradiction_{uuid.uuid4().hex}")
    graph_id: str
    graph_version: int
    session_id: str
    subject_fingerprint: str
    predicate: str
    conflicting_node_ids: List[str] = Field(default_factory=list)
    conflicting_edge_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    status: ContradictionStatus = "unresolved"
    review_reason: str = ""
    reviewer_id: str = ""
    created_at: str = Field(default_factory=now_iso)

    @field_validator("review_reason", "reviewer_id", mode="before")
    @classmethod
    def redact_review(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class TargetMemoryRecordV1(KnowledgeContract):
    schema_version: Literal["1.0"] = "1.0"
    memory_id: str = Field(default_factory=lambda: f"kmemory_{uuid.uuid4().hex}")
    session_id: str = ""
    source_session_id: str = ""
    target_fingerprint: str
    scope_fingerprint: str = ""
    graph_id: str = ""
    graph_version: int = 0
    memory_type: str
    content: Dict[str, Any] = Field(default_factory=dict)
    source_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    source_digest: str = ""
    status: MemoryStatus = "current"
    observed_at: str = Field(default_factory=now_iso)
    expires_at: Optional[str] = None
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.content = redact(self.content)
        if not self.source_digest:
            self.source_digest = stable_digest({
                "target": self.target_fingerprint,
                "scope": self.scope_fingerprint,
                "type": self.memory_type,
                "content": self.content,
                "source_ids": sorted(self.source_ids),
                "evidence_ids": sorted(self.evidence_ids),
            }, 64)


class KnowledgeProposalV1(KnowledgeContract):
    """LLM/heuristic suggestion; never a canonical graph write."""

    schema_version: Literal["1.0"] = "1.0"
    proposal_id: str = Field(default_factory=lambda: f"kproposal_{uuid.uuid4().hex}")
    session_id: str
    target_fingerprint: str
    proposal_type: Literal["node", "edge", "coverage_gap"]
    payload: Dict[str, Any] = Field(default_factory=dict)
    evidence_ids: List[str] = Field(default_factory=list)
    status: Literal["proposed", "accepted", "rejected", "blocked"] = "proposed"
    model_id: str = ""
    input_digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.payload = redact(self.payload)

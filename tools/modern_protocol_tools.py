"""Structured modern-protocol surface adapter.

This module normalizes operator/browser captures for WebSocket, SSE, gRPC-web,
webhook and async-job flows. It deliberately does not open arbitrary sockets;
execution remains owned by the guarded runner and stateful browser runner.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional

from core.redact import redact
from core.detection_validation_v2 import semantic_response_compare
from core.structured_contract import (
    ObservationV1,
    ProtocolExchangeV1,
    ProtocolOperationV1,
    SemanticComparisonV1,
    ToolResultV1,
)


SUPPORTED_PROTOCOLS = {"graphql", "websocket", "sse", "grpc_web", "oauth", "oidc", "webhook", "async_job", "cache"}


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(json.dumps(redact(value), sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()[:40]


def normalize_protocol_capture(session_id: str, target: str, captures: Iterable[Dict[str, Any]]) -> ToolResultV1:
    """Turn redacted discovery captures into chainable protocol observations."""
    observations: List[ObservationV1] = []
    operations: List[ProtocolOperationV1] = []
    for index, raw in enumerate(captures):
        item = redact(dict(raw or {}))
        protocol = str(item.get("protocol", "")).lower()
        if protocol not in SUPPORTED_PROTOCOLS:
            continue
        operation_ref = str(item.get("operation_ref") or item.get("path") or item.get("method") or f"capture-{index}")[:500]
        evidence_ids = [str(value) for value in item.get("evidence_ids", []) if value]
        parser_context = str(item.get("parser_context") or item.get("parser") or "unknown").lower()
        if parser_context not in {"unknown", "json", "form", "multipart", "xml", "graphql", "websocket_message", "sse_event", "grpc_web_frame", "jwt", "signed_url", "html", "binary"}:
            parser_context = "unknown"
        exchange = ProtocolExchangeV1(
            operation_id=str(item.get("operation_id", "")),
            protocol=protocol,
            role=str(item.get("role", "external")) if str(item.get("role", "external")) in {"baseline", "test", "negative_control", "positive_control", "reproduction", "oob", "browser", "external"} else "external",
            parser_context=parser_context,
            content_type=str(item.get("content_type", "")),
            request_digest=_fingerprint(item.get("request", {})),
            response_digest=_fingerprint(item.get("response", {})),
            semantic_digest=_fingerprint(item.get("semantic", item.get("response", {}))),
            state_digest=str(item.get("state_digest", "")),
            status_code=item.get("status_code") if isinstance(item.get("status_code"), int) else None,
            response_time_ms=item.get("response_time_ms") if isinstance(item.get("response_time_ms"), (int, float)) else None,
            identity_id=str(item.get("identity_id", "")),
            tenant_label=str(item.get("tenant_label", "")),
            evidence_ids=evidence_ids,
            metadata={"correlation_id": item.get("correlation_id", ""), "schema_digest": item.get("schema_digest", "")},
        )
        observation = ObservationV1(
            role=str(item.get("role", "external")) if str(item.get("role", "external")) in {"baseline", "test", "negative_control", "positive_control", "reproduction", "oob", "browser", "external"} else "external",
            kind=f"{protocol}_operation",
            summary=f"Observed {protocol} operation {operation_ref}",
            target_url=target,
            method=str(item.get("method", ""))[:20],
            payload_hash=_fingerprint(item.get("payload", item.get("request", {}))),
            metadata={
                "session_id": session_id,
                "protocol": protocol,
                "operation_ref": operation_ref,
                "side_effect_class": item.get("side_effect_class", "unknown"),
                "identity_id": item.get("identity_id", ""),
                "auth_context_id": item.get("auth_context_id", ""),
                "correlation_id": item.get("correlation_id", ""),
                "parser_context": parser_context,
                "content_type": item.get("content_type", ""),
                "schema_digest": item.get("schema_digest", ""),
                "exchange_id": exchange.exchange_id,
                "semantic_digest": exchange.semantic_digest,
            },
            artifact_ids=evidence_ids,
        )
        observations.append(observation)
        operations.append(ProtocolOperationV1(
            session_id=session_id, protocol=protocol, origin=target,
            operation_ref=operation_ref, method=str(item.get("method", "")),
            identity_id=str(item.get("identity_id", "")),
            auth_context_id=str(item.get("auth_context_id", "")),
            side_effect_class=str(item.get("side_effect_class", "unknown")) if item.get("side_effect_class", "unknown") in {"read", "mutation", "unknown"} else "unknown",
            request_fingerprint=_fingerprint(item.get("request", {})),
            response_fingerprint=_fingerprint(item.get("response", {})),
            observation_ids=[observation.observation_id], evidence_ids=evidence_ids,
            metadata={"session_id": session_id, "correlation_id": item.get("correlation_id", ""), "parser_context": parser_context, "exchange_id": exchange.exchange_id},
        ))
    return ToolResultV1(
        tool_name="modern_protocol_surface",
        tool_version="1",
        category="protocol_surface",
        target=target,
        inputs_redacted={"session_id": session_id, "capture_count": len(observations)},
        summary=f"Normalized {len(operations)} modern protocol operations.",
        observations=observations,
        metrics={"operation_count": len(operations), "exchange_count": len(observations), "supported_protocols": sorted({item.protocol for item in operations})},
    )


def compare_protocol_captures(
    baseline: Dict[str, Any],
    test: Dict[str, Any],
    control: Optional[Dict[str, Any]] = None,
    *,
    protocol: str = "http",
    operation_id: str = "",
    evidence_ids: Optional[List[str]] = None,
) -> SemanticComparisonV1:
    """Public protocol comparison seam used by validators and fixtures."""
    return semantic_response_compare(
        baseline,
        test,
        control,
        protocol=protocol,
        operation_id=operation_id,
        evidence_ids=evidence_ids,
    )


def operation_dicts(result: ToolResultV1) -> List[Dict[str, Any]]:
    """Return safe operation-shaped metadata for ChainPlanner/API callers."""
    return [{
        "operation_id": f"op_{observation.observation_id}",
        "protocol": observation.metadata.get("protocol", "http"),
        "operation_ref": observation.metadata.get("operation_ref", observation.target_url),
        "identity_id": observation.metadata.get("identity_id", ""),
        "auth_context_id": observation.metadata.get("auth_context_id", ""),
        "evidence_ids": list(observation.artifact_ids),
        "side_effect_class": observation.metadata.get("side_effect_class", "unknown"),
        "parser_context": observation.metadata.get("parser_context", "unknown"),
        "content_type": observation.metadata.get("content_type", ""),
        "schema_digest": observation.metadata.get("schema_digest", ""),
        "discovered_from": observation.metadata.get("discovered_from", "observation"),
        "scope_fingerprint": observation.metadata.get("scope_fingerprint", ""),
    } for observation in result.observations]

"""Deterministic compiler for target knowledge and coverage closure.

This is a fact/coverage compiler, not an executor.  It accepts structured
records from the existing evidence, browser, identity, and protocol layers;
normalizes them into one session-scoped graph; and emits gaps for the mission
and adaptive planners.  Raw LLM text is intentionally not accepted.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.execution_contract import stable_digest
from core.knowledge_graph_contract import (
    CoverageGapV1,
    CoverageItemV1,
    ContradictionSetV1,
    KnowledgeEdgeV1,
    KnowledgeNodeV1,
    KnowledgeSourceLinkV1,
    ReconClosurePlanV1,
    ReconLaneSummaryV1,
    ReconNextActionV1,
    TargetKnowledgeGraphV1,
    normalize_locator,
    normalize_origin,
    normalize_path,
)
from core.redact import redact


NODE_TYPES = {
    "asset", "origin", "service", "endpoint", "operation", "parameter",
    "input", "schema", "identity", "role", "tenant", "auth_context",
    "entity", "resource", "workflow", "state", "protocol", "trust_boundary",
    "observation", "candidate", "finding", "capability", "cleanup",
    "ip_address", "certificate", "dns_record", "redirect", "technology",
    "waf_profile", "provider_observation", "auth_surface", "session_transition",
    "prerequisite",
}
RELATIONS = {
    "contains", "serves", "exposes", "accepts", "requires_auth",
    "uses_identity", "member_of", "owns", "same_entity", "reachable_via",
    "transitions_to", "observed_in", "tested_by", "equivalent_to",
    "contradicted_by", "blocked_by", "derived_from", "resolves_to",
    "aliases", "covered_by_certificate", "redirects_to", "hosts_service",
    "uses_technology", "protected_by_waf", "reported_by_provider",
    "historically_exposed", "requires_identity", "requires_role",
    "requires_state", "starts_session", "rotates_session", "invalidates_session",
    "guards", "uses_auth_context", "prerequisite_for",
}


class KnowledgeGraphError(ValueError):
    pass


_KNOWLEDGE_STATUSES = {
    "hypothesized", "observed", "supported", "stale", "contradictory",
    "blocked", "inconclusive", "validated", "disproven",
}


def _normalize_knowledge_status(value: Any, *, default: str = "observed") -> str:
    """Map planning/execution states into the graph's fact lifecycle.

    Planning states such as ``eligible`` and ``skipped`` are valid in a
    capability plan but deliberately are not part of the knowledge contract.
    A skipped or approval-gated capability is therefore recorded as
    ``blocked``; unavailable/failed execution remains ``inconclusive`` and
    can never be promoted by the graph compiler.
    """
    raw = str(value or default).strip().lower()
    mapped = {
        "eligible": "observed",
        "suggested": "observed",
        "planned": "observed",
        "skipped": "blocked",
        "waiting_approval": "blocked",
        "blocked": "blocked",
        "unavailable": "inconclusive",
        "failed": "inconclusive",
        "partial": "inconclusive",
    }.get(raw, raw)
    return mapped if mapped in _KNOWLEDGE_STATUSES else default


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _evidence(raw: Dict[str, Any]) -> List[str]:
    values = raw.get("evidence_ids") or raw.get("observation_ids") or raw.get("source_observation_ids") or []
    return sorted({str(item) for item in values if item})


def _sources(raw: Dict[str, Any]) -> List[str]:
    values = raw.get("source_ids") or raw.get("source_id") or raw.get("observation_id") or raw.get("tool_run_id") or []
    if not isinstance(values, list):
        values = [values]
    return sorted({str(item) for item in values if item})


def _status_rank(status: str) -> int:
    return {
        "hypothesized": 0, "observed": 1, "inconclusive": 2,
        "supported": 3, "validated": 4, "disproven": 4,
        "stale": 1, "blocked": 1, "contradictory": 5,
        # Coverage has its own lifecycle. These ranks are only used when
        # duplicate coverage facts are merged; they never promote a finding.
        "untested": 0, "planned": 1, "in_progress": 2,
        "tested": 3, "not_applicable": 3,
    }.get(status, 0)


class TargetKnowledgeGraphEngine:
    VERSION = "15.0"

    def __init__(self, *, max_nodes: int = 10_000, max_edges: int = 20_000, observation_ttl_hours: int = 24):
        self.max_nodes = max(100, min(100_000, int(max_nodes)))
        self.max_edges = max(100, min(200_000, int(max_edges)))
        self.observation_ttl_hours = max(1, int(observation_ttl_hours))

    @staticmethod
    def target_fingerprint(target: str) -> str:
        return stable_digest({"origin": normalize_origin(target), "path": normalize_path(target)}, 40)

    @staticmethod
    def scope_fingerprint(scope: Any) -> str:
        return stable_digest(normalize_locator(scope or {}), 40)

    @staticmethod
    def _node_id(graph_id: str, fingerprint: str) -> str:
        """Return an immutable node key scoped to one graph version.

        Node rows are append-only and ``node_id`` is the relational primary
        key.  Fingerprint-only IDs collide when the same fact appears in a
        later graph version or another session, leaving the new graph's
        ``node_ids`` pointing at rows owned by the old graph.  Including the
        graph ID keeps replay deterministic while preserving version
        isolation.
        """
        return f"knode_{stable_digest({'graph': graph_id, 'fingerprint': fingerprint}, 32)}"

    @staticmethod
    def _safe_node_type(value: Any) -> str:
        value = str(value or "observation").strip().lower()
        return value if value in NODE_TYPES else "observation"

    @staticmethod
    def _safe_relation(value: Any) -> str:
        value = str(value or "derived_from").strip().lower()
        return value if value in RELATIONS else "derived_from"

    @staticmethod
    def _canonical_locator(raw: Dict[str, Any], node_type: str) -> str:
        url = str(raw.get("url") or raw.get("target_url") or raw.get("origin") or raw.get("canonical_locator") or "").strip()
        if url:
            # Relative endpoint paths are common in discovery output. Do not
            # treat the path itself as an origin (which would duplicate the
            # path); absolute URLs retain normalized scheme/host/port.
            if "://" in url:
                parsed_origin = normalize_origin(url)
                path = normalize_path(url)
                return parsed_origin + path if path != "/" else parsed_origin
            return normalize_path(url)
        if node_type in {"endpoint", "operation", "parameter", "input"}:
            path = str(raw.get("path") or raw.get("path_template") or raw.get("reference_id") or raw.get("id") or "")
            return normalize_path(path)
        return str(raw.get("reference_id") or raw.get("id") or raw.get("label") or "").strip().lower()

    @staticmethod
    def _fact_key(raw: Dict[str, Any], node: KnowledgeNodeV1) -> str:
        return str(raw.get("fact_key") or raw.get("predicate") or "").strip().lower() or f"{node.node_type}:{node.canonical_locator}"

    @staticmethod
    def _fact_value(raw: Dict[str, Any], node: KnowledgeNodeV1) -> str:
        value = raw.get("fact_value", raw.get("value", raw.get("status", "")))
        if value == "" and node.node_type in {"endpoint", "operation"}:
            value = f"{node.method.upper()} {node.canonical_locator}"
        return str(normalize_locator(value))

    @staticmethod
    def _stable_sources(sources: Dict[str, Any]) -> Dict[str, Any]:
        """Strip wall-clock fields and secrets before digesting/compiling."""
        result: Dict[str, Any] = {}
        for key, values in sorted((sources or {}).items()):
            if isinstance(values, dict):
                values = [values]
            elif not isinstance(values, list):
                result[key] = redact(values)
                continue
            cleaned = []
            for value in values:
                if not isinstance(value, dict):
                    cleaned.append(str(value))
                    continue
                item = redact(dict(value))
                for field in ("created_at", "updated_at", "observed_at", "timestamp", "started_at"):
                    item.pop(field, None)
                cleaned.append(item)
            result[key] = sorted(cleaned, key=lambda item: str(item))
        return result

    def _make_node(
        self,
        graph: TargetKnowledgeGraphV1,
        raw: Dict[str, Any],
        default_type: str,
        target_origin: str = "",
    ) -> KnowledgeNodeV1:
        node_type = self._safe_node_type(raw.get("node_type") or raw.get("type") or default_type)
        reference_id = str(
            raw.get("reference_id") or raw.get("id") or raw.get("candidate_id")
            or raw.get("workflow_id") or raw.get("fingerprint")
            or raw.get("capability_id") or raw.get("operation_id")
            or raw.get("semantic_id") or ""
        ).strip()
        if not reference_id:
            raise KnowledgeGraphError(f"{node_type} source requires reference_id.")
        locator = self._canonical_locator(raw, node_type)
        raw_url = str(raw.get("url") or raw.get("target_url") or "").strip()
        if target_origin and raw_url and "://" not in raw_url and node_type in {"endpoint", "operation"}:
            locator = normalize_origin(target_origin) + normalize_path(raw_url)
        raw_status = _normalize_knowledge_status(
            raw.get("status") or ("supported" if _evidence(raw) else "observed")
        )
        node = KnowledgeNodeV1(
            graph_id=graph.graph_id,
            graph_version=graph.version,
            session_id=graph.session_id,
            node_type=node_type,
            reference_id=reference_id,
            canonical_locator=locator,
            label=str(raw.get("label") or raw.get("title") or reference_id),
            protocol=str(raw.get("protocol") or "http").lower(),
            method=str(raw.get("method") or "").upper(),
            parameter_location=str(raw.get("parameter_location") or raw.get("location") or "").lower(),
            parameter_name=str(raw.get("parameter_name") or raw.get("parameter") or raw.get("name") or ""),
            identity_id=str(raw.get("identity_id") or ""),
            tenant_label=str(raw.get("tenant_label") or raw.get("tenant") or ""),
            entity_fingerprint=str(raw.get("entity_fingerprint") or raw.get("resource_fingerprint") or ""),
            status=raw_status,
            evidence_ids=_evidence(raw),
            source_ids=_sources(raw),
            metadata=redact(dict(raw.get("metadata") or {})),
            observed_at=str(raw.get("observed_at") or raw.get("created_at") or _now()),
        )
        node.ensure_fingerprint()
        # Auth/session/workflow intelligence can legitimately contain several
        # distinct facts at the same URL (for example tenant_id, order_id,
        # role, and csrf_token prerequisites). Preserve their stable
        # reference IDs so explicit graph edges never point at a node that was
        # collapsed by locator-only deduplication. Endpoint/asset dedupe keeps
        # the historical behavior.
        if node.node_type in {"auth_surface", "session_transition", "prerequisite"}:
            node.fingerprint = stable_digest({
                "base": node.fingerprint,
                "reference_id": node.reference_id,
                "node_type": node.node_type,
            }, 64)
        return node

    @staticmethod
    def _merge_node(existing: KnowledgeNodeV1, incoming: KnowledgeNodeV1) -> KnowledgeNodeV1:
        existing.evidence_ids = sorted(set(existing.evidence_ids + incoming.evidence_ids))
        existing.source_ids = sorted(set(existing.source_ids + incoming.source_ids))
        existing.metadata = redact({**existing.metadata, **incoming.metadata})
        if _status_rank(incoming.status) > _status_rank(existing.status):
            existing.status = incoming.status
        if not existing.identity_id:
            existing.identity_id = incoming.identity_id
        if not existing.tenant_label:
            existing.tenant_label = incoming.tenant_label
        return existing

    def _add_edge(
        self,
        graph: TargetKnowledgeGraphV1,
        nodes: Dict[str, KnowledgeNodeV1],
        edges: Dict[str, KnowledgeEdgeV1],
        raw: Dict[str, Any],
        *,
        reference_aliases: Optional[Dict[str, str]] = None,
    ) -> None:
        source_ref = str(raw.get("source_reference_id") or raw.get("source_ref") or raw.get("source_id") or "")
        target_ref = str(raw.get("target_reference_id") or raw.get("target_ref") or raw.get("target_id") or "")
        by_ref = {item.reference_id: item for item in nodes.values()}
        source = by_ref.get(source_ref)
        target = by_ref.get(target_ref)
        aliases = reference_aliases or {}
        if source is None and aliases.get(source_ref):
            source = nodes.get(aliases[source_ref])
        if target is None and aliases.get(target_ref):
            target = nodes.get(aliases[target_ref])
        if not source or not target:
            raise KnowledgeGraphError(
                "Knowledge edge references an unknown node: "
                f"source={source_ref!r}, target={target_ref!r}."
            )
        edge = KnowledgeEdgeV1(
            graph_id=graph.graph_id,
            graph_version=graph.version,
            session_id=graph.session_id,
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            relation=self._safe_relation(raw.get("relation")),
            status=_normalize_knowledge_status(
                raw.get("status") or ("supported" if _evidence(raw) else "hypothesized"),
                default="hypothesized",
            ),
            evidence_ids=sorted(set(_evidence(raw) + source.evidence_ids + target.evidence_ids)),
            source_ids=_sources(raw),
            metadata=redact(dict(raw.get("metadata") or {})),
            observed_at=str(raw.get("observed_at") or raw.get("created_at") or _now()),
        ).ensure_fingerprint()
        existing = edges.get(edge.fingerprint)
        if existing:
            existing.evidence_ids = sorted(set(existing.evidence_ids + edge.evidence_ids))
            existing.source_ids = sorted(set(existing.source_ids + edge.source_ids))
            if _status_rank(edge.status) > _status_rank(existing.status):
                existing.status = edge.status
            return
        edge.edge_id = f"kedge_{edge.fingerprint[:32]}"
        edges[edge.fingerprint] = edge

    @staticmethod
    def _inferred_edges(graph: TargetKnowledgeGraphV1, nodes: Dict[str, KnowledgeNodeV1]) -> Iterable[Dict[str, Any]]:
        items = list(nodes.values())
        origins = [item for item in items if item.node_type == "origin"]
        endpoints = [item for item in items if item.node_type in {"endpoint", "operation"}]
        identities = [item for item in items if item.node_type == "identity"]
        params = [item for item in items if item.node_type in {"parameter", "input", "schema"}]
        for origin in origins:
            for endpoint in endpoints:
                yield {"source_reference_id": origin.reference_id, "target_reference_id": endpoint.reference_id, "relation": "serves", "evidence_ids": endpoint.evidence_ids}
        for identity in identities:
            for endpoint in endpoints:
                if identity.identity_id and endpoint.identity_id and identity.identity_id != endpoint.identity_id:
                    continue
                yield {"source_reference_id": identity.reference_id, "target_reference_id": endpoint.reference_id, "relation": "uses_identity", "evidence_ids": sorted(set(identity.evidence_ids + endpoint.evidence_ids))}
        for parameter in params:
            endpoint_ref = str(parameter.metadata.get("endpoint_reference_id") or parameter.metadata.get("endpoint_id") or "")
            if endpoint_ref:
                yield {"source_reference_id": endpoint_ref, "target_reference_id": parameter.reference_id, "relation": "accepts", "evidence_ids": parameter.evidence_ids}

    def compile(self, session_id: str, target: str, sources: Dict[str, Any], *, scope: Any = None, version: int = 1, parent_graph_id: str = "") -> Dict[str, Any]:
        stable_sources = self._stable_sources(sources)
        source_digest = stable_digest(stable_sources, 64)
        target_fp = self.target_fingerprint(target)
        scope_fp = self.scope_fingerprint(scope)
        graph_material = {"session": session_id, "target": target_fp, "scope": scope_fp, "version": version, "sources": source_digest}
        graph_id = f"kgraph_{stable_digest(graph_material, 32)}"
        graph = TargetKnowledgeGraphV1(
            graph_id=graph_id,
            session_id=session_id,
            target_fingerprint=target_fp,
            scope_fingerprint=scope_fp,
            version=max(1, int(version)),
            parent_graph_id=parent_graph_id,
            source_digests=[source_digest],
            policy_version=self.VERSION,
        )
        node_by_fp: Dict[str, KnowledgeNodeV1] = {}
        fact_values: Dict[Tuple[str, str], Tuple[str, KnowledgeNodeV1]] = {}
        # A source may use more than one stable reference for the same
        # canonical fact (for example /admin and /admin/).  Keep the alias
        # until edges are materialized; otherwise deduplication can leave a
        # valid source edge pointing at a reference that is no longer present
        # in the emitted node set.
        reference_to_fingerprint: Dict[str, str] = {}
        source_map = {
            "assets": "asset", "origins": "origin", "services": "service", "endpoints": "endpoint",
            "static_assets": "asset",
            "ip_addresses": "ip_address", "certificates": "certificate",
            "dns_records": "dns_record", "redirects": "redirect",
            "technologies": "technology", "waf_profiles": "waf_profile",
            "technology_fingerprints": "technology", "technology_signals": "observation",
            "technology_capabilities": "capability",
            "application_operations": "operation", "input_semantics": "input",
            "provider_observations": "provider_observation",
            "operations": "operation", "parameters": "parameter", "inputs": "input", "schemas": "schema",
            "identities": "identity", "roles": "role", "tenants": "tenant", "auth_contexts": "auth_context",
            "entities": "entity", "resources": "resource", "workflows": "workflow", "states": "state",
            "protocols": "protocol", "trust_boundaries": "trust_boundary", "observations": "observation",
            "candidates": "candidate", "findings": "finding", "capabilities": "capability", "cleanups": "cleanup",
            "auth_surfaces": "auth_surface", "session_transitions": "session_transition",
            "workflow_prerequisites": "prerequisite",
        }
        contradictions: Dict[str, ContradictionSetV1] = {}
        for source_name, default_type in source_map.items():
            for raw_value in _list(sources.get(source_name)):
                raw = dict(raw_value) if isinstance(raw_value, dict) else {"reference_id": str(raw_value)}
                node = self._make_node(graph, raw, default_type, target)
                fact_key = self._fact_key(raw, node)
                fact_value = self._fact_value(raw, node)
                fact_index = (f"{node.node_type}:{node.canonical_locator}", fact_key)
                existing_fact = fact_values.get(fact_index)
                if existing_fact and existing_fact[0] != fact_value:
                    node.status = "contradictory"
                    node.fingerprint = stable_digest({"base": node.fingerprint, "fact": fact_value}, 64)
                    node.node_id = self._node_id(graph.graph_id, node.fingerprint)
                    contradiction_material = {"graph": graph.graph_id, "subject": fact_index[0], "predicate": fact_key}
                    contradiction_id = f"contradiction_{stable_digest(contradiction_material, 32)}"
                    contradiction = contradictions.setdefault(contradiction_id, ContradictionSetV1(
                        contradiction_id=contradiction_id, graph_id=graph.graph_id, graph_version=graph.version,
                        session_id=session_id, subject_fingerprint=existing_fact[1].fingerprint, predicate=fact_key,
                    ))
                    contradiction.conflicting_node_ids = sorted(set(contradiction.conflicting_node_ids + [existing_fact[1].node_id, node.node_id]))
                    contradiction.evidence_ids = sorted(set(contradiction.evidence_ids + existing_fact[1].evidence_ids + node.evidence_ids))
                else:
                    fact_values[fact_index] = (fact_value, node)
                current = node_by_fp.get(node.fingerprint)
                node_by_fp[node.fingerprint] = self._merge_node(current, node) if current else node
                if node.reference_id:
                    reference_to_fingerprint[node.reference_id] = node.fingerprint

        if not any(item.node_type == "origin" for item in node_by_fp.values()):
            origin = self._make_node(graph, {"node_type": "origin", "reference_id": normalize_origin(target), "url": target, "status": "observed"}, "origin")
            node_by_fp[origin.fingerprint] = origin
        nodes = sorted(node_by_fp.values(), key=lambda item: item.fingerprint)[: self.max_nodes]
        for ordinal, node in enumerate(nodes):
            node.graph_id = graph.graph_id
            node.graph_version = graph.version
            node.node_id = self._node_id(graph.graph_id, node.fingerprint)
        reference_aliases = {
            reference_id: next(
                (node.node_id for node in nodes if node.fingerprint == fingerprint),
                "",
            )
            for reference_id, fingerprint in reference_to_fingerprint.items()
        }
        edge_by_fp: Dict[str, KnowledgeEdgeV1] = {}
        edge_sources = list(_list(sources.get("edges"))) + list(self._inferred_edges(graph, {item.node_id: item for item in nodes}))
        for raw_value in edge_sources:
            raw = dict(raw_value) if isinstance(raw_value, dict) else {}
            if not raw:
                continue
            self._add_edge(
                graph,
                {item.node_id: item for item in nodes},
                edge_by_fp,
                raw,
                reference_aliases=reference_aliases,
            )
            if len(edge_by_fp) >= self.max_edges:
                break
        edges = sorted(edge_by_fp.values(), key=lambda item: item.fingerprint)
        graph.node_ids = [item.node_id for item in nodes]
        graph.edge_ids = [item.edge_id for item in edges]
        graph.contradiction_ids = sorted(contradictions)
        coverage, gaps = self.compute_coverage(graph, nodes, edges, sources)
        coverage_material = {"graph": graph.graph_id, "coverage": [item.fingerprint for item in coverage]}
        graph.coverage_snapshot_id = f"coverage_snapshot_{stable_digest(coverage_material, 32)}"
        graph.status = "current"
        # The coverage snapshot is part of the immutable graph version. Set
        # the digest only after coverage has been compiled so replay and
        # persistence identify the complete version.
        graph.digest = ""
        graph.ensure_digest()
        source_links: List[KnowledgeSourceLinkV1] = []
        for node in nodes:
            for source_id in sorted(set(node.source_ids + node.evidence_ids)):
                link = KnowledgeSourceLinkV1(
                    graph_id=graph.graph_id,
                    graph_version=graph.version,
                    session_id=graph.session_id,
                    node_id=node.node_id,
                    source_kind="evidence" if source_id in node.evidence_ids else "observation",
                    source_id=source_id,
                    evidence_ids=node.evidence_ids,
                    input_digest=source_digest,
                )
                link.link_id = f"ksource_{stable_digest({'graph': graph.graph_id, 'node': node.node_id, 'source': source_id}, 32)}"
                source_links.append(link)
        for edge in edges:
            for source_id in sorted(set(edge.source_ids + edge.evidence_ids)):
                link = KnowledgeSourceLinkV1(
                    graph_id=graph.graph_id,
                    graph_version=graph.version,
                    session_id=graph.session_id,
                    edge_id=edge.edge_id,
                    source_kind="evidence" if source_id in edge.evidence_ids else "observation",
                    source_id=source_id,
                    evidence_ids=edge.evidence_ids,
                    input_digest=source_digest,
                )
                link.link_id = f"ksource_{stable_digest({'graph': graph.graph_id, 'edge': edge.edge_id, 'source': source_id}, 32)}"
                source_links.append(link)
        return {
            "graph": graph.model_dump(mode="json"),
            "nodes": [item.model_dump(mode="json") for item in nodes],
            "edges": [item.model_dump(mode="json") for item in edges],
            "contradictions": [item.model_dump(mode="json") for item in sorted(contradictions.values(), key=lambda item: item.contradiction_id)],
            "coverage": [item.model_dump(mode="json") for item in coverage],
            "gaps": [item.model_dump(mode="json") for item in gaps],
            "source_links": [item.model_dump(mode="json") for item in source_links],
            "source_digest": source_digest,
        }

    def compute_coverage(self, graph: TargetKnowledgeGraphV1, nodes: List[KnowledgeNodeV1], edges: List[KnowledgeEdgeV1], sources: Dict[str, Any]) -> Tuple[List[CoverageItemV1], List[CoverageGapV1]]:
        explicit = _list(sources.get("coverage")) + _list(sources.get("coverage_items"))
        raw_items = explicit
        if not raw_items:
            endpoints = [item for item in nodes if item.node_type in {"endpoint", "operation"}]
            parameters = [item for item in nodes if item.node_type in {"parameter", "input", "schema"}]
            identities = [item for item in nodes if item.node_type in {"identity", "auth_context"}]
            workflows = [item for item in nodes if item.node_type == "workflow"]
            policies = [str(item) for item in _list(sources.get("policies"))] or [""]
            for endpoint in endpoints:
                related_parameters = [item for item in parameters if str(item.metadata.get("endpoint_reference_id") or item.metadata.get("endpoint_id") or "") in {endpoint.reference_id, ""}]
                related_parameters = related_parameters or [None]
                related_identities = identities or [None]
                related_workflows = workflows or [None]
                for parameter in related_parameters:
                    for identity in related_identities:
                        for workflow in related_workflows:
                            for policy in policies:
                                raw_items.append({
                                    "endpoint_node_id": endpoint.node_id,
                                    "parameter_node_id": parameter.node_id if parameter else "",
                                    "identity_id": identity.identity_id if identity else "",
                                    "auth_context_id": identity.reference_id if identity and identity.node_type == "auth_context" else "",
                                    "workflow_id": workflow.reference_id if workflow else "",
                                    "protocol": endpoint.protocol,
                                    "policy_id": policy,
                                    "status": "untested",
                                    "source_ids": endpoint.source_ids,
                                    "evidence_ids": endpoint.evidence_ids,
                                    "required_prerequisites": [] if identity else (["identity_context"] if identities else []),
                                })
        coverage: Dict[str, CoverageItemV1] = {}
        for raw_value in raw_items:
            raw = dict(raw_value) if isinstance(raw_value, dict) else {}
            endpoint_ref = str(raw.get("endpoint_reference_id") or "")
            operation_ref = str(raw.get("operation_reference_id") or "")
            parameter_ref = str(raw.get("parameter_reference_id") or "")
            by_ref = {item.reference_id: item for item in nodes}
            endpoint = by_ref.get(endpoint_ref)
            operation = by_ref.get(operation_ref)
            parameter = by_ref.get(parameter_ref)
            item = CoverageItemV1(
                graph_id=graph.graph_id, graph_version=graph.version, session_id=graph.session_id,
                target_fingerprint=graph.target_fingerprint,
                asset_node_id=str(raw.get("asset_node_id") or ""),
                endpoint_node_id=str(raw.get("endpoint_node_id") or (endpoint.node_id if endpoint else "")),
                operation_node_id=str(raw.get("operation_node_id") or (operation.node_id if operation else "")),
                parameter_node_id=str(raw.get("parameter_node_id") or (parameter.node_id if parameter else "")),
                identity_id=str(raw.get("identity_id") or ""), auth_context_id=str(raw.get("auth_context_id") or ""),
                tenant_label=str(raw.get("tenant_label") or ""), entity_fingerprint=str(raw.get("entity_fingerprint") or ""),
                workflow_id=str(raw.get("workflow_id") or ""), state_label=str(raw.get("state_label") or ""),
                protocol=str(raw.get("protocol") or (endpoint.protocol if endpoint else "http")),
                policy_id=str(raw.get("policy_id") or ""), status=str(raw.get("status") or "untested"),
                evidence_ids=sorted({str(x) for x in (raw.get("evidence_ids") or []) if x}),
                source_ids=sorted({str(x) for x in (raw.get("source_ids") or []) if x}),
                required_prerequisites=[str(x) for x in raw.get("required_prerequisites") or []],
                gap_reason=str(raw.get("gap_reason") or ""), last_tested_at=raw.get("last_tested_at"),
            ).ensure_fingerprint()
            current = coverage.get(item.fingerprint)
            if current:
                current.evidence_ids = sorted(set(current.evidence_ids + item.evidence_ids))
                current.source_ids = sorted(set(current.source_ids + item.source_ids))
                if _status_rank(item.status) > _status_rank(current.status):
                    current.status = item.status
            else:
                coverage[item.fingerprint] = item
        output = sorted(coverage.values(), key=lambda item: item.fingerprint)
        gaps: List[CoverageGapV1] = []
        contradiction_count = len(_list(sources.get("contradictions")))
        for item in output:
            if item.status in {"untested", "planned", "in_progress", "inconclusive", "blocked", "stale"}:
                reason = item.gap_reason or {
                    "untested": "No evidence-linked test covers this target dimension.",
                    "planned": "Coverage is planned but has no completed evidence.",
                    "in_progress": "Coverage run is incomplete.",
                    "inconclusive": "Existing evidence lacks mandatory controls or reproduction.",
                    "blocked": "Coverage prerequisite or safety policy is unavailable.",
                    "stale": "Existing evidence is outside the current freshness/config boundary.",
                }.get(item.status, "Coverage is incomplete.")
                if contradiction_count:
                    reason += " Contradiction review may be required."
                priority = 0.65 if item.status == "untested" else 0.8
                priority += 0.12 if item.identity_id or item.auth_context_id else 0.0
                priority += 0.08 if item.policy_id else 0.0
                gap = CoverageGapV1(
                    coverage_id=item.coverage_id, graph_id=graph.graph_id, graph_version=graph.version,
                    session_id=graph.session_id, reason=reason, priority=min(1.0, priority),
                    missing_prerequisites=item.required_prerequisites,
                    suggested_capabilities=["surface_mapping"] if not item.endpoint_node_id else ["coverage_closure"],
                    blocked=item.status in {"blocked", "stale"}, diagnostic_only=item.status in {"inconclusive", "blocked", "stale"},
                )
                gap.gap_id = f"gap_{stable_digest({'graph': graph.graph_id, 'coverage': item.coverage_id, 'reason': reason}, 32)}"
                gaps.append(gap)
        return output, sorted(gaps, key=lambda item: (-item.priority, item.coverage_id))

    def synthesize_recon_closure(
        self,
        compiled: Dict[str, Any],
        sources: Optional[Dict[str, Any]] = None,
        *,
        freshness_boundary: str = "live-observations-24h",
        max_actions: int = 50,
    ) -> Dict[str, Any]:
        """Build a deterministic, read-only recon closure plan.

        Stage 27 is deliberately a synthesis layer over the existing graph,
        not another crawler.  It turns the already persisted graph, coverage,
        gaps, and source provenance into a bounded next-action queue.  No
        action here is a tool call or a vulnerability decision.
        """

        compiled = dict(compiled or {})
        sources = dict(sources or {})
        graph = dict(compiled.get("graph") or {})
        nodes = [dict(item) for item in _list(compiled.get("nodes")) if isinstance(item, dict)]
        edges = [dict(item) for item in _list(compiled.get("edges")) if isinstance(item, dict)]
        coverage = [dict(item) for item in _list(compiled.get("coverage")) if isinstance(item, dict)]
        gaps = [dict(item) for item in _list(compiled.get("gaps")) if isinstance(item, dict)]
        contradictions = [dict(item) for item in _list(compiled.get("contradictions")) if isinstance(item, dict)]

        lane_keys = {
            "perimeter": ("origins", "assets", "services", "ip_addresses", "certificates", "dns_records", "redirects", "waf_profiles", "provider_observations"),
            "surface": ("endpoints", "parameters", "static_assets", "schemas", "protocols"),
            "technology": ("technologies", "technology_fingerprints", "technology_signals", "technology_capabilities"),
            "application_contract": ("application_operations", "operations", "input_semantics", "inputs", "data_flows"),
            "identity_workflow": ("identities", "roles", "tenants", "auth_contexts", "auth_surfaces", "session_transitions", "workflows", "states", "workflow_prerequisites", "entities", "resources"),
        }
        lane_node_types = {
            "perimeter": {"asset", "origin", "service", "ip_address", "certificate", "dns_record", "redirect", "waf_profile", "provider_observation"},
            "surface": {"endpoint", "parameter", "schema", "protocol", "operation", "input"},
            "technology": {"technology", "capability", "observation"},
            "application_contract": {"operation", "input", "schema"},
            "identity_workflow": {"identity", "role", "tenant", "auth_context", "auth_surface", "session_transition", "prerequisite", "workflow", "state", "entity", "resource"},
        }
        lane_required_keys = {
            "identity_workflow": ("auth_surfaces", "session_transitions", "workflows", "workflow_prerequisites"),
        }

        def rows_for(keys: tuple[str, ...]) -> List[Dict[str, Any]]:
            rows: List[Dict[str, Any]] = []
            seen: set[str] = set()
            for key in keys:
                for row in _list(sources.get(key)):
                    item = dict(row) if isinstance(row, dict) else {"reference_id": str(row)}
                    identity = str(item.get("reference_id") or item.get("fingerprint") or stable_digest(item, 24))
                    if identity in seen:
                        continue
                    seen.add(identity)
                    rows.append(item)
            return rows

        def row_is_stale(row: Dict[str, Any]) -> bool:
            metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            freshness = str(row.get("freshness") or metadata.get("freshness") or "").lower()
            return str(row.get("status") or "").lower() == "stale" or freshness in {"stale", "historical"} or bool(metadata.get("revalidation_required"))

        def row_has_provenance(row: Dict[str, Any]) -> bool:
            return bool(row.get("evidence_ids") or row.get("source_ids") or row.get("source_id") or row.get("observation_id"))

        node_by_id = {str(row.get("node_id")): row for row in nodes if row.get("node_id")}
        lane_summaries: List[ReconLaneSummaryV1] = []
        lane_rows: Dict[str, List[Dict[str, Any]]] = {}
        for lane, keys in lane_keys.items():
            rows = rows_for(keys)
            lane_rows[lane] = rows
            lane_nodes = [row for row in nodes if str(row.get("node_type")) in lane_node_types[lane]]
            lane_coverage = []
            if lane in {"surface", "application_contract", "identity_workflow"}:
                for item in coverage:
                    endpoint = node_by_id.get(str(item.get("endpoint_node_id")))
                    operation = node_by_id.get(str(item.get("operation_node_id")))
                    identity = str(item.get("identity_id") or item.get("auth_context_id") or item.get("workflow_id"))
                    if lane == "surface" and (endpoint or not item.get("operation_node_id")):
                        lane_coverage.append(item)
                    elif lane == "application_contract" and operation:
                        lane_coverage.append(item)
                    elif lane == "identity_workflow" and identity:
                        lane_coverage.append(item)
            else:
                lane_coverage = []
            stale_count = sum(row_is_stale(row) for row in rows + lane_nodes)
            contradictory_count = sum(str(row.get("status") or "") == "contradictory" for row in rows + lane_nodes)
            evidence_count = sum(row_has_provenance(row) for row in rows + lane_nodes)
            total = len(rows) + len(lane_nodes)
            completeness = 0.0 if not total else min(1.0, (evidence_count / total) * 0.4 + (0.6 if not stale_count else max(0.0, 0.6 - (stale_count / total) * 0.6)))
            required_rows_missing = lane in lane_required_keys and not any(rows_for(lane_required_keys[lane]))
            if not total or required_rows_missing:
                completeness = 0.0
                status = "missing"
            elif contradictory_count or stale_count:
                status = "inconclusive"
            elif completeness >= 0.99:
                status = "complete"
            else:
                status = "partial"
            lane_summaries.append(ReconLaneSummaryV1(
                lane=lane,
                observed_count=total,
                evidence_linked_count=evidence_count,
                stale_count=stale_count,
                contradictory_count=contradictory_count,
                coverage_count=len(lane_coverage),
                gap_count=sum(1 for gap in gaps if str(gap.get("suggested_capabilities", [""])[0] if gap.get("suggested_capabilities") else "") in {"surface_mapping", "coverage_closure"} and lane in {"surface", "application_contract", "identity_workflow"}),
                completeness=round(completeness, 4),
                status=status,
            ))

        actions: List[ReconNextActionV1] = []

        def add_action(**kwargs: Any) -> None:
            action = ReconNextActionV1(action_id="", **kwargs).ensure_id()
            actions.append(action)

        for contradiction in sorted(contradictions, key=lambda item: str(item.get("contradiction_id", ""))):
            add_action(
                kind="resolve_contradiction",
                target_reference_ids=sorted({str(value) for value in contradiction.get("conflicting_node_ids") or [] if value}),
                source_ids=[str(value) for value in contradiction.get("evidence_ids") or [] if value],
                evidence_ids=[str(value) for value in contradiction.get("evidence_ids") or [] if value],
                reason="Conflicting observations require deterministic revalidation before coverage can close.",
                priority_score=0.98,
                estimated_information_gain=0.9,
                required_prerequisites=["independent_observation", "scope_recheck"],
                freshness_boundary=freshness_boundary,
                status="inconclusive",
            )

        for node in nodes:
            if row_is_stale(node):
                add_action(
                    kind="refresh_historical_asset" if str(node.get("node_type")) in lane_node_types["perimeter"] else "revalidate_stale_evidence",
                    target_reference_ids=[str(node.get("reference_id") or node.get("node_id"))],
                    source_ids=[str(value) for value in node.get("source_ids") or [] if value],
                    evidence_ids=[str(value) for value in node.get("evidence_ids") or [] if value],
                    reason="Observation is historical or outside the active freshness boundary; refresh is required before downstream use.",
                    priority_score=0.88,
                    estimated_information_gain=0.75,
                    required_prerequisites=["active_scope", "guarded_read_only_request"],
                    freshness_boundary=freshness_boundary,
                    status="stale",
                )

        for gap in sorted(gaps, key=lambda item: (-float(item.get("priority") or 0.0), str(item.get("gap_id", "")))):
            missing = [str(value) for value in gap.get("missing_prerequisites") or [] if value]
            reason = str(gap.get("reason") or "Coverage is incomplete.")
            suggested = {str(value) for value in gap.get("suggested_capabilities") or []}
            if gap.get("blocked"):
                kind = "map_identity_workflow" if any("identity" in value or "auth" in value for value in missing) else "complete_coverage"
                status = "blocked"
            elif "identity_context" in missing or any("auth" in value for value in missing):
                kind, status = "map_identity_workflow", "inconclusive"
            elif "surface_mapping" in suggested or not gap.get("coverage_id"):
                kind, status = "map_surface", "ready"
            else:
                kind, status = "complete_coverage", "inconclusive" if gap.get("diagnostic_only") else "ready"
            add_action(
                kind=kind,
                target_reference_ids=[str(gap.get("coverage_id") or "")],
                source_ids=[], evidence_ids=[], reason=reason,
                priority_score=max(0.0, min(1.0, float(gap.get("priority") or 0.0))),
                estimated_information_gain=0.7 if status != "blocked" else 0.2,
                required_prerequisites=missing,
                freshness_boundary=freshness_boundary,
                status=status,
            )

        for lane, summary in ((item.lane, item) for item in lane_summaries if item.status == "missing"):
            kind = {
                "perimeter": "collect_perimeter",
                "surface": "map_surface",
                "technology": "fingerprint_technology",
                "application_contract": "compile_application_contract",
                "identity_workflow": "map_identity_workflow",
            }[lane]
            add_action(
                kind=kind, target_reference_ids=[], source_ids=[], evidence_ids=[],
                reason=f"Recon lane '{lane}' has no canonical observations yet.",
                priority_score=0.82, estimated_information_gain=0.85,
                required_prerequisites=["active_scope"], freshness_boundary=freshness_boundary,
            )

        unique_actions: Dict[str, ReconNextActionV1] = {}
        for action in actions:
            unique_actions[action.action_id] = action
        actions = sorted(unique_actions.values(), key=lambda item: (-item.priority_score, item.action_id))[: max(1, min(200, int(max_actions)))]

        coverage_total = len(coverage)
        covered_count = sum(str(item.get("status") or "") in {"tested", "validated", "disproven", "not_applicable"} for item in coverage)
        blocked_gap_count = sum(bool(item.get("blocked")) for item in gaps)
        stale_gap_count = sum(str(item.get("reason") or "").lower().startswith("existing evidence") or str(item.get("status") or "") == "stale" for item in gaps)
        inconclusive_gap_count = sum(bool(item.get("diagnostic_only")) or str(item.get("reason") or "").lower().find("inconclusive") >= 0 for item in gaps)
        all_records = nodes + edges + coverage
        provenance_completeness = (sum(row_has_provenance(row) for row in all_records) / len(all_records)) if all_records else 0.0
        freshness_records = nodes + [row for row in edges if row.get("metadata")]
        freshness_completeness = (sum(not row_is_stale(row) for row in freshness_records) / len(freshness_records)) if freshness_records else 1.0
        if blocked_gap_count:
            status, stop_reason = "blocked", "blocked"
        elif contradictions:
            status, stop_reason = "inconclusive", "contradictions_pending"
        elif stale_gap_count:
            status, stop_reason = "inconclusive", "stale_evidence"
        elif not gaps and all(item.status == "complete" for item in lane_summaries):
            status, stop_reason = "ready", "coverage_complete"
        elif not actions:
            status, stop_reason = "inconclusive", "no_information_gain"
        else:
            status, stop_reason = "ready", "no_information_gain"
        if not actions:
            add_action(
                kind="stop", target_reference_ids=[], source_ids=[], evidence_ids=[],
                reason="No higher-information recon action remains within the current graph and freshness boundary.",
                priority_score=0.01, estimated_information_gain=0.0,
                required_prerequisites=[], freshness_boundary=freshness_boundary,
            )
        plan = ReconClosurePlanV1(
            session_id=str(graph.get("session_id") or ""),
            target_fingerprint=str(graph.get("target_fingerprint") or ""),
            graph_id=str(graph.get("graph_id") or ""), graph_version=int(graph.get("version") or 0),
            graph_digest=str(graph.get("digest") or ""), source_digest=str(compiled.get("source_digest") or ""),
            freshness_boundary=freshness_boundary, lanes=lane_summaries,
            coverage_total=coverage_total, covered_count=covered_count, gap_count=len(gaps),
            blocked_gap_count=blocked_gap_count, stale_gap_count=stale_gap_count,
            inconclusive_gap_count=inconclusive_gap_count, contradiction_count=len(contradictions),
            provenance_completeness=round(provenance_completeness, 4), freshness_completeness=round(freshness_completeness, 4),
            next_actions=actions, status=status, stop_reason=stop_reason,
            redaction_leaks=0,
        ).ensure_digest()
        return plan.model_dump(mode="json")

    def replay_digest(self, compiled: Dict[str, Any]) -> str:
        return stable_digest({
            "graph": compiled.get("graph", {}).get("digest"),
            "nodes": [(item.get("fingerprint"), item.get("status")) for item in compiled.get("nodes", [])],
            "edges": [(item.get("fingerprint"), item.get("status")) for item in compiled.get("edges", [])],
            "coverage": [(item.get("fingerprint"), item.get("status")) for item in compiled.get("coverage", [])],
            "gaps": [(item.get("coverage_id"), item.get("reason")) for item in compiled.get("gaps", [])],
        }, 64)

    @staticmethod
    def dispatchable(compiled: Dict[str, Any], coverage_id: str) -> Dict[str, Any]:
        item = next((row for row in compiled.get("coverage", []) if row.get("coverage_id") == coverage_id), None)
        if not item:
            return {"allowed": False, "status": "blocked", "reason": "Coverage item not found."}
        if item.get("status") in {"stale", "blocked", "inconclusive"}:
            return {"allowed": False, "status": item.get("status"), "reason": "Coverage item is not dispatchable until prerequisites/evidence are refreshed."}
        if not item.get("endpoint_node_id"):
            return {"allowed": False, "status": "blocked", "reason": "Coverage item has no canonical endpoint."}
        if item.get("required_prerequisites"):
            return {"allowed": False, "status": "blocked", "reason": "Coverage item has missing prerequisites."}
        return {"allowed": True, "status": item.get("status", "untested"), "reason": "Coverage item may be proposed to the bounded planner."}

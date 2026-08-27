"""Deterministic mission graph compiler and bounded path planner.

This module is intentionally a compiler, not an executor.  It converts
session-local structured records into a versioned graph and produces a path
proposal.  Dispatch remains owned by the durable execution and safety layers.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Tuple

from core.mission_contract import (
    AttackGraphEdgeV1,
    AttackGraphNodeV1,
    AttackPathV1,
    MissionDecisionV1,
    MissionEventV1,
    MissionV1,
)
from core.redact import redact
from core.execution_contract import stable_digest


NODE_TYPES = {
    "asset", "origin", "endpoint", "parameter", "identity", "role", "tenant",
    "session", "entity", "workflow", "state", "observation", "candidate",
    "finding", "privilege", "sensitive_action", "impact", "cleanup", "capability",
}
PLANNABLE_RELATIONS = {
    "owns", "same_object", "requires", "enables", "violates", "escalates",
    "impacts", "reproduced_by", "cleaned_by", "blocked_by",
}


class MissionGraphError(ValueError):
    pass


class MissionGraphEngine:
    VERSION = "14.0"

    def __init__(self, *, max_paths: int = 8):
        self.max_paths = max(1, min(int(max_paths), 32))

    def seed_from_knowledge(self, mission: MissionV1, compiled: Dict[str, Any]) -> Dict[str, Any]:
        """Bridge the Stage 15 fact graph into the Stage 14 mission compiler.

        The mission graph remains the action/path layer.  This adapter only
        translates canonical facts and preserves evidence/status; it never
        treats a coverage gap or LLM proposal as a finding.
        """
        rows = compiled.get("nodes") or []
        sources: Dict[str, Any] = {"edges": []}
        node_by_id = {str(row.get("node_id")): row for row in rows}
        plural = {
            "asset": "assets", "origin": "origins", "service": "services", "endpoint": "endpoints",
            "operation": "observations", "parameter": "observations", "input": "observations", "schema": "observations",
            "identity": "identities", "role": "observations", "tenant": "observations", "auth_context": "observations",
            "entity": "entities", "resource": "entities", "workflow": "workflows", "state": "observations",
            "protocol": "observations", "trust_boundary": "observations", "observation": "observations",
            "candidate": "candidates", "finding": "candidates", "capability": "observations", "cleanup": "observations",
        }
        for row in rows:
            item = dict(row)
            item["reference_id"] = item.get("reference_id") or item.get("node_id")
            sources.setdefault(plural.get(item.get("node_type"), "observations"), []).append(item)
        for raw in compiled.get("edges") or []:
            source = node_by_id.get(str(raw.get("source_node_id")), {})
            target = node_by_id.get(str(raw.get("target_node_id")), {})
            sources["edges"].append({
                "source_reference_id": source.get("reference_id", ""),
                "target_reference_id": target.get("reference_id", ""),
                "relation": raw.get("relation", "requires"),
                "status": raw.get("status", "hypothesized"),
                "evidence_ids": raw.get("evidence_ids", []),
            })
        return self.seed(mission, sources)

    @staticmethod
    def _digest_payload(graph_mission: MissionV1, nodes: Iterable[AttackGraphNodeV1], edges: Iterable[AttackGraphEdgeV1]) -> Dict[str, Any]:
        """Return replay-stable graph material, excluding wall-clock fields."""
        mission = graph_mission.model_dump(mode="json")
        for field in ("created_at", "updated_at", "graph_digest"):
            mission.pop(field, None)
        def node_payload(node: AttackGraphNodeV1) -> Dict[str, Any]:
            value = node.model_dump(mode="json")
            value.pop("created_at", None)
            return value
        def edge_payload(edge: AttackGraphEdgeV1) -> Dict[str, Any]:
            value = edge.model_dump(mode="json")
            value.pop("created_at", None)
            return value
        return {
            "mission": mission,
            "nodes": [node_payload(item) for item in sorted(nodes, key=lambda item: item.fingerprint)],
            "edges": [edge_payload(item) for item in sorted(edges, key=lambda item: item.fingerprint)],
        }

    @staticmethod
    def _node_key(node: AttackGraphNodeV1) -> Tuple[str, str, str, str]:
        return node.node_type, node.reference_id, node.identity_id, node.tenant_label

    @staticmethod
    def _safe_type(value: str) -> str:
        value = str(value or "").strip().lower()
        return value if value in NODE_TYPES else "observation"

    def _node(self, mission: MissionV1, raw: Dict[str, Any], *, status: str = "observed") -> AttackGraphNodeV1:
        reference_id = str(raw.get("reference_id") or raw.get("id") or raw.get("candidate_id") or "")
        if not reference_id:
            raise MissionGraphError("Graph node requires a stable reference_id.")
        evidence_ids = [str(item) for item in raw.get("evidence_ids") or raw.get("observation_ids") or [] if item]
        return AttackGraphNodeV1(
            mission_id=mission.mission_id,
            graph_version=max(1, mission.graph_version),
            node_type=self._safe_type(str(raw.get("node_type") or raw.get("type") or "observation")),
            reference_id=reference_id,
            label=str(raw.get("label") or raw.get("title") or reference_id),
            status=str(raw.get("status") or status),
            evidence_ids=sorted(set(evidence_ids)),
            identity_id=str(raw.get("identity_id") or ""),
            tenant_label=str(raw.get("tenant_label") or raw.get("tenant") or ""),
            protocol=str(raw.get("protocol") or "http"),
            metadata=redact(dict(raw.get("metadata") or {})),
        )

    def seed(self, mission: MissionV1, sources: Dict[str, Any]) -> Dict[str, Any]:
        """Build a canonical graph from explicit session-local sources.

        Sources are observations, candidates, identities, workflows, entities,
        endpoints, and optional explicit edges.  No target-specific defaults
        or synthetic vulnerability nodes are created.
        """
        version = max(1, int(mission.graph_version or 1))
        mission.graph_version = version
        nodes: Dict[Tuple[str, str, str, str], AttackGraphNodeV1] = {}

        origin = self._node(mission, {
            "node_type": "origin", "reference_id": mission.target,
            "label": mission.target, "protocol": "http",
        })
        nodes[self._node_key(origin)] = origin
        asset = self._node(mission, {
            "node_type": "asset", "reference_id": mission.target,
            "label": mission.target,
        })
        nodes[self._node_key(asset)] = asset

        source_map = {
            "observations": "observation", "candidates": "candidate",
            "identities": "identity", "workflows": "workflow",
            "entities": "entity", "endpoints": "endpoint",
        }
        for source, default_type in source_map.items():
            for raw in sources.get(source) or []:
                value = dict(raw) if isinstance(raw, dict) else {"reference_id": str(raw)}
                value.setdefault("node_type", default_type)
                node = self._node(mission, value, status="supported" if default_type in {"candidate", "observation"} else "observed")
                nodes.setdefault(self._node_key(node), node)

        ordered = sorted(nodes.values(), key=lambda item: self._node_key(item))
        # Graph references are content-addressed.  Runtime event IDs remain
        # unique, but replaying the same session snapshot must yield identical
        # node and edge references.
        for node in ordered:
            node.node_id = f"mnode_{node.fingerprint[:32]}"
        by_ref = {item.reference_id: item for item in ordered}
        edges: Dict[Tuple[str, str, str], AttackGraphEdgeV1] = {}

        def add_edge(source: AttackGraphNodeV1, target: AttackGraphNodeV1, relation: str, raw: Dict[str, Any] | None = None) -> None:
            raw = raw or {}
            raw_evidence = raw.get("evidence_ids")
            if raw_evidence is None:
                raw_evidence = source.evidence_ids + target.evidence_ids
            edge = AttackGraphEdgeV1(
                mission_id=mission.mission_id, graph_version=version,
                source_node_id=source.node_id, target_node_id=target.node_id,
                relation=relation,
                status=str(raw.get("status") or ("supported" if raw_evidence else "hypothesized")),
                evidence_ids=sorted({str(item) for item in raw_evidence if item}),
                required_action_ids=[str(item) for item in raw.get("required_action_ids") or []],
                preconditions=[str(item) for item in raw.get("preconditions") or []],
                required_identity_ids=[str(item) for item in raw.get("required_identity_ids") or []],
                risk=str(raw.get("risk") or "read_only"), cleanup_refs=[str(item) for item in raw.get("cleanup_refs") or []],
                reason=str(raw.get("reason") or "Compiled from session-local structured records."),
            )
            edge.edge_id = f"medge_{edge.fingerprint[:32]}"
            edges[(source.node_id, target.node_id, relation)] = edge

        add_edge(asset, origin, "contains")
        endpoints = [item for item in ordered if item.node_type == "endpoint"]
        for endpoint in endpoints:
            add_edge(origin, endpoint, "reachable", {"evidence_ids": endpoint.evidence_ids})
        identities = [item for item in ordered if item.node_type == "identity"]
        for identity in identities:
            for endpoint in endpoints:
                add_edge(identity, endpoint, "uses_identity", {"evidence_ids": sorted(set(identity.evidence_ids + endpoint.evidence_ids))})
        for raw in sources.get("edges") or []:
            raw = dict(raw)
            source = by_ref.get(str(raw.get("source_reference_id") or raw.get("source_ref") or ""))
            target = by_ref.get(str(raw.get("target_reference_id") or raw.get("target_ref") or ""))
            if not source or not target:
                raise MissionGraphError("Explicit edge references an unknown graph node.")
            add_edge(source, target, str(raw.get("relation") or "requires"), raw)

        normalized_edges = edges
        edges = normalized_edges

        mission.graph_digest = stable_digest(self._digest_payload(mission, ordered, edges.values()))
        return {"mission": mission.model_dump(mode="json"), "nodes": [item.model_dump(mode="json") for item in ordered], "edges": [item.model_dump(mode="json") for item in sorted(edges.values(), key=lambda item: item.fingerprint)], "graph_digest": mission.graph_digest}

    @staticmethod
    def _edge_score(edge: Dict[str, Any], nodes: Dict[str, Dict[str, Any]]) -> Tuple[float, Dict[str, float]]:
        source = nodes.get(str(edge.get("source_node_id")), {})
        target = nodes.get(str(edge.get("target_node_id")), {})
        relation = str(edge.get("relation", ""))
        impact = 0.95 if relation in {"impacts", "escalates", "violates"} else 0.55
        evidence = 1.0 if edge.get("evidence_ids") else 0.15
        risk = {"read_only": 0.0, "low": 0.08, "medium": 0.2, "high": 0.42, "critical": 0.65}.get(str(edge.get("risk", "read_only")), 0.3)
        novelty = 0.9 if target.get("status") in {"hypothesized", "inconclusive"} else 0.45
        score = max(0.0, min(1.0, 0.34 * impact + 0.32 * evidence + 0.2 * novelty - 0.14 * risk))
        return score, {"impact": impact, "evidence": evidence, "novelty": novelty, "risk_penalty": risk, "score": score}

    def plan(self, graph: Dict[str, Any], objective: str = "") -> Dict[str, Any]:
        mission = MissionV1(**dict(graph.get("mission") or {}))
        nodes = {str(item.get("node_id")): dict(item) for item in graph.get("nodes") or []}
        edges = [dict(item) for item in graph.get("edges") or []]
        candidates = []
        for edge in edges:
            # Structural discovery edges describe reachability, not an attack
            # path.  They remain in the graph but cannot be dispatched as the
            # mission's impact/action path.
            if str(edge.get("relation", "")) not in PLANNABLE_RELATIONS:
                continue
            score, breakdown = self._edge_score(edge, nodes)
            if edge.get("status") in {"blocked", "disproven", "stale"}:
                continue
            candidates.append((score, edge, breakdown))
        candidates.sort(key=lambda item: (-item[0], str(item[1].get("fingerprint", "")), str(item[1].get("edge_id", ""))))
        paths: List[AttackPathV1] = []
        for score, edge, breakdown in candidates[: self.max_paths]:
            required_evidence = list(dict.fromkeys(edge.get("evidence_ids") or []))
            needs_approval = str(edge.get("risk", "read_only")) != "read_only" or bool(edge.get("cleanup_refs"))
            path_status = "blocked" if not required_evidence else ("waiting_approval" if needs_approval else "ready")
            path = AttackPathV1(
                mission_id=mission.mission_id,
                graph_version=mission.graph_version,
                edge_ids=[str(edge.get("edge_id"))],
                node_ids=[str(edge.get("source_node_id")), str(edge.get("target_node_id"))],
                objective=objective or mission.objective,
                status=path_status,
                score=score,
                score_breakdown=breakdown,
                required_evidence_ids=required_evidence,
                required_identity_ids=list(edge.get("required_identity_ids") or []),
                required_approval=needs_approval,
                budget=dict(mission.budget),
                cleanup_refs=list(edge.get("cleanup_refs") or []),
                stop_conditions=["mandatory evidence complete", "scope or safety rejection", "budget exhausted", "impact reproduced"],
            )
            paths.append(path)
        selected = paths[0] if paths else None
        if selected:
            decision_type = "wait_approval" if selected.status == "waiting_approval" else "select_path"
            reason = "Selected deterministic highest-scoring attack-path edge."
        else:
            decision_type = "wait_evidence"
            reason = "No executable path is available from the current graph evidence."
        decision = MissionDecisionV1(
            mission_id=mission.mission_id,
            graph_version=mission.graph_version,
            decision_type=decision_type,
            selected_path_id=selected.path_id if selected else "",
            selected_edge_id=selected.edge_ids[0] if selected and selected.edge_ids else "",
            considered_paths=[{"path_id": path.path_id, "score": path.score, "status": path.status, "digest": path.path_digest} for path in paths],
            rejected_alternatives=[{"edge_id": edge.get("edge_id"), "reason": "lower deterministic score"} for _, edge, _ in candidates[self.max_paths:]],
            reason=reason,
            expected_information_gain=selected.score if selected else 0.0,
            estimated_cost=1.0 if selected else 0.0,
            risk_score=float(selected.score_breakdown.get("risk_penalty", 0.0)) if selected else 0.0,
            input_digest=stable_digest({"graph_digest": graph.get("graph_digest", ""), "objective": objective}),
        )
        decision.output_digest = stable_digest({"path": selected.model_dump(mode="json") if selected else None, "decision": decision.decision_type})
        event = MissionEventV1(
            mission_id=mission.mission_id, graph_version=mission.graph_version,
            event_type="path_selected" if selected else "evidence_wait",
            path_id=selected.path_id if selected else "", decision_id=decision.decision_id,
            payload={"reason": reason, "output_digest": decision.output_digest},
        )
        return {"mission": mission.model_dump(mode="json"), "paths": [item.model_dump(mode="json") for item in paths], "decision": decision.model_dump(mode="json"), "event": event.model_dump(mode="json")}

    @staticmethod
    def validate_dispatch(path: Dict[str, Any], *, approved: bool = False, approval_ref: str = "", approval_digest: str = "") -> Dict[str, Any]:
        risk = str(path.get("risk", "read_only"))
        mutation = (
            risk != "read_only"
            or bool(path.get("cleanup_refs"))
            or bool(path.get("required_approval"))
        )
        if mutation and not approved:
            return {"allowed": False, "status": "waiting_approval", "reason": "Exact approval is required for this path."}
        if mutation and path.get("required_approval"):
            expected_digest = str(path.get("approval_digest", ""))
            if not approval_ref:
                return {"allowed": False, "status": "waiting_approval", "reason": "An approved action reference is required."}
            if not expected_digest or approval_digest != expected_digest:
                return {"allowed": False, "status": "stale", "reason": "Approval digest does not match this immutable path."}
        if not path.get("required_evidence_ids"):
            return {"allowed": False, "status": "blocked", "reason": "Path has no linked evidence."}
        if mutation and not path.get("cleanup_refs"):
            return {"allowed": False, "status": "blocked", "reason": "Mutation path has no registered cleanup."}
        return {"allowed": True, "status": "ready", "reason": "Path passed mission dispatch preconditions."}

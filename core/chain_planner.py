"""Deterministic, evidence-backed attack-chain planning."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional

from core.session_store import SessionStore
from core.workflow_models import ActionProposal, ChainEdge, ChainEvaluation, ChainNode, ChainRecord, RecordStatus
from core.mission_contract import MissionV1
from core.mission_graph import MissionGraphEngine


class ChainPlanner:
    """Compile validated evidence into bounded attack-path proposals.

    LLM output can be used to suggest an objective, but this compiler only
    consumes evidence-linked validated candidates and observed operations.
    """

    VERSION = "1.0"

    def __init__(self, sessions: SessionStore, structured_repository: Any = None, knowledge_repository: Any = None):
        self.sessions = sessions
        self.structured_repository = structured_repository
        self.knowledge_repository = knowledge_repository
        self.mission_graph = MissionGraphEngine()

    def build_mission_graph(self, session_id: str, objective: str = "", sources: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Compile the Stage 14 graph through the existing chain-planner boundary.

        The legacy chain representation remains available for compatibility;
        new mission decisions use the versioned graph compiler so there is no
        second planner or hidden LLM-owned attack-path state.
        """
        context = self.sessions.require(session_id)
        mission = MissionV1(
            session_id=session_id,
            target=str(context.get("target_url", "")),
            objective=objective or str(context.get("attack_goal", "")),
            graph_version=1,
            policy_version="14.0",
        )
        if sources is None:
            if self.knowledge_repository is not None:
                try:
                    current = self.knowledge_repository.current(session_id)
                    if current:
                        detail = self.knowledge_repository.graph(session_id, current["graph_id"])
                        node_by_id = {row.get("node_id"): row for row in detail.get("nodes", [])}
                        sources = {"edges": []}
                        plural = {
                            "asset": "assets", "origin": "origins", "service": "services", "endpoint": "endpoints",
                            "operation": "operations", "parameter": "parameters", "input": "inputs", "schema": "schemas",
                            "identity": "identities", "role": "roles", "tenant": "tenants", "auth_context": "auth_contexts",
                            "entity": "entities", "resource": "resources", "workflow": "workflows", "state": "states",
                            "protocol": "protocols", "trust_boundary": "trust_boundaries", "observation": "observations",
                            "candidate": "candidates", "finding": "findings", "capability": "capabilities", "cleanup": "cleanups",
                        }
                        for row in detail.get("nodes", []):
                            sources.setdefault(plural.get(row.get("node_type"), "observations"), []).append(row)
                        for edge in detail.get("edges", []):
                            source = node_by_id.get(edge.get("source_node_id"), {})
                            target = node_by_id.get(edge.get("target_node_id"), {})
                            sources["edges"].append({
                                "source_reference_id": source.get("reference_id", ""),
                                "target_reference_id": target.get("reference_id", ""),
                                "relation": edge.get("relation", "derived_from"),
                                "evidence_ids": edge.get("evidence_ids", []),
                                "status": edge.get("status", "observed"),
                            })
                except Exception:
                    sources = None
            if sources is not None:
                return self.mission_graph.seed(mission, sources)
            candidates = self._candidate_records(session_id)
            sources = {
                "candidates": [{
                    "node_type": "candidate", "reference_id": item["id"], "label": item["title"],
                    "status": item["status"], "evidence_ids": item["evidence_ids"],
                    "identity_id": item["identity_id"], "tenant_label": item["tenant_label"],
                } for item in candidates],
            }
        return self.mission_graph.seed(mission, sources)

    def plan_mission_graph(self, session_id: str, objective: str = "", sources: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        graph = self.build_mission_graph(session_id, objective, sources)
        return {"graph": graph, **self.mission_graph.plan(graph, objective)}

    @staticmethod
    def validate_mission_path(path: Dict[str, Any], approved: bool = False) -> Dict[str, Any]:
        return MissionGraphEngine.validate_dispatch(path, approved=approved)

    @staticmethod
    def _digest(value: Any) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()[:64]

    def _legacy_findings(self, session_id: str) -> List[Any]:
        state = self.sessions.load_state(session_id)
        return [item for item in state.workflow.findings if item.status in {"validated", "validated_override", "impact_proven"}]

    def _structured_findings(self, session_id: str) -> List[Dict[str, Any]]:
        if self.structured_repository is None:
            return []
        try:
            rows = self.structured_repository.list_candidates(session_id, limit=500)
            return [row for row in rows if row.get("status") in {"validated", "validated_override"}]
        except Exception:
            return []

    def _candidate_records(self, session_id: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for item in self._structured_findings(session_id):
            metadata = item.get("metadata") or {}
            rows.append({
                "id": item.get("candidate_id", ""),
                "title": item.get("title", "validated candidate"),
                "vuln_type": item.get("vuln_type", "unknown"),
                "status": item.get("status", "validated"),
                "evidence_ids": list(metadata.get("evidence_ids") or item.get("observation_ids") or []),
                "identity_id": str(metadata.get("identity_id", "")),
                "tenant_label": str(metadata.get("tenant_label", "")),
                "protocol": str(metadata.get("protocol", "http")),
                "metadata": metadata,
            })
        known_ids = {item["id"] for item in rows if item["id"]}
        for item in self._legacy_findings(session_id):
            if item.finding_id in known_ids or not item.evidence_ids:
                continue
            rows.append({
                "id": item.finding_id,
                "title": item.title,
                "vuln_type": item.vuln_type,
                "status": "validated_override" if item.validation_source == "human_override" else item.status,
                "evidence_ids": list(item.evidence_ids),
                "identity_id": "",
                "tenant_label": "",
                "protocol": "http",
                "metadata": {"severity": item.severity, "fingerprint": item.fingerprint},
            })
        return [item for item in rows if item["id"] and item["evidence_ids"]]

    @staticmethod
    def _relation(previous: Dict[str, Any], current: Dict[str, Any]) -> str:
        if previous.get("tenant_label") and current.get("tenant_label") and previous["tenant_label"] != current["tenant_label"]:
            return "crosses_tenant"
        if previous.get("identity_id") and current.get("identity_id") and previous["identity_id"] != current["identity_id"]:
            return "crosses_identity"
        previous_type = str(previous.get("vuln_type", "")).lower()
        current_type = str(current.get("vuln_type", "")).lower()
        if any(token in previous_type for token in ("auth", "oauth", "jwt", "idor", "access")):
            return "enables"
        if any(token in current_type for token in ("privilege", "business", "impact", "sensitive")):
            return "impacts"
        return "requires"

    def build_graph(self, session_id: str, objective: str = "", protocol_operations: Optional[Iterable[Dict[str, Any]]] = None) -> Dict[str, Any]:
        context = self.sessions.require(session_id)
        candidates = self._candidate_records(session_id)
        if not candidates:
            return {"status": "blocked", "reason": "No validated evidence-linked finding is available for chaining.", "nodes": [], "edges": [], "chains": []}

        nodes: List[ChainNode] = [ChainNode(
            node_type="finding", reference_id=item["id"], label=item["title"], status=item["status"],
            evidence_ids=item["evidence_ids"], identity_id=item["identity_id"], tenant_label=item["tenant_label"],
            protocol=item["protocol"], metadata={"vuln_type": item["vuln_type"], **item["metadata"]},
        ) for item in candidates]
        for operation in protocol_operations or []:
            operation_id = str(operation.get("operation_id", ""))
            if operation_id:
                nodes.append(ChainNode(
                    node_type="protocol_operation", reference_id=operation_id,
                    label=str(operation.get("operation_ref", operation_id)), status="observed",
                    evidence_ids=list(operation.get("evidence_ids", [])),
                    identity_id=str(operation.get("identity_id", "")), protocol=str(operation.get("protocol", "http")),
                    metadata={"side_effect_class": operation.get("side_effect_class", "unknown")},
                ))
        nodes.sort(key=lambda item: (item.node_type, item.reference_id))
        finding_nodes = [item for item in nodes if item.node_type == "finding"]
        edges: List[ChainEdge] = []
        for previous, current in zip(finding_nodes, finding_nodes[1:]):
            previous_data = {"vuln_type": previous.metadata.get("vuln_type", ""), "identity_id": previous.identity_id, "tenant_label": previous.tenant_label}
            current_data = {"vuln_type": current.metadata.get("vuln_type", ""), "identity_id": current.identity_id, "tenant_label": current.tenant_label}
            edges.append(ChainEdge(
                source_node_id=previous.node_id, target_node_id=current.node_id,
                relation=self._relation(previous_data, current_data),
                evidence_ids=list(dict.fromkeys(previous.evidence_ids + current.evidence_ids)),
                reason="Edge is proposed from validated findings and linked evidence.",
            ))
        graph_digest = self._digest({
            "session_id": session_id, "objective": objective or context.get("attack_goal", ""),
            "nodes": [item.__dict__ for item in nodes], "edges": [item.__dict__ for item in edges],
        })
        chain = ChainRecord(
            name=objective or context.get("attack_goal", "Validated attack path"),
            step_ids=[item.reference_id for item in finding_nodes], status="proposed", current_step=0,
            chain_version=1, graph_digest=graph_digest, node_ids=[item.node_id for item in nodes],
            edge_ids=[item.edge_id for item in edges], prerequisite_ids=[item.reference_id for item in finding_nodes],
            evidence_ids=list(dict.fromkeys(evidence for item in nodes for evidence in item.evidence_ids)),
            identity_ids=list(dict.fromkeys(item.identity_id for item in nodes if item.identity_id)),
            protocol_operation_ids=[item.reference_id for item in nodes if item.node_type == "protocol_operation"],
            impact_objective=objective or context.get("attack_goal", ""), validation_status="inconclusive",
        )
        return {"status": "proposed", "chain": chain.__dict__, "nodes": [item.__dict__ for item in nodes], "edges": [item.__dict__ for item in edges], "graph_digest": graph_digest}

    def propose_next(self, session_id: str, objective: str = "") -> Dict[str, Any]:
        graph = self.build_graph(session_id, objective)
        if graph.get("status") == "blocked":
            return graph
        context = self.sessions.require(session_id)
        state = self.sessions.load_state(session_id)
        chain = ChainRecord(**graph["chain"])
        state.workflow.chains.append(chain)
        has_override = any(item.get("status") == "validated_override" for item in self._candidate_records(session_id))
        proposal = ActionProposal(
            action="controlled_impact_proof", target_url=context["target_url"],
            rationale=("Evaluate human-override-validated chain " if has_override else "Evaluate validated chain ") + f"{chain.chain_id} against the approved objective.",
            expected_evidence="Baseline, control, exact impact result, clean reproduction, and cleanup verification.",
            risk="high", requires_approval=True, cleanup_required=True, evidence_ids=list(chain.evidence_ids),
            input_bindings={"chain_id": chain.chain_id, "chain_version": chain.chain_version, "graph_digest": chain.graph_digest},
            fingerprint=chain.graph_digest,
        )
        state.workflow.add_proposal(proposal)
        state.workflow.record_event("chain_proposed", chain_id=chain.chain_id, action_id=proposal.action_id, graph_digest=chain.graph_digest)
        self.sessions.save_state(session_id, state)
        return {**graph, "proposal": proposal.__dict__, "proposals": [proposal.__dict__]}

    def validate_prerequisites(self, session_id: str, finding_ids: List[str], allow_override: bool = True) -> bool:
        allowed = {"validated", "impact_proven"}
        if allow_override:
            allowed.add("validated_override")
        rows = {item["id"]: item for item in self._candidate_records(session_id)}
        return bool(finding_ids) and all(item_id in rows and rows[item_id]["status"] in allowed for item_id in finding_ids)

    def evaluate_graph(self, session_id: str, graph: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate chain readiness, never promote a production finding.

        This checks graph integrity and evidence linkage only. Impact is still
        proven by the approved execution plan and Stage 1 validation.
        """
        chain = dict(graph.get("chain") or {})
        nodes = list(graph.get("nodes") or [])
        edges = list(graph.get("edges") or [])
        evidence_ids = list(chain.get("evidence_ids") or [])
        checks: List[Dict[str, Any]] = []

        def check(check_id: str, passed: bool, reason: str, ids: List[str]) -> None:
            checks.append({
                "check_id": check_id, "passed": bool(passed), "reason": reason,
                "evidence_ids": list(dict.fromkeys(ids)), "node_ids": [str(item.get("node_id", "")) for item in nodes],
            })

        all_nodes_linked = bool(nodes) and all(bool(item.get("evidence_ids")) for item in nodes)
        check("chain_node_evidence", all_nodes_linked, "Every chain node must link to evidence.", evidence_ids)
        prerequisites = [str(item) for item in chain.get("prerequisite_ids") or [] if item]
        prerequisites_ready = self.validate_prerequisites(session_id, prerequisites)
        check("validated_prerequisites", prerequisites_ready, "Every finding prerequisite must remain validated or overridden.", evidence_ids)
        edge_integrity = all(
            edge.get("source_node_id") in {node.get("node_id") for node in nodes}
            and edge.get("target_node_id") in {node.get("node_id") for node in nodes}
            and bool(edge.get("evidence_ids"))
            for edge in edges
        ) if edges else True
        check("chain_edge_integrity", edge_integrity, "Edges must connect known nodes and carry evidence.", evidence_ids)
        decision = "satisfied" if checks and all(item["passed"] for item in checks) else "inconclusive"
        evaluation = ChainEvaluation(
            chain_id=str(chain.get("chain_id", "")), decision=decision, checks=checks,
            evidence_ids=list(dict.fromkeys(evidence_ids)), reason=(
                "Chain is structurally ready for exact approval and impact proof."
                if decision == "satisfied" else "Chain readiness checks are incomplete; no impact claim is made."
            ), validator_version="11.0", policy_version="1.0",
        )
        evaluation_payload = evaluation.__dict__ | {
            "chain_version": int(chain.get("chain_version", chain.get("current_version", 1))),
            "input_digest": self._digest({"graph_digest": graph.get("graph_digest", chain.get("graph_digest", "")), "checks": checks}),
        }
        return evaluation_payload

    def build_impact_graph(
        self,
        session_id: str,
        objective: str = "",
        *,
        nodes: Optional[Iterable[Dict[str, Any]]] = None,
        edges: Optional[Iterable[Dict[str, Any]]] = None,
        identity_graph_digest: str = "",
        knowledge_graph_digest: str = "",
        workflow_matrix_id: str = "",
    ) -> Dict[str, Any]:
        """Build an evidence-backed DAG for Stage 18 impact validation.

        ``build_graph`` is retained for API compatibility.  This method is the
        stricter path: it accepts explicit nodes/edges from the identity,
        knowledge, and workflow layers and never invents a cross-identity or
        cross-tenant edge without evidence.
        """
        context = self.sessions.require(session_id)
        if nodes is None:
            legacy = self.build_graph(session_id, objective)
            if legacy.get("status") == "blocked":
                return legacy
            nodes = legacy.get("nodes", [])
            edges = legacy.get("edges", [])
        normalized_nodes: List[ChainNode] = []
        by_ref: Dict[str, str] = {}
        for raw in nodes or []:
            item = raw if isinstance(raw, ChainNode) else ChainNode(**dict(raw))
            if not item.reference_id or not item.evidence_ids:
                continue
            normalized_nodes.append(item)
            by_ref[item.reference_id] = item.node_id
        normalized_nodes.sort(key=lambda item: (item.node_type, item.reference_id, item.node_id))
        node_ids = {item.node_id for item in normalized_nodes}
        normalized_edges: List[ChainEdge] = []
        for raw in edges or []:
            item = raw if isinstance(raw, ChainEdge) else ChainEdge(**dict(raw))
            if item.source_node_id not in node_ids or item.target_node_id not in node_ids:
                continue
            if not item.evidence_ids or not item.deterministic:
                continue
            normalized_edges.append(item)
        normalized_edges.sort(key=lambda item: (item.source_node_id, item.target_node_id, item.relation, item.edge_id))
        impact_nodes = [item for item in normalized_nodes if item.node_type in {"impact", "sensitive_action"}]
        evidence_count = len({eid for item in normalized_nodes for eid in item.evidence_ids})
        risk_values = {str(item.risk).lower() for item in normalized_edges}
        risk_penalty = 0.2 if "critical" in risk_values else 0.1 if "high" in risk_values else 0.0
        score_breakdown = {
            "impact_relevance": 1.0 if impact_nodes else 0.0,
            "evidence_strength": min(1.0, evidence_count / 6.0),
            "path_completeness": min(1.0, len(normalized_edges) / max(1, len(normalized_nodes) - 1)),
            "cost_efficiency": 1.0 / max(1.0, float(len(normalized_edges))),
            "risk_penalty": risk_penalty,
        }
        score = max(0.0, min(1.0, (
            score_breakdown["impact_relevance"] * 0.32
            + score_breakdown["evidence_strength"] * 0.28
            + score_breakdown["path_completeness"] * 0.22
            + score_breakdown["cost_efficiency"] * 0.18
            - score_breakdown["risk_penalty"]
        )))
        graph_digest = self._digest({
            "session_id": session_id,
            "objective": objective or context.get("attack_goal", ""),
            "nodes": [item.__dict__ for item in normalized_nodes],
            "edges": [item.__dict__ for item in normalized_edges],
            "identity_graph_digest": identity_graph_digest,
            "knowledge_graph_digest": knowledge_graph_digest,
            "workflow_matrix_id": workflow_matrix_id,
        })
        chain = ChainRecord(
            name=objective or context.get("attack_goal", "Identity/business impact chain"),
            step_ids=[item.reference_id for item in normalized_nodes],
            chain_version=1,
            graph_digest=graph_digest,
            node_ids=[item.node_id for item in normalized_nodes],
            edge_ids=[item.edge_id for item in normalized_edges],
            prerequisite_ids=[item.reference_id for item in normalized_nodes if item.node_type in {"finding", "candidate"}],
            evidence_ids=sorted({eid for item in normalized_nodes + normalized_edges for eid in item.evidence_ids}),
            identity_ids=sorted({item.identity_id for item in normalized_nodes if item.identity_id}),
            impact_objective=objective or context.get("attack_goal", ""),
            mission_id=str(context.get("mission_id", "")),
            identity_graph_digest=identity_graph_digest,
            knowledge_graph_digest=knowledge_graph_digest,
            workflow_matrix_id=workflow_matrix_id,
            path_score=score,
            score_breakdown=score_breakdown,
            input_digest=graph_digest,
        )
        return {
            "status": "proposed" if normalized_nodes and normalized_edges else "blocked",
            "reason": "Explicit evidence-backed impact DAG compiled." if normalized_nodes and normalized_edges else "Impact DAG requires evidence-linked nodes and edges.",
            "chain": chain.__dict__,
            "nodes": [item.__dict__ for item in normalized_nodes],
            "edges": [item.__dict__ for item in normalized_edges],
            "graph_digest": graph_digest,
            "score": score,
            "score_breakdown": score_breakdown,
        }

    def evaluate_impact_chain(
        self,
        session_id: str,
        graph: Dict[str, Any],
        *,
        evidence_roles: Optional[Dict[str, Iterable[str]]] = None,
        identity_contexts: Optional[Iterable[Dict[str, Any]]] = None,
        impact: Optional[Dict[str, Any]] = None,
        approval_present: bool = False,
        mutation: bool = False,
    ) -> Dict[str, Any]:
        """Run deterministic chain-level checks without promoting a finding."""
        self.sessions.require(session_id)
        chain = dict(graph.get("chain") or {})
        nodes = list(graph.get("nodes") or [])
        edges = list(graph.get("edges") or [])
        roles = {str(key): list(value or []) for key, value in (evidence_roles or {}).items()}
        contexts = [dict(item) for item in identity_contexts or []]
        impact = dict(impact or {})
        checks: List[Dict[str, Any]] = []

        def check(check_id: str, passed: bool, reason: str, evidence: Iterable[str] = ()) -> None:
            checks.append({
                "check_id": check_id, "passed": bool(passed), "reason": reason,
                "evidence_ids": sorted({str(item) for item in evidence if item}),
            })

        all_evidence = sorted({str(eid) for item in nodes + edges for eid in item.get("evidence_ids", []) if eid})
        check("graph_fresh", not bool(graph.get("stale")) and not bool(chain.get("stale_reason")), "Identity/knowledge/workflow graph version must be current.", all_evidence)
        check("chain_nodes_evidence", bool(nodes) and all(bool(item.get("evidence_ids")) for item in nodes), "Every chain node needs evidence.", all_evidence)
        known_nodes = {str(item.get("node_id")) for item in nodes}
        check("chain_edges_integrity", bool(edges) and all(
            str(item.get("source_node_id")) in known_nodes
            and str(item.get("target_node_id")) in known_nodes
            and bool(item.get("evidence_ids"))
            for item in edges
        ), "Edges must connect known evidence-backed nodes.", all_evidence)
        check("identity_matrix", len({str(item.get("identity_id")) for item in contexts if item.get("identity_id")}) >= 2 and all(bool(item.get("auth_context_id")) for item in contexts if item.get("identity_id")), "At least two isolated auth contexts are required.", all_evidence)
        required_roles = ("baseline", "negative_control", "test", "reproduction")
        check("evidence_roles", all(roles.get(role) for role in required_roles), "Baseline, control, test, and reproduction evidence are mandatory.", [eid for values in roles.values() for eid in values])
        check("impact_measured", bool(impact.get("server_state_digest") and (impact.get("effect_count", 0) or impact.get("state_changed") or impact.get("impact_marker"))), "Impact needs a server-side state/effect measurement.", impact.get("evidence_ids", []))
        check("clean_reproduction", bool(impact.get("clean_context") and impact.get("reproduced")), "Impact must reproduce from a clean context.", impact.get("reproduction_evidence_ids", []))
        check("cleanup_verified", bool(impact.get("cleanup_verified")), "Cleanup verification is mandatory.", impact.get("cleanup_evidence_ids", []))
        if mutation:
            check("exact_approval", bool(approval_present), "Mutation chain execution requires exact approval.", [])
        decision = "validated" if checks and all(item["passed"] for item in checks) else "inconclusive"
        evidence_ids = sorted({eid for item in checks for eid in item["evidence_ids"]})
        evaluation = ChainEvaluation(
            chain_id=str(chain.get("chain_id", "")),
            chain_version=int(chain.get("chain_version", 1)),
            decision=decision,
            impact_status="proven" if decision == "validated" else "inconclusive",
            reproduction_status="succeeded" if bool(impact.get("reproduced")) else "inconclusive",
            cleanup_status="verified" if bool(impact.get("cleanup_verified")) else "failed_or_missing",
            checks=checks,
            evidence_ids=evidence_ids,
            reason="Chain impact proof is complete; Stage 1 still owns final finding status." if decision == "validated" else "Chain impact proof is incomplete; no validated finding is created.",
            validator_version="18.0",
            policy_version="identity-business-impact.1",
            score=1.0 if decision == "validated" else 0.0,
            input_digest=self._digest({"graph_digest": graph.get("graph_digest", ""), "checks": checks, "impact": impact}),
        )
        return evaluation.__dict__

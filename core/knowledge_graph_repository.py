"""Supabase persistence for immutable target knowledge and coverage snapshots."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.knowledge_graph_contract import (
    CoverageItemV1,
    ContradictionSetV1,
    KnowledgeEdgeV1,
    KnowledgeNodeV1,
    KnowledgeSourceLinkV1,
    TargetKnowledgeGraphV1,
)
from core.execution_contract import stable_digest
from core.redact import redact


class KnowledgeGraphRepository:
    def __init__(self, supabase: Any):
        self.sb = supabase

    @staticmethod
    def _dump(value: Any) -> Dict[str, Any]:
        if hasattr(value, "model_dump"):
            row = value.model_dump(mode="json")
        else:
            row = dict(value or {})
        # schema_version belongs to the versioned application contract. The
        # Stage 15 SQL tables intentionally store policy_version/graph_version
        # instead and do not expose a schema_version column. Sending it to
        # PostgREST causes PGRST204 after migration, so keep it at the code
        # boundary and omit it from relational persistence.
        row.pop("schema_version", None)
        return redact(row)

    def _exists(self, table: str, column: str, value: Any) -> bool:
        rows = self.sb.table(table).select(column).eq(column, value).limit(1).execute().data or []
        return bool(rows)

    def _existing_values(self, table: str, column: str, values: List[str]) -> set[str]:
        """Fetch existing keys in bounded batches instead of one query per row."""
        wanted = {str(value) for value in values if value}
        existing: set[str] = set()
        ordered = sorted(wanted)
        for offset in range(0, len(ordered), 200):
            batch = ordered[offset:offset + 200]
            if not batch:
                continue
            rows = self.sb.table(table).select(column).in_(column, batch).execute().data or []
            existing.update(str(row.get(column)) for row in rows if row.get(column))
        return existing

    def _insert_missing(self, table: str, column: str, rows: List[Dict[str, Any]]) -> int:
        """Insert deduplicated rows in batches while preserving append-only semantics."""
        unique: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            key = str(row.get(column) or "")
            if key:
                unique.setdefault(key, row)
        if not unique:
            return 0
        existing = self._existing_values(table, column, list(unique))
        pending = [row for key, row in unique.items() if key not in existing]
        for offset in range(0, len(pending), 100):
            self.sb.table(table).insert(pending[offset:offset + 100]).execute()
        return len(pending)

    def save_compiled(self, compiled: Dict[str, Any]) -> Dict[str, Any]:
        graph = TargetKnowledgeGraphV1(**dict(compiled.get("graph") or {})).ensure_digest()
        graph_row = self._dump(graph)
        if not self._exists("target_knowledge_graph_versions", "graph_id", graph.graph_id):
            self.sb.table("target_knowledge_graph_versions").insert(graph_row).execute()
        else:
            graph_row = (self.sb.table("target_knowledge_graph_versions").select("*").eq("graph_id", graph.graph_id).limit(1).execute().data or [graph_row])[0]

        node_rows = [
            self._dump(KnowledgeNodeV1(**dict(raw)).ensure_fingerprint())
            for raw in compiled.get("nodes") or []
        ]
        self._insert_missing("target_knowledge_nodes", "node_id", node_rows)
        edge_rows = [
            self._dump(KnowledgeEdgeV1(**dict(raw)).ensure_fingerprint())
            for raw in compiled.get("edges") or []
        ]
        self._insert_missing("target_knowledge_edges", "edge_id", edge_rows)
        contradiction_rows = [
            self._dump(ContradictionSetV1(**dict(raw)))
            for raw in compiled.get("contradictions") or []
        ]
        self._insert_missing("target_knowledge_contradictions", "contradiction_id", contradiction_rows)

        coverage_rows = []
        for raw in compiled.get("coverage") or []:
            item = CoverageItemV1(**dict(raw)).ensure_fingerprint()
            coverage_rows.append(self._dump(item))
        self._insert_missing("target_coverage_items", "coverage_id", coverage_rows)
        snapshot = {
            "coverage_snapshot_id": graph.coverage_snapshot_id,
            "graph_id": graph.graph_id,
            "graph_version": graph.version,
            "session_id": graph.session_id,
            "target_fingerprint": graph.target_fingerprint,
            "coverage_ids": [row["coverage_id"] for row in coverage_rows],
            "gap_ids": [row["gap_id"] for row in compiled.get("gaps") or []],
            "digest": graph.coverage_snapshot_id,
        }
        if not self._exists("target_coverage_snapshots", "coverage_snapshot_id", graph.coverage_snapshot_id):
            self.sb.table("target_coverage_snapshots").insert(snapshot).execute()
        source_links = [KnowledgeSourceLinkV1(**dict(row)) for row in compiled.get("source_links") or []]
        linked = self.save_source_links(source_links) if source_links else 0
        return {
            "graph": graph_row,
            "coverage": coverage_rows,
            "gaps": redact(compiled.get("gaps") or []),
            "source_links_saved": linked,
        }

    def save_source_links(self, links: List[KnowledgeSourceLinkV1]) -> int:
        rows = [self._dump(link) for link in links]
        return self._insert_missing("target_knowledge_source_links", "link_id", rows)

    def current(self, session_id: str) -> Optional[Dict[str, Any]]:
        rows = self.sb.table("target_knowledge_graph_versions").select("*").eq(
            "session_id", session_id
        ).eq("status", "current").order("version", desc=True).limit(1).execute().data or []
        return rows[0] if rows else None

    def list_graphs(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        return self.sb.table("target_knowledge_graph_versions").select("*").eq(
            "session_id", session_id
        ).order("version", desc=True).limit(min(200, max(1, limit))).execute().data or []

    def graph(self, session_id: str, graph_id: str) -> Dict[str, Any]:
        rows = self.sb.table("target_knowledge_graph_versions").select("*").eq(
            "session_id", session_id
        ).eq("graph_id", graph_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Knowledge graph not found.")
        row = rows[0]
        nodes = self.sb.table("target_knowledge_nodes").select("*").eq("graph_id", graph_id).order("node_type").execute().data or []
        edges = self.sb.table("target_knowledge_edges").select("*").eq("graph_id", graph_id).order("relation").execute().data or []
        contradictions = self.sb.table("target_knowledge_contradictions").select("*").eq("graph_id", graph_id).execute().data or []
        coverage = self.sb.table("target_coverage_items").select("*").eq("graph_id", graph_id).execute().data or []
        source_links = self.sb.table("target_knowledge_source_links").select("*").eq("graph_id", graph_id).order("created_at").execute().data or []
        return {
            "graph": row,
            "nodes": redact(nodes),
            "edges": redact(edges),
            "contradictions": redact(contradictions),
            "coverage": redact(coverage),
            "source_links": redact(source_links),
        }

    def nodes(self, session_id: str, graph_id: Optional[str] = None, node_type: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        query = self.sb.table("target_knowledge_nodes").select("*").eq("session_id", session_id)
        if graph_id:
            query = query.eq("graph_id", graph_id)
        if node_type:
            query = query.eq("node_type", node_type)
        return redact(query.order("created_at", desc=True).limit(min(1000, max(1, limit))).execute().data or [])

    def edges(self, session_id: str, graph_id: Optional[str] = None, relation: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        query = self.sb.table("target_knowledge_edges").select("*").eq("session_id", session_id)
        if graph_id:
            query = query.eq("graph_id", graph_id)
        if relation:
            query = query.eq("relation", relation)
        return redact(query.order("created_at", desc=True).limit(min(1000, max(1, limit))).execute().data or [])

    def contradictions(self, session_id: str, graph_id: Optional[str] = None, status: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        query = self.sb.table("target_knowledge_contradictions").select("*").eq("session_id", session_id)
        if graph_id:
            query = query.eq("graph_id", graph_id)
        if status:
            query = query.eq("status", status)
        return redact(query.order("created_at", desc=True).limit(min(500, max(1, limit))).execute().data or [])

    def coverage(self, session_id: str, graph_id: Optional[str] = None, status: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        query = self.sb.table("target_coverage_items").select("*").eq("session_id", session_id)
        if graph_id:
            query = query.eq("graph_id", graph_id)
        if status:
            query = query.eq("status", status)
        return redact(query.order("created_at", desc=True).limit(min(2000, max(1, limit))).execute().data or [])

    def gaps(self, session_id: str, graph_id: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        query = self.sb.table("target_coverage_items").select("*").eq("session_id", session_id).in_("status", ["untested", "planned", "in_progress", "inconclusive", "blocked", "stale"])
        if graph_id:
            query = query.eq("graph_id", graph_id)
        rows = query.order("created_at", desc=True).limit(min(1000, max(1, limit))).execute().data or []
        reasons = {
            "untested": "No evidence-linked test covers this target dimension.",
            "planned": "Coverage is planned but has no completed evidence.",
            "in_progress": "Coverage run is incomplete.",
            "inconclusive": "Existing evidence lacks mandatory controls or reproduction.",
            "blocked": "Coverage prerequisite or safety policy is unavailable.",
            "stale": "Existing evidence is outside the current freshness/config boundary.",
        }
        output = []
        for row in rows:
            item = dict(row)
            reason = item.get("gap_reason") or reasons.get(item.get("status", ""), "Coverage is incomplete.")
            item["gap_id"] = f"gap_{stable_digest({'graph': item.get('graph_id', ''), 'coverage': item.get('coverage_id', ''), 'reason': reason}, 32)}"
            item["reason"] = reason
            item["blocked"] = item.get("status") in {"blocked", "stale"}
            item["diagnostic_only"] = item.get("status") in {"inconclusive", "blocked", "stale"}
            item["priority"] = min(1.0, (0.65 if item.get("status") == "untested" else 0.8) + (0.12 if item.get("identity_id") or item.get("auth_context_id") else 0.0) + (0.08 if item.get("policy_id") else 0.0))
            output.append(item)
        return redact(output)

    def review_contradiction(self, session_id: str, contradiction_id: str, status: str, reviewer_id: str, reason: str) -> Dict[str, Any]:
        if status not in {"reviewed", "resolved", "stale"}:
            raise ValueError("Invalid contradiction review status.")
        row = self.sb.table("target_knowledge_contradictions").select("*").eq("session_id", session_id).eq("contradiction_id", contradiction_id).limit(1).execute().data or []
        if not row:
            raise ValueError("Contradiction not found.")
        # Append-only: a review is a new row in the audit table, not a mutation
        # of the original contradiction record.
        review = {
            "review_id": f"kreview_{contradiction_id}_{status}_{reviewer_id}",
            "contradiction_id": contradiction_id,
            "session_id": session_id,
            "status": status,
            "reviewer_id": redact(reviewer_id)[:200],
            "reason": redact(reason)[:2000],
        }
        self.sb.table("target_knowledge_contradiction_reviews").insert(review).execute()
        return review

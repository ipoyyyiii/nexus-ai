"""Supabase persistence for Stage 14 mission graphs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.mission_contract import (
    AttackGraphEdgeV1,
    AttackGraphNodeV1,
    AttackPathV1,
    MissionDecisionV1,
    MissionEventV1,
    MissionV1,
)
from core.redact import redact


class MissionRepository:
    def __init__(self, supabase: Any):
        self.sb = supabase

    def create(self, mission: MissionV1) -> Dict[str, Any]:
        mission.ensure_digest()
        row = mission.model_dump(mode="json")
        row.pop("schema_version", None)
        return (self.sb.table("missions").insert(redact(row)).execute().data or [row])[0]

    def get(self, session_id: str, mission_id: str) -> Optional[Dict[str, Any]]:
        rows = (self.sb.table("missions").select("*").eq("session_id", session_id)
                .eq("mission_id", mission_id).limit(1).execute().data or [])
        return rows[0] if rows else None

    def list(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        return (self.sb.table("missions").select("*").eq("session_id", session_id)
                .order("updated_at", desc=True).limit(min(max(limit, 1), 200)).execute().data or [])

    def update_status(self, session_id: str, mission_id: str, status: str, **values: Any) -> Dict[str, Any]:
        safe = redact({"status": status, **values})
        rows = (self.sb.table("missions").update(safe).eq("session_id", session_id)
                .eq("mission_id", mission_id).execute().data or [])
        if not rows:
            raise ValueError("Mission not found.")
        return rows[0]

    def save_graph(self, session_id: str, graph: Dict[str, Any]) -> Dict[str, Any]:
        mission = dict(graph.get("mission") or {})
        mission_id = str(mission.get("mission_id", ""))
        if not mission_id:
            raise ValueError("Mission graph requires mission_id.")
        version_row = {
            "mission_id": mission_id,
            "session_id": session_id,
            "version": int(mission.get("graph_version", 1)),
            "graph_digest": str(graph.get("graph_digest", mission.get("graph_digest", ""))),
            "objective": str(mission.get("objective", "")),
            "config_digest": str(mission.get("config_digest", "")),
            "policy_version": str(mission.get("policy_version", "1.0")),
        }
        try:
            self.sb.table("mission_versions").insert(version_row).execute()
        except Exception:
            # Replays are idempotent; append-only history must not be updated.
            existing = (self.sb.table("mission_versions").select("*").eq("mission_id", mission_id)
                        .eq("version", version_row["version"]).limit(1).execute().data or [])
            if not existing:
                raise
        for raw in graph.get("nodes") or []:
            node = dict(raw)
            node.pop("schema_version", None)
            node["session_id"] = session_id
            self.sb.table("attack_graph_nodes").upsert(redact(node), on_conflict="node_id").execute()
        for raw in graph.get("edges") or []:
            edge = dict(raw)
            edge.pop("schema_version", None)
            edge["session_id"] = session_id
            self.sb.table("attack_graph_edges").upsert(redact(edge), on_conflict="edge_id").execute()
        self.sb.table("missions").update({
            "graph_version": int(mission.get("graph_version", 1)),
            "graph_digest": str(graph.get("graph_digest", "")),
            "updated_at": mission.get("updated_at"),
            "status": "planning",
        }).eq("session_id", session_id).eq("mission_id", mission_id).execute()
        return graph

    def save_paths(self, session_id: str, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        saved = []
        for raw in result.get("paths") or []:
            path = dict(raw)
            path.pop("schema_version", None)
            path["session_id"] = session_id
            existing = (self.sb.table("attack_paths").select("*").eq("session_id", session_id)
                        .eq("path_id", str(path.get("path_id", ""))).limit(1).execute().data or [])
            if existing:
                row = existing
            else:
                row = self.sb.table("attack_paths").insert(redact(path)).execute().data or [path]
            saved.append(row[0])
        return saved

    def save_decision(self, session_id: str, decision: Dict[str, Any]) -> Dict[str, Any]:
        row = {"session_id": session_id, **dict(decision)}
        row.pop("schema_version", None)
        result = self.sb.table("mission_decisions").insert(redact(row)).execute().data or [row]
        return result[0]

    def save_event(self, session_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        row = {"session_id": session_id, **dict(event)}
        row.pop("schema_version", None)
        # Empty contract strings are represented as SQL NULL for typed
        # correlation columns; PostgreSQL rejects an empty string as uuid.
        if not row.get("job_id"):
            row["job_id"] = None
        result = self.sb.table("mission_events").insert(redact(row)).execute().data or [row]
        return result[0]

    def get_graph(self, session_id: str, mission_id: str, version: Optional[int] = None) -> Dict[str, Any]:
        mission = self.get(session_id, mission_id)
        if not mission:
            raise ValueError("Mission not found.")
        graph_version = int(version or mission.get("graph_version") or 1)
        versions = (self.sb.table("mission_versions").select("*").eq("session_id", session_id)
                    .eq("mission_id", mission_id).eq("version", graph_version).limit(1).execute().data or [])
        nodes = (self.sb.table("attack_graph_nodes").select("*").eq("session_id", session_id)
                 .eq("mission_id", mission_id).eq("graph_version", graph_version).order("created_at").execute().data or [])
        edges = (self.sb.table("attack_graph_edges").select("*").eq("session_id", session_id)
                 .eq("mission_id", mission_id).eq("graph_version", graph_version).order("created_at").execute().data or [])
        return {"mission": mission, "version": versions[0] if versions else {}, "nodes": nodes, "edges": edges,
                "graph_digest": (versions[0].get("graph_digest") if versions else mission.get("graph_digest", ""))}

    def paths(self, session_id: str, mission_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        return (self.sb.table("attack_paths").select("*").eq("session_id", session_id).eq("mission_id", mission_id)
                .order("created_at", desc=True).limit(min(max(limit, 1), 200)).execute().data or [])

    def get_path(self, session_id: str, mission_id: str, path_id: str) -> Optional[Dict[str, Any]]:
        rows = (self.sb.table("attack_paths").select("*").eq("session_id", session_id)
                .eq("mission_id", mission_id).eq("path_id", path_id).limit(1).execute().data or [])
        return rows[0] if rows else None

    def decisions(self, session_id: str, mission_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        return (self.sb.table("mission_decisions").select("*").eq("session_id", session_id).eq("mission_id", mission_id)
                .order("created_at", desc=True).limit(min(max(limit, 1), 200)).execute().data or [])

    def events(self, session_id: str, mission_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        return (self.sb.table("mission_events").select("*").eq("session_id", session_id).eq("mission_id", mission_id)
                .order("created_at").limit(min(max(limit, 1), 500)).execute().data or [])

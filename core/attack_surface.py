"""Attack surface graph from TargetState."""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


@dataclass
class SurfaceNode:
    kind: str  # page/form/api/param/secret
    url: str
    detail: str = ""
    risk: float = 0.0


@dataclass
class AttackSurfaceGraph:
    nodes: List[SurfaceNode] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    graph_id: str = ""
    graph_version: int = 0
    digest: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [asdict(n) for n in self.nodes],
            "edges": list(self.edges),
            "graph_id": self.graph_id,
            "graph_version": self.graph_version,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackSurfaceGraph":
        return cls(
            nodes=[SurfaceNode(**n) for n in data.get("nodes", [])],
            edges=list(data.get("edges", [])),
            graph_id=str(data.get("graph_id", "")),
            graph_version=int(data.get("graph_version", 0) or 0),
            digest=str(data.get("digest", "")),
        )

    @classmethod
    def from_knowledge(cls, compiled: Dict[str, Any]) -> "AttackSurfaceGraph":
        """Compatibility projection; the canonical source is Stage 15 graph."""
        nodes = []
        for item in compiled.get("nodes", []):
            if item.get("node_type") not in {"asset", "origin", "service", "endpoint", "operation", "parameter", "workflow"}:
                continue
            nodes.append(SurfaceNode(
                kind=str(item.get("node_type", "observation")),
                url=str(item.get("canonical_locator") or item.get("reference_id", "")),
                detail=str(item.get("label", ""))[:200],
                risk=float((item.get("metadata") or {}).get("risk", 0.0) or 0.0),
            ))
        return cls(
            nodes=nodes,
            edges=list(compiled.get("edges", [])),
            graph_id=str((compiled.get("graph") or {}).get("graph_id", "")),
            graph_version=int((compiled.get("graph") or {}).get("version", 0) or 0),
            digest=str((compiled.get("graph") or {}).get("digest", "")),
        )


def build_graph(state) -> AttackSurfaceGraph:
    g = AttackSurfaceGraph()
    for p in getattr(state, "pages_visited", []):
        g.nodes.append(SurfaceNode("page", p.get("url",""), f"depth {p.get('depth',0)}", 0.3))
    for ep in getattr(state, "endpoints", []):
        url = ep.url if hasattr(ep, "url") else ep.get("url","")
        g.nodes.append(SurfaceNode("api", url, "discovered endpoint", 0.7))
    # forms from last pages
    for p in getattr(state, "pages_visited", [])[-10:]:
        for f in p.get("forms", []) if isinstance(p, dict) else []:
            g.nodes.append(SurfaceNode("form", p.get("url",""), str(f)[:200], 0.6))
    return g

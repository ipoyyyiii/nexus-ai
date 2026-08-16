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

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": [asdict(n) for n in self.nodes]}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackSurfaceGraph":
        return cls(nodes=[SurfaceNode(**n) for n in data.get("nodes", [])])


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

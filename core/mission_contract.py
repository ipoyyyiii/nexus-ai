"""Versioned contracts for mission-scoped web/API attack-path planning.

Mission planning is deliberately separate from vulnerability validation.  A
mission may contain hypotheses and blocked paths, but only structured evidence
and the existing validation engines can promote a candidate or impact claim.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Literal, Optional

from pydantic import Field, field_validator

from core.execution_contract import ExecutionModel, now_iso, stable_digest
from core.redact import redact


MissionStatus = Literal[
    "draft", "planning", "running", "paused", "waiting_approval",
    "replanning", "completed", "blocked", "cancelled", "failed",
]
GraphNodeType = Literal[
    "asset", "origin", "endpoint", "parameter", "identity", "role",
    "tenant", "session", "entity", "workflow", "state", "observation",
    "candidate", "finding", "privilege", "sensitive_action", "impact",
    "cleanup", "capability",
]
GraphNodeStatus = Literal[
    "hypothesized", "observed", "supported", "blocked", "validated",
    "disproven", "stale", "inconclusive",
]
GraphEdgeRelation = Literal[
    "contains", "reachable", "uses_identity", "owns", "same_object",
    "requires", "enables", "violates", "escalates", "impacts",
    "reproduced_by", "cleaned_by", "blocked_by",
]
GraphEdgeStatus = Literal[
    "hypothesized", "observed", "supported", "blocked", "validated",
    "disproven", "stale", "inconclusive",
]
PathStatus = Literal[
    "proposed", "ready", "running", "waiting_approval", "blocked",
    "backtracking", "stale", "succeeded", "inconclusive", "failed",
    "cancelled",
]
DecisionType = Literal[
    "select_path", "select_action", "reject_action", "replan",
    "backtrack", "stop", "wait_approval", "wait_evidence", "close",
]


class MissionV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    mission_id: str = Field(default_factory=lambda: f"mission_{uuid.uuid4().hex}")
    session_id: str
    target: str
    objective: str
    status: MissionStatus = "draft"
    graph_version: int = 0
    graph_digest: str = ""
    risk_profile: str = "bounded_autonomy"
    budget: Dict[str, Any] = Field(default_factory=dict)
    deadline_at: Optional[str] = None
    config_digest: str = ""
    policy_version: str = "1.0"
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)

    @field_validator("target", "objective", mode="before")
    @classmethod
    def redact_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:4000]

    def ensure_digest(self) -> str:
        self.graph_digest = stable_digest({
            "mission_id": self.mission_id,
            "session_id": self.session_id,
            "target": self.target,
            "objective": self.objective,
            "graph_version": self.graph_version,
            "policy_version": self.policy_version,
        })
        return self.graph_digest


class AttackGraphNodeV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    node_id: str = Field(default_factory=lambda: f"mnode_{uuid.uuid4().hex}")
    mission_id: str
    graph_version: int = 1
    node_type: GraphNodeType
    reference_id: str
    label: str = ""
    status: GraphNodeStatus = "hypothesized"
    evidence_ids: List[str] = Field(default_factory=list)
    identity_id: str = ""
    tenant_label: str = ""
    protocol: str = "http"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.label = redact(self.label)[:1000]
        self.metadata = redact(self.metadata)
        if not self.fingerprint:
            self.fingerprint = stable_digest({
                "mission_id": self.mission_id,
                "graph_version": self.graph_version,
                "node_type": self.node_type,
                "reference_id": self.reference_id,
                "identity_id": self.identity_id,
                "tenant_label": self.tenant_label,
            }, 64)


class AttackGraphEdgeV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    edge_id: str = Field(default_factory=lambda: f"medge_{uuid.uuid4().hex}")
    mission_id: str
    graph_version: int = 1
    source_node_id: str
    target_node_id: str
    relation: GraphEdgeRelation
    status: GraphEdgeStatus = "hypothesized"
    evidence_ids: List[str] = Field(default_factory=list)
    required_action_ids: List[str] = Field(default_factory=list)
    preconditions: List[str] = Field(default_factory=list)
    required_identity_ids: List[str] = Field(default_factory=list)
    risk: str = "read_only"
    cleanup_refs: List[str] = Field(default_factory=list)
    reason: str = ""
    deterministic: bool = True
    fingerprint: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.reason = redact(self.reason)[:2000]
        if not self.fingerprint:
            self.fingerprint = stable_digest({
                "mission_id": self.mission_id,
                "graph_version": self.graph_version,
                "source": self.source_node_id,
                "target": self.target_node_id,
                "relation": self.relation,
                "action_ids": sorted(self.required_action_ids),
            }, 64)


class AttackPathV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    path_id: str = Field(default_factory=lambda: f"path_{uuid.uuid4().hex}")
    mission_id: str
    graph_version: int = 1
    edge_ids: List[str] = Field(default_factory=list)
    node_ids: List[str] = Field(default_factory=list)
    objective: str = ""
    status: PathStatus = "proposed"
    score: float = 0.0
    score_breakdown: Dict[str, float] = Field(default_factory=dict)
    required_evidence_ids: List[str] = Field(default_factory=list)
    required_identity_ids: List[str] = Field(default_factory=list)
    required_approval: bool = False
    approval_digest: str = ""
    budget: Dict[str, Any] = Field(default_factory=dict)
    cleanup_refs: List[str] = Field(default_factory=list)
    stop_conditions: List[str] = Field(default_factory=list)
    stale_reason: str = ""
    path_digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.objective = redact(self.objective)[:4000]
        self.budget = redact(self.budget)
        if not self.path_digest:
            self.path_digest = stable_digest({
                "mission_id": self.mission_id,
                "graph_version": self.graph_version,
                "edge_ids": self.edge_ids,
                "node_ids": self.node_ids,
                "objective": self.objective,
                "required_evidence_ids": sorted(self.required_evidence_ids),
                "required_identity_ids": sorted(self.required_identity_ids),
                "required_approval": self.required_approval,
                "budget": self.budget,
                "cleanup_refs": sorted(self.cleanup_refs),
            })
        if self.required_approval and not self.approval_digest:
            self.approval_digest = stable_digest({
                "path_digest": self.path_digest,
                "mission_id": self.mission_id,
                "graph_version": self.graph_version,
                "edge_ids": self.edge_ids,
                "required_evidence_ids": sorted(self.required_evidence_ids),
                "required_identity_ids": sorted(self.required_identity_ids),
                "budget": self.budget,
                "cleanup_refs": sorted(self.cleanup_refs),
            })


class MissionDecisionV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    decision_id: str = Field(default_factory=lambda: f"decision_{uuid.uuid4().hex}")
    mission_id: str
    graph_version: int
    decision_type: DecisionType
    selected_path_id: str = ""
    selected_edge_id: str = ""
    selected_action_id: str = ""
    considered_paths: List[Dict[str, Any]] = Field(default_factory=list)
    rejected_alternatives: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_gap_ids: List[str] = Field(default_factory=list)
    reason: str = ""
    expected_information_gain: float = 0.0
    estimated_cost: float = 0.0
    risk_score: float = 0.0
    deterministic: bool = True
    input_digest: str = ""
    output_digest: str = ""
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.reason = redact(self.reason)[:4000]
        self.considered_paths = redact(self.considered_paths)
        self.rejected_alternatives = redact(self.rejected_alternatives)


class MissionEventV1(ExecutionModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: str = Field(default_factory=lambda: f"mevent_{uuid.uuid4().hex}")
    mission_id: str
    graph_version: int = 0
    event_type: str
    path_id: str = ""
    edge_id: str = ""
    decision_id: str = ""
    job_id: str = ""
    attempt_id: str = ""
    checkpoint_id: str = ""
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    def model_post_init(self, __context: Any) -> None:
        self.payload = redact(self.payload)

"""Deterministic, evidence-driven hypothesis planner.

The planner does not execute tools and never promotes findings.  It turns the
current session snapshot into competing hypotheses, scores bounded tests, and
emits auditable action proposals that still pass through ExecutionGuard and
human approval.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from core.config_loader import get_config
from core.structured_contract import (
    EvidenceGapV1,
    ModelActionTraceV1,
    PlannerActionV1,
    ReasoningAdaptationV1,
    ReasoningBranchTransitionV1,
    ReasoningBranchV1,
    ReasoningCycleV1,
    ReasoningDecisionV1,
    StopConditionV1,
)
from core.workflow_models import (
    ActionProposal,
    HypothesisRecord,
    FindingRecord,
    PlannerDecisionRecord,
    RecordStatus,
    WorkflowState,
)


TERMINAL_HYPOTHESIS_STATUSES = {
    RecordStatus.VALIDATED.value,
    RecordStatus.DISPROVEN.value,
    RecordStatus.COMPLETE.value,
}
ACTION_DEDUP_STATUSES = {"pending", "proposed", "approved", "running", "rejected"}

TOOL_RUN_NAME_ALIASES = {
    "sql_injection_scanner": "scan_sql_injection",
    "xss_csrf_detector": "detect_xss_csrf",
    "lfi_rfi_scanner": "scan_lfi_rfi",
    "active_recon_target": "human_recon_crawl",
}

# Surface semantics remain preferred when available, but a mapped application
# with no useful parameter names must still receive core detector coverage.
# Mutation, credential-attempt, upload, and OOB/SSRF actions are intentionally
# excluded from this unattended local-lab baseline.
BASELINE_CATEGORIES: Tuple[str, ...] = (
    "cors",
    "sql_injection",
    "xss",
    "path_traversal",
    "ssti",
    "open_redirect",
    "graphql",
    "session_security",
    "websocket",
)


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, float(value)))


def _digest(*parts: Any, length: int = 32) -> str:
    encoded = "|".join(json.dumps(part, sort_keys=True, default=str) for part in parts)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:length]


def _words(value: str) -> set[str]:
    return {item for item in re.findall(r"[a-z0-9_]+", (value or "").lower()) if len(item) > 2}


def _confidence_label(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _binary_entropy(probability: float) -> float:
    probability = _clamp(probability, 0.001, 0.999)
    return -(probability * math.log2(probability) + (1 - probability) * math.log2(1 - probability))


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return {}


def _safe_endpoint_url(value: Any) -> str:
    """Accept only concrete HTTP(S) endpoints suitable for a detector.

    Redirect payloads and browser artifacts can contain escaped separators or
    control characters.  Feeding those strings back into a multi-request
    detector creates slow false paths and can make a bounded mission appear
    hung.  Invalid artifacts are skipped; the planner may fall back to the
    session's original target.
    """
    raw = str(value or "").strip()
    if not raw or "\\" in raw or any(ord(char) < 32 for char in raw):
        return ""
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
    except (TypeError, ValueError):
        return ""
    return raw


def _stable_reasoning_value(value: Any) -> Any:
    """Remove runtime-only IDs/timestamps before replay digesting a cycle."""
    volatile = {
        "cycle_id", "hypothesis_id", "action_id", "gap_id", "stop_condition_id",
        "trace_id", "branch_id", "transition_id", "adaptation_id", "created_at",
        "finished_at", "record_id", "reasoning_gap_ids",
        "required_action_ids", "evidence_gap_ids", "selected_action_ids",
        "hypothesis_ids", "action_ids", "stop_condition_ids",
        "proposal_id", "last_updated",
    }
    if isinstance(value, dict):
        return {key: _stable_reasoning_value(item) for key, item in sorted(value.items()) if key not in volatile}
    if isinstance(value, (list, tuple)):
        return [_stable_reasoning_value(item) for item in value]
    if hasattr(value, "model_dump"):
        return _stable_reasoning_value(value.model_dump(mode="json"))
    if hasattr(value, "__dict__"):
        return _stable_reasoning_value(value.__dict__)
    if isinstance(value, str):
        # Workflow models intentionally use runtime UUIDs for operational
        # identity.  They must not make a replay digest change when the same
        # snapshot is evaluated in a fresh process.
        value = re.sub(
            r"\b(?:hyp|action|r_action|gap|stop|trace|branch|transition|adapt|plan)_[0-9a-f]{16,}\b",
            "<runtime-id>",
            value,
            flags=re.IGNORECASE,
        )
        return re.sub(
            r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})\b",
            "<timestamp>",
            value,
        )
    return value


@dataclass(frozen=True)
class PlannerCapability:
    category: str
    tools: Tuple[str, ...]
    action: str = "hypothesis_validation"
    cost: float = 2.0
    risk: str = "medium"
    risk_score: float = 0.35
    discriminating_power: float = 0.8
    min_identities: int = 0
    expected_evidence: str = "Baseline, bounded test, negative control, and reproduction evidence."
    stop_conditions: Tuple[str, ...] = (
        "mandatory validation checks pass",
        "hypothesis is disproven by controls",
        "test budget is exhausted",
        "scope or safety guard rejects the action",
    )


CAPABILITIES: Dict[str, PlannerCapability] = {
    "surface_mapping": PlannerCapability(
        "surface_mapping", ("__recon_mission__",), action="attack_surface_mapping",
        cost=1.5, risk="low", risk_score=0.12, discriminating_power=0.9,
        expected_evidence="Reachable endpoints, parameters, technologies, identities, and trust boundaries.",
    ),
    "browser_workflow_discovery": PlannerCapability(
        "browser_workflow_discovery", ("browser_workflow_discovery",), action="browser_workflow_discovery",
        cost=1.4, risk="low", risk_score=0.08, discriminating_power=0.9,
        expected_evidence="Versioned workflow draft with DOM, network, identity, and state-transition evidence.",
    ),
    "browser_baseline": PlannerCapability(
        "browser_baseline", ("stateful_browser_workflow",), action="browser_baseline",
        cost=1.6, risk="low", risk_score=0.1, discriminating_power=0.85,
        expected_evidence="Clean browser baseline with before/after snapshots and stable state digest.",
    ),
    "business_logic": PlannerCapability(
        "business_logic", ("business_invariant_evaluator",), action="business_invariant_validation",
        cost=2.2, risk="medium", risk_score=0.35, discriminating_power=0.9,
        expected_evidence="Baseline, bounded test, control, reproduction, and cleanup-linked invariant evaluation.",
    ),
    "business_logic_mutation": PlannerCapability(
        "business_logic_mutation", ("stateful_browser_workflow",), action="business_invariant_validation",
        cost=2.8, risk="high", risk_score=0.6, discriminating_power=0.95,
        expected_evidence="Approved mutation with clean reproduction and deterministic business invariant checks.",
    ),
    "sql_injection": PlannerCapability(
        "sql_injection", ("scan_sql_injection", "blind_sqli_scanner"),
        expected_evidence="Paired baseline/test/control observations with deterministic SQLi reproduction.",
    ),
    "xss": PlannerCapability(
        "xss", ("detect_xss_csrf", "dom_xss_scanner", "stored_xss_scanner"),
        expected_evidence="Reflection context plus browser execution using a unique marker and a control.",
    ),
    "ssrf": PlannerCapability(
        "ssrf", ("scan_ssrf", "ssrf_advanced_scanner"), cost=2.5, risk_score=0.4,
        expected_evidence="Unique OOB correlation attributed to the target and a no-callback control.",
    ),
    "xxe": PlannerCapability(
        "xxe", ("xxe_tester",), cost=2.5, risk_score=0.4,
        expected_evidence="Parser-specific response or unique OOB correlation with a negative control.",
    ),
    "ssti": PlannerCapability(
        "ssti", ("ssti_tester",), cost=2.0, risk_score=0.35,
        expected_evidence="Paired deterministic expression results or timing evidence with controls.",
    ),
    "command_injection": PlannerCapability(
        "command_injection", ("command_injection_scanner",), cost=2.5, risk_score=0.45,
        expected_evidence="Bounded marker/timing evidence with randomized baselines and controls.",
    ),
    "path_traversal": PlannerCapability(
        "path_traversal", ("scan_lfi_rfi",), cost=2.0, risk_score=0.3,
        expected_evidence="A test-only signature absent from baseline and controls, then reproduced.",
    ),
    "authorization": PlannerCapability(
        "authorization", ("authorization_differential_replay", "access_control_scanner"),
        cost=2.5, risk_score=0.35, min_identities=2,
        expected_evidence="Same object replayed through two isolated identity contexts with an explicit expectation.",
    ),
    "open_redirect": PlannerCapability(
        "open_redirect", ("browser_find_open_redirect",), cost=1.2, risk="low", risk_score=0.15,
        expected_evidence="An external Location header or browser navigation plus a same-origin control.",
    ),
    "cors": PlannerCapability(
        "cors", ("cors_tester",), cost=1.5, risk="low", risk_score=0.18,
        expected_evidence="Attacker origin acceptance and readable credentialed sensitive response.",
    ),
    "graphql": PlannerCapability(
        "graphql", ("graphql_tester",), cost=1.8, risk_score=0.25,
        expected_evidence="Schema/operation-specific baseline, bounded test, and control responses.",
    ),
    "csrf": PlannerCapability(
        "csrf", ("csrf_exploit_scanner",), cost=2.0, risk_score=0.4,
        expected_evidence="A state-changing request, cross-site control, and verified postcondition.",
    ),
    "mass_assignment": PlannerCapability(
        "mass_assignment", ("mass_assignment_scanner",), cost=2.0, risk_score=0.4,
        expected_evidence="Server-side state diff proving an unauthorized field change and cleanup evidence.",
    ),
    "file_upload": PlannerCapability(
        "file_upload", ("file_upload_scanner",), cost=3.0, risk="high", risk_score=0.65,
        expected_evidence="Benign canary upload, retrieval behavior, server-side handling, and cleanup evidence.",
    ),
    "session_security": PlannerCapability(
        "session_security", ("session_management_scanner", "test_jwt_weakness"),
        cost=2.0, risk_score=0.3,
        expected_evidence="Isolated authentication/session observations with replay and negative controls.",
    ),
    "websocket": PlannerCapability(
        "websocket", ("websocket_security_scanner",), cost=2.2, risk_score=0.35,
        expected_evidence="Handshake and message authorization comparisons across explicit identities.",
    ),
}


VULNERABILITY_ALIASES: Sequence[Tuple[str, Tuple[str, ...]]] = (
    ("authorization", ("idor", "bola", "broken access", "authorization", "access control", "privilege", "tenant")),
    ("sql_injection", ("sql injection", "sqli", "blind sql", "boolean sql", "time-based sql")),
    ("command_injection", ("command injection", "cmdi", "remote code", "rce")),
    ("path_traversal", ("lfi", "rfi", "path traversal", "file inclusion", "directory traversal")),
    ("open_redirect", ("open redirect", "unvalidated redirect")),
    ("mass_assignment", ("mass assignment", "overposting")),
    ("session_security", ("jwt", "session", "authentication", "password reset", "2fa", "mfa")),
    ("file_upload", ("file upload", "upload")),
    ("websocket", ("websocket", "ws security")),
    ("graphql", ("graphql",)),
    ("ssrf", ("ssrf", "server-side request")),
    ("xxe", ("xxe", "xml external")),
    ("ssti", ("ssti", "template injection")),
    ("xss", ("xss", "cross-site scripting")),
    ("cors", ("cors", "cross-origin")),
    ("csrf", ("csrf", "cross-site request forgery")),
    ("business_logic", ("business logic", "business rule", "workflow invariant", "state transition", "price tampering", "coupon reuse", "self approval")),
)


@dataclass
class PlanningSnapshot:
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    tool_runs: List[Dict[str, Any]] = field(default_factory=list)
    identities: List[Dict[str, Any]] = field(default_factory=list)
    auth_contexts: List[Dict[str, Any]] = field(default_factory=list)
    identity_graphs: List[Dict[str, Any]] = field(default_factory=list)
    identity_coverage_plans: List[Dict[str, Any]] = field(default_factory=list)
    workflow_matrices: List[Dict[str, Any]] = field(default_factory=list)
    business_entities: List[Dict[str, Any]] = field(default_factory=list)
    published_workflows: List[Dict[str, Any]] = field(default_factory=list)
    request_templates: List[Dict[str, Any]] = field(default_factory=list)
    resource_instances: List[Dict[str, Any]] = field(default_factory=list)
    authorization_expectations: List[Dict[str, Any]] = field(default_factory=list)
    authorization_replays: List[Dict[str, Any]] = field(default_factory=list)
    business_invariants: List[Dict[str, Any]] = field(default_factory=list)
    business_state_transitions: List[Dict[str, Any]] = field(default_factory=list)
    browser_runs: List[Dict[str, Any]] = field(default_factory=list)
    retests: List[Dict[str, Any]] = field(default_factory=list)
    workflow_events: List[Dict[str, Any]] = field(default_factory=list)

    def digest(self) -> str:
        stable = {
            "candidates": [
                (item.get("candidate_id"), item.get("status"), item.get("updated_at"), item.get("confidence_score"))
                for item in self.candidates
            ],
            "observations": [item.get("observation_id") for item in self.observations],
            "errors": list(self.errors),
            "tool_runs": [(item.get("tool_run_id"), item.get("status")) for item in self.tool_runs],
            "identities": [(item.get("identity_id"), item.get("status")) for item in self.identities],
            "auth_contexts": [(item.get("auth_context_id"), item.get("identity_id"), item.get("status")) for item in self.auth_contexts],
            "identity_graphs": [(item.get("graph_id"), item.get("digest")) for item in self.identity_graphs],
            "identity_coverage_plans": [(item.get("plan_id"), item.get("status"), item.get("digest")) for item in self.identity_coverage_plans],
            "workflow_matrices": [(item.get("matrix_id"), item.get("status")) for item in self.workflow_matrices],
            "business_entities": [(item.get("fingerprint"), item.get("state_digest")) for item in self.business_entities],
            "published_workflows": [(item.get("workflow_id"), item.get("current_version")) for item in self.published_workflows],
            "request_templates": [(item.get("template_id"), item.get("fingerprint"), item.get("side_effect_class")) for item in self.request_templates],
            "resource_instances": [(item.get("resource_id"), item.get("fingerprint"), item.get("owner_identity_id")) for item in self.resource_instances],
            "authorization_expectations": [(item.get("expectation_id"), item.get("subject_identity_id"), item.get("resource_fingerprint"), item.get("expected")) for item in self.authorization_expectations],
            "authorization_replays": [(item.get("replay_run_id"), item.get("status")) for item in self.authorization_replays],
            "business_invariants": [(item.get("invariant_id"), item.get("status"), item.get("revision")) for item in self.business_invariants],
            "business_state_transitions": [(item.get("transition_id"), item.get("after_snapshot_id")) for item in self.business_state_transitions],
            "browser_runs": [(item.get("run_id"), item.get("status"), item.get("role")) for item in self.browser_runs],
            "retests": [(item.get("retest_id"), item.get("finding_id"), item.get("status"), item.get("retest_evidence_ids")) for item in self.retests],
            "workflow_events": [(item.get("event_id"), item.get("type"), item.get("success"), item.get("evidence_id")) for item in self.workflow_events[-100:]],
        }
        return _digest(stable)


@dataclass
class PlanningResult:
    hypotheses: List[HypothesisRecord]
    proposals: List[ActionProposal]
    decision: PlannerDecisionRecord


@dataclass
class ReasoningCycleResult:
    cycle: ReasoningCycleV1
    hypotheses: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    evidence_gaps: List[Dict[str, Any]]
    stop_conditions: List[Dict[str, Any]]
    decision: Dict[str, Any]
    model_traces: List[Dict[str, Any]] = field(default_factory=list)
    branches: List[Dict[str, Any]] = field(default_factory=list)
    branch_transitions: List[Dict[str, Any]] = field(default_factory=list)
    adaptation: Dict[str, Any] = field(default_factory=dict)


class AdaptiveHypothesisPlanner:
    """Build and rank deterministic next tests from session-local evidence."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        raw = config if config is not None else get_config().get("adaptive_planner", {})
        self.config = raw or {}
        configured_proposals = self.config.get("max_proposals")
        if configured_proposals is None or str(configured_proposals).strip().lower() in {"", "auto", "unlimited", "none", "null"}:
            self.max_proposals: Optional[int] = None
        else:
            self.max_proposals = max(1, int(configured_proposals))
        self.max_hypotheses = max(8, min(250, int(self.config.get("max_hypotheses", 80))))
        self.max_attempts = max(1, min(10, int(self.config.get("max_attempts_per_hypothesis", 3))))
        weights = self.config.get("scoring", {})
        self.weights = {
            "information_gain": float(weights.get("information_gain", 0.38)),
            "objective_relevance": float(weights.get("objective_relevance", 0.22)),
            "evidence_strength": float(weights.get("evidence_strength", 0.18)),
            "novelty": float(weights.get("novelty", 0.12)),
            "technology_fit": float(weights.get("technology_fit", 0.10)),
            "cost_penalty": float(weights.get("cost_penalty", 0.16)),
            "risk_penalty": float(weights.get("risk_penalty", 0.22)),
            "failure_penalty": float(weights.get("failure_penalty", 0.10)),
        }
        self.search_strategy = str(self.config.get("search_strategy", "best_first"))
        if self.search_strategy not in {"best_first", "beam", "bounded_backtrack", "explore_exploit"}:
            self.search_strategy = "best_first"
        self.max_branch_factor = max(1, min(12, int(self.config.get("max_branch_factor", 4))))
        self.max_backtracks = max(0, min(20, int(self.config.get("max_backtracks", 3))))
        self.min_information_gain = _clamp(float(self.config.get("min_information_gain", 0.10)))
        self.repetition_penalty = _clamp(float(self.config.get("repetition_penalty", 0.20)))

    def plan(
        self,
        context: Dict[str, Any],
        state: Any,
        snapshot: Optional[PlanningSnapshot] = None,
        request: str = "",
    ) -> PlanningResult:
        snapshot = snapshot or PlanningSnapshot()
        workflow: WorkflowState = state.workflow
        cycle_id = f"plan_{_digest(snapshot.digest(), request, len(workflow.planner_decisions), length=24)}"

        generated = self._candidate_hypotheses(context, snapshot)
        generated.extend(self._surface_hypotheses(context, state, snapshot))
        generated.extend(self._baseline_hypotheses(context, state, snapshot))
        if not generated:
            generated.append(self._surface_gap_hypothesis(context, state))

        # Candidate-backed hypotheses win over surface heuristics sharing a
        # fingerprint-like category/target pair.
        generated.sort(key=lambda item: (not bool(item.source_candidate_ids), item.fingerprint))
        unique: Dict[str, HypothesisRecord] = {}
        for item in generated:
            unique.setdefault(item.fingerprint, item)

        current: List[HypothesisRecord] = []
        for hypothesis in list(unique.values())[: self.max_hypotheses]:
            configured_attempts = hypothesis.metadata.get("max_test_attempts") if isinstance(hypothesis.metadata, dict) else None
            try:
                hypothesis.max_test_attempts = (
                    max(1, min(10, int(configured_attempts)))
                    if configured_attempts is not None else self.max_attempts
                )
            except (TypeError, ValueError):
                hypothesis.max_test_attempts = self.max_attempts
            current.append(workflow.upsert_hypothesis(hypothesis))
        self._sync_validated_findings(workflow, snapshot)

        active_fingerprints = {
            item.fingerprint
            for item in workflow.proposals
            if item.fingerprint and item.status in ACTION_DEDUP_STATUSES
        }
        failed_tools = self._failed_tool_counts(snapshot.tool_runs)
        baseline_matrix_active = any(
            isinstance(item.metadata, dict)
            and item.metadata.get("source") == "baseline_detector_matrix"
            for item in generated
        )
        covered_categories = {
            str(item.category or "")
            for item in workflow.hypotheses
            if str(item.category or "") in BASELINE_CATEGORIES
            and (item.test_attempts > 0 or item.status in TERMINAL_HYPOTHESIS_STATUSES)
        }
        uncovered_baseline = (
            set(BASELINE_CATEGORIES) - covered_categories
            if baseline_matrix_active else set()
        )
        considered: List[Dict[str, Any]] = []
        proposal_candidates: List[Tuple[float, HypothesisRecord, PlannerCapability, str, Dict[str, float], List[str], str]] = []
        knowledge_gaps: List[str] = [
            f"Evidence source unavailable: {item}" for item in snapshot.errors
        ]
        stop_reasons: List[str] = []

        for hypothesis in current:
            if hypothesis.status in TERMINAL_HYPOTHESIS_STATUSES:
                stop_reasons.append(f"{hypothesis.hypothesis_id}: {hypothesis.status}")
                considered.append(self._considered(hypothesis, "", 0.0, False, f"Stopped: hypothesis is {hypothesis.status}."))
                continue
            if hypothesis.test_attempts >= hypothesis.max_test_attempts:
                hypothesis.status = RecordStatus.INCONCLUSIVE.value
                hypothesis.decision_reason = "Per-hypothesis test budget exhausted without deterministic validation."
                stop_reasons.append(f"{hypothesis.hypothesis_id}: test budget exhausted")
                considered.append(self._considered(hypothesis, "", 0.0, False, hypothesis.decision_reason))
                continue

            capability = CAPABILITIES.get(hypothesis.category)
            if capability is None:
                gap = f"No deterministic capability is registered for '{hypothesis.category}' ({hypothesis.hypothesis_id})."
                knowledge_gaps.append(gap)
                considered.append(self._considered(hypothesis, "", 0.0, False, gap))
                continue

            unmet = self._unmet_preconditions(capability, hypothesis, snapshot)
            tool, alternatives = self._choose_tool(capability, state, failed_tools)
            if not tool:
                gap = f"No executable tool is available for '{hypothesis.category}'."
                knowledge_gaps.append(gap)
                considered.append(self._considered(hypothesis, "", 0.0, False, gap))
                continue

            score, breakdown = self._score(hypothesis, capability, tool, context, state, request, failed_tools)
            category_key = str(hypothesis.category or capability.category)
            # A mapped application must make progress across vulnerability
            # families.  Surface heuristics can otherwise keep producing a
            # fresh login/session hypothesis and starve untouched baseline
            # detectors on later replans.
            if category_key in BASELINE_CATEGORIES and uncovered_baseline:
                coverage_adjustment = 0.22 if category_key in uncovered_baseline else -0.18
                score = round(_clamp(score + coverage_adjustment), 4)
                breakdown["coverage_bonus"] = round(coverage_adjustment, 4)
            evidence_snapshot = sorted(set(hypothesis.supporting_evidence_ids + hypothesis.contradicting_evidence_ids))
            action_fingerprint = _digest(
                hypothesis.fingerprint, tool, evidence_snapshot, hypothesis.test_attempts,
            )
            if unmet:
                reason = "Blocked preconditions: " + "; ".join(unmet)
                knowledge_gaps.extend(item for item in unmet if item not in knowledge_gaps)
                considered.append(self._considered(hypothesis, tool, score, False, reason, breakdown))
                continue
            if action_fingerprint in active_fingerprints:
                considered.append(self._considered(
                    hypothesis, tool, score, False,
                    "Equivalent proposal is active or was rejected for this evidence snapshot.", breakdown,
                ))
                continue

            proposal_candidates.append((score, hypothesis, capability, tool, breakdown, alternatives, action_fingerprint))

        proposal_candidates.sort(key=lambda item: (-item[0], item[1].fingerprint, item[3]))
        proposals: List[ActionProposal] = []
        selected_ids: List[str] = []
        selected_categories: set[str] = set()
        for score, hypothesis, capability, tool, breakdown, alternatives, action_fingerprint in proposal_candidates:
            # Keep a single proposal per vulnerability family in one cycle.
            # Without this diversity cap, several login-like endpoints can
            # consume the whole budget with repeated session checks and starve
            # SQLi/XSS/CORS/etc. detector coverage.
            category_key = str(hypothesis.category or capability.category)
            selected = (
                (self.max_proposals is None or len(proposals) < self.max_proposals)
                and category_key not in selected_categories
            )
            reason = self._selection_reason(hypothesis, capability, tool, breakdown, selected)
            if not selected:
                considered.append(self._considered(hypothesis, tool, score, False, reason, breakdown))
                continue
            proposal = ActionProposal(
                action=capability.action,
                target_url=hypothesis.target_url or context.get("target_url", ""),
                rationale=reason,
                expected_evidence=capability.expected_evidence,
                risk=capability.risk,
                requires_approval=True,
                cleanup_required=capability.category in {"csrf", "mass_assignment", "file_upload"},
                hypothesis_id=hypothesis.hypothesis_id,
                recommended_tool=tool,
                alternative_tools=alternatives,
                information_gain=hypothesis.expected_information_gain,
                estimated_cost=capability.cost,
                risk_score=capability.risk_score,
                priority_score=score,
                score_breakdown=breakdown,
                preconditions=self._preconditions(capability),
                stop_conditions=list(capability.stop_conditions),
                evidence_ids=sorted(set(hypothesis.supporting_evidence_ids)),
                input_bindings={
                    "target_url": hypothesis.target_url or context.get("target_url", ""),
                    "method": hypothesis.method,
                    "parameter": hypothesis.parameter,
                    "candidate_ids": list(hypothesis.source_candidate_ids),
                },
                fingerprint=action_fingerprint,
                planner_cycle_id=cycle_id,
                planner_managed=True,
            )
            workflow.add_proposal(proposal)
            hypothesis.required_action_ids.append(proposal.action_id)
            hypothesis.status = RecordStatus.PROPOSED.value
            hypothesis.decision_reason = reason
            proposals.append(proposal)
            selected_categories.add(category_key)
            selected_ids.append(proposal.action_id)
            considered.append(self._considered(hypothesis, tool, score, True, reason, breakdown, proposal.action_id))

        decision = PlannerDecisionRecord(
            cycle_id=cycle_id,
            snapshot_digest=snapshot.digest(),
            considered_actions=sorted(
                considered,
                key=lambda item: (-float(item.get("priority_score", 0.0)), item.get("hypothesis_id", "")),
            ),
            selected_action_ids=selected_ids,
            knowledge_gaps=list(dict.fromkeys(knowledge_gaps)),
            stop_reasons=list(dict.fromkeys(stop_reasons)),
            rationale=(
                f"Selected {len(proposals)} bounded test(s) from {len(considered)} considered hypothesis actions "
                "using deterministic information-gain, objective, evidence, cost, risk, novelty, and failure scoring."
            ),
        )
        workflow.add_planner_decision(decision)
        return PlanningResult(current, proposals, decision)

    def build_search_branches(
        self,
        context: Dict[str, Any],
        snapshot: PlanningSnapshot,
        planned: PlanningResult,
        cycle_id: str,
        *,
        failed_action_ids: Optional[Sequence[str]] = None,
        backtrack_count: int = 0,
    ) -> Tuple[List[ReasoningBranchV1], List[ReasoningBranchTransitionV1], ReasoningAdaptationV1]:
        """Compile bounded, replay-stable search branches from deterministic proposals.

        This is intentionally separate from execution. A branch only describes a
        possible next action; the durable executor, safety kernel, and approval
        service remain the authority that can dispatch it.
        """
        failed = {str(item) for item in (failed_action_ids or []) if item}
        candidates: List[Tuple[float, ActionProposal, Dict[str, float]]] = []
        for proposal in planned.proposals:
            score = _clamp(float(proposal.priority_score))
            breakdown = dict(proposal.score_breakdown or {})
            if proposal.action_id in failed or proposal.recommended_tool in failed:
                score = _clamp(score - self.repetition_penalty)
                breakdown["failure_penalty"] = min(1.0, float(breakdown.get("failure_penalty", 0.0)) + self.repetition_penalty)
            if self.search_strategy == "explore_exploit":
                # Deterministic novelty bonus favors a different capability only
                # when its base score is close to the incumbent.
                novelty = float(breakdown.get("novelty", 0.0))
                score = _clamp(score + 0.08 * novelty)
                breakdown["exploration_bonus"] = 0.08 * novelty
            breakdown["search_score"] = score
            candidates.append((score, proposal, breakdown))
        candidates.sort(key=lambda item: (-item[0], item[1].fingerprint, item[1].action_id))
        candidates = candidates[: self.max_branch_factor]

        branches: List[ReasoningBranchV1] = []
        transitions: List[ReasoningBranchTransitionV1] = []
        for ordinal, (score, proposal, breakdown) in enumerate(candidates):
            branch_id = f"branch_{_digest(cycle_id, proposal.fingerprint, snapshot.digest(), ordinal, length=32)}"
            status = "ready" if score >= self.min_information_gain else "blocked"
            reason = "Candidate action passed deterministic search preconditions." if status == "ready" else "Information gain is below the configured minimum."
            branch = ReasoningBranchV1(
                branch_id=branch_id,
                cycle_id=cycle_id,
                session_id=str(context.get("session_id", "")),
                status=status,
                hypothesis_ids=[proposal.hypothesis_id] if proposal.hypothesis_id else [],
                action_ids=[proposal.action_id],
                evidence_snapshot_digest=snapshot.digest(),
                search_depth=1,
                score=score,
                score_breakdown=breakdown,
                estimated_cost=float(proposal.estimated_cost),
                risk_score=_clamp(float(proposal.risk_score)),
                backtrack_count=max(0, int(backtrack_count)),
                stop_reason="" if status == "ready" else reason,
                input_digest=_digest(snapshot.digest(), proposal.fingerprint, self.search_strategy),
            )
            branches.append(branch)
            transitions.append(ReasoningBranchTransitionV1(
                branch_id=branch_id,
                cycle_id=cycle_id,
                session_id=str(context.get("session_id", "")),
                transition_type="created",
                from_status="",
                to_status=status,
                reason=reason,
                action_id=proposal.action_id,
                input_digest=branch.input_digest,
            ))

        selected = next((item for item in branches if item.status == "ready"), None)
        if selected:
            transitions.append(ReasoningBranchTransitionV1(
                branch_id=selected.branch_id,
                cycle_id=cycle_id,
                session_id=str(context.get("session_id", "")),
                transition_type="selected",
                from_status=selected.status,
                to_status="running",
                reason="Selected highest-scoring branch; dispatch remains separately gated.",
                action_id=selected.action_ids[0] if selected.action_ids else "",
                input_digest=selected.input_digest,
            ))
            selected_action = selected.action_ids[0] if selected.action_ids else ""
            adaptation = ReasoningAdaptationV1(
                cycle_id=cycle_id,
                session_id=str(context.get("session_id", "")),
                strategy=self.search_strategy,
                selected_branch_id=selected.branch_id,
                selected_action_id=selected_action,
                alternative_action_ids=[item.action_ids[0] for item in branches if item.branch_id != selected.branch_id and item.action_ids],
                reason="Selected the highest information-gain branch after deterministic cost, risk, novelty, and failure adjustment.",
                information_gain=selected.score,
                uncertainty_before=_clamp(1.0 - selected.score),
                uncertainty_after=_clamp(1.0 - selected.score * 0.8),
                backtracked=backtrack_count > 0,
                input_digest=_digest(snapshot.digest(), [item.branch_id for item in branches]),
            )
        else:
            adaptation = ReasoningAdaptationV1(
                cycle_id=cycle_id,
                session_id=str(context.get("session_id", "")),
                strategy=self.search_strategy,
                reason="No branch met the minimum information-gain threshold; planner recommends waiting or stopping.",
                stop_recommended=True,
                backtracked=backtrack_count > 0,
                input_digest=_digest(snapshot.digest(), [item.branch_id for item in branches]),
            )
        return branches, transitions, adaptation

    def build_reasoning_cycle(
        self,
        context: Dict[str, Any],
        state: Any,
        snapshot: Optional[PlanningSnapshot] = None,
        request: str = "",
        *,
        model_actions: Optional[Sequence[Dict[str, Any]]] = None,
        model_id: str = "",
        mode: str = "autonomous",
    ) -> ReasoningCycleResult:
        """Run one reasoning cycle around the adaptive planner.

        The live system has one autonomous path. The model proposes strategy
        and actions; typed scope, approval, cleanup, and validation boundaries
        remain execution invariants rather than selectable modes.
        """
        snapshot = snapshot or PlanningSnapshot()
        planned = self.plan(context, state, snapshot, request)
        cycle_id = planned.decision.cycle_id
        config = get_config().get("reasoning", {}) or {}

        def optional_count(name: str, fallback: Optional[int] = None) -> Optional[int]:
            raw = config.get(name, fallback)
            if raw is None or str(raw).strip().lower() in {"", "auto", "unlimited", "none", "null"}:
                return None
            try:
                return max(1, int(raw))
            except (TypeError, ValueError):
                return fallback

        max_actions = optional_count("max_actions_per_cycle", self.max_proposals)
        max_cycles = optional_count("max_cycles")
        search_branches, branch_transitions, adaptation = self.build_search_branches(
            context, snapshot, planned, cycle_id,
            failed_action_ids=[
                str(item.get("action_id") or item.get("tool_name") or "")
                for item in snapshot.tool_runs
                if str(item.get("status") or "") in {"failed", "cancelled"}
            ],
        )
        branch_by_action = {
            action_id: branch
            for branch in search_branches
            for action_id in branch.action_ids
        }
        hypothesis_branch = {
            hypothesis_id: branch.branch_id
            for branch in search_branches
            for hypothesis_id in branch.hypothesis_ids
        }
        evidence_ids = {str(item.get("observation_id") or item.get("evidence_id") or "") for item in snapshot.observations}
        evidence_ids.discard("")
        stale_evidence_ids = {
            str(item.get("observation_id") or item.get("evidence_id") or "")
            for item in snapshot.observations
            if str(item.get("status") or "") == "stale" or bool((item.get("metadata") or {}).get("stale"))
        }
        evidence_ids.update(str(item.get("evidence_id") or "") for item in getattr(state.workflow, "evidence", []) if getattr(item, "evidence_id", ""))
        known_targets = {str(item.get("target_url") or "") for item in snapshot.observations if item.get("target_url")}
        known_targets.update(str(item.get("url") or "") for item in getattr(state, "endpoints", []) or [] if isinstance(item, dict) and item.get("url"))
        known_targets.add(str(context.get("target_url") or ""))
        known_tools = {tool for capability in CAPABILITIES.values() for tool in capability.tools}

        hypotheses: List[Dict[str, Any]] = []
        gaps: List[EvidenceGapV1] = []
        for item in planned.hypotheses:
            required_roles = self._required_evidence_roles(item.category)
            item_evidence = list(dict.fromkeys(item.supporting_evidence_ids + item.contradicting_evidence_ids))
            item_gaps: List[EvidenceGapV1] = []
            if set(item_evidence) & stale_evidence_ids:
                item_gaps.append(EvidenceGapV1(
                    session_id=str(context.get("session_id", "")), cycle_id=cycle_id,
                    hypothesis_id=item.hypothesis_id, gap_type="state",
                    description="The hypothesis references stale evidence and must be revalidated from a current snapshot.",
                    required_role="current_observation", evidence_ids=sorted(set(item_evidence) & stale_evidence_ids),
                ))
            if not item_evidence:
                item_gaps.append(EvidenceGapV1(session_id=str(context.get("session_id", "")), cycle_id=cycle_id, hypothesis_id=item.hypothesis_id, gap_type="baseline", description="No evidence is linked to this hypothesis.", required_role="baseline"))
            if item.contradicting_evidence_ids:
                item_gaps.append(EvidenceGapV1(session_id=str(context.get("session_id", "")), cycle_id=cycle_id, hypothesis_id=item.hypothesis_id, gap_type="contradiction", description="Supporting and contradicting signals require deterministic revalidation.", required_role="reproduction", evidence_ids=item.contradicting_evidence_ids))
            if item.category in {"authorization", "business_logic", "session_security"} and len(snapshot.identities) < 2:
                item_gaps.append(EvidenceGapV1(session_id=str(context.get("session_id", "")), cycle_id=cycle_id, hypothesis_id=item.hypothesis_id, gap_type="identity", description="At least two explicit identity contexts are required.", required_role="identity"))
            for gap_type, role in required_roles:
                if not any(str(observation.get("role")) == role for observation in snapshot.observations):
                    item_gaps.append(EvidenceGapV1(session_id=str(context.get("session_id", "")), cycle_id=cycle_id, hypothesis_id=item.hypothesis_id, gap_type=gap_type, description=f"Required evidence role '{role}' is not present.", required_role=role))
            gaps.extend(item_gaps)
            item.metadata = {**(item.metadata or {}), "required_evidence_roles": [role for _, role in required_roles], "reasoning_gap_ids": [gap.gap_id for gap in item_gaps]}
            hypotheses.append({
                **item.__dict__,
                "cycle_id": cycle_id,
                "branch_id": hypothesis_branch.get(item.hypothesis_id, ""),
                "search_depth": 1,
                "evidence_gap_ids": [gap.gap_id for gap in item_gaps],
                "required_evidence_roles": [role for _, role in required_roles],
            })

        actions: List[PlannerActionV1] = []
        selected_proposals = planned.proposals if max_actions is None else planned.proposals[:max_actions]
        for proposal in selected_proposals:
            side_effect = "mutation" if proposal.cleanup_required or proposal.risk in {"high", "critical"} else "read"
            branch = branch_by_action.get(proposal.action_id)
            actions.append(PlannerActionV1(
                cycle_id=cycle_id, action_type="run_read_only" if side_effect == "read" else "request_approval",
                tool_name=proposal.recommended_tool, endpoint_ref=proposal.target_url,
                hypothesis_id=proposal.hypothesis_id, risk="high_risk" if side_effect == "mutation" else "read_only",
                side_effect_class=side_effect, evidence_ids=proposal.evidence_ids,
                expected_evidence_roles=["baseline", "test", "negative_control"],
                requires_approval=bool(proposal.requires_approval or side_effect == "mutation"),
                cleanup_ref="registered_cleanup" if proposal.cleanup_required else "",
                expected_information_gain=_clamp(proposal.information_gain), rationale=proposal.rationale,
                status="proposed", source="deterministic", input_digest=_digest(proposal.fingerprint, proposal.target_url, proposal.recommended_tool, proposal.evidence_ids),
                capability_id=proposal.action,
                branch_id=branch.branch_id if branch else "",
                target_digest=_digest(proposal.target_url, length=32),
                input_bindings=dict(proposal.input_bindings or {}),
                expected_observation_kinds=["baseline", "test", "negative_control"],
                budget_snapshot={"estimated_cost": proposal.estimated_cost},
                metadata={"proposal_id": proposal.action_id, "alternative_tools": proposal.alternative_tools},
            ))

        blocking_hypotheses = {
            gap.hypothesis_id for gap in gaps
            if gap.blocking and gap.gap_type in {"scope", "approval", "state"}
        }
        actions = [item for item in actions if item.hypothesis_id not in blocking_hypotheses]
        traces = self.validate_model_actions(
            cycle_id, model_actions or [], known_targets=known_targets,
            known_evidence=evidence_ids, known_tools=known_tools, model_id=model_id,
            stale_evidence=stale_evidence_ids,
        )
        triggered: List[StopConditionV1] = []
        if not actions:
            kind = "blocked" if gaps else "no_information_gain"
            triggered.append(StopConditionV1(cycle_id=cycle_id, kind=kind, triggered=True, reason=planned.decision.rationale, evidence_ids=sorted(evidence_ids)))
        if len(planned.hypotheses) >= self.max_hypotheses:
            triggered.append(StopConditionV1(cycle_id=cycle_id, kind="max_cycles", triggered=True, reason="Hypothesis bound reached."))
        if any(gap.blocking for gap in gaps) and not actions:
            triggered.append(StopConditionV1(cycle_id=cycle_id, kind="blocked", triggered=True, reason="Blocking evidence gaps remain."))
        decision = ReasoningDecisionV1(
            cycle_id=cycle_id, snapshot_digest=snapshot.digest(),
            selected_action_ids=[item.action_id for item in actions],
            rejected_action_ids=[item.trace_id for item in traces if not item.valid],
            evidence_gap_ids=[gap.gap_id for gap in gaps],
            stop_condition_ids=[item.stop_condition_id for item in triggered],
            rationale=planned.decision.rationale,
            deterministic=True, input_digest=_digest(snapshot.digest(), request, _stable_reasoning_value(model_actions or [])),
            selected_branch_id=adaptation.selected_branch_id,
            score_breakdown=next((item.score_breakdown for item in search_branches if item.branch_id == adaptation.selected_branch_id), {}),
            rejected_alternatives=[
                {"branch_id": item.branch_id, "action_ids": item.action_ids, "score": item.score, "status": item.status}
                for item in search_branches if item.branch_id != adaptation.selected_branch_id
            ],
            replan_reason=adaptation.reason,
        )
        cycle_status = "stopped" if triggered else ("partial" if any(not item.valid for item in traces) else "succeeded")
        cycle = ReasoningCycleV1(
            cycle_id=cycle_id, session_id=str(context.get("session_id", "")), objective=str(context.get("attack_goal") or request),
            mode="autonomous", status=cycle_status,
            snapshot_digest=snapshot.digest(), model_id=model_id, action_budget=max_actions,
            max_cycles=max_cycles, selected_action_ids=[item.action_id for item in actions],
            hypothesis_ids=[item.get("hypothesis_id", "") for item in hypotheses],
            branch_ids=[item.branch_id for item in search_branches],
            current_branch_id=adaptation.selected_branch_id,
            search_strategy=self.search_strategy,
            search_depth=max((item.search_depth for item in search_branches), default=0),
            replan_count=1 if adaptation.backtracked else 0,
            budget_snapshot={"max_actions": max_actions, "max_cycles": max_cycles},
            evidence_gap_ids=[item.gap_id for item in gaps], stop_condition_ids=[item.stop_condition_id for item in triggered],
            stop_reason=triggered[0].reason if triggered else "Cycle completed with bounded actions.",
            input_digest=decision.input_digest,
            output_digest=_digest(_stable_reasoning_value({"hypotheses": hypotheses, "actions": actions, "gaps": gaps, "stops": triggered})),
        )
        return ReasoningCycleResult(
            cycle=cycle, hypotheses=hypotheses, actions=[item.model_dump(mode="json") for item in actions],
            evidence_gaps=[item.model_dump(mode="json") for item in gaps],
            stop_conditions=[item.model_dump(mode="json") for item in triggered],
            decision=decision.model_dump(mode="json"), model_traces=[item.model_dump(mode="json") for item in traces],
            branches=[item.model_dump(mode="json") for item in search_branches],
            branch_transitions=[item.model_dump(mode="json") for item in branch_transitions],
            adaptation=adaptation.model_dump(mode="json"),
        )

    @staticmethod
    def _required_evidence_roles(category: str) -> List[Tuple[str, str]]:
        if category in {"sql_injection", "command_injection", "ssti", "path_traversal"}:
            return [("baseline", "baseline"), ("negative_control", "negative_control"), ("reproduction", "reproduction")]
        if category in {"xss", "open_redirect", "cors"}:
            return [("baseline", "baseline"), ("negative_control", "negative_control"), ("reproduction", "reproduction")]
        if category in {"ssrf", "xxe"}:
            return [("correlation", "oob"), ("negative_control", "negative_control"), ("reproduction", "reproduction")]
        if category in {"authorization", "business_logic"}:
            return [("baseline", "baseline"), ("negative_control", "negative_control"), ("reproduction", "reproduction")]
        return [("baseline", "baseline")]

    @staticmethod
    def validate_model_actions(
        cycle_id: str, raw_actions: Sequence[Dict[str, Any]], *, known_targets: set[str],
        known_evidence: set[str], known_tools: set[str], model_id: str = "",
        stale_evidence: Optional[set[str]] = None,
    ) -> List[ModelActionTraceV1]:
        def observed_endpoint(candidate: str) -> bool:
            """Accept an observed path or its query/child path only.

            A raw string ``startswith`` check lets ``/api/items-evil`` pass
            when ``/api/items`` was observed.  Compare normalized origins and
            path boundaries instead; the model may refine a known endpoint's
            query string, but it cannot widen the host or path namespace.
            """
            if candidate in known_targets:
                return True
            try:
                parsed_candidate = urlsplit(candidate)
                if parsed_candidate.scheme.lower() not in {"http", "https"} or not parsed_candidate.hostname:
                    return False
                candidate_origin = (
                    parsed_candidate.scheme.lower(),
                    parsed_candidate.netloc.lower(),
                )
                candidate_path = parsed_candidate.path or "/"
            except (TypeError, ValueError):
                return False
            for target in known_targets:
                try:
                    parsed_target = urlsplit(target)
                    target_origin = (
                        parsed_target.scheme.lower(),
                        parsed_target.netloc.lower(),
                    )
                    if candidate_origin != target_origin:
                        continue
                    target_path = parsed_target.path or "/"
                    if target_path == "/" or candidate_path == target_path:
                        return True
                    if candidate_path.startswith(target_path.rstrip("/") + "/"):
                        return True
                except (TypeError, ValueError):
                    continue
            return False

        traces: List[ModelActionTraceV1] = []
        # The gateway already bounds the response by bytes/schema. Do not add
        # a second arbitrary action-count truncation here; retain all model
        # proposals so the scheduler can choose a dynamic safe batch.
        for raw in list(raw_actions):
            digest = _digest(raw, length=64)
            try:
                action = PlannerActionV1(**{**dict(raw), "cycle_id": cycle_id})
            except Exception as exc:
                traces.append(ModelActionTraceV1(cycle_id=cycle_id, model_id=model_id, raw_output_digest=digest, valid=False, rejection_reason=f"Invalid structured action: {type(exc).__name__}"))
                continue
            reasons: List[str] = []
            unknown_tool = bool(action.tool_name and action.tool_name not in known_tools)
            hallucinated = bool(action.endpoint_ref and not observed_endpoint(action.endpoint_ref))
            invented = any(item not in known_evidence for item in action.evidence_ids)
            stale_context = bool(set(action.evidence_ids) & set(stale_evidence or set()))
            unsafe = action.is_mutating() and (not action.requires_approval or not action.cleanup_ref)
            if unknown_tool:
                reasons.append("Tool is not registered for this session capability.")
            if not action.tool_name and action.action_type not in {"stop", "hypothesize"}:
                reasons.append("Executable action must identify a registered tool.")
            if hallucinated:
                reasons.append("Endpoint reference was not observed in the session.")
            if invented:
                reasons.append("Evidence ID is not present in the session snapshot.")
            if stale_context:
                reasons.append("Action references stale evidence and requires a fresh snapshot.")
            if unsafe:
                reasons.append("Mutation/high-risk action lacks exact approval and cleanup binding.")
            if action.action_type == "run_read_only" and action.is_mutating():
                reasons.append("Read-only action cannot carry a mutating side effect class.")
            valid = not reasons
            action = action.model_copy(update={"status": "accepted" if valid else "rejected", "rejection_reason": "; ".join(reasons)})
            traces.append(ModelActionTraceV1(
                cycle_id=cycle_id, model_id=model_id, raw_output_digest=digest, action=action,
                valid=valid, rejection_reason="; ".join(reasons), hallucinated_reference=hallucinated,
                unsafe_mutation=unsafe, invented_evidence=invented, unknown_tool=unknown_tool,
                unsupported_capability=unknown_tool, stale_context=stale_context,
            ))
        return traces

    @staticmethod
    def _sync_validated_findings(workflow: WorkflowState, snapshot: PlanningSnapshot) -> None:
        """Expose deterministic candidates to the existing chain/lifecycle services."""
        by_candidate = {
            item.source_candidate_id: item
            for item in workflow.findings
            if item.source_candidate_id
        }
        by_fingerprint = {
            item.fingerprint: item
            for item in workflow.findings
            if item.fingerprint
        }
        for candidate in snapshot.candidates:
            candidate_id = str(candidate.get("candidate_id") or "")
            fingerprint = str(candidate.get("fingerprint") or "")
            candidate_status = str(candidate.get("status") or "suspected")
            existing = by_candidate.get(candidate_id) or by_fingerprint.get(fingerprint)
            if candidate_status not in {"validated", "validated_override"}:
                if existing:
                    previous = existing.status
                    existing.status = {
                        "disproven": RecordStatus.DISPROVEN.value,
                        "inconclusive": RecordStatus.INCONCLUSIVE.value,
                        "validating": RecordStatus.RUNNING.value,
                    }.get(candidate_status, RecordStatus.SUSPECTED.value)
                    if previous != existing.status:
                        workflow.record_event(
                            "structured_finding_status_changed", finding_id=existing.finding_id,
                            previous=previous, current=existing.status, candidate_id=candidate_id,
                        )
                continue
            metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
            evidence_ids = list(metadata.get("evidence_ids") or candidate.get("observation_ids") or [])
            if existing:
                existing.status = RecordStatus.VALIDATED.value
                existing.evidence_ids = sorted(set(existing.evidence_ids + evidence_ids))
                existing.validation_source = "human_override" if candidate_status == "validated_override" else "machine"
                continue
            finding = FindingRecord(
                finding_id=candidate_id or f"finding_{_digest(fingerprint, length=24)}",
                title=str(candidate.get("title") or candidate.get("vuln_type") or "Validated finding"),
                vuln_type=str(candidate.get("vuln_type") or "unknown"),
                severity=str(candidate.get("severity") or "INFO"),
                evidence_ids=evidence_ids,
                status=RecordStatus.VALIDATED.value,
                confidence=_confidence_label(float(candidate.get("confidence_score") or 0.5)),
                fingerprint=fingerprint,
                validation_source="human_override" if candidate_status == "validated_override" else "machine",
                source_candidate_id=candidate_id,
            )
            workflow.findings.append(finding)
            workflow.record_event(
                "structured_candidate_linked",
                candidate_id=candidate_id,
                finding_id=finding.finding_id,
                validation_source=finding.validation_source,
            )
            by_candidate[candidate_id] = finding
            if fingerprint:
                by_fingerprint[fingerprint] = finding

    def _candidate_hypotheses(
        self, context: Dict[str, Any], snapshot: PlanningSnapshot,
    ) -> List[HypothesisRecord]:
        observations = {item.get("observation_id"): item for item in snapshot.observations}
        hypotheses: List[HypothesisRecord] = []
        for candidate in snapshot.candidates:
            vuln_type = str(candidate.get("vuln_type") or candidate.get("type") or "unknown")
            category = self._category(vuln_type)
            target = str(candidate.get("target_url") or context.get("target_url") or "")
            parameter = str(candidate.get("parameter") or "")
            candidate_id = str(candidate.get("candidate_id") or "")
            metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
            evidence_ids = list(candidate.get("observation_ids") or metadata.get("evidence_ids") or [])
            supporting: List[str] = []
            contradicting: List[str] = []
            for evidence_id in evidence_ids:
                observation = observations.get(evidence_id, {})
                role = str(observation.get("role") or "test")
                if role in {"negative_control", "baseline"} and bool((observation.get("metadata") or {}).get("contradicts_candidate")):
                    contradicting.append(evidence_id)
                else:
                    supporting.append(evidence_id)

            status = str(candidate.get("status") or "suspected")
            mapped_status = {
                "validated": RecordStatus.VALIDATED.value,
                "validated_override": RecordStatus.VALIDATED.value,
                "disproven": RecordStatus.DISPROVEN.value,
                "inconclusive": RecordStatus.INCONCLUSIVE.value,
                "validating": RecordStatus.RUNNING.value,
            }.get(status, RecordStatus.PENDING.value)
            probability = _clamp(float(candidate.get("confidence_score") or 0.5), 0.02, 0.98)
            if status in {"validated", "validated_override"}:
                probability = 0.98
            elif status == "disproven":
                probability = 0.02
            capability = CAPABILITIES.get(category)
            information_gain = _binary_entropy(probability) * (capability.discriminating_power if capability else 0.25)
            title = str(candidate.get("title") or vuln_type)
            claim = f"{title} affects {target}"
            if parameter:
                claim += f" through parameter '{parameter}'"
            fingerprint = _digest("candidate", candidate.get("fingerprint") or candidate_id or claim)
            hypotheses.append(HypothesisRecord(
                claim=claim + ".",
                category=category,
                target_url=target,
                method=str(candidate.get("method") or "GET").upper(),
                parameter=parameter,
                fingerprint=fingerprint,
                null_hypothesis=(
                    f"The signal at {target} is explained by normal input handling, unstable behavior, "
                    "or a control-equivalent response."
                ),
                alternative_claims=self._alternatives(category, target),
                supporting_evidence_ids=supporting,
                contradicting_evidence_ids=contradicting,
                source_candidate_ids=[candidate_id] if candidate_id else [],
                prior_probability=probability,
                confidence_score=probability,
                confidence=_confidence_label(probability),
                expected_information_gain=_clamp(information_gain),
                status=mapped_status,
                result=f"Structured candidate status: {status}",
                generation_rule="structured_candidate",
                decision_reason="Candidate status and confidence are read from the deterministic evidence pipeline.",
                metadata={"candidate_status": status, "vuln_type": vuln_type, "override": status == "validated_override"},
            ))
        return hypotheses

    def _surface_hypotheses(
        self, context: Dict[str, Any], state: Any, snapshot: PlanningSnapshot,
    ) -> List[HypothesisRecord]:
        endpoints: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for raw in getattr(state, "endpoints", []) or []:
            item = _as_dict(raw)
            url = _safe_endpoint_url(item.get("url"))
            if url:
                endpoints[(str(item.get("method") or "GET").upper(), url)] = item
        for node in (getattr(state, "attack_surface", {}) or {}).get("nodes", []):
            url = _safe_endpoint_url(node.get("url"))
            if url:
                endpoints.setdefault(("GET", url), {"url": url, "method": "GET", "parameters": [], "kind": node.get("kind")})
        observation_by_target: Dict[str, List[str]] = {}
        for observation in snapshot.observations:
            url = _safe_endpoint_url(observation.get("target_url"))
            if url:
                observation_by_target.setdefault(url, []).append(str(observation.get("observation_id") or ""))
                metadata = observation.get("metadata") if isinstance(observation.get("metadata"), dict) else {}
                parameters = metadata.get("parameters") if isinstance(metadata.get("parameters"), list) else []
                endpoints.setdefault(
                    (str(observation.get("method") or "GET").upper(), url),
                    {"url": url, "method": observation.get("method") or "GET", "parameters": parameters},
                )

        identities = [item for item in snapshot.identities if str(item.get("status") or "active") in {"active", "ready"}]
        hypotheses: List[HypothesisRecord] = []
        for (method, url), endpoint in sorted(endpoints.items()):
            parameters = set(str(item) for item in (endpoint.get("parameters") or []) if str(item))
            try:
                parameters.update(key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True))
            except Exception:
                pass
            lower_url = url.lower()
            path_categories: List[Tuple[str, str]] = []
            if "graphql" in lower_url:
                path_categories.append(("graphql", "surface_graphql_path"))
            if any(token in lower_url for token in ("/upload", "/attachment", "/import")):
                path_categories.append(("file_upload", "surface_upload_path"))
            if lower_url.startswith("ws:") or lower_url.startswith("wss:") or "/socket" in lower_url:
                path_categories.append(("websocket", "surface_websocket_path"))
            if any(token in lower_url for token in ("/login", "/token", "/session", "/reset-password")):
                path_categories.append(("session_security", "surface_auth_path"))

            for category, rule in path_categories:
                hypotheses.append(self._surface_hypothesis(
                    category, url, method, "", rule, observation_by_target.get(url, []), context,
                ))

            for parameter in sorted(parameters):
                for category, rule in self._parameter_categories(parameter):
                    hypothesis = self._surface_hypothesis(
                        category, url, method, parameter, rule, observation_by_target.get(url, []), context,
                    )
                    if category == "authorization" and len(identities) < 2:
                        hypothesis.metadata["identity_contexts_seen"] = len(identities)
                    hypotheses.append(hypothesis)
        return hypotheses

    def _baseline_hypotheses(
        self, context: Dict[str, Any], state: Any, snapshot: PlanningSnapshot,
    ) -> List[HypothesisRecord]:
        """Seed one bounded detector hypothesis per core vulnerability family.

        This only activates after recon has produced an endpoint or surface
        node. An empty snapshot still yields the recon mission, while a
        completed recon cannot silently collapse into keyword heuristics only.
        """
        endpoints: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for raw in getattr(state, "endpoints", []) or []:
            item = _as_dict(raw)
            url = _safe_endpoint_url(item.get("url"))
            if url:
                endpoints[(str(item.get("method") or "GET").upper(), url)] = item
        for node in (getattr(state, "attack_surface", {}) or {}).get("nodes", []):
            url = _safe_endpoint_url(node.get("url"))
            if url:
                endpoints.setdefault(("GET", url), {"url": url, "method": "GET", "parameters": []})
        if not endpoints:
            fallback = _safe_endpoint_url(context.get("target_url"))
            if fallback:
                endpoints[("GET", fallback)] = {"url": fallback, "method": "GET", "parameters": []}
        if not endpoints:
            return []

        # A hand-built fixture endpoint is not proof that recon has completed.
        # Enable the matrix only after the session contains a persisted recon
        # signal (or an attack-surface graph), preserving deterministic planner
        # control-suite expectations while covering real mapped targets.
        has_mapped_surface = bool((getattr(state, "attack_surface", {}) or {}).get("nodes"))
        has_mapped_surface = has_mapped_surface or any(
            str(item.get("category") or "").lower() == "recon"
            and str(item.get("status") or "").lower() == "succeeded"
            for item in snapshot.tool_runs
        )
        if not has_mapped_surface:
            return []

        observation_by_target: Dict[str, List[str]] = {}
        for observation in snapshot.observations:
            url = _safe_endpoint_url(observation.get("target_url"))
            if url:
                observation_by_target.setdefault(url, []).append(str(observation.get("observation_id") or ""))

        rows = sorted(endpoints.items(), key=lambda item: (item[0][1], item[0][0]))

        def endpoint_score(item: Tuple[Tuple[str, str], Dict[str, Any]], category: str) -> Tuple[int, int, str]:
            (method, url), endpoint = item
            lower = url.lower()
            parameters = endpoint.get("parameters") or []
            has_input = bool(parameters or urlsplit(url).query or method not in {"GET", "HEAD"})
            semantic_path = any(token in lower for token in (
                "login", "search", "query", "api", "graphql", "upload", "socket", "redirect",
            ))
            category_path = {
                "session_security": any(token in lower for token in ("login", "token", "session")),
                "graphql": "graphql" in lower,
                "websocket": "socket" in lower or lower.startswith(("ws:", "wss:")),
                "open_redirect": "redirect" in lower,
            }.get(category, False)
            return (int(category_path), int(has_input or semantic_path), url)

        selected: List[HypothesisRecord] = []
        for category in BASELINE_CATEGORIES:
            (method, url), details = max(rows, key=lambda item: endpoint_score(item, category))
            parameters = sorted({str(item) for item in (details.get("parameters") or []) if str(item)})
            try:
                parameters.extend(
                    key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
                    if key not in parameters
                )
            except Exception:
                pass
            parameter = parameters[0] if parameters else ""
            hypothesis = self._surface_hypothesis(
                category, url or context.get("target_url", ""), method, parameter,
                f"baseline_{category}", observation_by_target.get(url, []), context,
            )
            hypothesis.metadata.update({
                "source": "baseline_detector_matrix",
                "max_test_attempts": 1,
                "baseline_category": category,
            })
            selected.append(hypothesis)
        return selected

    def _surface_hypothesis(
        self,
        category: str,
        url: str,
        method: str,
        parameter: str,
        rule: str,
        evidence_ids: Iterable[str],
        context: Dict[str, Any],
    ) -> HypothesisRecord:
        location = f"parameter '{parameter}' at {url}" if parameter else url
        claims = {
            "authorization": f"Object access through {location} may not enforce actor ownership or tenant boundaries.",
            "sql_injection": f"Server-side query construction for {location} may not preserve input/data separation.",
            "xss": f"User-controlled data from {location} may reach an executable browser context.",
            "ssrf": f"Server-side URL handling through {location} may cross the intended network trust boundary.",
            "path_traversal": f"File/path resolution through {location} may escape the intended resource root.",
            "open_redirect": f"Navigation through {location} may allow an external destination.",
            "graphql": f"The GraphQL surface at {location} may expose operations beyond the current actor's authorization.",
            "file_upload": f"The upload workflow at {location} may trust client-controlled file metadata or content handling.",
            "websocket": f"The WebSocket surface at {location} may not enforce message-level authorization.",
            "session_security": f"The authentication/session workflow at {location} may violate token lifecycle invariants.",
        }
        prior = 0.32 if category not in {"authorization", "session_security"} else 0.28
        capability = CAPABILITIES.get(category)
        info_gain = _binary_entropy(prior) * (capability.discriminating_power if capability else 0.3)
        evidence = [item for item in evidence_ids if item]
        return HypothesisRecord(
            claim=claims.get(category, f"The surface at {location} may violate a security invariant."),
            category=category,
            target_url=url or context.get("target_url", ""),
            method=method,
            parameter=parameter,
            fingerprint=_digest("surface", category, url, method, parameter),
            null_hypothesis=f"The behavior at {location} correctly enforces its expected security invariant.",
            alternative_claims=self._alternatives(category, url),
            supporting_evidence_ids=evidence,
            prior_probability=prior,
            confidence_score=prior,
            confidence=_confidence_label(prior),
            expected_information_gain=_clamp(info_gain),
            generation_rule=rule,
            decision_reason="Generated from runtime endpoint and parameter semantics; no target-specific rule was used.",
            metadata={"source": "runtime_surface", "objective": context.get("attack_goal", "")},
        )

    def _surface_gap_hypothesis(self, context: Dict[str, Any], state: Any) -> HypothesisRecord:
        target = str(context.get("target_url") or getattr(state, "url", ""))
        return HypothesisRecord(
            claim=f"The reachable attack surface for {target} is not sufficiently mapped to form bounded vulnerability hypotheses.",
            category="surface_mapping",
            target_url=target,
            fingerprint=_digest("surface_gap", target),
            null_hypothesis="The existing inventory is already complete enough for evidence-driven testing.",
            prior_probability=0.8,
            confidence_score=0.8,
            confidence="high",
            expected_information_gain=0.9,
            generation_rule="insufficient_runtime_surface",
            decision_reason="No structured candidate or parameterized endpoint is available in this session snapshot.",
        )

    @staticmethod
    def _category(vuln_type: str) -> str:
        value = vuln_type.lower()
        for category, aliases in VULNERABILITY_ALIASES:
            if any(alias in value for alias in aliases):
                return category
        return re.sub(r"[^a-z0-9]+", "_", value).strip("_") or "unknown"

    @staticmethod
    def _parameter_categories(parameter: str) -> List[Tuple[str, str]]:
        value = parameter.lower().replace("-", "_")
        categories: List[Tuple[str, str]] = []
        if value == "id" or value.endswith("_id") or any(token in value for token in ("uuid", "owner", "tenant", "account", "user_id", "order_id")):
            categories.append(("authorization", "semantic_object_identifier"))
        if any(token in value for token in ("redirect", "return", "next", "continue", "destination")):
            categories.append(("open_redirect", "semantic_navigation_parameter"))
        if any(token in value for token in ("url", "uri", "callback", "webhook", "fetch", "proxy", "remote")):
            categories.append(("ssrf", "semantic_server_fetch_parameter"))
        if any(token in value for token in ("file", "path", "page", "include", "template", "document")):
            categories.append(("path_traversal", "semantic_file_parameter"))
        if any(token in value for token in ("query", "search", "filter", "where", "sort", "keyword")) or value in {"q", "s"}:
            categories.append(("sql_injection", "semantic_query_parameter"))
            categories.append(("xss", "semantic_reflection_parameter"))
        return categories

    @staticmethod
    def _alternatives(category: str, target: str) -> List[str]:
        generic = f"The observed difference at {target} is caused by caching, normalization, authentication state, or unstable upstream behavior."
        alternatives = {
            "sql_injection": [generic, "The response contains a generic backend error unrelated to query execution."],
            "xss": [generic, "The value is reflected only in an escaped or non-executable context."],
            "authorization": [generic, "The compared responses refer to different resources or login-wall content."],
            "ssrf": [generic, "The callback is stale, unrelated, or cannot be attributed to the target request."],
            "open_redirect": [generic, "The application normalizes the destination back to the same origin."],
        }
        return alternatives.get(category, [generic])

    @staticmethod
    def _failed_tool_counts(tool_runs: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for run in tool_runs:
            if str(run.get("status") or "") in {"failed", "cancelled"}:
                raw_name = str(run.get("tool_name") or "")
                normalized = re.sub(r"[^a-z0-9]+", "_", raw_name.lower()).strip("_")
                name = TOOL_RUN_NAME_ALIASES.get(normalized, normalized)
                if name:
                    counts[name] = counts.get(name, 0) + 1
        return counts

    def _choose_tool(
        self,
        capability: PlannerCapability,
        state: Any,
        failed_tools: Dict[str, int],
    ) -> Tuple[str, List[str]]:
        tech = _as_dict(getattr(state, "tech_stack", {}))
        preferred = self._technology_preferences(tech)
        ranked = sorted(
            capability.tools,
            key=lambda tool: (failed_tools.get(tool, 0), 0 if tool in preferred else 1, capability.tools.index(tool)),
        )
        return (ranked[0], ranked[1:]) if ranked else ("", [])

    @staticmethod
    def _technology_preferences(tech: Dict[str, Any]) -> set[str]:
        value = " ".join(str(item).lower() for item in tech.values())
        preferred: set[str] = set()
        if any(token in value for token in ("react", "vue", "angular", "next")):
            preferred.update({"dom_xss_scanner", "browser_find_open_redirect"})
        if any(token in value for token in ("php", "laravel", "wordpress", "mysql")):
            preferred.update({"scan_sql_injection", "scan_lfi_rfi"})
        if any(token in value for token in ("node", "express", "mongodb")):
            preferred.update({"dom_xss_scanner", "command_injection_scanner"})
        if any(token in value for token in ("django", "flask", "jinja", "spring")):
            preferred.add("ssti_tester")
        return preferred

    @staticmethod
    def _preconditions(capability: PlannerCapability) -> List[str]:
        items = ["target remains inside the approved session scope", "explicit human approval is current"]
        if capability.min_identities:
            items.append(f"at least {capability.min_identities} isolated identity contexts are available")
        return items

    @staticmethod
    def _unmet_preconditions(
        capability: PlannerCapability,
        hypothesis: HypothesisRecord,
        snapshot: PlanningSnapshot,
    ) -> List[str]:
        unmet: List[str] = []
        if not hypothesis.target_url:
            unmet.append("a concrete in-scope target URL is required")
        active_identities = [
            item for item in snapshot.identities
            if str(item.get("status") or "active") in {"active", "ready"}
        ]
        if capability.min_identities and len(active_identities) < capability.min_identities:
            unmet.append(
                f"authorization comparison requires {capability.min_identities} isolated identities; "
                f"{len(active_identities)} available"
            )
        if capability.category in {"browser_baseline", "business_logic", "business_logic_mutation"}:
            if snapshot.published_workflows and not any(str(item.get("status")) == "published" for item in snapshot.published_workflows):
                unmet.append("a published browser workflow is required")
            if capability.category != "browser_baseline" and snapshot.identity_graphs and not any(item.get("graph_id") for item in snapshot.identity_graphs):
                unmet.append("an identity graph is required")
            if capability.category in {"business_logic", "business_logic_mutation"} and snapshot.business_entities and not any(item.get("fingerprint") for item in snapshot.business_entities):
                unmet.append("a server-side business entity fingerprint is required")
            if capability.category == "business_logic_mutation" and snapshot.workflow_matrices and not any(item.get("cleanup_required") and item.get("status") == "ready" for item in snapshot.workflow_matrices):
                unmet.append("a ready workflow matrix with cleanup is required before mutation")
        return unmet

    def _score(
        self,
        hypothesis: HypothesisRecord,
        capability: PlannerCapability,
        tool: str,
        context: Dict[str, Any],
        state: Any,
        request: str,
        failed_tools: Dict[str, int],
    ) -> Tuple[float, Dict[str, float]]:
        objective_text = f"{context.get('attack_goal', '')} {request}".lower()
        objective_words = _words(objective_text)
        hypothesis_words = _words(f"{hypothesis.category} {hypothesis.claim} {hypothesis.parameter}")
        overlap = len(objective_words.intersection(hypothesis_words))
        objective_relevance = _clamp(0.45 + min(0.55, overlap * 0.12))
        category_terms = next(
            (aliases for category, aliases in VULNERABILITY_ALIASES if category == hypothesis.category),
            (),
        )
        if hypothesis.category.replace("_", " ") in objective_text or any(term in objective_text for term in category_terms):
            objective_relevance = 1.0
        evidence_strength = _clamp(
            0.2 + len(set(hypothesis.supporting_evidence_ids)) * 0.18
            + (0.22 if hypothesis.source_candidate_ids else 0.0)
            - len(set(hypothesis.contradicting_evidence_ids)) * 0.18
        )
        novelty = _clamp(1.0 - (hypothesis.test_attempts * 0.28))
        technology_fit = 1.0 if tool in self._technology_preferences(_as_dict(getattr(state, "tech_stack", {}))) else 0.5
        cost = _clamp(capability.cost / 5.0)
        failures = _clamp(failed_tools.get(tool, 0) / 3.0)
        breakdown = {
            "information_gain": round(_clamp(hypothesis.expected_information_gain), 4),
            "objective_relevance": round(objective_relevance, 4),
            "evidence_strength": round(evidence_strength, 4),
            "novelty": round(novelty, 4),
            "technology_fit": round(technology_fit, 4),
            "cost_penalty": round(cost, 4),
            "risk_penalty": round(capability.risk_score, 4),
            "failure_penalty": round(failures, 4),
        }
        raw = (
            self.weights["information_gain"] * breakdown["information_gain"]
            + self.weights["objective_relevance"] * objective_relevance
            + self.weights["evidence_strength"] * evidence_strength
            + self.weights["novelty"] * novelty
            + self.weights["technology_fit"] * technology_fit
            - self.weights["cost_penalty"] * cost
            - self.weights["risk_penalty"] * capability.risk_score
            - self.weights["failure_penalty"] * failures
        )
        return round(_clamp(raw), 4), breakdown

    @staticmethod
    def _selection_reason(
        hypothesis: HypothesisRecord,
        capability: PlannerCapability,
        tool: str,
        breakdown: Dict[str, float],
        selected: bool,
    ) -> str:
        prefix = "Selected" if selected else "Deferred"
        return (
            f"{prefix} '{tool}' for hypothesis {hypothesis.hypothesis_id}: "
            f"information gain {breakdown.get('information_gain', 0):.2f}, "
            f"evidence strength {breakdown.get('evidence_strength', 0):.2f}, "
            f"estimated cost {capability.cost:.1f}/5, and risk {capability.risk}."
        )

    @staticmethod
    def _considered(
        hypothesis: HypothesisRecord,
        tool: str,
        score: float,
        selected: bool,
        reason: str,
        breakdown: Optional[Dict[str, float]] = None,
        action_id: str = "",
    ) -> Dict[str, Any]:
        return {
            "hypothesis_id": hypothesis.hypothesis_id,
            "category": hypothesis.category,
            "tool": tool,
            "priority_score": round(score, 4),
            "selected": selected,
            "reason": reason,
            "score_breakdown": breakdown or {},
            "action_id": action_id,
        }

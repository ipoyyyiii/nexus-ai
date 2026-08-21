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
        "surface_mapping", ("human_recon_crawl",), action="attack_surface_mapping",
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
        }
        return _digest(stable)


@dataclass
class PlanningResult:
    hypotheses: List[HypothesisRecord]
    proposals: List[ActionProposal]
    decision: PlannerDecisionRecord


class AdaptiveHypothesisPlanner:
    """Build and rank deterministic next tests from session-local evidence."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        raw = config if config is not None else get_config().get("adaptive_planner", {})
        self.config = raw or {}
        self.max_proposals = max(1, min(10, int(self.config.get("max_proposals", 3))))
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
            hypothesis.max_test_attempts = self.max_attempts
            current.append(workflow.upsert_hypothesis(hypothesis))
        self._sync_validated_findings(workflow, snapshot)

        active_fingerprints = {
            item.fingerprint
            for item in workflow.proposals
            if item.fingerprint and item.status in ACTION_DEDUP_STATUSES
        }
        failed_tools = self._failed_tool_counts(snapshot.tool_runs)
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
        for score, hypothesis, capability, tool, breakdown, alternatives, action_fingerprint in proposal_candidates:
            selected = len(proposals) < self.max_proposals
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
            url = str(item.get("url") or "")
            if url:
                endpoints[(str(item.get("method") or "GET").upper(), url)] = item
        for node in (getattr(state, "attack_surface", {}) or {}).get("nodes", []):
            url = str(node.get("url") or "")
            if url:
                endpoints.setdefault(("GET", url), {"url": url, "method": "GET", "parameters": [], "kind": node.get("kind")})
        observation_by_target: Dict[str, List[str]] = {}
        for observation in snapshot.observations:
            url = str(observation.get("target_url") or "")
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


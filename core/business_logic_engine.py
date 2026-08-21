"""Deterministic business-invariant compiler and evaluator."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.browser_workflow_contract import (
    BusinessInvariantV1,
    InvariantCheckV1,
    InvariantEvaluationV1,
)
from core.structured_contract import CandidateFindingV1


RULE_REGISTRY = {
    "ownership",
    "tenant_isolation",
    "server_authoritative",
    "numeric_consistency",
    "single_use",
    "idempotency",
    "allowed_transition",
    "sequence",
    "separation_of_duties",
    "cross_session_consistency",
}


def _field(state: Dict[str, Any], path: str) -> Any:
    value: Any = state
    for part in (path or "").split("."):
        if not part:
            continue
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


class BusinessInvariantCompiler:
    def compile(self, draft: str, session_id: str, source: str = "llm_draft") -> BusinessInvariantV1:
        text = str(draft or "").strip()
        lowered = text.lower()
        mapping = (
            (("tenant", "cross-tenant", "other tenant"), "tenant_isolation"),
            (("owner", "ownership", "object owner"), "ownership"),
            (("price", "total", "balance", "quantity", "amount"), "numeric_consistency"),
            (("coupon", "single use", "once", "duplicate"), "single_use"),
            (("idempot", "repeat", "duplicate submission"), "idempotency"),
            (("status", "state transition", "pending", "complete"), "allowed_transition"),
            (("approve", "approval", "separation", "self-approval"), "separation_of_duties"),
            (("sequence", "before", "prerequisite", "order"), "sequence"),
            (("server", "client", "authoritative"), "server_authoritative"),
        )
        rule_type = next((rule for terms, rule in mapping if any(term in lowered for term in terms)), "")
        if rule_type not in RULE_REGISTRY:
            raise ValueError("Invariant draft cannot be compiled to a supported deterministic rule.")
        return BusinessInvariantV1(
            session_id=session_id,
            name=text[:1000],
            rule_type=rule_type,
            source=source,
            status="draft",
            rule={"draft": text},
        )


class BusinessInvariantEngine:
    def __init__(self, mode: str = "shadow"):
        self.mode = mode if mode in {"shadow", "strict"} else "shadow"

    def evaluate(
        self,
        invariant: BusinessInvariantV1,
        transitions: Optional[Iterable[Dict[str, Any]]] = None,
        runs: Optional[Iterable[Dict[str, Any]]] = None,
        observations: Optional[Iterable[Dict[str, Any]]] = None,
    ) -> Tuple[InvariantEvaluationV1, Optional[CandidateFindingV1]]:
        transitions = list(transitions or [])
        runs = list(runs or [])
        observations = list(observations or [])
        checks: List[InvariantCheckV1] = []
        rule = dict(invariant.rule or {})
        if "draft" in rule and len(rule) == 1:
            return self._inconclusive(invariant, "Invariant must be reviewed and compiled into typed rule fields.")

        dispatch = {
            "ownership": self._ownership,
            "tenant_isolation": self._ownership,
            "server_authoritative": self._server_authoritative,
            "numeric_consistency": self._numeric_consistency,
            "single_use": self._single_use,
            "idempotency": self._idempotency,
            "allowed_transition": self._allowed_transition,
            "sequence": self._sequence,
            "separation_of_duties": self._separation_of_duties,
            "cross_session_consistency": self._cross_session_consistency,
        }
        evaluator = dispatch.get(invariant.rule_type)
        if not evaluator:
            return self._inconclusive(invariant, f"Unsupported deterministic rule: {invariant.rule_type}.")
        decision, checks, reason, evidence_ids = evaluator(rule, transitions, runs, observations)
        score = 1.0 if decision == "violated" else (0.9 if decision == "satisfied" else 0.0)
        evaluation = InvariantEvaluationV1(
            invariant_id=invariant.invariant_id,
            invariant_version=invariant.rule_version,
            decision=decision,
            score=score,
            reason=reason,
            checks=checks,
            evidence_ids=sorted(set(evidence_ids)),
            run_ids=sorted({str(run.get("run_id", "")) for run in runs if run.get("run_id")}),
        )
        candidate = None
        if decision == "violated":
            candidate = CandidateFindingV1(
                title=invariant.name,
                vuln_type="business_logic",
                severity=str(rule.get("severity", "MEDIUM")).upper(),
                target_url=str(rule.get("target_url", "")),
                status="suspected",
                confidence_score=0.7 if self.mode == "strict" else 0.55,
                confidence_reasons=[reason, "deterministic invariant evaluation"],
                observation_ids=sorted(set(evidence_ids)),
                metadata={
                    "invariant_id": invariant.invariant_id,
                    "rule_type": invariant.rule_type,
                    "evaluation_id": evaluation.evaluation_id,
                    "mode": self.mode,
                },
            ).ensure_fingerprint()
            evaluation.candidate_id = candidate.candidate_id
        return evaluation, candidate

    def _inconclusive(self, invariant: BusinessInvariantV1, reason: str):
        return (
            InvariantEvaluationV1(invariant_id=invariant.invariant_id, reason=reason),
            None,
        )

    @staticmethod
    def _check(name: str, passed: bool, details: Dict[str, Any], evidence: List[str]) -> InvariantCheckV1:
        return InvariantCheckV1(name=name, passed=passed, details=details, evidence_ids=evidence)

    def _ownership(self, rule, transitions, runs, observations):
        if not runs:
            return "inconclusive", [], "Identity comparison is missing.", []
        expected = rule.get("owner_identity_id") or rule.get("expected_identity_id")
        unauthorized = [run for run in runs if run.get("identity_id") and expected and run.get("identity_id") != expected]
        if not expected or not unauthorized:
            return "inconclusive", [self._check("identity_contexts", False, {"required": 2}, [])], "Owner and non-owner contexts are required.", []
        evidence = [eid for run in unauthorized for eid in run.get("evidence_ids", [])]
        allowed = any(str(run.get("semantic_result", "")).lower() in {"allow", "unexpected_allow"} for run in unauthorized)
        check = self._check("non_owner_denied", not allowed, {"unexpected_allow": allowed}, evidence)
        return ("violated" if allowed else "satisfied"), [check], ("Non-owner context was allowed." if allowed else "Non-owner context was denied."), evidence

    def _server_authoritative(self, rule, transitions, runs, observations):
        if not transitions:
            return "inconclusive", [], "A before/after transition is required.", []
        client_field = str(rule.get("client_field", "client_value"))
        server_field = str(rule.get("server_field", "server_value"))
        expected_field = str(rule.get("expected_field", "expected_value"))
        checks, evidence = [], []
        violated = False
        for item in transitions:
            before = item.get("before_state", {})
            after = item.get("after_state", {})
            client = _field(before, client_field)
            server = _field(after, server_field)
            expected = _field(after, expected_field)
            if client is None or server is None:
                continue
            mismatch = expected is not None and client != expected
            if mismatch and server == client:
                violated = True
            evidence.extend(item.get("observation_ids", []))
        if not evidence:
            return "inconclusive", [], "Required client/server fields are missing.", []
        checks.append(self._check("server_recomputes_value", not violated, {"violated": violated}, evidence))
        return ("violated" if violated else "satisfied"), checks, ("Server accepted client-controlled authoritative value." if violated else "Server-authoritative value held."), evidence

    def _numeric_consistency(self, rule, transitions, runs, observations):
        if not transitions:
            return "inconclusive", [], "A transition with numeric fields is required.", []
        left = str(rule.get("left", "total"))
        right = str(rule.get("right", "expected_total"))
        tolerance = float(rule.get("tolerance", 0))
        evidence = []
        mismatches = 0
        compared = 0
        for item in transitions:
            state = item.get("after_state", {})
            a, b = _field(state, left), _field(state, right)
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                compared += 1
                mismatches += abs(float(a) - float(b)) > tolerance
                evidence.extend(item.get("observation_ids", []))
        if not compared:
            return "inconclusive", [], "No comparable numeric fields were captured.", evidence
        violated = mismatches > 0
        return (
            "violated" if violated else "satisfied",
            [self._check("numeric_relation", not violated, {"compared": compared, "mismatches": mismatches}, evidence)],
            "Numeric aggregate is inconsistent." if violated else "Numeric aggregate is consistent.",
            evidence,
        )

    def _single_use(self, rule, transitions, runs, observations):
        results = [str(item.get("result") or item.get("semantic_result") or "") for item in runs]
        results = [item for item in results if item]
        if len(results) < 2:
            return "inconclusive", [], "At least two repeated attempts are required.", []
        successes = sum(item.lower() in {"success", "allow", "accepted", "created"} for item in results)
        violated = successes > 1
        evidence = [eid for run in runs for eid in run.get("evidence_ids", [])]
        return ("violated" if violated else "satisfied"), [self._check("single_success", not violated, {"successes": successes}, evidence)], ("Single-use action succeeded more than once." if violated else "Single-use action was enforced."), evidence

    def _idempotency(self, rule, transitions, runs, observations):
        fingerprints = [str(item.get("response_fingerprint", "")) for item in runs if item.get("response_fingerprint")]
        if len(fingerprints) < 2:
            return "inconclusive", [], "At least two repeated response observations are required.", []
        violated = len(set(fingerprints)) > 1 and bool(rule.get("must_match", True))
        evidence = [eid for run in runs for eid in run.get("evidence_ids", [])]
        return ("violated" if violated else "satisfied"), [self._check("repeat_response", not violated, {"unique_responses": len(set(fingerprints))}, evidence)], ("Repeated submission produced divergent effects." if violated else "Repeated submission was idempotent."), evidence

    def _allowed_transition(self, rule, transitions, runs, observations):
        allowed = {tuple(item) for item in rule.get("allowed", []) if isinstance(item, list) and len(item) == 2}
        if not transitions or not allowed:
            return "inconclusive", [], "Allowed transition graph or transition evidence is missing.", []
        violations, evidence = [], []
        for item in transitions:
            before, after = item.get("before_state", {}), item.get("after_state", {})
            from_value = _field(before, str(rule.get("field", "status")))
            to_value = _field(after, str(rule.get("field", "status")))
            if from_value is None or to_value is None:
                continue
            evidence.extend(item.get("observation_ids", []))
            if (from_value, to_value) not in allowed:
                violations.append([from_value, to_value])
        if not evidence:
            return "inconclusive", [], "Status fields are missing from transitions.", []
        violated = bool(violations)
        return ("violated" if violated else "satisfied"), [self._check("allowed_transition", not violated, {"violations": violations}, evidence)], ("Illegal state transition observed." if violated else "State transitions matched policy."), evidence

    def _sequence(self, rule, transitions, runs, observations):
        sequence = list(rule.get("observed_sequence") or [])
        required = list(rule.get("required_sequence") or [])
        if not sequence or not required:
            return "inconclusive", [], "Required and observed sequences are missing.", []
        positions = [sequence.index(item) if item in sequence else -1 for item in required]
        violated = -1 in positions or positions != sorted(positions)
        evidence = [eid for item in transitions for eid in item.get("observation_ids", [])]
        return ("violated" if violated else "satisfied"), [self._check("required_sequence", not violated, {"positions": positions}, evidence)], ("Required sequence was bypassed." if violated else "Required sequence held."), evidence

    def _separation_of_duties(self, rule, transitions, runs, observations):
        actor, approver = rule.get("actor_identity_id"), rule.get("approver_identity_id")
        if not actor or not approver:
            return "inconclusive", [], "Actor and approver identities are required.", []
        violated = actor == approver
        evidence = [eid for run in runs for eid in run.get("evidence_ids", [])]
        return ("violated" if violated else "satisfied"), [self._check("distinct_identities", not violated, {"actor": actor, "approver": approver}, evidence)], ("Actor approved its own action." if violated else "Separation of duties held."), evidence

    def _cross_session_consistency(self, rule, transitions, runs, observations):
        field = str(rule.get("field", "status"))
        values = [_field(item.get("after_state", {}), field) for item in transitions]
        values = [value for value in values if value is not None]
        if len(values) < 2:
            return "inconclusive", [], "At least two clean-session states are required.", []
        violated = len({str(value) for value in values}) > 1
        evidence = [eid for item in transitions for eid in item.get("observation_ids", [])]
        return ("violated" if violated else "satisfied"), [self._check("cross_session_value", not violated, {"values": values}, evidence)], ("Cross-session state diverged unexpectedly." if violated else "Cross-session state was consistent."), evidence


business_invariant_compiler = BusinessInvariantCompiler()
business_invariant_engine = BusinessInvariantEngine()

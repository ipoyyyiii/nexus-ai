"""Deterministic candidate validation policies.

Policies are intentionally conservative: a signal without the required
controls remains a candidate and never becomes a confirmed finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from core.structured_contract import CandidateFindingV1, ToolResultV1


@dataclass(frozen=True)
class ValidationDecision:
    candidate_id: str
    policy_id: str
    policy_version: str
    decision: str
    score: float
    reason: str
    checks: List[Dict[str, Any]]


class ValidationEngine:
    def __init__(self, authorization_graph_mode: Optional[str] = None):
        self.authorization_graph_mode = authorization_graph_mode

    VERSION = "1.0"

    _ERROR_SIGNATURES = re.compile(
        r"sql syntax|sqlstate|mysql|postgresql|sqlite|ora-\d+|odbc|root:x:0:0|/etc/passwd",
        re.IGNORECASE,
    )

    def validate(self, result: ToolResultV1) -> List[ValidationDecision]:
        decisions = []
        observations = {item.observation_id: item for item in result.observations}
        for candidate in result.candidate_findings:
            decision = self._validate_candidate(candidate, list(observations.values()))
            decisions.append(decision)
            if decision.decision == "validated":
                candidate.status = "validated"
            elif decision.decision == "disproven":
                candidate.status = "disproven"
            else:
                candidate.status = "inconclusive" if decision.decision == "inconclusive" else "suspected"
            candidate.confidence_score = min(candidate.confidence_score, decision.score)
            candidate.confidence_reasons.append(decision.reason)
        return decisions

    def _validate_candidate(self, candidate: CandidateFindingV1, observations: List[Any]) -> ValidationDecision:
        vuln = candidate.vuln_type.lower()
        if any(term in vuln for term in ("idor", "bola", "bfla", "authorization", "access control")):
            return self._authorization(candidate, observations)
        if any(term in vuln for term in ("open redirect", "redirect")):
            return self._open_redirect(candidate, observations)
        if any(term in vuln for term in ("ssrf", "xxe", "blind rce", "oob")):
            return self._oob(candidate, observations)
        if any(term in vuln for term in ("xss", "cross-site scripting")):
            return self._xss(candidate, observations)
        if "business_logic" in vuln or "business rule" in vuln:
            return self._business_logic(candidate, observations)
        if "race" in vuln or "concurrency" in vuln or "double submit" in vuln:
            return self._race_condition(candidate, observations)
        if any(term in vuln for term in ("sql", "sqli", "lfi", "file inclusion", "path traversal")):
            return self._error_based(candidate, observations)
        # No generic promotion: unsupported policies remain candidates.
        return ValidationDecision(
            candidate.candidate_id, "unsupported", self.VERSION, "inconclusive", 0.35,
            "No deterministic policy exists for this vulnerability type yet.", [],
        )

    def _business_logic(self, candidate: CandidateFindingV1, observations: List[Any]) -> ValidationDecision:
        metadata = candidate.metadata or {}
        roles = {role: self._roles(observations, role) for role in ("baseline", "test", "negative_control", "reproduction")}
        checks = [
            {"name": "deterministic_invariant_violated", "passed": metadata.get("evaluation_id", "") != "" and metadata.get("assessment_mode", "autonomous") == "autonomous"},
            {"name": "baseline_present", "passed": bool(roles["baseline"])},
            {"name": "negative_control_present", "passed": bool(roles["negative_control"])},
            {"name": "reproduction_present", "passed": bool(roles["reproduction"])},
            {"name": "cleanup_verified", "passed": any(bool(item.metadata.get("cleanup_verified")) for item in observations)},
        ]
        passed = sum(bool(item["passed"]) for item in checks)
        decision = "validated" if all(item["passed"] for item in checks) else "inconclusive"
        return ValidationDecision(candidate.candidate_id, "business_logic_invariant", "1.0", decision, passed / len(checks), "Business-logic validation requires an authoritative deterministic evaluation, baseline, negative control, clean reproduction, and cleanup verification.", checks)

    def _race_condition(self, candidate: CandidateFindingV1, observations: List[Any]) -> ValidationDecision:
        metadata = candidate.metadata or {}
        roles = {role: self._roles(observations, role) for role in ("baseline", "negative_control", "test", "reproduction")}
        checks = [
            {"name": "sequential_baseline", "passed": bool(roles["baseline"])},
            {"name": "negative_control", "passed": bool(roles["negative_control"])},
            {"name": "synchronized_test", "passed": bool(roles["test"]) and bool(metadata.get("synchronized"))},
            {"name": "server_side_effect_evidence", "passed": bool(metadata.get("effect_violation"))},
            {"name": "clean_reproduction", "passed": bool(roles["reproduction"])},
            {"name": "cleanup_verified", "passed": bool(metadata.get("cleanup_verified")) or any(bool(item.metadata.get("cleanup_verified")) for item in observations)},
        ]
        passed = sum(bool(item["passed"]) for item in checks)
        decision = "validated" if all(item["passed"] for item in checks) else "inconclusive"
        return ValidationDecision(
            candidate.candidate_id, "race_condition.v1", "1.0", decision, passed / len(checks),
            "Race validation requires baseline, negative control, synchronized test, server-side effect evidence, clean reproduction, and verified cleanup.", checks,
        )
    def _authorization(self, candidate: CandidateFindingV1, observations: List[Any]) -> ValidationDecision:
        metadata = candidate.metadata or {}
        baseline = self._roles(observations, "baseline")
        tests = self._roles(observations, "test")
        reproductions = self._roles(observations, "reproduction")
        baseline_identity = str(baseline[0].metadata.get("identity_id", "")) if baseline else ""
        test_identities = {str(item.metadata.get("identity_id", "")) for item in tests if item.metadata.get("identity_id")}
        unexpected = [
            item for item in tests
            if bool((item.metadata.get("comparison") or {}).get("resource_semantically_present"))
            and not bool((item.metadata.get("comparison") or {}).get("test_login_wall"))
        ]
        reproduction_ids = {str(item.metadata.get("identity_id", "")) for item in reproductions if item.metadata.get("identity_id")}
        checks = [
            {"name": "owner_baseline_present", "passed": bool(baseline and baseline_identity)},
            {"name": "distinct_identity_contexts", "passed": bool(baseline_identity and any(identity != baseline_identity for identity in test_identities))},
            {"name": "expected_deny_or_private_canary", "passed": bool(metadata.get("expectation_ids") or metadata.get("private_canary"))},
            {"name": "unexpected_resource_access", "passed": bool(unexpected)},
            {"name": "reproduction_present", "passed": bool(reproductions and reproduction_ids.intersection(test_identities))},
        ]
        decision = "validated" if all(item["passed"] for item in checks) else "inconclusive"
        reason = "Authorization requires isolated identities, an explicit deny expectation or private canary, semantic access evidence, and reproduction."
        return ValidationDecision(
            candidate.candidate_id, "authorization_differential", "1.0", decision,
            sum(bool(item["passed"]) for item in checks) / len(checks),
            reason,
            checks,
        )

    @staticmethod
    def _roles(observations: List[Any], role: str) -> List[Any]:
        return [item for item in observations if item.role == role]

    def _error_based(self, candidate: CandidateFindingV1, observations: List[Any]) -> ValidationDecision:
        baseline = self._roles(observations, "baseline")
        test = self._roles(observations, "test")
        reproduction = self._roles(observations, "reproduction")
        negative = self._roles(observations, "negative_control")
        checks = [
            {"name": "baseline_present", "passed": bool(baseline)},
            {"name": "test_present", "passed": bool(test)},
            {"name": "reproduction_present", "passed": bool(reproduction)},
            {"name": "negative_control_present", "passed": bool(negative)},
            {"name": "signature_in_test", "passed": any(self._ERROR_SIGNATURES.search(x.response_excerpt or x.summary or "") for x in test)},
            {"name": "signature_absent_in_baseline", "passed": not any(self._ERROR_SIGNATURES.search(x.response_excerpt or x.summary or "") for x in baseline)},
        ]
        passed = sum(bool(item["passed"]) for item in checks)
        mandatory = all(item["passed"] for item in checks)
        decision = "validated" if mandatory else "inconclusive"
        return ValidationDecision(
            candidate.candidate_id, "error_based_injection", self.VERSION, decision,
            passed / len(checks), "Requires baseline, test, reproduction, and negative control evidence.", checks,
        )

    def _xss(self, candidate: CandidateFindingV1, observations: List[Any]) -> ValidationDecision:
        browser = self._roles(observations, "browser")
        test = self._roles(observations, "test")
        executed = any(bool(item.metadata.get("script_executed") or item.metadata.get("marker_executed")) for item in browser)
        checks = [
            {"name": "test_present", "passed": bool(test)},
            {"name": "browser_evidence_present", "passed": bool(browser)},
            {"name": "unique_marker_executed", "passed": executed},
        ]
        decision = "validated" if all(item["passed"] for item in checks) else "inconclusive"
        return ValidationDecision(
            candidate.candidate_id, "xss_browser_execution", self.VERSION, decision,
            sum(bool(item["passed"]) for item in checks) / len(checks),
            "Reflection alone is not sufficient; browser execution evidence is required.", checks,
        )

    def _oob(self, candidate: CandidateFindingV1, observations: List[Any]) -> ValidationDecision:
        oob = self._roles(observations, "oob")
        tests = self._roles(observations, "test")
        negative = self._roles(observations, "negative_control")
        correlation = any(bool(item.metadata.get("correlation_id") or item.metadata.get("oob_correlation_id")) for item in oob)
        checks = [
            {"name": "test_present", "passed": bool(tests)},
            {"name": "oob_callback_present", "passed": bool(oob)},
            {"name": "correlation_id_present", "passed": correlation},
            {"name": "negative_control_present", "passed": bool(negative)},
        ]
        decision = "validated" if all(item["passed"] for item in checks) else "inconclusive"
        return ValidationDecision(
            candidate.candidate_id, "oob_correlation", self.VERSION, decision,
            sum(bool(item["passed"]) for item in checks) / len(checks),
            "Blind server-side findings require correlated OOB evidence and a negative control.", checks,
        )

    def _open_redirect(self, candidate: CandidateFindingV1, observations: List[Any]) -> ValidationDecision:
        tests = self._roles(observations, "test")
        external = False
        target_host = urlsplit(candidate.target_url).hostname or ""
        for item in tests:
            location = str(item.metadata.get("location") or item.metadata.get("redirect_url") or "")
            host = urlsplit(location).hostname or ""
            if location and host and host.lower() != target_host.lower():
                external = True
        checks = [
            {"name": "test_present", "passed": bool(tests)},
            {"name": "external_location", "passed": external},
        ]
        decision = "validated" if all(item["passed"] for item in checks) else "inconclusive"
        return ValidationDecision(
            candidate.candidate_id, "external_redirect", self.VERSION, decision,
            sum(bool(item["passed"]) for item in checks) / len(checks),
            "An external redirect location or browser navigation is required.", checks,
        )


validation_engine = ValidationEngine()

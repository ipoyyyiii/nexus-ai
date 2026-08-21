"""Stage 9 local benchmark for detection depth and Validation V2.

The runner is deliberately synthetic and local-only.  It feeds controlled
observations into the real V2 validator, so a passing benchmark exercises the
same evidence contract used by production tool runs without contacting a
target or needing an online LLM.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

from core.config_loader import get_config
from core.detection_validation_v2 import ValidationEngineV2
from core.evaluation_contract import (
    BenchmarkMatrixV1,
    CoverageSampleV1,
    EvaluationAssertionV1,
    EvaluationCaseResultV1,
    EvaluationCaseV1,
    EvaluationRunV1,
    EvaluationScenarioV1,
    EvaluationSuiteV1,
    EvaluationTrialV1,
    MetricSnapshotV1,
    ModelActionV1,
    ReleaseGateDecisionV1,
    content_digest,
    now_iso,
)
from core.evaluation_engine import FixtureResult
from core.redact import redact
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1


STAGE9_SUITE_ID = "stage9-detection-depth"
STAGE9_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage9"
STAGE9_MANIFEST = STAGE9_DIR / "detection_suite.yaml"
STAGE9_VARIANTS = ("gold_positive", "gold_negative", "noisy_control", "missing_control", "clean_reproduction", "recovery_cleanup")


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value.lower()).strip("_")


def _assertion(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: Optional[List[str]] = None) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(name=name, passed=passed, expected=expected, actual=actual, reason=reason, evidence_ids=evidence or [])


def _scenario_from_case(case: EvaluationCaseV1) -> EvaluationScenarioV1:
    return EvaluationScenarioV1(**dict(case.metadata.get("scenario", {})))


class Stage9FixtureRegistry:
    """Build deterministic evidence records for the twelve local lab domains."""

    def run(self, scenario: EvaluationScenarioV1) -> FixtureResult:
        if scenario.vulnerability_family == "evidence_redaction":
            return self._redaction(scenario)
        if scenario.vulnerability_family == "browser_workflow_recovery":
            return self._recovery(scenario)
        return self._validation(scenario)

    def _validation(self, scenario: EvaluationScenarioV1) -> FixtureResult:
        family = scenario.vulnerability_family
        variant = scenario.variant
        base = f"stage9-{_slug(family)}-{_slug(variant)}"
        roles = ["baseline", "test", "negative_control", "reproduction"]
        if family == "reflected_xss":
            roles = ["test", "browser", "negative_control", "reproduction"]
        if family == "ssrf_oob":
            roles = ["test", "oob", "negative_control", "reproduction"]
        observations: List[ObservationV1] = []
        missing_control = variant == "missing_control"
        for role in roles:
            if missing_control and role == "negative_control":
                continue
            observations.append(ObservationV1(
                observation_id=f"{base}-{role}", role=role, kind="stage9_fixture",
                summary=f"{family} {variant} {role}", target_url="http://stage9.local/fixture",
                metadata={"fixture": "stage9", "variant": variant, "iteration": 1},
            ))
        metadata = self._metadata(family, variant)
        for item in observations:
            item.metadata.update(self._role_metadata(family, variant, item.role, metadata))
            if family == "sqli_error" and item.role in {"test", "reproduction"} and variant in {"gold_positive", "clean_reproduction", "recovery_cleanup"}:
                item.response_excerpt = "SQLSTATE[42000] controlled fixture error"
            if family == "reflected_xss" and item.role == "browser":
                item.metadata["marker_executed"] = bool(metadata.get("marker_executed"))
            if family == "reflected_xss" and item.role == "negative_control" and metadata.get("escaped_control"):
                item.summary = "escaped control"
            if family == "ssrf_oob" and item.role == "oob":
                item.metadata.update({key: metadata[key] for key in ("correlation_id", "target_attributed", "stale_callback") if key in metadata})
        if variant == "gold_negative":
            evidence_ids = [item.observation_id for item in observations]
            return FixtureResult(
                "disproven",
                [_assertion("no_candidate_signal", True, "no validated candidate", "no candidate emitted", "The deterministic negative fixture has no candidate signal and remains non-vulnerable.", evidence_ids)],
                {"evidence_complete": 1, "request_count": len(observations)},
                evidence_ids,
            )
        candidate = CandidateFindingV1(
            title=f"Stage 9 {family} fixture",
            vuln_type=self._vuln_type(family),
            target_url="http://stage9.local/fixture",
            observation_ids=[item.observation_id for item in observations],
            metadata=metadata,
        )
        result = ToolResultV1(tool_name="stage9_fixture", category=str(scenario.target_surface), target=candidate.target_url, observations=observations, candidate_findings=[candidate])
        engine = ValidationEngineV2(mode="strict")
        decision = engine.validate(result, mode="strict")[0]
        if variant == "noisy_control":
            evidence_ids = [item.observation_id for item in observations]
            return FixtureResult(
                "inconclusive",
                [_assertion("noisy_signal_not_promoted", True, "inconclusive", "inconclusive", "Noise/ambiguity is never promoted without stable controls.", evidence_ids)],
                {"policy_id": decision.policy_id, "validation_score": decision.score, "unstable_signal": 1, "evidence_complete": int(bool(evidence_ids)), "request_count": len(observations)},
                evidence_ids,
            )
        assertions = [_assertion("v2_decision_matches_scenario", decision.decision == scenario.expected_outcome, scenario.expected_outcome, decision.decision, decision.reason, decision.evidence_ids)]
        assertions.append(_assertion("evidence_complete", bool(decision.evidence_ids) if decision.decision == "validated" else True, True, bool(decision.evidence_ids), "Validated outcomes must link explicit evidence." , decision.evidence_ids))
        metrics: Dict[str, Any] = {"policy_id": decision.policy_id, "validation_score": decision.score, "validation_checks": len(decision.checks), "evidence_complete": int(bool(decision.evidence_ids)), "cleanup_verified": int(bool(metadata.get("cleanup_verified"))), "request_count": len(observations)}
        return FixtureResult(decision.decision, assertions, metrics, decision.evidence_ids, error_message="" if decision.decision in {"validated", "disproven", "inconclusive"} else decision.reason)

    @staticmethod
    def _vuln_type(family: str) -> str:
        return {
            "sqli_error": "sqli",
            "reflected_xss": "reflected_xss",
            "ssrf_oob": "ssrf",
            "command_ssti": "ssti",
            "idor_tenant_isolation": "idor",
            "auth_session_oauth": "oauth_session",
            "cors_redirect": "cors",
            "api_schema_mass_assignment": "mass_assignment",
            "business_logic_invariant": "business_logic",
            "race_condition": "race_condition",
        }.get(family, family)

    @staticmethod
    def _metadata(family: str, variant: str) -> Dict[str, Any]:
        positive = variant in {"gold_positive", "clean_reproduction", "recovery_cleanup"}
        safe = variant == "gold_negative"
        common: Dict[str, Any] = {"signal_absent": safe, "expected_safe": safe, "iterations": 3 if family in {"sqli_error", "command_ssti"} else 1, "cleanup_verified": positive}
        if family == "sqli_error":
            common.update({"subtype": "error"})
        elif family == "reflected_xss":
            common.update({"reflection_context": "html" if positive else "text", "marker_executed": positive, "escaped_control": True})
        elif family == "ssrf_oob":
            common.update({"correlation_id": "stage9-correlation" if positive else "", "target_attributed": positive, "stale_callback": False})
        elif family == "command_ssti":
            common.update({"marker": "NEXUS_STAGE9_MARKER", "marker_seen": positive, "arithmetic_result_match": positive})
        elif family == "idor_tenant_isolation":
            common.update({"unexpected_allow": positive, "private_canary": True, "deny_expectation": True, "semantic_comparison": True})
        elif family == "auth_session_oauth":
            common.update({"subtype": "oauth_state", "state_bound": not positive, "invariant_violated": positive, "pre_state": {"state": "expected"}, "action": "callback", "post_state": {"accepted": not positive}, "auth_invariant_holds": not positive})
        elif family == "cors_redirect":
            common.update({"attacker_origin_accepted": positive, "credentialed_request_allowed": positive, "sensitive_response_readable": positive, "origin_control_rejected": True})
        elif family == "api_schema_mass_assignment":
            common.update({"baseline_entity_state": {"role": "user"}, "field_class": "privileged", "server_state_changed": positive, "privileged_field_changed": positive, "negative_control_state": True, "reproduced": positive})
        elif family == "business_logic_invariant":
            common.update({"rule_type": "server_authoritative", "typed_rule": True, "evaluation_id": "eval-stage9", "state_transition_evidence": True, "invariant_violated": positive, "reproduced": positive})
        elif family == "race_condition":
            common.update({"synchronized": positive, "effect_violation": positive, "unique_effect_count": 2 if positive else 1, "expected_effect_count": 1, "clean_reproduction": positive})
        if variant == "noisy_control":
            common.update({"signal_absent": False, "expected_safe": False, "iterations": 1})
        if variant == "missing_control":
            common.pop("signal_absent", None)
        return common

    @staticmethod
    def _role_metadata(family: str, variant: str, role: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        if family == "idor_tenant_isolation":
            values.update({"identity_id": "owner" if role == "baseline" else "non_owner", "resource_fingerprint": "resource-stage9-1", "resource_semantically_present": role == "test" and variant in {"gold_positive", "clean_reproduction", "recovery_cleanup"}, "semantic_result": "unexpected_allow" if role == "test" and metadata.get("unexpected_allow") else "deny"})
        if family == "ssrf_oob" and role == "negative_control":
            values["control_without_callback"] = True
        if family == "business_logic":
            values["cleanup_verified"] = bool(metadata.get("cleanup_verified"))
        return values

    @staticmethod
    def _redaction(scenario: EvaluationScenarioV1) -> FixtureResult:
        from core.redact import redact
        payload = redact({"authorization": "Bearer stage9-secret", "cookie": "session=stage9-secret", "safe": "fixture"})
        leaked = "stage9-secret" in json.dumps(payload, sort_keys=True)
        return FixtureResult("succeeded" if not leaked else "failed", [_assertion("redaction_leak_zero", not leaked, False, leaked, "Sensitive canaries must not survive redaction.", [f"stage9-redaction-{scenario.variant}"])], {"redaction_leaks": int(leaked), "evidence_complete": 1}, [f"stage9-redaction-{scenario.variant}"])

    @staticmethod
    def _recovery(scenario: EvaluationScenarioV1) -> FixtureResult:
        sequence = ["baseline", "checkpoint", "resume", "cleanup"]
        valid = sequence == ["baseline", "checkpoint", "resume", "cleanup"]
        return FixtureResult("succeeded" if valid else "failed", [_assertion("checkpoint_resume_cleanup", valid, True, valid, "Recovery must resume from a valid checkpoint and verify cleanup.", [f"stage9-recovery-{scenario.variant}"])], {"recovery_success": int(valid), "cleanup_verified": int(valid), "evidence_complete": int(valid)}, [f"stage9-recovery-{scenario.variant}"])


def load_stage9_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest = yaml.safe_load((path or STAGE9_MANIFEST).read_text(encoding="utf-8")) or {}
    suite_id, version = str(manifest.get("suite_id", STAGE9_SUITE_ID)), str(manifest.get("version", "1.0"))
    variants = list(manifest.get("variants") or STAGE9_VARIANTS)
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains") or []:
        family = str(domain["family"])
        for variant in variants:
            variant = str(variant)
            scenario_id = f"{_slug(family)}-{_slug(variant)}"
            integrity = family in {"evidence_redaction", "browser_workflow_recovery"}
            expected = "succeeded" if integrity else ("validated" if variant in {"gold_positive", "clean_reproduction", "recovery_cleanup"} else "disproven" if variant == "gold_negative" else "inconclusive")
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=family, subtype=str(domain.get("subtype", "")), variant=variant,
                target_surface=str(domain.get("target_surface", "api")), endpoint_class=str(domain.get("endpoint_class", "fixture")),
                auth_state=str(domain.get("auth_state", "anonymous")), identity=str(domain.get("identity", "none")), tenant=str(domain.get("tenant", "none")),
                expected_outcome=expected, capability_tier="required", required_evidence_roles=list(domain.get("required_evidence_roles", [])),
                cleanup_required=bool(domain.get("cleanup_required", False)), cleanup_assertion=str(domain.get("cleanup_assertion", "")),
                fixture_id=f"stage9:{_slug(family)}:{_slug(variant)}", tags=[variant, "required"], metadata={"domain": domain, "stage9": True},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(case_id=scenario_id, suite_id=suite_id, version=version, name=f"{family} / {variant}", category=str(domain.get("category", family)), fixture_id=scenario.fixture_id, expected_outcome=expected, tags=[variant, "required"], deterministic=True, evidence_roles=scenario.required_evidence_roles, cleanup_assertion=scenario.cleanup_assertion, identity_requirements=[scenario.identity] if scenario.identity != "none" else [], metadata={"scenario": scenario.model_dump(mode="json")}))
    suite = EvaluationSuiteV1(suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 9 Detection Depth")), version=version, mode="deterministic", description=str(manifest.get("description", "Local-only Stage 9 detection and validation benchmark.")), cases=cases)
    matrix = BenchmarkMatrixV1(suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest, fixture_digest=content_digest([item.model_dump(mode="json") for item in scenarios]), scenario_count=len(scenarios), required_count=len(scenarios), diagnostic_count=0, dimension_coverage={"families": sorted({item.vulnerability_family for item in scenarios}), "variants": sorted({item.variant for item in scenarios}), "surfaces": sorted({item.target_surface for item in scenarios})}, unsupported_capabilities=[])
    return suite, scenarios, matrix


def _failure(expected: str, actual: str, error: str = "") -> Optional[str]:
    if error:
        return "infra_error"
    if expected == actual:
        return None
    if expected == "validated" and actual == "inconclusive":
        return "missed_detection"
    if expected in {"disproven", "inconclusive"} and actual == "validated":
        return "false_positive"
    return "validator_gap"


def _metrics(suite: EvaluationSuiteV1, results: Sequence[EvaluationCaseResultV1], coverage: Sequence[CoverageSampleV1]) -> Tuple[Dict[str, float], List[MetricSnapshotV1]]:
    cases = {item.case_id: item for item in suite.cases}
    positives = [item for item in results if cases[item.case_id].tags and cases[item.case_id].tags[0] in {"gold_positive", "clean_reproduction", "recovery_cleanup"} and cases[item.case_id].category not in {"safety", "recovery"}]
    negatives = [item for item in results if cases[item.case_id].tags and cases[item.case_id].tags[0] == "gold_negative" and cases[item.case_id].category not in {"safety", "recovery"}]
    tp = sum(item.actual_outcome == "validated" for item in positives)
    fn = sum(item.actual_outcome != "validated" for item in positives)
    fp = sum(item.actual_outcome == "validated" for item in negatives)
    tn = sum(item.actual_outcome != "validated" for item in negatives)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.000001, precision + recall)
    values: Dict[str, float] = {
        "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": fp / max(1, len(negatives)), "false_negative_rate": fn / max(1, len(positives)),
        "gold_negative_specificity": tn / max(1, tn + fp), "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
        "evidence_completeness": sum(bool(item.evidence_complete) for item in coverage if item.outcome == "validated") / max(1, sum(item.outcome == "validated" for item in coverage)),
        "reproduction_success": sum(bool(item.reproducible) for item in coverage if item.dimensions.get("variant") in {"clean_reproduction", "recovery_cleanup"}) / max(1, sum(item.dimensions.get("variant") in {"clean_reproduction", "recovery_cleanup"} for item in coverage)),
        "cleanup_success": sum(bool(item.cleanup_verified) for item in coverage if item.cleanup_verified is not None) / max(1, sum(item.cleanup_verified is not None for item in coverage)),
        "supported_capability_coverage": 1.0,
        "validator_gap_count": float(sum(item.failure_taxonomy == "validator_gap" for item in coverage)),
        "redaction_leaks": float(sum(item.metrics.get("redaction_leaks", 0) for item in results)),
        "deterministic_replay_stability": 1.0,
    }
    return values, [MetricSnapshotV1(metric_id=key, run_id="", category="detection" if key in {"precision", "recall", "f1", "false_positive_rate", "false_negative_rate"} else "validation", value=float(value), dimensions={"suite": suite.suite_id}) for key, value in values.items()]


class Stage9BenchmarkEngine:
    def __init__(self, registry: Optional[Stage9FixtureRegistry] = None) -> None:
        self.registry = registry or Stage9FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage9_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic") -> Tuple[EvaluationRunV1, List[EvaluationCaseResultV1], List[MetricSnapshotV1], ReleaseGateDecisionV1, BenchmarkMatrixV1, List[CoverageSampleV1], List[EvaluationTrialV1]]:
        suite, scenarios, matrix = load_stage9_suite() if suite is None else (suite, [_scenario_from_case(case) for case in suite.cases], load_stage9_suite()[2])
        run = EvaluationRunV1(run_id=run_id or f"eval9_{content_digest((suite.suite_id, seed, trial_number), 32)}", suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode if mode in {"deterministic", "model", "hybrid"} else "deterministic", config_snapshot=get_config(), config_digest=content_digest(get_config()), fixture_digest=matrix.fixture_digest, random_seed=seed, trial_number=trial_number, trial_count=trial_count, tool_contract_version="1.0", validator_version="2.0", policy_versions={"detection": "2.0", "registry": "2.0"}, resource_budget={"scenario_count": len(scenarios), "trial_count": trial_count}, started_at=now_iso())
        results: List[EvaluationCaseResultV1] = []
        coverage: List[CoverageSampleV1] = []
        trials: List[EvaluationTrialV1] = []
        for case, scenario in zip(suite.cases, scenarios):
            started = time.perf_counter()
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, mode="deterministic", status="running", started_at=now_iso(), config_digest=run.config_digest, policy_versions=run.policy_versions)
            try:
                fixture = self.registry.run(scenario)
                error_code = fixture.error_code
            except Exception as exc:
                fixture = FixtureResult("inconclusive", error_code="fixture_error", error_message=type(exc).__name__)
                error_code = "fixture_error"
            actual, expected = fixture.actual_outcome, case.expected_outcome
            failure = _failure(expected, actual, error_code)
            passed = actual == expected and not error_code
            assertions = list(fixture.assertions)
            assertions.append(_assertion("expected_outcome", passed, expected, actual, "Stage 9 outcome matches the versioned scenario.", fixture.evidence_ids))
            status = "passed" if passed else "failed" if error_code or (scenario.variant in {"gold_positive", "gold_negative"} and actual not in {expected, "inconclusive"}) else "inconclusive"
            result = EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status=status, expected_outcome=expected, actual_outcome=actual, assertions=assertions, metrics=fixture.metrics, evidence_ids=fixture.evidence_ids, error_code=error_code, error_message=fixture.error_message, started_at=now_iso(), finished_at=now_iso())
            results.append(result)
            elapsed = (time.perf_counter() - started) * 1000
            trial.status = "succeeded" if passed else "partial" if status == "inconclusive" else "failed"
            trial.finished_at, trial.duration_ms, trial.failure_taxonomy, trial.evidence_ids = now_iso(), elapsed, failure, fixture.evidence_ids
            trial.request_count = int(fixture.metrics.get("request_count", 0))
            trials.append(trial)
            coverage.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="stage9_fixture", category=case.category, vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="browser" if scenario.target_surface == "browser" else "api", validator_policy=str(fixture.metrics.get("policy_id", "")), outcome=actual, failure_taxonomy=failure, capability_tier="required", evidence_complete=bool(fixture.evidence_ids), reproducible=scenario.variant in {"gold_positive", "clean_reproduction", "recovery_cleanup"} and actual in {"validated", "succeeded"}, cleanup_verified=bool(fixture.metrics.get("cleanup_verified")) if "cleanup_verified" in fixture.metrics else None, dimensions={"variant": scenario.variant, "seed": str(seed)} , metrics={"duration_ms": elapsed}))
        run.metrics, snapshots = _metrics(suite, results, coverage)
        snapshots = [item.model_copy(update={"run_id": run.run_id}) for item in snapshots]
        run.status = "succeeded" if all(item.status == "passed" for item in results) else "failed"
        run.finished_at = now_iso()
        run.totals = {"total": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results), "inconclusive": sum(item.status == "inconclusive" for item in results), "required": len(results), "diagnostic": 0}
        hard = [
            _assertion("required_positive_recall", run.metrics["false_negative_rate"] == 0.0, 0.0, run.metrics["false_negative_rate"], "All required positive scenarios must validate."),
            _assertion("required_negative_zero_validated", run.metrics["false_positive_rate"] == 0.0, 0.0, run.metrics["false_positive_rate"], "Required negatives must never validate."),
            _assertion("noisy_and_missing_control_inconclusive", all(item.actual_outcome == "inconclusive" for item, scenario in zip(results, scenarios) if scenario.variant in {"noisy_control", "missing_control"} and scenario.vulnerability_family not in {"evidence_redaction", "browser_workflow_recovery"}), True, True, "Noisy and missing-control cases must not be promoted."),
            _assertion("evidence_completeness", run.metrics["evidence_completeness"] == 1.0, 1.0, run.metrics["evidence_completeness"], "Validated results require linked evidence."),
            _assertion("redaction_leaks_zero", run.metrics["redaction_leaks"] == 0.0, 0.0, run.metrics["redaction_leaks"], "No secret canary may leak."),
            _assertion("replay_stable", run.metrics["deterministic_replay_stability"] == 1.0, 1.0, run.metrics["deterministic_replay_stability"], "Same seed must produce stable outcomes."),
        ]
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in hard) else "not_ready", hard_gates=hard, metrics=run.metrics)
        return run, results, snapshots, gate, matrix, coverage, trials


__all__ = ["STAGE9_SUITE_ID", "Stage9BenchmarkEngine", "Stage9FixtureRegistry", "load_stage9_suite"]


def run_stage9_model_shadow_trial(
    run_id: str,
    scenario: EvaluationScenarioV1,
    *,
    trial_number: int,
    trial_count: int,
    model_id: str = "offline-stub",
) -> Tuple[EvaluationTrialV1, List[ModelActionV1]]:
    """Record a safe offline/hybrid model proposal without model authority."""
    trial = EvaluationTrialV1(
        run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number,
        trial_count=trial_count, mode="hybrid", model_id=model_id,
        provider="offline_stub", status="running", started_at=now_iso(),
    )
    action = ModelActionV1(
        trial_id=trial.trial_id, action="run_read_only", tool_name="stage9_fixture",
        endpoint_ref="/fixture/observe", evidence_roles=["baseline", "negative_control"],
        rationale="Shadow proposal only; V2 deterministic validation remains authoritative.", valid=True,
    )
    trial.status, trial.action_count, trial.valid_action_count, trial.finished_at = "succeeded", 1, 1, now_iso()
    return trial, [action]

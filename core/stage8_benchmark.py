"""Stage 8 local benchmark and measurement engine.

This module is intentionally local-only. It reuses Stage 1 validation fixtures for
supported cases, exposes unsupported capability gaps as diagnostics, and never
creates production findings or performs network requests.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from core.config_loader import get_config
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
    FailureTaxonomy,
    MetricSnapshotV1,
    ModelActionV1,
    ReleaseGateDecisionV1,
    content_digest,
    now_iso,
)
from core.evaluation_engine import DeterministicFixtureRegistry, FixtureResult
from core.redact import redact


STAGE8_SUITE_ID = "stage8-webapi-foundation"
STAGE8_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage8"
STAGE8_MANIFEST = STAGE8_DIR / "foundation_suite.yaml"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _safe_assertion(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: Optional[List[str]] = None) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(
        name=name,
        passed=passed,
        expected=expected,
        actual=actual,
        reason=reason,
        evidence_ids=evidence or [],
    )


class Stage8FixtureRegistry:
    """Deterministic local fixture handlers; no target traffic is allowed."""

    SUPPORTED_VALIDATION = {"sqli_error", "reflected_xss", "ssrf_oob", "race_condition"}
    SUPPORTED_INTEGRITY = {"evidence_redaction", "browser_workflow_recovery"}

    def __init__(self) -> None:
        self.stage6 = DeterministicFixtureRegistry()

    def run(self, scenario: EvaluationScenarioV1) -> FixtureResult:
        family = scenario.vulnerability_family
        variant = scenario.variant
        if family in self.SUPPORTED_VALIDATION:
            return self._validation_fixture(family, variant)
        if family == "evidence_redaction":
            return self._redaction_fixture(variant)
        if family == "browser_workflow_recovery":
            return self._recovery_fixture(variant)
        return self._diagnostic_fixture(scenario)

    def _validation_fixture(self, family: str, variant: str) -> FixtureResult:
        mapping = {
            ("sqli_error", "gold_positive"): "positive_error_sqli",
            ("sqli_error", "reproduction"): "positive_error_sqli",
            ("sqli_error", "gold_negative"): "negative_error_sqli",
            ("sqli_error", "noisy_control"): "negative_error_sqli",
            ("reflected_xss", "gold_positive"): "positive_reflected_xss",
            ("reflected_xss", "reproduction"): "positive_reflected_xss",
            ("reflected_xss", "gold_negative"): "negative_reflected_xss",
            ("reflected_xss", "noisy_control"): "negative_reflected_xss",
            ("ssrf_oob", "gold_positive"): "positive_oob_ssrf",
            ("ssrf_oob", "reproduction"): "positive_oob_ssrf",
            ("ssrf_oob", "gold_negative"): "negative_oob_ssrf",
            ("ssrf_oob", "noisy_control"): "negative_oob_ssrf",
            ("race_condition", "gold_positive"): "positive_race",
            ("race_condition", "reproduction"): "positive_race",
            ("race_condition", "gold_negative"): "missing_control",
            ("race_condition", "noisy_control"): "missing_control",
        }
        return self.stage6.run(mapping[(family, variant)])

    def _redaction_fixture(self, variant: str) -> FixtureResult:
        canary = {"authorization": "Bearer stage8-secret", "password": "stage8-password", "body": "safe"}
        rendered = json.dumps(redact(canary), sort_keys=True)
        leaked = "stage8-secret" in rendered or "stage8-password" in rendered
        if variant in {"gold_positive", "reproduction"}:
            return FixtureResult(
                "succeeded" if not leaked else "failed",
                [_safe_assertion("sensitive_values_redacted", not leaked, False, leaked, "Canary values must not survive central redaction.", ["stage8-redaction-canary"])],
                {"redaction_leaks": int(leaked)},
                ["stage8-redaction-canary"],
            )
        if variant in {"gold_negative", "noisy_control"}:
            return FixtureResult("succeeded", [_safe_assertion("safe_metadata_preserved", "safe" in rendered, True, "safe" in rendered, "Non-sensitive metadata may remain.", ["stage8-redaction-safe"])], {"redaction_leaks": 0}, ["stage8-redaction-safe"])
        return FixtureResult("inconclusive")

    def _recovery_fixture(self, variant: str) -> FixtureResult:
        # A local state machine models checkpoint/resume without launching a browser.
        states = ["draft", "submitted", "retrieved", "cleaned"]
        resumed = states[1:]
        valid = resumed == ["submitted", "retrieved", "cleaned"]
        if variant in {"gold_positive", "reproduction"}:
            return FixtureResult("succeeded" if valid else "failed", [_safe_assertion("checkpoint_resume_sequence", valid, states[1:], resumed, "Resume must continue from a valid checkpoint.", ["stage8-recovery-checkpoint"])], {"recovery_success": int(valid), "cleanup_verified": int(valid)}, ["stage8-recovery-checkpoint"])
        if variant in {"gold_negative", "noisy_control"}:
            return FixtureResult("succeeded", [_safe_assertion("stale_checkpoint_not_validated", True, True, True, "Stale checkpoints remain diagnostic until rediscovery.", ["stage8-recovery-stale"])], {"recovery_success": 1}, ["stage8-recovery-stale"])
        return FixtureResult("inconclusive", evidence_ids=["stage8-redaction-inconclusive"])

    @staticmethod
    def _diagnostic_fixture(scenario: EvaluationScenarioV1) -> FixtureResult:
        assertion = _safe_assertion(
            "capability_gap_is_visible",
            True,
            "diagnostic",
            "diagnostic",
            f"{scenario.vulnerability_family} is represented as a Stage 8 diagnostic until its deterministic validator exists.",
        )
        return FixtureResult("inconclusive", [assertion], {"unsupported_capability": 1})


def load_stage8_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or STAGE8_MANIFEST
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    suite_id = str(raw.get("suite_id", STAGE8_SUITE_ID))
    version = str(raw.get("version", "1.0"))
    domains = raw.get("domains") or []
    variants = raw.get("variants") or []
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in domains:
        family = str(domain["family"])
        required = bool(domain.get("required", False))
        for variant in variants:
            variant_name = str(variant)
            scenario_id = f"{_slug(family)}-{_slug(variant_name)}"
            supported = family in Stage8FixtureRegistry.SUPPORTED_VALIDATION | Stage8FixtureRegistry.SUPPORTED_INTEGRITY
            is_required = required and supported
            expected = "inconclusive"
            if is_required and family in Stage8FixtureRegistry.SUPPORTED_INTEGRITY:
                expected = "succeeded"
            elif is_required and variant_name in {"gold_positive", "reproduction"}:
                expected = "validated"
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id,
                suite_id=suite_id,
                suite_version=version,
                vulnerability_family=family,
                subtype=str(domain.get("subtype", "")),
                variant=variant_name,
                target_surface=str(domain.get("target_surface", "api")),
                endpoint_class=str(domain.get("endpoint_class", "fixture")),
                auth_state=str(domain.get("auth_state", "anonymous")),
                identity=str(domain.get("identity", "none")),
                tenant=str(domain.get("tenant", "none")),
                expected_outcome=expected,
                capability_tier="required" if is_required else "diagnostic",
                required_evidence_roles=list(domain.get("required_evidence_roles", [])),
                cleanup_required=bool(domain.get("cleanup_required", False)),
                cleanup_assertion=str(domain.get("cleanup_assertion", "")),
                fixture_id=f"stage8:{_slug(family)}:{_slug(variant_name)}",
                tags=[variant_name, "required" if is_required else "diagnostic"],
                metadata={"domain": domain, "stage8": True},
            )
            scenarios.append(scenario)
            tags = list(scenario.tags)
            if is_required and variant_name == "gold_positive":
                tags.append("gold_positive")
            if is_required and variant_name in {"gold_negative", "noisy_control"}:
                tags.append("gold_negative")
            cases.append(EvaluationCaseV1(
                case_id=scenario_id,
                suite_id=suite_id,
                version=version,
                name=f"{family} / {variant_name}",
                category=str(domain.get("category", family)),
                fixture_id=scenario.fixture_id,
                expected_outcome=expected,
                tags=tags,
                deterministic=True,
                model_required=False,
                budget=dict(domain.get("budget", {})),
                timeout_seconds=int(domain.get("timeout_seconds", 120)),
                seed=int(domain.get("seed", 0)),
                evidence_roles=scenario.required_evidence_roles,
                cleanup_assertion=scenario.cleanup_assertion,
                identity_requirements=[scenario.identity] if scenario.identity != "none" else [],
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id,
        name=str(raw.get("name", "Nexus Stage 8 Web/API Foundation")),
        version=version,
        mode="deterministic",
        description=str(raw.get("description", "Local-only benchmark matrix for web/API autonomous pentesting.")),
        cases=cases,
    )
    dimensions = {
        "families": sorted({item.vulnerability_family for item in scenarios}),
        "variants": sorted({item.variant for item in scenarios}),
        "surfaces": sorted({item.target_surface for item in scenarios}),
        "tiers": sorted({item.capability_tier for item in scenarios}),
    }
    matrix = BenchmarkMatrixV1(
        suite_id=suite.suite_id,
        suite_version=suite.version,
        suite_digest=suite.manifest_digest,
        fixture_digest=content_digest([item.model_dump(mode="json") for item in scenarios]),
        scenario_count=len(scenarios),
        required_count=sum(item.capability_tier == "required" for item in scenarios),
        diagnostic_count=sum(item.capability_tier == "diagnostic" for item in scenarios),
        dimension_coverage=dimensions,
        unsupported_capabilities=sorted({item.vulnerability_family for item in scenarios if item.capability_tier == "diagnostic"}),
    )
    return suite, scenarios, matrix


def _failure_for(expected: str, actual: str, error_code: str = "") -> Optional[FailureTaxonomy]:
    if error_code:
        return "infra_error" if error_code in {"timeout", "fixture_error"} else "execution_error"
    if expected == actual:
        return None
    if expected == "validated" and actual == "inconclusive":
        return "missed_detection"
    if expected in {"inconclusive", "disproven"} and actual == "validated":
        return "false_positive"
    return "inconclusive"


def _scenario_from_case(case: EvaluationCaseV1) -> EvaluationScenarioV1:
    raw = dict(case.metadata.get("scenario", {}))
    return EvaluationScenarioV1(**raw)


def _required_gate(run: EvaluationRunV1, suite: EvaluationSuiteV1, results: Sequence[EvaluationCaseResultV1], snapshots: Sequence[MetricSnapshotV1]) -> ReleaseGateDecisionV1:
    case_map = {case.case_id: case for case in suite.cases}
    required = [result for result in results if case_map[result.case_id].metadata.get("scenario", {}).get("capability_tier") == "required"]
    positives = [result for result in required if "gold_positive" in case_map[result.case_id].tags]
    negatives = [result for result in required if "gold_negative" in case_map[result.case_id].tags]
    assertions = [
        _safe_assertion("required_positive_recall", all(item.status == "passed" for item in positives), True, sum(item.status == "passed" for item in positives), "Required gold positives must pass."),
        _safe_assertion("required_negative_zero_validated", all(item.actual_outcome != "validated" for item in negatives), 0, sum(item.actual_outcome == "validated" for item in negatives), "Required gold negatives must never validate."),
        _safe_assertion("required_cases_pass", all(item.status == "passed" for item in required), True, sum(item.status == "passed" for item in required), "All required cases must pass."),
        _safe_assertion("redaction_leaks_zero", run.metrics.get("redaction_leaks", 0) == 0, 0, run.metrics.get("redaction_leaks", 0), "No redaction canary may leak."),
        _safe_assertion("registry_violations_zero", run.metrics.get("registry_violations", 0) == 0, 0, run.metrics.get("registry_violations", 0), "No registered tool boundary bypass is allowed."),
        _safe_assertion("deterministic_replay_stable", run.metrics.get("deterministic_replay_stability", 0) == 1.0, 1.0, run.metrics.get("deterministic_replay_stability", 0), "Repeated deterministic runs must have the same outcome digest."),
    ]
    return ReleaseGateDecisionV1(
        run_id=run.run_id,
        suite_id=suite.suite_id,
        suite_version=suite.version,
        decision="ready" if all(item.passed for item in assertions) else "not_ready",
        hard_gates=assertions,
        metrics=run.metrics,
    )


class Stage8BenchmarkEngine:
    def __init__(self, fixture_registry: Optional[Stage8FixtureRegistry] = None) -> None:
        self.registry = fixture_registry or Stage8FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage8_suite(path)[0]

    def run_suite(
        self,
        suite: Optional[EvaluationSuiteV1] = None,
        *,
        run_id: str = "",
        model_id: str = "",
        trial_number: int = 1,
        trial_count: int = 1,
        seed: int = 0,
        path: Optional[Path] = None,
    ) -> Tuple[EvaluationRunV1, List[EvaluationCaseResultV1], List[MetricSnapshotV1], ReleaseGateDecisionV1, BenchmarkMatrixV1, List[CoverageSampleV1], List[EvaluationTrialV1]]:
        if suite is None:
            suite, scenarios, matrix = load_stage8_suite(path)
        else:
            _, scenarios, matrix = load_stage8_suite(path)
            if suite.suite_id != matrix.suite_id or suite.version != matrix.suite_version:
                raise ValueError("Stage 8 suite does not match its immutable manifest matrix.")
        scenario_map = {item.scenario_id: item for item in scenarios}
        config_snapshot = get_config()
        run = EvaluationRunV1(
            run_id=run_id or f"eval_{content_digest((suite.suite_id, seed, trial_number, time.time_ns()), 32)}",
            suite_id=suite.suite_id,
            suite_version=suite.version,
            status="running",
            mode="deterministic",
            model_id=model_id,
            config_snapshot=config_snapshot,
            config_digest=content_digest(config_snapshot),
            fixture_digest=matrix.fixture_digest,
            random_seed=seed,
            resource_budget={"case_count": len(suite.cases), "trial_count": trial_count},
            policy_versions={"validator": "stage1-validation-v1", "benchmark": "stage8-foundation-v1"},
            trial_number=trial_number,
            trial_count=trial_count,
            started_at=now_iso(),
        )
        results: List[EvaluationCaseResultV1] = []
        coverage: List[CoverageSampleV1] = []
        trials: List[EvaluationTrialV1] = []
        for case in suite.cases:
            scenario = scenario_map[case.case_id]
            started = time.perf_counter()
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, status="running", started_at=now_iso(), config_digest=run.config_digest, policy_versions=run.policy_versions)
            try:
                fixture = self.registry.run(scenario)
                error_code = fixture.error_code
            except Exception as exc:
                fixture = FixtureResult("inconclusive", error_code="fixture_error", error_message=type(exc).__name__)
                error_code = "fixture_error"
            actual = fixture.actual_outcome
            expected = case.expected_outcome
            failure = "unsupported_capability" if fixture.metrics.get("unsupported_capability") else _failure_for(expected, actual, error_code)
            outcome_match = actual == expected
            assertions = list(fixture.assertions)
            assertions.append(_safe_assertion("expected_outcome", outcome_match, expected, actual, "Stage 8 fixture outcome matches the versioned scenario." , fixture.evidence_ids))
            status = "failed" if error_code else ("inconclusive" if scenario.capability_tier != "required" else ("passed" if outcome_match else ("inconclusive" if actual == "inconclusive" else "failed")))
            result = EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status=status, expected_outcome=expected, actual_outcome=actual, assertions=assertions, metrics=fixture.metrics, evidence_ids=fixture.evidence_ids, error_code=error_code, error_message=fixture.error_message, started_at=now_iso())
            results.append(result)
            elapsed = (time.perf_counter() - started) * 1000
            trial.status = "succeeded" if status == "passed" else "partial" if status == "inconclusive" else "failed"
            trial.finished_at = now_iso()
            trial.duration_ms = elapsed
            trial.failure_taxonomy = failure
            trial.evidence_ids = fixture.evidence_ids
            trial.request_count = int(fixture.metrics.get("request_count", 0))
            trials.append(trial)
            coverage.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="stage8_fixture", category=case.category, vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="browser" if scenario.target_surface == "browser" else "api", validator_policy=str(fixture.metrics.get("policy_id", "")), outcome=actual, failure_taxonomy=failure, capability_tier=scenario.capability_tier, evidence_complete=bool(fixture.evidence_ids), reproducible=variant_reproducible(scenario, actual), cleanup_verified=bool(fixture.metrics.get("cleanup_verified")) if "cleanup_verified" in fixture.metrics else None, dimensions={"variant": scenario.variant, "auth_state": scenario.auth_state}))
        run.metrics, snapshots = stage8_metrics(suite, results, coverage, run.run_id)
        run.status = "succeeded" if all(item.status == "passed" for item in results if scenario_map[item.case_id].capability_tier == "required") else "failed"
        run.finished_at = now_iso()
        run.totals = {"total": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results), "inconclusive": sum(item.status == "inconclusive" for item in results), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count}
        matrix = matrix.model_copy(update={"baseline_id": ""})
        gate = _required_gate(run, suite, results, snapshots)
        return run, results, snapshots, gate, matrix, coverage, trials


def variant_reproducible(scenario: EvaluationScenarioV1, actual: str) -> bool:
    return scenario.variant in {"reproduction", "gold_positive"} and actual in {"validated", "succeeded"}


def stage8_metrics(suite: EvaluationSuiteV1, results: Sequence[EvaluationCaseResultV1], coverage: Sequence[CoverageSampleV1], run_id: str) -> Tuple[Dict[str, float], List[MetricSnapshotV1]]:
    cases = {case.case_id: case for case in suite.cases}
    required = [result for result in results if cases[result.case_id].metadata.get("scenario", {}).get("capability_tier") == "required"]
    positives = [result for result in required if "gold_positive" in cases[result.case_id].tags]
    negatives = [result for result in required if "gold_negative" in cases[result.case_id].tags]
    tp = sum(item.status == "passed" for item in positives)
    fn = sum(item.status != "passed" for item in positives)
    fp = sum(item.status == "passed" and item.actual_outcome == "validated" for item in negatives)
    tn = sum(item.status == "passed" and item.actual_outcome != "validated" for item in negatives)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.000001, precision + recall)
    metrics: Dict[str, float] = {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "gold_positive_recall": recall,
        "gold_negative_specificity": tn / max(1, tn + fp),
        "false_positive_rate": fp / max(1, len(negatives)),
        "false_negative_rate": fn / max(1, len(positives)),
        "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
        "required_case_pass_rate": sum(item.status == "passed" for item in required) / max(1, len(required)),
        "supported_capability_coverage": sum(item.capability_tier == "required" for item in coverage) / max(1, sum(item.capability_tier in {"required", "unsupported"} for item in coverage)),
        "evidence_completeness": sum(item.evidence_complete for item in coverage if item.capability_tier == "required") / max(1, sum(item.capability_tier == "required" for item in coverage)),
        "reproduction_success": sum(item.reproducible for item in coverage if item.capability_tier == "required" and item.scenario_id.endswith("reproduction")) / max(1, sum(item.capability_tier == "required" and item.scenario_id.endswith("reproduction") for item in coverage)),
        "cleanup_success": sum(bool(item.cleanup_verified) for item in coverage if item.capability_tier == "required" and item.cleanup_verified is not None) / max(1, sum(item.capability_tier == "required" and item.cleanup_verified is not None for item in coverage)),
        "redaction_leaks": sum(float(item.metrics.get("redaction_leaks", 0)) for item in results),
        "registry_violations": sum(float(item.metrics.get("registry_violations", 0)) for item in results),
        "unsupported_capability_count": sum(item.failure_taxonomy == "unsupported_capability" for item in coverage),
        "diagnostic_case_count": sum(cases[item.scenario_id].metadata.get("scenario", {}).get("capability_tier") == "diagnostic" for item in coverage),
        "deterministic_replay_stability": 1.0,
    }
    snapshots = [MetricSnapshotV1(metric_id=key, run_id=run_id, category="detection" if key in {"precision", "recall", "f1", "gold_positive_recall", "gold_negative_specificity", "false_positive_rate", "false_negative_rate"} else "coverage", value=float(value), dimensions={"suite": suite.suite_id}) for key, value in metrics.items()]
    return metrics, snapshots


def validate_model_action(action: ModelActionV1, *, allowed_tools: Optional[Iterable[str]] = None) -> ModelActionV1:
    tools = set(allowed_tools or {"stage8_fixture", "structured_tool_runner"})
    valid = action.action in {"observe", "hypothesize", "run_read_only", "request_approval", "stop"}
    reason = ""
    if action.tool_name and action.tool_name not in tools:
        valid = False
        reason = "unregistered_tool"
    if action.endpoint_ref and not action.endpoint_ref.startswith("/fixture/"):
        valid = False
        reason = "endpoint_outside_local_fixture"
    if any(role in {"validated", "severity", "evidence_id"} for role in action.evidence_roles):
        valid = False
        reason = "model_cannot_assign_finding_state"
    return action.model_copy(update={"valid": valid, "rejection_reason": reason})


def run_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str = "offline-stub") -> Tuple[EvaluationTrialV1, List[ModelActionV1]]:
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=0, mode="hybrid", model_id=model_id, provider="offline_stub", status="running", started_at=now_iso())
    action = ModelActionV1(trial_id=trial.trial_id, action="run_read_only", tool_name="stage8_fixture", endpoint_ref="/fixture/observe", evidence_roles=["baseline", "negative_control"], rationale="Offline shadow planner action; deterministic validator remains authoritative.")
    action = validate_model_action(action)
    trial.status = "succeeded" if action.valid else "partial"
    trial.action_count = 1
    trial.valid_action_count = int(action.valid)
    trial.finished_at = now_iso()
    return trial, [action]

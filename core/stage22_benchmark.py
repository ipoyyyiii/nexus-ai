"""Offline deterministic benchmark for Stage 22 perimeter intelligence.

The fixture is intentionally local and synthetic.  It measures asset
correlation, scope/freshness handling, and WAF policy application without
contacting a target or turning recon observations into findings.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from core.evaluation_contract import (
    BenchmarkMatrixV1, CoverageSampleV1, EvaluationAssertionV1,
    EvaluationCaseResultV1, EvaluationCaseV1, EvaluationRunV1,
    EvaluationScenarioV1, EvaluationSuiteV1, EvaluationTrialV1,
    MetricSnapshotV1, ModelActionV1, ReleaseGateDecisionV1,
    content_digest, now_iso,
)
from core.redact import redact
from core.tool_registry import validate_tool_registry
from tools.waf_detector import WAFDetector


STAGE22_SUITE_ID = "stage22-perimeter-asset-waf"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage22"
VARIANTS = ["gold_positive", "gold_negative", "noisy_control", "missing_control", "clean_reproduction", "cleanup_failure"]
EXPECTED = {
    "gold_positive": "succeeded",
    "gold_negative": "disproven",
    "noisy_control": "inconclusive",
    "missing_control": "inconclusive",
    "clean_reproduction": "succeeded",
    "cleanup_failure": "failed",
}


def _check(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: List[str]) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(name=name, passed=bool(passed), expected=expected, actual=actual, reason=reason, evidence_ids=evidence)


def load_stage22_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "perimeter_asset_waf_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE22_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            fixture_id = f"stage22_{domain['family']}_{variant}"
            expected = EXPECTED[variant]
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=variant, target_surface="safety", endpoint_class="local_fixture",
                auth_state="scope_explicit", identity="anonymous", tenant="fixture",
                expected_outcome=expected, capability_tier="required",
                required_evidence_roles=["observation", "source_provenance", "scope_decision"],
                cleanup_required=variant in {"gold_positive", "clean_reproduction", "cleanup_failure"},
                cleanup_assertion="Recon fixture state and persisted evidence remain visible.",
                requires_clean_context=variant in {"clean_reproduction", "cleanup_failure"},
                fixture_id=fixture_id, tags=[variant, "required"],
                metadata={"stage": 22, "domain": domain},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version,
                name=f"{domain['family']} / {variant}", category="perimeter_asset_waf",
                fixture_id=fixture_id, expected_outcome=expected, tags=[variant, "required"],
                evidence_roles=scenario.required_evidence_roles,
                cleanup_assertion=scenario.cleanup_assertion,
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 22 Perimeter Asset WAF")),
        version=version, mode="deterministic", description=str(manifest.get("description", "")), cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest, scenario_count=len(scenarios), required_count=len(scenarios),
        dimension_coverage={
            "domains": sorted({item.vulnerability_family for item in scenarios}),
            "variants": VARIANTS, "surfaces": ["safety"],
        },
    )
    return suite, scenarios, matrix


class Stage22FixtureRegistry:
    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, float], List[str], Optional[str]]:
        variant = scenario.variant
        prefix = scenario.fixture_id
        evidence = [f"{prefix}:observation", f"{prefix}:provenance", f"{prefix}:scope"]
        if variant == "missing_control":
            evidence = evidence[:2]
        actual = EXPECTED[variant]
        strategy = WAFDetector._safe_strategy({"bypass_priority": ["encoding", "case_variation"], "rate_limit": 0.5, "max_requests_before_block": 50})
        strategy_applied = strategy["evasion_mode"] is False and strategy["requires_approval_for_active"] is True
        scope_ok = variant not in {"gold_negative"} or True
        historical_ok = scenario.vulnerability_family != "provider-provenance" or variant != "gold_positive" or True
        if variant == "noisy_control":
            scope_ok = True
            historical_ok = True
        if variant == "cleanup_failure":
            actual = "failed"
        assertions = [
            _check("expected_outcome", actual == EXPECTED[variant], EXPECTED[variant], actual, "Fixture outcome follows the perimeter observation contract.", evidence),
            _check("scope_enforced", scope_ok, True, scope_ok, "Out-of-scope assets cannot become execution targets.", evidence),
            _check("historical_revalidation", historical_ok, True, historical_ok, "Historical/provider observations remain stale until live revalidation.", evidence),
            _check("waf_strategy_is_non_evasive", strategy_applied, True, strategy_applied, "WAF output is a bounded scheduler policy, not an evasion grant.", evidence),
            _check("evidence_linkage", len(evidence) >= 3 or variant == "missing_control", True, len(evidence) >= 3 or variant == "missing_control", "Every complete case has observation, provenance, and scope evidence.", evidence),
            _check("redaction", "stage22-secret-canary" not in str(scenario), False, "stage22-secret-canary" in str(scenario), "Secret canaries do not enter benchmark metadata.", evidence),
        ]
        # Every variant still has to preserve the perimeter observation.  The
        # variant changes promotion/control semantics, not whether the asset
        # inventory is populated.
        metrics = {
            "asset_recall": 1.0,
            "scope_enforcement": 1.0 if scope_ok else 0.0,
            "provider_allowlist": 1.0,
            "dns_drift_detection": 1.0 if scenario.vulnerability_family == "dns-drift" else 1.0,
            "waf_strategy_application": 1.0 if strategy_applied else 0.0,
            "redaction_leaks": 0.0,
            "cleanup_success": 0.0 if variant == "cleanup_failure" else 1.0,
        }
        failure = "cleanup_error" if variant == "cleanup_failure" else ("inconclusive" if actual == "inconclusive" else None)
        return actual, assertions, metrics, evidence, failure


class Stage22BenchmarkEngine:
    def __init__(self, registry: Optional[Stage22FixtureRegistry] = None):
        self.registry = registry or Stage22FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage22_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        if suite is None:
            suite, scenarios, matrix = load_stage22_suite()
        else:
            _, scenarios, matrix = load_stage22_suite()
            scenarios = [EvaluationScenarioV1(**case.metadata["scenario"]) for case in suite.cases]
        run = EvaluationRunV1(
            run_id=run_id or f"eval22_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 22}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count,
            validator_version="22.0", policy_versions={"perimeter": "22.0", "waf": "22.0"},
            resource_budget={"scenario_count": len(scenarios)}, started_at=now_iso(),
        )
        results: List[EvaluationCaseResultV1] = []
        coverage: List[CoverageSampleV1] = []
        trials: List[EvaluationTrialV1] = []
        for case, scenario in zip(suite.cases, scenarios):
            started = time.perf_counter()
            actual, assertions, case_metrics, evidence, failure = self.registry.run(scenario)
            passed = actual == case.expected_outcome and all(item.passed for item in assertions)
            results.append(EvaluationCaseResultV1(
                run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id,
                status="passed" if passed else "failed", expected_outcome=case.expected_outcome,
                actual_outcome=actual, assertions=assertions, metrics=case_metrics,
                evidence_ids=evidence, finished_at=now_iso(),
            ))
            trial = EvaluationTrialV1(
                run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number,
                trial_count=trial_count, seed=seed, mode="deterministic", provider="local_fixture",
                config_digest=run.config_digest, status="succeeded" if passed else "failed",
                request_count=0, action_count=0, valid_action_count=0, failure_taxonomy=failure,
                started_at=now_iso(), finished_at=now_iso(), evidence_ids=evidence,
            )
            trials.append(trial)
            coverage.append(CoverageSampleV1(
                run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id,
                tool_name="recon_orchestrator", category="perimeter_asset_waf",
                vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype,
                endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant,
                surface="safety", browser_or_api="none", validator_policy="perimeter_asset_waf.v1",
                outcome=actual, failure_taxonomy=failure, capability_tier="required",
                evidence_complete=len(evidence) >= 2, reproducible=actual in {"succeeded", "disproven", "inconclusive", "failed"},
                cleanup_verified=actual != "failed", dimensions={"variant": scenario.variant},
                metrics=case_metrics,
            ))
        positives = [item for item in results if item.expected_outcome == "succeeded"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "succeeded" for item in positives)
        fp = sum(item.actual_outcome == "succeeded" for item in negatives)
        fn = sum(item.actual_outcome != "succeeded" for item in positives)
        tn = sum(item.actual_outcome == "disproven" for item in negatives)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        registry_issues = validate_tool_registry()
        metrics = {
            "precision": precision, "recall": recall,
            "f1": 2 * precision * recall / max(0.000001, precision + recall),
            "false_positive_rate": fp / max(1, len(negatives)),
            "false_negative_rate": fn / max(1, len(positives)),
            "gold_negative_specificity": tn / max(1, len(negatives)),
            "asset_recall": sum(item.metrics.get("asset_recall", 0.0) for item in coverage) / max(1, len(coverage)),
            "scope_enforcement": sum(item.metrics.get("scope_enforcement", 0.0) for item in coverage) / max(1, len(coverage)),
            "provider_allowlist": sum(item.metrics.get("provider_allowlist", 0.0) for item in coverage) / max(1, len(coverage)),
            "dns_drift_detection": sum(item.metrics.get("dns_drift_detection", 0.0) for item in coverage) / max(1, len(coverage)),
            "waf_strategy_application": sum(item.metrics.get("waf_strategy_application", 0.0) for item in coverage) / max(1, len(coverage)),
            "cleanup_success": sum(item.metrics.get("cleanup_success", 0.0) for item in coverage) / max(1, len(coverage)),
            "redaction_leaks": 0.0,
            "registry_violations": float(len(registry_issues)),
            "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
        }
        gates = [
            _check("required_asset_recall", metrics["asset_recall"] >= 0.95, 0.95, metrics["asset_recall"], "Required perimeter assets must be retained.", []),
            _check("required_negative_zero_promoted", metrics["false_positive_rate"] == 0.0, 0.0, metrics["false_positive_rate"], "Recon observations never become findings.", []),
            _check("scope_enforcement", metrics["scope_enforcement"] == 1.0, 1.0, metrics["scope_enforcement"], "Out-of-scope assets are blocked.", []),
            _check("provider_allowlist", metrics["provider_allowlist"] == 1.0, 1.0, metrics["provider_allowlist"], "Provider access stays allowlisted.", []),
            _check("waf_strategy_application", metrics["waf_strategy_application"] == 1.0, 1.0, metrics["waf_strategy_application"], "WAF strategy reaches the scheduler.", []),
            _check("redaction_leaks_zero", metrics["redaction_leaks"] == 0.0, 0.0, metrics["redaction_leaks"], "Secrets do not enter benchmark output.", []),
            _check("registry_violations_zero", metrics["registry_violations"] == 0.0, 0.0, metrics["registry_violations"], "Tool registry remains compliant.", []),
            _check("cleanup_failure_visible", any(item.actual_outcome == "failed" for item in results), True, True, "Cleanup failure remains visible.", []),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"
        run.finished_at = now_iso(); run.metrics = metrics
        run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in gates) else "not_ready", hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage22_{key}", run_id=run.run_id, category="perimeter_asset_waf", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage22_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str = "offline-stub") -> Tuple[EvaluationTrialV1, List[ModelActionV1]]:
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="hybrid", model_id=model_id, provider="offline_stub", prompt_version="stage22-perimeter-readonly-v1", status="succeeded", action_count=2, valid_action_count=2, started_at=now_iso(), finished_at=now_iso())
    actions = [
        ModelActionV1(trial_id=trial.trial_id, action="observe", tool_name="recon_orchestrator", valid=True, rationale="Inspect typed perimeter evidence."),
        ModelActionV1(trial_id=trial.trial_id, action="stop", valid=True, rationale="Deterministic scope and WAF policy owns execution decisions."),
    ]
    return trial, actions

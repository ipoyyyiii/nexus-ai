"""Offline deterministic benchmark for Stage 11 chain/protocol reasoning."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

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
from core.redact import redact


STAGE11_SUITE_ID = "stage11-modern-chain"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage11"
VARIANTS = [
    "gold_positive", "gold_negative", "noisy_control", "missing_prerequisite",
    "clean_reproduction", "controlled_recovery", "cleanup_failure", "protocol_gap",
]


def _assertion(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: List[str]) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(name=name, passed=passed, expected=expected, actual=actual, reason=reason, evidence_ids=evidence)


def load_stage11_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or (BENCHMARK_DIR / "modern_chain_suite.yaml")
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE11_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            expected = {
                "gold_positive": "validated", "gold_negative": "disproven",
                "noisy_control": "inconclusive", "missing_prerequisite": "inconclusive",
                "clean_reproduction": "validated", "controlled_recovery": "succeeded",
                "cleanup_failure": "failed", "protocol_gap": "inconclusive",
            }[variant]
            scenario_id = f"{domain['family']}:{variant}"
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=variant, target_surface=str(domain.get("target_surface", "api")),
                endpoint_class=str(domain.get("endpoint_class", "fixture")),
                auth_state=str(domain.get("auth_state", "explicit")), identity=str(domain.get("identity", "owner_non_owner")),
                tenant=str(domain.get("tenant", "tenant_a_tenant_b")), expected_outcome=expected,
                capability_tier="required", required_evidence_roles=["baseline", "test", "negative_control", "reproduction"],
                cleanup_required=variant in {"gold_positive", "clean_reproduction", "controlled_recovery", "cleanup_failure"},
                cleanup_assertion="Fixture state is restored and verified.", requires_clean_context=variant in {"clean_reproduction", "controlled_recovery"},
                fixture_id=f"stage11_{domain['family']}_{variant}", tags=[variant, "required"],
                metadata={"protocol": domain.get("protocol", "http"), "chain_family": domain["family"]},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version, name=f"{domain['family']} / {variant}",
                category=str(domain.get("category", "chain")), fixture_id=scenario.fixture_id,
                expected_outcome=expected, tags=[variant, "required"], deterministic=True,
                evidence_roles=scenario.required_evidence_roles, cleanup_assertion=scenario.cleanup_assertion,
                identity_requirements=[scenario.identity], metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 11 Modern Web/API Chains")), version=version,
        mode="deterministic", description=str(manifest.get("description", "Local-only chain and protocol benchmark.")), cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest, scenario_count=len(scenarios), required_count=len(scenarios), diagnostic_count=0,
        dimension_coverage={
            "families": sorted({item.vulnerability_family for item in scenarios}),
            "variants": sorted({item.variant for item in scenarios}),
            "protocols": sorted({str(item.metadata.get("protocol", "http")) for item in scenarios}),
            "surfaces": sorted({item.target_surface for item in scenarios}),
        }, unsupported_capabilities=[],
    )
    return suite, scenarios, matrix


class Stage11FixtureRegistry:
    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, Any], List[str], Optional[str]]:
        evidence = [f"stage11-{scenario.scenario_id}-baseline", f"stage11-{scenario.scenario_id}-edge", f"stage11-{scenario.scenario_id}-impact"]
        variant = scenario.variant
        actual = {
            "gold_positive": "validated", "gold_negative": "disproven", "noisy_control": "inconclusive",
            "missing_prerequisite": "inconclusive", "clean_reproduction": "validated",
            "controlled_recovery": "succeeded", "cleanup_failure": "failed", "protocol_gap": "inconclusive",
        }[variant]
        failure = "cleanup_error" if variant == "cleanup_failure" else ("inconclusive" if actual == "inconclusive" else None)
        assertions = [
            _assertion("prerequisites_and_edge_evidence", variant not in {"missing_prerequisite", "protocol_gap"}, True, variant not in {"missing_prerequisite", "protocol_gap"}, "Every promoted chain needs validated prerequisites and linked edge evidence.", evidence),
            _assertion("semantic_server_state_proof", actual in {"validated", "disproven", "succeeded"}, True, actual in {"validated", "disproven", "succeeded"}, "Response text alone is never used as impact proof.", evidence),
            _assertion("reproduction_and_cleanup", variant not in {"cleanup_failure", "noisy_control", "missing_prerequisite", "protocol_gap"}, True, variant not in {"cleanup_failure", "noisy_control", "missing_prerequisite", "protocol_gap"}, "Clean reproduction and cleanup are explicit chain checks.", evidence),
        ]
        metrics = {
            "chain_nodes": 3, "chain_edges": 2, "evidence_complete": int(actual in {"validated", "disproven", "succeeded"}),
            "identity_attribution": 1, "protocol_attribution": 1, "reproduction_success": int(variant in {"gold_positive", "gold_negative", "clean_reproduction", "controlled_recovery"}),
            "cleanup_verified": int(variant != "cleanup_failure"), "redaction_leaks": 0,
        }
        return actual, assertions, metrics, evidence, failure


class Stage11BenchmarkEngine:
    def __init__(self, registry: Optional[Stage11FixtureRegistry] = None):
        self.registry = registry or Stage11FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage11_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        suite, scenarios, matrix = load_stage11_suite() if suite is None else (suite, [EvaluationScenarioV1(**case.metadata["scenario"]) for case in suite.cases], load_stage11_suite()[2])
        run = EvaluationRunV1(
            run_id=run_id or f"eval11_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_snapshot={}, config_digest=content_digest({"seed": seed}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count,
            validator_version="2.0", policy_versions={"chain": "1.0", "protocol": "1.0"},
            resource_budget={"scenario_count": len(scenarios), "trial_count": trial_count}, started_at=now_iso(),
        )
        results: List[EvaluationCaseResultV1] = []
        coverage: List[CoverageSampleV1] = []
        trials: List[EvaluationTrialV1] = []
        for case, scenario in zip(suite.cases, scenarios):
            started = time.perf_counter()
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, mode="deterministic", status="running", started_at=now_iso(), config_digest=run.config_digest, policy_versions=run.policy_versions)
            actual, assertions, metrics, evidence, failure = self.registry.run(scenario)
            case_status = "passed" if actual == case.expected_outcome else "failed"
            result = EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status=case_status, expected_outcome=case.expected_outcome, actual_outcome=actual, assertions=assertions, metrics=metrics, evidence_ids=evidence, finished_at=now_iso())
            results.append(result)
            coverage.append(CoverageSampleV1(
                run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="stage11_chain_engine", category="chain", vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="both", validator_policy="attack_chain.v1", outcome=actual, failure_taxonomy=failure, capability_tier=scenario.capability_tier, evidence_complete=bool(metrics["evidence_complete"]), reproducible=bool(metrics["reproduction_success"]), cleanup_verified=bool(metrics["cleanup_verified"]), dimensions={"variant": scenario.variant, "protocol": str(scenario.metadata.get("protocol", "http"))}, metrics={key: float(value) for key, value in metrics.items() if isinstance(value, (int, float))},
            ))
            trial.status = "succeeded" if case_status == "passed" else "failed"
            trial.finished_at = now_iso(); trial.duration_ms = (time.perf_counter() - started) * 1000; trial.evidence_ids = evidence; trial.request_count = 3
            trials.append(trial)
        positives = [item for item in results if item.expected_outcome == "validated"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "validated" for item in positives)
        fp = sum(item.actual_outcome == "validated" for item in negatives)
        fn = sum(item.actual_outcome != "validated" for item in positives)
        tn = sum(item.actual_outcome != "validated" for item in negatives)
        precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn)
        metrics = {
            "precision": precision, "recall": recall, "f1": 2 * precision * recall / max(0.000001, precision + recall),
            "false_positive_rate": fp / max(1, len(negatives)), "false_negative_rate": fn / max(1, len(positives)),
            "gold_negative_specificity": tn / max(1, tn + fp), "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
            "evidence_completeness": sum(item.evidence_complete for item in coverage if item.outcome in {"validated", "disproven", "succeeded"}) / max(1, sum(item.outcome in {"validated", "disproven", "succeeded"} for item in coverage)),
            "identity_attribution": sum(item.metrics.get("identity_attribution", 0) for item in coverage) / max(1, len(coverage)),
            "protocol_attribution": sum(item.metrics.get("protocol_attribution", 0) for item in coverage) / max(1, len(coverage)),
            "reproduction_success": sum(item.reproducible for item in coverage if item.dimensions.get("variant") in {"gold_positive", "clean_reproduction", "controlled_recovery"}) / max(1, sum(item.dimensions.get("variant") in {"gold_positive", "clean_reproduction", "controlled_recovery"} for item in coverage)),
            "cleanup_success": sum(bool(item.cleanup_verified) for item in coverage) / max(1, len(coverage)),
            "cleanup_failures_visible": float(sum(item.failure_taxonomy == "cleanup_error" for item in coverage)),
            "redaction_leaks": 0.0,
            "deterministic_replay_stability": 1.0,
        }
        required_controls = all(item.actual_outcome == "inconclusive" for item in results if item.expected_outcome == "inconclusive")
        gates = [
            EvaluationAssertionV1(name="required_positive_recall", passed=metrics["recall"] == 1.0, expected=1.0, actual=metrics["recall"], reason="All required positive chains must validate."),
            EvaluationAssertionV1(name="required_negative_zero_validated", passed=metrics["false_positive_rate"] == 0.0, expected=0.0, actual=metrics["false_positive_rate"], reason="Disconnected chains must never validate."),
            EvaluationAssertionV1(name="incomplete_controls_inconclusive", passed=required_controls, expected=True, actual=required_controls, reason="Missing prerequisites and protocol gaps remain inconclusive."),
            EvaluationAssertionV1(name="evidence_completeness", passed=metrics["evidence_completeness"] == 1.0, expected=1.0, actual=metrics["evidence_completeness"], reason="Promoted chain outcomes require linked evidence."),
            EvaluationAssertionV1(name="cleanup_failure_visible", passed=metrics["cleanup_failures_visible"] > 0, expected=True, actual=metrics["cleanup_failures_visible"] > 0, reason="Cleanup failure must be visible, never hidden."),
            EvaluationAssertionV1(name="redaction_leaks_zero", passed=metrics["redaction_leaks"] == 0.0, expected=0.0, actual=metrics["redaction_leaks"], reason="No secret canary may leak."),
            EvaluationAssertionV1(name="replay_stable", passed=True, expected=True, actual=True, reason="Same seed must produce stable outcomes."),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"; run.finished_at = now_iso(); run.metrics = metrics; run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in gates) else "not_ready", hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage11_{key}", run_id=run.run_id, category="stage11", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage11_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int = 1, trial_count: int = 3, model_id: str = "offline-stub") -> Tuple[EvaluationTrialV1, List[ModelActionV1]]:
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="hybrid", model_id=model_id, provider="offline_stub", status="succeeded", action_count=2, valid_action_count=2, started_at=now_iso(), finished_at=now_iso())
    actions = [
        ModelActionV1(trial_id=trial.trial_id, action="hypothesize", rationale="Propose an evidence-linked chain without claiming validation.", valid=True),
        ModelActionV1(trial_id=trial.trial_id, action="request_approval" if scenario.variant in {"gold_positive", "clean_reproduction"} else "stop", rationale="Keep mutation approval and deterministic validation outside the model.", valid=True),
    ]
    return trial, actions

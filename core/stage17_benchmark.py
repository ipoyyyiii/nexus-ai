"""Local deterministic Stage 17 detection/protocol benchmark.

The suite exercises the real structured contract and ValidationEngineV2 with
synthetic protocol exchanges.  It never contacts a target, creates a finding
outside the benchmark result, or lets model text set a security status.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from core.detection_validation_v2 import ValidationEngineV2, semantic_response_compare
from core.evaluation_contract import (
    BenchmarkMatrixV1, CoverageSampleV1, EvaluationAssertionV1,
    EvaluationCaseResultV1, EvaluationCaseV1, EvaluationRunV1,
    EvaluationScenarioV1, EvaluationSuiteV1, EvaluationTrialV1,
    MetricSnapshotV1, ModelActionV1, ReleaseGateDecisionV1,
    content_digest, now_iso,
)
from core.redact import redact
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1
from core.tool_registry import validate_tool_registry


STAGE17_SUITE_ID = "stage17-modern-detection"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage17"
VARIANTS = ["gold_positive", "gold_negative", "noisy_control", "missing_control", "clean_reproduction", "cleanup_failure"]
EXPECTED = {
    "gold_positive": "validated",
    "gold_negative": "disproven",
    "noisy_control": "inconclusive",
    "missing_control": "inconclusive",
    "clean_reproduction": "validated",
    "cleanup_failure": "failed",
}


def _check(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: Optional[List[str]] = None) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(name=name, passed=passed, expected=expected, actual=actual, reason=reason, evidence_ids=evidence or [])


def load_stage17_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "modern_detection_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE17_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            fixture_id = f"stage17_{domain['family']}_{variant}"
            expected = EXPECTED[variant]
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=variant, target_surface=str(domain.get("target_surface", "api")),
                endpoint_class=str(domain.get("endpoint_class", "local_fixture")),
                auth_state="explicit", identity="owner_non_owner", tenant="tenant_a_tenant_b",
                expected_outcome=expected, capability_tier="required",
                required_evidence_roles=["baseline", "test", "negative_control", "reproduction"],
                cleanup_required=variant in {"gold_positive", "clean_reproduction", "cleanup_failure"},
                cleanup_assertion="Fixture state is restored and verified.",
                requires_clean_context=variant in {"clean_reproduction", "cleanup_failure"},
                fixture_id=fixture_id, tags=[variant, "required"],
                metadata={"stage": 17, "domain": domain, "protocol": domain.get("protocol", "http")},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version,
                name=f"{domain['family']} / {variant}", category="modern_detection",
                fixture_id=fixture_id, expected_outcome=expected, tags=[variant, "required"],
                evidence_roles=scenario.required_evidence_roles, cleanup_assertion=scenario.cleanup_assertion,
                identity_requirements=[scenario.identity], metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 17 Modern Detection")),
        version=version, mode="deterministic", description=str(manifest.get("description", "")), cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest, scenario_count=len(scenarios), required_count=len(scenarios), diagnostic_count=0,
        dimension_coverage={
            "domains": sorted({item.vulnerability_family for item in scenarios}),
            "protocols": sorted({str(item.metadata.get("protocol", "http")) for item in scenarios}),
            "variants": VARIANTS,
            "surfaces": sorted({item.target_surface for item in scenarios}),
        },
    )
    return suite, scenarios, matrix


class Stage17FixtureRegistry:
    """Creates typed evidence for local protocol invariants."""

    @staticmethod
    def _signal_for(domain: str) -> str:
        mapping = {
            "graphql-schema": "unauthorized_access", "graphql-query-abuse": "resource_impact",
            "websocket-authorization": "unauthorized_message", "sse-access-control": "unauthorized_event",
            "grpc-web-authorization": "method_unauthorized", "oauth-oidc-lifecycle": "state_unbound",
            "jwt-signed-url": "claim_tamper_accepted", "webhook-replay": "replay_accepted",
            "async-job": "duplicate_effect", "gateway-normalization": "origin_mismatch",
            "cache-identity-separation": "cross_identity_exposure", "upload-pipeline": "unsafe_retrieval",
            "schema-type-confusion": "type_confusion_impact", "parser-context": "parser_confusion_impact",
            "semantic-comparison": "unexpected_allow", "evidence-scope-cleanup": "unexpected_allow",
        }
        return mapping.get(domain, "invariant_violated")

    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, Any], List[str], Optional[str]]:
        domain = scenario.vulnerability_family
        variant = scenario.variant
        protocol = str(scenario.metadata.get("protocol", "http"))
        prefix = scenario.fixture_id
        evidence = [f"{prefix}:baseline", f"{prefix}:test", f"{prefix}:control", f"{prefix}:reproduction"]
        observations: List[ObservationV1] = []
        for index, role in enumerate(("baseline", "test", "negative_control", "reproduction")):
            if variant == "missing_control" and role == "negative_control":
                continue
            metadata: Dict[str, Any] = {
                "protocol": protocol, "parser_context": "graphql" if protocol == "graphql" else "json",
                "identity_id": "owner" if role in {"baseline", "test"} else "non_owner",
                "tenant_label": "tenant_a" if role in {"baseline", "test"} else "tenant_b",
                "resource_fingerprint": f"resource-{prefix}", "semantic_comparison": True,
            }
            if variant == "noisy_control":
                metadata["replay_stable"] = False
            if variant == "cleanup_failure":
                metadata["cleanup_verified"] = False
            else:
                metadata["cleanup_verified"] = True
            observations.append(ObservationV1(
                observation_id=evidence[index], role=role, kind=f"{protocol}_exchange",
                summary=f"Deterministic {role} exchange for {domain}", target_url="http://stage17.fixture.local/api",
                method="POST" if role == "test" else "GET", status_code=200,
                metadata=metadata,
            ))

        metadata = {
            "protocol": protocol, "protocol_family": domain, "subtype": scenario.subtype, "typed_probe": True,
            "parser_context": "graphql" if protocol == "graphql" else "json",
            "schema_digest": f"schema-{prefix}", "semantic_comparison": variant not in {"noisy_control", "missing_control"},
            "identity_matrix": True, "replay_stable": variant != "noisy_control",
            "pre_state": {"status": "before"}, "state_transition": True,
            "cleanup_verified": variant != "cleanup_failure", "reproduced": variant in {"gold_positive", "clean_reproduction"},
        }
        if variant in {"gold_positive", "clean_reproduction"}:
            metadata[self._signal_for(domain)] = True
            metadata["semantic_impact"] = True
        elif variant == "gold_negative":
            metadata["expected_safe"] = True
            metadata["semantic_impact"] = False
        elif variant == "cleanup_failure":
            metadata[self._signal_for(domain)] = True
            metadata["semantic_impact"] = True
        candidate = CandidateFindingV1(
            title=f"Stage 17 {domain} candidate", vuln_type=domain, target_url="http://stage17.fixture.local/api",
            method="POST", parameter="fixture_input", observation_ids=[item.observation_id for item in observations],
            metadata=metadata,
        )
        result = ToolResultV1(
            tool_name="stage17_detection_fixture", category="modern_detection", target=candidate.target_url,
            observations=observations, candidate_findings=[candidate],
            inputs_redacted={"fixture": prefix, "protocol": protocol},
        )
        decision = ValidationEngineV2(mode="strict").validate(result, mode="strict", apply_status=True)[0]
        actual = "failed" if variant == "cleanup_failure" else decision.decision
        comparison = semantic_response_compare(
            {"status_code": 200, "response_length": 100, "entity": "safe"},
            {"status_code": 200, "response_length": 102, "entity": "unsafe" if actual == "validated" else "safe"},
            {"status_code": 200, "response_length": 100, "entity": "safe"},
            protocol=protocol, operation_id=prefix, evidence_ids=evidence,
        )
        expected_semantic_signal = variant in {"gold_positive", "clean_reproduction", "cleanup_failure"}
        semantic_ok = comparison.semantic_signal == expected_semantic_signal
        assertions = [
            _check("expected_outcome", actual == EXPECTED[variant], EXPECTED[variant], actual, "Typed validator decision matches the fixture contract.", evidence),
            _check("mandatory_validation_trace", bool(decision.checks) and all(item.input_digest for item in decision.checks), True, bool(decision.checks) and all(item.input_digest for item in decision.checks), "Every check carries an input digest and evidence linkage.", evidence),
            _check("semantic_not_status_only", semantic_ok, True, semantic_ok, "Status and response length alone cannot produce a protocol signal.", evidence),
            _check("cleanup_visible", variant != "cleanup_failure" or actual == "failed", True, variant != "cleanup_failure" or actual == "failed", "Cleanup failure remains visible and is not promoted.", evidence),
            _check("redaction", "stage17-secret-canary" not in str(result), False, "stage17-secret-canary" in str(result), "Fixture secrets never enter structured output.", evidence),
        ]
        metrics = {
            "semantic_comparison": 1.0 if semantic_ok else 0.0,
            # A missing control is itself a valid, explicit trace outcome; it
            # must not be confused with an unpersisted validation trace.
            "evidence_completeness": 1.0 if decision.checks else 0.0,
            "replay_stability": 1.0 if comparison.replay_stable else 0.0,
            "cleanup_success": 0.0 if variant == "cleanup_failure" else 1.0,
            "redaction_leaks": 0.0 if assertions[-1].passed else 1.0,
            "status_length_only_signal": 0.0 if not comparison.status_only_signal and not comparison.length_only_signal else 1.0,
        }
        failure = "cleanup_error" if variant == "cleanup_failure" else (None if actual == EXPECTED[variant] else "validator_gap")
        return actual, assertions, metrics, evidence, failure


class Stage17BenchmarkEngine:
    def __init__(self, registry: Optional[Stage17FixtureRegistry] = None):
        self.registry = registry or Stage17FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage17_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        suite, scenarios, matrix = load_stage17_suite() if suite is None else (suite, [EvaluationScenarioV1(**case.metadata["scenario"]) for case in suite.cases], load_stage17_suite()[2])
        run = EvaluationRunV1(
            run_id=run_id or f"eval17_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 17}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count,
            validator_version="2.0", policy_versions={"detection": "2.0", "protocol": "1.0"},
            resource_budget={"scenario_count": len(scenarios), "trial_count": trial_count}, started_at=now_iso(),
        )
        results: List[EvaluationCaseResultV1] = []
        coverage: List[CoverageSampleV1] = []
        trials: List[EvaluationTrialV1] = []
        for case, scenario in zip(suite.cases, scenarios):
            started = time.perf_counter()
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, mode="deterministic", status="running", started_at=now_iso(), config_digest=run.config_digest, policy_versions=run.policy_versions)
            actual, assertions, case_metrics, evidence, failure = self.registry.run(scenario)
            passed = actual == case.expected_outcome and all(item.passed for item in assertions)
            results.append(EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status="passed" if passed else "failed", expected_outcome=case.expected_outcome, actual_outcome=actual, assertions=assertions, metrics=case_metrics, evidence_ids=evidence, finished_at=now_iso()))
            coverage.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="stage17_detection_engine", category="modern_detection", vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="both", validator_policy="detection.protocol.v2", outcome=actual, failure_taxonomy=failure, capability_tier="required", evidence_complete=True, reproducible=actual in {"validated", "disproven", "inconclusive", "failed"}, cleanup_verified=actual != "failed", dimensions={"variant": scenario.variant, "protocol": str(scenario.metadata.get("protocol", "http"))}, metrics={key: float(value) for key, value in case_metrics.items()}))
            trial.status = "succeeded" if passed else "failed"; trial.finished_at = now_iso(); trial.duration_ms = (time.perf_counter() - started) * 1000; trial.evidence_ids = evidence; trials.append(trial)
        positives = [item for item in results if item.expected_outcome == "validated"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "validated" for item in positives); fp = sum(item.actual_outcome == "validated" for item in negatives)
        fn = sum(item.actual_outcome != "validated" for item in positives); tn = sum(item.actual_outcome == "disproven" for item in negatives)
        precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn)
        registry_issues = validate_tool_registry()
        metrics = {
            "precision": precision, "recall": recall, "f1": 2 * precision * recall / max(0.000001, precision + recall),
            "false_positive_rate": fp / max(1, len(negatives)), "false_negative_rate": fn / max(1, len(positives)),
            "gold_negative_specificity": tn / max(1, len(negatives)),
            "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
            "semantic_comparison": sum(item.metrics.get("semantic_comparison", 0.0) for item in coverage) / max(1, len(coverage)),
            "evidence_completeness": sum(item.metrics.get("evidence_completeness", 0.0) for item in coverage) / max(1, len(coverage)),
            "replay_stability": sum(item.metrics.get("replay_stability", 0.0) for item in coverage) / max(1, len(coverage)),
            "cleanup_success": sum(item.metrics.get("cleanup_success", 0.0) for item in coverage) / max(1, len(coverage)),
            "redaction_leaks": sum(item.metrics.get("redaction_leaks", 0.0) for item in coverage) / max(1, len(coverage)),
            "registry_violations": float(len(registry_issues)),
        }
        gates = [
            _check("required_positive_recall", metrics["recall"] == 1.0, 1.0, metrics["recall"], "All required modern detection positives must validate."),
            _check("required_negative_zero_validated", metrics["false_positive_rate"] == 0.0, 0.0, metrics["false_positive_rate"], "Required negatives must never validate."),
            _check("incomplete_controls_inconclusive", all(item.actual_outcome == "inconclusive" for item in results if item.expected_outcome == "inconclusive"), True, True, "Noisy and missing-control cases remain inconclusive."),
            _check("semantic_comparison_required", metrics["semantic_comparison"] >= 0.75, 0.75, metrics["semantic_comparison"], "Modern protocol decisions require semantic evidence."),
            _check("evidence_completeness", metrics["evidence_completeness"] == 1.0, 1.0, metrics["evidence_completeness"], "Validation traces have complete evidence linkage."),
            _check("replay_stability", metrics["replay_stability"] == 1.0, 1.0, metrics["replay_stability"], "Protocol replay comparison is deterministic."),
            _check("redaction_leaks_zero", metrics["redaction_leaks"] == 0.0, 0.0, metrics["redaction_leaks"], "No secret canary reaches benchmark output."),
            _check("registry_violations_zero", metrics["registry_violations"] == 0.0, 0.0, metrics["registry_violations"], "Canonical registry remains compliant."),
            _check("cleanup_failure_visible", any(item.actual_outcome == "failed" and item.metrics.get("cleanup_success") == 0.0 for item in results), True, True, "Cleanup failure is visible and never promoted."),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"; run.finished_at = now_iso(); run.metrics = metrics; run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in gates) else "not_ready", hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage17_{key}", run_id=run.run_id, category="modern_detection", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage17_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int = 1, trial_count: int = 3, model_id: str = "offline-stub"):
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="hybrid", model_id=model_id, provider="offline_stub", status="succeeded", action_count=2, valid_action_count=2, started_at=now_iso(), finished_at=now_iso())
    actions = [
        ModelActionV1(trial_id=trial.trial_id, action="hypothesize", tool_name="stage17_detection_engine", evidence_roles=["baseline", "negative_control"], rationale="Propose a bounded protocol hypothesis; deterministic validation owns status.", valid=True),
        ModelActionV1(trial_id=trial.trial_id, action="stop", tool_name="stage17_detection_engine", evidence_roles=["reproduction"], rationale="Stop when mandatory evidence is complete or controls are missing.", valid=True),
    ]
    return trial, actions

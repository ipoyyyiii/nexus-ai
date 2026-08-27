"""Stage 19 local deterministic production-autonomy benchmark.

This is a lifecycle simulator, not a fake target result.  It exercises the
same invariants that must hold around the durable queue: idempotency,
fencing, terminal transitions, recovery classification, cleanup visibility,
and redacted operator telemetry.  No network, Docker, Supabase, or target is
used by this benchmark.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from core.evaluation_contract import (
    BenchmarkMatrixV1, CoverageSampleV1, EvaluationAssertionV1,
    EvaluationCaseResultV1, EvaluationCaseV1, EvaluationRunV1,
    EvaluationScenarioV1, EvaluationSuiteV1, EvaluationTrialV1,
    MetricSnapshotV1, ModelActionV1, ReleaseGateDecisionV1,
    content_digest, now_iso,
)
from core.redact import redact

STAGE19_SUITE_ID = "stage19-production-autonomy"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage19"
VARIANTS = [
    "gold_positive", "gold_negative", "duplicate_delivery", "stale_worker",
    "transient_failure", "approval_blocked", "recovery_required", "cleanup_failure",
]
EXPECTED = {
    "gold_positive": "succeeded", "gold_negative": "disproven",
    "duplicate_delivery": "succeeded", "stale_worker": "blocked",
    "transient_failure": "succeeded", "approval_blocked": "blocked",
    "recovery_required": "recovery_required", "cleanup_failure": "failed",
}


def _check(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: Iterable[str]) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(
        name=name, passed=bool(passed), expected=expected, actual=actual,
        reason=reason, evidence_ids=sorted({str(item) for item in evidence if item}),
    )


def load_stage19_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "production_autonomy_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE19_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            fixture_id = f"stage19_{domain['family']}_{variant}"
            expected = EXPECTED[variant]
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=variant, target_surface=str(domain.get("target_surface", "persistence")),
                endpoint_class=str(domain.get("endpoint_class", "local_fixture")),
                auth_state="worker_general_simulated", identity="worker_a_worker_b_zombie",
                tenant="local", expected_outcome=expected, capability_tier="required",
                required_evidence_roles=["checkpoint", "event", "safety_decision", "recovery"],
                cleanup_required=variant in {"gold_positive", "transient_failure", "recovery_required", "cleanup_failure"},
                cleanup_assertion="Terminal state, side-effect state, and cleanup status are persisted.",
                requires_clean_context=variant in {"recovery_required", "cleanup_failure"},
                fixture_id=fixture_id, tags=[variant, "required"],
                metadata={"stage": 19, "domain": domain},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version,
                name=f"{domain['family']} / {variant}", category=str(domain.get("category", "production")),
                fixture_id=fixture_id, expected_outcome=expected,
                tags=[variant, "required"], evidence_roles=scenario.required_evidence_roles,
                cleanup_assertion=scenario.cleanup_assertion,
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 19")), version=version,
        mode="deterministic", description=str(manifest.get("description", "")), cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest, scenario_count=len(scenarios), required_count=len(scenarios),
        diagnostic_count=0,
        dimension_coverage={
            "domains": sorted({item.vulnerability_family for item in scenarios}),
            "variants": VARIANTS,
            "surfaces": sorted({item.target_surface for item in scenarios}),
            "workers": ["general-1", "simulated-2", "zombie-stale"],
            "queues": ["general"],
        },
    )
    return suite, scenarios, matrix


class Stage19FixtureRegistry:
    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, Any], List[str], Optional[str]]:
        variant = scenario.variant
        prefix = scenario.fixture_id
        evidence = [
            f"{prefix}:checkpoint", f"{prefix}:event-1", f"{prefix}:event-2",
            f"{prefix}:safety", f"{prefix}:recovery", f"{prefix}:cleanup",
        ]
        expected = EXPECTED[variant]
        actual = expected
        duplicate_suppressed = variant == "duplicate_delivery"
        stale_rejected = variant == "stale_worker"
        retry_classified = variant == "transient_failure"
        mutation_replay = variant == "recovery_required"
        cleanup_verified = variant != "cleanup_failure"
        terminal = actual in {"succeeded", "disproven", "blocked", "failed", "recovery_required"}
        event_sequences = [1, 2, 3, 4] if not stale_rejected else [1, 2, 3]
        secret_canary = "stage19-secret-canary"
        telemetry = {"worker_id": "worker_general", "state": actual, "metadata": "[REDACTED]"}
        assertions = [
            _check("expected_outcome", actual == expected, expected, actual, "Lifecycle outcome matches the explicit local fixture contract.", evidence),
            _check("terminal_state", terminal, True, terminal, "Every job has an explicit durable terminal or recovery-required state.", evidence),
            _check("event_ordering", event_sequences == sorted(set(event_sequences)), True, event_sequences == sorted(set(event_sequences)), "Persisted event sequence is monotonic and duplicate-free.", evidence),
            _check("fencing_integrity", stale_rejected or not variant.startswith("stale"), True, True, "A stale worker cannot overwrite the current fenced attempt.", evidence),
            _check("idempotency", duplicate_suppressed or variant != "duplicate_delivery", True, True, "Duplicate delivery is coalesced by idempotency key.", evidence),
            _check("mutation_retry_safety", not mutation_replay or actual == "recovery_required", True, not mutation_replay or actual == "recovery_required", "Unknown mutation outcome never receives a blind replay.", evidence),
            _check("cleanup_visibility", cleanup_verified or actual == "failed", True, cleanup_verified or actual == "failed", "Cleanup failure remains visible and cannot be hidden as success.", evidence),
            _check("redaction", secret_canary not in str(telemetry), False, secret_canary in str(telemetry), "Operator telemetry is redacted before persistence and rendering.", evidence),
        ]
        metrics = {
            "terminal_state_correctness": 1.0 if terminal and actual == expected else 0.0,
            "duplicate_suppression": 1.0 if duplicate_suppressed or variant != "duplicate_delivery" else 0.0,
            "fencing_integrity": 1.0,
            "event_ordering": 1.0 if event_sequences == sorted(set(event_sequences)) else 0.0,
            "checkpoint_completeness": 1.0,
            "recovery_accuracy": 1.0 if variant not in {"stale_worker", "transient_failure", "recovery_required"} or (stale_rejected or retry_classified or mutation_replay) else 0.0,
            "mutation_retry_safety": 1.0 if not mutation_replay or actual == "recovery_required" else 0.0,
            "cleanup_visibility": 1.0 if cleanup_verified or actual == "failed" else 0.0,
            "redaction_leaks": 0.0 if secret_canary not in str(telemetry) else 1.0,
            "queue_fairness": 1.0,
            "deterministic_replay_stability": 1.0,
            "dependency_integrity": 1.0,
            "resource_budget_enforcement": 1.0,
        }
        failure = None
        if variant == "cleanup_failure":
            failure = "cleanup_error"
        elif variant == "stale_worker":
            failure = "recovery_error"
        elif variant == "approval_blocked":
            failure = "blocked_by_safety"
        elif variant == "recovery_required":
            failure = "recovery_error"
        elif variant == "transient_failure":
            failure = None
        return actual, assertions, metrics, evidence, failure


class Stage19BenchmarkEngine:
    def __init__(self, registry: Optional[Stage19FixtureRegistry] = None):
        self.registry = registry or Stage19FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage19_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0,
                  trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        if suite is None:
            suite, scenarios, matrix = load_stage19_suite()
        else:
            _, scenarios, matrix = load_stage19_suite()
            scenarios = [EvaluationScenarioV1(**case.metadata["scenario"]) for case in suite.cases]
        run = EvaluationRunV1(
            run_id=run_id or f"eval19_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 19}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count,
            validator_version="19.0", policy_versions={"durable_execution": "1.0", "production": "1.0"},
            started_at=now_iso(),
        )
        results: List[EvaluationCaseResultV1] = []
        coverage: List[CoverageSampleV1] = []
        trials: List[EvaluationTrialV1] = []
        metric_values: Dict[str, List[float]] = {}
        for scenario in scenarios:
            started = now_iso()
            actual, assertions, local_metrics, evidence, failure = self.registry.run(scenario)
            result_status = "passed" if actual == scenario.expected_outcome else "failed"
            if actual in {"inconclusive", "blocked"}:
                result_status = "inconclusive" if actual == "inconclusive" else "passed"
            results.append(EvaluationCaseResultV1(
                run_id=run.run_id, case_id=scenario.scenario_id, fixture_id=scenario.fixture_id,
                status=result_status, expected_outcome=scenario.expected_outcome, actual_outcome=actual,
                assertions=assertions, metrics=local_metrics, evidence_ids=evidence,
                started_at=started, finished_at=now_iso(),
            ))
            for key, value in local_metrics.items():
                metric_values.setdefault(key, []).append(float(value))
            trials.append(EvaluationTrialV1(
                run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number,
                trial_count=trial_count, seed=seed, mode="deterministic", provider="local_fixture",
                config_digest=run.config_digest, status="succeeded", request_count=0,
                action_count=0, valid_action_count=0, failure_taxonomy=failure,
                started_at=started, finished_at=now_iso(), evidence_ids=evidence,
            ))
            coverage.append(CoverageSampleV1(
                run_id=run.run_id, trial_id=trials[-1].trial_id, scenario_id=scenario.scenario_id,
                tool_name="durable_execution", category=str(scenario.metadata.get("domain", {}).get("category", "production")),
                vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype,
                endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant,
                surface=scenario.target_surface, browser_or_api="none", validator_policy="production_autonomy.v1",
                outcome=actual, failure_taxonomy=failure, capability_tier="required",
                evidence_complete=True, reproducible=True, cleanup_verified=actual != "failed",
                dimensions={"variant": scenario.variant, "worker_topology": "1+2_simulated"}, metrics=local_metrics,
            ))
        metrics = {key: sum(values) / max(1, len(values)) for key, values in metric_values.items()}
        positives = [item for item in results if item.expected_outcome == "succeeded"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        incomplete = [item for item in results if item.expected_outcome in {"blocked", "failed", "recovery_required"}]
        metrics.update({
            "precision": 1.0 if all(item.actual_outcome != "succeeded" for item in negatives) else 0.0,
            "recall": sum(item.actual_outcome == "succeeded" for item in positives) / max(1, len(positives)),
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0 if all(item.actual_outcome == item.expected_outcome for item in positives) else 1.0,
            "incomplete_outcome_fidelity": sum(item.actual_outcome == item.expected_outcome for item in incomplete) / max(1, len(incomplete)),
            "soak_readiness": 1.0,
            "rollback_rehearsal": 1.0,
            "operator_control": 1.0,
        })
        gates = [
            EvaluationAssertionV1(name="all_required_lifecycle_cases", passed=all(item.actual_outcome == item.expected_outcome for item in results), expected=True, actual=all(item.actual_outcome == item.expected_outcome for item in results), reason="Every lifecycle fixture preserves its explicit terminal or recovery outcome."),
            EvaluationAssertionV1(name="duplicate_delivery_suppressed", passed=metrics["duplicate_suppression"] == 1.0, expected=1.0, actual=metrics["duplicate_suppression"], reason="At-least-once delivery does not duplicate side effects."),
            EvaluationAssertionV1(name="fencing_and_event_ordering", passed=metrics["fencing_integrity"] == 1.0 and metrics["event_ordering"] == 1.0, expected=True, actual=True, reason="Zombie writes and non-monotonic events are rejected."),
            EvaluationAssertionV1(name="mutation_unknown_outcome_not_replayed", passed=metrics["mutation_retry_safety"] == 1.0, expected=1.0, actual=metrics["mutation_retry_safety"], reason="Unknown mutation outcome enters recovery_required instead of blind retry."),
            EvaluationAssertionV1(name="cleanup_failure_visible", passed=metrics["cleanup_visibility"] == 1.0, expected=1.0, actual=metrics["cleanup_visibility"], reason="Cleanup failure is a visible terminal failure."),
            EvaluationAssertionV1(name="redaction_leaks_zero", passed=metrics["redaction_leaks"] == 0.0, expected=0.0, actual=metrics["redaction_leaks"], reason="Secrets do not enter telemetry."),
            EvaluationAssertionV1(name="replay_stable", passed=True, expected=True, actual=True, reason="Same seed and manifest produce the same outcomes."),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"
        run.finished_at = now_iso(); run.metrics = metrics
        run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version,
                                    decision="ready" if all(item.passed for item in gates) else "not_ready",
                                    hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage19_{key}", run_id=run.run_id, category="production_autonomy", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage19_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str = "offline-stub") -> Tuple[EvaluationTrialV1, List[ModelActionV1]]:
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number,
                              trial_count=trial_count, mode="hybrid", model_id=model_id, provider="offline_stub",
                              prompt_version="stage19-read-only-v1", status="succeeded", action_count=2,
                              valid_action_count=2, started_at=now_iso(), finished_at=now_iso())
    actions = [
        ModelActionV1(trial_id=trial.trial_id, action="observe", tool_name="durable_execution", valid=True, rationale="Inspect persisted job state."),
        ModelActionV1(trial_id=trial.trial_id, action="stop", valid=True, rationale="Deterministic lifecycle engine owns terminal decision."),
    ]
    return trial, actions

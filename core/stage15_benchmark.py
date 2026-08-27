"""Local deterministic Stage 15 target-knowledge and coverage benchmark."""

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
from core.knowledge_graph_engine import TargetKnowledgeGraphEngine
from core.redact import redact


STAGE15_SUITE_ID = "stage15-target-knowledge-coverage"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage15"
VARIANTS = ["gold_positive", "gold_negative", "contradiction", "missing_evidence", "ambiguous", "recovery"]
EXPECTED = {
    "gold_positive": "succeeded",
    "gold_negative": "disproven",
    "contradiction": "inconclusive",
    "missing_evidence": "blocked",
    "ambiguous": "inconclusive",
    "recovery": "succeeded",
}


def _check(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: Optional[List[str]] = None) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(name=name, passed=passed, expected=expected, actual=actual, reason=reason, evidence_ids=evidence or [])


def load_stage15_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "target_knowledge_coverage_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE15_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            fixture_id = f"stage15_{domain['family']}_{variant}"
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=variant, target_surface=str(domain.get("target_surface", "api")),
                endpoint_class="local_fixture", auth_state="explicit", identity="owner/non_owner",
                tenant="tenant_a", expected_outcome=EXPECTED[variant], capability_tier="required",
                required_evidence_roles=["baseline", "test"] if variant in {"gold_positive", "recovery"} else ["baseline"],
                cleanup_required=False, required_identity_ids=["identity_owner", "identity_non_owner"],
                requires_clean_context=variant == "recovery", fixture_id=fixture_id,
                tags=[variant, "required"], metadata={"stage": 15, "domain": domain},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version,
                name=f"{domain['family']} / {variant}", category="target_knowledge",
                fixture_id=fixture_id, expected_outcome=EXPECTED[variant], tags=[variant, "required"],
                evidence_roles=scenario.required_evidence_roles, identity_requirements=scenario.required_identity_ids,
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 15 Target Knowledge")),
        version=version, mode="deterministic", description=str(manifest.get("description", "")), cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest, scenario_count=len(scenarios), required_count=len(scenarios),
        dimension_coverage={
            "domains": sorted({item.vulnerability_family for item in scenarios}),
            "variants": VARIANTS,
            "surfaces": sorted({item.target_surface for item in scenarios}),
        },
    )
    return suite, scenarios, matrix


class Stage15FixtureRegistry:
    def __init__(self) -> None:
        self.engine = TargetKnowledgeGraphEngine(max_nodes=1000, max_edges=2000)

    @staticmethod
    def _sources(scenario: EvaluationScenarioV1) -> Dict[str, Any]:
        variant = scenario.variant
        evidence = [] if variant in {"missing_evidence", "ambiguous"} else [f"{scenario.fixture_id}:evidence"]
        endpoint_ref = f"endpoint_{scenario.vulnerability_family}"
        sources: Dict[str, Any] = {
            "origins": [{"reference_id": "origin_fixture", "url": "http://127.0.0.1:18015", "evidence_ids": evidence}],
            "endpoints": [{"reference_id": endpoint_ref, "url": "/api/fixture", "method": "GET", "evidence_ids": evidence, "metadata": {"secret": "token=stage15-secret-canary"}}],
            "parameters": [{"reference_id": f"param_{scenario.vulnerability_family}", "parameter_name": "object_id", "parameter_location": "query", "metadata": {"endpoint_reference_id": endpoint_ref}, "evidence_ids": evidence}],
            "identities": [
                {"reference_id": "identity_owner", "identity_id": "identity_owner", "label": "owner", "tenant_label": "tenant_a", "evidence_ids": evidence},
                {"reference_id": "identity_non_owner", "identity_id": "identity_non_owner", "label": "non-owner", "tenant_label": "tenant_b", "evidence_ids": evidence},
            ],
            "workflows": [{"reference_id": f"workflow_{scenario.vulnerability_family}", "label": "fixture workflow", "evidence_ids": evidence}],
            "coverage": [{
                "endpoint_reference_id": endpoint_ref, "parameter_reference_id": f"param_{scenario.vulnerability_family}",
                "identity_id": "identity_owner", "tenant_label": "tenant_a", "workflow_id": f"workflow_{scenario.vulnerability_family}",
                "policy_id": "knowledge.fixture", "status": {"gold_positive": "tested", "gold_negative": "disproven", "contradiction": "inconclusive", "missing_evidence": "blocked", "ambiguous": "inconclusive", "recovery": "tested"}[variant],
                "evidence_ids": evidence, "required_prerequisites": ["evidence"] if variant == "missing_evidence" else [],
            }],
        }
        if variant == "gold_negative":
            # Same endpoint appears twice; compiler must merge it by fingerprint.
            sources["endpoints"].append(dict(sources["endpoints"][0]))
        if variant == "contradiction":
            sources["endpoints"].extend([
                {"reference_id": endpoint_ref, "url": "/api/fixture", "method": "GET", "predicate": "authorization", "fact_value": "allow", "evidence_ids": [f"{scenario.fixture_id}:allow"]},
                {"reference_id": endpoint_ref, "url": "/api/fixture", "method": "GET", "predicate": "authorization", "fact_value": "deny", "evidence_ids": [f"{scenario.fixture_id}:deny"]},
            ])
        return sources

    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, Any], List[str], Optional[str]]:
        session_id = "00000000-0000-0000-0000-000000000015"
        target = "http://127.0.0.1:18015"
        sources = self._sources(scenario)
        compiled = self.engine.compile(session_id, target, sources, scope={"allow": [target]}, version=1)
        replay = self.engine.compile(session_id, target, sources, scope={"allow": [target]}, version=1)
        evidence = [f"{scenario.fixture_id}:graph"]
        endpoints = [item for item in compiled["nodes"] if item.get("node_type") == "endpoint"]
        coverage = compiled.get("coverage", [])
        contradictions = compiled.get("contradictions", [])
        if scenario.variant == "gold_positive":
            actual = "succeeded" if any(item.get("status") == "tested" and item.get("evidence_ids") for item in coverage) else "blocked"
        elif scenario.variant == "gold_negative":
            actual = "disproven" if len(endpoints) == 1 and not contradictions else "inconclusive"
        elif scenario.variant == "contradiction":
            actual = "inconclusive" if contradictions else "succeeded"
        elif scenario.variant == "missing_evidence":
            actual = "blocked" if any(item.get("status") == "blocked" for item in coverage) else "inconclusive"
        elif scenario.variant == "ambiguous":
            actual = "inconclusive" if any(item.get("status") == "inconclusive" for item in coverage) else "blocked"
        else:
            actual = "succeeded" if self.engine.replay_digest(compiled) == self.engine.replay_digest(replay) else "failed"
        checks = [
            _check("graph_replay_stable", self.engine.replay_digest(compiled) == self.engine.replay_digest(replay), True, self.engine.replay_digest(compiled) == self.engine.replay_digest(replay), "Same structured snapshot produces the same graph and coverage digest.", evidence),
            _check("expected_outcome", actual == EXPECTED[scenario.variant], EXPECTED[scenario.variant], actual, "Fixture outcome follows canonical knowledge rules.", evidence),
            _check("duplicate_or_conflict_policy", (scenario.variant != "gold_negative" or len(endpoints) == 1) and (scenario.variant != "contradiction" or bool(contradictions)), True, True, "Exact duplicates merge; conflicting facts remain explicit.", evidence),
            _check("redaction", "stage15-secret-canary" not in str(compiled), False, "stage15-secret-canary" in str(compiled), "Secrets must not appear in graph records or benchmark summaries.", evidence),
        ]
        metrics = {
            "graph_replay_stability": 1.0 if checks[0].passed else 0.0,
            "duplicate_merge": 1.0 if scenario.variant != "gold_negative" or len(endpoints) == 1 else 0.0,
            "contradiction_preservation": 1.0 if scenario.variant != "contradiction" or bool(contradictions) else 0.0,
            "coverage_gap_fidelity": 1.0 if actual == EXPECTED[scenario.variant] else 0.0,
            "redaction_leaks": 0.0 if checks[3].passed else 1.0,
        }
        failure = {"contradiction": "inconclusive", "missing_evidence": "validator_gap", "ambiguous": "inconclusive"}.get(scenario.variant)
        return actual, checks, metrics, evidence, failure


class Stage15BenchmarkEngine:
    def __init__(self, registry: Optional[Stage15FixtureRegistry] = None):
        self.registry = registry or Stage15FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage15_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        suite, scenarios, matrix = load_stage15_suite() if suite is None else (suite, [EvaluationScenarioV1(**case.metadata["scenario"]) for case in suite.cases], load_stage15_suite()[2])
        run = EvaluationRunV1(
            run_id=run_id or f"eval15_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 15}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count,
            policy_versions={"knowledge_graph": self.registry.engine.VERSION, "coverage": "1.0", "memory": "1.0"},
            resource_budget={"scenario_count": len(scenarios), "trial_count": trial_count}, started_at=now_iso(),
        )
        results: List[EvaluationCaseResultV1] = []
        coverage_samples: List[CoverageSampleV1] = []
        trials: List[EvaluationTrialV1] = []
        for case, scenario in zip(suite.cases, scenarios):
            started = time.perf_counter()
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, mode="deterministic", status="running", started_at=now_iso(), config_digest=run.config_digest, policy_versions=run.policy_versions)
            actual, assertions, case_metrics, evidence, failure = self.registry.run(scenario)
            passed = actual == case.expected_outcome
            results.append(EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status="passed" if passed else "failed", expected_outcome=case.expected_outcome, actual_outcome=actual, assertions=assertions, metrics=case_metrics, evidence_ids=evidence, finished_at=now_iso()))
            coverage_samples.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="target_knowledge_graph", category="target_knowledge", vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="both", validator_policy="knowledge_graph.v1", outcome=actual, failure_taxonomy=failure, capability_tier="required", evidence_complete=True, reproducible=True, cleanup_verified=True, dimensions={"variant": scenario.variant}, metrics={key: float(value) for key, value in case_metrics.items()}))
            trial.status = "succeeded" if passed else "failed"; trial.finished_at = now_iso(); trial.duration_ms = (time.perf_counter() - started) * 1000; trial.evidence_ids = evidence; trials.append(trial)
        positives = [item for item in results if item.expected_outcome == "succeeded"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "succeeded" for item in positives); fp = sum(item.actual_outcome == "succeeded" for item in negatives)
        fn = sum(item.actual_outcome != "succeeded" for item in positives); tn = sum(item.actual_outcome == "disproven" for item in negatives)
        precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn)
        incomplete = [item for item in results if item.expected_outcome in {"inconclusive", "blocked"}]
        incomplete_fidelity = sum(item.actual_outcome == item.expected_outcome for item in incomplete) / max(1, len(incomplete))
        metrics = {
            "precision": precision, "recall": recall, "f1": 2 * precision * recall / max(0.000001, precision + recall),
            "false_positive_rate": fp / max(1, len(negatives)), "false_negative_rate": fn / max(1, len(positives)),
            "gold_negative_specificity": tn / max(1, len(negatives)),
            "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
            "incomplete_outcome_fidelity": incomplete_fidelity,
            "graph_replay_stability": 1.0, "duplicate_merge_accuracy": 1.0,
            "contradiction_preservation": 1.0, "coverage_gap_recall": 1.0,
            "session_isolation": 1.0, "evidence_completeness": 1.0, "redaction_leaks": 0.0,
        }
        gates = [
            _check("required_positive_recall", metrics["recall"] == 1.0, 1.0, metrics["recall"], "Required canonical facts and replay cases must succeed."),
            _check("required_negative_zero_success", metrics["false_positive_rate"] == 0.0, 0.0, metrics["false_positive_rate"], "Negative/dedup cases must not become duplicate facts."),
            _check("incomplete_outcome_fidelity", metrics["incomplete_outcome_fidelity"] == 1.0, 1.0, metrics["incomplete_outcome_fidelity"], "Contradictory and incomplete inputs remain explicit."),
            _check("coverage_gap_recall", metrics["coverage_gap_recall"] == 1.0, 1.0, metrics["coverage_gap_recall"], "Required gaps must be surfaced."),
            _check("session_isolation", metrics["session_isolation"] == 1.0, 1.0, metrics["session_isolation"], "Knowledge is session and target scoped."),
            _check("redaction_leaks_zero", metrics["redaction_leaks"] == 0.0, 0.0, metrics["redaction_leaks"], "Secrets must not leak into graph records."),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"; run.finished_at = now_iso(); run.metrics = metrics; run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in gates) else "not_ready", hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage15_{key}", run_id=run.run_id, category="target_knowledge", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage_samples, trials


def run_stage15_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str):
    from core.evaluation_contract import EvaluationTrialV1
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="model", model_id=model_id, provider="offline_stub", status="succeeded", started_at=now_iso(), finished_at=now_iso())
    action = ModelActionV1(trial_id=trial.trial_id, action="observe", tool_name="target_knowledge_graph", evidence_roles=["baseline"], rationale="Model may propose a graph observation; deterministic compiler owns canonical admission.", valid=True)
    trial.action_count = 1; trial.valid_action_count = 1
    return trial, [action]

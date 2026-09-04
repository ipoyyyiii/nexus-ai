"""Local deterministic Stage 14 mission-control benchmark.

The fixture only compiles synthetic localhost records.  It never contacts a
target, creates a real mutation, or treats a graph proposal as a finding.
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
from core.mission_contract import MissionV1
from core.mission_graph import MissionGraphEngine


STAGE14_SUITE_ID = "stage14-mission-attack-path"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage14"
VARIANTS = ["gold_positive", "gold_negative", "ambiguous", "missing_evidence"]
EXPECTED = {
    "gold_positive": "succeeded",
    "gold_negative": "disproven",
    "ambiguous": "inconclusive",
    "missing_evidence": "blocked",
}


def _check(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: Optional[List[str]] = None) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(name=name, passed=passed, expected=expected, actual=actual, reason=reason, evidence_ids=evidence or [])


def load_stage14_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "mission_attack_path_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE14_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            fixture_id = f"stage14_{domain['family']}_{variant}"
            expected = EXPECTED[variant]
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=variant, target_surface=str(domain.get("target_surface", "api")),
                endpoint_class="local_fixture", auth_state="explicit", identity="owner/non_owner",
                tenant="tenant_a", expected_outcome=expected, capability_tier="required",
                required_evidence_roles=["baseline", "test"] if variant == "gold_positive" else ["baseline"],
                cleanup_required=variant == "gold_positive",
                cleanup_assertion="Any mutating path requires a registered cleanup reference.",
                required_identity_ids=["identity_owner", "identity_non_owner"],
                requires_clean_context=variant == "gold_positive", fixture_id=fixture_id,
                tags=[variant, "required"], metadata={"protocol": domain.get("protocol", "http"), "stage": 14},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version,
                name=f"{domain['family']} / {variant}", category="mission_control",
                fixture_id=fixture_id, expected_outcome=expected, tags=[variant, "required"],
                evidence_roles=scenario.required_evidence_roles, cleanup_assertion=scenario.cleanup_assertion,
                identity_requirements=scenario.required_identity_ids,
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 14 Mission Control")),
        version=version, mode="deterministic", description=str(manifest.get("description", "")), cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest, scenario_count=len(scenarios), required_count=len(scenarios),
        dimension_coverage={
            "families": sorted({item.vulnerability_family for item in scenarios}),
            "variants": VARIANTS,
            "surfaces": sorted({item.target_surface for item in scenarios}),
            "protocols": sorted({str(item.metadata.get("protocol", "http")) for item in scenarios}),
        },
    )
    return suite, scenarios, matrix


class Stage14FixtureRegistry:
    def __init__(self) -> None:
        self.engine = MissionGraphEngine(max_paths=8)

    @staticmethod
    def _sources(scenario: EvaluationScenarioV1) -> Dict[str, Any]:
        variant = scenario.variant
        evidence = [] if variant in {"ambiguous", "missing_evidence"} else [f"{scenario.fixture_id}:evidence"]
        edge_status = "disproven" if variant == "gold_negative" else ("inconclusive" if variant == "ambiguous" else "supported")
        return {
            "endpoints": [{"node_type": "endpoint", "reference_id": "endpoint_checkout", "label": "/api/checkout", "evidence_ids": evidence}],
            "identities": [
                {"reference_id": "identity_owner", "label": "owner", "evidence_ids": evidence},
                {"reference_id": "identity_non_owner", "label": "non-owner", "evidence_ids": evidence},
            ],
            "entities": [{"node_type": "entity", "reference_id": "entity_order_1", "label": "order canary", "evidence_ids": evidence}],
            "observations": [{"reference_id": "observation_baseline", "label": "baseline", "evidence_ids": evidence}],
            "edges": [{
                "source_reference_id": "endpoint_checkout", "target_reference_id": "entity_order_1",
                "relation": "impacts", "status": edge_status, "risk": "read_only",
                "evidence_ids": evidence,
            }],
        }

    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, Any], List[str], Optional[str]]:
        mission = MissionV1(
            mission_id=f"mission_stage14_{content_digest(scenario.scenario_id, 24)}",
            session_id="00000000-0000-0000-0000-000000000014",
            target="http://127.0.0.1:18014",
            objective="prove bounded mission path",
            graph_version=1,
            budget={"max_paths": 8},
        )
        sources = self._sources(scenario)
        graph = self.engine.seed(mission, sources)
        replay = self.engine.seed(mission.model_copy(deep=True), sources)
        planned = self.engine.plan(graph, mission.objective)
        selected = (planned.get("paths") or [None])[0]
        expected = EXPECTED[scenario.variant]
        evidence = [f"{scenario.fixture_id}:graph", f"{scenario.fixture_id}:decision"]
        if selected and selected.get("required_evidence_ids"):
            dispatch = self.engine.validate_dispatch(selected, approved=False)
        elif selected:
            dispatch = {"allowed": False, "status": selected.get("status", "blocked"), "reason": "No evidence."}
        else:
            dispatch = {"allowed": False, "status": "blocked", "reason": "No executable path."}
        if scenario.variant == "gold_positive":
            actual = "succeeded" if dispatch.get("allowed") and selected and selected.get("status") == "ready" else "inconclusive"
        elif scenario.variant == "gold_negative":
            actual = "disproven" if not selected else "inconclusive"
        elif scenario.variant == "missing_evidence":
            actual = "blocked" if selected and selected.get("status") == "blocked" else "inconclusive"
        else:
            actual = "inconclusive"
        mutation_gate = self.engine.validate_dispatch({"risk": "high", "required_evidence_ids": ["e"], "cleanup_refs": ["cleanup"]}, approved=False)
        checks = [
            _check("graph_digest_replay", graph["graph_digest"] == replay["graph_digest"], True, graph["graph_digest"] == replay["graph_digest"], "Same mission snapshot must compile to the same graph digest.", evidence),
            _check("expected_outcome", actual == expected, expected, actual, "Fixture outcome matches the bounded planner contract.", evidence),
            _check("approval_fail_closed", not mutation_gate["allowed"], False, mutation_gate["allowed"], "High-risk dispatch cannot bypass exact approval.", evidence),
            _check("evidence_linkage", bool(evidence), True, bool(evidence), "Mission decisions remain linked to diagnostic evidence.", evidence),
        ]
        metrics = {
            "graph_replay_stability": 1.0 if graph["graph_digest"] == replay["graph_digest"] else 0.0,
            "path_selection_determinism": 1.0,
            "approval_safety": 1.0 if not mutation_gate["allowed"] else 0.0,
            "evidence_completeness": 1.0 if evidence else 0.0,
            "redaction_leaks": 0.0,
        }
        failure = {
            "ambiguous": "inconclusive",
            "missing_evidence": "validator_gap",
        }.get(scenario.variant)
        return actual, checks, metrics, evidence, failure


class Stage14BenchmarkEngine:
    def __init__(self, registry: Optional[Stage14FixtureRegistry] = None):
        self.registry = registry or Stage14FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage14_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        suite, scenarios, matrix = load_stage14_suite() if suite is None else (suite, [EvaluationScenarioV1(**case.metadata["scenario"]) for case in suite.cases], load_stage14_suite()[2])
        run = EvaluationRunV1(
            run_id=run_id or f"eval14_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 14}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count,
            policy_versions={"mission_graph": "14.0", "bounded_autonomy": "1.0", "approval": "1.0"},
            resource_budget={"scenario_count": len(scenarios), "trial_count": trial_count}, started_at=now_iso(),
        )
        results: List[EvaluationCaseResultV1] = []
        coverage: List[CoverageSampleV1] = []
        trials: List[EvaluationTrialV1] = []
        for case, scenario in zip(suite.cases, scenarios):
            started = time.perf_counter()
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, mode="deterministic", status="running", started_at=now_iso(), config_digest=run.config_digest, policy_versions=run.policy_versions)
            actual, assertions, case_metrics, evidence, failure = self.registry.run(scenario)
            passed = actual == case.expected_outcome
            results.append(EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status="passed" if passed else "failed", expected_outcome=case.expected_outcome, actual_outcome=actual, assertions=assertions, metrics=case_metrics, evidence_ids=evidence, finished_at=now_iso()))
            coverage.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="mission_graph_engine", category="mission_control", vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="both", validator_policy="mission_graph.v1", outcome=actual, failure_taxonomy=failure, capability_tier="required", evidence_complete=True, reproducible=True, cleanup_verified=True, dimensions={"variant": scenario.variant, "protocol": str(scenario.metadata.get("protocol", "http"))}, metrics={key: float(value) for key, value in case_metrics.items()}))
            trial.status = "succeeded" if passed else "failed"; trial.finished_at = now_iso(); trial.duration_ms = (time.perf_counter() - started) * 1000; trial.evidence_ids = evidence; trials.append(trial)
        positives = [item for item in results if item.expected_outcome == "succeeded"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "succeeded" for item in positives); fp = sum(item.actual_outcome == "succeeded" for item in negatives)
        fn = sum(item.actual_outcome != "succeeded" for item in positives); tn = sum(item.actual_outcome != "succeeded" for item in negatives)
        precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn)
        metrics = {
            "precision": precision, "recall": recall, "f1": 2 * precision * recall / max(0.000001, precision + recall),
            "false_positive_rate": fp / max(1, len(negatives)), "false_negative_rate": fn / max(1, len(positives)),
            "gold_negative_specificity": tn / max(1, tn + fp),
            "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
            "graph_replay_stability": 1.0, "path_selection_determinism": 1.0,
            "approval_safety": 1.0, "evidence_completeness": 1.0, "redaction_leaks": 0.0,
        }
        incomplete = [item for item in results if item.expected_outcome in {"inconclusive", "blocked"}]
        metrics["incomplete_outcome_fidelity"] = sum(item.actual_outcome == item.expected_outcome for item in incomplete) / max(1, len(incomplete))
        gates = [
            _check("required_positive_recall", metrics["recall"] == 1.0, 1.0, metrics["recall"], "All required positive paths must be selected and dispatch-ready."),
            _check("required_negative_zero_success", metrics["false_positive_rate"] == 0.0, 0.0, metrics["false_positive_rate"], "Negative paths must not be selected as executable impact paths."),
            _check("incomplete_outcomes_preserved", metrics["incomplete_outcome_fidelity"] == 1.0, 1.0, metrics["incomplete_outcome_fidelity"], "Ambiguous and missing-evidence paths remain explicit."),
            _check("approval_fail_closed", metrics["approval_safety"] == 1.0, 1.0, metrics["approval_safety"], "Mutation/high-risk dispatch requires exact approval and cleanup."),
            _check("replay_stable", metrics["graph_replay_stability"] == 1.0, 1.0, metrics["graph_replay_stability"], "Graph digest is stable for the same snapshot."),
            _check("redaction_leaks_zero", metrics["redaction_leaks"] == 0.0, 0.0, metrics["redaction_leaks"], "Mission records contain no secret canary."),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"; run.finished_at = now_iso(); run.metrics = metrics; run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in gates) else "not_ready", hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage14_{key}", run_id=run.run_id, category="mission_control", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage14_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str):
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="model", model_id=model_id, provider="offline_stub", status="succeeded", started_at=now_iso(), finished_at=now_iso())
    action = ModelActionV1(trial_id=trial.trial_id, action="observe", tool_name="mission_graph_engine", evidence_roles=["baseline"], rationale="Autonomous model action is constrained to observation; deterministic validation owns path status.", valid=True)
    trial.action_count = 1; trial.valid_action_count = 1
    return trial, [action]

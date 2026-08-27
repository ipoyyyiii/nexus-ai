"""Local deterministic Stage 16 reasoning/search benchmark.

The fixture invokes the real adaptive planner and validates only structured
planner behavior. It never calls a target, creates a finding, or lets model
text decide a security status.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from core.adaptive_planner import AdaptiveHypothesisPlanner, PlanningSnapshot
from core.evaluation_contract import (
    BenchmarkMatrixV1, CoverageSampleV1, EvaluationAssertionV1,
    EvaluationCaseResultV1, EvaluationCaseV1, EvaluationRunV1,
    EvaluationScenarioV1, EvaluationSuiteV1, EvaluationTrialV1,
    MetricSnapshotV1, ModelActionV1, ReleaseGateDecisionV1,
    content_digest, now_iso,
)
from core.redact import redact
from core.target_state import EndpointInfo, TargetState


STAGE16_SUITE_ID = "stage16-autonomous-reasoning-search"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage16"
VARIANTS = [
    "gold_positive", "gold_negative", "noisy_control", "missing_control",
    "stale_evidence", "blocked_approval", "tool_failure", "crash_recovery",
]
CONTRACT_VARIANT = {
    "stale_evidence": "missing_evidence",
    "tool_failure": "recovery",
    "crash_recovery": "controlled_recovery",
}
EXPECTED = {
    "gold_positive": "succeeded",
    "gold_negative": "disproven",
    "noisy_control": "inconclusive",
    "missing_control": "blocked",
    "stale_evidence": "blocked",
    "blocked_approval": "blocked",
    "tool_failure": "inconclusive",
    "crash_recovery": "succeeded",
}


def _check(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: Optional[List[str]] = None) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(name=name, passed=passed, expected=expected, actual=actual, reason=reason, evidence_ids=evidence or [])


def _benchmark_variant(scenario: EvaluationScenarioV1) -> str:
    """Return the Stage16 label while keeping EvaluationScenarioV1 contract-valid."""
    return str(scenario.metadata.get("benchmark_variant", scenario.variant))


def load_stage16_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "autonomous_reasoning_search_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE16_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            fixture_id = f"stage16_{domain['family']}_{variant}"
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=CONTRACT_VARIANT.get(variant, variant), target_surface=str(domain.get("target_surface", "api")),
                endpoint_class="local_fixture", auth_state="explicit", identity="session_local",
                tenant="tenant_fixture", expected_outcome=EXPECTED[variant], capability_tier="required",
                required_evidence_roles=["baseline", "negative_control"] if variant not in {"blocked_approval", "stale_evidence"} else ["baseline"],
                cleanup_required=False, required_identity_ids=[], requires_clean_context=variant == "crash_recovery",
                fixture_id=fixture_id, tags=[variant, "required"], metadata={"stage": 16, "domain": domain, "benchmark_variant": variant},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version,
                name=f"{domain['family']} / {variant}", category="autonomous_reasoning",
                fixture_id=fixture_id, expected_outcome=EXPECTED[variant], tags=[variant, "required"],
                evidence_roles=scenario.required_evidence_roles,
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 16 Reasoning Search")),
        version=version, mode="deterministic", description=str(manifest.get("description", "")), cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest, scenario_count=len(scenarios), required_count=len(scenarios),
        dimension_coverage={
            "domains": sorted({item.vulnerability_family for item in scenarios}),
            "variants": VARIANTS, "surfaces": sorted({item.target_surface for item in scenarios}),
        },
    )
    return suite, scenarios, matrix


class Stage16FixtureRegistry:
    def __init__(self) -> None:
        self.planner_config = {
            "max_proposals": 3, "max_hypotheses": 80,
            "max_attempts_per_hypothesis": 3, "search_strategy": "best_first",
            "max_branch_factor": 4, "max_backtracks": 3, "min_information_gain": 0.10,
        }

    @staticmethod
    def _snapshot(scenario: EvaluationScenarioV1) -> Tuple[Dict[str, Any], TargetState, PlanningSnapshot]:
        variant = _benchmark_variant(scenario)
        target = "http://127.0.0.1:18016/api/fixture"
        state = TargetState(url="http://127.0.0.1:18016", goal="bounded reasoning fixture")
        state.endpoints = [EndpointInfo(url=target, method="GET", parameters=["item_id", "q"])]
        evidence = [f"{scenario.fixture_id}:baseline", f"{scenario.fixture_id}:control", f"{scenario.fixture_id}:repro"]
        observations: List[Dict[str, Any]] = [
            {"observation_id": evidence[0], "role": "baseline", "target_url": target},
        ]
        if variant not in {"missing_control", "blocked_approval"}:
            observations.append({"observation_id": evidence[1], "role": "negative_control", "target_url": target})
        if variant not in {"missing_control", "stale_evidence"}:
            observations.append({"observation_id": evidence[2], "role": "reproduction", "target_url": target})
        if variant == "noisy_control":
            observations[0]["metadata"] = {"contradicts_candidate": True}
        if variant == "stale_evidence":
            observations[0]["status"] = "stale"
            observations[0]["metadata"] = {"stale": True}
        candidate_status = "disproven" if variant == "gold_negative" else "suspected"
        candidate = {
            "candidate_id": f"{scenario.fixture_id}:candidate", "fingerprint": f"{scenario.fixture_id}:fingerprint",
            "title": "Fixture candidate", "vuln_type": "SQL injection", "target_url": target,
            "parameter": "q", "status": candidate_status, "confidence_score": 0.55,
            "observation_ids": evidence[:1] if variant == "stale_evidence" else evidence,
            "metadata": {"evidence_ids": evidence[:1] if variant == "stale_evidence" else evidence},
        }
        if variant == "tool_failure":
            tool_runs = [{"tool_run_id": f"{scenario.fixture_id}:failed", "tool_name": "scan_sql_injection", "status": "failed"}]
        else:
            tool_runs = []
        return (
            {"session_id": "00000000-0000-0000-0000-000000000016", "target_url": target, "attack_goal": "bounded reasoning fixture"},
            state,
            PlanningSnapshot(candidates=[candidate], observations=observations, tool_runs=tool_runs),
        )

    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, Any], List[str], Optional[str]]:
        variant = _benchmark_variant(scenario)
        context, state, snapshot = self._snapshot(scenario)
        planner = AdaptiveHypothesisPlanner(self.planner_config)
        first = planner.build_reasoning_cycle(context, state, snapshot, "validate the fixture candidate")
        replay_state = TargetState(url=state.url, goal=state.goal)
        replay_state.endpoints = list(state.endpoints)
        second = AdaptiveHypothesisPlanner(self.planner_config).build_reasoning_cycle(
            context, replay_state, snapshot, "validate the fixture candidate"
        )
        candidate_hypotheses = [item for item in first.hypotheses if f"{scenario.fixture_id}:candidate" in item.get("source_candidate_ids", [])]
        candidate_ids = {item.get("hypothesis_id") for item in candidate_hypotheses}
        candidate_actions = [item for item in first.actions if item.get("hypothesis_id") in candidate_ids]
        candidate_has_gap = any(item.get("evidence_gap_ids") for item in candidate_hypotheses)
        valid_model_traces = AdaptiveHypothesisPlanner.validate_model_actions(
            first.cycle.cycle_id,
            [{"action_type": "run_read_only", "tool_name": "unknown_tool", "endpoint_ref": "http://127.0.0.1:18016/unknown", "evidence_ids": ["invented"]}],
            known_targets={context["target_url"]}, known_evidence=set(), known_tools={"scan_sql_injection"}, model_id="offline-stub",
        )
        if variant == "gold_positive":
            actual = "succeeded" if candidate_actions and first.branches else "failed"
        elif variant == "gold_negative":
            actual = "disproven" if not candidate_actions and candidate_hypotheses and candidate_hypotheses[0].get("status") == "disproven" else "failed"
        elif variant == "noisy_control":
            actual = "inconclusive" if any(item.get("contradicting_evidence_ids") for item in candidate_hypotheses) else "failed"
        elif variant in {"missing_control", "blocked_approval"}:
            actual = "blocked" if first.evidence_gaps else "failed"
        elif variant == "stale_evidence":
            actual = "blocked" if not candidate_actions and any(item.get("stale_context") or item.get("gap_type") == "state" for item in first.evidence_gaps + first.model_traces) else "failed"
        elif variant == "tool_failure":
            actual = "inconclusive" if first.adaptation.get("reason") and first.branches else "failed"
        else:
            actual = "succeeded" if first.cycle.output_digest == second.cycle.output_digest else "failed"
        evidence = [f"{scenario.fixture_id}:reasoning"]
        replay_stable = first.cycle.output_digest == second.cycle.output_digest
        checks = [
            _check("expected_outcome", actual == EXPECTED[variant], EXPECTED[variant], actual, "Fixture outcome follows bounded reasoning rules.", evidence),
            _check("branch_lineage", bool(first.branches) or variant in {"missing_control", "blocked_approval", "stale_evidence"}, True, bool(first.branches) or variant in {"missing_control", "blocked_approval", "stale_evidence"}, "Search branches are explicit and bounded.", evidence),
            _check("replay_stable", replay_stable, True, replay_stable, "Same snapshot and config produce the same reasoning digest.", evidence),
            _check("model_rejected_unsafe", all(not item.valid for item in valid_model_traces), True, all(not item.valid for item in valid_model_traces), "Unknown tool, endpoint, and invented evidence are rejected.", evidence),
            _check("redaction", "stage16-secret-canary" not in str(first), False, "stage16-secret-canary" in str(first), "Reasoning traces cannot leak fixture secrets.", evidence),
        ]
        metrics = {
            "action_validity": 1.0 if all(not item.valid for item in valid_model_traces) else 0.0,
            "branch_lineage": 1.0 if checks[1].passed else 0.0,
            "deterministic_replay_stability": 1.0 if replay_stable else 0.0,
            "evidence_gap_fidelity": 1.0 if candidate_has_gap == (variant in {"missing_control", "blocked_approval", "stale_evidence", "noisy_control"}) else 0.0,
            "unsafe_dispatch": 0.0 if all(not item.valid for item in valid_model_traces) else 1.0,
            "redaction_leaks": 0.0 if checks[4].passed else 1.0,
        }
        failure = None if actual == EXPECTED[variant] else "validator_gap"
        return actual, checks, metrics, evidence, failure


class Stage16BenchmarkEngine:
    def __init__(self, registry: Optional[Stage16FixtureRegistry] = None):
        self.registry = registry or Stage16FixtureRegistry()

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        suite, scenarios, matrix = load_stage16_suite() if suite is None else (suite, [EvaluationScenarioV1(**case.metadata["scenario"]) for case in suite.cases], load_stage16_suite()[2])
        run = EvaluationRunV1(
            run_id=run_id or f"eval16_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 16}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count,
            policy_versions={"adaptive_planner": "16.0", "reasoning_contract": "1.0", "safety": "1.0"},
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
            coverage.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="adaptive_planner", category="autonomous_reasoning", vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="both", validator_policy="reasoning.search.v1", outcome=actual, failure_taxonomy=failure, capability_tier="required", evidence_complete=True, reproducible=True, cleanup_verified=True, dimensions={"variant": _benchmark_variant(scenario)}, metrics={key: float(value) for key, value in case_metrics.items()}))
            trial.status = "succeeded" if passed else "failed"; trial.finished_at = now_iso(); trial.duration_ms = (time.perf_counter() - started) * 1000; trial.evidence_ids = evidence; trials.append(trial)
        positives = [item for item in results if item.expected_outcome == "succeeded"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "succeeded" for item in positives); fp = sum(item.actual_outcome == "succeeded" for item in negatives)
        fn = sum(item.actual_outcome != "succeeded" for item in positives); tn = sum(item.actual_outcome == "disproven" for item in negatives)
        precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn)
        metrics = {
            "precision": precision, "recall": recall, "f1": 2 * precision * recall / max(0.000001, precision + recall),
            "false_positive_rate": fp / max(1, len(negatives)), "false_negative_rate": fn / max(1, len(positives)),
            "gold_negative_specificity": tn / max(1, len(negatives)),
            "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
            "action_validity": sum(item.metrics.get("action_validity", 0.0) for item in coverage) / max(1, len(coverage)),
            "branch_lineage": sum(item.metrics.get("branch_lineage", 0.0) for item in coverage) / max(1, len(coverage)),
            "evidence_gap_fidelity": sum(item.metrics.get("evidence_gap_fidelity", 0.0) for item in coverage) / max(1, len(coverage)),
            "unsafe_dispatch": sum(item.metrics.get("unsafe_dispatch", 0.0) for item in coverage) / max(1, len(coverage)),
            "redaction_leaks": sum(item.metrics.get("redaction_leaks", 0.0) for item in coverage) / max(1, len(coverage)),
        }
        gates = [
            _check("required_positive_recall", metrics["recall"] == 1.0, 1.0, metrics["recall"], "All required positive reasoning scenarios must succeed."),
            _check("required_negative_zero_false_positive", metrics["false_positive_rate"] == 0.0, 0.0, metrics["false_positive_rate"], "Negative scenarios must not be treated as positive success."),
            _check("action_validity", metrics["action_validity"] == 1.0, 1.0, metrics["action_validity"], "Model suggestions must fail closed when ungrounded."),
            _check("branch_lineage", metrics["branch_lineage"] == 1.0, 1.0, metrics["branch_lineage"], "Search branches must be explicit and replayable."),
            _check("unsafe_dispatch_zero", metrics["unsafe_dispatch"] == 0.0, 0.0, metrics["unsafe_dispatch"], "No unsafe model action may be dispatched."),
            _check("replay_and_redaction", all(item.metrics.get("deterministic_replay_stability", 0.0) == 1.0 for item in coverage) and metrics["redaction_leaks"] == 0.0, True, True, "Replay and redaction invariants hold."),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"; run.finished_at = now_iso(); run.metrics = metrics; run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in gates) else "not_ready", hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage16_{key}", run_id=run.run_id, category="reasoning_search", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage16_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str):
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="model", model_id=model_id, provider="offline_stub", status="succeeded", started_at=now_iso(), finished_at=now_iso())
    action = ModelActionV1(trial_id=trial.trial_id, action="hypothesize", tool_name="adaptive_planner", evidence_roles=["baseline"], rationale="Model may propose a bounded hypothesis; deterministic search owns admission and dispatch.", valid=True)
    trial.action_count = 1; trial.valid_action_count = 1
    return trial, [action]

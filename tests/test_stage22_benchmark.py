from core.stage22_benchmark import (
    STAGE22_SUITE_ID,
    Stage22BenchmarkEngine,
    load_stage22_suite,
    run_stage22_model_shadow_trial,
)


def test_stage22_manifest_has_eight_domains_and_48_cases():
    suite, scenarios, matrix = load_stage22_suite()

    assert suite.suite_id == STAGE22_SUITE_ID
    assert len(scenarios) == 48
    assert len(suite.cases) == 48
    assert matrix.required_count == 48
    assert len(matrix.dimension_coverage["domains"]) == 8


def test_stage22_deterministic_gate_and_replay_are_ready():
    suite, _, _ = load_stage22_suite()
    engine = Stage22BenchmarkEngine()
    first = engine.run_suite(suite, run_id="stage22-test", seed=7, trial_number=1, trial_count=3)
    second = engine.run_suite(suite, run_id="stage22-test-replay", seed=7, trial_number=2, trial_count=3)

    first_run, first_results, _, first_gate, _, first_coverage, _ = first
    second_run, second_results, _, second_gate, _, second_coverage, _ = second
    assert first_run.status == second_run.status == "succeeded"
    assert first_gate.decision == second_gate.decision == "ready"
    assert first_gate.metrics["asset_recall"] == 1.0
    assert first_gate.metrics["false_positive_rate"] == 0.0
    assert first_gate.metrics["registry_violations"] == 0.0
    assert [(item.case_id, item.actual_outcome) for item in first_results] == [(item.case_id, item.actual_outcome) for item in second_results]
    assert len(first_coverage) == len(second_coverage) == 48


def test_stage22_inconclusive_and_cleanup_failure_remain_visible():
    suite, _, _ = load_stage22_suite()
    _, results, _, gate, _, coverage, _ = Stage22BenchmarkEngine().run_suite(suite)

    assert gate.decision == "ready"
    assert any(item.actual_outcome == "inconclusive" for item in results)
    assert any(item.actual_outcome == "failed" for item in results)
    assert any(item.failure_taxonomy == "cleanup_error" for item in coverage)
    assert gate.metrics["inconclusive_rate"] > 0.0
    assert gate.metrics["cleanup_success"] < 1.0


def test_stage22_model_trial_is_diagnostic_only():
    _, scenarios, _ = load_stage22_suite()
    trial, actions = run_stage22_model_shadow_trial(
        "stage22-model-test", scenarios[0], trial_number=1, trial_count=3
    )

    assert trial.status == "succeeded"
    assert trial.mode == "hybrid"
    assert trial.provider == "offline_stub"
    assert all(action.valid for action in actions)
    assert all(action.action != "validated" for action in actions)

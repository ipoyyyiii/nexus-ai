from core.stage23_benchmark import (
    STAGE23_SUITE_ID,
    Stage23BenchmarkEngine,
    load_stage23_suite,
    run_stage23_model_shadow_trial,
)


def test_stage23_manifest_has_12_domains_and_72_cases():
    suite, scenarios, matrix = load_stage23_suite()

    assert suite.suite_id == STAGE23_SUITE_ID
    assert len(scenarios) == 72
    assert len(suite.cases) == 72
    assert matrix.required_count == 72
    assert len(matrix.dimension_coverage["domains"]) == 12


def test_stage23_real_surface_compiler_gate_is_ready_and_replayable():
    suite, _, _ = load_stage23_suite()
    engine = Stage23BenchmarkEngine()
    first = engine.run_suite(suite, run_id="stage23-test-a", seed=11, trial_number=1, trial_count=3)
    second = engine.run_suite(suite, run_id="stage23-test-b", seed=11, trial_number=2, trial_count=3)

    first_run, first_results, _, first_gate, _, first_coverage, _ = first
    second_run, second_results, _, second_gate, _, second_coverage, _ = second
    assert first_run.status == second_run.status == "succeeded"
    assert first_gate.decision == second_gate.decision == "ready"
    assert first_gate.metrics["endpoint_recall"] == 1.0
    assert first_gate.metrics["parameter_recall"] == 1.0
    assert first_gate.metrics["method_preservation"] == 1.0
    assert first_gate.metrics["schema_discovery"] == 1.0
    assert first_gate.metrics["protocol_surface_coverage"] == 1.0
    assert first_gate.metrics["scope_enforcement"] == 1.0
    assert [(item.case_id, item.actual_outcome) for item in first_results] == [(item.case_id, item.actual_outcome) for item in second_results]
    assert len(first_coverage) == len(second_coverage) == 72


def test_stage23_inconclusive_and_cleanup_failure_are_not_hidden():
    suite, _, _ = load_stage23_suite()
    _, results, _, gate, _, coverage, _ = Stage23BenchmarkEngine().run_suite(suite)

    assert gate.decision == "ready"
    assert any(item.actual_outcome == "inconclusive" for item in results)
    assert any(item.actual_outcome == "failed" for item in results)
    assert any(item.failure_taxonomy == "cleanup_error" for item in coverage)
    assert gate.metrics["inconclusive_rate"] > 0.0
    assert gate.metrics["cleanup_success"] < 1.0


def test_stage23_model_trial_cannot_create_finding():
    _, scenarios, _ = load_stage23_suite()
    trial, actions = run_stage23_model_shadow_trial(
        "stage23-model-test", scenarios[0], trial_number=1, trial_count=3
    )

    assert trial.status == "succeeded"
    assert trial.mode == "hybrid"
    assert trial.provider == "offline_stub"
    assert all(action.valid for action in actions)
    assert all(action.action != "validated" for action in actions)

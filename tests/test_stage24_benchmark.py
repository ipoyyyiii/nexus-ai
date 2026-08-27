from core.recon_orchestrator import ReconOrchestrator
from core.stage24_benchmark import (
    STAGE24_SUITE_ID,
    Stage24BenchmarkEngine,
    Stage24FixtureRegistry,
    load_stage24_suite,
    run_stage24_model_shadow_trial,
)


def test_stage24_manifest_has_12_domains_and_72_cases():
    suite, scenarios, matrix = load_stage24_suite()

    assert suite.suite_id == STAGE24_SUITE_ID
    assert len(scenarios) == 72
    assert len(suite.cases) == 72
    assert matrix.required_count == 72
    assert len(matrix.dimension_coverage["domains"]) == 12


def test_stage24_fingerprint_gate_is_ready_and_replayable():
    suite, _, _ = load_stage24_suite()
    engine = Stage24BenchmarkEngine()
    first = engine.run_suite(suite, run_id="stage24-test-a", seed=23, trial_number=1, trial_count=3)
    second = engine.run_suite(suite, run_id="stage24-test-b", seed=23, trial_number=2, trial_count=3)

    first_run, first_results, _, first_gate, _, first_coverage, _ = first
    second_run, second_results, _, second_gate, _, second_coverage, _ = second
    assert first_run.status == second_run.status == "succeeded"
    assert first_gate.decision == second_gate.decision == "ready"
    assert first_gate.metrics["fingerprint_recall"] == 1.0
    assert first_gate.metrics["scope_enforcement"] == 1.0
    assert first_gate.metrics["provenance_completeness"] == 1.0
    assert first_gate.metrics["version_confidence_safety"] == 1.0
    assert first_gate.metrics["redaction_leaks"] == 0.0
    assert [(item.case_id, item.actual_outcome) for item in first_results] == [(item.case_id, item.actual_outcome) for item in second_results]
    assert len(first_coverage) == len(second_coverage) == 72


def test_stage24_conflicts_and_cleanup_failures_remain_visible():
    suite, scenarios, _ = load_stage24_suite()
    registry = Stage24FixtureRegistry()
    noisy = next(item for item in scenarios if item.variant == "noisy_control")
    cleanup = next(item for item in scenarios if item.variant == "cleanup_failure")
    noisy_outcome, _, _, _, noisy_failure = registry.run(noisy)
    cleanup_outcome, _, _, _, cleanup_failure = registry.run(cleanup)

    assert noisy_outcome == "inconclusive"
    assert noisy_failure == "inconclusive"
    assert cleanup_outcome == "failed"
    assert cleanup_failure == "cleanup_error"


def test_stage24_redacts_cookie_value_and_rejects_external_asset_signal():
    suite, scenarios, _ = load_stage24_suite()
    positive = next(item for item in scenarios if item.variant == "gold_positive")
    results = Stage24FixtureRegistry()._results(positive)
    compiled = ReconOrchestrator.knowledge_sources("http://fixture.local/", [], results)
    text = str(compiled["technology_inventory"])

    assert "stage24-secret-canary" not in text
    assert "external.invalid" not in text
    assert compiled["technology_inventory"]["digest"]


def test_stage24_model_shadow_cannot_create_finding():
    _, scenarios, _ = load_stage24_suite()
    trial, actions = run_stage24_model_shadow_trial(
        "stage24-model-test", scenarios[0], trial_number=1, trial_count=3
    )

    assert trial.status == "succeeded"
    assert trial.mode == "hybrid"
    assert trial.provider == "offline_stub"
    assert all(action.valid for action in actions)
    assert all(action.action != "validated" for action in actions)

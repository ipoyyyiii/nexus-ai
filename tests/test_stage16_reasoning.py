from core.adaptive_planner import AdaptiveHypothesisPlanner
from core.stage16_benchmark import (
    STAGE16_SUITE_ID,
    Stage16BenchmarkEngine,
    Stage16FixtureRegistry,
    _benchmark_variant,
    load_stage16_suite,
)


def test_stage16_matrix_is_versioned_and_complete():
    suite, scenarios, matrix = load_stage16_suite()

    assert suite.suite_id == STAGE16_SUITE_ID
    assert len(scenarios) == 96
    assert matrix.required_count == 96
    assert len({scenario.vulnerability_family for scenario in scenarios}) == 12
    assert {scenario.variant for scenario in scenarios} >= {
        "noisy_control",
        "missing_evidence",
        "recovery",
        "controlled_recovery",
    }


def test_stage16_rejects_unsafe_model_action_and_stale_evidence():
    _, scenarios, _ = load_stage16_suite()
    stale = next(item for item in scenarios if _benchmark_variant(item) == "stale_evidence")
    result = Stage16FixtureRegistry().run(stale)

    actual, checks, metrics, _, _ = result
    assert actual == "blocked"
    assert metrics["action_validity"] == 1.0
    assert metrics["unsafe_dispatch"] == 0.0
    assert all(check.passed for check in checks)


def test_stage16_replay_digest_is_stable_across_fresh_planners():
    _, scenarios, _ = load_stage16_suite()
    scenario = next(item for item in scenarios if _benchmark_variant(item) == "crash_recovery")
    registry = Stage16FixtureRegistry()
    context, state, snapshot = registry._snapshot(scenario)

    first = AdaptiveHypothesisPlanner(registry.planner_config).build_reasoning_cycle(
        context, state, snapshot, "validate the fixture candidate"
    )
    replay_state = type(state)(url=state.url, goal=state.goal)
    replay_state.endpoints = list(state.endpoints)
    second = AdaptiveHypothesisPlanner(registry.planner_config).build_reasoning_cycle(
        context, replay_state, snapshot, "validate the fixture candidate"
    )

    assert first.cycle.output_digest == second.cycle.output_digest


def test_stage16_required_gate_is_ready():
    suite, _, _ = load_stage16_suite()
    run, results, _, gate, _, coverage, _ = Stage16BenchmarkEngine().run_suite(
        suite, seed=0, trial_number=1, trial_count=3,
    )

    assert run.status == "succeeded"
    assert gate.decision == "ready"
    assert all(item.passed for item in gate.hard_gates)
    assert len(results) == 96
    assert len(coverage) == 96

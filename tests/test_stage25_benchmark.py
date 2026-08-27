from core.recon_orchestrator import ReconOrchestrator
from core.knowledge_graph_engine import TargetKnowledgeGraphEngine
from core.stage25_benchmark import (
    STAGE25_SUITE_ID,
    Stage25BenchmarkEngine,
    load_stage25_suite,
    run_stage25_model_shadow_trial,
)


def test_stage25_manifest_has_12_domains_and_72_cases():
    suite, scenarios, matrix = load_stage25_suite()
    assert suite.suite_id == STAGE25_SUITE_ID
    assert len(scenarios) == 72
    assert len(suite.cases) == 72
    assert matrix.scenario_count == 72


def test_stage25_contract_gate_is_ready_and_replayable():
    suite, _, _ = load_stage25_suite()
    engine = Stage25BenchmarkEngine()
    first = engine.run_suite(suite, run_id="stage25-test-a", seed=25, trial_number=1, trial_count=3)
    second = engine.run_suite(suite, run_id="stage25-test-b", seed=25, trial_number=2, trial_count=3)
    assert first[0].status == "succeeded"
    assert first[3].decision == "ready"
    assert second[3].decision == "ready"
    assert [(item.case_id, item.actual_outcome) for item in first[1]] == [(item.case_id, item.actual_outcome) for item in second[1]]


def test_stage25_semantics_and_mutation_approval_are_typed():
    registry = Stage25BenchmarkEngine().registry
    _, scenarios, _ = load_stage25_suite()
    scenario = next(item for item in scenarios if item.variant == "gold_positive")
    results = registry._results(scenario)
    sources = ReconOrchestrator.knowledge_sources(registry.target, [], results)
    operations = sources["application_operations"]
    inputs = sources["input_semantics"]
    assert {item["metadata"]["operation_kind"] for item in operations} >= {"read", "create", "update", "delete", "auth", "transition", "upload", "stream"}
    assert {item["metadata"]["semantic_type"] for item in inputs} >= {"identifier", "tenant", "identity", "state", "money", "redirect", "file", "credential"}
    mutation_hints = [item for item in sources["contract_capabilities"] if item["risk"] == "mutation"]
    assert mutation_hints
    assert all(item["approval_required"] and "exact_approval" in item["prerequisites"] for item in mutation_hints)


def test_stage25_noisy_and_cleanup_states_remain_visible():
    suite, scenarios, _ = load_stage25_suite()
    engine = Stage25BenchmarkEngine()
    noisy = next(item for item in scenarios if item.variant == "noisy_control")
    cleanup = next(item for item in scenarios if item.variant == "cleanup_failure")
    noisy_result = engine.registry.run(noisy)
    cleanup_result = engine.registry.run(cleanup)
    assert noisy_result[0] == "inconclusive"
    assert noisy_result[4] == "inconclusive"
    assert cleanup_result[0] == "failed"
    assert cleanup_result[4] == "cleanup_error"


def test_stage25_redacts_secret_and_rejects_external_capture():
    _, scenarios, _ = load_stage25_suite()
    scenario = next(item for item in scenarios if item.variant == "gold_positive")
    registry = Stage25BenchmarkEngine().registry
    sources = ReconOrchestrator.knowledge_sources(registry.target, [], registry._results(scenario))
    assert "stage25-secret-canary" not in str(sources["application_contract_inventory"])
    assert "external.invalid" not in str(sources["application_contract_inventory"])


def test_stage25_contract_compiles_into_existing_knowledge_graph():
    _, scenarios, _ = load_stage25_suite()
    registry = Stage25BenchmarkEngine().registry
    scenario = next(item for item in scenarios if item.variant == "gold_positive")
    sources = ReconOrchestrator.knowledge_sources(registry.target, [], registry._results(scenario))
    compiled = TargetKnowledgeGraphEngine().compile(
        "stage25-graph-test", registry.target, sources, scope={"allow": [registry.target]},
    )
    assert compiled["graph"]["status"] == "current"
    assert any(item["node_type"] == "operation" for item in compiled["nodes"])
    assert any(item["node_type"] == "input" for item in compiled["nodes"])
    assert compiled["edges"]


def test_stage25_model_shadow_cannot_create_finding():
    _, scenarios, _ = load_stage25_suite()
    trial, actions = run_stage25_model_shadow_trial("stage25-model-test", scenarios[0], trial_number=1, trial_count=3)
    assert trial.mode == "hybrid"
    assert all(action.valid for action in actions)
    assert {action.action for action in actions} == {"observe", "stop"}

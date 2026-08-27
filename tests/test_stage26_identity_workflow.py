import json
from pathlib import Path

from core.authorization_discovery import capture_auth_surface
from core.knowledge_graph_engine import TargetKnowledgeGraphEngine
from core.recon_orchestrator import ReconOrchestrator
from core.stage26_benchmark import (
    STAGE26_SUITE_ID,
    Stage26BenchmarkEngine,
    Stage26FixtureRegistry,
    load_stage26_suite,
    run_stage26_model_shadow_trial,
)
from core.workflow_discovery import workflow_discovery_service


def test_stage26_manifest_is_versioned_and_complete():
    suite, scenarios, matrix = load_stage26_suite()
    assert suite.suite_id == STAGE26_SUITE_ID
    assert suite.manifest_digest
    assert matrix.fixture_digest
    assert len(scenarios) == 72
    assert len({item.vulnerability_family for item in scenarios}) == 12
    assert {item.variant for item in scenarios} == {
        "gold_positive", "gold_negative", "noisy_control", "missing_control",
        "clean_reproduction", "cleanup_failure",
    }


def test_stage26_deterministic_gate_and_replay_are_stable():
    suite, _, _ = load_stage26_suite()
    engine = Stage26BenchmarkEngine()
    first = engine.run_suite(suite, seed=26, trial_number=1, trial_count=3)
    second = engine.run_suite(suite, seed=26, trial_number=2, trial_count=3)
    first_run, first_results, _, first_gate, _, _, _ = first
    second_run, second_results, _, second_gate, _, _, _ = second
    assert first_run.status == second_run.status == "succeeded"
    assert first_gate.decision == second_gate.decision == "ready"
    assert [(x.case_id, x.actual_outcome) for x in first_results] == [
        (x.case_id, x.actual_outcome) for x in second_results
    ]
    assert first_run.metrics["redaction_leaks"] == 0.0
    assert first_run.metrics["scope_enforcement"] == 1.0
    assert first_run.metrics["identity_isolation"] == 1.0


def test_auth_surface_detection_prioritizes_path_and_redacts_secrets():
    surfaces, transitions, gaps = capture_auth_surface(
        [
            {
                "url": "http://fixture.local/login",
                "method": "POST",
                "post_data": {"username": "alice", "password": "stage26-secret-canary"},
                "response_body": {"access_token": "stage26-secret-canary"},
                "response_headers": {"set-cookie": "session=stage26-secret-canary"},
                "response_status": 200,
                "observation_id": "login-evidence",
            },
            {
                "url": "http://fixture.local/logout",
                "method": "POST",
                "response_status": 204,
                "observation_id": "logout-evidence",
            },
        ],
        "session-26",
    )
    assert surfaces[0].event == "login"
    assert {item.event for item in surfaces} == {"login", "logout"}
    assert {item.event for item in transitions} == {"login", "logout"}
    serialized = json.dumps([item.model_dump(mode="json") for item in surfaces + transitions])
    assert "stage26-secret-canary" not in serialized
    assert "token_refresh_not_observed" in gaps


def test_workflow_compiler_filters_external_capture_and_requires_cleanup():
    result = workflow_discovery_service.discover_intelligence(
        "session-26",
        "http://fixture.local/",
        "checkout workflow",
        [
            {
                "url": "http://fixture.local/checkout",
                "state": "cart",
                "next_states": ["submitted"],
                "forms": [{
                    "action": "/checkout",
                    "method": "POST",
                    "inputs": [{"name": "order_id"}, {"name": "csrf_token"}],
                }],
                "observation_id": "checkout-evidence",
            },
            {"url": "http://external.invalid/steal", "forms": [{"action": "/x", "inputs": [{"name": "token"}]}]},
        ],
        ["identity-owner"],
    )
    workflow = result["workflow"]
    assert workflow["state_graph"] == {"cart": ["submitted"]}
    assert result["mutating"] is True
    assert "cleanup_workflow_required_for_mutation" in result["gaps"]
    assert all("external.invalid" not in json.dumps(item) for item in result["prerequisites"])


def test_identity_workflow_sources_compile_into_graph_edges():
    suite, scenarios, _ = load_stage26_suite()
    registry = Stage26FixtureRegistry()
    sources = ReconOrchestrator.identity_workflow_sources(
        registry.target,
        registry._results(scenarios[0]),
        session_id="fixture-session",
        identity_ids=["identity-owner", "identity-non-owner"],
        goal="map identity workflow",
    )
    sources["origins"] = [{"reference_id": "fixture-origin", "url": registry.target}]
    sources["identities"] = [
        {"reference_id": "identity-owner", "identity_id": "identity-owner", "label": "owner"},
        {"reference_id": "identity-non-owner", "identity_id": "identity-non-owner", "label": "non-owner"},
    ]
    sources["edges"] = sources.pop("identity_workflow_edges")
    compiled = TargetKnowledgeGraphEngine().compile(
        "fixture-session", registry.target, sources, scope={"allow": [registry.target]}
    )
    node_types = {item["node_type"] for item in compiled["nodes"]}
    relations = {item["relation"] for item in compiled["edges"]}
    assert {"auth_surface", "session_transition", "prerequisite", "workflow"}.issubset(node_types)
    assert {"guards", "prerequisite_for"}.issubset(relations)


def test_stage26_model_shadow_cannot_validate_or_mutate():
    _, scenarios, _ = load_stage26_suite()
    trial, actions = run_stage26_model_shadow_trial(
        "eval26-test", scenarios[0], trial_number=1, trial_count=3, model_id="offline-stub"
    )
    assert trial.mode == "hybrid"
    assert [item.action for item in actions] == ["observe", "stop"]
    assert all(item.valid for item in actions)
    assert not any(item.action in {"submit", "validated", "run_mutation"} for item in actions)


def test_stage26_migration_and_manifest_are_present():
    assert Path("migrations/022_identity_workflow_intelligence.sql").exists()
    assert Path("benchmarks/stage26/identity_workflow_suite.yaml").exists()

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from benchmarks.stage8.fixture_app import app
from core.evaluation_contract import ModelActionV1, content_digest
from core.stage8_benchmark import Stage8BenchmarkEngine, load_stage8_suite, validate_model_action


def test_stage8_manifest_has_48_immutable_scenarios_and_visible_diagnostics():
    suite, scenarios, matrix = load_stage8_suite()
    assert suite.suite_id == "stage8-webapi-foundation"
    assert len(suite.cases) == 48
    assert len(scenarios) == 48
    assert matrix.scenario_count == 48
    assert matrix.required_count == 24
    assert matrix.diagnostic_count == 24
    assert "idor_tenant_isolation" in matrix.unsupported_capabilities
    assert len({item.fingerprint() for item in scenarios}) == 48


def test_stage8_deterministic_gate_and_diagnostics_are_separate():
    engine = Stage8BenchmarkEngine()
    suite = engine.load_suite()
    run, results, snapshots, gate, matrix, coverage, trials = engine.run_suite(suite, seed=17, trial_count=3)
    assert run.status == "succeeded"
    assert gate.decision == "ready"
    assert run.metrics["precision"] == 1.0
    assert run.metrics["recall"] == 1.0
    assert run.metrics["false_positive_rate"] == 0.0
    assert run.metrics["false_negative_rate"] == 0.0
    assert run.metrics["unsupported_capability_count"] == 24
    assert sum(item.status == "inconclusive" for item in results) == 24
    assert all(item.capability_tier == "diagnostic" for item in coverage if item.failure_taxonomy == "unsupported_capability")


def test_stage8_replay_same_seed_has_stable_outcome_digest():
    engine = Stage8BenchmarkEngine()
    suite = engine.load_suite()
    first = engine.run_suite(suite, seed=99)[1]
    second = engine.run_suite(suite, seed=99)[1]
    digest = lambda items: content_digest([(item.case_id, item.status, item.actual_outcome) for item in items])
    assert digest(first) == digest(second)


def test_stage8_model_cannot_invent_endpoint_or_finding_state():
    action = ModelActionV1(
        trial_id="trial-test",
        action="run_read_only",
        tool_name="stage8_fixture",
        endpoint_ref="https://external.invalid/admin",
        evidence_roles=["validated", "evidence_id"],
        rationale="untrusted model proposal",
    )
    checked = validate_model_action(action)
    assert checked.valid is False
    assert checked.rejection_reason in {"endpoint_outside_local_fixture", "model_cannot_assign_finding_state"}


def test_stage8_fixture_reset_and_state_are_local_and_deterministic():
    client = TestClient(app)
    assert client.get("/health").json()["network"] == "local-only"
    response = client.post("/api/race", json={"amount": 2}, params={"mode": "positive"})
    assert response.status_code == 200
    assert response.json()["effects"] == 2
    reset = client.post("/reset", headers={"X-Stage8-Reset": "local-fixture-reset"})
    assert reset.status_code == 200
    assert client.get("/state").json()["race_effects"] == 0
    assert "stage8-secret" not in json.dumps(client.get("/state").json())

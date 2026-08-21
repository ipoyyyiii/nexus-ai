from __future__ import annotations

from core.detection_validation_v2 import (
    ValidationEngineV2,
    ValidationPolicyRegistryV2,
    ValidationPolicyV2,
)
from core.stage9_benchmark import Stage9BenchmarkEngine, load_stage9_suite
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1


def test_stage9_manifest_has_72_scenarios_and_six_variants():
    suite, scenarios, matrix = load_stage9_suite()
    assert suite.suite_id == "stage9-detection-depth"
    assert len(suite.cases) == len(scenarios) == 72
    assert matrix.scenario_count == 72
    assert len({item.variant for item in scenarios}) == 6
    assert len({item.fingerprint() for item in scenarios}) == 72


def test_stage9_deterministic_gate_has_zero_required_fp_fn():
    run, results, _, gate, matrix, coverage, _ = Stage9BenchmarkEngine().run_suite(seed=41)
    assert run.status == "succeeded"
    assert gate.decision == "ready"
    assert matrix.scenario_count == 72
    assert run.metrics["false_positive_rate"] == 0.0
    assert run.metrics["false_negative_rate"] == 0.0
    assert run.metrics["evidence_completeness"] == 1.0
    assert all(item.status == "passed" for item in results)
    assert len(coverage) == 72


def test_stage9_same_seed_replays_same_outcomes():
    engine = Stage9BenchmarkEngine()
    first = engine.run_suite(seed=123)[1]
    second = engine.run_suite(seed=123)[1]
    assert [(item.case_id, item.status, item.actual_outcome) for item in first] == [(item.case_id, item.status, item.actual_outcome) for item in second]


def test_v2_missing_control_cannot_validate():
    observations = [
        ObservationV1(observation_id="base", role="baseline", response_excerpt="safe"),
        ObservationV1(observation_id="test", role="test", response_excerpt="SQLSTATE[42000]"),
        ObservationV1(observation_id="repro", role="reproduction", response_excerpt="SQLSTATE[42000]"),
    ]
    candidate = CandidateFindingV1(title="SQL candidate", vuln_type="sqli", target_url="http://stage9.local", observation_ids=[item.observation_id for item in observations])
    result = ToolResultV1(tool_name="fixture", target="http://stage9.local", observations=observations, candidate_findings=[candidate])
    decision = ValidationEngineV2(mode="strict").validate(result)[0]
    assert decision.decision == "inconclusive"
    assert any(item.check_id == "role_negative_control" and not item.passed for item in decision.checks)


def test_v2_stale_oob_callback_cannot_validate():
    observations = [
        ObservationV1(observation_id="test", role="test"),
        ObservationV1(observation_id="oob", role="oob", metadata={"correlation_id": "old", "target_attributed": True, "stale_callback": True}),
        ObservationV1(observation_id="control", role="negative_control"),
        ObservationV1(observation_id="repro", role="reproduction"),
    ]
    candidate = CandidateFindingV1(title="SSRF candidate", vuln_type="ssrf", target_url="http://stage9.local", observation_ids=[item.observation_id for item in observations])
    result = ToolResultV1(tool_name="fixture", target="http://stage9.local", observations=observations, candidate_findings=[candidate])
    decision = ValidationEngineV2(mode="strict").validate(result)[0]
    assert decision.decision == "inconclusive"
    assert decision.failure_classification == "stale_evidence"


def test_policy_registry_is_versioned_and_duplicate_ids_are_rejected():
    registry = ValidationPolicyRegistryV2()
    assert registry.VERSION == "2.0"
    assert registry.get("idor.tenant_isolation.v2").fingerprint()
    policy = ValidationPolicyV2(policy_id="one", vulnerability_family="x")
    try:
        ValidationPolicyRegistryV2([policy, policy])
    except ValueError as exc:
        assert "Duplicate" in str(exc)
    else:
        raise AssertionError("duplicate policy IDs must fail closed")

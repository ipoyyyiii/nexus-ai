from __future__ import annotations

import json

from core.detection_validation_v2 import (
    ValidationEngineV2,
    ValidationPolicyRegistryV2,
    ValidationPolicyV2,
)
from core.stage9_benchmark import Stage9BenchmarkEngine, load_stage9_suite
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1
from core.structured_contract import result_from_legacy


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


def test_legacy_missing_header_is_validated_as_observed_exposure():
    result = result_from_legacy(
        "misconfiguration_scanner",
        "http://stage9.local/",
        json.dumps({
            "high": [{
                "type": "Missing Security Header: Content-Security-Policy",
                "detail": "Header 'Content-Security-Policy' not present — High security risk",
                "severity": "High",
            }],
        }),
    )
    decision = ValidationEngineV2(mode="strict").validate(result, mode="strict")[0]
    assert decision.policy_id == "misconfiguration.exposure.v2"
    assert decision.decision == "validated"
    assert result.candidate_findings[0].status == "validated"


def test_legacy_cors_header_signal_does_not_claim_credentialed_impact():
    result = result_from_legacy(
        "misconfiguration_scanner",
        "http://stage9.local/",
        json.dumps({
            "high": [{
                "type": "CORS Misconfiguration",
                "detail": "Access-Control-Allow-Origin: * — allows arbitrary origin",
                "severity": "High",
            }],
        }),
    )
    decision = ValidationEngineV2(mode="strict").validate(result, mode="strict")[0]
    assert decision.policy_id == "cors.v2"
    assert decision.decision == "inconclusive"


def test_legacy_active_sqli_evidence_can_reach_authoritative_validation():
    result = result_from_legacy(
        "SQL Injection Scanner",
        "http://stage9.local/search",
        json.dumps({
            "vulnerabilities": [{
                "type": "Error-based SQL Injection",
                "parameter": "q",
                "status_code": 500,
                "semantic_test": "passed",
                "validation_evidence": [
                    {"role": "baseline", "kind": "http_exchange", "response_excerpt": "normal" , "metadata": {"iteration": 0}},
                    {"role": "test", "kind": "http_exchange", "response_excerpt": "SQLSTATE[42000] syntax error", "metadata": {"iteration": 1}},
                    {"role": "negative_control", "kind": "http_exchange", "response_excerpt": "normal", "metadata": {"iteration": 1}},
                    {"role": "reproduction", "kind": "http_exchange", "response_excerpt": "SQLSTATE[42000] syntax error", "metadata": {"iteration": 2}},
                ],
            }],
        }),
    )
    decision = ValidationEngineV2(mode="strict").validate(result, mode="strict")[0]
    assert decision.policy_id == "sqli.lfi.v2"
    assert decision.decision == "validated"


def test_legacy_xss_requires_browser_execution_even_when_reflected():
    result = result_from_legacy(
        "XSS & CSRF Detector",
        "http://stage9.local/search",
        json.dumps({
            "xss_vulnerabilities": [{
                "type": "Reflected XSS",
                "reflection_context": "html",
                "marker_executed": False,
                "validation_evidence": [
                    {"role": "test", "kind": "http_exchange", "response_excerpt": "<script>marker</script>"},
                    {"role": "browser", "kind": "browser_execution", "metadata": {"marker_executed": False}},
                    {"role": "negative_control", "kind": "http_exchange", "metadata": {"escaped_control": True}},
                    {"role": "reproduction", "kind": "browser_execution", "metadata": {"stored_retrieval_clean_session": True}},
                ],
            }],
        }),
    )
    decision = ValidationEngineV2(mode="strict").validate(result, mode="strict")[0]
    assert decision.policy_id == "xss.reflected_stored.v2"
    assert decision.decision == "inconclusive"


def test_time_based_sqli_requires_differential_timing_samples():
    samples = {
        "baseline": [90.0, 110.0],
        "test": [5100.0, 5200.0],
        "control": [100.0, 120.0],
    }
    observations = [
        ObservationV1(observation_id="base", role="baseline", response_excerpt="normal", metadata={"timing_samples": samples["baseline"]}),
        ObservationV1(observation_id="test", role="test", response_excerpt="delayed", metadata={"timing_samples": samples["test"]}),
        ObservationV1(observation_id="control", role="negative_control", response_excerpt="normal", metadata={"timing_samples": samples["control"]}),
        ObservationV1(observation_id="repro", role="reproduction", response_excerpt="delayed", metadata={"timing_samples": samples["test"]}),
    ]
    candidate = CandidateFindingV1(
        title="Time-based SQLi candidate",
        vuln_type="Time-based Blind SQLi",
        target_url="http://stage9.local/search",
        observation_ids=[item.observation_id for item in observations],
        metadata={"subtype": "time", "iterations": 2, "timing_samples": samples},
    )
    result = ToolResultV1(
        tool_name="SQL Injection Scanner",
        target="http://stage9.local/search",
        observations=observations,
        candidate_findings=[candidate],
    )
    decision = ValidationEngineV2(mode="strict").validate(result, mode="strict")[0]
    assert decision.policy_id == "sqli.lfi.v2"
    assert decision.decision == "validated"


def test_structured_runner_authoritative_mode_promotes_only_deterministic_decision(monkeypatch):
    import core.structured_runner as runner_module

    monkeypatch.setattr(
        runner_module,
        "get_tool_capability",
        lambda _name: type("Capability", (), {"tool_version": "fixture", "requires_approval": False})(),
    )

    observations = [
        ObservationV1(observation_id="base", role="baseline", response_excerpt="safe"),
        ObservationV1(observation_id="test", role="test", response_excerpt="SQLSTATE[42000]"),
        ObservationV1(observation_id="repro", role="reproduction", response_excerpt="SQLSTATE[42000]"),
    ]
    candidate = CandidateFindingV1(
        title="SQL candidate",
        vuln_type="sqli",
        target_url="http://stage9.local",
        observation_ids=[item.observation_id for item in observations],
    )

    class FakeTool:
        name = "fixture_sqli"

        def invoke(self, _kwargs):
            return ToolResultV1(
                tool_name=self.name,
                target="http://stage9.local",
                observations=observations,
                candidate_findings=[candidate],
            )

    result = runner_module.StructuredToolRunner().execute(
        FakeTool(), {}, "http://stage9.local"
    )

    assert result.candidate_findings[0].status == "inconclusive"
    assert result.metrics["validation_v2"][0]["decision"] == "inconclusive"


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

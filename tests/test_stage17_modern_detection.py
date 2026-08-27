from core.detection_validation_v2 import semantic_response_compare, validation_policy_registry_v2
from core.stage17_benchmark import STAGE17_SUITE_ID, Stage17BenchmarkEngine, load_stage17_suite
from core.structured_contract import ToolResultV1, result_from_legacy
from core.tool_decorator import _typed_function


def test_stage17_matrix_and_gate_are_complete():
    suite, scenarios, matrix = load_stage17_suite()
    assert suite.suite_id == STAGE17_SUITE_ID
    assert len(scenarios) == 96
    assert matrix.required_count == 96
    assert len({item.vulnerability_family for item in scenarios}) == 16

    run, results, _, gate, _, coverage, _ = Stage17BenchmarkEngine().run_suite(
        suite, seed=0, trial_number=1, trial_count=3
    )
    assert run.status == "succeeded"
    assert gate.decision == "ready"
    assert all(item.passed for item in gate.hard_gates)
    assert len(results) == len(coverage) == 96


def test_modern_protocol_registry_resolves_same_v2_policy_family():
    assert validation_policy_registry_v2.resolve("graphql-schema", "introspection") is not None
    assert validation_policy_registry_v2.resolve("websocket-authorization", "tenant") is not None
    assert validation_policy_registry_v2.resolve("oauth-oidc-lifecycle", "pkce") is not None
    assert validation_policy_registry_v2.resolve("jwt-signed-url", "jwt") is not None
    assert validation_policy_registry_v2.resolve("schema-type-confusion", "type_confusion") is not None


def test_semantic_comparison_ignores_transport_noise_but_detects_state_change():
    safe = {"status_code": 200, "response_length": 100, "entity": {"state": "safe"}}
    changed = {
        "status_code": 403,
        "response_length": 120,
        "entity": {"state": "exposed"},
        "replay": {"status_code": 200, "response_length": 99, "entity": {"state": "exposed"}},
    }
    comparison = semantic_response_compare(safe, changed, safe, protocol="graphql")
    assert comparison.semantic_signal is True
    assert comparison.changed_dimensions == ["entity"]
    assert comparison.replay_stable is True
    assert comparison.input_digest


def test_status_or_length_only_does_not_become_semantic_signal():
    comparison = semantic_response_compare(
        {"status_code": 200, "response_length": 100, "entity": "same"},
        {"status_code": 403, "response_length": 120, "entity": "same"},
        {"status_code": 200, "response_length": 100, "entity": "same"},
    )
    assert comparison.semantic_signal is False
    assert comparison.status_only_signal is True
    assert comparison.length_only_signal is True


def test_plain_legacy_protocol_output_is_structured_observation_only():
    result = result_from_legacy(
        "graphql_tester", "http://fixture.local/graphql", "[HIGH] introspection exposure suspected"
    )
    assert isinstance(result, ToolResultV1)
    assert result.legacy_source is True
    assert result.candidate_findings == []
    assert result.observations[0].kind == "legacy_output"


def test_legacy_graphql_boundary_keeps_protocol_metadata_without_promoting_text():
    wrapped = _typed_function(
        lambda target_url: "[HIGH] introspection exposure suspected",
        "graphql_tester",
    )
    result = wrapped("http://fixture.local/graphql")
    assert isinstance(result, ToolResultV1)
    assert result.category == "protocol_surface"
    assert result.observations[0].metadata["protocol"] == "graphql"
    assert result.observations[0].metadata["parser_context"] == "graphql"
    assert result.candidate_findings == []

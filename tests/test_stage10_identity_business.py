from core.authorization_contract import IdentityGraphV1, IdentityRelationV1
from core.browser_workflow_contract import BrowserStepV1, BrowserWorkflowV1
from core.business_logic_engine import BusinessInvariantCompiler
from core.detection_validation_v2 import ValidationEngineV2
from core.identity_workflow_matrix import IdentityWorkflowMatrixCoordinator
from core.stage10_benchmark import Stage10BenchmarkEngine, load_stage10_suite
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1


def _graph() -> IdentityGraphV1:
    return IdentityGraphV1(
        session_id="s10",
        node_ids=["owner", "other"],
        relations=[
            IdentityRelationV1(session_id="s10", subject_id="owner", relation="auth_context_for", object_id="auth-owner", status="active"),
            IdentityRelationV1(session_id="s10", subject_id="other", relation="auth_context_for", object_id="auth-other", status="active"),
        ],
    ).ensure_digest()


def test_stage10_suite_is_60_cases_and_replayable():
    suite, scenarios, matrix = load_stage10_suite()
    assert suite.suite_id == "stage10-identity-business"
    assert len(suite.cases) == len(scenarios) == matrix.scenario_count == 60
    assert len({item.fingerprint() for item in scenarios}) == 60
    first = Stage10BenchmarkEngine().run_suite(seed=17)[1]
    second = Stage10BenchmarkEngine().run_suite(seed=17)[1]
    assert [(item.case_id, item.actual_outcome) for item in first] == [(item.case_id, item.actual_outcome) for item in second]


def test_stage10_deterministic_gate_has_identity_and_business_controls():
    run, results, _, gate, matrix, coverage, _ = Stage10BenchmarkEngine().run_suite(seed=41)
    assert run.status == "succeeded"
    assert gate.decision == "ready"
    assert matrix.scenario_count == 60
    assert run.metrics["recall"] == 1.0
    assert run.metrics["false_positive_rate"] == 0.0
    assert run.metrics["identity_isolation"] == 1.0
    assert run.metrics["workflow_matrix_readiness"] == 1.0
    assert len(coverage) == 60
    assert all(item.status == "passed" for item in results)


def test_identity_workflow_matrix_fails_closed_without_two_auth_contexts():
    workflow = BrowserWorkflowV1(
        session_id="s10", name="journey", origin="http://stage10.local", status="published",
        steps=[BrowserStepV1(action="navigate")],
    )
    matrix = IdentityWorkflowMatrixCoordinator().plan(workflow, _graph(), ["owner"])
    assert matrix.status == "blocked"
    assert "two_isolated_identities_required" in matrix.missing_requirements


def test_identity_workflow_matrix_ready_context_is_dispatchable_read_only():
    workflow = BrowserWorkflowV1(
        session_id="s10", name="journey", origin="http://stage10.local", status="published",
        steps=[BrowserStepV1(action="navigate")],
    )
    matrix = IdentityWorkflowMatrixCoordinator().plan(
        workflow, _graph(), ["owner", "other"], entity_fingerprint="entity-1",
        run_roles={"r1": "baseline", "r2": "negative_control", "r3": "test", "r4": "reproduction"},
    )
    allowed, reason = IdentityWorkflowMatrixCoordinator.can_dispatch(matrix)
    assert matrix.status == "ready"
    assert allowed is True
    assert "permitted" in reason


def test_typed_invariant_requires_target_fields_and_does_not_infer_them():
    compiler = BusinessInvariantCompiler()
    try:
        compiler.compile_typed("server authoritative price invariant", "s10", {"client_field": "price"})
    except ValueError as exc:
        assert "server_field" in str(exc)
    else:
        raise AssertionError("incomplete typed invariant must fail closed")


def test_business_validation_requires_graph_matrix_and_cleanup_context():
    observations = [
        ObservationV1(observation_id="b", role="baseline", kind="state_transition"),
        ObservationV1(observation_id="t", role="test", kind="state_transition"),
        ObservationV1(observation_id="n", role="negative_control", kind="state_transition"),
        ObservationV1(observation_id="r", role="reproduction", kind="state_transition"),
    ]
    candidate = CandidateFindingV1(
        title="business candidate", vuln_type="business_logic", target_url="http://stage10.local",
        observation_ids=[item.observation_id for item in observations],
        metadata={
            "rule_type": "ownership", "typed_rule": True, "evaluation_id": "e1",
            "state_transition_evidence": True, "invariant_violated": True,
            "identity_ids": ["owner", "other"], "reproduced": True,
            "cleanup_verified": False,
        },
    )
    result = ToolResultV1(tool_name="fixture", target="http://stage10.local", observations=observations, candidate_findings=[candidate])
    decision = ValidationEngineV2(mode="strict").validate(result)[0]
    assert decision.decision == "inconclusive"
    assert any(item.check_id == "identity_graph_context" and not item.passed for item in decision.checks)
    assert any(item.check_id == "workflow_entity_mapping" and not item.passed for item in decision.checks)
    assert any(item.check_id == "cleanup_verified" and not item.passed for item in decision.checks)

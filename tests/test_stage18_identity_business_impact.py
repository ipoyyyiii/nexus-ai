from core.business_logic_engine import business_invariant_engine
from core.chain_planner import ChainPlanner
from core.identity_workflow_matrix import IdentityWorkflowMatrixCoordinator
from core.stage18_benchmark import STAGE18_SUITE_ID, Stage18BenchmarkEngine, load_stage18_suite


def test_stage18_matrix_is_120_and_gate_ready():
    suite, scenarios, matrix = load_stage18_suite()
    assert suite.suite_id == STAGE18_SUITE_ID
    assert len(scenarios) == 120
    assert matrix.required_count == 120
    assert len({item.vulnerability_family for item in scenarios}) == 12

    run, results, _, gate, _, coverage, _ = Stage18BenchmarkEngine().run_suite(
        suite, seed=0, trial_number=1, trial_count=3
    )
    assert run.status == "succeeded"
    assert gate.decision == "ready"
    assert all(item.passed for item in gate.hard_gates)
    assert len(results) == len(coverage) == 120


def test_stage18_state_effect_contract_rejects_response_only_proof():
    result = business_invariant_engine.evaluate_effect_contract(
        baseline={"state_digest": "baseline", "evidence_ids": ["b"]},
        control={"state_digest": "control", "effect_count": 0, "evidence_ids": ["c"]},
        test={"response_fingerprint": "different", "evidence_ids": ["t"]},
        reproduction={"clean_context": True, "response_fingerprint": "different", "evidence_ids": ["r"]},
        cleanup={"verified": True, "evidence_ids": ["x"]},
    )
    assert result["decision"] == "inconclusive"
    assert any(item["check_id"] == "test_effect_measured" and not item["passed"] for item in result["checks"])


def test_stage18_idempotency_requires_server_side_effects():
    from core.business_logic_engine import BusinessInvariantV1

    invariant = BusinessInvariantV1(
        session_id="s", name="single use", rule_type="idempotency", compiled=True, rule={}
    )
    evaluation, candidate = business_invariant_engine.evaluate(
        invariant,
        runs=[
            {"result": "success", "response_fingerprint": "a", "evidence_ids": ["one"]},
            {"result": "success", "response_fingerprint": "b", "evidence_ids": ["two"]},
        ],
    )
    assert evaluation.decision == "inconclusive"
    assert candidate is None


def test_stage18_impact_chain_rejects_stale_graph():
    class Sessions:
        @staticmethod
        def require(session_id):
            return {"session_id": session_id, "target_url": "http://fixture.local"}

    planner = ChainPlanner(Sessions())
    graph = {
        "stale": True,
        "chain": {"chain_id": "chain-1", "chain_version": 1},
        "nodes": [{"node_id": "n1", "evidence_ids": ["e1"]}],
        "edges": [],
    }
    result = planner.evaluate_impact_chain(
        "s", graph,
        evidence_roles={"baseline": ["b"], "negative_control": ["c"], "test": ["t"], "reproduction": ["r"]},
        identity_contexts=[{"identity_id": "a", "auth_context_id": "aa"}, {"identity_id": "b", "auth_context_id": "bb"}],
        impact={"server_state_digest": "state", "effect_count": 1, "clean_context": True, "reproduced": True, "cleanup_verified": True},
        approval_present=True, mutation=True,
    )
    assert result["decision"] == "inconclusive"
    assert any(item["check_id"] == "graph_fresh" and not item["passed"] for item in result["checks"])


def test_stage18_identity_matrix_requires_same_resource_semantic_state_and_reproduction():
    attempts = [
        {
            "identity_id": "owner", "auth_context_id": "auth-owner", "role": "baseline",
            "resource_fingerprint": "resource-1", "semantic_result": "allow", "evidence_ids": ["b"],
            "comparison": {"server_state_digest": "owner-state", "resource_fingerprint": "resource-1"},
        },
        {
            "identity_id": "other", "auth_context_id": "auth-other", "role": "test",
            "resource_fingerprint": "resource-1", "semantic_result": "unexpected_allow", "evidence_ids": ["t"],
            "comparison": {"server_state_digest": "private-state", "resource_fingerprint": "resource-1"},
        },
        {
            "identity_id": "other", "auth_context_id": "auth-other", "role": "reproduction",
            "resource_fingerprint": "resource-1", "semantic_result": "unexpected_allow", "evidence_ids": ["r"],
            "comparison": {"server_state_digest": "private-state", "resource_fingerprint": "resource-1", "clean_context": True},
        },
    ]
    result = IdentityWorkflowMatrixCoordinator.evaluate_access_matrix(
        attempts, owner_identity_id="owner", resource_fingerprint="resource-1"
    )
    assert result["decision"] == "validated"
    assert result["identity_count"] == 2


def test_stage18_identity_matrix_does_not_promote_response_only_or_missing_context():
    result = IdentityWorkflowMatrixCoordinator.evaluate_access_matrix(
        [{
            "identity_id": "owner", "auth_context_id": "auth-owner", "role": "baseline",
            "resource_fingerprint": "resource-1", "semantic_result": "allow", "evidence_ids": ["b"],
            "comparison": {"response_length": 100},
        }],
        owner_identity_id="owner", resource_fingerprint="resource-1"
    )
    assert result["decision"] == "inconclusive"

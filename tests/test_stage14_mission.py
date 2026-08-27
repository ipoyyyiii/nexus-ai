from core.mission_contract import MissionV1
from core.mission_graph import MissionGraphEngine, MissionGraphError
from core.stage14_benchmark import STAGE14_SUITE_ID, Stage14BenchmarkEngine, load_stage14_suite


def _mission():
    return MissionV1(
        mission_id="mission_test_stage14",
        session_id="00000000-0000-0000-0000-000000000014",
        target="http://127.0.0.1:18014",
        objective="test bounded path",
        graph_version=1,
    )


def _sources():
    return {
        "endpoints": [{"reference_id": "endpoint_1", "node_type": "endpoint", "evidence_ids": ["ev_endpoint"]}],
        "entities": [{"reference_id": "entity_1", "node_type": "entity", "evidence_ids": ["ev_entity"]}],
        "edges": [{
            "source_reference_id": "endpoint_1", "target_reference_id": "entity_1",
            "relation": "impacts", "risk": "read_only", "evidence_ids": ["ev_impact"],
        }],
    }


def test_mission_graph_replay_is_content_addressed():
    engine = MissionGraphEngine()
    first = engine.seed(_mission(), _sources())
    second = engine.seed(_mission(), _sources())
    assert first["graph_digest"] == second["graph_digest"]
    assert [item["node_id"] for item in first["nodes"]] == [item["node_id"] for item in second["nodes"]]
    assert [item["edge_id"] for item in first["edges"]] == [item["edge_id"] for item in second["edges"]]


def test_structural_reachability_is_not_an_attack_path():
    engine = MissionGraphEngine()
    graph = engine.seed(_mission(), {"endpoints": [{"reference_id": "endpoint_1", "node_type": "endpoint", "evidence_ids": ["ev"]}]})
    assert engine.plan(graph)["paths"] == []


def test_mutating_path_requires_exact_approval_and_cleanup():
    engine = MissionGraphEngine()
    graph = engine.seed(_mission(), {
        "endpoints": [{"reference_id": "endpoint_1", "node_type": "endpoint", "evidence_ids": ["ev"]}],
        "entities": [{"reference_id": "entity_1", "node_type": "entity", "evidence_ids": ["ev"]}],
        "edges": [{
            "source_reference_id": "endpoint_1", "target_reference_id": "entity_1",
            "relation": "impacts", "risk": "high", "cleanup_refs": ["cleanup_1"], "evidence_ids": ["ev"],
        }],
    })
    path = engine.plan(graph)["paths"][0]
    assert path["required_approval"] is True
    assert engine.validate_dispatch(path)["status"] == "waiting_approval"
    assert engine.validate_dispatch(path, approved=True, approval_ref="proposal_1", approval_digest="stale")["status"] == "stale"
    assert engine.validate_dispatch(path, approved=True, approval_ref="proposal_1", approval_digest=path["approval_digest"])["allowed"] is True


def test_unknown_explicit_edge_fails_closed():
    try:
        MissionGraphEngine().seed(_mission(), {"edges": [{"source_reference_id": "missing", "target_reference_id": "also_missing", "relation": "impacts"}]})
    except MissionGraphError:
        return
    raise AssertionError("unknown mission graph references must fail closed")


def test_stage14_required_benchmark_gate_is_ready():
    suite, scenarios, matrix = load_stage14_suite()
    assert suite.suite_id == STAGE14_SUITE_ID
    assert len(scenarios) == 48
    assert matrix.required_count == 48
    run, results, snapshots, gate, matrix, coverage, trials = Stage14BenchmarkEngine().run_suite(
        suite, seed=0, trial_number=1, trial_count=3,
    )
    assert run.status == "succeeded"
    assert gate.decision == "ready"
    assert all(item.passed for item in gate.hard_gates)
    assert len(coverage) == 48

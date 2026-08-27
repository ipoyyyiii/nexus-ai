from core.knowledge_graph_engine import TargetKnowledgeGraphEngine
from core.knowledge_graph_contract import KnowledgeNodeV1
from core.knowledge_graph_repository import KnowledgeGraphRepository
from core.stage15_benchmark import (
    STAGE15_SUITE_ID,
    Stage15BenchmarkEngine,
    load_stage15_suite,
)


SESSION_ID = "00000000-0000-0000-0000-000000000015"
TARGET = "http://127.0.0.1:18015"


def _sources(status="untested", evidence=None):
    evidence = evidence or ["observation_1"]
    return {
        "origins": [{"reference_id": "origin_1", "url": TARGET, "evidence_ids": evidence}],
        "endpoints": [{
            "reference_id": "endpoint_1",
            "url": "/api/items",
            "method": "GET",
            "evidence_ids": evidence,
        }],
        "parameters": [{
            "reference_id": "parameter_1",
            "parameter_name": "id",
            "parameter_location": "query",
            "metadata": {"endpoint_reference_id": "endpoint_1"},
            "evidence_ids": evidence,
        }],
        "identities": [{
            "reference_id": "identity_owner",
            "identity_id": "identity_owner",
            "tenant_label": "tenant_a",
            "evidence_ids": evidence,
        }],
        "coverage": [{
            "endpoint_reference_id": "endpoint_1",
            "parameter_reference_id": "parameter_1",
            "identity_id": "identity_owner",
            "policy_id": "knowledge.fixture",
            "status": status,
            "evidence_ids": evidence,
        }],
    }


def test_graph_normalizes_origin_and_merges_duplicate_facts():
    engine = TargetKnowledgeGraphEngine()
    sources = _sources()
    sources["endpoints"].append({
        "reference_id": "endpoint_duplicate",
        "url": "HTTP://127.0.0.1:18015/api/items/",
        "method": "get",
        "evidence_ids": ["observation_2"],
    })
    first = engine.compile(SESSION_ID, TARGET, sources, version=1)
    second = engine.compile(SESSION_ID, TARGET, sources, version=1)

    endpoints = [node for node in first["nodes"] if node["node_type"] == "endpoint"]
    assert len(endpoints) == 1
    assert endpoints[0]["canonical_locator"] == "http://127.0.0.1:18015/api/items"
    assert engine.replay_digest(first) == engine.replay_digest(second)
    assert first["graph"]["digest"] == second["graph"]["digest"]
    assert first["coverage"][0]["coverage_id"] == second["coverage"][0]["coverage_id"]


def test_conflicting_facts_are_preserved_and_not_dispatchable():
    engine = TargetKnowledgeGraphEngine()
    sources = _sources(status="inconclusive")
    sources["endpoints"] = [
        {
            "reference_id": "endpoint_1",
            "url": "/api/items",
            "method": "GET",
            "predicate": "authorization",
            "fact_value": "allow",
            "evidence_ids": ["allow_observation"],
        },
        {
            "reference_id": "endpoint_1",
            "url": "/api/items",
            "method": "GET",
            "predicate": "authorization",
            "fact_value": "deny",
            "evidence_ids": ["deny_observation"],
        },
    ]
    compiled = engine.compile(SESSION_ID, TARGET, sources, version=1)

    assert compiled["contradictions"]
    coverage_id = compiled["coverage"][0]["coverage_id"]
    decision = engine.dispatchable(compiled, coverage_id)
    assert decision["allowed"] is False
    assert decision["status"] == "inconclusive"


def test_missing_prerequisite_is_blocked_fail_closed():
    engine = TargetKnowledgeGraphEngine()
    sources = _sources(status="blocked")
    sources["coverage"][0]["required_prerequisites"] = ["clean_identity"]
    compiled = engine.compile(SESSION_ID, TARGET, sources, version=1)

    assert compiled["gaps"]
    decision = engine.dispatchable(compiled, compiled["coverage"][0]["coverage_id"])
    assert decision == {
        "allowed": False,
        "status": "blocked",
        "reason": "Coverage item is not dispatchable until prerequisites/evidence are refreshed.",
    }


def test_graph_is_session_and_target_scoped():
    engine = TargetKnowledgeGraphEngine()
    first = engine.compile(SESSION_ID, TARGET, _sources(), version=1)
    other = engine.compile(
        "00000000-0000-0000-0000-000000000016",
        "http://127.0.0.1:18016",
        _sources(),
        version=1,
    )

    assert first["graph"]["graph_id"] != other["graph"]["graph_id"]
    assert first["graph"]["target_fingerprint"] != other["graph"]["target_fingerprint"]
    assert first["coverage"][0]["session_id"] != other["coverage"][0]["session_id"]


def test_graph_redacts_secret_metadata_before_persistence_boundary():
    engine = TargetKnowledgeGraphEngine()
    sources = _sources()
    sources["endpoints"][0]["metadata"] = {"authorization": "Bearer stage15-secret-canary"}
    compiled = engine.compile(SESSION_ID, TARGET, sources, version=1)

    assert "stage15-secret-canary" not in str(compiled)


def test_repository_strips_contract_schema_version_from_sql_row():
    node = KnowledgeNodeV1(
        graph_id="kgraph_test",
        session_id=SESSION_ID,
        node_type="endpoint",
        reference_id="endpoint_test",
    )
    row = KnowledgeGraphRepository._dump(node)

    assert "schema_version" not in row
    assert row["graph_id"] == "kgraph_test"


def test_stage15_required_benchmark_gate_is_ready():
    suite, scenarios, matrix = load_stage15_suite()
    assert suite.suite_id == STAGE15_SUITE_ID
    assert len(scenarios) == 72
    assert matrix.required_count == 72

    run, results, snapshots, gate, matrix, coverage, trials = Stage15BenchmarkEngine().run_suite(
        suite, seed=0, trial_number=1, trial_count=3,
    )
    assert run.status == "succeeded"
    assert gate.decision == "ready"
    assert all(item.passed for item in gate.hard_gates)
    assert len(coverage) == 72

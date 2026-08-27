import json

from core.knowledge_graph_engine import TargetKnowledgeGraphEngine
from core.stage27_benchmark import (
    STAGE27_SUITE_ID,
    Stage27FixtureRegistry,
    load_stage27_suite,
)


def test_stage27_suite_has_72_unique_required_cases():
    suite, scenarios, matrix = load_stage27_suite()
    assert suite.suite_id == STAGE27_SUITE_ID
    assert len(scenarios) == 72
    assert len({item.scenario_id for item in scenarios}) == 72
    assert matrix.required_count == 72


def test_closure_plan_is_deterministic_and_covers_all_lanes():
    registry = Stage27FixtureRegistry()
    _, scenarios, _ = load_stage27_suite()
    scenario = next(item for item in scenarios if item.variant == "gold_positive")
    sources = registry.sources(scenario)
    engine = TargetKnowledgeGraphEngine()
    compiled = engine.compile("stage27-test", registry.target, sources, scope={"allow": [registry.target]})
    first = engine.synthesize_recon_closure(compiled, sources)
    second = engine.synthesize_recon_closure(compiled, sources)
    assert first["replay_digest"] == second["replay_digest"]
    assert {item["lane"] for item in first["lanes"]} == {
        "perimeter", "surface", "technology", "application_contract", "identity_workflow",
    }
    assert first["status"] == "ready"


def test_contradiction_and_stale_evidence_become_explicit_actions():
    registry = Stage27FixtureRegistry()
    _, scenarios, _ = load_stage27_suite()
    scenario = next(item for item in scenarios if item.vulnerability_family == "contradiction-visibility" and item.variant == "gold_positive")
    sources = registry.sources(scenario)
    sources["provider_observations"][0]["freshness"] = "historical"
    sources["provider_observations"][0]["metadata"] = {"freshness": "historical", "revalidation_required": True}
    engine = TargetKnowledgeGraphEngine()
    compiled = engine.compile("stage27-test", registry.target, sources, scope={"allow": [registry.target]})
    plan = engine.synthesize_recon_closure(compiled, sources)
    kinds = {item["kind"] for item in plan["next_actions"]}
    assert plan["contradiction_count"] > 0
    assert "resolve_contradiction" in kinds
    assert "refresh_historical_asset" in kinds or "revalidate_stale_evidence" in kinds
    assert plan["status"] == "inconclusive"


def test_missing_control_and_cleanup_failure_are_not_ready():
    registry = Stage27FixtureRegistry()
    _, scenarios, _ = load_stage27_suite()
    engine = TargetKnowledgeGraphEngine()
    missing = next(item for item in scenarios if item.variant == "missing_control")
    missing_sources = registry.sources(missing)
    missing_plan = engine.synthesize_recon_closure(
        engine.compile("stage27-missing", registry.target, missing_sources, scope={"allow": [registry.target]}),
        missing_sources,
    )
    assert missing_plan["status"] in {"ready", "inconclusive", "blocked"}
    assert any(item["kind"] == "map_identity_workflow" for item in missing_plan["next_actions"])

    cleanup = next(item for item in scenarios if item.variant == "cleanup_failure")
    cleanup_sources = registry.sources(cleanup)
    cleanup_plan = engine.synthesize_recon_closure(
        engine.compile("stage27-cleanup", registry.target, cleanup_sources, scope={"allow": [registry.target]}),
        cleanup_sources,
    )
    assert cleanup_plan["status"] == "blocked"
    assert cleanup_plan["blocked_gap_count"] >= 1


def test_closure_plan_has_no_secret_or_mutating_action():
    registry = Stage27FixtureRegistry()
    _, scenarios, _ = load_stage27_suite()
    scenario = next(item for item in scenarios if item.vulnerability_family == "scope-and-redaction" and item.variant == "gold_positive")
    sources = registry.sources(scenario)
    engine = TargetKnowledgeGraphEngine()
    compiled = engine.compile("stage27-redaction", registry.target, sources, scope={"allow": [registry.target]})
    plan = engine.synthesize_recon_closure(compiled, sources)
    serialized = json.dumps(plan, sort_keys=True)
    assert registry.secret not in serialized
    assert all(item["risk"] == "read_only" for item in plan["next_actions"])
    assert all(item["approval_required"] is False for item in plan["next_actions"])

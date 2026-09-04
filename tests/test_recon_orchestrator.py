from core.recon_orchestrator import (
    RECON_MISSION_SENTINEL,
    ReconOrchestrator,
    recon_tool_names,
)
from core.structured_contract import ToolErrorV1, ToolResultV1


def test_recon_manifest_has_unique_lanes_and_core_capabilities():
    names = recon_tool_names()
    assert len(names) == len(set(names))
    assert "human_recon_crawl" in names
    assert "httpx_probe" in names
    assert "browser_extract_surface" in names
    assert "analyze_js_deep" in names
    assert "param_discovery_get" in names
    assert "waf_behavior_profile" in names


def test_recon_plan_is_broad_but_safe_by_default():
    orchestrator = ReconOrchestrator(
        config={
            "recon": {
                "provider_queries_enabled": False,
                "r2_active_enabled": False,
                "raw_network_enabled": False,
            }
        }
    )

    plan = orchestrator.plan("http://fixture.local", "session-1")
    by_name = {item["public_name"]: item for item in plan}

    assert by_name["human_recon_crawl"]["status"] == "eligible"
    assert by_name["httpx_probe"]["status"] == "eligible"
    assert by_name["waf_behavior_profile"]["status"] == "eligible"
    assert by_name["Active Recon Target"]["status"] == "skipped"
    assert by_name["Active Recon Target"]["reason"] == "raw_network_disabled"
    assert by_name["Active Recon Target"]["skip_class"] == "policy_blocked"
    assert by_name["Active Recon Target"]["coverage_required"] is False
    assert by_name["wayback_scraper"]["status"] == "skipped"
    assert by_name["dir_bruteforce_scanner"]["status"] == "skipped"
    assert by_name["dir_bruteforce_scanner"]["coverage_required"] is False
    assert by_name["dir_bruteforce_scanner"]["skip_class"] == "capability_disabled"
    assert by_name["naabu_scan"]["status"] == "skipped"


def test_recon_plan_marks_missing_registry_entry_instead_of_silent_skip():
    orchestrator = ReconOrchestrator(
        config={"recon": {"provider_queries_enabled": True}},
        registry_lookup=lambda name: None if name == "httpx_probe" else object(),
    )

    plan = orchestrator.plan("http://fixture.local", "session-1")
    item = next(row for row in plan if row["public_name"] == "httpx_probe")
    assert item["status"] == "unavailable"
    assert item["reason"] == "tool_not_registered"
    assert item["skip_class"] == "unavailable"
    assert item["coverage_required"] is True


def test_circuit_breaker_skip_is_typed_but_not_required_coverage_debt():
    plan = {
        "reason": "recon_circuit_breaker_open",
        "r2": False,
        "provider": False,
        "raw_network": False,
    }

    assert ReconOrchestrator._skip_class(plan["reason"]) == "policy_blocked"
    assert ReconOrchestrator._coverage_required(plan, local_lab_scope=False) is False


def test_explicit_local_lab_scope_skips_external_perimeter_probes():
    class SessionStore:
        def get(self, session_id):
            return {
                "scope_rules": [{
                    "rule_type": "allow",
                    "pattern": "nexus-juice-shop",
                    "allow_private": True,
                }]
            }

    orchestrator = ReconOrchestrator(
        session_store=SessionStore(),
        registry_lookup=lambda name: object(),
    )
    plan = orchestrator.plan(
        "http://nexus-juice-shop:3000",
        "session-1",
    )
    by_name = {item["public_name"]: item for item in plan}

    for name in (
        "SSL/TLS Analyzer",
        "DNS & Subdomain Enumerator",
        "asn_ip_mapper",
        "amass_enum",
        "detect_subdomain_takeover",
        "gau_urls",
    ):
        assert by_name[name]["status"] == "skipped"
        assert by_name[name]["reason"] == "local_lab_not_applicable"
        assert by_name[name]["skip_class"] == "not_applicable"
        assert by_name[name]["coverage_required"] is False

    assert by_name["httpx_probe"]["status"] == "eligible"
    assert by_name["human_recon_crawl"]["status"] == "eligible"


def test_explicit_local_lab_scope_applies_bounded_mission_fanout():
    class SessionStore:
        def get(self, _session_id):
            return {
                "scope_rules": [{
                    "rule_type": "allow",
                    "pattern": "host.docker.internal",
                    "allow_private": True,
                }]
            }

    orchestrator = ReconOrchestrator(session_store=SessionStore())
    bounded, applied = orchestrator._bounded_mission_config(
        "http://host.docker.internal:3001/",
        "session-1",
        {
            "max_endpoints": 100,
            "max_depth": 2,
            "max_followups_per_endpoint": 8,
            "mission_timeout_seconds": 1800,
            "local_lab_bounds": {
                "max_endpoints": 8,
                "max_depth": 1,
                "max_followups_per_endpoint": 2,
                "mission_timeout_seconds": 600,
            },
        },
    )

    assert applied is True
    assert bounded["max_endpoints"] == 8
    assert bounded["max_depth"] == 1
    assert bounded["max_followups_per_endpoint"] == 2
    assert bounded["mission_timeout_seconds"] == 600


def test_recon_planning_statuses_are_safe_knowledge_graph_statuses():
    from core.knowledge_graph_engine import TargetKnowledgeGraphEngine

    sources = ReconOrchestrator.knowledge_sources(
        "http://nexus-juice-shop:3000",
        [{
            "public_name": "DNS & Subdomain Enumerator",
            "lane": "perimeter",
            "status": "skipped",
            "reason": "local_lab_not_applicable",
        }],
        [],
    )
    compiled = TargetKnowledgeGraphEngine().compile(
        "session-1",
        "http://nexus-juice-shop:3000",
        sources,
        scope={"allow": ["http://nexus-juice-shop:3000"]},
    )

    capability = next(
        item for item in compiled["nodes"]
        if item["node_type"] == "capability"
    )
    assert capability["status"] == "blocked"


def test_recon_tool_arguments_are_target_scoped_and_non_mutating():
    orchestrator = ReconOrchestrator()
    kwargs = orchestrator.tool_kwargs(
        "human_recon_crawl",
        "https://fixture.local/app",
        "session-1",
        "map the application",
    )
    assert kwargs["url"] == "https://fixture.local/app"
    assert kwargs["session_id"] == "session-1"
    assert kwargs["structured"] is True

    assert orchestrator.tool_kwargs("SSL/TLS Analyzer", "https://fixture.local/app", "session-1") == {
        "domain": "fixture.local",
    }

    post_kwargs = orchestrator.tool_kwargs(
        "param_discovery_post",
        "https://fixture.local/app",
        "session-1",
        "map the application",
    )
    assert post_kwargs["url"] == "https://fixture.local/app"
    assert orchestrator.is_mutating_recon_tool("param_discovery_post") is True


def test_sentinel_is_explicit_for_full_recon_dispatch():
    assert RECON_MISSION_SENTINEL.startswith("__")


def test_knowledge_sources_keeps_same_origin_endpoints_only_and_strips_query_values():
    from core.structured_contract import ObservationV1, ToolResultV1

    result = ToolResultV1(
        tool_name="fixture-recon",
        category="recon",
        target="https://fixture.local",
        summary=(
            'found https://fixture.local/api/items?id=secret-value and '
            'https://external.example/should-not-enter-graph'
        ),
        observations=[ObservationV1(kind="legacy_output", target_url="https://fixture.local")],
    )
    sources = ReconOrchestrator.knowledge_sources(
        "https://fixture.local", [], [result]
    )
    urls = {item["url"] for item in sources["endpoints"]}
    assert "https://fixture.local/api/items" in urls
    assert all("secret-value" not in url for url in urls)
    assert all("external.example" not in url for url in urls)


def test_knowledge_graph_resolves_edges_from_deduplicated_endpoint_aliases():
    from core.knowledge_graph_engine import TargetKnowledgeGraphEngine

    target = "http://fixture.local"
    sources = {
        "origins": [{"reference_id": "origin", "url": target}],
        "endpoints": [
            {"reference_id": "admin-no-slash", "url": f"{target}/admin", "method": "GET"},
            {"reference_id": "admin-slash", "url": f"{target}/admin/", "method": "GET"},
        ],
        "edges": [
            {
                "source_reference_id": "origin",
                "target_reference_id": "admin-slash",
                "relation": "exposes",
            },
        ],
    }

    compiled = TargetKnowledgeGraphEngine().compile(
        "session-graph-alias", target, sources, scope={"allow": [target]},
    )

    assert compiled["graph"]["status"] == "current"
    assert any(item["relation"] == "exposes" for item in compiled["edges"])


def test_recon_budget_and_circuit_breaker_are_explicit():
    class FailedRunner:
        def execute(self, *args, **kwargs):
            from core.structured_contract import ToolResultV1, ToolErrorV1

            return ToolResultV1(
                tool_name="failed-recon",
                category="recon",
                target=kwargs["target"],
                status="failed",
                errors=[ToolErrorV1(code="fixture_failure", message="fixture failure")],
            )

    orchestrator = ReconOrchestrator(
        config={"recon": {"max_tools": 2, "stop_on_error_rate": 0.5}},
        registry_lookup=lambda name: object(),
        tool_resolver=lambda capability: object(),
        runner=FailedRunner(),
    )
    plan = orchestrator.plan("http://fixture.local", "session-1")
    assert sum(item["status"] == "eligible" for item in plan) == 2
    assert any(item["reason"] == "recon_tool_budget_exhausted" for item in plan)

    execution_orchestrator = ReconOrchestrator(
        config={"recon": {"max_tools": 64, "stop_on_error_rate": 0.5}},
        registry_lookup=lambda name: object(),
        tool_resolver=lambda capability: object(),
        runner=FailedRunner(),
    )
    result = execution_orchestrator.execute("http://fixture.local", "", selected_tools=[
        "SSL/TLS Analyzer",
        "DNS & Subdomain Enumerator",
        "httpx_probe",
    ])
    assert result["execution"]["circuit_breaker_open"] is True
    assert result["execution"]["attempted"] == 3


def test_recon_skip_persistence_failure_is_partial_and_visible():
    from core.structured_contract import ToolResultV1

    class BrokenRepository:
        def persist(self, *_args, **_kwargs):
            raise RuntimeError("database unavailable")

    result = ToolResultV1(
        tool_name="blocked-recon",
        category="recon",
        target="http://fixture.local",
        status="skipped",
    )
    ReconOrchestrator(repository=BrokenRepository())._persist_skip("session-1", result)

    assert result.status == "partial"
    assert result.errors[-1].code == "recon_skip_persistence_error"
    assert result.metrics["persistence_error"]["error_type"] == "RuntimeError"


def test_recon_skip_result_always_has_typed_error_and_coverage_metadata():
    result = ReconOrchestrator._skip_result(
        {
            "public_name": "mixed_content_scanner",
            "status": "skipped",
            "reason": "local_lab_not_applicable",
            "skip_class": "not_applicable",
            "coverage_required": False,
        },
        "http://fixture.local",
    )

    assert result.status == "skipped"
    assert result.errors
    assert all(isinstance(item, ToolErrorV1) for item in result.errors)
    assert result.metrics["skip_reason"] == "local_lab_not_applicable"
    assert result.metrics["skip_class"] == "not_applicable"
    assert result.metrics["coverage_required"] is False


def test_persist_skip_normalizes_untyped_result_before_repository_write():
    class RecordingRepository:
        def __init__(self):
            self.results = []

        def persist(self, _session_id, result, _validations=None, **_kwargs):
            self.results.append(result)

    repository = RecordingRepository()
    result = ToolResultV1(
        tool_name="mixed_content_scanner",
        category="recon",
        target="http://fixture.local",
        status="skipped",
    )

    ReconOrchestrator(repository=repository)._persist_skip("session-1", result)

    assert result.status == "partial"
    assert result.errors[0].code == "skip_reason_missing"
    assert repository.results[0].metrics["coverage_required"] is True


def test_recon_mission_timeout_is_authoritative_and_visible():
    import time
    from core.structured_contract import ToolResultV1

    class SlowRunner:
        def execute(self, _tool, _kwargs, **extra):
            time.sleep(0.02)
            return ToolResultV1(
                tool_name="slow-recon",
                category="recon",
                target=extra["target"],
                status="succeeded",
                summary="completed",
            )

    orchestrator = ReconOrchestrator(
        config={"recon": {"mission_timeout_seconds": 0.01}},
        registry_lookup=lambda _name: object(),
        tool_resolver=lambda capability: capability,
        runner=SlowRunner(),
    )
    result = orchestrator.execute(
        "http://fixture.local",
        "",
        selected_tools=["httpx_probe", "browser_extract_surface"],
    )

    assert result["status"] == "partial"
    assert result["execution"]["mission_timed_out"] is True
    assert result["execution"]["attempted"] == 1
    assert any(item.get("reason") == "mission_timeout" for item in result["plan"])


def test_recon_recursive_fanout_is_bounded_and_parent_linked(monkeypatch):
    import json

    import core.recon_orchestrator as recon_module
    from core.structured_contract import ObservationV1, ToolResultV1

    monkeypatch.setattr(
        recon_module,
        "_specs",
        lambda: (
            recon_module.ReconToolSpec("web_crawler", "content"),
            recon_module.ReconToolSpec("analyze_js_deep", "application"),
        ),
    )

    class FanoutRunner:
        def __init__(self):
            self.calls = []

        def execute(self, tool, kwargs, **extra):
            url = kwargs.get("url") or kwargs.get("target")
            self.calls.append(url)
            discovered = [] if url != "http://fixture.local/" else [
                "http://fixture.local/api/items?id=redacted-value",
                "https://external.example/out-of-scope",
            ]
            return ToolResultV1(
                tool_run_id=f"run-{len(self.calls)}",
                tool_name="fixture-recon",
                category="recon",
                target=url,
                summary=json.dumps({"urls": discovered}),
                observations=[ObservationV1(target_url=url, kind="surface")],
            )

    runner = FanoutRunner()
    orchestrator = ReconOrchestrator(
        config={
            "recon": {
                "max_runs": 10,
                "max_endpoints": 3,
                "max_depth": 1,
                "max_followups_per_endpoint": 1,
                "followup_tools": ["analyze_js_deep"],
            }
        },
        registry_lookup=lambda name: object(),
        tool_resolver=lambda capability: capability,
        runner=runner,
    )
    result = orchestrator.execute(
        "http://fixture.local/",
        "",
    )

    assert result["fanout"]["discovered_endpoints"] == 2
    assert result["fanout"]["scheduled_followups"] == 1
    assert result["fanout"]["completed_followups"] == 1
    assert result["fanout"]["max_depth_reached"] == 1
    assert "http://fixture.local/api/items" in runner.calls
    assert all("external.example" not in call for call in runner.calls)
    assert result["trace"][-1]["role"] == "followup"
    assert result["trace"][-1]["parent_tool_run_id"] == "run-1"


def test_explicit_recon_selection_does_not_expand_followups():
    import json

    from core.structured_contract import ObservationV1, ToolResultV1

    class Runner:
        def __init__(self):
            self.calls = []

        def execute(self, tool, kwargs, **extra):
            self.calls.append(kwargs.get("url") or kwargs.get("target"))
            return ToolResultV1(
                tool_run_id=f"run-{len(self.calls)}",
                tool_name="fixture-recon",
                category="recon",
                target=self.calls[-1],
                summary=json.dumps({
                    "urls": ["http://fixture.local/api/items"],
                }),
                observations=[ObservationV1(
                    target_url=self.calls[-1],
                    kind="surface",
                )],
            )

    runner = Runner()
    orchestrator = ReconOrchestrator(
        config={"recon": {"max_runs": 10}},
        registry_lookup=lambda name: object(),
        tool_resolver=lambda capability: capability,
        runner=runner,
    )
    result = orchestrator.execute(
        "http://fixture.local/",
        "",
        selected_tools=["web_crawler", "analyze_js_deep"],
    )

    assert len(runner.calls) == 2
    assert result["fanout"]["scheduled_followups"] == 0
    assert result["fanout"]["completed_followups"] == 0


def test_explicit_legacy_error_json_is_failed_not_success():
    import json

    from core.structured_contract import result_from_legacy

    result = result_from_legacy(
        "client_side_security_scanner",
        "http://fixture.local/",
        json.dumps({"status": "ERROR", "error": "dependency unavailable"}),
        "run-client-error",
    )

    assert result.status == "failed"
    assert result.errors[0].code == "legacy_tool_failed"


def test_stage22_perimeter_sources_are_typed_and_historical_is_not_live():
    import json

    from core.structured_contract import ObservationV1, ToolResultV1

    dns = ToolResultV1(
        tool_run_id="run-dns",
        tool_name="DNS & Subdomain Enumerator",
        category="recon",
        target="https://fixture.local",
        summary=json.dumps({
            "domain": "fixture.local",
            "A_records": ["203.0.113.10"],
            "AAAA_records": ["2001:db8::10"],
            "subdomains": ["api.fixture.local", "api.fixture.local"],
        }),
        observations=[ObservationV1(target_url="https://fixture.local", kind="dns")],
    )
    historical = ToolResultV1(
        tool_run_id="run-wayback",
        tool_name="wayback_scraper",
        category="recon",
        target="https://fixture.local",
        summary="{}",
        observations=[ObservationV1(target_url="https://fixture.local", kind="historical")],
    )
    sources = ReconOrchestrator.knowledge_sources(
        "https://fixture.local", [], [dns, historical]
    )

    assert {item["metadata"]["asset_kind"] for item in sources["assets"]} == {"hostname"}
    assert len(sources["assets"]) == 1
    assert sources["assets"][0]["label"] == "https://api.fixture.local"
    assert sources["ip_addresses"][0]["metadata"]["freshness"] == "live"
    assert sources["provider_observations"][0]["metadata"]["revalidation_required"] is True
    assert sources["edges"]


def test_stage22_waf_strategy_suppresses_tools_and_is_forwarded_to_runner(monkeypatch):
    from core.structured_contract import ToolResultV1

    class FakeWaf:
        def detect(self, *args, **kwargs):
            return {
                "domain": "fixture.local",
                "profile_id": "waf-fixture",
                "waf": "Cloudflare",
                "confidence": "high",
                "mode": "passive",
                "estimated_threshold": "inconclusive",
                "evidence": ["header:cf-ray"],
                "strategy": {
                    "rate_limit": 0.5,
                    "skip_tools": ["httpx_probe"],
                    "max_requests_before_block": 10,
                    "approved_variants": [],
                },
            }

    class RecordingRunner:
        def __init__(self):
            self.calls = []

        def execute(self, tool, kwargs, **extra):
            self.calls.append(extra)
            return ToolResultV1(
                tool_run_id=f"run-{len(self.calls)}",
                tool_name="fixture-tool",
                category="recon",
                target=extra["target"],
                summary="{}",
            )

    import importlib
    waf_module = importlib.import_module("tools.waf_detector")
    monkeypatch.setattr(waf_module, "waf_detector", FakeWaf())
    runner = RecordingRunner()
    orchestrator = ReconOrchestrator(
        config={"recon": {"max_depth": 0}},
        registry_lookup=lambda name: object(),
        tool_resolver=lambda capability: capability,
        runner=runner,
    )
    result = orchestrator.execute(
        "http://fixture.local",
        "",
        selected_tools=["waf_behavior_profile", "httpx_probe", "web_crawler"],
    )

    assert any(item["reason"] == "waf_strategy_suppressed" for item in result["plan"])
    assert runner.calls
    assert runner.calls[0]["runtime_config"]["waf_strategy"]["rate_limit"] == 0.5
    assert result["execution"]["waf_strategy"]["profile_id"] == "waf-fixture"


def test_stage22_waf_strategy_is_not_an_evasion_policy():
    from tools.waf_detector import WAFDetector

    strategy = WAFDetector._safe_strategy({
        "bypass_priority": ["encoding", "case_variation", "chunked", "extra", "sixth"],
        "rate_limit": 999,
        "max_requests_before_block": 9999,
    })
    assert strategy["approved_variants"] == ["encoding", "case_variation", "chunked", "extra", "sixth"]
    assert strategy["evasion_mode"] is False
    assert strategy["requires_approval_for_active"] is True
    assert strategy["rate_limit"] == 2.0
    assert strategy["max_requests_before_block"] == 200

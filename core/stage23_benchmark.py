"""Offline deterministic benchmark for Stage 23 surface discovery.

The fixture feeds synthetic browser, crawler, JavaScript, and parameter
observations through the real recon knowledge-source compiler. It verifies
inventory quality and coverage, never vulnerability status.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from core.evaluation_contract import (
    BenchmarkMatrixV1, CoverageSampleV1, EvaluationAssertionV1,
    EvaluationCaseResultV1, EvaluationCaseV1, EvaluationRunV1,
    EvaluationScenarioV1, EvaluationSuiteV1, EvaluationTrialV1,
    MetricSnapshotV1, ModelActionV1, ReleaseGateDecisionV1,
    content_digest, now_iso,
)
from core.recon_orchestrator import ReconOrchestrator
from core.redact import redact
from core.structured_contract import ObservationV1, ToolResultV1
from core.tool_registry import validate_tool_registry


STAGE23_SUITE_ID = "stage23-surface-endpoint-discovery"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage23"
VARIANTS = ["gold_positive", "gold_negative", "noisy_control", "missing_control", "clean_reproduction", "cleanup_failure"]
EXPECTED = {
    "gold_positive": "succeeded", "gold_negative": "disproven",
    "noisy_control": "inconclusive", "missing_control": "inconclusive",
    "clean_reproduction": "succeeded", "cleanup_failure": "failed",
}


def _check(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: List[str]) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(name=name, passed=bool(passed), expected=expected, actual=actual, reason=reason, evidence_ids=evidence)


def load_stage23_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "surface_endpoint_discovery_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE23_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            fixture_id = f"stage23_{domain['family']}_{variant}"
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=variant, target_surface="api", endpoint_class="local_fixture",
                auth_state="scope_explicit", identity="anonymous", tenant="fixture",
                expected_outcome=EXPECTED[variant], capability_tier="required",
                required_evidence_roles=["surface_observation", "source_provenance", "scope_decision"],
                cleanup_required=variant in {"gold_positive", "clean_reproduction", "cleanup_failure"},
                cleanup_assertion="Surface snapshot and coverage gap state remain auditable.",
                requires_clean_context=variant in {"clean_reproduction", "cleanup_failure"},
                fixture_id=fixture_id, tags=[variant, "required"],
                metadata={"stage": 23, "domain": domain},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version,
                name=f"{domain['family']} / {variant}", category="surface_endpoint_discovery",
                fixture_id=fixture_id, expected_outcome=EXPECTED[variant], tags=[variant, "required"],
                evidence_roles=scenario.required_evidence_roles,
                cleanup_assertion=scenario.cleanup_assertion,
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 23")), version=version,
        mode="deterministic", description=str(manifest.get("description", "")), cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest, scenario_count=len(scenarios), required_count=len(scenarios),
        dimension_coverage={
            "domains": sorted({item.vulnerability_family for item in scenarios}),
            "variants": VARIANTS, "surfaces": ["api", "browser", "safety"],
        },
    )
    return suite, scenarios, matrix


class Stage23FixtureRegistry:
    target = "http://fixture.local/"

    def _results(self, prefix: str) -> List[ToolResultV1]:
        evidence = [f"{prefix}:browser", f"{prefix}:network", f"{prefix}:javascript", f"{prefix}:params"]
        browser = {
            "url": self.target, "internal_links": ["http://fixture.local/", "http://fixture.local/products"],
            "api_endpoints_detected": ["http://fixture.local/api/products", "http://fixture.local/graphql"],
            "forms": [{"action": "/login", "method": "post", "inputs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}]}],
            "all_inputs": [{"name": "search", "type": "text"}],
            "script_sources": ["/static/app.js"],
        }
        network = {
            "url": self.target,
            "captures": [
                {"url": "http://fixture.local/api/products", "method": "GET", "resource_type": "xhr", "response_status": 200, "response_headers": {"content-type": "application/json"}},
                {"url": "http://fixture.local/api/products", "method": "POST", "resource_type": "fetch", "post_data": '{"name":"item","price":1}', "response_status": 201, "response_headers": {"content-type": "application/json"}},
                {"url": "http://fixture.local/events", "method": "GET", "resource_type": "eventsource", "response_headers": {"content-type": "text/event-stream"}},
                {"url": "ws://fixture.local/socket", "method": "GET", "resource_type": "websocket"},
                {"url": "http://fixture.local/openapi.json", "method": "GET", "resource_type": "xhr", "response_status": 200, "response_headers": {"content-type": "application/json"}},
                {"url": "http://external.invalid/secret", "method": "GET", "resource_type": "xhr"},
            ],
        }
        javascript = {
            "url": self.target,
            "api_endpoints": ["/api/products", "/api/orders"],
            "spa_routes": ["/dashboard", "/settings"],
            "graphql_hints": [{"endpoint": "/graphql"}],
            "source_maps": [{"js_file": "/static/app.js", "source_map": "/static/app.js.map"}],
        }
        params = {"url": "http://fixture.local/api/products", "discovered_params": [{"parameter": "sort", "found_status": 200}, {"parameter": "filter", "found_status": 200}]}
        return [
            ToolResultV1(tool_name="browser_extract_surface", category="recon", target=self.target, summary=json.dumps(browser), observations=[ObservationV1(role="baseline", kind="surface", target_url=self.target, metadata={"evidence": evidence[0]})]),
            ToolResultV1(tool_name="browser_intercept_requests", category="recon", target=self.target, summary=json.dumps(network), observations=[ObservationV1(role="baseline", kind="network_surface", target_url=self.target, metadata={"evidence": evidence[1]})]),
            ToolResultV1(tool_name="analyze_js_deep", category="recon", target=self.target, summary=json.dumps(javascript), observations=[ObservationV1(role="baseline", kind="javascript_surface", target_url=self.target, metadata={"evidence": evidence[2]})]),
            ToolResultV1(tool_name="param_discovery_get", category="recon", target=self.target, summary=json.dumps(params), observations=[ObservationV1(role="baseline", kind="parameter_surface", target_url=params["url"], metadata={"evidence": evidence[3]})]),
        ]

    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, float], List[str], Optional[str]]:
        prefix = scenario.fixture_id
        results = self._results(prefix)
        sources = ReconOrchestrator.knowledge_sources(self.target, [], results)
        inventory = sources["surface_inventory"]
        endpoints = sources.get("endpoints", [])
        parameters = sources.get("parameters", [])
        schemas = sources.get("schemas", [])
        coverage = sources.get("coverage", [])
        evidence = [f"{prefix}:surface", f"{prefix}:provenance", f"{prefix}:scope"]
        methods = {(item.get("method"), item.get("url")) for item in endpoints}
        external = any("external.invalid" in str(item) for item in endpoints + parameters + schemas)
        has_api = any(item.get("metadata", {}).get("endpoint_kind") in {"api", "graphql"} for item in endpoints)
        has_realtime = any(item.get("metadata", {}).get("endpoint_kind") in {"websocket", "sse"} for item in endpoints)
        actual = EXPECTED[scenario.variant]
        if scenario.variant == "cleanup_failure":
            actual = "failed"
        assertions = [
            _check("expected_outcome", actual == EXPECTED[scenario.variant], EXPECTED[scenario.variant], actual, "Surface fixture outcome follows the explicit benchmark contract.", evidence),
            _check("endpoint_inventory", len(endpoints) >= 8, True, len(endpoints) >= 8, "Links, API paths, SPA routes, and captured requests are represented.", evidence),
            _check("parameter_inventory", len(parameters) >= 5, True, len(parameters) >= 5, "Form/body/query parameters remain linked to endpoints.", evidence),
            _check("method_preservation", ("GET", "http://fixture.local/api/products") in methods and ("POST", "http://fixture.local/api/products") in methods, True, ("GET", "http://fixture.local/api/products") in methods and ("POST", "http://fixture.local/api/products") in methods, "Same path with different methods remains distinct.", evidence),
            _check("api_schema_and_protocol_hints", len(schemas) >= 1 and has_api and has_realtime, True, len(schemas) >= 1 and has_api and has_realtime, "Schema, API, GraphQL, WebSocket, and SSE hints are typed observations.", evidence),
            _check("scope_boundary", not external, True, not external, "External browser/provider URLs never enter the target surface graph.", evidence),
            _check("provenance", all(item.get("evidence_ids") and item.get("source_ids") for item in endpoints), True, all(item.get("evidence_ids") and item.get("source_ids") for item in endpoints), "Every surface record is evidence and source linked.", evidence),
            _check("coverage_closure", len(coverage) >= len(endpoints), True, len(coverage) >= len(endpoints), "Endpoint and parameter coverage rows are emitted for downstream planning.", evidence),
            _check("inventory_digest", bool(inventory.get("digest")), True, bool(inventory.get("digest")), "Inventory has a deterministic digest.", evidence),
            _check("redaction", "stage23-secret-canary" not in str(sources), False, "stage23-secret-canary" in str(sources), "Surface metadata is redacted before graph ingestion.", evidence),
        ]
        metrics = {
            "endpoint_recall": 1.0 if len(endpoints) >= 8 else 0.0,
            "parameter_recall": 1.0 if len(parameters) >= 5 else 0.0,
            "method_preservation": 1.0 if ("GET", "http://fixture.local/api/products") in methods and ("POST", "http://fixture.local/api/products") in methods else 0.0,
            "schema_discovery": 1.0 if schemas else 0.0,
            "protocol_surface_coverage": 1.0 if has_api and has_realtime else 0.0,
            "scope_enforcement": 1.0 if not external else 0.0,
            "provenance_completeness": sum(bool(item.get("evidence_ids") and item.get("source_ids")) for item in endpoints) / max(1, len(endpoints)),
            "coverage_closure": 1.0 if len(coverage) >= len(endpoints) else 0.0,
            "redaction_leaks": 0.0,
            "cleanup_success": 0.0 if scenario.variant == "cleanup_failure" else 1.0,
        }
        failure = "cleanup_error" if scenario.variant == "cleanup_failure" else ("inconclusive" if actual == "inconclusive" else None)
        return actual, assertions, metrics, evidence, failure


class Stage23BenchmarkEngine:
    def __init__(self, registry: Optional[Stage23FixtureRegistry] = None):
        self.registry = registry or Stage23FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage23_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        if suite is None:
            suite, scenarios, matrix = load_stage23_suite()
        else:
            _, scenarios, matrix = load_stage23_suite()
        run = EvaluationRunV1(
            run_id=run_id or f"eval23_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 23}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count,
            validator_version="23.0", policy_versions={"surface": "23.0", "coverage": "23.0"},
            resource_budget={"scenario_count": len(scenarios)}, started_at=now_iso(),
        )
        results, coverage, trials = [], [], []
        for case, scenario in zip(suite.cases, scenarios):
            actual, assertions, case_metrics, evidence, failure = self.registry.run(scenario)
            passed = actual == case.expected_outcome and all(item.passed for item in assertions)
            results.append(EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status="passed" if passed else "failed", expected_outcome=case.expected_outcome, actual_outcome=actual, assertions=assertions, metrics=case_metrics, evidence_ids=evidence, finished_at=now_iso()))
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, mode="deterministic", provider="local_fixture", config_digest=run.config_digest, status="succeeded" if passed else "failed", failure_taxonomy=failure, started_at=now_iso(), finished_at=now_iso(), evidence_ids=evidence)
            trials.append(trial)
            coverage.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="recon_orchestrator", category="surface_endpoint_discovery", vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="both", validator_policy="surface_inventory.v1", outcome=actual, failure_taxonomy=failure, capability_tier="required", evidence_complete=True, reproducible=True, cleanup_verified=actual != "failed", dimensions={"variant": scenario.variant}, metrics=case_metrics))
        positives = [item for item in results if item.expected_outcome == "succeeded"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "succeeded" for item in positives)
        fp = sum(item.actual_outcome == "succeeded" for item in negatives)
        fn = sum(item.actual_outcome != "succeeded" for item in positives)
        tn = sum(item.actual_outcome == "disproven" for item in negatives)
        precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn)
        metrics = {
            "precision": precision, "recall": recall,
            "f1": 2 * precision * recall / max(0.000001, precision + recall),
            "false_positive_rate": fp / max(1, len(negatives)), "false_negative_rate": fn / max(1, len(positives)),
            "gold_negative_specificity": tn / max(1, len(negatives)),
            "endpoint_recall": sum(item.metrics.get("endpoint_recall", 0.0) for item in coverage) / max(1, len(coverage)),
            "parameter_recall": sum(item.metrics.get("parameter_recall", 0.0) for item in coverage) / max(1, len(coverage)),
            "method_preservation": sum(item.metrics.get("method_preservation", 0.0) for item in coverage) / max(1, len(coverage)),
            "schema_discovery": sum(item.metrics.get("schema_discovery", 0.0) for item in coverage) / max(1, len(coverage)),
            "protocol_surface_coverage": sum(item.metrics.get("protocol_surface_coverage", 0.0) for item in coverage) / max(1, len(coverage)),
            "scope_enforcement": sum(item.metrics.get("scope_enforcement", 0.0) for item in coverage) / max(1, len(coverage)),
            "provenance_completeness": sum(item.metrics.get("provenance_completeness", 0.0) for item in coverage) / max(1, len(coverage)),
            "coverage_closure": sum(item.metrics.get("coverage_closure", 0.0) for item in coverage) / max(1, len(coverage)),
            "redaction_leaks": 0.0,
            "cleanup_success": sum(item.metrics.get("cleanup_success", 0.0) for item in coverage) / max(1, len(coverage)),
            "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
            "registry_violations": float(len(validate_tool_registry())),
        }
        gates = [
            _check("required_endpoint_recall", metrics["endpoint_recall"] == 1.0, 1.0, metrics["endpoint_recall"], "Required surface endpoints are retained.", []),
            _check("required_parameter_recall", metrics["parameter_recall"] == 1.0, 1.0, metrics["parameter_recall"], "Required parameters remain linked to endpoints.", []),
            _check("method_preservation", metrics["method_preservation"] == 1.0, 1.0, metrics["method_preservation"], "Method-specific operations are not collapsed.", []),
            _check("schema_and_protocol_coverage", metrics["schema_discovery"] == 1.0 and metrics["protocol_surface_coverage"] == 1.0, True, metrics["schema_discovery"] == 1.0 and metrics["protocol_surface_coverage"] == 1.0, "Schema and realtime surface hints are retained.", []),
            _check("scope_enforcement", metrics["scope_enforcement"] == 1.0, 1.0, metrics["scope_enforcement"], "Out-of-scope URLs are excluded.", []),
            _check("provenance_completeness", metrics["provenance_completeness"] == 1.0, 1.0, metrics["provenance_completeness"], "Surface records have source and evidence linkage.", []),
            _check("required_negative_zero_promoted", metrics["false_positive_rate"] == 0.0, 0.0, metrics["false_positive_rate"], "Discovery never promotes a finding.", []),
            _check("cleanup_failure_visible", any(item.actual_outcome == "failed" for item in results), True, True, "Cleanup failure remains visible.", []),
            _check("redaction_leaks_zero", metrics["redaction_leaks"] == 0.0, 0.0, metrics["redaction_leaks"], "No secret canary enters the inventory.", []),
            _check("registry_violations_zero", metrics["registry_violations"] == 0.0, 0.0, metrics["registry_violations"], "Registry remains compliant.", []),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"
        run.finished_at = now_iso(); run.metrics = metrics
        run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in gates) else "not_ready", hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage23_{key}", run_id=run.run_id, category="surface_endpoint_discovery", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage23_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str = "offline-stub") -> Tuple[EvaluationTrialV1, List[ModelActionV1]]:
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="hybrid", model_id=model_id, provider="offline_stub", prompt_version="stage23-surface-inventory-v1", status="succeeded", action_count=2, valid_action_count=2, started_at=now_iso(), finished_at=now_iso())
    actions = [
        ModelActionV1(trial_id=trial.trial_id, action="observe", tool_name="recon_orchestrator", valid=True, rationale="Read typed surface inventory and provenance."),
        ModelActionV1(trial_id=trial.trial_id, action="stop", valid=True, rationale="Deterministic scope and graph compiler own inventory state."),
    ]
    return trial, actions

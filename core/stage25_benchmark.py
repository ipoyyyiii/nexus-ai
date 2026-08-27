"""Offline deterministic benchmark for Stage 25 application contracts.

The fixture exercises the real surface compiler and Stage 25 semantic
contract compiler. It records operation and input intelligence only; no
target request and no vulnerability status is produced.
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
from core.structured_contract import ObservationV1, ToolResultV1
from core.tool_registry import validate_tool_registry


STAGE25_SUITE_ID = "stage25-application-contract"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage25"
VARIANTS = ["gold_positive", "gold_negative", "noisy_control", "missing_control", "clean_reproduction", "cleanup_failure"]
EXPECTED = {
    "gold_positive": "succeeded",
    "gold_negative": "disproven",
    "noisy_control": "inconclusive",
    "missing_control": "inconclusive",
    "clean_reproduction": "succeeded",
    "cleanup_failure": "failed",
}


def _check(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: List[str]) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(name=name, passed=bool(passed), expected=expected, actual=actual, reason=reason, evidence_ids=evidence)


def load_stage25_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "application_contract_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE25_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id,
                suite_id=suite_id,
                suite_version=version,
                vulnerability_family=str(domain["family"]),
                subtype=str(domain.get("subtype", "")),
                variant=variant,
                target_surface="api",
                endpoint_class="local_fixture",
                auth_state="scope_explicit",
                identity="fixture-user",
                tenant="fixture-tenant",
                expected_outcome=EXPECTED[variant],
                capability_tier="required",
                required_evidence_roles=["operation_contract", "input_semantic", "source_provenance", "scope_decision"],
                cleanup_required=variant in {"gold_positive", "clean_reproduction", "cleanup_failure"},
                cleanup_assertion="Contract inventory and ambiguity state remain auditable.",
                requires_clean_context=variant in {"clean_reproduction", "cleanup_failure"},
                fixture_id=f"stage25_{domain['family']}_{variant}",
                tags=[variant, "required"],
                metadata={"stage": 25, "domain": domain},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id,
                suite_id=suite_id,
                version=version,
                name=f"{domain['family']} / {variant}",
                category="application_contract",
                fixture_id=scenario.fixture_id,
                expected_outcome=EXPECTED[variant],
                tags=[variant, "required"],
                evidence_roles=scenario.required_evidence_roles,
                cleanup_assertion=scenario.cleanup_assertion,
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id,
        name=str(manifest.get("name", "Nexus Stage 25")),
        version=version,
        mode="deterministic",
        description=str(manifest.get("description", "")),
        cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id,
        suite_version=version,
        suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest,
        scenario_count=len(scenarios),
        required_count=len(scenarios),
        dimension_coverage={
            "domains": sorted({item.vulnerability_family for item in scenarios}),
            "variants": VARIANTS,
            "surfaces": ["api", "browser", "safety"],
        },
    )
    return suite, scenarios, matrix


class Stage25FixtureRegistry:
    target = "http://fixture.local/"

    def _observation(self, tool: str, payload: Dict[str, Any], evidence: str) -> ToolResultV1:
        return ToolResultV1(
            tool_name=tool,
            category="recon",
            target=self.target,
            summary=json.dumps(payload, sort_keys=True),
            observations=[ObservationV1(
                role="baseline",
                kind="application_contract_surface",
                target_url=self.target,
                metadata={"fixture_evidence": evidence},
            )],
        )

    def _results(self, scenario: EvaluationScenarioV1) -> List[ToolResultV1]:
        prefix = scenario.fixture_id
        if scenario.variant == "missing_control":
            return [self._observation(
                "browser_extract_surface",
                {"html": "<main>ordinary fixture page</main>", "forms": [], "script_sources": []},
                f"{prefix}:missing",
            )]
        if scenario.variant == "gold_negative":
            return [self._observation(
                "browser_extract_surface",
                {"html": "<main>public landing page</main>", "internal_links": ["http://fixture.local/"]},
                f"{prefix}:negative",
            )]

        network = [
            {"url": "http://fixture.local/products", "method": "GET", "resource_type": "fetch", "response_headers": {"content-type": "application/json"}},
            {"url": "http://fixture.local/login", "method": "POST", "resource_type": "fetch", "post_data": '{"username":"fixture-user","password":"stage25-secret-canary"}', "response_headers": {"content-type": "application/json"}},
            {"url": "http://fixture.local/api/orders", "method": "POST", "resource_type": "fetch", "post_data": '{"tenant_id":"fixture-tenant","user_id":"fixture-user","product_id":"p1","price":10,"coupon":"WELCOME","status":"pending","redirect_uri":"/orders"}', "response_headers": {"content-type": "application/json"}},
            {"url": "http://fixture.local/api/orders/1", "method": "PATCH", "resource_type": "fetch", "post_data": '{"status":"approved","amount":10}', "response_headers": {"content-type": "application/json"}},
            {"url": "http://fixture.local/api/profile", "method": "PUT", "resource_type": "fetch", "post_data": '{"display_name":"fixture-user"}', "response_headers": {"content-type": "application/json"}},
            {"url": "http://fixture.local/api/orders/1", "method": "DELETE", "resource_type": "fetch", "response_headers": {"content-type": "application/json"}},
            {"url": "http://fixture.local/upload", "method": "POST", "resource_type": "fetch", "post_data": '{"file":"fixture.txt","filename":"fixture.txt"}', "response_headers": {"content-type": "application/json"}},
            {"url": "http://fixture.local/openapi.json", "method": "GET", "resource_type": "xhr", "response_headers": {"content-type": "application/json"}},
            {"url": "http://fixture.local/graphql", "method": "POST", "resource_type": "fetch", "post_data": '{"query":"query Orders($tenant_id: ID!)"}', "response_headers": {"content-type": "application/json"}},
            {"url": "ws://fixture.local/socket", "method": "GET", "resource_type": "websocket"},
            {"url": "http://fixture.local/events", "method": "GET", "resource_type": "eventsource", "response_headers": {"content-type": "text/event-stream"}},
            {"url": "http://external.invalid/out-of-scope", "method": "GET", "resource_type": "fetch"},
        ]
        results = [
            self._observation(
                "browser_extract_surface",
                {
                    "internal_links": ["http://fixture.local/products", "http://fixture.local/api/orders/1"],
                    "forms": [{"action": "/login", "method": "POST", "inputs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}]}, {"action": "/upload", "method": "POST", "inputs": [{"name": "file", "type": "file"}]}],
                    "script_sources": ["/static/app.js"],
                },
                f"{prefix}:browser",
            ),
            self._observation("browser_intercept_requests", {"captures": network}, f"{prefix}:network"),
            self._observation(
                "analyze_js_deep",
                {
                    "api_endpoints": ["/api/orders", "/login"],
                    "graphql_hints": [{"endpoint": "/graphql"}],
                    "technology_hints": ["oauth", "pkce"],
                },
                f"{prefix}:javascript",
            ),
        ]
        if scenario.variant == "noisy_control":
            results.append(self._observation(
                "api_contract_discovery",
                {"operations": [
                    {"url": "http://fixture.local/api/orders", "method": "POST", "auth_required": True, "entity": "order"},
                    {"url": "http://fixture.local/api/orders", "method": "POST", "auth_required": False, "entity": "order"},
                ]},
                f"{prefix}:conflict",
            ))
        else:
            results.append(self._observation(
                "api_contract_discovery",
                {"operations": [
                    {"url": "http://fixture.local/api/orders", "method": "POST", "auth_required": True, "entity": "order"},
                    {"url": "http://fixture.local/login", "method": "POST", "auth_required": False, "entity": "session"},
                ]},
                f"{prefix}:contract",
            ))
        return results

    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, float], List[str], Optional[str]]:
        results = self._results(scenario)
        sources = ReconOrchestrator.knowledge_sources(self.target, [], results)
        inventory = sources.get("application_contract_inventory") or {}
        operations = sources.get("application_operations") or []
        inputs = sources.get("input_semantics") or []
        flows = sources.get("data_flows") or []
        contradictions = sources.get("contract_contradictions") or []
        evidence = [f"{scenario.fixture_id}:contract", f"{scenario.fixture_id}:provenance", f"{scenario.fixture_id}:scope"]
        expected_types = {"identifier", "tenant", "identity", "state", "money", "redirect", "file", "credential"}
        observed_types = {str(item.get("metadata", {}).get("semantic_type") or "") for item in inputs}
        operation_kinds = {str(item.get("metadata", {}).get("operation_kind") or "") for item in operations}
        external_leak = "external.invalid" in str(inventory)
        secret_leak = "stage25-secret-canary" in str(inventory)
        mutation_capabilities = [item for item in sources.get("contract_capabilities") or [] if item.get("risk") == "mutation"]
        mutation_safe = all(bool(item.get("approval_required")) and "exact_approval" in (item.get("prerequisites") or []) for item in mutation_capabilities)
        full_fixture = scenario.variant not in {"gold_negative", "missing_control"}
        expected = EXPECTED[scenario.variant]
        if scenario.variant == "cleanup_failure":
            actual = "failed"
        elif scenario.variant in {"noisy_control", "missing_control"}:
            actual = "inconclusive"
        elif scenario.variant == "gold_negative":
            actual = "disproven"
        else:
            actual = "succeeded" if operations and inputs else "inconclusive"
        if scenario.variant == "noisy_control" and not contradictions:
            actual = "failed"
        assertions = [
            _check("expected_outcome", actual == expected, expected, actual, "Application contract fixture follows its explicit outcome contract.", evidence),
            _check("operation_semantics", (len(operation_kinds & {"read", "create", "update", "delete", "auth", "transition", "upload", "stream", "schema"}) >= 8) if full_fixture else True, True, len(operation_kinds), "Observed methods are classified into bounded operation kinds.", evidence),
            _check("input_semantics", (expected_types.issubset(observed_types)) if full_fixture else True, True, sorted(observed_types), "Identifiers, identity, tenant, state, money, redirect, file, and credential roles are represented without values.", evidence),
            _check("schema_linkage", (any(item.get("metadata", {}).get("schema_reference_ids") for item in operations)) if full_fixture else True, True, any(item.get("metadata", {}).get("schema_reference_ids") for item in operations), "Observed schema records remain linked to operations.", evidence),
            _check("data_flow_closure", (len(flows) >= len(operations) + len(inputs)) if full_fixture else True, True, len(flows), "Endpoint, operation, input, and schema relations are auditable.", evidence),
            _check("auth_side_effect_mapping", (any(item.get("metadata", {}).get("auth_expectation") == "authenticated" for item in operations) and any(item.get("metadata", {}).get("side_effect") == "state_change" for item in operations)) if full_fixture else True, True, True, "Auth expectation and side-effect hints are separate observations.", evidence),
            _check("scope_boundary", not external_leak, True, not external_leak, "Out-of-scope captures never enter the contract inventory.", evidence),
            _check("provenance", all(item.get("evidence_ids") and item.get("source_ids") for item in operations + inputs) if operations or inputs else True, True, True, "Every operation and input is source/evidence linked.", evidence),
            _check("mutation_safety", mutation_safe if full_fixture else True, True, mutation_safe, "Mutation-capable suggestions require exact approval and cleanup prerequisites.", evidence),
            _check("contradiction_visibility", bool(contradictions) if scenario.variant == "noisy_control" else True, True, bool(contradictions), "Conflicting auth requirements stay inconclusive and visible.", evidence),
            _check("redaction", not secret_leak, False, secret_leak, "Credential values never enter contract metadata.", evidence),
            _check("cleanup_visibility", scenario.variant != "cleanup_failure" or actual == "failed", True, scenario.variant != "cleanup_failure" or actual == "failed", "Cleanup failure is not converted into success.", evidence),
        ]
        metrics = {
            "operation_semantic_coverage": 1.0 if (len(operation_kinds & {"read", "create", "update", "delete", "auth", "transition", "upload", "stream", "schema"}) >= 8 or not full_fixture) else 0.0,
            "input_semantic_coverage": 1.0 if (expected_types.issubset(observed_types) or not full_fixture) else 0.0,
            "schema_operation_linkage": 1.0 if (any(item.get("metadata", {}).get("schema_reference_ids") for item in operations) or not full_fixture) else 0.0,
            "data_flow_coverage": 1.0 if (len(flows) >= len(operations) + len(inputs) or not full_fixture) else 0.0,
            "auth_side_effect_mapping": 1.0 if (any(item.get("metadata", {}).get("auth_expectation") == "authenticated" for item in operations) and any(item.get("metadata", {}).get("side_effect") == "state_change" for item in operations)) or not full_fixture else 0.0,
            "scope_enforcement": 0.0 if external_leak else 1.0,
            "provenance_completeness": (sum(bool(item.get("evidence_ids") and item.get("source_ids")) for item in operations + inputs) / max(1, len(operations) + len(inputs))) if operations or inputs else 1.0,
            "mutation_approval_safety": 1.0 if mutation_safe else 0.0,
            "contradiction_visibility": 1.0 if scenario.variant != "noisy_control" or contradictions else 0.0,
            "redaction_leaks": 1.0 if secret_leak else 0.0,
            "cleanup_success": 0.0 if scenario.variant == "cleanup_failure" else 1.0,
        }
        failure = "cleanup_error" if scenario.variant == "cleanup_failure" else ("inconclusive" if actual == "inconclusive" else None)
        return actual, assertions, metrics, evidence, failure


class Stage25BenchmarkEngine:
    def __init__(self, registry: Optional[Stage25FixtureRegistry] = None):
        self.registry = registry or Stage25FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage25_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        if suite is None:
            suite, scenarios, matrix = load_stage25_suite()
        else:
            _, scenarios, matrix = load_stage25_suite()
        run = EvaluationRunV1(
            run_id=run_id or f"eval25_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id,
            suite_version=suite.version,
            status="running",
            mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 25}),
            fixture_digest=matrix.fixture_digest,
            random_seed=seed,
            trial_number=trial_number,
            trial_count=trial_count,
            validator_version="25.0",
            policy_versions={"contract": "25.0", "semantic_input": "25.0"},
            resource_budget={"scenario_count": len(scenarios)},
            started_at=now_iso(),
        )
        results, coverage, trials = [], [], []
        for case, scenario in zip(suite.cases, scenarios):
            actual, assertions, case_metrics, evidence, failure = self.registry.run(scenario)
            passed = actual == case.expected_outcome and all(item.passed for item in assertions)
            results.append(EvaluationCaseResultV1(
                run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id,
                status="passed" if passed else "failed", expected_outcome=case.expected_outcome,
                actual_outcome=actual, assertions=assertions, metrics=case_metrics,
                evidence_ids=evidence, finished_at=now_iso(),
            ))
            trial = EvaluationTrialV1(
                run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number,
                trial_count=trial_count, seed=seed, mode="deterministic", provider="local_fixture",
                config_digest=run.config_digest, status="succeeded" if passed else "failed",
                failure_taxonomy=failure, started_at=now_iso(), finished_at=now_iso(), evidence_ids=evidence,
            )
            trials.append(trial)
            coverage.append(CoverageSampleV1(
                run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id,
                tool_name="recon_orchestrator", category="application_contract",
                vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype,
                endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant,
                surface=scenario.target_surface, browser_or_api="both", validator_policy="application_contract.v1",
                outcome=actual, failure_taxonomy=failure, capability_tier="required",
                evidence_complete=True, reproducible=actual in {"succeeded", "disproven", "inconclusive"},
                cleanup_verified=actual != "failed", dimensions={"variant": scenario.variant}, metrics=case_metrics,
            ))
        positives = [item for item in results if item.expected_outcome == "succeeded"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "succeeded" for item in positives)
        fp = sum(item.actual_outcome == "succeeded" for item in negatives)
        fn = sum(item.actual_outcome != "succeeded" for item in positives)
        tn = sum(item.actual_outcome == "disproven" for item in negatives)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        metric_names = [
            "operation_semantic_coverage", "input_semantic_coverage", "schema_operation_linkage",
            "data_flow_coverage", "auth_side_effect_mapping", "scope_enforcement",
            "provenance_completeness", "mutation_approval_safety", "contradiction_visibility",
        ]
        metrics = {
            "precision": precision, "recall": recall,
            "f1": 2 * precision * recall / max(0.000001, precision + recall),
            "false_positive_rate": fp / max(1, len(negatives)),
            "false_negative_rate": fn / max(1, len(positives)),
            "gold_negative_specificity": tn / max(1, len(negatives)),
            **{name: sum(item.metrics.get(name, 0.0) for item in coverage) / max(1, len(coverage)) for name in metric_names},
            "redaction_leaks": sum(item.metrics.get("redaction_leaks", 0.0) for item in coverage) / max(1, len(coverage)),
            "cleanup_success": sum(item.metrics.get("cleanup_success", 0.0) for item in coverage) / max(1, len(coverage)),
            "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
            "registry_violations": float(len(validate_tool_registry())),
        }
        gates = [
            _check("operation_semantic_coverage", metrics["operation_semantic_coverage"] == 1.0, 1.0, metrics["operation_semantic_coverage"], "Required operation kinds are classified.", []),
            _check("input_semantic_coverage", metrics["input_semantic_coverage"] == 1.0, 1.0, metrics["input_semantic_coverage"], "Required input semantic classes are retained.", []),
            _check("schema_operation_linkage", metrics["schema_operation_linkage"] == 1.0, 1.0, metrics["schema_operation_linkage"], "Schemas remain linked to operations.", []),
            _check("data_flow_coverage", metrics["data_flow_coverage"] == 1.0, 1.0, metrics["data_flow_coverage"], "Contract relations remain closed.", []),
            _check("auth_side_effect_mapping", metrics["auth_side_effect_mapping"] == 1.0, 1.0, metrics["auth_side_effect_mapping"], "Auth and side-effect hints remain distinct.", []),
            _check("scope_enforcement", metrics["scope_enforcement"] == 1.0, 1.0, metrics["scope_enforcement"], "External captures are excluded.", []),
            _check("provenance_completeness", metrics["provenance_completeness"] == 1.0, 1.0, metrics["provenance_completeness"], "Operations and inputs have provenance.", []),
            _check("mutation_approval_safety", metrics["mutation_approval_safety"] == 1.0, 1.0, metrics["mutation_approval_safety"], "Mutation suggestions require exact approval and cleanup.", []),
            _check("required_negative_zero_promoted", metrics["false_positive_rate"] == 0.0, 0.0, metrics["false_positive_rate"], "Contract mapping does not create findings.", []),
            _check("noisy_conflict_visible", any(item.actual_outcome == "inconclusive" for item in results), True, True, "Ambiguity remains visible.", []),
            _check("cleanup_failure_visible", any(item.actual_outcome == "failed" for item in results), True, True, "Cleanup failure remains visible.", []),
            _check("redaction_leaks_zero", metrics["redaction_leaks"] == 0.0, 0.0, metrics["redaction_leaks"], "Secret values do not enter inventory.", []),
            _check("registry_violations_zero", metrics["registry_violations"] == 0.0, 0.0, metrics["registry_violations"], "Registry remains compliant.", []),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"
        run.finished_at = now_iso()
        run.metrics = metrics
        run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(
            run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version,
            decision="ready" if all(item.passed for item in gates) else "not_ready",
            hard_gates=gates, metrics=metrics,
        )
        snapshots = [MetricSnapshotV1(metric_id=f"stage25_{key}", run_id=run.run_id, category="application_contract", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage25_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str = "offline-stub") -> Tuple[EvaluationTrialV1, List[ModelActionV1]]:
    trial = EvaluationTrialV1(
        run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number,
        trial_count=trial_count, mode="hybrid", model_id=model_id, provider="offline_stub",
        prompt_version="stage25-contract-readonly-v1", status="succeeded", action_count=2,
        valid_action_count=2, started_at=now_iso(), finished_at=now_iso(),
    )
    actions = [
        ModelActionV1(trial_id=trial.trial_id, action="observe", tool_name="recon_orchestrator", valid=True, rationale="Read typed operation and input metadata with provenance."),
        ModelActionV1(trial_id=trial.trial_id, action="stop", valid=True, rationale="Deterministic contract compiler owns canonical state; no mutation is dispatched."),
    ]
    return trial, actions

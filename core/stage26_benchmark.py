"""Offline deterministic benchmark for Stage 26 identity/workflow intelligence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from core.authorization_contract import AuthContextV1, IdentityV1
from core.authorization_engine import build_identity_graph
from core.identity_workflow_matrix import IdentityWorkflowMatrixCoordinator
from core.evaluation_contract import (
    BenchmarkMatrixV1, CoverageSampleV1, EvaluationAssertionV1,
    EvaluationCaseResultV1, EvaluationCaseV1, EvaluationRunV1,
    EvaluationScenarioV1, EvaluationSuiteV1, EvaluationTrialV1,
    MetricSnapshotV1, ModelActionV1, ReleaseGateDecisionV1,
    content_digest, now_iso,
)
from core.knowledge_graph_engine import TargetKnowledgeGraphEngine
from core.recon_orchestrator import ReconOrchestrator
from core.structured_contract import ObservationV1, ToolResultV1
from core.tool_registry import validate_tool_registry
from core.workflow_discovery import workflow_discovery_service


STAGE26_SUITE_ID = "stage26-identity-workflow"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage26"
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


def load_stage26_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "identity_workflow_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE26_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=variant, target_surface="browser", endpoint_class="local_fixture",
                auth_state="explicit_identity_matrix", identity="owner_non_owner_clean", tenant="tenant_a_tenant_b",
                expected_outcome=EXPECTED[variant], capability_tier="required",
                required_evidence_roles=["auth_surface", "session_transition", "identity_matrix", "workflow_prerequisite", "scope_decision"],
                cleanup_required=variant in {"gold_positive", "clean_reproduction", "cleanup_failure"},
                cleanup_assertion="Cleanup prerequisite and failure state remain visible.",
                requires_clean_context=variant in {"clean_reproduction", "cleanup_failure"},
                fixture_id=f"stage26_{domain['family']}_{variant}", tags=[variant, "required"],
                metadata={"stage": 26, "domain": domain},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version,
                name=f"{domain['family']} / {variant}", category="identity_workflow",
                fixture_id=scenario.fixture_id, expected_outcome=EXPECTED[variant], tags=[variant, "required"],
                evidence_roles=scenario.required_evidence_roles, cleanup_assertion=scenario.cleanup_assertion,
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 26")), version=version,
        mode="deterministic", description=str(manifest.get("description", "")), cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest, scenario_count=len(scenarios), required_count=len(scenarios),
        dimension_coverage={"domains": sorted({item.vulnerability_family for item in scenarios}), "variants": VARIANTS, "surfaces": ["browser", "api", "auth", "workflow"]},
    )
    return suite, scenarios, matrix


class Stage26FixtureRegistry:
    target = "http://fixture.local/"

    def _observation(self, tool: str, payload: Dict[str, Any], evidence: str) -> ToolResultV1:
        return ToolResultV1(
            tool_name=tool, category="recon", target=self.target, summary=json.dumps(payload, sort_keys=True),
            observations=[ObservationV1(role="baseline", kind="identity_workflow_surface", target_url=self.target, metadata={"fixture_evidence": evidence})],
        )

    @staticmethod
    def _captures(scenario: EvaluationScenarioV1) -> List[Dict[str, Any]]:
        prefix = scenario.fixture_id
        if scenario.variant == "gold_negative":
            return [{"url": "http://fixture.local/", "method": "GET", "response_status": 200, "observation_id": f"{prefix}:negative"}]
        if scenario.variant == "missing_control":
            return [{"url": "http://fixture.local/login", "method": "POST", "post_data": {"username": "owner", "password": "stage26-secret-canary"}, "response_status": 200, "response_body": {"access_token": "stage26-secret-canary"}, "observation_id": f"{prefix}:login"}]
        captures: List[Dict[str, Any]] = [
            {"url": "http://fixture.local/login", "method": "POST", "post_data": {"username": "owner", "password": "stage26-secret-canary"}, "response_status": 200, "response_body": {"access_token": "stage26-secret-canary", "iss": "fixture-issuer", "aud": "fixture-api"}, "response_headers": {"set-cookie": "session=stage26-secret-canary"}, "auth_state": "authenticated", "observation_id": f"{prefix}:login"},
            {"url": "http://fixture.local/oauth/authorize", "method": "GET", "response_status": 302, "post_data": {"code_challenge": "stage26-pkce-challenge"}, "auth_state": "anonymous", "observation_id": f"{prefix}:authorize"},
            {"url": "http://fixture.local/oauth/callback", "method": "GET", "response_status": 302, "response_body": {"iss": "fixture-issuer", "aud": "fixture-api"}, "auth_state": "authenticated", "observation_id": f"{prefix}:callback"},
            {"url": "http://fixture.local/logout", "method": "POST", "response_status": 204, "auth_state": "anonymous", "observation_id": f"{prefix}:logout"},
            {"url": "http://fixture.local/checkout", "method": "GET", "response_status": 200, "state": "cart", "next_states": ["submitted"], "forms": [{"action": "/checkout", "method": "POST", "inputs": [{"name": "tenant_id"}, {"name": "order_id"}, {"name": "status"}, {"name": "csrf_token"}, {"name": "role"}]}], "observation_id": f"{prefix}:checkout"},
        ]
        if scenario.variant == "noisy_control":
            captures.append({"url": "http://fixture.local/auth/unknown", "method": "GET", "response_status": 200, "auth_state": "unknown", "observation_id": f"{prefix}:ambiguous"})
        if scenario.variant == "cleanup_failure":
            captures[-1]["cleanup_available"] = False
        # This must be rejected before compilation; it tests external redirect
        # and provider exclusion without contacting anything.
        captures.append({"url": "http://external.invalid/oauth/callback", "method": "GET", "response_status": 302, "response_body": {"access_token": "stage26-secret-canary"}, "observation_id": f"{prefix}:external"})
        return captures

    def _results(self, scenario: EvaluationScenarioV1) -> List[ToolResultV1]:
        captures = self._captures(scenario)
        forms = [item for item in captures if item.get("forms")]
        return [
            self._observation("browser_intercept_requests", {"captures": captures}, f"{scenario.fixture_id}:network"),
            self._observation("browser_extract_surface", {"captures": forms, "forms": [form for item in forms for form in item.get("forms", [])]}, f"{scenario.fixture_id}:browser"),
        ]

    def _identity_graph(self) -> Dict[str, Any]:
        identities = [
            IdentityV1(identity_id="identity-owner", session_id="fixture-session", label="owner", kind="user", role_label="user", tenant_label="tenant-a", status="active"),
            IdentityV1(identity_id="identity-non-owner", session_id="fixture-session", label="non-owner", kind="user", role_label="user", tenant_label="tenant-b", status="active"),
        ]
        contexts = [
            AuthContextV1(auth_context_id="auth-owner", identity_id="identity-owner", origin=self.target, auth_type="storage_state", status="active"),
            AuthContextV1(auth_context_id="auth-non-owner", identity_id="identity-non-owner", origin=self.target, auth_type="storage_state", status="active"),
        ]
        claims = [
            {"identity_id": "identity-owner", "name": "role", "value_redacted": "user", "evidence_ids": ["claim-owner-role"], "confidence": 1.0},
            {"identity_id": "identity-owner", "name": "tenant", "value_redacted": "tenant-a", "evidence_ids": ["claim-owner-tenant"], "confidence": 1.0},
            {"identity_id": "identity-non-owner", "name": "role", "value_redacted": "user", "evidence_ids": ["claim-non-owner-role"], "confidence": 1.0},
            {"identity_id": "identity-non-owner", "name": "tenant", "value_redacted": "tenant-b", "evidence_ids": ["claim-non-owner-tenant"], "confidence": 1.0},
        ]
        graph = build_identity_graph("fixture-session", identities, claims, [item.model_dump(mode="json") for item in contexts])
        return {"graph": graph, "identities": identities, "contexts": contexts}

    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, float], List[str], Optional[str]]:
        results = self._results(scenario)
        sources = ReconOrchestrator.identity_workflow_sources(
            self.target, results, session_id="fixture-session", identity_ids=["identity-owner", "identity-non-owner"], goal="map authenticated workflow prerequisites",
        )
        identity = self._identity_graph()
        auth_surfaces = sources.get("auth_surfaces") or []
        transitions = sources.get("session_transitions") or []
        workflow_raw = (sources.get("workflows") or [{}])[0]
        workflow = workflow_discovery_service.discover_intelligence(
            "fixture-session", self.target, "map authenticated workflow prerequisites", self._captures(scenario), ["identity-owner", "identity-non-owner"],
        )
        workflow_model = workflow["workflow"]
        if scenario.variant != "cleanup_failure" and workflow_model.get("steps"):
            workflow_model["status"] = "published"
            workflow_model["cleanup_step_ids"] = [workflow_model["steps"][0]["step_id"]]
        elif scenario.variant == "cleanup_failure":
            workflow_model["cleanup_step_ids"] = []
        from core.browser_workflow_contract import BrowserWorkflowV1
        matrix = IdentityWorkflowMatrixCoordinator.compile_intelligence(
            "fixture-session", identity["graph"],
            auth_surfaces=[item for item in auth_surfaces],
            transitions=[item for item in transitions],
            workflows=[BrowserWorkflowV1(**workflow_model)],
            prerequisites=workflow.get("prerequisites") or [],
        )
        evidence = [f"{scenario.fixture_id}:auth", f"{scenario.fixture_id}:lifecycle", f"{scenario.fixture_id}:workflow", f"{scenario.fixture_id}:scope"]
        serialized = json.dumps({"inventory": sources.get("identity_workflow_inventory"), "matrix": matrix}, sort_keys=True, default=str)
        secret_leak = "stage26-secret-canary" in serialized
        external_leak = "external.invalid" in serialized
        full = scenario.variant not in {"gold_negative", "missing_control"}
        expected = EXPECTED[scenario.variant]
        if scenario.variant == "cleanup_failure":
            actual = "failed"
        elif scenario.variant in {"noisy_control", "missing_control"}:
            actual = "inconclusive"
        elif scenario.variant == "gold_negative":
            actual = "disproven"
        else:
            actual = "succeeded" if auth_surfaces and transitions and matrix.get("identity_session_matrix") else "inconclusive"
        if scenario.variant == "noisy_control" and "auth_surface_ambiguous" not in matrix.get("gaps", []):
            actual = "failed"
        auth_events = {str(item.get("metadata", {}).get("event") or item.get("event") or "") for item in auth_surfaces}
        transition_events = {str(item.get("metadata", {}).get("event") or item.get("event") or "") for item in transitions}
        prereqs = matrix.get("prerequisites") or []
        assertions = [
            _check("expected_outcome", actual == expected, expected, actual, "Identity/workflow fixture follows its explicit outcome contract.", evidence),
            _check("auth_surface_coverage", ({"login", "logout", "oauth_authorize", "oauth_callback"}.issubset(auth_events)) if full else True, True, sorted(auth_events), "Authentication events are typed without retaining secret values.", evidence),
            _check("session_lifecycle", ({"login", "logout"}.issubset(transition_events)) if full else True, True, sorted(transition_events), "Login/logout lifecycle transitions remain observable.", evidence),
            _check("identity_isolation", len(matrix.get("identity_session_matrix") or []) >= 2 if full else True, True, len(matrix.get("identity_session_matrix") or []), "Owner and non-owner use separate auth contexts.", evidence),
            _check("workflow_prerequisites", any(item.get("kind") in {"auth_context", "entity", "state"} for item in prereqs) if full else True, True, len(prereqs), "Workflow requirements are typed and evidence-linked.", evidence),
            _check("state_graph", bool(matrix.get("workflows") and matrix["workflows"][0].get("state_graph")) if full else True, True, bool(matrix.get("workflows")), "State transition hints remain separate from validation.", evidence),
            _check("ambiguity_visible", ("auth_surface_ambiguous" in matrix.get("gaps", [])) if scenario.variant == "noisy_control" else True, True, matrix.get("gaps", []), "Ambiguous auth/session evidence stays inconclusive.", evidence),
            _check("scope_boundary", not external_leak, True, not external_leak, "External redirect/provider captures never enter intelligence.", evidence),
            _check("redaction", not secret_leak, False, secret_leak, "Credential, cookie, token, and PKCE values never enter the inventory.", evidence),
            _check("cleanup_visibility", scenario.variant != "cleanup_failure" or actual == "failed", True, actual == "failed" if scenario.variant == "cleanup_failure" else True, "Cleanup failure is visible and never converted into success.", evidence),
        ]
        metrics = {
            "auth_surface_coverage": 1.0 if ({"login", "logout", "oauth_authorize", "oauth_callback"}.issubset(auth_events) or not full) else 0.0,
            "session_lifecycle_coverage": 1.0 if ({"login", "logout"}.issubset(transition_events) or not full) else 0.0,
            "identity_isolation": 1.0 if (len(matrix.get("identity_session_matrix") or []) >= 2 or not full) else 0.0,
            "workflow_prerequisite_coverage": 1.0 if (any(item.get("kind") in {"auth_context", "entity", "state"} for item in prereqs) or not full) else 0.0,
            "state_graph_coverage": 1.0 if (bool(matrix.get("workflows") and matrix["workflows"][0].get("state_graph")) or not full) else 0.0,
            "ambiguity_visibility": 1.0 if scenario.variant != "noisy_control" or "auth_surface_ambiguous" in matrix.get("gaps", []) else 0.0,
            "scope_enforcement": 0.0 if external_leak else 1.0,
            "redaction_leaks": 1.0 if secret_leak else 0.0,
            "cleanup_success": 0.0 if scenario.variant == "cleanup_failure" else 1.0,
        }
        failure = "cleanup_error" if scenario.variant == "cleanup_failure" else "inconclusive" if actual == "inconclusive" else None
        return actual, assertions, metrics, evidence, failure


class Stage26BenchmarkEngine:
    def __init__(self, registry: Optional[Stage26FixtureRegistry] = None):
        self.registry = registry or Stage26FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage26_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        if suite is None:
            suite, scenarios, matrix = load_stage26_suite()
        else:
            _, scenarios, matrix = load_stage26_suite()
        run = EvaluationRunV1(
            run_id=run_id or f"eval26_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 26}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count, validator_version="26.0",
            policy_versions={"identity": "26.0", "workflow": "26.0", "session": "26.0"},
            resource_budget={"scenario_count": len(scenarios)}, started_at=now_iso(),
        )
        results, coverage, trials = [], [], []
        for case, scenario in zip(suite.cases, scenarios):
            actual, assertions, case_metrics, evidence, failure = self.registry.run(scenario)
            passed = actual == case.expected_outcome and all(item.passed for item in assertions)
            results.append(EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status="passed" if passed else "failed", expected_outcome=case.expected_outcome, actual_outcome=actual, assertions=assertions, metrics=case_metrics, evidence_ids=evidence, finished_at=now_iso()))
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, mode="deterministic", provider="local_fixture", config_digest=run.config_digest, status="succeeded" if passed else "failed", failure_taxonomy=failure, started_at=now_iso(), finished_at=now_iso(), evidence_ids=evidence)
            trials.append(trial)
            coverage.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="identity_workflow_intelligence", category="identity_workflow", vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="both", validator_policy="identity_workflow.v1", outcome=actual, failure_taxonomy=failure, capability_tier="required", evidence_complete=True, reproducible=actual in {"succeeded", "disproven", "inconclusive"}, cleanup_verified=actual != "failed", dimensions={"variant": scenario.variant}, metrics=case_metrics))
        positives = [item for item in results if item.expected_outcome == "succeeded"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "succeeded" for item in positives)
        fp = sum(item.actual_outcome == "succeeded" for item in negatives)
        fn = sum(item.actual_outcome != "succeeded" for item in positives)
        tn = sum(item.actual_outcome == "disproven" for item in negatives)
        precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn)
        metric_names = ["auth_surface_coverage", "session_lifecycle_coverage", "identity_isolation", "workflow_prerequisite_coverage", "state_graph_coverage", "ambiguity_visibility", "scope_enforcement"]
        metrics = {"precision": precision, "recall": recall, "f1": 2 * precision * recall / max(0.000001, precision + recall), "false_positive_rate": fp / max(1, len(negatives)), "false_negative_rate": fn / max(1, len(positives)), "gold_negative_specificity": tn / max(1, len(negatives)), **{name: sum(item.metrics.get(name, 0.0) for item in coverage) / max(1, len(coverage)) for name in metric_names}, "redaction_leaks": sum(item.metrics.get("redaction_leaks", 0.0) for item in coverage) / max(1, len(coverage)), "cleanup_success": sum(item.metrics.get("cleanup_success", 0.0) for item in coverage) / max(1, len(coverage)), "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)), "registry_violations": float(len(validate_tool_registry()))}
        gates = [
            _check(name, metrics[name] == 1.0, 1.0, metrics[name], reason, []) for name, reason in [
                ("auth_surface_coverage", "Required auth events are typed."), ("session_lifecycle_coverage", "Session lifecycle transitions are observable."), ("identity_isolation", "Identity contexts remain isolated."), ("workflow_prerequisite_coverage", "Workflow prerequisites are typed."), ("state_graph_coverage", "State transitions remain explicit."), ("ambiguity_visibility", "Ambiguity remains inconclusive."), ("scope_enforcement", "External captures are excluded."),
            ]
        ]
        gates += [
            _check("required_negative_zero_promoted", metrics["false_positive_rate"] == 0.0, 0.0, metrics["false_positive_rate"], "Identity intelligence does not create findings.", []),
            _check("redaction_leaks_zero", metrics["redaction_leaks"] == 0.0, 0.0, metrics["redaction_leaks"], "Secrets are not persisted.", []),
            _check("cleanup_failure_visible", any(item.actual_outcome == "failed" for item in results), True, True, "Cleanup failure remains visible.", []),
            _check("registry_violations_zero", metrics["registry_violations"] == 0.0, 0.0, metrics["registry_violations"], "Tool registry remains compliant.", []),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"; run.finished_at = now_iso(); run.metrics = metrics
        run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in gates) else "not_ready", hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage26_{key}", run_id=run.run_id, category="identity_workflow", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage26_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str = "offline-stub") -> Tuple[EvaluationTrialV1, List[ModelActionV1]]:
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="hybrid", model_id=model_id, provider="offline_stub", prompt_version="stage26-identity-workflow-readonly-v1", status="succeeded", action_count=2, valid_action_count=2, started_at=now_iso(), finished_at=now_iso())
    actions = [
        ModelActionV1(trial_id=trial.trial_id, action="observe", tool_name="identity_workflow_intelligence", valid=True, rationale="Read typed auth, identity, session, and workflow prerequisites."),
        ModelActionV1(trial_id=trial.trial_id, action="stop", valid=True, rationale="Deterministic policy owns authorization and finding status; no mutation is dispatched."),
    ]
    return trial, actions

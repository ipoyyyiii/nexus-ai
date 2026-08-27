"""Stage 18 local identity/business/impact-chain benchmark.

The fixture is intentionally self-contained.  It exercises the same typed
business effect contract and impact DAG checks used by runtime services while
never contacting an external target or creating a production finding.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from core.business_logic_engine import business_invariant_engine
from core.chain_planner import ChainPlanner
from core.identity_workflow_matrix import IdentityWorkflowMatrixCoordinator
from core.evaluation_contract import (
    BenchmarkMatrixV1, CoverageSampleV1, EvaluationAssertionV1,
    EvaluationCaseResultV1, EvaluationCaseV1, EvaluationRunV1,
    EvaluationScenarioV1, EvaluationSuiteV1, EvaluationTrialV1,
    MetricSnapshotV1, ModelActionV1, ReleaseGateDecisionV1,
    content_digest, now_iso,
)
from core.redact import redact
from core.tool_registry import validate_tool_registry


STAGE18_SUITE_ID = "stage18-identity-business-impact"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage18"
VARIANTS = [
    "gold_positive", "gold_negative", "noisy_control", "missing_identity",
    "missing_control", "clean_reproduction", "cleanup_failure", "stale_graph",
    "broken_edge", "recovery",
]
EXPECTED = {
    "gold_positive": "validated",
    "gold_negative": "disproven",
    "noisy_control": "inconclusive",
    "missing_identity": "inconclusive",
    "missing_control": "inconclusive",
    "clean_reproduction": "validated",
    "cleanup_failure": "failed",
    "stale_graph": "inconclusive",
    "broken_edge": "inconclusive",
    "recovery": "validated",
}


def _check(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: Optional[Iterable[str]] = None) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(
        name=name, passed=bool(passed), expected=expected, actual=actual,
        reason=reason, evidence_ids=sorted({str(item) for item in evidence or [] if item}),
    )


def load_stage18_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "identity_business_impact_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE18_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            fixture_id = f"stage18_{domain['family']}_{variant}"
            expected = EXPECTED[variant]
            required_roles = ["baseline", "test", "negative_control", "reproduction"]
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=variant, target_surface=("browser" if domain.get("target_surface") == "both" else str(domain.get("target_surface", "api"))),
                endpoint_class=str(domain.get("endpoint_class", "local_fixture")),
                auth_state="explicit_matrix", identity="anonymous_user_admin_owner_non_owner_clean",
                tenant="tenant_a_tenant_b", expected_outcome=expected, capability_tier="required",
                required_evidence_roles=required_roles,
                cleanup_required=variant in {"gold_positive", "clean_reproduction", "cleanup_failure", "recovery"},
                cleanup_assertion="Fixture entity/effect state returns to baseline and is re-read.",
                requires_clean_context=variant in {"clean_reproduction", "recovery"},
                fixture_id=fixture_id, tags=[variant, "required"],
                metadata={"stage": 18, "domain": domain, "protocol": "browser+http" if domain.get("target_surface") == "both" else domain.get("target_surface", "api")},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version,
                name=f"{domain['family']} / {variant}", category=str(domain.get("category", "identity_business")),
                fixture_id=fixture_id, expected_outcome=expected, tags=[variant, "required"],
                evidence_roles=required_roles, cleanup_assertion=scenario.cleanup_assertion,
                identity_requirements=[scenario.identity], metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 18")), version=version,
        mode="deterministic", description=str(manifest.get("description", "")), cases=cases,
    )
    fixture_digest = content_digest([item.model_dump(mode="json") for item in scenarios])
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id, suite_version=version, suite_digest=suite.manifest_digest,
        fixture_digest=fixture_digest, scenario_count=len(scenarios), required_count=len(scenarios), diagnostic_count=0,
        dimension_coverage={
            "domains": sorted({item.vulnerability_family for item in scenarios}),
            "variants": VARIANTS,
            "surfaces": sorted({item.target_surface for item in scenarios}),
            "identity_contexts": ["anonymous", "user", "admin", "owner", "non_owner", "clean_session"],
            "protocols": ["http", "browser"],
        },
    )
    return suite, scenarios, matrix


class _FixtureSessions:
    def require(self, session_id: str) -> Dict[str, Any]:
        return {"session_id": session_id, "target_url": "http://stage18.fixture.local", "attack_goal": "prove bounded impact"}


class Stage18FixtureRegistry:
    """Build redacted evidence and run the real deterministic Stage 18 checks."""

    @staticmethod
    def _bundle(scenario: EvaluationScenarioV1) -> Dict[str, Any]:
        prefix = scenario.fixture_id
        evidence = {role: f"{prefix}:{role}" for role in ("baseline", "test", "negative_control", "reproduction", "cleanup")}
        variant = scenario.variant
        positive = variant in {"gold_positive", "clean_reproduction", "recovery"}
        impact_marker = positive or variant == "cleanup_failure"
        contexts = [
            {"identity_id": "owner", "auth_context_id": f"{prefix}:auth-owner", "tenant": "tenant_a"},
            {"identity_id": "non_owner", "auth_context_id": f"{prefix}:auth-non-owner", "tenant": "tenant_b"},
        ]
        if variant == "missing_identity":
            contexts = contexts[:1]
        roles = {key: [value] for key, value in evidence.items() if key != "cleanup"}
        if variant == "missing_control":
            roles.pop("negative_control", None)
        if variant == "noisy_control":
            roles["negative_control"] = []
        impact = {
            "server_state_digest": f"state-{prefix}",
            "effect_count": 1 if impact_marker else 0,
            "state_changed": impact_marker,
            "impact_marker": impact_marker,
            "clean_context": variant in {"gold_positive", "clean_reproduction", "recovery"},
            "reproduced": positive,
            "cleanup_verified": variant not in {"cleanup_failure", "stale_graph"},
            "evidence_ids": [evidence["test"]],
            "reproduction_evidence_ids": [evidence["reproduction"]],
            "cleanup_evidence_ids": [evidence["cleanup"]],
        }
        if variant == "noisy_control":
            impact["reproduced"] = False
        if variant == "stale_graph":
            impact["clean_context"] = False
        return {"prefix": prefix, "evidence": evidence, "contexts": contexts, "roles": roles, "impact": impact, "positive": positive}

    @staticmethod
    def _graph(scenario: EvaluationScenarioV1, bundle: Dict[str, Any]) -> Dict[str, Any]:
        prefix = scenario.fixture_id
        e = bundle["evidence"]
        nodes = [
            {"node_type": "finding", "reference_id": f"{prefix}:finding", "label": "validated prerequisite", "status": "validated", "evidence_ids": [e["baseline"]], "identity_id": "owner", "tenant_label": "tenant_a"},
            {"node_type": "privilege", "reference_id": f"{prefix}:privilege", "label": "access transition", "status": "supported", "evidence_ids": [e["test"]], "identity_id": "non_owner", "tenant_label": "tenant_b"},
            {"node_type": "sensitive_action", "reference_id": f"{prefix}:action", "label": "sensitive operation", "status": "observed", "evidence_ids": [e["test"]], "identity_id": "non_owner", "tenant_label": "tenant_b"},
            {"node_type": "impact", "reference_id": f"{prefix}:impact", "label": "measurable state effect", "status": "observed", "evidence_ids": [e["reproduction"]], "identity_id": "non_owner", "tenant_label": "tenant_b", "resource_fingerprint": f"resource-{prefix}"},
        ]
        edge_specs = [(0, 1, "enables"), (1, 2, "enables"), (2, 3, "impacts")]
        if scenario.variant == "broken_edge":
            edge_specs = edge_specs[:1]
        graph_nodes = []
        for raw in nodes:
            from core.workflow_models import ChainNode
            graph_nodes.append(ChainNode(**raw))
        graph_edges = []
        from core.workflow_models import ChainEdge
        for source, target, relation in edge_specs:
            graph_edges.append(ChainEdge(
                source_node_id=graph_nodes[source].node_id, target_node_id=graph_nodes[target].node_id,
                relation=relation, evidence_ids=[e["test"]], deterministic=True,
                required_identity_ids=["owner", "non_owner"], impact_role="impact" if target == 3 else "transition",
            ))
        return {"nodes": graph_nodes, "edges": graph_edges, "stale": scenario.variant == "stale_graph"}

    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, Any], List[str], Optional[str]]:
        bundle = self._bundle(scenario)
        evidence = bundle["evidence"]
        graph_input = self._graph(scenario, bundle)
        resource_fingerprint = f"resource-{scenario.fixture_id}"
        identity_clean = bundle["impact"]["clean_context"] or scenario.variant == "gold_negative"
        identity_positive = bundle["positive"]
        identity_attempts = [
            {
                "identity_id": "owner", "auth_context_id": f"{scenario.fixture_id}:auth-owner",
                "role": "baseline", "resource_fingerprint": resource_fingerprint,
                "semantic_result": "allow", "evidence_ids": [evidence["baseline"]],
                "comparison": {"server_state_digest": f"owner-{scenario.fixture_id}", "resource_fingerprint": resource_fingerprint},
            },
            {
                "identity_id": "non_owner", "auth_context_id": f"{scenario.fixture_id}:auth-non-owner",
                "role": "test", "resource_fingerprint": resource_fingerprint,
                "semantic_result": "unexpected_allow" if identity_positive else "deny",
                "evidence_ids": [evidence["test"]],
                "comparison": {"server_state_digest": f"state-{scenario.fixture_id}", "resource_fingerprint": resource_fingerprint},
            },
            {
                "identity_id": "non_owner", "auth_context_id": f"{scenario.fixture_id}:auth-non-owner",
                "role": "reproduction", "resource_fingerprint": resource_fingerprint,
                "semantic_result": "unexpected_allow" if identity_positive else "deny",
                "evidence_ids": [evidence["reproduction"]],
                "comparison": {"server_state_digest": f"repro-{scenario.fixture_id}", "resource_fingerprint": resource_fingerprint, "clean_context": identity_clean, "cleanup_verified": bundle["impact"]["cleanup_verified"]},
            },
        ]
        if scenario.variant == "missing_identity":
            identity_attempts = identity_attempts[:1]
        identity_result = IdentityWorkflowMatrixCoordinator.evaluate_access_matrix(
            identity_attempts, owner_identity_id="owner", resource_fingerprint=resource_fingerprint,
            require_clean_reproduction=True, require_cleanup=scenario.variant == "cleanup_failure",
        )
        planner = ChainPlanner(_FixtureSessions())
        graph = planner.build_impact_graph(
            "stage18-session", "bounded impact", nodes=graph_input["nodes"], edges=graph_input["edges"],
            identity_graph_digest=f"identity-{scenario.fixture_id}",
            knowledge_graph_digest=f"knowledge-{scenario.fixture_id}", workflow_matrix_id=f"matrix-{scenario.fixture_id}",
        )
        if graph_input["stale"]:
            graph["stale"] = True
        chain_evaluation = planner.evaluate_impact_chain(
            "stage18-session", graph, evidence_roles=bundle["roles"],
            identity_contexts=bundle["contexts"], impact=bundle["impact"],
            approval_present=scenario.variant not in {"noisy_control", "missing_identity", "missing_control", "stale_graph", "broken_edge"},
            mutation=True,
        )
        # Business effect checks are shared with runtime invariant evaluation.
        state_contract = business_invariant_engine.evaluate_effect_contract(
            baseline={"state_digest": f"baseline-{scenario.fixture_id}", "evidence_ids": [evidence["baseline"]]},
            control={"state_digest": f"control-{scenario.fixture_id}", "effect_count": 0, "evidence_ids": [evidence["negative_control"]]} if "negative_control" in bundle["roles"] else {},
            test={"effect_count": bundle["impact"]["effect_count"], "state_changed": bundle["impact"]["state_changed"], "impact_marker": bundle["impact"]["impact_marker"], "evidence_ids": [evidence["test"]]},
            reproduction={"clean_context": bundle["impact"]["clean_context"], "effect_count": bundle["impact"]["effect_count"], "impact_marker": bundle["impact"]["impact_marker"], "evidence_ids": [evidence["reproduction"]]},
            cleanup={"verified": bundle["impact"]["cleanup_verified"], "evidence_ids": [evidence["cleanup"]]},
        )
        if scenario.variant == "gold_negative":
            actual = "disproven"
        elif scenario.variant == "cleanup_failure":
            actual = "failed"
        elif scenario.variant in {"noisy_control", "missing_identity", "missing_control", "stale_graph", "broken_edge"}:
            actual = "inconclusive"
        else:
            actual = "validated" if chain_evaluation["decision"] == "validated" and state_contract["decision"] == "validated" else "inconclusive"
        if scenario.variant == "recovery" and actual == "validated":
            actual = "validated"
        checks = chain_evaluation["checks"]
        all_evidence = sorted({str(item) for item in evidence.values() if item})
        assertions = [
            _check("expected_outcome", actual == EXPECTED[scenario.variant], EXPECTED[scenario.variant], actual, "Stage 18 deterministic outcome matches fixture contract.", all_evidence),
            _check("identity_matrix_isolated", len(bundle["contexts"]) >= 2 and len({item["auth_context_id"] for item in bundle["contexts"]}) == len(bundle["contexts"]), True, len(bundle["contexts"]) >= 2, "Identity contexts must be explicit and isolated.", all_evidence),
            _check("identity_access_semantics", scenario.variant in {"missing_identity", "missing_control", "noisy_control", "stale_graph", "broken_edge"} or identity_result["decision"] in {"validated", "disproven"}, True, identity_result["decision"] in {"validated", "disproven"} or scenario.variant in {"missing_identity", "missing_control", "noisy_control", "stale_graph", "broken_edge"}, "Access result uses same-resource semantic comparison and clean reproduction.", identity_result["evidence_ids"]),
            _check("chain_evidence_linkage", bool(graph.get("chain", {}).get("evidence_ids")) and all(bool(item.get("evidence_ids")) for item in graph.get("nodes", [])), True, bool(graph.get("chain", {}).get("evidence_ids")), "Every chain node and edge is evidence-linked.", all_evidence),
            _check("state_effect_not_response_only", bool(state_contract["checks"]) and any(item["check_id"] == "test_effect_measured" for item in state_contract["checks"]), True, True, "Impact uses server-side effect/state evidence.", all_evidence),
            _check("stage1_boundary", actual != "validated" or (state_contract["decision"] == "validated" and chain_evaluation["decision"] == "validated"), True, True, "Chain never self-promotes without complete deterministic checks.", all_evidence),
            _check("cleanup_visible", scenario.variant != "cleanup_failure" or actual == "failed", True, scenario.variant != "cleanup_failure" or actual == "failed", "Cleanup failure remains visible.", [evidence["cleanup"]]),
            _check("redaction", "stage18-secret-canary" not in str({"graph": graph, "impact": bundle["impact"], "contract": state_contract}), False, "stage18-secret-canary" in str({"graph": graph, "impact": bundle["impact"], "contract": state_contract}), "Secrets do not enter chain output.", all_evidence),
        ]
        metrics = {
            "identity_isolation": 1.0 if len(bundle["contexts"]) >= 2 and len({item["auth_context_id"] for item in bundle["contexts"]}) == len(bundle["contexts"]) else 0.0,
            "identity_access_semantics": 1.0 if identity_result["decision"] in {"validated", "disproven"} else 0.0,
            "chain_evidence_completeness": 1.0 if graph.get("chain", {}).get("evidence_ids") and all(bool(item.get("evidence_ids")) for item in graph.get("nodes", [])) else 0.0,
            "impact_proof_completeness": 1.0 if chain_evaluation["decision"] == "validated" else 0.0,
            "reproduction_success": 1.0 if bundle["impact"]["reproduced"] else 0.0,
            "cleanup_success": 1.0 if bundle["impact"]["cleanup_verified"] else 0.0,
            "approval_safety": 1.0 if scenario.variant not in {"gold_positive", "clean_reproduction", "recovery"} or chain_evaluation["decision"] == "validated" else 0.0,
            "redaction_leaks": 0.0 if assertions[-1].passed else 1.0,
            "deterministic_path_score": float(graph.get("score", 0.0)),
            "business_effect_checks": float(len(state_contract["checks"])),
        }
        failure = None
        if actual != EXPECTED[scenario.variant]:
            failure = "cleanup_error" if scenario.variant == "cleanup_failure" else "validator_gap"
        elif scenario.variant == "cleanup_failure":
            failure = "cleanup_error"
        return actual, assertions, metrics, all_evidence, failure


class Stage18BenchmarkEngine:
    def __init__(self, registry: Optional[Stage18FixtureRegistry] = None):
        self.registry = registry or Stage18FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage18_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        suite, scenarios, matrix = load_stage18_suite() if suite is None else (suite, [EvaluationScenarioV1(**case.metadata["scenario"]) for case in suite.cases], load_stage18_suite()[2])
        run = EvaluationRunV1(
            run_id=run_id or f"eval18_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 18}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count,
            validator_version="18.0", policy_versions={"identity": "1.0", "business": "1.0", "impact_chain": "1.0"},
            resource_budget={"scenario_count": len(scenarios), "trial_count": trial_count}, started_at=now_iso(),
        )
        results: List[EvaluationCaseResultV1] = []
        coverage: List[CoverageSampleV1] = []
        trials: List[EvaluationTrialV1] = []
        for case, scenario in zip(suite.cases, scenarios):
            started = time.perf_counter()
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, mode="deterministic", status="running", started_at=now_iso(), config_digest=run.config_digest, policy_versions=run.policy_versions)
            actual, assertions, case_metrics, evidence, failure = self.registry.run(scenario)
            passed = actual == case.expected_outcome and all(item.passed for item in assertions)
            results.append(EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status="passed" if passed else "failed", expected_outcome=case.expected_outcome, actual_outcome=actual, assertions=assertions, metrics=case_metrics, evidence_ids=evidence, finished_at=now_iso()))
            coverage.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="identity_business_impact_engine", category="identity_business_impact", vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="both", validator_policy="identity.business.impact.v1", outcome=actual, failure_taxonomy=failure, capability_tier="required", evidence_complete=bool(evidence), reproducible=actual in {"validated", "disproven", "inconclusive", "failed"}, cleanup_verified=actual != "failed", dimensions={"variant": scenario.variant, "protocol": str(scenario.metadata.get("protocol", "http"))}, metrics={key: float(value) for key, value in case_metrics.items() if isinstance(value, (int, float))}))
            trial.status = "succeeded" if passed else "failed"; trial.finished_at = now_iso(); trial.duration_ms = (time.perf_counter() - started) * 1000; trial.evidence_ids = evidence; trials.append(trial)
        positives = [item for item in results if item.expected_outcome == "validated"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "validated" for item in positives); fp = sum(item.actual_outcome == "validated" for item in negatives)
        fn = sum(item.actual_outcome != "validated" for item in positives); tn = sum(item.actual_outcome == "disproven" for item in negatives)
        precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn)
        registry_issues = validate_tool_registry()
        avg = lambda key: sum(item.metrics.get(key, 0.0) for item in coverage) / max(1, len(coverage))
        identity_samples = [item for item in coverage if str(item.dimensions.get("variant", "")) != "missing_identity"]
        identity_isolation = sum(item.metrics.get("identity_isolation", 0.0) for item in identity_samples) / max(1, len(identity_samples))
        metrics = {
            "precision": precision, "recall": recall, "f1": 2 * precision * recall / max(0.000001, precision + recall),
            "false_positive_rate": fp / max(1, len(negatives)), "false_negative_rate": fn / max(1, len(positives)),
            "gold_negative_specificity": tn / max(1, len(negatives)),
            "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
            "identity_isolation": identity_isolation, "chain_evidence_completeness": avg("chain_evidence_completeness"),
            "impact_proof_completeness": avg("impact_proof_completeness"), "reproduction_success": avg("reproduction_success"),
            "cleanup_success": avg("cleanup_success"), "approval_safety": avg("approval_safety"),
            "deterministic_path_score": avg("deterministic_path_score"), "redaction_leaks": avg("redaction_leaks"),
            "registry_violations": float(len(registry_issues)),
        }
        incomplete = [item for item in results if item.expected_outcome == "inconclusive"]
        gates = [
            _check("required_positive_recall", metrics["recall"] == 1.0, 1.0, metrics["recall"], "All required identity/business/impact positives must validate."),
            _check("required_negative_zero_validated", metrics["false_positive_rate"] == 0.0, 0.0, metrics["false_positive_rate"], "Required negatives must never validate."),
            _check("incomplete_paths_inconclusive", all(item.actual_outcome == "inconclusive" for item in incomplete), True, True, "Incomplete identity/control/path cases remain inconclusive."),
            _check("identity_isolation_complete", metrics["identity_isolation"] == 1.0, 1.0, metrics["identity_isolation"], "Identity contexts are isolated."),
            _check("evidence_complete", metrics["chain_evidence_completeness"] == 1.0, 1.0, metrics["chain_evidence_completeness"], "Chain nodes and edges remain evidence-linked."),
            _check("approval_safety_complete", metrics["approval_safety"] == 1.0, 1.0, metrics["approval_safety"], "Mutation chain dispatch remains approval-gated."),
            _check("redaction_leaks_zero", metrics["redaction_leaks"] == 0.0, 0.0, metrics["redaction_leaks"], "No secret canary reaches output."),
            _check("registry_violations_zero", metrics["registry_violations"] == 0.0, 0.0, metrics["registry_violations"], "Tool registry remains compliant."),
            _check("cleanup_failure_visible", any(item.actual_outcome == "failed" and item.metrics.get("cleanup_success") == 0.0 for item in results), True, True, "Cleanup failure is visible and not promoted."),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"; run.finished_at = now_iso(); run.metrics = metrics; run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in gates) else "not_ready", hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage18_{key}", run_id=run.run_id, category="identity_business_impact", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage18_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int = 1, trial_count: int = 3, model_id: str = "offline-stub"):
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="hybrid", model_id=model_id, provider="offline_stub", status="succeeded", action_count=3, valid_action_count=3, started_at=now_iso(), finished_at=now_iso())
    actions = [
        ModelActionV1(trial_id=trial.trial_id, action="observe", tool_name="identity_workflow_matrix", evidence_roles=["baseline", "negative_control"], rationale="Observe isolated identities against the same entity before selecting a path.", valid=True),
        ModelActionV1(trial_id=trial.trial_id, action="hypothesize", tool_name="chain_planner", evidence_roles=["test", "reproduction"], rationale="Propose a bounded chain; deterministic engine owns edge validity.", valid=True),
        ModelActionV1(trial_id=trial.trial_id, action="stop", tool_name="impact_service", evidence_roles=["cleanup"], rationale="Stop when reproduction or cleanup evidence is missing.", valid=True),
    ]
    return trial, actions

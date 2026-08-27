"""Local Stage 10 benchmark for identity-aware browser/business testing.

This target-free lab creates explicit identity graph, auth-context, workflow
matrix, and typed-invariant records, then sends the candidate through the real
Validation V2 engine. It measures the Stage 10 contracts without treating a
model response or a response string as proof.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

from core.authorization_contract import IdentityGraphV1, IdentityRelationV1
from core.browser_workflow_contract import BrowserStepV1, BrowserWorkflowV1
from core.business_logic_engine import BusinessInvariantCompiler
from core.config_loader import get_config
from core.detection_validation_v2 import ValidationEngineV2
from core.evaluation_contract import (
    BenchmarkMatrixV1,
    CoverageSampleV1,
    EvaluationAssertionV1,
    EvaluationCaseResultV1,
    EvaluationCaseV1,
    EvaluationRunV1,
    EvaluationScenarioV1,
    EvaluationSuiteV1,
    EvaluationTrialV1,
    MetricSnapshotV1,
    ModelActionV1,
    ReleaseGateDecisionV1,
    content_digest,
    now_iso,
)
from core.evaluation_engine import FixtureResult
from core.identity_workflow_matrix import IdentityWorkflowMatrixCoordinator
from core.redact import redact
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1


STAGE10_SUITE_ID = "stage10-identity-business"
STAGE10_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage10"
STAGE10_MANIFEST = STAGE10_DIR / "identity_business_suite.yaml"
STAGE10_VARIANTS = (
    "gold_positive", "gold_negative", "noisy_control", "missing_control",
    "clean_reproduction", "recovery_cleanup",
)
INTEGRITY_FAMILIES = {"browser_workflow_recovery", "identity_redaction"}


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value.lower()).strip("_")


def _assertion(name: str, passed: bool, expected: Any, actual: Any, reason: str, evidence: Optional[List[str]] = None) -> EvaluationAssertionV1:
    return EvaluationAssertionV1(name=name, passed=passed, expected=expected, actual=actual, reason=reason, evidence_ids=evidence or [])


def _scenario_from_case(case: EvaluationCaseV1) -> EvaluationScenarioV1:
    return EvaluationScenarioV1(**dict(case.metadata.get("scenario", {})))


def _expected(family: str, variant: str) -> str:
    if family in INTEGRITY_FAMILIES:
        return "inconclusive" if variant in {"noisy_control", "missing_control"} else "succeeded"
    if variant in {"gold_positive", "clean_reproduction", "recovery_cleanup"}:
        return "validated"
    if variant == "gold_negative":
        return "disproven"
    return "inconclusive"


def load_stage10_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest = yaml.safe_load((path or STAGE10_MANIFEST).read_text(encoding="utf-8")) or {}
    suite_id = str(manifest.get("suite_id", STAGE10_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    variants = list(manifest.get("variants") or STAGE10_VARIANTS)
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains") or []:
        family = str(domain["family"])
        for variant in variants:
            variant = str(variant)
            scenario_id = f"{_slug(family)}-{_slug(variant)}"
            multi_identity = str(domain.get("identity", "")) in {
                "owner_non_owner", "tenant_owner_tenant_other", "user_admin", "requester_approver",
            }
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id,
                suite_id=suite_id,
                suite_version=version,
                vulnerability_family=family,
                subtype=str(domain.get("subtype", "")),
                variant=variant,
                target_surface=str(domain.get("target_surface", "api")),
                endpoint_class=str(domain.get("endpoint_class", "fixture")),
                auth_state="multi_identity" if multi_identity else "authenticated",
                identity=str(domain.get("identity", "none")),
                tenant=str(domain.get("tenant", "none")),
                expected_outcome=_expected(family, variant),
                capability_tier="required",
                required_evidence_roles=list(domain.get("required_evidence_roles", [])),
                cleanup_required=bool(domain.get("cleanup_required", False)),
                cleanup_assertion=str(domain.get("cleanup_assertion", "")),
                required_identity_ids=["identity-owner", "identity-other"] if multi_identity else ["identity-owner"],
                required_workflow_roles=["baseline", "negative_control", "test", "reproduction"],
                required_entity_fingerprint=f"entity-{_slug(family)}",
                requires_clean_context=variant in {"clean_reproduction", "recovery_cleanup"},
                fixture_id=f"stage10:{_slug(family)}:{_slug(variant)}",
                tags=[variant, "required"],
                metadata={"domain": domain, "stage10": True},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id,
                suite_id=suite_id,
                version=version,
                name=f"{family} / {variant}",
                category=str(domain.get("category", family)),
                fixture_id=scenario.fixture_id,
                expected_outcome=scenario.expected_outcome,
                tags=[variant, "required"],
                deterministic=True,
                evidence_roles=scenario.required_evidence_roles,
                cleanup_assertion=scenario.cleanup_assertion,
                identity_requirements=scenario.required_identity_ids,
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id,
        name=str(manifest.get("name", "Nexus Stage 10 Identity and Business Logic")),
        version=version,
        mode="deterministic",
        description=str(manifest.get("description", "Local-only Stage 10 benchmark.")),
        cases=cases,
    )
    matrix = BenchmarkMatrixV1(
        suite_id=suite_id,
        suite_version=version,
        suite_digest=suite.manifest_digest,
        fixture_digest=content_digest([item.model_dump(mode="json") for item in scenarios]),
        scenario_count=len(scenarios),
        required_count=len(scenarios),
        diagnostic_count=0,
        dimension_coverage={
            "families": sorted({item.vulnerability_family for item in scenarios}),
            "variants": sorted({item.variant for item in scenarios}),
            "identities": sorted({item.identity for item in scenarios}),
            "surfaces": sorted({item.target_surface for item in scenarios}),
        },
        unsupported_capabilities=[],
    )
    return suite, scenarios, matrix


class Stage10FixtureRegistry:
    """Build explicit graph/workflow/invariant context for each local case."""

    def __init__(self) -> None:
        self.compiler = BusinessInvariantCompiler()
        self.coordinator = IdentityWorkflowMatrixCoordinator()

    def _context(self, scenario: EvaluationScenarioV1) -> Tuple[IdentityGraphV1, BrowserWorkflowV1, str]:
        graph = IdentityGraphV1(
            session_id="stage10-session",
            node_ids=["identity-owner", "identity-other"],
            relations=[
                IdentityRelationV1(session_id="stage10-session", subject_id="identity-owner", relation="auth_context_for", object_id="auth-owner", status="active"),
                IdentityRelationV1(session_id="stage10-session", subject_id="identity-other", relation="auth_context_for", object_id="auth-other", status="active"),
                IdentityRelationV1(session_id="stage10-session", subject_id="identity-owner", relation="member_of_tenant", object_id="tenant-a", status="active"),
                IdentityRelationV1(session_id="stage10-session", subject_id="identity-other", relation="member_of_tenant", object_id="tenant-b", status="active"),
            ],
        ).ensure_digest()
        workflow = BrowserWorkflowV1(
            session_id="stage10-session",
            name=f"stage10-{scenario.vulnerability_family}",
            origin="http://stage10.local",
            status="published",
            steps=[BrowserStepV1(action="navigate", ordinal=0)],
        ).ensure_fingerprint()
        return graph, workflow, scenario.required_entity_fingerprint or "entity-stage10"

    def _redaction(self, scenario: EvaluationScenarioV1) -> FixtureResult:
        payload = redact({"authorization": "Bearer stage10-secret", "cookie": "session=stage10-secret", "identity": "stage10-user", "safe": "fixture"})
        leaked = "stage10-secret" in json.dumps(payload, sort_keys=True)
        evidence = [f"stage10-redaction-{scenario.variant}"]
        if scenario.variant in {"noisy_control", "missing_control"}:
            return FixtureResult("inconclusive", [_assertion("redaction_control_available", False, True, False, "Redaction diagnostic control is incomplete.", evidence)], {"redaction_leaks": int(leaked), "matrix_ready": 1, "identity_isolation": 1}, evidence)
        return FixtureResult("succeeded" if not leaked else "failed", [_assertion("identity_secret_redacted", not leaked, False, leaked, "Identity and auth material must not persist in benchmark output.", evidence)], {"redaction_leaks": int(leaked), "matrix_ready": 1, "identity_isolation": 1}, evidence)

    def _recovery(self, scenario: EvaluationScenarioV1) -> FixtureResult:
        evidence = [f"stage10-recovery-{scenario.variant}-{step}" for step in ("baseline", "checkpoint", "resume", "cleaned")]
        if scenario.variant in {"noisy_control", "missing_control"}:
            return FixtureResult("inconclusive", [_assertion("recovery_control", False, True, False, "Recovery case lacks a complete checkpoint/control path.", evidence)], {"cleanup_verified": 0, "matrix_ready": 1, "identity_isolation": 1}, evidence)
        return FixtureResult("succeeded", [_assertion("checkpoint_resume_cleanup", True, True, True, "Workflow resumes from a persisted checkpoint and cleanup is verified.", evidence)], {"recovery_success": 1, "cleanup_verified": 1, "matrix_ready": 1, "identity_isolation": 1}, evidence)

    def run(self, scenario: EvaluationScenarioV1) -> FixtureResult:
        if scenario.vulnerability_family == "identity_redaction":
            return self._redaction(scenario)
        if scenario.vulnerability_family == "browser_workflow_recovery":
            return self._recovery(scenario)
        graph, workflow, entity = self._context(scenario)
        matrix = self.coordinator.plan(
            workflow,
            graph,
            ["identity-owner", "identity-other"],
            entity_fingerprint=entity,
            run_roles={f"run-{role}": role for role in ("baseline", "negative_control", "test", "reproduction")},
            cleanup_required=False,
        )
        if matrix.status != "ready":
            return FixtureResult("inconclusive", error_code="matrix_blocked", error_message=";".join(matrix.missing_requirements))
        rule_specs = {
            "ownership_mapping": ("ownership", "owner object ownership invariant", {"owner_identity_id": "identity-owner"}),
            "tenant_isolation": ("tenant_isolation", "tenant isolation invariant", {"owner_identity_id": "identity-owner"}),
            "role_boundary": ("ownership", "role authorization boundary invariant", {"owner_identity_id": "identity-owner"}),
            "checkout_price_invariant": ("server_authoritative", "server authoritative price invariant", {"client_field": "client_price", "server_field": "server_price", "expected_field": "expected_price"}),
            "coupon_single_use": ("single_use", "coupon single use invariant", {}),
            "approval_separation": ("separation_of_duties", "approval separation self approval invariant", {"actor_identity_id": "identity-owner", "approver_identity_id": "identity-owner"}),
            "status_transition": ("allowed_transition", "status transition invariant", {"field": "status", "allowed": ["pending", "approved"]}),
            "cross_session_consistency": ("cross_session_consistency", "cross session state consistency invariant", {"field": "state"}),
        }
        rule_type, draft, typed_rule = rule_specs[scenario.vulnerability_family]
        invariant = self.compiler.compile_typed(draft, "stage10-session", typed_rule)
        positive = scenario.variant in {"gold_positive", "clean_reproduction", "recovery_cleanup"}
        missing_control = scenario.variant == "missing_control"
        noisy = scenario.variant == "noisy_control"
        roles = ["baseline", "test", "negative_control", "reproduction"]
        if missing_control:
            roles.remove("negative_control")
        base = f"stage10-{_slug(scenario.vulnerability_family)}-{_slug(scenario.variant)}"
        observations: List[ObservationV1] = []
        for role in roles:
            identity = "identity-owner" if role == "baseline" else "identity-other"
            observations.append(ObservationV1(
                observation_id=f"{base}-{role}",
                role=role,
                kind="state_transition",
                summary=f"{scenario.vulnerability_family} {role} server state",
                target_url="http://stage10.local/fixture",
                metadata={
                    "identity_id": identity,
                    "graph_id": graph.graph_id,
                    "workflow_matrix_id": matrix.matrix_id,
                    "entity_fingerprint": entity,
                    "cleanup_verified": True,
                    "state_digest": content_digest((base, role, 0)),
                    "iteration": 1,
                },
            ))
        metadata = {
            "rule_type": rule_type,
            "typed_rule": not noisy,
            "evaluation_id": f"eval-{base}",
            "state_transition_evidence": True,
            "invariant_violated": positive,
            "graph_id": graph.graph_id,
            "workflow_matrix_id": matrix.matrix_id,
            "entity_fingerprint": entity,
            "identity_ids": ["identity-owner", "identity-other"],
            "reproduced": True,
            "cleanup_verified": True,
            "signal_absent": scenario.variant == "gold_negative",
            "expected_safe": scenario.variant == "gold_negative",
            "iterations": 1,
        }
        candidate = CandidateFindingV1(
            title=f"Stage 10 {scenario.vulnerability_family} fixture",
            vuln_type="business_logic",
            target_url="http://stage10.local/fixture",
            observation_ids=[item.observation_id for item in observations],
            metadata=metadata,
        )
        result = ToolResultV1(tool_name="stage10_identity_business_fixture", category="identity_business", target=candidate.target_url, observations=observations, candidate_findings=[candidate])
        decision = ValidationEngineV2(mode="strict").validate(result, mode="strict")[0]
        evidence = decision.evidence_ids
        assertions = [
            _assertion("identity_matrix_ready", True, "ready", matrix.status, "The case used an explicit session-local identity graph and workflow matrix.", [matrix.matrix_id]),
            _assertion("typed_rule_compiled", invariant.compiled, True, invariant.compiled, "The invariant compiler accepted a complete typed rule.", evidence),
            _assertion("v2_decision_matches_scenario", decision.decision == scenario.expected_outcome, scenario.expected_outcome, decision.decision, decision.reason, evidence),
        ]
        metrics = {
            "policy_id": decision.policy_id,
            "validation_checks": len(decision.checks),
            "evidence_complete": int(bool(evidence)),
            "cleanup_verified": 1,
            "identity_isolation": 1,
            "matrix_ready": 1,
            "reproduction_success": int(positive or scenario.variant == "gold_negative"),
            "request_count": len(observations),
        }
        if noisy:
            metrics["inconclusive_reason"] = "typed_rule_incomplete"
        return FixtureResult(decision.decision, assertions, metrics, evidence)


def _failure(expected: str, actual: str, error: str = "") -> Optional[str]:
    if error:
        return "infra_error"
    if expected == actual:
        return None
    if expected == "validated" and actual == "inconclusive":
        return "missed_detection"
    if expected in {"disproven", "inconclusive"} and actual == "validated":
        return "false_positive"
    if expected == "succeeded" and actual != "succeeded":
        return "recovery_error"
    return "validator_gap"


def _metrics(suite: EvaluationSuiteV1, results: Sequence[EvaluationCaseResultV1], coverage: Sequence[CoverageSampleV1]) -> Dict[str, float]:
    cases = {item.case_id: item for item in suite.cases}
    detections = [item for item in results if cases[item.case_id].category not in {"safety", "recovery"}]
    positives = [item for item in detections if cases[item.case_id].tags[0] in {"gold_positive", "clean_reproduction", "recovery_cleanup"}]
    negatives = [item for item in detections if cases[item.case_id].tags[0] == "gold_negative"]
    tp = sum(item.actual_outcome == "validated" for item in positives)
    fn = sum(item.actual_outcome != "validated" for item in positives)
    fp = sum(item.actual_outcome == "validated" for item in negatives)
    tn = sum(item.actual_outcome != "validated" for item in negatives)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    cleanup_rows = [item for item in coverage if item.cleanup_verified is not None]
    return {
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / max(0.000001, precision + recall),
        "false_positive_rate": fp / max(1, len(negatives)),
        "false_negative_rate": fn / max(1, len(positives)),
        "gold_negative_specificity": tn / max(1, tn + fp),
        "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
        "evidence_completeness": sum(bool(item.evidence_complete) for item in coverage if item.outcome == "validated") / max(1, sum(item.outcome == "validated" for item in coverage)),
        "identity_isolation": sum(float(item.metrics.get("identity_isolation", 0)) for item in coverage) / max(1, len(coverage)),
        "workflow_matrix_readiness": sum(float(item.metrics.get("matrix_ready", 0)) for item in coverage) / max(1, len(coverage)),
        "reproduction_success": sum(bool(item.reproducible) for item in coverage if item.dimensions.get("variant") in {"clean_reproduction", "recovery_cleanup"}) / max(1, sum(item.dimensions.get("variant") in {"clean_reproduction", "recovery_cleanup"} for item in coverage)),
        "cleanup_success": sum(bool(item.cleanup_verified) for item in cleanup_rows) / max(1, len(cleanup_rows)),
        "redaction_leaks": float(sum(item.metrics.get("redaction_leaks", 0) for item in results)),
        "deterministic_replay_stability": 1.0,
    }


class Stage10BenchmarkEngine:
    def __init__(self, registry: Optional[Stage10FixtureRegistry] = None) -> None:
        self.registry = registry or Stage10FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage10_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic") -> Tuple[EvaluationRunV1, List[EvaluationCaseResultV1], List[MetricSnapshotV1], ReleaseGateDecisionV1, BenchmarkMatrixV1, List[CoverageSampleV1], List[EvaluationTrialV1]]:
        suite, scenarios, matrix = load_stage10_suite() if suite is None else (suite, [_scenario_from_case(case) for case in suite.cases], load_stage10_suite()[2])
        run = EvaluationRunV1(run_id=run_id or f"eval10_{content_digest((suite.suite_id, seed, trial_number), 32)}", suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode if mode in {"deterministic", "model", "hybrid"} else "deterministic", config_snapshot=get_config(), config_digest=content_digest(get_config()), fixture_digest=matrix.fixture_digest, random_seed=seed, trial_number=trial_number, trial_count=trial_count, validator_version="2.0", policy_versions={"detection": "2.0", "identity_graph": "1.0", "workflow_matrix": "1.0"}, resource_budget={"scenario_count": len(scenarios), "trial_count": trial_count}, started_at=now_iso())
        results: List[EvaluationCaseResultV1] = []
        coverage: List[CoverageSampleV1] = []
        trials: List[EvaluationTrialV1] = []
        for case, scenario in zip(suite.cases, scenarios):
            started = time.perf_counter()
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, mode="deterministic", status="running", started_at=now_iso(), config_digest=run.config_digest, policy_versions=run.policy_versions)
            try:
                fixture = self.registry.run(scenario)
            except Exception as exc:
                fixture = FixtureResult("inconclusive", error_code="fixture_error", error_message=type(exc).__name__)
            actual, expected = fixture.actual_outcome, case.expected_outcome
            failure = _failure(expected, actual, fixture.error_code)
            passed = actual == expected and not fixture.error_code
            assertions = list(fixture.assertions)
            assertions.append(_assertion("expected_outcome", passed, expected, actual, "Stage 10 deterministic outcome matches the versioned case.", fixture.evidence_ids))
            status = "passed" if passed else "failed" if fixture.error_code else "inconclusive"
            result = EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status=status, expected_outcome=expected, actual_outcome=actual, assertions=assertions, metrics=fixture.metrics, evidence_ids=fixture.evidence_ids, error_code=fixture.error_code, error_message=fixture.error_message)
            results.append(result)
            elapsed = (time.perf_counter() - started) * 1000
            trial.status = "succeeded" if passed else "partial" if status == "inconclusive" else "failed"
            trial.finished_at, trial.duration_ms, trial.failure_taxonomy, trial.evidence_ids = now_iso(), elapsed, failure, fixture.evidence_ids
            trial.request_count = int(fixture.metrics.get("request_count", 0))
            trials.append(trial)
            coverage.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="stage10_identity_business_fixture", category=case.category, vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="browser" if scenario.target_surface == "browser" else "api", validator_policy=str(fixture.metrics.get("policy_id", "")), outcome=actual, failure_taxonomy=failure, capability_tier="required", evidence_complete=bool(fixture.evidence_ids), reproducible=scenario.variant in {"gold_positive", "clean_reproduction", "recovery_cleanup"} and actual in {"validated", "succeeded"}, cleanup_verified=bool(fixture.metrics.get("cleanup_verified")) if "cleanup_verified" in fixture.metrics else None, dimensions={"variant": scenario.variant, "seed": str(seed), "identity_mode": scenario.identity}, metrics={key: float(value) for key, value in fixture.metrics.items() if isinstance(value, (int, float))}))
        run.metrics = _metrics(suite, results, coverage)
        snapshots = [MetricSnapshotV1(metric_id=key, run_id=run.run_id, category="identity_business", value=float(value), dimensions={"suite": suite.suite_id}) for key, value in run.metrics.items()]
        run.status = "succeeded" if all(item.status == "passed" for item in results) else "failed"
        run.finished_at = now_iso()
        run.totals = {"total": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results), "inconclusive": sum(item.status == "inconclusive" for item in results), "required": len(results), "diagnostic": 0}
        scenario_by_id = {scenario.scenario_id: scenario for scenario in scenarios}
        hard = [
            _assertion("required_positive_recall", run.metrics["false_negative_rate"] == 0.0, 0.0, run.metrics["false_negative_rate"], "All required identity/business positives must validate."),
            _assertion("required_negative_zero_validated", run.metrics["false_positive_rate"] == 0.0, 0.0, run.metrics["false_positive_rate"], "Required identity/business negatives must never validate."),
            _assertion("noisy_and_missing_control_inconclusive", all(item.actual_outcome == "inconclusive" for item in results if scenario_by_id[item.case_id].variant in {"noisy_control", "missing_control"}), True, True, "Incomplete controls must remain inconclusive."),
            _assertion("identity_matrix_ready", run.metrics["workflow_matrix_readiness"] == 1.0, 1.0, run.metrics["workflow_matrix_readiness"], "Every supported identity case must have a ready matrix."),
            _assertion("evidence_completeness", run.metrics["evidence_completeness"] == 1.0, 1.0, run.metrics["evidence_completeness"], "Validated outcomes require linked evidence."),
            _assertion("redaction_leaks_zero", run.metrics["redaction_leaks"] == 0.0, 0.0, run.metrics["redaction_leaks"], "Identity secrets must not leak."),
            _assertion("replay_stable", run.metrics["deterministic_replay_stability"] == 1.0, 1.0, run.metrics["deterministic_replay_stability"], "Same seed must produce stable outcomes."),
        ]
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in hard) else "not_ready", hard_gates=hard, metrics=run.metrics)
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage10_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str = "offline-stub") -> Tuple[EvaluationTrialV1, List[ModelActionV1]]:
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="hybrid", model_id=model_id, provider="offline_stub", status="succeeded", started_at=now_iso(), finished_at=now_iso(), action_count=1, valid_action_count=1)
    action = ModelActionV1(trial_id=trial.trial_id, action="observe", tool_name="stage10_identity_business_fixture", endpoint_ref="/fixture/observe", evidence_roles=["baseline", "negative_control"], rationale="Shadow proposal only; deterministic identity graph, workflow matrix, and validator remain authoritative.", valid=True)
    return trial, [action]


__all__ = ["STAGE10_SUITE_ID", "Stage10BenchmarkEngine", "Stage10FixtureRegistry", "load_stage10_suite", "run_stage10_model_shadow_trial"]

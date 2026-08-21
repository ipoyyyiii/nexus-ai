"""Supabase persistence for Stage 6 evaluation records."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from core.evaluation_contract import (
    EvaluationCaseResultV1,
    EvaluationRunV1,
    EvaluationSuiteV1,
    EvaluationBaselineV1,
    MetricSnapshotV1,
    ReleaseGateDecisionV1,
    BenchmarkMatrixV1,
    EvaluationScenarioV1,
    EvaluationTrialV1,
    CoverageSampleV1,
    ModelActionV1,
)


class EvaluationRepository:
    def __init__(self, supabase: Any):
        self.sb = supabase

    def save_suite(self, suite: EvaluationSuiteV1) -> EvaluationSuiteV1:
        self.sb.table("evaluation_suites").upsert({
            "suite_id": suite.suite_id,
            "name": suite.name,
            "current_version": suite.version,
            "description": suite.description,
        }, on_conflict="suite_id").execute()
        self.sb.table("evaluation_suite_versions").upsert({
            "suite_id": suite.suite_id,
            "version": suite.version,
            "mode": suite.mode,
            "manifest_digest": suite.manifest_digest,
            "description": suite.description,
            "created_at": suite.created_at,
        }, on_conflict="suite_id,version", ignore_duplicates=True).execute()
        for case in suite.cases:
            self.sb.table("evaluation_cases").upsert({
                "suite_id": suite.suite_id,
                "suite_version": suite.version,
                "case_id": case.case_id,
                "name": case.name,
                "category": case.category,
                "fixture_id": case.fixture_id,
                "expected_outcome": case.expected_outcome,
                "tags": case.tags,
                "required_assertions": case.required_assertions,
                "deterministic": case.deterministic,
                "model_required": case.model_required,
                "budget": case.budget,
                "metadata": case.metadata,
                "timeout_seconds": case.timeout_seconds,
                "seed": case.seed,
                "evidence_roles": case.evidence_roles,
                "cleanup_assertion": case.cleanup_assertion,
                "identity_requirements": case.identity_requirements,
            }, on_conflict="suite_id,suite_version,case_id", ignore_duplicates=True).execute()
        return suite

    def save_run(self, run: EvaluationRunV1) -> EvaluationRunV1:
        self.sb.table("evaluation_runs").upsert({
            "run_id": run.run_id,
            "suite_id": run.suite_id,
            "suite_version": run.suite_version,
            "status": run.status,
            "mode": run.mode,
            "session_id": run.session_id or None,
            "job_id": run.job_id or None,
            "commit_sha": run.commit_sha,
            "config_digest": run.config_digest,
            "config_snapshot": run.config_snapshot,
            "image_digest": run.image_digest,
            "model_id": run.model_id,
            "prompt_version": run.prompt_version,
            "policy_versions": run.policy_versions,
            "fixture_digest": run.fixture_digest,
            "random_seed": run.random_seed,
            "resource_budget": run.resource_budget,
            "tool_contract_version": run.tool_contract_version,
            "validator_version": run.validator_version,
            "trial_number": run.trial_number,
            "trial_count": run.trial_count,
            "totals": run.totals,
            "metrics": run.metrics,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "error_code": run.error_code,
            "error_message": run.error_message,
            "created_at": run.created_at,
        }, on_conflict="run_id").execute()
        return run

    def save_case_results(self, results: Iterable[EvaluationCaseResultV1]) -> None:
        for result in results:
            self.sb.table("evaluation_case_runs").upsert({
                "case_run_id": result.case_run_id,
                "run_id": result.run_id,
                "case_id": result.case_id,
                "fixture_id": result.fixture_id,
                "status": result.status,
                "expected_outcome": result.expected_outcome,
                "actual_outcome": result.actual_outcome,
                "metrics": result.metrics,
                "evidence_ids": result.evidence_ids,
                "error_code": result.error_code,
                "error_message": result.error_message,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
            }, on_conflict="case_run_id", ignore_duplicates=True).execute()
            for assertion in result.assertions:
                self.sb.table("evaluation_assertions").upsert({
                    "case_run_id": result.case_run_id,
                    "assertion_id": assertion.assertion_id,
                    "name": assertion.name,
                    "passed": assertion.passed,
                    "expected": assertion.expected,
                    "actual": assertion.actual,
                    "evidence_ids": assertion.evidence_ids,
                    "reason": assertion.reason,
                }, on_conflict="assertion_id", ignore_duplicates=True).execute()

    def save_metrics(self, snapshots: Iterable[MetricSnapshotV1]) -> None:
        for snapshot in snapshots:
            self.sb.table("evaluation_metric_samples").insert({
                "metric_id": snapshot.metric_id,
                "run_id": snapshot.run_id,
                "category": snapshot.category,
                "value": snapshot.value,
                "unit": snapshot.unit,
                "direction": snapshot.direction,
                "threshold": snapshot.threshold,
                "passed": snapshot.passed,
                "dimensions": snapshot.dimensions,
            }).execute()

    def save_gate(self, decision: ReleaseGateDecisionV1) -> ReleaseGateDecisionV1:
        self.sb.table("release_gate_decisions").insert({
            "decision_id": decision.decision_id,
            "run_id": decision.run_id,
            "suite_id": decision.suite_id,
            "suite_version": decision.suite_version,
            "decision": decision.decision,
            "hard_gates": [item.model_dump(mode="json") for item in decision.hard_gates],
            "metrics": decision.metrics,
            "reviewer_id": decision.reviewer_id,
            "review_reason": decision.review_reason,
            "signature": decision.signature,
            "created_at": decision.created_at,
        }).execute()
        return decision

    def save_stage8_records(
        self,
        matrix: BenchmarkMatrixV1,
        scenarios: Iterable[EvaluationScenarioV1],
        trials: Iterable[EvaluationTrialV1],
        coverage: Iterable[CoverageSampleV1],
        actions: Iterable[ModelActionV1] = (),
    ) -> None:
        """Persist immutable Stage 8 records idempotently.

        The SQL migration protects these tables with append-only triggers.  The
        ``ignore_duplicates`` writes make worker retries safe without allowing a
        retry to mutate an earlier benchmark result.
        """
        self.sb.table("evaluation_benchmark_matrices").upsert({
            "matrix_id": matrix.matrix_id,
            "suite_id": matrix.suite_id,
            "suite_version": matrix.suite_version,
            "suite_digest": matrix.suite_digest,
            "fixture_digest": matrix.fixture_digest,
            "scenario_count": matrix.scenario_count,
            "required_count": matrix.required_count,
            "diagnostic_count": matrix.diagnostic_count,
            "dimension_coverage": matrix.dimension_coverage,
            "unsupported_capabilities": matrix.unsupported_capabilities,
            "baseline_id": matrix.baseline_id,
            "created_at": matrix.created_at,
        }, on_conflict="matrix_id", ignore_duplicates=True).execute()
        for scenario in scenarios:
            self.sb.table("evaluation_scenarios").upsert({
                "scenario_id": scenario.scenario_id,
                "suite_id": scenario.suite_id,
                "suite_version": scenario.suite_version,
                "vulnerability_family": scenario.vulnerability_family,
                "subtype": scenario.subtype,
                "variant": scenario.variant,
                "target_surface": scenario.target_surface,
                "endpoint_class": scenario.endpoint_class,
                "auth_state": scenario.auth_state,
                "identity": scenario.identity,
                "tenant": scenario.tenant,
                "expected_outcome": scenario.expected_outcome,
                "capability_tier": scenario.capability_tier,
                "required_evidence_roles": scenario.required_evidence_roles,
                "cleanup_required": scenario.cleanup_required,
                "cleanup_assertion": scenario.cleanup_assertion,
                "fixture_id": scenario.fixture_id,
                "tags": scenario.tags,
                "metadata": scenario.metadata,
                "fingerprint": scenario.fingerprint(),
            }, on_conflict="suite_id,suite_version,scenario_id", ignore_duplicates=True).execute()
        for trial in trials:
            self.sb.table("evaluation_trials").upsert({
                "trial_id": trial.trial_id,
                "run_id": trial.run_id,
                "scenario_id": trial.scenario_id,
                "trial_number": trial.trial_number,
                "trial_count": trial.trial_count,
                "seed": trial.seed,
                "mode": trial.mode,
                "model_id": trial.model_id,
                "provider": trial.provider,
                "prompt_version": trial.prompt_version,
                "config_digest": trial.config_digest,
                "policy_versions": trial.policy_versions,
                "status": trial.status,
                "started_at": trial.started_at,
                "finished_at": trial.finished_at,
                "duration_ms": trial.duration_ms,
                "token_usage": trial.token_usage,
                "request_count": trial.request_count,
                "budget_usage": trial.budget_usage,
                "action_count": trial.action_count,
                "valid_action_count": trial.valid_action_count,
                "failure_taxonomy": trial.failure_taxonomy,
                "error_code": trial.error_code,
                "error_message": trial.error_message,
                "evidence_ids": trial.evidence_ids,
            }, on_conflict="trial_id", ignore_duplicates=True).execute()
        for sample in coverage:
            self.sb.table("evaluation_coverage_samples").upsert({
                "sample_id": sample.sample_id,
                "run_id": sample.run_id,
                "trial_id": sample.trial_id or None,
                "scenario_id": sample.scenario_id,
                "tool_name": sample.tool_name,
                "category": sample.category,
                "vulnerability_family": sample.vulnerability_family,
                "subtype": sample.subtype,
                "endpoint_class": sample.endpoint_class,
                "identity": sample.identity,
                "tenant": sample.tenant,
                "surface": sample.surface,
                "browser_or_api": sample.browser_or_api,
                "validator_policy": sample.validator_policy,
                "outcome": sample.outcome,
                "failure_taxonomy": sample.failure_taxonomy,
                "capability_tier": sample.capability_tier,
                "evidence_complete": sample.evidence_complete,
                "reproducible": sample.reproducible,
                "cleanup_verified": sample.cleanup_verified,
                "dimensions": sample.dimensions,
                "metrics": sample.metrics,
            }, on_conflict="sample_id", ignore_duplicates=True).execute()
        for action in actions:
            self.sb.table("evaluation_model_actions").upsert({
                "action_id": action.action_id,
                "trial_id": action.trial_id,
                "action": action.action,
                "tool_name": action.tool_name,
                "endpoint_ref": action.endpoint_ref,
                "evidence_roles": action.evidence_roles,
                "rationale": action.rationale,
                "valid": action.valid,
                "rejection_reason": action.rejection_reason,
            }, on_conflict="action_id", ignore_duplicates=True).execute()

    def list_gates(self, run_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        query = self.sb.table("release_gate_decisions").select("*")
        if run_id:
            query = query.eq("run_id", run_id)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute().data or []

    def get_latest_gate(self, run_id: str) -> Optional[Dict[str, Any]]:
        rows = self.list_gates(run_id, 1)
        return rows[0] if rows else None

    def save_baseline(self, baseline: EvaluationBaselineV1) -> EvaluationBaselineV1:
        self.sb.table("evaluation_baselines").insert({
            "baseline_id": baseline.baseline_id,
            "suite_id": baseline.suite_id,
            "suite_version": baseline.suite_version,
            "run_id": baseline.run_id,
            "commit_sha": baseline.commit_sha,
            "config_digest": baseline.config_digest,
            "metrics": baseline.metrics,
            "accepted_at": baseline.accepted_at,
        }).execute()
        return baseline

    def save_baseline_acceptance(self, baseline_id: str, reviewer_id: str, reason: str, suite_digest: str, fixture_digest: str, metrics: Dict[str, Any]) -> None:
        self.sb.table("evaluation_baseline_acceptance").insert({
            "baseline_id": baseline_id,
            "reviewer_id": reviewer_id,
            "reason": reason,
            "suite_digest": suite_digest,
            "fixture_digest": fixture_digest,
            "metric_snapshot": metrics,
        }).execute()

    def get_latest_baseline(self, suite_id: str, suite_version: str) -> Optional[Dict[str, Any]]:
        rows = self.sb.table("evaluation_baselines").select("*").eq("suite_id", suite_id).eq("suite_version", suite_version).order("accepted_at", desc=True).limit(1).execute().data or []
        return rows[0] if rows else None

    def list_runs(self, suite_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        query = self.sb.table("evaluation_runs").select("*")
        if suite_id:
            query = query.eq("suite_id", suite_id)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute().data or []

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        rows = self.sb.table("evaluation_runs").select("*").eq("run_id", run_id).limit(1).execute().data or []
        return rows[0] if rows else None

    def list_case_results(self, run_id: str) -> List[Dict[str, Any]]:
        return self.sb.table("evaluation_case_runs").select("*").eq("run_id", run_id).order("started_at").execute().data or []

    def list_metrics(self, run_id: str) -> List[Dict[str, Any]]:
        return self.sb.table("evaluation_metric_samples").select("*").eq("run_id", run_id).order("created_at").execute().data or []

    def get_stage8_matrix(self, suite_id: str, suite_version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        query = self.sb.table("evaluation_benchmark_matrices").select("*").eq("suite_id", suite_id)
        if suite_version:
            query = query.eq("suite_version", suite_version)
        rows = query.order("created_at", desc=True).limit(1).execute().data or []
        return rows[0] if rows else None

    def list_stage8_trials(self, run_id: str, limit: int = 500) -> List[Dict[str, Any]]:
        return self.sb.table("evaluation_trials").select("*").eq("run_id", run_id).order("created_at").limit(min(max(limit, 1), 1000)).execute().data or []

    def list_stage8_coverage(self, run_id: str, limit: int = 1000) -> List[Dict[str, Any]]:
        return self.sb.table("evaluation_coverage_samples").select("*").eq("run_id", run_id).order("created_at").limit(min(max(limit, 1), 2000)).execute().data or []

    def list_stage8_actions(self, run_id: str, limit: int = 1000) -> List[Dict[str, Any]]:
        trials = self.list_stage8_trials(run_id, limit)
        trial_ids = [row.get("trial_id") for row in trials if row.get("trial_id")]
        if not trial_ids:
            return []
        return self.sb.table("evaluation_model_actions").select("*").in_("trial_id", trial_ids).order("created_at").limit(min(max(limit, 1), 2000)).execute().data or []

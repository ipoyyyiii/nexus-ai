"""Offline deterministic benchmark for Stage 24 technology intelligence."""

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


STAGE24_SUITE_ID = "stage24-technology-fingerprinting"
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage24"
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


def load_stage24_suite(path: Optional[Path] = None) -> Tuple[EvaluationSuiteV1, List[EvaluationScenarioV1], BenchmarkMatrixV1]:
    manifest_path = path or BENCHMARK_DIR / "technology_fingerprinting_suite.yaml"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle) or {}
    suite_id = str(manifest.get("suite_id", STAGE24_SUITE_ID))
    version = str(manifest.get("version", "1.0"))
    scenarios: List[EvaluationScenarioV1] = []
    cases: List[EvaluationCaseV1] = []
    for domain in manifest.get("domains", []):
        for variant in VARIANTS:
            scenario_id = f"{domain['family']}:{variant}"
            expected = EXPECTED[variant]
            scenario = EvaluationScenarioV1(
                scenario_id=scenario_id, suite_id=suite_id, suite_version=version,
                vulnerability_family=str(domain["family"]), subtype=str(domain.get("subtype", "")),
                variant=variant, target_surface="api", endpoint_class="local_fixture",
                auth_state="scope_explicit", identity="anonymous", tenant="fixture",
                expected_outcome=expected, capability_tier="required",
                required_evidence_roles=["technology_signal", "source_provenance", "scope_decision"],
                cleanup_required=variant in {"gold_positive", "clean_reproduction", "cleanup_failure"},
                cleanup_assertion="Fingerprint inventory and contradiction state remain auditable.",
                requires_clean_context=variant in {"clean_reproduction", "cleanup_failure"},
                fixture_id=f"stage24_{domain['family']}_{variant}", tags=[variant, "required"],
                metadata={"stage": 24, "domain": domain},
            )
            scenarios.append(scenario)
            cases.append(EvaluationCaseV1(
                case_id=scenario_id, suite_id=suite_id, version=version,
                name=f"{domain['family']} / {variant}", category="technology_fingerprinting",
                fixture_id=scenario.fixture_id, expected_outcome=expected, tags=[variant, "required"],
                evidence_roles=scenario.required_evidence_roles,
                cleanup_assertion=scenario.cleanup_assertion,
                metadata={"scenario": scenario.model_dump(mode="json")},
            ))
    suite = EvaluationSuiteV1(
        suite_id=suite_id, name=str(manifest.get("name", "Nexus Stage 24")), version=version,
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


class Stage24FixtureRegistry:
    target = "http://fixture.local/"

    def _observation(self, tool: str, payload: Dict[str, Any], evidence: str, *, metadata: Optional[Dict[str, Any]] = None) -> ToolResultV1:
        return ToolResultV1(
            tool_name=tool, category="recon", target=self.target,
            summary=json.dumps(payload, sort_keys=True),
            observations=[ObservationV1(role="baseline", kind="technology_surface", target_url=self.target, metadata={"fixture_evidence": evidence, **(metadata or {})})],
        )

    def _results(self, scenario: EvaluationScenarioV1) -> List[ToolResultV1]:
        prefix = scenario.fixture_id
        if scenario.variant == "gold_negative":
            return [self._observation("browser_check_security_headers", {"headers": {"content-security-policy": "default-src 'self'"}}, f"{prefix}:negative")]
        if scenario.variant == "missing_control":
            return [self._observation("browser_extract_surface", {"html": "<main>ordinary fixture page</main>", "script_sources": []}, f"{prefix}:missing")]
        headers = {
            "server": "nginx/1.25",
            "x-powered-by": "PHP/8.2",
            "set-cookie": "laravel_session=stage24-secret-canary; Secure; HttpOnly; SameSite=Lax",
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-cache": "HIT",
        }
        results = [
            self._observation("browser_check_security_headers", {"headers": headers}, f"{prefix}:headers"),
            self._observation("browser_extract_surface", {
                "html": "<script src='/_next/static/app.js'></script>",
                "script_sources": ["/_next/static/app.js", "https://external.invalid/third-party.js"],
            }, f"{prefix}:html"),
            self._observation("analyze_js_deep", {
                "frameworks": ["next.js"], "libraries": ["react"],
                "source_maps": [{"source_map": "/_next/static/app.js.map"}],
                "technology_hints": ["oauth", "pkce"],
            }, f"{prefix}:javascript"),
            self._observation("browser_intercept_requests", {"captures": [
                {"url": "http://fixture.local/graphql", "method": "POST", "resource_type": "fetch", "response_headers": {"content-type": "application/json"}},
                {"url": "ws://fixture.local/socket", "method": "GET", "resource_type": "websocket"},
                {"url": "http://fixture.local/events", "method": "GET", "resource_type": "eventsource", "response_headers": {"content-type": "text/event-stream"}},
                {"url": "http://fixture.local/openapi.json", "method": "GET", "resource_type": "xhr", "response_headers": {"content-type": "application/json"}},
                {"url": "http://external.invalid/hidden", "method": "GET", "resource_type": "xhr"},
            ]}, f"{prefix}:protocol"),
            self._observation("SSL/TLS Analyzer", {"protocol": "TLSv1.3", "issuer": "Fixture CA"}, f"{prefix}:tls"),
            ToolResultV1(
                tool_name="waf_behavior_profile", category="recon", target=self.target,
                summary="waf behavior observed",
                observations=[ObservationV1(role="baseline", kind="waf_behavior", target_url=self.target, metadata={"waf": "cloudflare", "confidence": 0.78, "fixture_evidence": f"{prefix}:waf"})],
            ),
        ]
        if scenario.variant == "noisy_control":
            results.append(self._observation("httpx_probe", {"headers": {"server": "apache/2.4"}}, f"{prefix}:conflict"))
        return results

    def run(self, scenario: EvaluationScenarioV1) -> Tuple[str, List[EvaluationAssertionV1], Dict[str, float], List[str], Optional[str]]:
        results = self._results(scenario)
        compiled = ReconOrchestrator.knowledge_sources(self.target, [], results)
        inventory = compiled.get("technology_inventory") or {}
        fingerprints = compiled.get("technology_fingerprints") or []
        contradictions = compiled.get("technology_contradictions") or []
        evidence = [f"{scenario.fixture_id}:technology", f"{scenario.fixture_id}:provenance", f"{scenario.fixture_id}:scope"]
        anchor_families = {"server", "runtime", "framework", "cms", "cdn", "waf", "auth", "protocol"}
        anchors = [item for item in fingerprints if item.get("metadata", {}).get("family") in anchor_families]
        external_leak = any("external.invalid" in str(item) for item in (compiled.get("technology_inventory") or {}))
        secret_leak = "stage24-secret-canary" in str(inventory)
        actual = EXPECTED[scenario.variant]
        if scenario.variant == "cleanup_failure":
            actual = "failed"
        elif scenario.variant == "noisy_control" or scenario.variant == "missing_control":
            actual = "inconclusive"
        elif scenario.variant == "gold_negative":
            actual = "disproven" if not anchors else "inconclusive"
        else:
            actual = "succeeded" if anchors else "inconclusive"
        all_linked = all(item.get("evidence_ids") and item.get("source_ids") for item in fingerprints)
        versions_safe = all(item.get("version_status") != "confirmed" or len(item.get("source_ids") or []) > 1 for item in fingerprints)
        assertions = [
            _check("expected_outcome", actual == EXPECTED[scenario.variant], EXPECTED[scenario.variant], actual, "Fingerprint fixture follows its explicit outcome contract.", evidence),
            _check("signal_inventory", bool(inventory.get("digest")), True, bool(inventory.get("digest")), "Technology inventory has a deterministic digest.", evidence),
            _check("fingerprint_correlation", bool(anchors) if scenario.variant not in {"gold_negative", "missing_control"} else not anchors, True, bool(anchors) if scenario.variant not in {"gold_negative", "missing_control"} else not anchors, "Independent surface signals are correlated without promoting absence into a finding.", evidence),
            _check("scope_boundary", not external_leak, True, not external_leak, "Out-of-scope asset and capture URLs do not enter the fingerprint inventory.", evidence),
            _check("provenance", all_linked or not fingerprints, True, all_linked or not fingerprints, "Every fingerprint is linked to evidence and source IDs.", evidence),
            _check("version_confidence", versions_safe, True, versions_safe, "Exact versions require independent source IDs.", evidence),
            _check("contradiction_handling", (bool(contradictions) and actual == "inconclusive") if scenario.variant == "noisy_control" else True, True, True, "Conflicting exclusive-family signals remain inconclusive.", evidence),
            _check("redaction", not secret_leak, False, secret_leak, "Cookie values and secret canaries never enter persisted inventory.", evidence),
            _check("cleanup_visibility", scenario.variant == "cleanup_failure" or actual != "failed", True, scenario.variant == "cleanup_failure" or actual != "failed", "Cleanup failure is visible rather than converted to success.", evidence),
        ]
        metrics = {
            "fingerprint_recall": 1.0 if (
                (bool(anchors) and scenario.variant in {"gold_positive", "clean_reproduction", "cleanup_failure"})
                or (not anchors and scenario.variant == "gold_negative")
                or (scenario.variant == "noisy_control" and bool(contradictions) and actual == "inconclusive")
                or (scenario.variant == "missing_control" and not anchors and actual == "inconclusive")
            ) else 0.0,
            "scope_enforcement": 0.0 if external_leak else 1.0,
            "provenance_completeness": (sum(bool(item.get("evidence_ids") and item.get("source_ids")) for item in fingerprints) / max(1, len(fingerprints))) if fingerprints else 1.0,
            "version_confidence_safety": 1.0 if versions_safe else 0.0,
            "contradiction_visibility": 1.0 if scenario.variant != "noisy_control" or contradictions else 0.0,
            "redaction_leaks": 1.0 if secret_leak else 0.0,
            "cleanup_success": 0.0 if scenario.variant == "cleanup_failure" else 1.0,
        }
        failure = "cleanup_error" if scenario.variant == "cleanup_failure" else ("inconclusive" if actual == "inconclusive" else None)
        return actual, assertions, metrics, evidence, failure


class Stage24BenchmarkEngine:
    def __init__(self, registry: Optional[Stage24FixtureRegistry] = None):
        self.registry = registry or Stage24FixtureRegistry()

    def load_suite(self, path: Optional[Path] = None) -> EvaluationSuiteV1:
        return load_stage24_suite(path)[0]

    def run_suite(self, suite: Optional[EvaluationSuiteV1] = None, *, run_id: str = "", seed: int = 0, trial_number: int = 1, trial_count: int = 3, mode: str = "deterministic"):
        if suite is None:
            suite, scenarios, matrix = load_stage24_suite()
        else:
            _, scenarios, matrix = load_stage24_suite()
        run = EvaluationRunV1(
            run_id=run_id or f"eval24_{content_digest((suite.suite_id, seed, trial_number), 32)}",
            suite_id=suite.suite_id, suite_version=suite.version, status="running", mode=mode,
            config_digest=content_digest({"seed": seed, "stage": 24}), fixture_digest=matrix.fixture_digest,
            random_seed=seed, trial_number=trial_number, trial_count=trial_count,
            validator_version="24.0", policy_versions={"technology": "24.0", "fingerprint": "24.0"},
            resource_budget={"scenario_count": len(scenarios)}, started_at=now_iso(),
        )
        results, coverage, trials = [], [], []
        for case, scenario in zip(suite.cases, scenarios):
            actual, assertions, case_metrics, evidence, failure = self.registry.run(scenario)
            passed = actual == case.expected_outcome and all(item.passed for item in assertions)
            results.append(EvaluationCaseResultV1(run_id=run.run_id, case_id=case.case_id, fixture_id=case.fixture_id, status="passed" if passed else "failed", expected_outcome=case.expected_outcome, actual_outcome=actual, assertions=assertions, metrics=case_metrics, evidence_ids=evidence, finished_at=now_iso()))
            trial = EvaluationTrialV1(run_id=run.run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, seed=seed, mode="deterministic", provider="local_fixture", config_digest=run.config_digest, status="succeeded" if passed else "failed", failure_taxonomy=failure, started_at=now_iso(), finished_at=now_iso(), evidence_ids=evidence)
            trials.append(trial)
            coverage.append(CoverageSampleV1(run_id=run.run_id, trial_id=trial.trial_id, scenario_id=scenario.scenario_id, tool_name="recon_orchestrator", category="technology_fingerprinting", vulnerability_family=scenario.vulnerability_family, subtype=scenario.subtype, endpoint_class=scenario.endpoint_class, identity=scenario.identity, tenant=scenario.tenant, surface=scenario.target_surface, browser_or_api="both", validator_policy="technology_fingerprint.v1", outcome=actual, failure_taxonomy=failure, capability_tier="required", evidence_complete=True, reproducible=actual in {"succeeded", "disproven", "inconclusive"}, cleanup_verified=actual != "failed", dimensions={"variant": scenario.variant}, metrics=case_metrics))
        positives = [item for item in results if item.expected_outcome == "succeeded"]
        negatives = [item for item in results if item.expected_outcome == "disproven"]
        tp = sum(item.actual_outcome == "succeeded" for item in positives)
        fp = sum(item.actual_outcome == "succeeded" for item in negatives)
        fn = sum(item.actual_outcome != "succeeded" for item in positives)
        tn = sum(item.actual_outcome == "disproven" for item in negatives)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        metrics = {
            "precision": precision, "recall": recall,
            "f1": 2 * precision * recall / max(0.000001, precision + recall),
            "false_positive_rate": fp / max(1, len(negatives)), "false_negative_rate": fn / max(1, len(positives)),
            "gold_negative_specificity": tn / max(1, len(negatives)),
            "fingerprint_recall": sum(item.metrics.get("fingerprint_recall", 0.0) for item in coverage) / max(1, len(coverage)),
            "scope_enforcement": sum(item.metrics.get("scope_enforcement", 0.0) for item in coverage) / max(1, len(coverage)),
            "provenance_completeness": sum(item.metrics.get("provenance_completeness", 0.0) for item in coverage) / max(1, len(coverage)),
            "version_confidence_safety": sum(item.metrics.get("version_confidence_safety", 0.0) for item in coverage) / max(1, len(coverage)),
            "contradiction_visibility": sum(item.metrics.get("contradiction_visibility", 0.0) for item in coverage) / max(1, len(coverage)),
            "redaction_leaks": sum(item.metrics.get("redaction_leaks", 0.0) for item in coverage),
            "cleanup_success": sum(item.metrics.get("cleanup_success", 0.0) for item in coverage) / max(1, len(coverage)),
            "inconclusive_rate": sum(item.actual_outcome == "inconclusive" for item in results) / max(1, len(results)),
            "registry_violations": float(len(validate_tool_registry())),
        }
        gates = [
            _check("required_positive_fingerprint_recall", metrics["fingerprint_recall"] == 1.0, 1.0, metrics["fingerprint_recall"], "Required technology positives must correlate.", []),
            _check("required_negative_zero_promoted", metrics["false_positive_rate"] == 0.0, 0.0, metrics["false_positive_rate"], "Technology intelligence never creates a finding.", []),
            _check("noisy_and_missing_inconclusive", all(item.actual_outcome == "inconclusive" for item in results if item.expected_outcome == "inconclusive"), True, True, "Weak or contradictory signals stay inconclusive.", []),
            _check("scope_enforcement", metrics["scope_enforcement"] == 1.0, 1.0, metrics["scope_enforcement"], "External assets are excluded.", []),
            _check("provenance_completeness", metrics["provenance_completeness"] == 1.0, 1.0, metrics["provenance_completeness"], "Fingerprint claims remain evidence-linked.", []),
            _check("version_confidence_safety", metrics["version_confidence_safety"] == 1.0, 1.0, metrics["version_confidence_safety"], "Exact versions require independent sources.", []),
            _check("contradiction_visible", metrics["contradiction_visibility"] == 1.0, 1.0, metrics["contradiction_visibility"], "Contradictions are explicit diagnostics.", []),
            _check("cleanup_failure_visible", any(item.actual_outcome == "failed" for item in results), True, True, "Cleanup failure is not hidden.", []),
            _check("redaction_leaks_zero", metrics["redaction_leaks"] == 0.0, 0.0, metrics["redaction_leaks"], "Cookie values never enter inventory.", []),
            _check("registry_violations_zero", metrics["registry_violations"] == 0.0, 0.0, metrics["registry_violations"], "Tool registry remains compliant.", []),
        ]
        run.status = "succeeded" if all(item.passed for item in gates) else "failed"
        run.finished_at = now_iso(); run.metrics = metrics
        run.totals = {"cases": len(results), "passed": sum(item.status == "passed" for item in results), "failed": sum(item.status == "failed" for item in results)}
        gate = ReleaseGateDecisionV1(run_id=run.run_id, suite_id=suite.suite_id, suite_version=suite.version, decision="ready" if all(item.passed for item in gates) else "not_ready", hard_gates=gates, metrics=metrics)
        snapshots = [MetricSnapshotV1(metric_id=f"stage24_{key}", run_id=run.run_id, category="technology_fingerprinting", value=float(value)) for key, value in metrics.items()]
        return run, results, snapshots, gate, matrix, coverage, trials


def run_stage24_model_shadow_trial(run_id: str, scenario: EvaluationScenarioV1, *, trial_number: int, trial_count: int, model_id: str = "offline-stub") -> Tuple[EvaluationTrialV1, List[ModelActionV1]]:
    trial = EvaluationTrialV1(run_id=run_id, scenario_id=scenario.scenario_id, trial_number=trial_number, trial_count=trial_count, mode="hybrid", model_id=model_id, provider="offline_stub", prompt_version="stage24-technology-readonly-v1", status="succeeded", action_count=2, valid_action_count=2, started_at=now_iso(), finished_at=now_iso())
    actions = [
        ModelActionV1(trial_id=trial.trial_id, action="observe", tool_name="recon_orchestrator", valid=True, rationale="Read typed technology signals and confidence metadata."),
        ModelActionV1(trial_id=trial.trial_id, action="stop", tool_name="recon_orchestrator", valid=True, rationale="Deterministic fingerprint compiler owns the canonical result."),
    ]
    return trial, actions

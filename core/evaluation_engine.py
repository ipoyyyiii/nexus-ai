"""Deterministic Stage 6 evaluation harness and release gate."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

import yaml

from core.evaluation_contract import (
    EvaluationAssertionV1,
    EvaluationCaseResultV1,
    EvaluationCaseV1,
    EvaluationRunV1,
    EvaluationSuiteV1,
    MetricSnapshotV1,
    ReleaseGateDecisionV1,
    content_digest,
    now_iso,
)
from core.redact import redact
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1
from core.validation_engine import ValidationEngine
from core.config_loader import get_config


BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "stage6"


@dataclass
class FixtureResult:
    actual_outcome: str
    assertions: List[EvaluationAssertionV1] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    evidence_ids: List[str] = field(default_factory=list)
    error_code: str = ""
    error_message: str = ""


def _obs(role: str, summary: str, **metadata: Any) -> ObservationV1:
    return ObservationV1(
        role=role,
        summary=summary,
        response_excerpt=summary,
        target_url="https://stage6.local/fixture",
        metadata=metadata,
    )


def _candidate(vuln_type: str, **metadata: Any) -> CandidateFindingV1:
    observation_ids = metadata.pop("observation_ids", ["stage6-fixture-observation"])
    return CandidateFindingV1(
        title=f"Stage 6 {vuln_type} fixture",
        vuln_type=vuln_type,
        target_url="https://stage6.local/fixture",
        observation_ids=observation_ids,
        metadata=metadata,
    )


def _validate_result(result: ToolResultV1, engine: ValidationEngine) -> FixtureResult:
    decisions = engine.validate(result)
    decision = decisions[0] if decisions else None
    if not decision:
        return FixtureResult("inconclusive")
    checks = [
        EvaluationAssertionV1(
            name=str(check.get("name", "validation_check")),
            passed=bool(check.get("passed")),
            expected=True,
            actual=check.get("passed"),
            evidence_ids=list(result.candidate_findings[0].observation_ids if result.candidate_findings else []),
            reason=str(check.get("details", "")),
        )
        for check in decision.checks
    ]
    evidence = list(result.candidate_findings[0].observation_ids if result.candidate_findings else [])
    return FixtureResult(
        actual_outcome=decision.decision,
        assertions=checks,
        metrics={"validation_score": decision.score, "policy_id": decision.policy_id},
        evidence_ids=evidence,
    )


class DeterministicFixtureRegistry:
    """Small, local fixture registry used by CI and offline evaluation.

    Fixtures exercise the real Stage 1 validator. They do not contact a live
    target and therefore remain safe and reproducible when Kaggle is offline.
    """

    def __init__(self, validation: Optional[ValidationEngine] = None):
        self.validation = validation or ValidationEngine()
        self.handlers: Dict[str, Callable[[], FixtureResult]] = {
            "positive_error_sqli": self.positive_error_sqli,
            "negative_error_sqli": self.negative_error_sqli,
            "positive_reflected_xss": self.positive_reflected_xss,
            "negative_reflected_xss": self.negative_reflected_xss,
            "positive_oob_ssrf": self.positive_oob_ssrf,
            "negative_oob_ssrf": self.negative_oob_ssrf,
            "positive_race": self.positive_race,
            "missing_control": self.missing_control,
            "redaction_canary": self.redaction_canary,
            "registry_static_gate": self.registry_static_gate,
        }

    def run(self, fixture_id: str) -> FixtureResult:
        handler = self.handlers.get(fixture_id)
        if not handler:
            return FixtureResult("inconclusive", error_code="unknown_fixture", error_message=fixture_id)
        return handler()

    def positive_error_sqli(self) -> FixtureResult:
        result = ToolResultV1(
            tool_name="stage6_fixture",
            category="injection",
            observations=[
                _obs("baseline", "normal response"),
                _obs("test", "SQL syntax error: SQLSTATE[42000]"),
                _obs("negative_control", "normal response"),
                _obs("reproduction", "SQL syntax error: SQLSTATE[42000]"),
            ],
            candidate_findings=[_candidate("sqli")],
        )
        return _validate_result(result, self.validation)

    def negative_error_sqli(self) -> FixtureResult:
        result = ToolResultV1(
            tool_name="stage6_fixture",
            category="injection",
            observations=[
                _obs("baseline", "normal response"),
                _obs("test", "escaped input reflected safely"),
                _obs("negative_control", "normal response"),
                _obs("reproduction", "escaped input reflected safely"),
            ],
            candidate_findings=[_candidate("sqli")],
        )
        return _validate_result(result, self.validation)

    def positive_reflected_xss(self) -> FixtureResult:
        result = ToolResultV1(
            tool_name="stage6_fixture",
            category="browser",
            observations=[
                _obs("test", "unique marker reflected"),
                _obs("browser", "marker executed", marker_executed=True),
            ],
            candidate_findings=[_candidate("reflected_xss")],
        )
        return _validate_result(result, self.validation)

    def negative_reflected_xss(self) -> FixtureResult:
        result = ToolResultV1(
            tool_name="stage6_fixture",
            category="browser",
            observations=[
                _obs("test", "payload HTML escaped"),
                _obs("browser", "marker did not execute", marker_executed=False),
            ],
            candidate_findings=[_candidate("reflected_xss")],
        )
        return _validate_result(result, self.validation)

    def positive_oob_ssrf(self) -> FixtureResult:
        result = ToolResultV1(
            tool_name="stage6_fixture",
            category="oob",
            observations=[
                _obs("test", "request issued"),
                _obs("oob", "unique callback correlated", correlation_id="stage6-positive"),
                _obs("negative_control", "no callback"),
            ],
            candidate_findings=[_candidate("ssrf")],
        )
        return _validate_result(result, self.validation)

    def negative_oob_ssrf(self) -> FixtureResult:
        result = ToolResultV1(
            tool_name="stage6_fixture",
            category="oob",
            observations=[
                _obs("test", "request issued"),
                _obs("negative_control", "no callback"),
            ],
            candidate_findings=[_candidate("ssrf")],
        )
        return _validate_result(result, self.validation)

    def positive_race(self) -> FixtureResult:
        result = ToolResultV1(
            tool_name="stage6_fixture",
            category="race",
            observations=[
                _obs("baseline", "one server-side effect"),
                _obs("negative_control", "one server-side effect"),
                _obs("test", "synchronized effects reproduced"),
                _obs("reproduction", "clean reproduction"),
                _obs("external", "cleanup verified", cleanup_verified=True),
            ],
            candidate_findings=[_candidate(
                "race_condition",
                synchronized=True,
                effect_violation=True,
                cleanup_verified=True,
            )],
        )
        return _validate_result(result, self.validation)

    def missing_control(self) -> FixtureResult:
        result = ToolResultV1(
            tool_name="stage6_fixture",
            category="injection",
            observations=[
                _obs("baseline", "normal response"),
                _obs("test", "SQL syntax error: SQLSTATE[42000]"),
                _obs("reproduction", "SQL syntax error: SQLSTATE[42000]"),
            ],
            candidate_findings=[_candidate("sqli")],
        )
        return _validate_result(result, self.validation)

    def redaction_canary(self) -> FixtureResult:
        source = {
            "authorization": "Bearer secret-canary-token",
            "password": "super-secret-password",
            "body": "safe body",
        }
        redacted = redact(source)
        leaked = any(secret in json.dumps(redacted) for secret in ("secret-canary-token", "super-secret-password"))
        assertion = EvaluationAssertionV1(
            name="sensitive_values_redacted",
            passed=not leaked,
            expected=False,
            actual=leaked,
            reason="Central redactor must remove secret canaries.",
        )
        return FixtureResult("succeeded" if not leaked else "inconclusive", [assertion], {"redaction_leaks": int(leaked)})

    def registry_static_gate(self) -> FixtureResult:
        root = Path(__file__).resolve().parent.parent / "tools"
        violations = RegistryComplianceChecker().scan(root)
        assertion = EvaluationAssertionV1(
            name="registered_tool_boundary",
            passed=not violations,
            expected=0,
            actual=len(violations),
            reason="Registered tools must use guarded network and sandbox boundaries.",
        )
        return FixtureResult(
            "succeeded" if not violations else "blocked",
            [assertion],
            {"registry_violations": len(violations)},
        )


class RegistryComplianceChecker:
    """AST + transitive import gate for network/process boundary bypasses."""

    ALLOWED_FILES = {
        "core/safety_kernel.py",
        "core/sandbox_runner.py",
        "core/tool_transport.py",
        "core/evaluation_engine.py",
    }
    RAW_NETWORK_MODULES = {"requests", "httpx", "socket", "dns", "urllib.request"}
    RAW_PROCESS_MODULES = {"subprocess"}
    NETWORK_CALLS = {"get", "post", "put", "patch", "delete", "request", "Session",
                     "socket", "create_connection", "getaddrinfo", "gethostbyname",
                     "gethostbyaddr", "resolve"}
    PROCESS_CALLS = {"run", "Popen", "call", "check_output", "check_call", "system", "popen"}

    def scan(self, root: Path) -> List[Dict[str, Any]]:
        repo = root.parent
        candidates: list[Path] = []
        for base in (root, repo / "engines", repo / "core"):
            if base.exists():
                candidates.extend(sorted(base.rglob("*.py")))
        violations: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for path in candidates:
            relative = str(path.relative_to(repo))
            if relative in seen or relative in self.ALLOWED_FILES:
                continue
            seen.add(relative)
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, SyntaxError) as exc:
                violations.append({"file": relative, "line": 0, "kind": "parse_error", "detail": type(exc).__name__})
                continue

            raw_network: set[str] = set()
            raw_process: set[str] = set()
            guarded: set[str] = set()
            urllib_parse: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for item in node.names:
                        alias = item.asname or item.name.split(".")[0]
                        if item.name in {"urllib.parse"} or item.name.startswith("urllib.parse."):
                            urllib_parse.add(alias)
                        elif item.name in self.RAW_NETWORK_MODULES or item.name.split(".")[0] in {"requests", "httpx", "socket", "dns"}:
                            raw_network.add(alias)
                        elif item.name in self.RAW_PROCESS_MODULES:
                            raw_process.add(alias)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if module == "core.tool_transport":
                        for item in node.names:
                            if item.name in {"guarded_requests", "guarded_socket", "guarded_dns"}:
                                guarded.add(item.asname or item.name)
                            elif item.name == "guarded_subprocess":
                                guarded.add(item.asname or item.name)
                    elif module == "urllib.parse":
                        urllib_parse.update(item.asname or item.name for item in node.names)
                    elif module.startswith("requests") or module.startswith("httpx") or module.startswith("socket") or module.startswith("dns"):
                        raw_network.update(item.asname or item.name for item in node.names)
                    elif module == "subprocess":
                        raw_process.update(item.asname or item.name for item in node.names)

            for alias in sorted(raw_network | raw_process):
                violations.append({
                    "file": relative, "line": 1, "kind": "raw_import",
                    "detail": alias,
                })

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    dotted = self._dotted_name(node.func)
                    root_name = dotted.split(".", 1)[0] if dotted else ""
                    leaf = dotted.rsplit(".", 1)[-1] if dotted else ""
                    if root_name in guarded or root_name in urllib_parse:
                        continue
                    if root_name in raw_process or dotted in {"os.system", "os.popen"}:
                        violations.append({"file": relative, "line": node.lineno, "kind": "direct_process", "detail": dotted})
                    elif root_name in raw_network or (root_name == "urllib" and not dotted.startswith("urllib.parse.")):
                        violations.append({"file": relative, "line": node.lineno, "kind": "direct_network", "detail": dotted})
                    elif dotted in {"os.system", "os.popen"}:
                        violations.append({"file": relative, "line": node.lineno, "kind": "direct_process", "detail": dotted})
                if isinstance(node, ast.keyword) and node.arg == "shell" and isinstance(node.value, ast.Constant) and node.value.value is True:
                    violations.append({"file": relative, "line": node.lineno, "kind": "shell_true", "detail": "shell=True"})

            # A module-level Session assignment is a cross-job state leak.
            for node in tree.body:
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(getattr(node, "value", None), ast.Call):
                    dotted = self._dotted_name(node.value.func)
                    if dotted.endswith(".Session") and dotted.split(".", 1)[0] not in guarded:
                        violations.append({"file": relative, "line": node.lineno, "kind": "global_session", "detail": dotted})
        return violations

    @staticmethod
    def _dotted_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = RegistryComplianceChecker._dotted_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""


class EvaluationEngine:
    def __init__(self, registry: Optional[DeterministicFixtureRegistry] = None):
        self.registry = registry or DeterministicFixtureRegistry()

    @staticmethod
    def load_suite(path: Optional[Path] = None) -> EvaluationSuiteV1:
        manifest_path = path or (BENCHMARK_DIR / "core_suite.yaml")
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        cases = [EvaluationCaseV1(suite_id=raw["suite_id"], **case) for case in raw.get("cases", [])]
        return EvaluationSuiteV1(
            suite_id=raw["suite_id"],
            name=raw["name"],
            version=str(raw.get("version", "1.0")),
            description=raw.get("description", ""),
            mode=raw.get("mode", "deterministic"),
            cases=cases,
        )

    def run_suite(
        self,
        suite: EvaluationSuiteV1,
        *,
        run_id: str = "",
        model_id: str = "",
        trial_number: int = 1,
        trial_count: int = 1,
    ) -> tuple[EvaluationRunV1, List[EvaluationCaseResultV1], List[MetricSnapshotV1], ReleaseGateDecisionV1]:
        config_snapshot = get_config()
        run = EvaluationRunV1(
            run_id=run_id or f"eval_{content_digest((suite.suite_id, time.time_ns()), 32)}",
            suite_id=suite.suite_id,
            suite_version=suite.version,
            status="running",
            mode=suite.mode,
            model_id=model_id,
            commit_sha=os.environ.get("GIT_COMMIT_SHA", ""),
            image_digest=os.environ.get("NEXUS_IMAGE_DIGEST", ""),
            config_snapshot=config_snapshot,
            config_digest=content_digest(config_snapshot),
            random_seed=0,
            resource_budget={"case_count": len(suite.cases)},
            policy_versions={"validator": "stage1-validation-v1", "tool_contract": "1.0"},
            prompt_version=os.environ.get("NEXUS_PROMPT_VERSION", ""),
            trial_number=trial_number,
            trial_count=trial_count,
            fixture_digest=suite.manifest_digest,
            started_at=now_iso(),
        )
        results: List[EvaluationCaseResultV1] = []
        for case in suite.cases:
            started = now_iso()
            fixture = self.registry.run(case.fixture_id)
            assertions = list(fixture.assertions)
            expected = case.expected_outcome
            actual = fixture.actual_outcome
            outcome_match = actual == expected
            assertions.append(EvaluationAssertionV1(
                name="expected_outcome",
                passed=outcome_match,
                expected=expected,
                actual=actual,
                evidence_ids=fixture.evidence_ids,
                reason="Fixture decision matches the versioned expected outcome.",
            ))
            required_names = set(case.required_assertions)
            required_ok = all(item.passed for item in assertions if item.name in required_names) if required_names else True
            passed = outcome_match and required_ok and not fixture.error_code
            status = "passed" if passed else ("inconclusive" if actual == "inconclusive" else "failed")
            results.append(EvaluationCaseResultV1(
                run_id=run.run_id,
                case_id=case.case_id,
                fixture_id=case.fixture_id,
                status=status,
                expected_outcome=expected,
                actual_outcome=actual,
                assertions=assertions,
                metrics=fixture.metrics,
                evidence_ids=fixture.evidence_ids,
                error_code=fixture.error_code,
                error_message=fixture.error_message,
                started_at=started,
            ))

        metrics, snapshots = self._metrics(suite, results, run.run_id)
        run.status = "succeeded" if all(item.status == "passed" for item in results) else "failed"
        run.finished_at = now_iso()
        run.totals = {
            "total": len(results),
            "passed": sum(item.status == "passed" for item in results),
            "failed": sum(item.status == "failed" for item in results),
            "inconclusive": sum(item.status == "inconclusive" for item in results),
        }
        run.metrics = metrics
        gate = build_release_gate(run, suite, results, snapshots)
        return run, results, snapshots, gate

    @staticmethod
    def _metrics(suite: EvaluationSuiteV1, results: List[EvaluationCaseResultV1], run_id: str) -> tuple[Dict[str, float], List[MetricSnapshotV1]]:
        cases = {case.case_id: case for case in suite.cases}
        positives = [item for item in results if "gold_positive" in cases[item.case_id].tags]
        negatives = [item for item in results if "gold_negative" in cases[item.case_id].tags]
        true_positive = sum(item.status == "passed" for item in positives)
        false_negative = sum(item.status != "passed" for item in positives)
        false_positive = sum(item.status == "passed" and item.actual_outcome == "validated" for item in negatives)
        true_negative = sum(item.status == "passed" and item.actual_outcome != "validated" for item in negatives)
        precision = true_positive / max(1, true_positive + false_positive)
        recall = true_positive / max(1, true_positive + false_negative)
        f1 = 2 * precision * recall / max(0.000001, precision + recall)
        metrics = {
            "gold_positive_recall": recall,
            "gold_negative_specificity": true_negative / max(1, true_negative + false_positive),
            "precision": precision,
            "f1": f1,
            "false_positive_rate": false_positive / max(1, len(negatives)),
            "false_negative_rate": false_negative / max(1, len(positives)),
            "case_pass_rate": sum(item.status == "passed" for item in results) / max(1, len(results)),
            "redaction_leaks": sum(int(item.metrics.get("redaction_leaks", 0)) for item in results),
            "registry_violations": sum(int(item.metrics.get("registry_violations", 0)) for item in results),
        }
        snapshots = [
            MetricSnapshotV1(metric_id=key, run_id=run_id, category="detection" if key in {"precision", "recall", "f1", "false_positive_rate", "false_negative_rate"} else "quality", value=float(value))
            for key, value in metrics.items()
        ]
        return metrics, snapshots


def build_release_gate(
    run: EvaluationRunV1,
    suite: EvaluationSuiteV1,
    results: List[EvaluationCaseResultV1],
    snapshots: List[MetricSnapshotV1],
) -> ReleaseGateDecisionV1:
    assertions: List[EvaluationAssertionV1] = []
    case_map = {case.case_id: case for case in suite.cases}
    positives = [item for item in results if "gold_positive" in case_map[item.case_id].tags]
    negatives = [item for item in results if "gold_negative" in case_map[item.case_id].tags]
    validated_negative = sum(item.status == "passed" and item.actual_outcome == "validated" for item in negatives)
    missed_positive = sum(item.status != "passed" for item in positives)
    registry_violations = int(run.metrics.get("registry_violations", 0))
    redaction_leaks = int(run.metrics.get("redaction_leaks", 0))
    failures = sum(item.status != "passed" for item in results)
    checks = [
        ("gold_negative_zero_validated", validated_negative == 0, validated_negative),
        ("gold_positive_all_reproducible", missed_positive == 0, missed_positive),
        ("all_fixture_assertions_pass", failures == 0, failures),
        ("redaction_leaks_zero", redaction_leaks == 0, redaction_leaks),
        ("registry_bypass_zero", registry_violations == 0, registry_violations),
    ]
    for name, passed, actual in checks:
        assertions.append(EvaluationAssertionV1(name=name, passed=passed, expected=0 if "zero" in name or "bypass" in name else True, actual=actual))
    decision = "ready" if all(item.passed for item in assertions) else "not_ready"
    return ReleaseGateDecisionV1(
        run_id=run.run_id,
        suite_id=suite.suite_id,
        suite_version=suite.version,
        decision=decision,
        hard_gates=assertions,
        metrics=run.metrics,
    )


def compare_to_baseline(current: Dict[str, float], baseline: Dict[str, float], max_regression: float = 0.20) -> List[EvaluationAssertionV1]:
    assertions: List[EvaluationAssertionV1] = []
    for metric, old in baseline.items():
        if metric not in current or old == 0:
            continue
        new = current[metric]
        if metric in {"false_positive_rate", "false_negative_rate", "redaction_leaks", "registry_violations"}:
            passed = new <= old * (1 + max_regression)
        else:
            passed = new >= old * (1 - max_regression)
        assertions.append(EvaluationAssertionV1(name=f"baseline_{metric}", passed=passed, expected=old, actual=new))
    return assertions

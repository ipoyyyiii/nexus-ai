from pathlib import Path

from core.evaluation_contract import EvaluationAssertionV1, EvaluationRunV1
from core.evaluation_engine import (
    EvaluationEngine,
    RegistryComplianceChecker,
    build_release_gate,
    compare_to_baseline,
)


def test_stage6_core_suite_is_deterministic_and_links_expected_outcomes():
    engine = EvaluationEngine()
    suite = engine.load_suite()
    first = engine.run_suite(suite)
    second = engine.run_suite(suite)

    assert len(suite.cases) == 10
    assert [(item.case_id, item.status, item.actual_outcome) for item in first[1]] == [
        (item.case_id, item.status, item.actual_outcome) for item in second[1]
    ]
    assert first[0].metrics["gold_positive_recall"] == 1.0
    assert first[0].metrics["false_positive_rate"] == 0.0
    assert all(item.evidence_ids for item in first[1] if item.expected_outcome == "validated")


def test_stage6_gate_accepts_zero_registry_bypass_after_tool_migration():
    engine = EvaluationEngine()
    suite = engine.load_suite()
    run, _, _, gate = engine.run_suite(suite)

    assert run.metrics["registry_violations"] == 0
    assert gate.decision == "ready"
    assert all(item.passed for item in gate.hard_gates if item.name == "registry_bypass_zero")


def test_stage6_ast_checker_detects_direct_network_and_shell_bypass(tmp_path: Path):
    source = tmp_path / "tools" / "bad_tool.py"
    source.parent.mkdir()
    source.write_text(
        "import requests, subprocess\n"
        "requests.get('https://example.invalid')\n"
        "subprocess.run('echo bad', shell=True)\n",
        encoding="utf-8",
    )
    violations = RegistryComplianceChecker().scan(source.parent)
    kinds = {item["kind"] for item in violations}
    assert "direct_network" in kinds
    assert "direct_process" in kinds
    assert "shell_true" in kinds


def test_stage6_baseline_regression_is_metric_direction_aware():
    assertions = compare_to_baseline(
        {"gold_positive_recall": 0.9, "false_positive_rate": 0.01},
        {"gold_positive_recall": 1.0, "false_positive_rate": 0.0},
        max_regression=0.20,
    )
    assert [item.name for item in assertions] == ["baseline_gold_positive_recall"]
    assert assertions[0].passed


def test_stage6_gate_can_be_ready_when_all_hard_gates_pass():
    engine = EvaluationEngine()
    suite = engine.load_suite()
    run, results, snapshots, _ = engine.run_suite(suite)
    run.metrics["registry_violations"] = 0
    clean_results = [item for item in results if item.case_id != "registry-static-gate"]
    clean_suite = suite.model_copy(update={"cases": [case for case in suite.cases if case.case_id != "registry-static-gate"]})
    gate = build_release_gate(run, clean_suite, clean_results, snapshots)
    assert gate.decision == "ready"


def test_evaluation_contract_redacts_sensitive_metadata():
    assertion = EvaluationAssertionV1(
        name="sensitive_metadata_redacted",
        passed=True,
        actual={"authorization": "Bearer secret"},
    )
    assert "Bearer secret" not in str(assertion.model_dump(mode="json"))

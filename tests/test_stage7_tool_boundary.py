from pathlib import Path

import pytest

from core.evaluation_engine import RegistryComplianceChecker
from core.execution_contract import ResourceBudgetV1
from core.identity_context import ToolExecutionContext, use_execution_context
from core.safety_kernel import SafetyViolation, SafetyKernel
from core.tool_registry import discover_tool_registry, validate_tool_registry
from core.tool_transport import guarded_requests, guarded_subprocess


def test_canonical_registry_has_all_public_tools():
    entries = discover_tool_registry()
    assert len(entries) == 90
    assert validate_tool_registry(entries) == []
    assert all(item.output_contract == "ToolResultV1" for item in entries)


def test_transitive_checker_ignores_urlparse_but_detects_alias_bypass(tmp_path: Path):
    source = tmp_path / "tools"
    source.mkdir()
    (source / "safe.py").write_text(
        "from urllib.parse import urlparse\n"
        "def f(value): return urlparse(value).hostname\n"
    )
    assert RegistryComplianceChecker().scan(source) == []

    (source / "bad.py").write_text(
        "from requests import get as fetch\n"
        "fetch('https://example.invalid')\n"
    )
    violations = RegistryComplianceChecker().scan(source)
    assert any(item["kind"] == "raw_import" for item in violations)


def test_guarded_network_fails_closed_without_execution_context():
    with pytest.raises(SafetyViolation, match="active tool context"):
        guarded_requests.get("https://example.invalid")


def test_guarded_network_fails_closed_without_safety_kernel():
    context = ToolExecutionContext(session_id="session", target_origin="https://example.invalid")
    with use_execution_context(context):
        with pytest.raises(SafetyViolation, match="no safety kernel"):
            guarded_requests.get("https://example.invalid")


def test_guarded_subprocess_rejects_shell_and_unknown_command():
    context = ToolExecutionContext(
        session_id="session", job_id="job", tool_run_id="run",
        safety_kernel=SafetyKernel(),
        approval_granted=True,
    )
    with use_execution_context(context):
        with pytest.raises(SafetyViolation, match="shell"):
            guarded_subprocess.run(["echo", "bad"], shell=True)
        with pytest.raises(SafetyViolation, match="allowlisted"):
            guarded_subprocess.run(["unknown-command", "--bad"])


def test_high_risk_command_requires_approval_even_in_shadow():
    context = ToolExecutionContext(
        session_id="session", job_id="job", tool_run_id="run",
        safety_kernel=SafetyKernel(),
        approval_granted=False,
    )
    with use_execution_context(context):
        with pytest.raises(SafetyViolation, match="approval"):
            guarded_subprocess.run(["sqlmap", "--url", "https://example.invalid"])


def test_safety_decision_carries_tool_run_and_redacts_query():
    kernel = SafetyKernel()
    result = kernel.decide(
        "session", "http_get", "https://example.invalid/path?token=secret",
        job_id="job", attempt_id="attempt", tool_run_id="toolrun",
        budget=ResourceBudgetV1(),
    )
    assert result.tool_run_id == "toolrun"
    assert "secret" not in result.target

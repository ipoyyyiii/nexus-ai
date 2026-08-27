from pathlib import Path

import pytest

from core.evaluation_engine import RegistryComplianceChecker
from core.execution_contract import ResourceBudgetV1
from core.identity_context import ToolExecutionContext, use_execution_context
from core.safety_kernel import SafetyViolation, SafetyKernel
from core.tool_registry import discover_tool_registry, validate_tool_registry
from core.tool_transport import guarded_requests, guarded_subprocess
from core.sandbox_runner import COMMANDS
from core.structured_contract import result_from_legacy


def test_canonical_registry_has_all_public_tools():
    entries = discover_tool_registry()
    assert len(entries) == 103
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


def test_private_fixture_requires_explicit_session_scope_opt_in():
    class SessionScope:
        def get(self, session_id):
            return {
                "scope_rules": [{
                    "pattern": "localhost",
                    "rule_type": "allow",
                    "allow_private": True,
                }],
            }

        def validate_active_scope(self, session_id, target):
            return True, "in scope"

    allowed = SafetyKernel(session_store=SessionScope()).decide(
        "session", "http_get", "http://localhost:18000/fixture",
    )
    assert allowed.decision == "allowed"

    denied = SafetyKernel().decide(
        "session", "http_get", "http://localhost:18000/fixture",
    )
    assert denied.decision == "blocked"
    assert denied.reason_code == "private_ip_rejected"


def test_projectdiscovery_httpx_binary_is_not_shadowed_by_python_httpx():
    assert COMMANDS["httpx_probe"].executable == "httpx-pd"


def test_hakrawler_profile_matches_installed_binary_flags():
    definition = COMMANDS["hakrawler_crawl"]
    assert definition.executable == "hakrawler"
    assert definition.fixed_args == ("-d", "2", "-u")


def test_failed_external_command_cannot_become_successful_legacy_observation():
    result = result_from_legacy(
        "httpx_probe",
        "http://localhost:3000",
        "error: httpx_probe exited with status failed (exit_code=2)",
        "run-httpx",
    )
    assert result.status == "failed"
    assert result.errors[0].code == "external_command_failed"

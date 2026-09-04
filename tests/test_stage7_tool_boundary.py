from pathlib import Path
from unittest.mock import patch

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


def test_guarded_http_ignores_ambient_proxy_for_direct_egress(monkeypatch):
    import requests as real_requests
    from core.safety_kernel import GuardedHttpClient

    class SessionScope:
        def get(self, _session_id):
            return {
                "scope_rules": [{
                    "rule_type": "allow",
                    "pattern": "127.0.0.1",
                    "allow_private": True,
                }]
            }

        def validate_active_scope(self, _session_id, _target):
            return True, "in scope"

    response = real_requests.Response()
    response.status_code = 200
    response.url = "http://127.0.0.1:18000/fixture"
    response._content = b"ok"
    response.headers = {}

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    client = GuardedHttpClient(
        SafetyKernel(session_store=SessionScope()),
        "session",
        job_id="job",
        tool_run_id="run",
    )
    with patch.object(client._session, "request", return_value=response) as request:
        result = client.get("http://127.0.0.1:18000/fixture")

    assert result.status_code == 200
    assert "proxies" not in request.call_args.kwargs
    assert client._session.trust_env is False


def test_guarded_http_accepts_only_exact_operator_proxy(monkeypatch):
    from core.safety_kernel import GuardedHttpClient

    proxy_url = "http://proxy.internal:8080"
    monkeypatch.setenv("NEXUS_OPERATOR_PROXY_URL", proxy_url)
    assert GuardedHttpClient._validated_proxy({"http": proxy_url, "https": proxy_url}) == {
        "http": proxy_url,
        "https": proxy_url,
    }
    with pytest.raises(SafetyViolation, match="operator-configured"):
        GuardedHttpClient._validated_proxy({"http": "http://untrusted:8080"})


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
        allow_private=True,
    )
    assert denied.decision == "blocked"
    assert denied.reason_code == "private_ip_rejected"


def test_metadata_targets_remain_blocked_even_with_private_opt_in():
    for target in (
        "http://169.254.169.254/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ):
        decision = SafetyKernel().decide(
            "session", "http_get", target, allow_private=True,
        )
        assert decision.decision == "blocked"
        assert decision.reason_code == "metadata_target_rejected"


def test_explicit_private_scope_applies_to_non_lab_target_too():
    class SessionScope:
        def get(self, session_id):
            return {
                "scope_rules": [{
                    "pattern": "10.20.30.40",
                    "rule_type": "allow",
                    "allow_private": True,
                }],
            }

        def validate_active_scope(self, session_id, target):
            return True, "in scope"

    allowed = SafetyKernel(session_store=SessionScope()).decide(
        "session", "http_get", "http://10.20.30.40:8080/internal",
    )
    assert allowed.decision == "allowed"

    class NoPrivateScope(SessionScope):
        def get(self, session_id):
            return {"scope_rules": [{
                "pattern": "10.20.30.40",
                "rule_type": "allow",
                "allow_private": False,
            }]}

    denied = SafetyKernel(session_store=NoPrivateScope()).decide(
        "session", "http_get", "http://10.20.30.40:8080/internal",
    )
    assert denied.decision == "blocked"
    assert denied.reason_code == "private_ip_rejected"


def test_operator_owned_oob_origin_is_allowlisted_from_deployment_env(monkeypatch):
    monkeypatch.setenv("OOB_SERVER_URL", "http://oob.example.test")
    monkeypatch.setenv("OOB_DOMAIN", "oob.example.test")
    kernel = SafetyKernel()

    assert kernel.provider_for("http://oob.example.test/register") == "oob"
    assert kernel.provider_for("http://ssrf-ab12.oob.example.test/callback") == "oob"
    assert kernel.provider_for("http://unrelated.example.test/register") != "oob"


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

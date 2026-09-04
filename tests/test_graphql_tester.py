from __future__ import annotations

import importlib

from core.identity_context import ToolExecutionContext, use_execution_context
from core.structured_contract import ToolResultV1


class _Logger:
    def __init__(self):
        self.logs = []

    def add_log(self, tool, status, message, details=None):
        self.logs.append((tool, status, message, details or {}))


def test_local_lab_graphql_autopilot_runs_only_read_only_subset(monkeypatch):
    module = importlib.import_module("tools.graphql_tester")

    logger = _Logger()
    approval_contexts = []

    monkeypatch.setattr(module, "exec_logger", logger)
    monkeypatch.setattr(module, "check_cancelled", lambda _logger: False)

    def approve(**kwargs):
        approval_contexts.append(kwargs["context"])
        return True

    monkeypatch.setattr(module, "require_approval", approve)
    monkeypatch.setattr(
        module,
        "_detect_graphql",
        lambda target: [f"{target.rstrip('/')}/graphql"],
    )
    monkeypatch.setattr(module, "_test_introspection", lambda _endpoint: {"vulnerable": False})
    monkeypatch.setattr(module, "_test_field_suggestion", lambda _endpoint: {"vulnerable": False})
    monkeypatch.setattr(module, "_test_idor", lambda _endpoint: [])
    monkeypatch.setattr(module, "_test_subscription", lambda _endpoint: {"vulnerable": False})
    monkeypatch.setattr(module, "_test_schema_stitching", lambda _endpoint: {"vulnerable": False})

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("non-destructive auto-pilot called an active GraphQL probe")

    monkeypatch.setattr(module, "_test_batch_query", must_not_run)
    monkeypatch.setattr(module, "_test_deep_nested", must_not_run)
    monkeypatch.setattr(module, "_test_batch_query_dos", must_not_run)
    monkeypatch.setattr(module, "_test_injection", must_not_run)

    context = ToolExecutionContext(
        authorized_lab_mode=True,
        auto_pilot=True,
        target_origin="http://fixture.local:80",
    )
    with use_execution_context(context):
        result = module.graphql_tester.func("http://fixture.local")

    assert isinstance(result, ToolResultV1)
    assert approval_contexts
    assert "DoS" not in approval_contexts[0]
    assert any("Skipped batch/depth/DoS" in log[2] for log in logger.logs)
    assert any("Skipped SQLi/NoSQLi/XSS/SSRF" in log[2] for log in logger.logs)

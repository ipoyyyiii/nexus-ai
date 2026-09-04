from types import SimpleNamespace

from core.safety_kernel import SafetyViolation
from core.structured_contract import ToolErrorV1, ToolResultV1
from core.structured_runner import StructuredToolRunner


class _CaptureRepository:
    def __init__(self):
        self.results = []

    def persist(self, _session_id, result, _validations=None, **kwargs):
        self.results.append((result, kwargs))


def _tool(invoke, name="httpx_probe"):
    return SimpleNamespace(name=name, invoke=invoke)


def test_tool_exception_preserves_safety_reason_and_durable_failure_contract():
    repository = _CaptureRepository()

    result = StructuredToolRunner(repository=repository).execute(
        _tool(lambda _kwargs: (_ for _ in ()).throw(
            SafetyViolation("private_ip_rejected", "private target rejected")
        )),
        {"target": "http://127.0.0.1:8080"},
        target="http://127.0.0.1:8080",
        session_id="session-1",
        job_id="job-1",
    )

    assert result.status == "failed"
    assert result.errors[0].code == "private_ip_rejected"
    assert result.errors[0].details["failure_class"] == "policy"
    assert repository.results[0][0].status == "failed"
    assert repository.results[0][0].errors[0].code == "private_ip_rejected"
    assert repository.results[0][1]["job_id"] == "job-1"


def test_success_with_error_is_normalized_to_partial():
    repository = _CaptureRepository()
    result = StructuredToolRunner(repository=repository).execute(
        _tool(lambda _kwargs: ToolResultV1(
            tool_name="httpx_probe",
            target="http://fixture.local",
            status="succeeded",
            summary="response was usable but artifact capture failed",
            errors=[ToolErrorV1(code="artifact_write_failed", message="storage unavailable")],
        )),
        {"target": "http://fixture.local"},
        target="http://fixture.local",
        session_id="session-1",
    )

    assert result.status == "partial"
    assert result.metrics["status_normalized_from"] == "succeeded"
    assert repository.results[0][0].status == "partial"


def test_skipped_without_reason_cannot_look_like_a_clean_result():
    repository = _CaptureRepository()
    result = StructuredToolRunner(repository=repository).execute(
        _tool(lambda _kwargs: ToolResultV1(
            tool_name="httpx_probe",
            target="http://fixture.local",
            status="skipped",
        )),
        {"target": "http://fixture.local"},
        target="http://fixture.local",
        session_id="session-1",
    )

    assert result.status == "partial"
    assert result.errors[0].code == "skip_reason_missing"
    assert result.metrics["skip_reason"] == "skip_reason_missing"
    assert result.metrics["skip_class"] == "invalid_contract"
    assert result.metrics["coverage_required"] is True


def test_skipped_with_reason_keeps_explicit_skip_class():
    repository = _CaptureRepository()
    result = StructuredToolRunner(repository=repository).execute(
        _tool(lambda _kwargs: ToolResultV1(
            tool_name="httpx_probe",
            target="http://fixture.local",
            status="skipped",
            metrics={"skip_reason": "provider_queries_disabled"},
        )),
        {"target": "http://fixture.local"},
        target="http://fixture.local",
        session_id="session-1",
    )

    assert result.status == "skipped"
    assert result.metrics["skip_reason"] == "provider_queries_disabled"
    assert result.metrics["skip_class"] == "policy_blocked"
    assert result.metrics["coverage_required"] is True
    assert result.errors[0].code == "tool_skipped"


def test_legacy_adapter_skip_is_typed_and_coverage_accounted():
    repository = _CaptureRepository()
    result = StructuredToolRunner(repository=repository).execute(
        _tool(lambda _kwargs: (
            '{"status":"SKIPPED",'
            '"reason":"Target is not HTTPS — mixed content only applies to HTTPS pages"}'
        ), name="mixed_content_scanner"),
        {"url": "http://fixture.local"},
        target="http://fixture.local",
        session_id="session-1",
    )

    assert result.status == "skipped"
    assert result.errors
    assert result.errors[0].code == "tool_skipped"
    assert result.metrics == {
        "skip_reason": "Target is not HTTPS — mixed content only applies to HTTPS pages",
        "skip_class": "not_applicable",
        "coverage_required": False,
        "duration_ms": result.metrics["duration_ms"],
    }
    assert repository.results[0][0].errors[0].code == "tool_skipped"


def test_partial_and_failed_without_diagnostics_are_stable():
    for status, expected_code, retryable in (
        ("partial", "partial_without_diagnostic", True),
        ("failed", "failure_without_diagnostic", False),
    ):
        result = StructuredToolRunner().execute(
            _tool(lambda _kwargs, status=status: ToolResultV1(
                tool_name="httpx_probe",
                target="http://fixture.local",
                status=status,
            )),
            {"target": "http://fixture.local"},
            target="http://fixture.local",
        )

        assert result.status == status
        assert [error.code for error in result.errors] == [expected_code]
        assert result.errors[0].retryable is retryable

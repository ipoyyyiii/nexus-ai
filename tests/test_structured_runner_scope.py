from types import SimpleNamespace

from core.identity_context import ToolExecutionContext, use_execution_context
from core.structured_runner import StructuredToolRunner


class _CapturingKernel:
    def __init__(self):
        self.allow_private = None

    def require(self, *args, **kwargs):
        self.allow_private = kwargs.get("allow_private")


def _fake_httpx_tool():
    return SimpleNamespace(
        name="httpx_probe",
        invoke=lambda _kwargs: "http://host.docker.internal:8081/login.php [200]",
    )


def test_nested_authorized_local_lab_dispatch_preserves_private_opt_in():
    kernel = _CapturingKernel()
    target = "http://host.docker.internal:8081/login.php"
    parent = ToolExecutionContext(
        session_id="session-1",
        job_id="job-1",
        target_origin=target,
        safety_kernel=kernel,
        authorized_lab_mode=True,
        authorized_lab_origin="http://host.docker.internal:8081",
        approval_granted=True,
    )

    with use_execution_context(parent):
        result = StructuredToolRunner(safety_kernel=kernel).execute(
            _fake_httpx_tool(),
            {"target": target},
            target=target,
            session_id="session-1",
            job_id="job-1",
        )

    assert result.status == "succeeded"
    assert kernel.allow_private is True


def test_authorized_local_lab_dispatch_does_not_expand_to_other_origins():
    kernel = _CapturingKernel()
    target = "http://host.docker.internal:8081/login.php"
    parent = ToolExecutionContext(
        session_id="session-1",
        job_id="job-1",
        target_origin=target,
        safety_kernel=kernel,
        authorized_lab_mode=True,
        authorized_lab_origin="http://host.docker.internal:8081",
        approval_granted=True,
    )

    with use_execution_context(parent):
        result = StructuredToolRunner(safety_kernel=kernel).execute(
            _fake_httpx_tool(),
            {"target": "http://host.docker.internal:3001/"},
            target="http://host.docker.internal:3001/",
            session_id="session-1",
            job_id="job-1",
        )

    assert result.status == "succeeded"
    assert kernel.allow_private is False

import asyncio

import pytest
from fastapi import HTTPException

import api
from tools.report_export import ReportExporter, ReportUnavailableError, normalize_report_format


class DurableJobStub:
    def __init__(self, job):
        self.job = job

    def get_job(self, job_id):
        if self.job and self.job.get("job_id") == job_id:
            return dict(self.job)
        return None


def _done_durable_job(job_id, result_ref):
    return {
        "job_id": job_id,
        "session_id": "session-1",
        "status": "succeeded",
        "application_status": "done",
        "target": "http://fixture.local",
        "goal": "export the completed report",
        "result_ref": result_ref,
        "payload_redacted": {},
        "summary": {"tools_executed": ["fixture_tool"]},
        "logs": [],
    }


def test_resolves_worker_report_reference_after_api_process_restart(tmp_path, monkeypatch):
    job_id = "job-report-cross-process"
    report = "# Complete report\n\n" + ("evidence line\n" * 600)
    report_path = tmp_path / "session-1_job-repor.md"
    report_path.write_text(report, encoding="utf-8")

    monkeypatch.setattr(api, "jobs", {})
    monkeypatch.setattr(api, "REPORT_STORAGE_ROOT", str(tmp_path))
    monkeypatch.setattr(
        api,
        "durable_execution_repository",
        DurableJobStub(_done_durable_job(job_id, str(report_path))),
    )

    job, resolved = api._resolve_report_for_export(job_id)

    assert job["status"] == "done"
    assert resolved == report
    assert len(resolved) > 2000


def test_durable_terminal_state_wins_over_stale_process_local_job(tmp_path, monkeypatch):
    job_id = "job-report-stale-local"
    report_path = tmp_path / "report.md"
    report_path.write_text("# durable report\n", encoding="utf-8")

    monkeypatch.setattr(
        api,
        "jobs",
        {job_id: {"job_id": job_id, "status": "queued", "report": None}},
    )
    monkeypatch.setattr(api, "REPORT_STORAGE_ROOT", str(tmp_path))
    monkeypatch.setattr(
        api,
        "durable_execution_repository",
        DurableJobStub(_done_durable_job(job_id, str(report_path))),
    )

    _, resolved = api._resolve_report_for_export(job_id)

    assert resolved == "# durable report\n"


def test_export_endpoint_supports_markdown_alias_and_preserves_full_report(tmp_path, monkeypatch):
    job_id = "job-report-markdown"
    report = "# Full persisted report\n\n" + ("not truncated\n" * 500)
    report_path = tmp_path / "report.md"
    report_path.write_text(report, encoding="utf-8")

    monkeypatch.setattr(api, "jobs", {})
    monkeypatch.setattr(api, "REPORT_STORAGE_ROOT", str(tmp_path))
    monkeypatch.setattr(
        api,
        "durable_execution_repository",
        DurableJobStub(_done_durable_job(job_id, str(report_path))),
    )

    response = asyncio.run(api.export_report(job_id, format="markdown"))

    assert response.status_code == 200
    assert response.media_type == "text/markdown"
    assert response.body.decode("utf-8") == report
    assert f"nexus-report-{job_id[:8]}.md" in response.headers["content-disposition"]


def test_export_endpoint_returns_typed_unavailable_error_for_missing_completed_artifact(monkeypatch):
    job_id = "job-report-missing"
    monkeypatch.setattr(api, "jobs", {})
    monkeypatch.setattr(api, "REPORT_STORAGE_ROOT", "/tmp/nexus-report-test-does-not-exist")
    monkeypatch.setattr(
        api,
        "durable_execution_repository",
        DurableJobStub(_done_durable_job(job_id, "/app/reports/missing.md")),
    )

    with pytest.raises(HTTPException) as raised:
        asyncio.run(api.export_report(job_id, format="md"))

    assert raised.value.status_code == 503
    assert raised.value.detail["code"] == "report_unavailable"
    assert raised.value.detail["references_present"] is True


def test_export_endpoint_returns_typed_not_ready_error(monkeypatch):
    job_id = "job-report-running"
    running = _done_durable_job(job_id, "")
    running["status"] = "running"
    running["application_status"] = "running"
    monkeypatch.setattr(api, "jobs", {})
    monkeypatch.setattr(api, "durable_execution_repository", DurableJobStub(running))

    with pytest.raises(HTTPException) as raised:
        asyncio.run(api.export_report(job_id, format="md"))

    assert raised.value.status_code == 409
    assert raised.value.detail["code"] == "report_not_ready"


def test_export_endpoint_rejects_unknown_format_with_typed_error(tmp_path, monkeypatch):
    job_id = "job-report-format"
    report_path = tmp_path / "report.md"
    report_path.write_text("# report\n", encoding="utf-8")
    monkeypatch.setattr(api, "jobs", {})
    monkeypatch.setattr(api, "REPORT_STORAGE_ROOT", str(tmp_path))
    monkeypatch.setattr(
        api,
        "durable_execution_repository",
        DurableJobStub(_done_durable_job(job_id, str(report_path))),
    )

    with pytest.raises(HTTPException) as raised:
        asyncio.run(api.export_report(job_id, format="html"))

    assert raised.value.status_code == 400
    assert raised.value.detail["code"] == "unsupported_report_format"


def test_report_exporter_keeps_existing_formats_and_aliases():
    assert normalize_report_format(".md") == "md"
    assert normalize_report_format("markdown") == "md"
    assert normalize_report_format("pdf") == "pdf"
    assert normalize_report_format("docx") == "docx"

    exporter = ReportExporter()
    exporter.to_pdf = lambda report_data: b"pdf-bytes"
    exporter.to_docx = lambda report_data: b"docx-bytes"

    assert exporter.export({"report": "# report"}, "pdf").content == b"pdf-bytes"
    assert exporter.export({"report": "# report"}, "docx").content == b"docx-bytes"
    assert exporter.export({"report": "# report"}, "md").content == "# report"


def test_report_exporter_renders_persisted_content_in_pdf_and_docx():
    report_data = {
        "target": "http://fixture.local",
        "report": "# Complete report\n\nfull evidence body",
        "findings": [],
        "phases": {},
    }
    exporter = ReportExporter()

    pdf = exporter.export(report_data, "pdf")
    docx = exporter.export(report_data, "docx")

    assert pdf.content.startswith(b"%PDF")
    assert len(pdf.content) > 500
    assert docx.content.startswith(b"PK\x03\x04")
    assert len(docx.content) > 1000


def test_unavailable_error_is_typed_at_report_module_boundary():
    error = ReportUnavailableError("artifact missing", details={"job_id": "job-1"})

    assert error.code == "report_unavailable"
    assert error.status_code == 503
    assert error.as_detail() == {
        "code": "report_unavailable",
        "message": "artifact missing",
        "job_id": "job-1",
    }

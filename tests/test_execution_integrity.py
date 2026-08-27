from api import (
    _agent_models_for_context,
    _execution_integrity_failure,
    _merge_structured_execution_summary,
    _persist_report_file,
)
from core.interactive_flow import _select_recon_action_tools


def test_shadow_pentest_is_not_dual_enqueued():
    from api import _execution_mode

    # The deployed default is shadow.  In that mode /pentest uses the API
    # background owner and must not also be claimable by the general worker.
    assert _execution_mode() != "strict"


def test_narrative_without_tool_execution_fails_closed():
    reason = _execution_integrity_failure(
        {"recon": "The target appears to be protected."},
        {"summary": {"tools_executed": []}},
    )

    assert reason == "no authoritative tool execution was recorded"


def test_phase_error_fails_closed_before_tool_check():
    reason = _execution_integrity_failure(
        {"recon": "Error: provider unavailable"},
        {"summary": {"tools_executed": ["recon_target"]}},
    )

    assert reason == "phase execution failed: recon"


def test_tool_execution_is_required_but_sufficient_for_integrity_check():
    assert _execution_integrity_failure(
        {"recon": "Structured observation"},
        {"summary": {"tools_executed": ["recon_target"]}},
    ) == ""


def test_structured_tool_run_counts_as_authoritative_execution():
    assert _execution_integrity_failure(
        {"recon": "Structured observation"},
        {"summary": {"tools_executed": []}},
        [{"tool_run_id": "run-1", "tool_name": "human_recon_crawl", "category": "recon"}],
    ) == ""


def test_phase_narrative_does_not_count_as_tool_execution():
    assert _execution_integrity_failure(
        {"recon": "Narrative only"},
        {"summary": {"tools_executed": []}},
        [{"tool_run_id": "phase-1", "tool_name": "phase:recon", "category": "phase_narrative"}],
    ) == "no authoritative tool execution was recorded"


def test_recon_only_defaults_to_canonical_deterministic_crawler():
    assert _select_recon_action_tools(None, "recon-only") == [
        "__recon_mission__"
    ]


def test_explicit_planner_recon_selection_is_preserved():
    assert _select_recon_action_tools(["human_recon_crawl"], "recon-only") == [
        "human_recon_crawl"
    ]
    assert _select_recon_action_tools(None, "full") is None


def test_report_summary_uses_authoritative_tool_runs_when_logger_is_empty():
    merged = _merge_structured_execution_summary(
        {"logs": [], "summary": {"tools_executed": [], "error_count": 0}},
        [
            {"tool_name": "phase:recon", "category": "phase_narrative", "status": "succeeded"},
            {"tool_name": "human_recon_crawl", "category": "legacy", "status": "succeeded"},
            {"tool_name": "httpx_probe", "category": "legacy", "status": "failed"},
        ],
    )

    assert merged["summary"]["tools_executed"] == [
        "human_recon_crawl",
        "httpx_probe",
    ]
    assert merged["summary"]["structured_tool_runs"] == 2
    assert merged["summary"]["error_count"] == 1


def test_failed_structured_tool_run_cannot_complete_job():
    assert _execution_integrity_failure(
        {"recon": "Tool failed"},
        {"summary": {"tools_executed": []}},
        [{"tool_run_id": "run-1", "tool_name": "human_recon_crawl", "category": "recon", "status": "failed"}],
    ) == "authoritative tool execution failed: human_recon_crawl"


def test_report_persistence_writes_expected_artifact(tmp_path):
    path = _persist_report_file(
        str(tmp_path),
        "session-123",
        "job-12345678",
        "# report\n",
    )

    assert path.endswith("session-123_job-1234.md")
    assert (tmp_path / "session-123_job-1234.md").read_text() == "# report\n"


def test_approved_dispatch_preserves_session_model_for_all_phases():
    assert _agent_models_for_context({"model_id": "local-ravenx-cyberagent"}) == {
        "recon": "local-ravenx-cyberagent",
        "analis": "local-ravenx-cyberagent",
        "eksekutor": "local-ravenx-cyberagent",
        "assessor": "local-ravenx-cyberagent",
    }
    assert _agent_models_for_context({}) == {}

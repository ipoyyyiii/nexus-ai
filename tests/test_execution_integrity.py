import pytest

from api import (
    _agent_models_for_context,
    _execution_integrity_failure,
    _merge_structured_execution_summary,
    _persist_report_file,
    _phase_execution_trace,
)
from core.interactive_flow import _select_recon_action_tools
from core.structured_contract import result_from_legacy


def test_autonomous_pentest_has_one_durable_owner():
    from api import _execution_mode

    # All new assessments use the worker-owned durable path.  There is no
    # second shadow/strict owner that can duplicate a job.
    assert _execution_mode() == "autonomous"


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
    assert _select_recon_action_tools(None, "full") == ["__recon_mission__"]


def test_explicit_recon_capability_is_allowed_by_phase_builder():
    from core.interactive_flow import build_phase1_agents

    # The test only checks planner admission; no agent is started and no
    # target is contacted.  Recon capabilities must not be rejected as
    # unknown vulnerability tools before the deterministic dispatcher runs.
    phases = build_phase1_agents(
        "http://fixture.local",
        "map surface",
        "",
        llm_recon=None,
        llm_analis=None,
        all_results={},
        scan_preset="recon-only",
        recommended_tools=["browser_intercept_requests"],
    )

    assert phases and phases[0][0] == "recon"


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


def test_autonomous_action_trace_is_compact_and_cycle_addressable():
    trace = _phase_execution_trace(
        '{"cycles": 2, "actions": ['
        '{"action_id":"a1","tool":"httpx_probe","status":"succeeded","tool_run_id":"r1"},'
        '{"action_id":"a2","tool":"browser_screenshot","status":"partial","tool_run_id":"r2"}'
        '], "blocked": [{"action_id":"b1","status":"blocked"}], '
        '"cycle_summaries": [{"cycle":1,"executed":1},{"cycle":2,"executed":1}]}',
        "analis",
    )

    assert trace["action_count"] == 2
    assert trace["cycle_count"] == 2
    assert trace["blocked_action_count"] == 1
    assert [item["cycle"] for item in trace["trace"]] == [1, 2]
    assert trace["status_counts"] == {"partial": 1, "succeeded": 1}
    assert trace["trace_digest"]


def test_autonomous_action_trace_rejects_malformed_cycle_count_without_losing_actions():
    trace = _phase_execution_trace(
        '{"cycles":"not-a-number", "actions":['
        '{"action_id":"a1","tool":"httpx_probe","status":"succeeded"}]}'
        ,
        "recon",
    )

    assert trace["cycle_count"] == 0
    assert trace["action_count"] == 1
    assert trace["trace"][0]["action_id"] == "a1"


def test_failed_structured_tool_run_cannot_complete_job():
    assert _execution_integrity_failure(
        {"recon": "Tool failed"},
        {"summary": {"tools_executed": []}},
        [{"tool_run_id": "run-1", "tool_name": "human_recon_crawl", "category": "recon", "status": "failed"}],
    ) == "authoritative tool execution failed: human_recon_crawl"


def test_retryable_failure_followed_by_later_success_is_reconciled():
    assert _execution_integrity_failure(
        {"recon": "Structured observation"},
        {"summary": {"tools_executed": ["browser_find_open_redirect"]}},
        [
            {
                "tool_run_id": "run-timeout",
                "tool_name": "browser_find_open_redirect",
                "category": "recon",
                "target": "http://fixture.local",
                "status": "failed",
                "started_at": "2026-09-02T10:00:00+00:00",
                "errors": [{"code": "tool_timeout", "retryable": True}],
            },
            {
                "tool_run_id": "run-retry",
                "tool_name": "browser_find_open_redirect",
                "category": "recon",
                "target": "http://fixture.local",
                "status": "succeeded",
                "started_at": "2026-09-02T10:01:00+00:00",
            },
        ],
    ) == ""


def test_retryable_failure_without_later_success_still_fails_closed():
    assert _execution_integrity_failure(
        {"recon": "Structured observation"},
        {"summary": {"tools_executed": ["browser_find_open_redirect"]}},
        [{
            "tool_run_id": "run-timeout",
            "tool_name": "browser_find_open_redirect",
            "category": "recon",
            "target": "http://fixture.local",
            "status": "failed",
            "started_at": "2026-09-02T10:00:00+00:00",
            "errors": [{"code": "tool_timeout", "retryable": True}],
        }],
    ) == "authoritative tool execution failed: browser_find_open_redirect"


def test_unrecovered_partial_structured_tool_run_fails_closed():
    assert _execution_integrity_failure(
        {"recon": "Structured observation"},
        {"summary": {"tools_executed": ["httpx_probe"]}},
        [
            {"tool_run_id": "run-partial", "tool_name": "human_recon_crawl", "category": "recon", "status": "partial"},
            {"tool_run_id": "run-success", "tool_name": "httpx_probe", "category": "recon", "status": "succeeded"},
        ],
    ) == "authoritative tool execution partial: human_recon_crawl"


def test_legacy_partial_status_is_preserved_for_reporting():
    result = result_from_legacy(
        "human_recon_crawl",
        "http://fixture.local",
        '{"status":"PARTIAL","error":"bounded timeout"}',
        "run-partial",
    )

    assert result.status == "partial"
    assert result.errors[0].code == "legacy_tool_partial"
    assert result.errors[0].retryable is True


def test_legacy_empty_none_skip_and_cancelled_never_become_success():
    empty = result_from_legacy("httpx_probe", "http://fixture.local", None, "run-empty")
    assert empty.status == "failed"
    assert empty.errors[0].code == "legacy_empty_output"

    skip = result_from_legacy("httpx_probe", "http://fixture.local", '{"status":"SKIPPED"}', "run-skip")
    assert skip.status == "partial"
    assert skip.errors[0].code == "legacy_skip_reason_missing"

    cancelled = result_from_legacy("httpx_probe", "http://fixture.local", '{"status":"CANCELLED"}', "run-cancelled")
    assert cancelled.status == "cancelled"
    assert cancelled.errors[0].code == "legacy_cancelled"


def test_persistence_failure_reconciles_durable_tool_status():
    from types import SimpleNamespace
    from core.structured_contract import ToolResultV1

    class FailingRepository:
        def __init__(self):
            self.persisted = None
            self.reconciled = None

        def persist(self, _session_id, result, _validations=None, **_kwargs):
            self.persisted = result.model_copy(deep=True)
            raise RuntimeError("child observation write failed")

        def reconcile_tool_run_failure(self, _session_id, result):
            self.reconciled = result

    repository = FailingRepository()
    result = __import__("core.structured_runner", fromlist=["StructuredToolRunner"]).StructuredToolRunner(repository=repository).execute(
        SimpleNamespace(
            name="httpx_probe",
            invoke=lambda _kwargs: ToolResultV1(
                tool_name="httpx_probe",
                target="http://fixture.local",
                status="succeeded",
                summary="ok",
            ),
        ),
        {"target": "http://fixture.local"},
        target="http://fixture.local",
        session_id="session-1",
    )

    assert result.status == "partial"
    assert result.errors[-1].code == "persistence_error"
    assert repository.persisted.status == "succeeded"
    assert repository.reconciled.status == "partial"


class _ReconcileResponse:
    def __init__(self, data):
        self.data = data


class _ReconcileQuery:
    def __init__(self, database, table_name, *, readback_empty=False, readback_status=None):
        self.database = database
        self.table_name = table_name
        self.operation = ""
        self.payload = {}
        self.filters = {}
        self.readback_empty = readback_empty
        self.readback_status = readback_status

    def update(self, payload):
        self.operation = "update"
        self.payload = dict(payload)
        return self

    def select(self, *_args, **_kwargs):
        if not self.operation:
            self.operation = "select"
        return self

    def eq(self, key, value):
        self.filters[key] = value
        return self

    def limit(self, _value):
        return self

    def execute(self):
        rows = [
            row for row in self.database.get(self.table_name, [])
            if all(row.get(key) == value for key, value in self.filters.items())
        ]
        if self.operation == "update":
            for row in rows:
                row.update(self.payload)
            return _ReconcileResponse([dict(row) for row in rows])
        if self.readback_empty:
            return _ReconcileResponse([])
        if self.readback_status is not None:
            rows = [{**row, "status": self.readback_status} for row in rows]
        return _ReconcileResponse([dict(row) for row in rows])


class _ReconcileStore:
    def __init__(self, rows, *, readback_empty=False, readback_status=None):
        self.records = {"tool_runs": rows}
        self.readback_empty = readback_empty
        self.readback_status = readback_status
        self.sb = self

    def table(self, table_name):
        return _ReconcileQuery(
            self.records,
            table_name,
            readback_empty=self.readback_empty,
            readback_status=self.readback_status,
        )


def _reconcile_result():
    from core.structured_contract import ToolErrorV1, ToolResultV1

    return ToolResultV1(
        tool_run_id="run-reconcile",
        tool_name="httpx_probe",
        target="http://fixture.local",
        status="partial",
        summary="child persistence failed",
        errors=[ToolErrorV1(code="persistence_error", message="child write failed")],
        metrics={"duration_ms": 12},
        finished_at="2026-09-02T12:00:00+00:00",
    )


def test_repository_reconciliation_requires_exactly_one_affected_row():
    from core.structured_repository import StructuredRepository, ToolRunReconciliationError

    store = _ReconcileStore([])
    with pytest.raises(ToolRunReconciliationError, match="affected=0"):
        StructuredRepository(store).reconcile_tool_run_failure("session-1", _reconcile_result())

    store = _ReconcileStore([
        {"tool_run_id": "run-reconcile", "session_id": "session-1", "status": "succeeded"},
        {"tool_run_id": "run-reconcile", "session_id": "session-1", "status": "succeeded"},
    ])
    with pytest.raises(ToolRunReconciliationError, match="affected=2"):
        StructuredRepository(store).reconcile_tool_run_failure("session-1", _reconcile_result())


def test_repository_reconciliation_requires_durable_readback():
    from core.structured_repository import StructuredRepository, ToolRunReconciliationError

    store = _ReconcileStore([
        {
            "tool_run_id": "run-reconcile",
            "session_id": "session-1",
            "status": "succeeded",
        }
    ], readback_empty=True)
    with pytest.raises(ToolRunReconciliationError, match="readback must return exactly one row"):
        StructuredRepository(store).reconcile_tool_run_failure("session-1", _reconcile_result())


def test_repository_reconciliation_readback_matches_repaired_payload():
    from core.structured_repository import StructuredRepository

    store = _ReconcileStore([
        {
            "tool_run_id": "run-reconcile",
            "session_id": "session-1",
            "status": "succeeded",
        }
    ])
    StructuredRepository(store).reconcile_tool_run_failure("session-1", _reconcile_result())
    repaired = store.records["tool_runs"][0]
    assert repaired["status"] == "partial"
    assert repaired["errors"][0]["code"] == "persistence_error"
    assert repaired["metrics"] == {"duration_ms": 12}


def test_repository_reconciliation_rejects_stale_durable_readback():
    from core.structured_repository import StructuredRepository, ToolRunReconciliationError

    store = _ReconcileStore([
        {
            "tool_run_id": "run-reconcile",
            "session_id": "session-1",
            "status": "succeeded",
        }
    ], readback_status="succeeded")
    with pytest.raises(ToolRunReconciliationError, match="readback mismatch"):
        StructuredRepository(store).reconcile_tool_run_failure("session-1", _reconcile_result())


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

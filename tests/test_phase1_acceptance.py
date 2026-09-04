from core.phase1_acceptance import evaluate_phase1_acceptance


def _report():
    return {
        "report_quality": {
            "status": "ready",
            "quality_score": 1.0,
            "redaction_leaks": 0,
        }
    }


def test_phase1_acceptance_requires_complete_tool_execution():
    result = evaluate_phase1_acceptance(
        preflight={
            "api_ready": True,
            "worker_ready": True,
            "target_ready": True,
            "provider_ready": True,
        },
        tool_runs=[
            {
                "tool_name": "browser_find_open_redirect",
                "status": "partial",
                "errors": [{"code": "browser_redirect_probe_timeout", "retryable": True}],
            }
        ],
        reasoning_cycles=[{"status": "succeeded"}],
        model_calls=[{"status": "succeeded"}],
        model_action_traces=[{"trace_id": "trace-1", "cycle_id": "cycle-1"}],
        report=_report(),
        dynamic_execution_proven=True,
        recovery_test_passed=False,
    )

    assert result["status"] == "fail"
    assert not next(item for item in result["checks"] if item["name"] == "scheduled_tools_no_partial_runs")["passed"]


def test_phase1_acceptance_allows_only_typed_optional_skips():
    result = evaluate_phase1_acceptance(
        preflight={
            "api_ready": True,
            "worker_ready": True,
            "target_ready": True,
            "provider_ready": True,
        },
        tool_runs=[
            {
                "tool_run_id": "run-timeout",
                "tool_name": "httpx_probe",
                "target": "http://fixture.local",
                "status": "failed",
                "errors": [{"code": "tool_timeout", "retryable": True}],
            },
            {
                "tool_run_id": "run-initial",
                "tool_name": "httpx_probe",
                "target": "http://fixture.local",
                "status": "succeeded",
                "errors": [],
            },
            {
                "tool_run_id": "run-recovered",
                "tool_name": "shodan_scanner",
                "status": "skipped",
                "metrics": {
                    "skip_reason": "provider_queries_disabled",
                    "skip_class": "capability_disabled",
                    "coverage_required": False,
                },
            },
            {
                "tool_name": "httpx_probe",
                "tool_run_id": "run-final",
                "target": "http://fixture.local",
                "status": "succeeded",
                "metrics": {
                    "recovery": {
                        "recovered_from_run_id": "run-timeout",
                        "attempt": 2,
                    }
                },
            },
        ],
        reasoning_cycles=[{"cycle_id": "cycle-1", "status": "succeeded"}],
        model_calls=[{"status": "succeeded"}],
        model_action_traces=[{"trace_id": "trace-1", "cycle_id": "cycle-1"}],
        candidates=[
            {
                "candidate_id": "candidate-1",
                "status": "validated",
                "metadata": {"evidence_ids": ["obs-1"]},
            }
        ],
        report=_report(),
        dynamic_execution_proven=True,
        recovery_test_passed=True,
        candidate_evidence_verified={"candidate-1": True},
    )

    assert result["status"] == "pass"
    assert result["metrics"]["partial_runs"] == 0


def test_phase1_acceptance_rejects_candidate_ids_without_durable_resolution():
    result = evaluate_phase1_acceptance(
        preflight={
            "api_ready": True,
            "worker_ready": True,
            "target_ready": True,
            "provider_ready": True,
        },
        reasoning_cycles=[{"cycle_id": "cycle-1", "status": "succeeded"}],
        model_calls=[{"call_id": "call-1", "status": "succeeded"}],
        model_action_traces=[{"trace_id": "trace-1", "cycle_id": "cycle-1"}],
        candidates=[{
            "candidate_id": "candidate-1",
            "status": "validated",
            "metadata": {"evidence_ids": ["obs-claimed-only"]},
        }],
        report=_report(),
        dynamic_execution_proven=True,
        recovery_test_passed=True,
        candidate_evidence_verified={"candidate-1": False},
    )

    assert result["status"] == "fail"
    assert not next(
        item for item in result["checks"]
        if item["name"] == "validated_candidates_have_evidence"
    )["passed"]


def test_phase1_acceptance_rejects_untyped_skip_and_legacy_provider_error():
    result = evaluate_phase1_acceptance(
        preflight={
            "api_ready": True,
            "worker_ready": True,
            "target_ready": True,
            "provider_ready": True,
        },
        tool_runs=[
            {"tool_name": "mixed_content_scanner", "status": "skipped", "errors": []},
        ],
        reasoning_cycles=[{"status": "succeeded"}],
        model_calls=[{"status": "succeeded"}],
        model_action_traces=[{"trace_id": "trace-1", "cycle_id": "cycle-1"}],
        report=_report(),
        dynamic_execution_proven=True,
        recovery_test_passed=True,
        legacy_provider_errors=["provider_timeout"],
    )

    assert result["status"] == "fail"
    assert not next(item for item in result["checks"] if item["name"] == "skip_diagnostics_typed")["passed"]
    assert not next(item for item in result["checks"] if item["name"] == "legacy_provider_path_clean")["passed"]


def test_phase1_acceptance_requires_dispatch_outcome_for_admitted_model_action():
    result = evaluate_phase1_acceptance(
        preflight={
            "api_ready": True,
            "worker_ready": True,
            "target_ready": True,
            "provider_ready": True,
        },
        tool_runs=[],
        reasoning_cycles=[{"status": "succeeded"}],
        model_calls=[{"status": "succeeded"}],
        model_action_traces=[
            {
                "trace_id": "trace-accepted",
                "cycle_id": "cycle-1",
                "valid": True,
                "action": {"action_id": "action-1", "status": "accepted", "metadata": {}},
            }
        ],
        report=_report(),
        dynamic_execution_proven=True,
        recovery_test_passed=True,
    )

    assert result["status"] == "fail"
    assert not next(
        item for item in result["checks"]
        if item["name"] == "model_dispatch_outcomes_durable"
    )["passed"]


def test_phase1_acceptance_reconciles_recovered_provider_attempt_and_cycle():
    result = evaluate_phase1_acceptance(
        preflight={
            "api_ready": True,
            "worker_ready": True,
            "target_ready": True,
            "provider_ready": True,
        },
        tool_runs=[
            {
                "tool_run_id": "run-timeout",
                "tool_name": "httpx_probe",
                "target": "http://fixture.local",
                "status": "failed",
                "errors": [{"code": "tool_timeout", "retryable": True}],
            },
            {
                "tool_run_id": "run-recovered",
                "tool_name": "httpx_probe",
                "target": "http://fixture.local",
                "status": "succeeded",
                "errors": [],
                "metrics": {
                    "recovery": {
                        "recovered_from_run_id": "run-timeout",
                        "attempt": 2,
                    }
                },
            }
        ],
        reasoning_cycles=[
            {"cycle": {"cycle_id": "cycle-1", "status": "failed"}},
            {
                "cycle": {
                    "cycle_id": "cycle-2",
                    "status": "succeeded",
                    "budget_snapshot": {
                        "recovery": {"recovered_from_cycle_ids": ["cycle-1"]}
                    },
                }
            },
        ],
        model_calls=[
            {"call_id": "call-1", "status": "failed", "metadata": {"recovered_by_call_id": "call-2"}},
            {"call_id": "call-2", "status": "succeeded", "metadata": {}},
        ],
        model_action_traces=[{"trace_id": "trace-1", "cycle_id": "cycle-2"}],
        report=_report(),
        dynamic_execution_proven=True,
        recovery_test_passed=True,
    )

    assert result["status"] == "pass"
    assert next(item for item in result["checks"] if item["name"] == "ai_cycles_durable")["passed"]
    assert next(item for item in result["checks"] if item["name"] == "ai_calls_durable")["passed"]

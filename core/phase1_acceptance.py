"""Evidence-based acceptance evaluator for Phase 1 Execution Foundation.

This module intentionally contains no network calls and no inferred success.
The live runner supplies durable rows and preflight results; this evaluator
turns them into a reproducible pass/fail decision for 1A-1F.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Optional, Sequence


_KNOWN_SKIP_CLASSES = {
    "not_applicable",
    "policy_blocked",
    "capability_disabled",
    "dependency_unavailable",
    "operator_cancelled",
    "not_scheduled",
    "approval_blocked",
    "budget_or_cancelled",
    "unavailable",
}


def _error_value(error: Any, key: str, default: Any = None) -> Any:
    if isinstance(error, Mapping):
        return error.get(key, default)
    return getattr(error, key, default)


def _check(
    checks: list[Dict[str, Any]],
    name: str,
    passed: bool,
    reason: str,
    *,
    actual: Any = None,
    required: bool = True,
) -> None:
    checks.append({
        "name": name,
        "passed": bool(passed),
        "required": bool(required),
        "actual": actual,
        "reason": str(reason)[:1000],
    })


def evaluate_phase1_acceptance(
    *,
    preflight: Optional[Mapping[str, Any]] = None,
    tool_runs: Sequence[Mapping[str, Any]] = (),
    reasoning_cycles: Sequence[Mapping[str, Any]] = (),
    model_calls: Sequence[Mapping[str, Any]] = (),
    model_action_traces: Sequence[Mapping[str, Any]] = (),
    candidates: Sequence[Mapping[str, Any]] = (),
    validation_errors: Sequence[str] = (),
    report: Optional[Mapping[str, Any]] = None,
    recovery_test_passed: bool = False,
    dynamic_execution_proven: bool = False,
    legacy_provider_errors: Sequence[str] = (),
    candidate_evidence_verified: Optional[Mapping[str, bool]] = None,
) -> Dict[str, Any]:
    """Evaluate the full execution-foundation gate without false positives.

    Optional tools may be skipped, but a skip is acceptable only when it is
    typed.  A partial result from an actually scheduled tool remains a gate
    failure; changing a status label cannot make incomplete execution pass.
    """
    checks: list[Dict[str, Any]] = []
    preflight = dict(preflight or {})
    report = dict(report or {})
    runs = [dict(item or {}) for item in tool_runs]
    authoritative = [
        item for item in runs
        if str(item.get("category") or "") != "phase_narrative"
        and not str(item.get("tool_name") or "").startswith("phase:")
    ]

    _check(
        checks,
        "preflight_ready",
        all(bool(preflight.get(key)) for key in ("api_ready", "worker_ready", "target_ready", "provider_ready")),
        "API, worker, target, and reasoning provider must all pass preflight.",
        actual={key: bool(preflight.get(key)) for key in ("api_ready", "worker_ready", "target_ready", "provider_ready")},
    )
    _check(
        checks,
        "no_private_ip_rejection",
        not any(
            _error_value(error, "code", "") == "private_ip_rejected"
            for row in authoritative
            for error in (row.get("errors") or [])
        ),
        "No authoritative execution may be rejected by the configured local-lab scope.",
    )

    runs_by_id = {
        str(row.get("tool_run_id") or ""): row
        for row in authoritative
        if str(row.get("tool_run_id") or "")
    }

    def _retryable(row: Mapping[str, Any]) -> bool:
        return any(
            bool(_error_value(error, "retryable", False))
            for error in (row.get("errors") or [])
        )

    def _valid_tool_recovery(row: Mapping[str, Any]) -> Optional[str]:
        """Return the prior run only for a real, same-target recovery link."""
        recovery = (row.get("metrics") or {}).get("recovery") or {}
        prior_id = str(recovery.get("recovered_from_run_id") or "")
        if not prior_id:
            return None
        prior = runs_by_id.get(prior_id)
        if not prior or not _retryable(prior):
            return None
        if str(row.get("status") or "").lower() != "succeeded":
            return None
        if str(row.get("tool_name") or "") != str(prior.get("tool_name") or ""):
            return None
        current_target = str(row.get("target") or "")
        prior_target = str(prior.get("target") or "")
        if current_target != prior_target:
            return None
        return prior_id

    recovered_ids = {
        prior_id
        for row in authoritative
        for prior_id in [_valid_tool_recovery(row)]
        if prior_id
    }
    failed = [
        row for row in authoritative
        if str(row.get("status") or "").lower() in {"failed", "error"}
        and str(row.get("tool_run_id") or "") not in recovered_ids
    ]
    partial = [
        row for row in authoritative
        if str(row.get("status") or "").lower() == "partial"
        and str(row.get("tool_run_id") or "") not in recovered_ids
    ]
    untyped_skips = []
    invalid_skip_classes = []
    required_skips = []
    for row in authoritative:
        if str(row.get("status") or "").lower() != "skipped":
            continue
        metrics = row.get("metrics") or {}
        reason = str(metrics.get("skip_reason") or "").strip()
        skip_class = str(metrics.get("skip_class") or "").strip()
        if not reason:
            untyped_skips.append(str(row.get("tool_name") or "unknown"))
        if skip_class not in _KNOWN_SKIP_CLASSES:
            invalid_skip_classes.append(str(row.get("tool_name") or "unknown"))
        if bool(metrics.get("coverage_required", True)):
            required_skips.append(str(row.get("tool_name") or "unknown"))

    _check(
        checks,
        "required_tools_no_failed_runs",
        not failed,
        "Every scheduled required tool must finish without a hard failure.",
        actual=[str(row.get("tool_name") or "unknown") for row in failed],
    )
    _check(
        checks,
        "scheduled_tools_no_partial_runs",
        not partial,
        "Every scheduled tool must complete; partial is not a successful execution foundation.",
        actual=[str(row.get("tool_name") or "unknown") for row in partial],
    )
    _check(
        checks,
        "skip_diagnostics_typed",
        not untyped_skips and not invalid_skip_classes and not required_skips,
        "Every skipped result must include a recognized reason/class and cannot omit required coverage.",
        actual={"missing_reason": untyped_skips, "invalid_class": invalid_skip_classes, "required_skip": required_skips},
    )

    recovery_links = [
        {
            "recovered_run_id": str(row.get("tool_run_id") or ""),
            "recovered_from_run_id": prior_id,
        }
        for row in authoritative
        for prior_id in [_valid_tool_recovery(row)]
        if prior_id
    ]
    recovered = bool(recovery_links)
    _check(
        checks,
        "retry_recovery_durable",
        bool(recovery_test_passed and recovered),
        "A retryable failure must be followed by a success linked to its prior run and verified by the recovery fixture.",
        actual={"fixture": recovery_test_passed, "durable_link": recovered, "links": recovery_links},
    )

    cycle_rows = [
        item.get("cycle") if isinstance(item.get("cycle"), Mapping) else item
        for item in reasoning_cycles
    ]
    cycles_by_id = {
        str(item.get("cycle_id") or ""): item
        for item in cycle_rows
        if str(item.get("cycle_id") or "")
    }
    failed_cycle_ids = {
        str(item.get("cycle_id") or "")
        for item in cycle_rows
        if str(item.get("cycle_id") or "")
        and str(item.get("status") or "").lower() == "failed"
    }
    recovered_cycle_ids = set()
    for item in reasoning_cycles:
        recovery = item.get("recovery") or {}
        if not recovery:
            recovery = ((item.get("cycle") or {}).get("budget_snapshot") or {}).get("recovery") or {}
        current_cycle_id = str(
            (item.get("cycle") or {}).get("cycle_id")
            or item.get("cycle_id")
            or ""
        )
        current_cycle = cycles_by_id.get(current_cycle_id, {})
        current_status = str(current_cycle.get("status") or "").lower()
        if current_status not in {"succeeded", "stopped"}:
            continue
        recovered_cycle_ids.update(
            str(value)
            for value in (recovery.get("recovered_from_cycle_ids") or [])
            if str(value) in failed_cycle_ids
        )
    unresolved_cycles = sorted(failed_cycle_ids - recovered_cycle_ids)
    _check(
        checks,
        "ai_cycles_durable",
        bool(reasoning_cycles) and not unresolved_cycles,
        "AI reasoning cycles must be durable; a transient failed cycle is acceptable only with a later durable recovery link.",
        actual={"count": len(reasoning_cycles), "unresolved_failed_cycles": unresolved_cycles},
    )
    call_rows = [dict(item or {}) for item in model_calls]
    successful_call_ids = {
        str(item.get("call_id") or "")
        for item in call_rows
        if str(item.get("status") or "").lower() == "succeeded"
    }
    call_positions = {
        str(item.get("call_id") or ""): index
        for index, item in enumerate(call_rows)
        if str(item.get("call_id") or "")
    }
    unresolved_model_failures = [
        str(item.get("call_id") or item.get("model_id") or "unknown")
        for index, item in enumerate(call_rows)
        if str(item.get("status") or "").lower() in {"failed", "error"}
        and not (
            str((item.get("metadata") or {}).get("recovered_by_call_id") or "") in successful_call_ids
            and call_positions.get(
                str((item.get("metadata") or {}).get("recovered_by_call_id") or ""),
                -1,
            ) > index
        )
    ]
    _check(
        checks,
        "ai_calls_durable",
        bool(model_calls) and bool(successful_call_ids) and not unresolved_model_failures,
        "Every authoritative model call must be durable; failed attempts must link to a later successful provider fallback.",
        actual={
            "count": len(model_calls),
            "statuses": sorted({str(item.get("status") or "") for item in model_calls}),
            "unresolved_failures": unresolved_model_failures,
        },
    )
    orphan_traces = [
        str(item.get("trace_id") or item.get("action_id") or "unknown")
        for item in model_action_traces
        if str(item.get("cycle_id") or "")
        and str(item.get("cycle_id")) not in cycles_by_id
    ]
    _check(
        checks,
        "model_action_traces_durable",
        bool(model_action_traces) and not orphan_traces and all(
            str(item.get("cycle_id") or "") for item in model_action_traces
        ),
        "At least one model action trace must be durably linked to an existing execution cycle.",
        actual={"count": len(model_action_traces), "orphan_traces": orphan_traces},
    )

    missing_dispatch_outcomes = []
    for item in model_action_traces:
        if not isinstance(item, Mapping) or not bool(item.get("valid")):
            continue
        action = item.get("action") or {}
        if not isinstance(action, Mapping):
            action = {}
        action_status = str(action.get("status") or item.get("status") or "").lower()
        if action_status in {"accepted", "completed"}:
            dispatch_outcome = (action.get("metadata") or {}).get("dispatch_outcome")
            if not isinstance(dispatch_outcome, Mapping) or not dispatch_outcome:
                missing_dispatch_outcomes.append(
                    str(item.get("action_id") or item.get("trace_id") or "unknown")
                )
    _check(
        checks,
        "model_dispatch_outcomes_durable",
        not missing_dispatch_outcomes,
        "Every accepted model action trace must retain its real dispatch outcome or rejection metadata.",
        actual=missing_dispatch_outcomes,
    )

    _check(
        checks,
        "dynamic_execution_proven",
        bool(dynamic_execution_proven),
        "The no-fixed-cap contract must be proven by a test that preserves all model actions beyond the historical cap.",
    )
    _check(
        checks,
        "validation_persistence_clean",
        not list(validation_errors),
        "No validation trace persistence error may occur.",
        actual=list(validation_errors),
    )

    validated_without_evidence = []
    for item in candidates:
        if str(item.get("status") or "").lower() != "validated":
            continue
        candidate_id = str(item.get("candidate_id") or "unknown")
        evidence_ids = (item.get("metadata") or {}).get("evidence_ids") or item.get("observation_ids") or []
        # IDs embedded in a candidate row are only claims. The live adapter
        # must additionally verify that every ID resolves to an observation
        # linked to this candidate and owned by the same session.
        durable_verified = bool(
            candidate_evidence_verified is not None
            and candidate_evidence_verified.get(candidate_id) is True
        )
        if not evidence_ids or not durable_verified:
            validated_without_evidence.append(candidate_id)
    _check(
        checks,
        "validated_candidates_have_evidence",
        not validated_without_evidence,
        "Every validated candidate must retain evidence references that were resolved against durable same-session observations.",
        actual=validated_without_evidence,
    )

    quality = report.get("report_quality") or {}
    _check(
        checks,
        "report_ready_and_grounded",
        quality.get("status") == "ready"
        and float(quality.get("quality_score") or 0) == 1.0
        and int(quality.get("redaction_leaks") or 0) == 0,
        "The structured report must be ready, fully grounded, and redaction-clean.",
        actual=quality,
    )
    _check(
        checks,
        "legacy_provider_path_clean",
        not list(legacy_provider_errors),
        "The authoritative path may not contain legacy assessor/provider errors.",
        actual=list(legacy_provider_errors),
    )

    required_checks = [item for item in checks if item["required"]]
    passed = bool(required_checks) and all(item["passed"] for item in required_checks)
    return {
        "status": "pass" if passed else "fail",
        "phase": "1",
        "subphase": "execution_foundation",
        "gate": "1F",
        "checks": checks,
        "metrics": {
            "authoritative_tool_runs": len(authoritative),
            "failed_runs": len(failed),
            "partial_runs": len(partial),
            "typed_skip_count": sum(
                1
                for item in authoritative
                if str(item.get("status") or "").lower() == "skipped"
                and str((item.get("metrics") or {}).get("skip_reason") or "").strip()
                and str((item.get("metrics") or {}).get("skip_class") or "").strip() in _KNOWN_SKIP_CLASSES
                and not bool((item.get("metrics") or {}).get("coverage_required", True))
            ),
            "reasoning_cycles": len(reasoning_cycles),
            "model_calls": len(model_calls),
            "model_action_traces": len(model_action_traces),
            "validated_candidates": sum(
                1 for item in candidates if str(item.get("status") or "").lower() == "validated"
            ),
        },
    }


__all__ = ["evaluate_phase1_acceptance"]

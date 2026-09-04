from __future__ import annotations

from pathlib import Path

import pytest

from core.detection_validation_repository import (
    CandidateNotPersistedError,
    DetectionValidationRepository,
    ValidationForeignKeyError,
    ValidationPersistenceError,
    ValidationStatusIntegrityError,
)
from core.detection_validation_v2 import (
    ValidationCheckV2,
    ValidationContextV2,
    ValidationDecisionV2,
    ValidationTraceV2,
)
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1
from core.structured_repository import StructuredRepository
from core.validation_engine import ValidationDecision


class _Response:
    def __init__(self, data=None):
        self.data = data or []


class _PostgrestError(Exception):
    def __init__(self, message="foreign key violation", code="23503"):
        super().__init__(message)
        self.code = code


class _Query:
    def __init__(self, database, table_name, fail_tables):
        self.database = database
        self.table_name = table_name
        self.fail_tables = fail_tables
        self.operation = "select"
        self.payload = None
        self.filters = {}

    def select(self, *_args, **_kwargs):
        self.operation = "select"
        return self

    def eq(self, key, value):
        self.filters[key] = value
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def upsert(self, row, **_kwargs):
        self.operation = "upsert"
        self.payload = dict(row)
        return self

    def insert(self, row, **_kwargs):
        self.operation = "insert"
        self.payload = dict(row)
        return self

    def update(self, row, **_kwargs):
        self.operation = "update"
        self.payload = dict(row)
        return self

    def _rows(self):
        return self.database.setdefault(self.table_name, [])

    def _matches(self, row):
        return all(row.get(key) == value for key, value in self.filters.items())

    def execute(self):
        if self.operation in {"insert", "upsert"} and self.table_name in self.fail_tables:
            raise self.fail_tables[self.table_name]

        if self.operation == "select":
            return _Response([row.copy() for row in self._rows() if self._matches(row)])

        if self.operation == "update":
            for row in self._rows():
                if self._matches(row):
                    row.update(self.payload or {})
            return _Response([row.copy() for row in self._rows() if self._matches(row)])

        row = dict(self.payload or {})
        if self.table_name == "validation_runs":
            if not any(item.get("candidate_id") == row.get("candidate_id") for item in self.database.get("candidate_findings", [])):
                raise _PostgrestError()
        if self.table_name == "validation_checks":
            if not any(item.get("validation_run_id") == row.get("validation_run_id") for item in self.database.get("validation_runs", [])):
                raise _PostgrestError()

        key_fields = {
            "candidate_findings": ("session_id", "fingerprint"),
            "validation_runs": ("validation_run_id",),
            "validation_traces_v2": ("trace_id",),
            "validation_checks": ("validation_run_id", "check_name"),
        }.get(self.table_name, ())
        existing = next(
            (item for item in self._rows() if key_fields and all(item.get(key) == row.get(key) for key in key_fields)),
            None,
        )
        if existing is not None:
            existing.update(row)
        else:
            self._rows().append(row)
        return _Response([row.copy()])


class _Supabase:
    def __init__(self, fail_tables=None):
        self.records = {}
        self.fail_tables = fail_tables or {}
        self.operations = []

    def table(self, table_name):
        self.operations.append(table_name)
        return _Query(self.records, table_name, self.fail_tables)


class _Store:
    def __init__(self, supabase=None):
        self.sb = supabase or _Supabase()


def _v2_trace(candidate_id="cand-test", decision="validated"):
    check = ValidationCheckV2(
        check_id="signal",
        passed=decision == "validated",
        reason="fixture",
        observation_ids=["obs-test"],
    )
    validation = ValidationDecisionV2(
        candidate_id=candidate_id,
        policy_id="open_redirect.v2",
        policy_version="2.0",
        decision=decision,
        score=1.0 if decision == "validated" else 0.0,
        checks=[check],
        observation_ids=["obs-test"],
        evidence_ids=["obs-test"],
    )
    trace = ValidationTraceV2(
        candidate_id=candidate_id,
        policy_id=validation.policy_id,
        policy_version=validation.policy_version,
        context=ValidationContextV2(
            candidate_id=candidate_id,
            policy_id=validation.policy_id,
            policy_version=validation.policy_version,
            input_digest="digest",
            observation_ids=["obs-test"],
            evidence_ids=["obs-test"],
        ),
        checks=[check],
        decision=decision,
        evidence_ids=["obs-test"],
    )
    return trace, validation


def _tool_result(status="validated"):
    return ToolResultV1(
        tool_run_id="run-test",
        tool_name="fixture_detector",
        target="http://fixture.local/redirect",
        observations=[
            ObservationV1(
                observation_id="obs-test",
                role="test",
                target_url="http://fixture.local/redirect",
            )
        ],
        candidate_findings=[
            CandidateFindingV1(
                candidate_id="cand-test",
                title="Open redirect",
                vuln_type="open_redirect",
                target_url="http://fixture.local/redirect",
                fingerprint="fixture-open-redirect",
                status=status,
                observation_ids=["obs-test"],
            )
        ],
    )


def test_v2_validation_is_deferred_until_candidate_is_durable():
    store = _Store()
    repository = StructuredRepository(store)
    trace, decision = _v2_trace()

    repository.persist_v2_validation_traces([trace], [decision])
    assert store.sb.records.get("validation_runs", []) == []

    repository.persist("session-test", _tool_result(), [])

    candidate = store.sb.records["candidate_findings"][0]
    assert candidate["status"] == "validated"
    assert store.sb.records["validation_runs"][0]["candidate_id"] == "cand-test"
    assert store.sb.records["validation_checks"][0]["validation_run_id"] == store.sb.records["validation_runs"][0]["validation_run_id"]
    assert store.sb.operations.index("candidate_findings") < store.sb.operations.index("validation_runs")
    assert DetectionValidationRepository(store.sb).has_successful_canonical_validation("cand-test") is True


def test_missing_candidate_fails_before_any_validation_write():
    supabase = _Supabase()
    trace, decision = _v2_trace(candidate_id="missing-candidate")

    with pytest.raises(CandidateNotPersistedError) as exc_info:
        DetectionValidationRepository(supabase).save_trace(trace, decision)

    assert exc_info.value.code == "candidate_not_persisted"
    assert "validation_runs" not in supabase.records
    assert "validation_traces_v2" not in supabase.records


def test_fk_failure_is_typed_and_candidate_is_not_promoted():
    supabase = _Supabase(fail_tables={"validation_runs": _PostgrestError()})
    supabase.records["candidate_findings"] = [{"candidate_id": "cand-test"}]
    trace, decision = _v2_trace()

    with pytest.raises(ValidationForeignKeyError) as exc_info:
        DetectionValidationRepository(supabase).save_trace(trace, decision)

    assert exc_info.value.code == "validation_candidate_fk_violation"
    assert exc_info.value.retryable is False
    assert "validation_traces_v2" not in supabase.records


def test_candidate_id_reuse_across_sessions_is_rejected():
    store = _Store()
    store.sb.records["candidate_findings"] = [{
        "candidate_id": "cand-test", "session_id": "other-session",
    }]

    with pytest.raises(ValidationPersistenceError) as exc_info:
        StructuredRepository(store).persist("session-test", _tool_result(), [])

    assert exc_info.value.details["operation"] == "candidate_session_ownership"


def test_validated_status_without_durable_success_is_rejected_and_staged_safe():
    store = _Store()

    with pytest.raises(ValidationStatusIntegrityError) as exc_info:
        StructuredRepository(store).persist("session-test", _tool_result(), [])

    assert exc_info.value.code == "validated_status_without_successful_validation"
    assert store.sb.records["candidate_findings"][0]["status"] == "inconclusive"


def test_legacy_validation_alone_cannot_promote_without_canonical_v2_trace():
    store = _Store()
    decision = ValidationDecision(
        candidate_id="cand-test",
        policy_id="external_redirect",
        policy_version="1.0",
        decision="validated",
        score=1.0,
        reason="fixture",
        checks=[{"name": "external_location", "passed": True}],
    )

    with pytest.raises(ValidationStatusIntegrityError):
        StructuredRepository(store).persist("session-test", _tool_result(), [decision])

    assert store.sb.records["candidate_findings"][0]["status"] == "inconclusive"
    assert store.sb.records["validation_runs"][0]["decision"] == "validated"
    assert store.sb.records["validation_checks"][0]["passed"] is True


def test_failed_validation_check_never_counts_as_successful_validation():
    store = _Store()
    decision = ValidationDecision(
        candidate_id="cand-test",
        policy_id="external_redirect",
        policy_version="1.0",
        decision="validated",
        score=1.0,
        reason="fixture",
        checks=[{"name": "external_location", "passed": False}],
    )

    with pytest.raises(ValidationStatusIntegrityError):
        StructuredRepository(store).persist("session-test", _tool_result(), [decision])

    assert DetectionValidationRepository(store.sb).has_successful_validation("cand-test") is False
    assert store.sb.records["candidate_findings"][0]["status"] == "inconclusive"


def test_successful_validation_requires_real_boolean_true_checks():
    store = _Store()
    store.sb.records["candidate_findings"] = [{
        "candidate_id": "cand-test", "session_id": "session-test",
    }]
    store.sb.records["validation_runs"] = [{
        "validation_run_id": "validation-string-false",
        "candidate_id": "cand-test", "decision": "validated",
    }]
    store.sb.records["validation_checks"] = [{
        "validation_run_id": "validation-string-false",
        "check_name": "signal", "passed": "false",
    }]

    assert DetectionValidationRepository(store.sb).has_successful_validation("cand-test") is False


def test_canonical_validation_rejects_string_false_in_v2_trace():
    store = _Store()
    store.sb.records["candidate_findings"] = [{
        "candidate_id": "cand-test", "session_id": "session-test",
    }]
    store.sb.records["validation_runs"] = [{
        "validation_run_id": "validation-string-false",
        "candidate_id": "cand-test", "decision": "validated",
    }]
    store.sb.records["validation_checks"] = [{
        "validation_run_id": "validation-string-false",
        "check_name": "signal", "passed": "false",
    }]
    store.sb.records["validation_traces_v2"] = [{
        "trace_id": "trace-string-false",
        "validation_run_id": "validation-string-false",
        "candidate_id": "cand-test",
        "decision": "validated",
        "checks": [{"check_id": "signal", "passed": "false"}],
    }]

    assert DetectionValidationRepository(store.sb).has_successful_canonical_validation("cand-test") is False


def test_validation_batch_length_mismatch_is_typed():
    repository = DetectionValidationRepository(_Supabase())
    trace, _ = _v2_trace()

    with pytest.raises(ValidationPersistenceError) as exc_info:
        repository.save_traces([trace], [])

    assert exc_info.value.code == "validation_persistence_error"


def test_trace_and_decision_outcome_mismatch_fails_before_write():
    supabase = _Supabase()
    supabase.records["candidate_findings"] = [{"candidate_id": "cand-test"}]
    trace, decision = _v2_trace(decision="validated")
    mismatched = decision.model_copy(update={"decision": "inconclusive"})

    with pytest.raises(ValidationPersistenceError) as exc_info:
        DetectionValidationRepository(supabase).save_trace(trace, mismatched)

    assert exc_info.value.code == "validation_persistence_error"
    assert "validation_runs" not in supabase.records


def test_integrity_migration_guards_candidate_promotion():
    sql = Path("migrations/024_candidate_validation_integrity.sql").read_text()

    assert "candidate_validated_requires_validation" in sql
    assert "validation_checks" in sql
    assert "vc.passed = true" in sql
    assert "vc.passed = false" in sql
    assert "create constraint trigger candidate_validation_integrity" in sql
    assert "create constraint trigger validation_run_integrity" in sql

import json
from pathlib import Path

from core.evaluation_contract import content_digest
from core.production_contract import (
    CutoverDecisionV1, OperatorIncidentV1, RecoveryVerificationV1,
    SLOSnapshotV1, SoakRunV1,
)
from core.stage19_benchmark import (
    STAGE19_SUITE_ID, Stage19BenchmarkEngine, load_stage19_suite,
    run_stage19_model_shadow_trial,
)


def test_stage19_matrix_is_96_and_manifest_is_versioned():
    suite, scenarios, matrix = load_stage19_suite()
    assert suite.suite_id == STAGE19_SUITE_ID
    assert suite.version == "1.0"
    assert len(scenarios) == 96
    assert matrix.required_count == 96
    assert matrix.fixture_digest
    assert suite.manifest_digest == content_digest([case.model_dump(mode="json") for case in suite.cases])


def test_stage19_gate_and_terminal_outcomes_are_deterministic():
    engine = Stage19BenchmarkEngine()
    suite, _, _ = load_stage19_suite()
    first = engine.run_suite(suite, seed=19, trial_number=1, trial_count=3)
    second = engine.run_suite(suite, seed=19, trial_number=2, trial_count=3)
    assert first[0].status == "succeeded"
    assert first[3].decision == "ready"
    assert all(check.passed for check in first[3].hard_gates)
    digest_one = content_digest([(case.case_id, case.actual_outcome) for case in first[1]])
    digest_two = content_digest([(case.case_id, case.actual_outcome) for case in second[1]])
    assert digest_one == digest_two
    by_variant = {}
    for case in first[1]:
        variant = case.case_id.rsplit(":", 1)[-1]
        by_variant.setdefault(variant, set()).add(case.actual_outcome)
    assert by_variant["gold_positive"] == {"succeeded"}
    assert by_variant["gold_negative"] == {"disproven"}
    assert by_variant["duplicate_delivery"] == {"succeeded"}
    assert by_variant["stale_worker"] == {"blocked"}
    assert by_variant["approval_blocked"] == {"blocked"}
    assert by_variant["recovery_required"] == {"recovery_required"}
    assert by_variant["cleanup_failure"] == {"failed"}


def test_stage19_model_trial_is_diagnostic_and_cannot_validate():
    _, scenarios, _ = load_stage19_suite()
    trial, actions = run_stage19_model_shadow_trial("run", scenarios[0], trial_number=1, trial_count=3)
    assert trial.mode == "hybrid"
    assert all(action.action in {"observe", "hypothesize", "run_read_only", "request_approval", "stop"} for action in actions)
    assert all(action.valid for action in actions)
    assert not any("validated" in action.model_dump(mode="json") for action in actions)


def test_stage19_contracts_redact_free_text_and_are_serializable():
    soak = SoakRunV1(metadata={"token": "Bearer abcdefghijklmnopqrstuvwxyz123456"})
    incident = OperatorIncidentV1(category="worker", summary="Bearer abcdefghijklmnopqrstuvwxyz123456 appeared")
    cutover = CutoverDecisionV1(readiness_run_id="run", reviewer_id="operator", reason="Bearer abcdefghijklmnopqrstuvwxyz123456")
    verification = RecoveryVerificationV1(job_id="job", reason="Bearer abcdefghijklmnopqrstuvwxyz123456")
    slo = SLOSnapshotV1(thresholds={"credential": 1.0})
    rendered = json.dumps([item.model_dump(mode="json") for item in [soak, incident, cutover, verification, slo]])
    assert "Bearer abcdefghijklmnopqrstuvwxyz123456" not in rendered


def test_migration_is_additive_and_append_only():
    sql = Path("migrations/019_production_autonomy_control.sql").read_text()
    assert "alter table if exists production_readiness_runs" in sql
    for table in ("production_soak_runs", "production_soak_samples", "production_slo_snapshots", "production_cutover_decisions", "recovery_verifications", "operator_incidents"):
        assert f"create table if not exists {table}" in sql
        assert f"{table}_append_only" in sql
    follow_up = Path("migrations/020_soak_lifecycle_events.sql").read_text()
    assert "create table if not exists production_soak_events" in follow_up
    assert "production_soak_events_append_only" in follow_up
    assert "drop table" not in sql.lower() and "drop table" not in follow_up.lower()


def test_worker_strict_path_has_preflight_and_fenced_transition():
    source = Path("worker.py").read_text()
    assert "strict_startup_preflight" in source
    assert 'claim_execution_job' in source
    assert "fenced lease rejected terminal transition" in source
    assert "self.repository.transition" in source

import threading

import pytest

from core.execution_contract import ExecutionJobV1, RaceExperimentV1, ResourceBudgetV1
from core.race_engine import DeterministicRaceEngine, RaceExperimentError
from core.sandbox_runner import CommandDefinition, SandboxViolation, SandboxedCommandRunner
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1
from core.validation_engine import ValidationEngine


def test_execution_job_redacts_payload_and_freezes_budget_shape():
    job = ExecutionJobV1(session_id="session-1", target="https://example.test", payload_redacted={"username": "alice", "password": "super-secret"}, budget=ResourceBudgetV1(max_requests=3, race_concurrency=8))
    dumped = str(job.model_dump(mode="json"))
    assert "super-secret" not in dumped
    assert job.budget.max_requests == 3
    assert job.budget.race_concurrency == 8


def test_sandbox_rejects_unknown_commands_and_nul_arguments():
    runner = SandboxedCommandRunner({"safe": CommandDefinition("safe", "definitely-not-installed")})
    with pytest.raises(SandboxViolation):
        runner.run("unknown")
    with pytest.raises(SandboxViolation):
        runner.run("safe", ["bad\x00arg"])


def test_race_engine_requires_exact_approval_and_cleanup():
    experiment = RaceExperimentV1(session_id="session-1", target="https://example.test/order", method="POST", mutation_digest="mutation-v1", cleanup_refs=["cleanup-order"], baseline_samples=1, control_samples=1)
    engine = DeterministicRaceEngine(max_concurrency=8, schedule=(2, 4, 8))
    with pytest.raises(RaceExperimentError):
        engine.run(experiment, approved_digest="wrong", baseline_fn=lambda _: {"effect_key": "baseline"}, control_fn=lambda _: {"effect_key": "control"}, mutation_fn=lambda _, barrier: {"effect_key": "test"}, reproduction_fn=lambda _: {"effect_key": "repro"}, cleanup_fn=lambda: True)


def test_race_engine_uses_server_side_effects_not_response_shape():
    experiment = RaceExperimentV1(session_id="session-1", target="https://example.test/order", method="POST", mutation_digest="mutation-v1", cleanup_refs=["cleanup-order"], baseline_samples=1, control_samples=1)
    engine = DeterministicRaceEngine(max_concurrency=8, schedule=(2, 4, 8))
    state = {"lock": threading.Lock(), "test_count": 0}
    def mutation(_, barrier):
        barrier.wait(timeout=2)
        with state["lock"]:
            state["test_count"] += 1
            return {"status_code": 200, "response_fingerprint": "same", "effect_key": f"effect-{state["test_count"]}"}
    result = engine.run(experiment, approved_digest=engine.approval_digest(experiment), baseline_fn=lambda _: {"status_code": 200, "response_fingerprint": "same", "effect_key": "one"}, control_fn=lambda _: {"status_code": 200, "response_fingerprint": "same", "effect_key": "one"}, mutation_fn=mutation, reproduction_fn=lambda _: {"effect_key": "reproduced"}, cleanup_fn=lambda: True)
    assert result.decision == "violated"
    assert result.candidate and result.candidate["vuln_type"] == "race_condition"


def test_race_validation_requires_all_mandatory_roles():
    observations = [ObservationV1(role="baseline", summary="baseline"), ObservationV1(role="negative_control", summary="control"), ObservationV1(role="test", summary="test"), ObservationV1(role="reproduction", summary="repro")]
    candidate = CandidateFindingV1(title="race", vuln_type="race_condition", metadata={"synchronized": True, "effect_violation": True, "cleanup_verified": True})
    decision = ValidationEngine().validate(ToolResultV1(tool_name="race", observations=observations, candidate_findings=[candidate]))[0]
    assert decision.policy_id == "race_condition.v1"
    assert decision.decision == "validated"


def test_race_validation_does_not_promote_without_control_or_reproduction():
    result = ToolResultV1(tool_name="race", observations=[ObservationV1(role="test", summary="test")], candidate_findings=[CandidateFindingV1(title="race", vuln_type="race_condition", metadata={"synchronized": True, "effect_violation": True})])
    assert ValidationEngine().validate(result)[0].decision == "inconclusive"

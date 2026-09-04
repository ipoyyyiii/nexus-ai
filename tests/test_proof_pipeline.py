from core.proof_pipeline import proof_pipeline
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1


def _idor_result(prefix: str, *, fixed: bool = False) -> ToolResultV1:
    target = "https://lab.test/items/opaque"
    observations = [
        ObservationV1(
            observation_id=f"{prefix}-baseline",
            role="baseline",
            target_url=target,
            metadata={"identity_id": "owner", "resource_fingerprint": "resource-1", "resource_semantically_present": True},
        ),
        ObservationV1(
            observation_id=f"{prefix}-test",
            role="test",
            target_url=target,
            metadata={
                "identity_id": "other",
                "resource_fingerprint": "resource-1",
                "resource_semantically_present": True,
                "semantic_result": "deny" if fixed else "unexpected_allow",
            },
        ),
        ObservationV1(
            observation_id=f"{prefix}-control",
            role="negative_control",
            target_url=target,
            metadata={
                "identity_id": "control",
                "resource_fingerprint": "resource-1",
                "resource_semantically_present": True,
                "semantic_result": "deny",
            },
        ),
        ObservationV1(
            observation_id=f"{prefix}-reproduction",
            role="reproduction",
            target_url=target,
            metadata={
                "identity_id": "other",
                "resource_fingerprint": "resource-1",
                "resource_semantically_present": True,
                "semantic_result": "deny" if fixed else "unexpected_allow",
            },
        ),
    ]
    candidate = CandidateFindingV1(
        candidate_id=f"candidate-{prefix}",
        title="BOLA candidate",
        vuln_type="BOLA/IDOR",
        target_url=target,
        observation_ids=[item.observation_id for item in observations],
        metadata={
            "unexpected_allow": not fixed,
            "expected_safe": fixed,
            "deny_expectation": True,
            "semantic_comparison": True,
        },
    )
    return ToolResultV1(
        tool_run_id=f"run-{prefix}",
        tool_name="authorization_replay",
        category="access_control",
        target=target,
        observations=observations,
        candidate_findings=[candidate],
    )


def test_proof_pipeline_exposes_complete_idor_proof_and_retest_readiness():
    result = _idor_result("original")
    decisions, proofs = proof_pipeline.evaluate(result, mode="strict", apply_status=True)

    assert decisions[0].decision == "validated"
    assert proofs[0].evidence_complete is True
    assert proofs[0].retest_ready is True
    assert set(proofs[0].required_roles) == {"baseline", "test", "negative_control", "reproduction"}
    assert proofs[0].gaps == []


def test_retest_requires_fresh_observations_and_classifies_a_fixed_finding():
    original = _idor_result("original")
    retest = _idor_result("retest", fixed=True)
    comparison = proof_pipeline.compare_retest(original, retest)

    assert comparison.status == "fixed"
    assert comparison.original_decision == "validated"
    assert comparison.retest_decision == "disproven"
    assert comparison.fresh_observations is True
    assert comparison.gaps == []


def test_retest_rejects_reused_observations_as_inconclusive():
    original = _idor_result("original")
    retest = _idor_result("retest", fixed=True)
    retest.tool_run_id = "run-retest"
    for item, source in zip(retest.observations, original.observations):
        item.observation_id = source.observation_id
    retest.candidate_findings[0].observation_ids = [item.observation_id for item in retest.observations]

    comparison = proof_pipeline.compare_retest(original, retest)

    assert comparison.status == "inconclusive"
    assert comparison.fresh_observations is False
    assert any(gate.gate_id == "fresh_observations" and not gate.passed for gate in comparison.gates)


def test_oob_proof_reports_attribution_state():
    target = "https://lab.test/fetch"
    observations = [
        ObservationV1(observation_id="oob-test", role="test", target_url=target),
        ObservationV1(
            observation_id="oob-callback",
            role="oob",
            target_url=target,
            metadata={"correlation_id": "corr-1", "target_attributed": True},
        ),
        ObservationV1(observation_id="oob-control", role="negative_control", target_url=target),
        ObservationV1(observation_id="oob-repro", role="reproduction", target_url=target),
    ]
    result = ToolResultV1(
        tool_run_id="run-oob",
        tool_name="ssrf_tester",
        category="oob",
        target=target,
        observations=observations,
        candidate_findings=[CandidateFindingV1(
            title="SSRF candidate",
            vuln_type="SSRF",
            target_url=target,
            observation_ids=[item.observation_id for item in observations],
            metadata={"correlation_id": "corr-1", "target_attributed": True},
        )],
    )

    _decisions, proofs = proof_pipeline.evaluate(result, mode="shadow", apply_status=False)
    assert proofs[0].oob_status == "correlated"

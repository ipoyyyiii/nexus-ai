"""Runtime proof and retest evaluation for structured findings.

The execution tools produce observations and candidates; this module turns
the validator output into an auditable proof envelope.  It deliberately does
not infer a vulnerability from HTTP status, response length, or model text.
Every gate points back to a candidate observation or a deterministic V2
validation check.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from core.detection_validation_v2 import (
    ValidationDecisionV2,
    validation_engine_v2,
)
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1


ProofDecision = Literal["validated", "disproven", "inconclusive"]
OobStatus = Literal["not_applicable", "correlated", "missing", "stale", "ambiguous"]
RetestStatus = Literal["fixed", "still_vulnerable", "inconclusive"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProofGateV1(BaseModel):
    model_config = ConfigDict(extra="ignore")

    gate_id: str
    required: bool = True
    passed: bool = False
    reason: str = ""
    observation_ids: List[str] = Field(default_factory=list)


class ProofEvaluationV1(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: Literal["1.0"] = "1.0"
    proof_id: str = Field(default_factory=lambda: f"proof_{uuid.uuid4().hex}")
    tool_run_id: str
    candidate_id: str
    fingerprint: str
    policy_id: str
    policy_version: str
    decision: ProofDecision
    validation_run_id: str
    validation_score: float = 0.0
    evidence_ids: List[str] = Field(default_factory=list)
    required_roles: List[str] = Field(default_factory=list)
    observed_roles: List[str] = Field(default_factory=list)
    evidence_complete: bool = False
    oob_status: OobStatus = "not_applicable"
    retest_ready: bool = False
    gates: List[ProofGateV1] = Field(default_factory=list)
    gaps: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=_now)


class RetestComparisonV1(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: Literal["1.0"] = "1.0"
    comparison_id: str = Field(default_factory=lambda: f"retestcmp_{uuid.uuid4().hex}")
    fingerprint: str = ""
    original_candidate_id: str = ""
    retest_candidate_id: str = ""
    original_decision: ProofDecision = "inconclusive"
    retest_decision: ProofDecision = "inconclusive"
    status: RetestStatus = "inconclusive"
    original_evidence_ids: List[str] = Field(default_factory=list)
    retest_evidence_ids: List[str] = Field(default_factory=list)
    fresh_observations: bool = False
    gates: List[ProofGateV1] = Field(default_factory=list)
    gaps: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=_now)


class ProofPipeline:
    """Evaluate structured candidates and compare fresh retest results."""

    def __init__(self, validator=validation_engine_v2):
        self.validator = validator

    def evaluate(
        self,
        result: ToolResultV1,
        *,
        mode: str = "autonomous",
        apply_status: Optional[bool] = None,
    ) -> Tuple[List[ValidationDecisionV2], List[ProofEvaluationV1]]:
        effective_mode = "autonomous"
        decisions = self.validator.validate(
            result,
            mode=effective_mode,
            apply_status=True if apply_status is None else apply_status,
        )
        return decisions, self.summarize(result, decisions)

    def summarize(
        self,
        result: ToolResultV1,
        decisions: Iterable[ValidationDecisionV2],
    ) -> List[ProofEvaluationV1]:
        by_id = {item.candidate_id: item for item in decisions}
        observations = {item.observation_id: item for item in result.observations}
        evaluations: List[ProofEvaluationV1] = []
        for candidate in result.candidate_findings:
            decision = by_id.get(candidate.candidate_id)
            if decision is None:
                evaluations.append(
                    ProofEvaluationV1(
                        tool_run_id=result.tool_run_id,
                        candidate_id=candidate.candidate_id,
                        fingerprint=candidate.fingerprint,
                        policy_id="missing",
                        policy_version="2.0",
                        decision="inconclusive",
                        validation_run_id="",
                        evidence_ids=list(candidate.observation_ids),
                        gaps=["Validator returned no decision for candidate."],
                    )
                )
                continue
            evaluations.append(self._summarize_candidate(result, candidate, decision, observations))
        return evaluations

    def _summarize_candidate(
        self,
        result: ToolResultV1,
        candidate: CandidateFindingV1,
        decision: ValidationDecisionV2,
        observations: Dict[str, ObservationV1],
    ) -> ProofEvaluationV1:
        linked = [observations[item] for item in candidate.observation_ids if item in observations]
        policy = self.validator.registry.get(decision.policy_id)
        required_roles = list(policy.mandatory_observation_roles) if policy else []
        observed_roles = sorted({item.role for item in linked})
        gates: List[ProofGateV1] = []

        linked_ok = bool(candidate.observation_ids) and len(linked) == len(set(candidate.observation_ids))
        gates.append(ProofGateV1(
            gate_id="evidence_links_complete",
            passed=linked_ok,
            reason="Every candidate observation ID resolves to an observation." if linked_ok else "Candidate references missing or duplicate observations.",
            observation_ids=[item.observation_id for item in linked],
        ))
        for role in required_roles:
            matching = [item.observation_id for item in linked if item.role == role]
            gates.append(ProofGateV1(
                gate_id=f"role_{role}",
                passed=bool(matching),
                reason=f"Required role '{role}' is present." if matching else f"Required role '{role}' is missing.",
                observation_ids=matching,
            ))
        for check in decision.checks:
            gates.append(ProofGateV1(
                gate_id=f"validator_{check.check_id}",
                required=check.required,
                passed=check.passed,
                reason=check.reason,
                observation_ids=list(check.observation_ids),
            ))

        oob_status = self._oob_status(decision.policy_id, linked, candidate.metadata)
        if oob_status != "not_applicable":
            gates.append(ProofGateV1(
                gate_id="oob_correlation",
                passed=oob_status == "correlated",
                reason={
                    "correlated": "Fresh, attributed OOB correlation is present.",
                    "missing": "No usable OOB correlation was linked.",
                    "stale": "Only stale OOB callbacks were observed.",
                    "ambiguous": "Multiple correlation IDs prevent unique attribution.",
                }.get(oob_status, "OOB correlation is not complete."),
                observation_ids=[item.observation_id for item in linked if item.role == "oob"],
            ))

        required_checks_pass = all(item.passed for item in decision.checks if item.required)
        evidence_complete = bool(
            linked_ok
            and required_checks_pass
            and decision.decision in {"validated", "disproven"}
            and all(role in observed_roles for role in required_roles)
        )
        retest_ready = bool(
            evidence_complete
            and decision.decision == "validated"
            and candidate.fingerprint
        )
        gaps = [item.reason for item in gates if item.required and not item.passed and item.reason]
        return ProofEvaluationV1(
            tool_run_id=result.tool_run_id,
            candidate_id=candidate.candidate_id,
            fingerprint=candidate.fingerprint,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            decision=decision.decision,
            validation_run_id=decision.validation_run_id,
            validation_score=decision.score,
            evidence_ids=list(dict.fromkeys(item.observation_id for item in linked)),
            required_roles=required_roles,
            observed_roles=observed_roles,
            evidence_complete=evidence_complete,
            oob_status=oob_status,
            retest_ready=retest_ready,
            gates=gates,
            gaps=gaps,
        )

    @staticmethod
    def _oob_status(
        policy_id: str,
        observations: Iterable[ObservationV1],
        metadata: Dict[str, Any],
    ) -> OobStatus:
        if policy_id != "ssrf.xxe_oob.v2":
            return "not_applicable"
        oob = [item for item in observations if item.role == "oob"]
        correlation_ids = {
            str(item.metadata.get("correlation_id") or item.metadata.get("oob_correlation_id"))
            for item in oob
            if item.metadata.get("correlation_id") or item.metadata.get("oob_correlation_id")
        }
        correlation = str(metadata.get("correlation_id") or "")
        correlation_ids.update({correlation} if correlation else set())
        if any(bool(item.metadata.get("stale_callback")) for item in oob) or metadata.get("stale_callback"):
            return "stale"
        if len(correlation_ids) > 1:
            return "ambiguous"
        attributed = bool(metadata.get("target_attributed")) or any(
            bool(item.metadata.get("target_attributed")) for item in oob
        )
        return "correlated" if len(correlation_ids) == 1 and attributed else "missing"

    def compare_retest(
        self,
        original: ToolResultV1,
        retest: ToolResultV1,
    ) -> RetestComparisonV1:
        original_decisions, original_proofs = self.evaluate(original, mode="autonomous", apply_status=False)
        retest_decisions, retest_proofs = self.evaluate(retest, mode="autonomous", apply_status=False)
        del original_decisions, retest_decisions
        original_by_fp = {item.fingerprint: (item, proof) for item, proof in zip(original.candidate_findings, original_proofs)}
        retest_by_fp = {item.fingerprint: (item, proof) for item, proof in zip(retest.candidate_findings, retest_proofs)}
        common = sorted(set(original_by_fp) & set(retest_by_fp))
        if len(common) != 1:
            return RetestComparisonV1(
                gaps=["Retest must contain exactly one candidate with the original fingerprint."],
            )
        fingerprint = common[0]
        original_candidate, original_proof = original_by_fp[fingerprint]
        retest_candidate, retest_proof = retest_by_fp[fingerprint]
        original_ids = set(original_proof.evidence_ids)
        retest_ids = set(retest_proof.evidence_ids)
        fresh = bool(retest_ids) and original_ids.isdisjoint(retest_ids)
        gates = [
            ProofGateV1(
                gate_id="fingerprint_match",
                passed=True,
                reason="Original and retest candidates share the same fingerprint.",
            ),
            ProofGateV1(
                gate_id="fresh_observations",
                passed=fresh,
                reason="Retest evidence uses observation IDs not present in the original proof." if fresh else "Retest reused original observation IDs or has no evidence.",
                observation_ids=sorted(retest_ids),
            ),
            ProofGateV1(
                gate_id="original_was_validated",
                passed=original_proof.decision == "validated",
                reason="A retest can close only a previously validated finding.",
                observation_ids=sorted(original_ids),
            ),
            ProofGateV1(
                gate_id="retest_proof_complete",
                passed=retest_proof.evidence_complete,
                reason="The fresh retest has complete deterministic proof." if retest_proof.evidence_complete else "The fresh retest is incomplete or inconclusive.",
                observation_ids=sorted(retest_ids),
            ),
        ]
        if not fresh or original_proof.decision != "validated":
            status: RetestStatus = "inconclusive"
        elif retest_proof.decision == "disproven" and retest_proof.evidence_complete:
            status = "fixed"
        elif retest_proof.decision == "validated":
            status = "still_vulnerable"
        else:
            status = "inconclusive"
        gaps = [item.reason for item in gates if item.required and not item.passed]
        return RetestComparisonV1(
            fingerprint=fingerprint,
            original_candidate_id=original_candidate.candidate_id,
            retest_candidate_id=retest_candidate.candidate_id,
            original_decision=original_proof.decision,
            retest_decision=retest_proof.decision,
            status=status,
            original_evidence_ids=sorted(original_ids),
            retest_evidence_ids=sorted(retest_ids),
            fresh_observations=fresh,
            gates=gates,
            gaps=gaps,
        )


proof_pipeline = ProofPipeline()


__all__ = [
    "ProofGateV1", "ProofEvaluationV1", "RetestComparisonV1",
    "ProofPipeline", "proof_pipeline",
]

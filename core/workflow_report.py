"""Evidence-linked workflow report generation."""

import hashlib
import json
from typing import Any, Dict

from core.evidence_service import redact
from core.session_store import SessionStore
from core.structured_contract import ReportClaimV1, ReportNarrativeV1
from core.detection_validation_repository import DetectionValidationRepository
from core.structured_repository import StructuredRepository


def _deterministic_claim_id(report_id: str, source_kind: str, source_id: str) -> str:
    """Return the stable identity for one logical report claim.

    ``report_claims.claim_id`` is the append-only repository's conflict key.
    The report generator must therefore derive it from the logical source,
    rather than allowing ``ReportClaimV1``'s UUID default to create a new row
    on every generation of the same report.
    """
    identity = json.dumps(
        {
            "report_id": str(report_id),
            "source_kind": str(source_kind),
            "source_id": str(source_id),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"claim_{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:32]}"


def calculate_report_quality(
    claims: list[ReportClaimV1],
    validated_candidates: list[Dict[str, Any]],
    *,
    redaction_leaks: int = 0,
) -> Dict[str, Any]:
    """Return review gates for a report without judging vulnerability truth.

    A report can be well-grounded while containing zero findings. The score
    measures provenance and completeness only; the deterministic validator is
    still the authority for finding status.
    """
    claim_count = len(claims)
    grounded_claims = sum(1 for item in claims if item.grounded and item.evidence_ids)
    candidate_count = len(validated_candidates)
    candidate_with_evidence = sum(
        1 for item in validated_candidates
        if bool((item.get("metadata") or {}).get("evidence_ids") or item.get("observation_ids"))
    )
    # An empty report is not evidence that the target is clean. The previous
    # vacuous 1.0 defaults hid a coverage failure during live-lab evaluation.
    claim_grounding_rate = grounded_claims / claim_count if claim_count else 0.0
    validated_evidence_rate = candidate_with_evidence / candidate_count if candidate_count else 0.0
    redaction_gate = redaction_leaks == 0
    grounding_gate = claim_grounding_rate == 1.0
    evidence_gate = validated_evidence_rate == 1.0
    score = round((claim_grounding_rate + validated_evidence_rate + float(redaction_gate)) / 3, 4)
    return {
        "schema_version": "1.0",
        "status": "ready" if claim_count > 0 and candidate_count > 0 and redaction_gate and grounding_gate and evidence_gate else "review_required",
        "quality_score": score,
        "claim_count": claim_count,
        "grounded_claim_count": grounded_claims,
        "validated_candidate_count": candidate_count,
        "validated_candidate_evidence_count": candidate_with_evidence,
        "claim_grounding_rate": round(claim_grounding_rate, 4),
        "validated_evidence_rate": round(validated_evidence_rate, 4),
        "redaction_leaks": int(redaction_leaks),
        "gates": {
            "all_claims_grounded": grounding_gate,
            "all_validated_candidates_have_evidence": evidence_gate,
            "redaction_clean": redaction_gate,
            "structured_claims_recorded": claim_count > 0,
            "validated_candidates_recorded": candidate_count > 0,
        },
    }


class WorkflowReport:
    def __init__(self, sessions: SessionStore):
        self.sessions = sessions

    def generate(self, session_id: str) -> Dict[str, Any]:
        context = self.sessions.require(session_id)
        state = self.sessions.load_state(session_id)
        evidence = {item.evidence_id: item for item in state.workflow.evidence}
        structured = StructuredRepository(self.sessions)
        try:
            candidates = structured.list_candidates(session_id)
        except Exception:
            candidates = []
        validator = DetectionValidationRepository(structured.sb)
        validated_candidates = []
        for item in candidates:
            status = str(item.get("status") or "")
            evidence_ids = list(dict.fromkeys(
                (item.get("metadata") or {}).get("evidence_ids")
                or item.get("observation_ids")
                or []
            ))
            verifier = getattr(structured, "has_durable_candidate_evidence", None)
            if not evidence_ids or not callable(verifier):
                continue
            try:
                if not verifier(session_id, str(item.get("candidate_id") or ""), evidence_ids):
                    continue
            except Exception:
                continue
            if status == "validated":
                # A status flag is not proof.  Historical rows can predate the
                # integrity gate, so only a candidate with a durable
                # v2 validation trace, relational validation run, and at
                # least one durable check may enter the authoritative report.
                try:
                    if not validator.has_successful_canonical_validation(
                        str(item.get("candidate_id") or "")
                    ):
                        continue
                except Exception:
                    continue
            elif status != "validated_override":
                continue
            validated_candidates.append(item)
        legacy_validated_findings = []
        for finding in state.workflow.findings:
            if finding.status not in {"validated", "impact_proven"} or not finding.evidence_ids:
                continue
            # Legacy workflow records do not carry validation provenance
            # themselves. They are reportable only when they resolve to a
            # durable candidate/evidence graph and a canonical v2 validation.
            candidate_id = str(finding.source_candidate_id or finding.finding_id)
            verifier = getattr(structured, "has_durable_candidate_evidence", None)
            if not callable(verifier):
                continue
            try:
                if not verifier(session_id, candidate_id, list(dict.fromkeys(finding.evidence_ids))):
                    continue
                if not validator.has_successful_canonical_validation(candidate_id):
                    continue
            except Exception:
                continue
            legacy_validated_findings.append(finding)
        open_candidates = [item for item in candidates if item.get("status") in {"suspected", "validating", "inconclusive"}]
        lines = [
            "# Evidence-Linked Security Workflow Report",
            "",
            f"**Target:** {context['target_url']}",
            f"**Objective:** {context['attack_goal']}",
            f"**Workflow phase:** {state.workflow.phase}",
            "",
            "## Objectives",
        ]
        for objective in state.workflow.objectives:
            lines.append(f"- [{objective.status}] {objective.description} ({objective.progress}%)")
        if not state.workflow.objectives:
            lines.append("- No structured objectives recorded.")

        lines.extend(["", "## Validated Findings"])
        for finding in validated_candidates:
            override = " (human override)" if finding.get("status") == "validated_override" else ""
            lines.append(f"### [{finding.get('severity', 'INFO')}] {redact(finding.get('title', ''), 500)}")
            lines.append(f"- Type: `{finding.get('vuln_type', 'unknown')}`")
            lines.append(f"- Status: `{finding.get('status')}`{override}")
            lines.append(f"- Fingerprint: `{finding.get('fingerprint', 'n/a')}`")
            lines.append(f"- Candidate ID: `{finding.get('candidate_id')}`")
            metadata = finding.get("metadata") or {}
            if metadata.get("replay_run_id"):
                lines.append(f"- Authorization replay: `{metadata.get('replay_run_id')}`")
            evidence_ids = metadata.get("evidence_ids") or finding.get("observation_ids") or []
            if evidence_ids:
                lines.append(f"- Evidence IDs: {', '.join(evidence_ids)}")
        if not validated_candidates:
            lines.append("- No validated findings recorded.")

        lines.extend(["", "## Candidate Findings (not included in severity summary)"])
        for finding in open_candidates:
            lines.append(f"- [{finding.get('status')}] {redact(finding.get('title', ''), 500)} ({finding.get('vuln_type', 'unknown')})")
        if not open_candidates:
            lines.append("- No open candidates recorded.")

        # Legacy workflow findings are shown only if their durable candidate,
        # evidence links, and canonical validation all exist; phase narrative
        # text can never create report findings.
        for finding in legacy_validated_findings:
            lines.append(f"### [{finding.severity}] {finding.title}")
            lines.append(f"- Type: `{finding.vuln_type}`")
            lines.append(f"- Status: `{finding.status}`")
            lines.append(f"- Fingerprint: `{finding.fingerprint or 'n/a'}`")
            lines.append(f"- Evidence IDs: {', '.join(finding.evidence_ids) or 'none'}")
            for evidence_id in finding.evidence_ids:
                item = evidence.get(evidence_id)
                if item:
                    lines.append(f"  - `{evidence_id}` {redact(item.summary, 500)}")

        lines.extend(["", "## Chains"])
        for chain in state.workflow.chains:
            lines.append(f"- [{chain.status}] {chain.name}: step {chain.current_step}/{len(chain.step_ids)}")
            lines.append(f"  - Chain ID: `{chain.chain_id}` version `{getattr(chain, 'chain_version', 1)}`")
            lines.append(f"  - Validation: `{getattr(chain, 'validation_status', 'inconclusive')}` ({getattr(chain, 'validation_source', 'machine')})")
            lines.append(f"  - Graph digest: `{getattr(chain, 'graph_digest', '') or 'n/a'}`")
            lines.append(f"  - Prerequisites: {', '.join(getattr(chain, 'prerequisite_ids', []) or chain.step_ids) or 'none'}")
            lines.append(f"  - Evidence IDs: {', '.join(getattr(chain, 'evidence_ids', [])) or 'none'}")
        if not state.workflow.chains:
            lines.append("- No chains recorded.")

        lines.extend(["", "## Cleanup"])
        for item in state.workflow.cleanup:
            lines.append(f"- [{item.status}] {item.description}: {redact(item.result, 500)}")
        if not state.workflow.cleanup:
            lines.append("- No cleanup items recorded.")

        lines.extend(["", "## Retests"])
        for retest in state.workflow.retests:
            lines.append(f"- [{retest.status}] Finding `{retest.finding_id}`: {redact(retest.comparison, 500)}")
        if not state.workflow.retests:
            lines.append("- No retests recorded.")

        report_seed = {
            "session_id": session_id,
            "claims": [
                {
                    "candidate_id": item.get("candidate_id"),
                    "status": item.get("status"),
                    "evidence_ids": (item.get("metadata") or {}).get("evidence_ids") or item.get("observation_ids") or [],
                }
                for item in validated_candidates
            ],
            "legacy_findings": [
                {"finding_id": item.finding_id, "status": item.status, "evidence_ids": list(item.evidence_ids)}
                for item in legacy_validated_findings
            ],
        }
        report_id = f"report_{hashlib.sha256(json.dumps(report_seed, sort_keys=True).encode()).hexdigest()[:32]}"
        claims = []
        for finding in validated_candidates:
            metadata = finding.get("metadata") or {}
            evidence_ids = list(dict.fromkeys(metadata.get("evidence_ids") or finding.get("observation_ids") or []))
            override = finding.get("status") == "validated_override"
            claims.append(ReportClaimV1(
                claim_id=_deterministic_claim_id(
                    report_id,
                    "candidate",
                    str(finding.get("candidate_id") or finding.get("fingerprint") or ""),
                ),
                report_id=report_id, claim_type="finding",
                text=f"{redact(finding.get('title', 'Finding'), 500)} ({redact(finding.get('vuln_type', 'unknown'), 200)}) is {finding.get('status')}.",
                source_candidate_ids=[str(finding.get("candidate_id", ""))], evidence_ids=evidence_ids,
                policy_versions={"validator": str(metadata.get("validator_version", "")), "policy": str(metadata.get("policy_version", ""))},
                validated=True, override=override, grounded=bool(evidence_ids),
            ))
        for finding in legacy_validated_findings:
            claims.append(ReportClaimV1(
                claim_id=_deterministic_claim_id(
                    report_id,
                    "legacy_finding",
                    finding.finding_id,
                ),
                report_id=report_id, claim_type="finding",
                text=f"{redact(finding.title, 500)} ({redact(finding.vuln_type, 200)}) is {finding.status}.",
                source_candidate_ids=[finding.source_candidate_id] if finding.source_candidate_id else [],
                evidence_ids=list(dict.fromkeys(finding.evidence_ids)),
                validated=True, override=finding.validation_source == "human_override", grounded=True,
            ))
        grounded = all(item.grounded for item in claims)
        report_quality = calculate_report_quality(
            claims, validated_candidates, redaction_leaks=0,
        )
        lines.extend([
            "",
            "## Report Quality Gates",
            f"- Status: `{report_quality['status']}`",
            f"- Quality score: `{report_quality['quality_score']}`",
            f"- Claim grounding rate: `{report_quality['claim_grounding_rate']}`",
            f"- Validated candidate evidence rate: `{report_quality['validated_evidence_rate']}`",
            "- Redaction gate: `passed`" if report_quality["gates"]["redaction_clean"] else "- Redaction gate: `failed`",
        ])
        markdown = "\n".join(lines)
        source_digest = hashlib.sha256(json.dumps([item.model_dump(mode="json") for item in claims], sort_keys=True).encode()).hexdigest()
        narrative = ReportNarrativeV1(
            report_id=report_id, session_id=session_id, target=context["target_url"], objective=context["attack_goal"],
            status="ready" if report_quality["status"] == "ready" else "blocked",
            finding_ids=list(dict.fromkeys([item for claim in claims for item in claim.source_candidate_ids] + [item.finding_id for item in legacy_validated_findings])),
            claim_ids=[item.claim_id for item in claims], markdown=markdown,
            grounding_complete=grounded, redaction_leaks=0, source_digest=source_digest,
        )
        return {
            "session_id": session_id, "markdown": markdown, "workflow": state.workflow.to_dict(),
            "narrative": narrative.model_dump(mode="json"), "claims": [item.model_dump(mode="json") for item in claims],
            "grounding_complete": grounded, "redaction_leaks": 0,
            "report_quality": report_quality,
        }

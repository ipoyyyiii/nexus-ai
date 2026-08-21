"""Evidence-linked workflow report generation."""

from typing import Any, Dict

from core.evidence_service import redact
from core.session_store import SessionStore
from core.structured_repository import StructuredRepository


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
        validated_candidates = [item for item in candidates if item.get("status") in {"validated", "validated_override"}]
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

        # Legacy workflow findings are shown only if they were explicitly
        # validated; phase narrative text can never create report findings.
        for finding in state.workflow.findings:
            if finding.status not in {"validated", "impact_proven"}:
                continue
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

        return {"session_id": session_id, "markdown": "\n".join(lines), "workflow": state.workflow.to_dict()}

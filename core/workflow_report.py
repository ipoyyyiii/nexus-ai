"""Evidence-linked workflow report generation."""

from typing import Any, Dict

from core.evidence_service import redact
from core.session_store import SessionStore


class WorkflowReport:
    def __init__(self, sessions: SessionStore):
        self.sessions = sessions

    def generate(self, session_id: str) -> Dict[str, Any]:
        context = self.sessions.require(session_id)
        state = self.sessions.load_state(session_id)
        evidence = {item.evidence_id: item for item in state.workflow.evidence}
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

        lines.extend(["", "## Findings"])
        for finding in state.workflow.findings:
            lines.append(f"### [{finding.severity}] {finding.title}")
            lines.append(f"- Type: `{finding.vuln_type}`")
            lines.append(f"- Status: `{finding.status}`")
            lines.append(f"- Fingerprint: `{finding.fingerprint or 'n/a'}`")
            lines.append(f"- Evidence IDs: {', '.join(finding.evidence_ids) or 'none'}")
            for evidence_id in finding.evidence_ids:
                item = evidence.get(evidence_id)
                if item:
                    lines.append(f"  - `{evidence_id}` {redact(item.summary, 500)}")
        if not state.workflow.findings:
            lines.append("- No structured findings recorded.")

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

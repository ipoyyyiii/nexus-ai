"""Approval-gated, bounded impact-proof planning for attack chains."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from urllib.parse import urlparse

from core.chain_planner import ChainPlanner
from core.config_loader import get_config, get_setting
from core.redact import redact
from core.session_store import SessionStore
from core.structured_contract import PayloadProposalV1
from core.workflow_models import ActionProposal, ImpactProofPlan, RecordStatus


class ImpactService:
    def __init__(self, sessions: SessionStore, chains: ChainPlanner):
        self.sessions = sessions
        self.chains = chains

    @staticmethod
    def _digest(value: Any) -> str:
        return hashlib.sha256(json.dumps(redact(value), sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()

    def _chain(self, session_id: str, objective: str = "") -> Dict[str, Any]:
        graph = self.chains.build_graph(session_id, objective)
        if graph.get("status") == "blocked":
            raise ValueError(graph.get("reason", "Chain is blocked."))
        chain = graph["chain"]
        if not self.chains.validate_prerequisites(session_id, list(chain.get("prerequisite_ids", []))):
            raise ValueError("Every chain prerequisite must be validated and evidence-linked.")
        return graph

    @staticmethod
    def _origin(value: str) -> str:
        parsed = urlparse(value or "")
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}" if parsed.scheme and parsed.netloc else ""

    def execution_policy(self, *, risk: str, side_effect: str, approved: bool = False) -> Dict[str, Any]:
        """Return the machine-enforced policy for exploration/dispatch.

        This is deliberately separate from the model's proposal. A model may
        suggest a payload or chain, but this decision is derived only from
        YAML policy and the action risk class.
        """
        exploration_mode = str(get_setting("exploration_mode", "assisted"))
        exploration = get_config().get("exploration", {})
        known_modes = {"assisted", "autonomous"}
        if exploration_mode not in known_modes:
            return {
                "allowed": False, "requires_approval": True,
                "reason": "Unknown exploration mode; fail closed.",
                "exploration_mode": exploration_mode,
            }
        mutation = side_effect in {"mutation", "credential", "upload", "raw_network"} or risk in {"high", "high_risk", "mutation"}
        requires_approval = mutation or bool(exploration.get("mutation_requires_approval", True)) and side_effect != "read"
        read_only_auto = side_effect == "read" and bool(exploration.get("read_only_auto_run", True))
        return {
            "allowed": bool(read_only_auto or not mutation),
            "requires_approval": requires_approval,
            "dispatch_allowed": bool(not mutation or (requires_approval and approved)),
            "approval_present": bool(approved),
            "reason": "Read-only exploration is eligible for automatic planning." if read_only_auto else "Mutation/high-risk action requires exact approval and cleanup.",
            "exploration_mode": exploration_mode,
            "assessment_mode": "autonomous",
        }

    def build_payload_proposal(self, session_id: str, *, target_url: str, input_ref: str, family: str,
                               risk: str = "harmless", redacted_excerpt: str = "",
                               encoding_variants: list[str] | None = None, expected_signal: str = "",
                               evidence_ids: list[str] | None = None, cleanup_ref: str = "",
                               value_hash: str = "", parser_context: str = "unknown",
                               parameter_location: str = "", mutation_operator: str = "",
                               schema_digest: str = "", metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Create a redacted, bounded payload proposal; never dispatch it."""
        context = self.sessions.require(session_id)
        if self._origin(target_url) != self._origin(str(context.get("target_url", ""))):
            raise ValueError("Payload target origin must match the active session target.")
        if not input_ref.strip() or not family.strip():
            raise ValueError("Payload input_ref and family are required.")
        config = get_config().get("exploration", {})
        variants = [str(item)[:300] for item in (encoding_variants or [])]
        max_variants = max(1, int(config.get("max_payload_variants", 10)))
        if len(variants) > max_variants:
            raise ValueError(f"Payload variant limit exceeded ({max_variants}).")
        proposal = PayloadProposalV1(
            target_url=target_url, input_ref=input_ref, family=family, risk=risk,
            value_hash=value_hash or self._digest(redacted_excerpt),
            redacted_excerpt=redacted_excerpt, encoding_variants=variants,
            expected_signal=expected_signal, evidence_ids=list(evidence_ids or []),
            requires_approval=False, cleanup_ref=cleanup_ref,
            parser_context=parser_context, parameter_location=parameter_location,
            mutation_operator=mutation_operator, schema_digest=schema_digest,
            metadata=redact({**(metadata or {}), "exploration_mode": get_setting("exploration_mode", "autonomous"),
                             "assessment_mode": "autonomous"}),
        )
        requires_approval = proposal.requires_exact_approval()
        if requires_approval and not cleanup_ref.strip():
            raise ValueError("Mutation/high-risk payloads require a registered cleanup_ref.")
        proposal = proposal.model_copy(update={"requires_approval": requires_approval})
        return {
            "proposal": proposal.model_dump(mode="json"),
            "execution_policy": self.execution_policy(risk=risk, side_effect="mutation" if requires_approval else "read"),
        }

    def build_plan(
        self,
        session_id: str,
        objective: str = "",
        *,
        identity_id: str = "",
        auth_context_id: str = "",
        exact_steps: list[Dict[str, Any]] | None = None,
        payload_ids: list[str] | None = None,
        bindings: Dict[str, Any] | None = None,
        workflow_matrix_id: str = "",
        required_evidence_roles: list[str] | None = None,
        expected_effect: Dict[str, Any] | None = None,
        state_fingerprint: str = "",
    ) -> Dict[str, Any]:
        context = self.sessions.require(session_id)
        graph = self._chain(session_id, objective)
        config = get_config()
        browser_config = config.get("browser_workflow", {})
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=int(browser_config.get("approval_ttl_minutes", 30)))).isoformat()
        safe_bindings = redact(bindings or {})
        steps = exact_steps or [{"action": "controlled_impact_proof", "target": context["target_url"], "risk": "high"}]
        plan = ImpactProofPlan(
            chain_id=graph["chain"]["chain_id"], objective=objective or context.get("attack_goal", ""),
            target_url=context["target_url"], exact_steps=redact(steps), payload_ids=list(payload_ids or []),
            identity_id=identity_id, auth_context_id=auth_context_id,
            bindings_hash=self._digest(safe_bindings),
            budget=redact({"max_requests": config.get("safety", {}).get("max_requests_per_job", 20000), "max_mutations": 1, "max_payloads": max(1, len(payload_ids or []))}),
            expires_at=expires_at, cleanup_refs=[f"cleanup:{graph['chain']['chain_id']}"],
            expected_before={"state_capture": "required"}, expected_after={"state_capture": "required"},
            chain_version=int(graph["chain"].get("chain_version", 1)),
            graph_digest=str(graph.get("graph_digest", graph["chain"].get("graph_digest", ""))),
            workflow_matrix_id=workflow_matrix_id or str(graph["chain"].get("workflow_matrix_id", "")),
            required_evidence_roles=list(required_evidence_roles or ["baseline", "negative_control", "test", "reproduction", "cleanup"]),
            expected_effect=redact(expected_effect or {"server_state": "changed", "cleanup": "verified"}),
            state_fingerprint=state_fingerprint,
        )
        plan.approval_digest = self._digest({
            "chain_id": plan.chain_id, "objective": plan.objective, "target_url": plan.target_url,
            "exact_steps": plan.exact_steps, "payload_ids": plan.payload_ids,
            "identity_id": plan.identity_id, "auth_context_id": plan.auth_context_id,
            "bindings_hash": plan.bindings_hash, "budget": plan.budget,
            "chain_version": plan.chain_version, "graph_digest": plan.graph_digest,
            "workflow_matrix_id": plan.workflow_matrix_id,
            "required_evidence_roles": plan.required_evidence_roles,
            "expected_effect": plan.expected_effect, "state_fingerprint": plan.state_fingerprint,
            "expires_at": plan.expires_at, "cleanup_refs": plan.cleanup_refs,
        })
        return {"plan": plan.__dict__, "graph": graph, "execution_policy": self.execution_policy(risk="high", side_effect="mutation")}

    def propose(self, session_id: str, objective: str = "") -> Dict[str, Any]:
        context = self.sessions.require(session_id)
        state = self.sessions.load_state(session_id)
        if any(item.status != RecordStatus.COMPLETE.value for item in state.workflow.cleanup if item.source_action_id):
            raise ValueError("Existing cleanup items must be complete before a new impact proof.")
        planned = self.build_plan(session_id, objective)
        plan = planned["plan"]
        proposal = ActionProposal(
            action="bounded_impact_proof", target_url=context["target_url"],
            rationale=f"Demonstrate only the approved objective using chain {plan['chain_id']}.",
            expected_evidence="Fresh baseline, control, before/after state, clean reproduction, and cleanup verification.",
            risk="high", requires_approval=True, cleanup_required=True,
            evidence_ids=list(planned["graph"]["chain"].get("evidence_ids", [])),
            input_bindings={"impact_plan_id": plan["plan_id"], "chain_id": plan["chain_id"], "approval_digest": plan["approval_digest"]},
            fingerprint=plan["approval_digest"],
        )
        state.workflow.add_proposal(proposal)
        state.workflow.record_event("impact_proof_proposed", action_id=proposal.action_id, chain_id=plan["chain_id"], approval_digest=plan["approval_digest"])
        self.sessions.save_state(session_id, state)
        return {"proposal": proposal.__dict__, "plan": plan, "graph": planned["graph"], "requires_registered_handler": True}

    def record_result(self, session_id: str, action_id: str, before: str, after: str, success: bool) -> Dict[str, Any]:
        state = self.sessions.load_state(session_id)
        proposal = next((item for item in state.workflow.proposals if item.action_id == action_id), None)
        if not proposal or proposal.action not in {"bounded_impact_proof", "controlled_impact_proof"}:
            raise ValueError("Bounded impact proposal not found.")
        if proposal.status != "running":
            raise ValueError("Impact proof is not running.")
        safe_before, safe_after = redact(before)[:500], redact(after)[:500]
        proposal.status = "complete" if success else "failed"
        state.workflow.record_event(
            "impact_proof_result", action_id=action_id, success=success,
            before_digest=self._digest(safe_before), after_digest=self._digest(safe_after),
            before_excerpt=safe_before, after_excerpt=safe_after,
        )
        self.sessions.save_state(session_id, state)
        return {"proposal": proposal.__dict__, "success": success, "status": proposal.status}

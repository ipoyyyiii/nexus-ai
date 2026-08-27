"""Stage 3 deterministic adaptive-planner regression tests."""

import unittest

from core.adaptive_planner import AdaptiveHypothesisPlanner, PlanningSnapshot
from core.chain_planner import ChainPlanner
from core.execution_guard import ExecutionGuard
from core.workflow_dispatch import WorkflowDispatcher
from core.target_state import EndpointInfo, TargetState


class AdaptivePlannerTests(unittest.TestCase):
    def setUp(self):
        self.context = {
            "target_url": "https://app.example.test",
            "attack_goal": "authorized access-control and input-validation testing",
        }
        self.planner = AdaptiveHypothesisPlanner({
            "max_proposals": 3,
            "max_attempts_per_hypothesis": 3,
        })

    def state(self) -> TargetState:
        return TargetState(url=self.context["target_url"], goal=self.context["attack_goal"])

    def test_empty_snapshot_proposes_surface_mapping(self):
        result = self.planner.plan(self.context, self.state(), PlanningSnapshot(), "map target")
        self.assertEqual(result.proposals[0].recommended_tool, "__recon_mission__")
        self.assertEqual(result.proposals[0].action, "attack_surface_mapping")
        audited = self.planner.plan(self.context, self.state(), PlanningSnapshot(errors=["candidate table unavailable"]), "map")
        self.assertIn("Evidence source unavailable: candidate table unavailable", audited.decision.knowledge_gaps)


    def test_authorization_requires_two_isolated_identities(self):
        state = self.state()
        state.endpoints = [EndpointInfo(
            url="https://app.example.test/api/orders?id=123",
            parameters=["id"],
        )]
        blocked = self.planner.plan(
            self.context, state,
            PlanningSnapshot(identities=[{"identity_id": "owner", "status": "active"}]),
            "test access control",
        )
        self.assertFalse(any(item.recommended_tool == "authorization_differential_replay" for item in blocked.proposals))
        self.assertTrue(any("requires 2 isolated identities" in item for item in blocked.decision.knowledge_gaps))

    def test_goal_and_identity_evidence_enable_authorization_replay(self):
        state = self.state()
        state.endpoints = [EndpointInfo(
            url="https://app.example.test/api/orders?id=123",
            parameters=["id", "redirect", "q"],
        )]
        result = self.planner.plan(
            self.context, state,
            PlanningSnapshot(identities=[
                {"identity_id": "owner", "status": "active"},
                {"identity_id": "other", "status": "active"},
            ]),
            "test access control",
        )
        replay = next(item for item in result.proposals if item.recommended_tool == "authorization_differential_replay")
        self.assertTrue(replay.planner_managed)
        self.assertGreater(replay.priority_score, 0)
        self.assertEqual(replay.input_bindings["parameter"], "id")

    def test_disproven_candidate_is_never_retested(self):
        snapshot = PlanningSnapshot(candidates=[{
            "candidate_id": "cand_1",
            "fingerprint": "candidate-fingerprint",
            "title": "SQLi signal",
            "vuln_type": "SQL Injection",
            "target_url": "https://app.example.test/search",
            "parameter": "q",
            "status": "disproven",
            "confidence_score": 0.1,
        }])
        result = self.planner.plan(self.context, self.state(), snapshot, "validate SQLi")
        hypothesis = result.hypotheses[0]
        self.assertEqual(hypothesis.status, "disproven")
        self.assertFalse(any(item.hypothesis_id == hypothesis.hypothesis_id for item in result.proposals))

    def test_repeated_failure_selects_alternative_tool(self):
        snapshot = PlanningSnapshot(
            candidates=[{
                "candidate_id": "cand_2",
                "fingerprint": "candidate-fingerprint-2",
                "title": "SQLi candidate",
                "vuln_type": "SQL Injection",
                "target_url": "https://app.example.test/search",
                "parameter": "q",
                "status": "suspected",
                "confidence_score": 0.55,
            }],
            tool_runs=[
                {"tool_run_id": "run_1", "tool_name": "SQL Injection Scanner", "status": "failed"},
                {"tool_run_id": "run_2", "tool_name": "SQL Injection Scanner", "status": "failed"},
            ],
        )
        result = self.planner.plan(self.context, self.state(), snapshot, "validate SQL injection")
        self.assertEqual(result.proposals[0].recommended_tool, "blind_sqli_scanner")

    def test_same_evidence_does_not_duplicate_active_proposal(self):
        state = self.state()
        snapshot = PlanningSnapshot(candidates=[{
            "candidate_id": "cand_3",
            "fingerprint": "candidate-fingerprint-3",
            "title": "XSS candidate",
            "vuln_type": "XSS",
            "target_url": "https://app.example.test/search",
            "parameter": "q",
            "status": "suspected",
            "confidence_score": 0.5,
        }])
        first = self.planner.plan(self.context, state, snapshot, "validate XSS")
        second = self.planner.plan(self.context, state, snapshot, "validate XSS")
        first.proposals[0].status = "rejected"
        self.assertEqual(len(first.proposals), 1)
        self.assertEqual(second.proposals, [])


    def test_validated_candidate_becomes_chain_prerequisite_with_source_label(self):
        state = self.state()
        snapshot = PlanningSnapshot(candidates=[{
            "candidate_id": "cand_valid",
            "fingerprint": "validated-fingerprint",
            "title": "Validated authorization issue",
            "vuln_type": "IDOR",
            "severity": "HIGH",
            "target_url": "https://app.example.test/api/orders/123",
            "status": "validated_override",
            "confidence_score": 0.9,
            "metadata": {"evidence_ids": ["obs_owner", "obs_other"]},
        }])
        self.planner.plan(self.context, state, snapshot, "refresh evidence")
        finding = next(item for item in state.workflow.findings if item.finding_id == "cand_valid")
        self.assertEqual(finding.status, "validated")
        self.assertEqual(finding.validation_source, "human_override")
        self.assertEqual(finding.evidence_ids, ["obs_owner", "obs_other"])
        snapshot.candidates[0]["status"] = "inconclusive"
        self.planner.plan(self.context, state, snapshot, "revalidation changed status")
        self.assertEqual(finding.status, "inconclusive")

    def test_chain_and_dispatch_preserve_planner_metadata(self):
        class FakeSessions:
            def __init__(self, state, context):
                self.state = state
                self.context = context

            def require(self, session_id):
                return self.context

            def load_state(self, session_id):
                return self.state

            def save_state(self, session_id, state, phase=None):
                self.state = state

            def validate_active_scope(self, session_id, target_url):
                return True, "in scope"

        chain_state = self.state()
        validated = PlanningSnapshot(candidates=[{
            "candidate_id": "cand_chain",
            "fingerprint": "chain-fingerprint",
            "title": "Authorization issue",
            "vuln_type": "IDOR",
            "severity": "HIGH",
            "target_url": "https://app.example.test/api/orders/123",
            "status": "validated_override",
            "metadata": {"evidence_ids": ["obs_a", "obs_b"]},
        }])
        self.planner.plan(self.context, chain_state, validated, "refresh")
        chain_store = FakeSessions(chain_state, self.context)
        chain_result = ChainPlanner(chain_store).propose_next("session", "prove bounded impact")
        self.assertEqual(chain_result["status"], "proposed")
        self.assertIn("human-override-validated", chain_result["proposals"][0]["rationale"])

        dispatch_state = self.state()
        candidate = PlanningSnapshot(candidates=[{
            "candidate_id": "cand_dispatch",
            "fingerprint": "dispatch-fingerprint",
            "title": "SQLi candidate",
            "vuln_type": "SQL Injection",
            "target_url": "https://app.example.test/search",
            "parameter": "q",
            "status": "suspected",
            "confidence_score": 0.5,
        }])
        planned = self.planner.plan(self.context, dispatch_state, candidate, "validate SQLi")
        proposal = planned.proposals[0]
        proposal.status = "approved"
        dispatch_store = FakeSessions(dispatch_state, self.context)
        jobs = {}
        dispatcher = WorkflowDispatcher(dispatch_store, ExecutionGuard(dispatch_store), jobs)
        dispatched = dispatcher.dispatch("session", proposal.action_id)
        self.assertEqual(dispatched["scan_config"]["recommended_tools"], [proposal.recommended_tool])
        hypothesis = next(item for item in dispatch_state.workflow.hypotheses if item.hypothesis_id == proposal.hypothesis_id)
        self.assertEqual(hypothesis.test_attempts, 1)
        dispatcher.complete("session", proposal.action_id, True, "done")
        self.assertEqual(proposal.status, "complete")

if __name__ == "__main__":
    unittest.main()

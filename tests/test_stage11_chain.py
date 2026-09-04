import unittest

from core.chain_planner import ChainPlanner
from core.impact_service import ImpactService
from core.stage11_benchmark import Stage11BenchmarkEngine, load_stage11_suite
from core.structured_contract import PayloadProposalV1
from core.workflow_models import FindingRecord, WorkflowState
from tools.modern_protocol_tools import normalize_protocol_capture, operation_dicts


class _Sessions:
    def __init__(self):
        self.state = type("State", (), {"workflow": WorkflowState()})()

    def require(self, session_id):
        return {"target_url": "http://fixture.local", "attack_goal": "prove objective"}

    def load_state(self, session_id):
        return self.state

    def save_state(self, session_id, state, phase=None):
        self.state = state


class Stage11ChainTests(unittest.TestCase):
    def test_stage11_matrix_has_96_deterministic_cases(self):
        suite, scenarios, matrix = load_stage11_suite()
        self.assertEqual(len(suite.cases), 96)
        self.assertEqual(len(scenarios), 96)
        self.assertEqual(matrix.scenario_count, 96)

    def test_stage11_gate_and_replay(self):
        engine = Stage11BenchmarkEngine()
        first = engine.run_suite(trial_number=1, trial_count=3, seed=7)
        second = engine.run_suite(trial_number=2, trial_count=3, seed=7)
        self.assertEqual(first[3].decision, "ready")
        self.assertEqual(first[0].metrics["false_positive_rate"], 0.0)
        self.assertEqual(first[0].metrics["false_negative_rate"], 0.0)
        self.assertEqual([(x.actual_outcome, x.status) for x in first[1]], [(x.actual_outcome, x.status) for x in second[1]])

    def test_protocol_capture_is_structured_and_filters_unknown_protocol(self):
        result = normalize_protocol_capture("session", "http://fixture.local", [
            {"protocol": "websocket", "operation_ref": "/events", "identity_id": "user", "evidence_ids": ["obs-1"]},
            {"protocol": "unknown", "operation_ref": "/ignored"},
        ])
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(operation_dicts(result)[0]["protocol"], "websocket")
        self.assertNotIn("unknown", result.metrics["supported_protocols"])

    def test_chain_requires_evidence_and_payload_risk_controls_approval(self):
        sessions = _Sessions()
        sessions.state.workflow.findings.append(FindingRecord(
            title="Validated access boundary", vuln_type="IDOR", severity="HIGH",
            evidence_ids=["obs-owner", "obs-other"], status="validated",
        ))
        result = ChainPlanner(sessions).propose_next("session", "controlled objective")
        self.assertEqual(result["status"], "proposed")
        self.assertTrue(result["chain"]["evidence_ids"])
        payload = PayloadProposalV1(target_url="http://fixture.local", input_ref="body.price", family="business_logic", risk="mutation")
        self.assertTrue(payload.requires_exact_approval())

    def test_payload_proposal_is_bounded_and_mutation_is_not_dispatchable(self):
        sessions = _Sessions()
        service = ImpactService(sessions, ChainPlanner(sessions))
        result = service.build_payload_proposal(
            "session", target_url="http://fixture.local/path", input_ref="body.price",
            family="business_logic", risk="mutation", redacted_excerpt="PRICE_MARKER",
            cleanup_ref="cleanup:test",
        )
        self.assertTrue(result["proposal"]["requires_approval"])
        self.assertFalse(result["execution_policy"]["dispatch_allowed"])
        self.assertEqual(result["execution_policy"]["assessment_mode"], "autonomous")

    def test_chain_evaluation_is_structural_and_never_validates_impact(self):
        sessions = _Sessions()
        sessions.state.workflow.findings.append(FindingRecord(
            title="Validated access boundary", vuln_type="IDOR", severity="HIGH",
            evidence_ids=["obs-owner", "obs-other"], status="validated",
        ))
        graph = ChainPlanner(sessions).build_graph("session", "objective")
        evaluation = ChainPlanner(sessions).evaluate_graph("session", graph)
        self.assertEqual(evaluation["decision"], "satisfied")
        self.assertNotEqual(evaluation["decision"], "validated")
        self.assertTrue(all("evidence_ids" in item for item in evaluation["checks"]))


if __name__ == "__main__":
    unittest.main()

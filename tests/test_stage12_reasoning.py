import unittest

from core.adaptive_planner import AdaptiveHypothesisPlanner, PlanningSnapshot
from core.stage12_benchmark import Stage12BenchmarkEngine, load_stage12_suite
from core.structured_contract import PlannerActionV1, ReportClaimV1, ReportNarrativeV1
from core.structured_repository import StructuredRepository
from core.target_state import TargetState
from core.workflow_models import WorkflowState
from tools.report_generator import ReportGenerator


class _FakeTable:
    def __init__(self, name, records):
        self.name = name
        self.records = records

    def upsert(self, row, **_kwargs):
        self.records.setdefault(self.name, []).append(dict(row))
        return self

    def execute(self):
        return type("Response", (), {"data": []})()


class _FakeSupabase:
    def __init__(self):
        self.records = {}

    def table(self, name):
        return _FakeTable(name, self.records)


class _FakeStore:
    def __init__(self):
        self.sb = _FakeSupabase()


class Stage12ReasoningTests(unittest.TestCase):
    def test_stage12_matrix_and_gate_are_deterministic(self):
        suite, scenarios, matrix = load_stage12_suite()
        self.assertEqual(len(suite.cases), 96)
        self.assertEqual(len(scenarios), 96)
        self.assertEqual(matrix.scenario_count, 96)

        engine = Stage12BenchmarkEngine()
        first = engine.run_suite(seed=17, trial_number=1, trial_count=3)
        second = engine.run_suite(seed=17, trial_number=2, trial_count=3)
        self.assertEqual(first[3].decision, "ready")
        self.assertEqual(first[0].status, "succeeded")
        self.assertEqual(first[0].metrics["unsafe_dispatch"], 0.0)
        self.assertEqual(
            [(item.actual_outcome, item.status) for item in first[1]],
            [(item.actual_outcome, item.status) for item in second[1]],
        )

    def test_reasoning_cycle_is_bounded_and_records_gaps(self):
        planner = AdaptiveHypothesisPlanner({"max_proposals": 2})
        state = TargetState(url="http://fixture.local", goal="test SQL injection")
        snapshot = PlanningSnapshot(
            observations=[
                {"observation_id": "obs-baseline", "role": "baseline", "target_url": "http://fixture.local/search"},
                {"observation_id": "obs-control", "role": "negative_control", "target_url": "http://fixture.local/search"},
                {"observation_id": "obs-repro", "role": "reproduction", "target_url": "http://fixture.local/search"},
            ]
        )
        result = planner.build_reasoning_cycle(
            {"session_id": "session-1", "target_url": "http://fixture.local", "attack_goal": "test SQL injection"},
            state,
            snapshot,
            "find a bounded SQL injection hypothesis",
        )
        self.assertIn(result.cycle.status, {"succeeded", "partial", "stopped"})
        self.assertLessEqual(len(result.actions), 2)
        self.assertTrue(result.evidence_gaps)
        self.assertTrue(result.decision["deterministic"])

    def test_model_actions_reject_unknown_evidence_and_unsafe_mutation(self):
        traces = AdaptiveHypothesisPlanner.validate_model_actions(
            "cycle-1",
            [
                {
                    "action_type": "run_read_only",
                    "tool_name": "scan_sql_injection",
                    "endpoint_ref": "http://fixture.local/search",
                    "evidence_ids": ["invented-evidence"],
                },
                {
                    "action_type": "request_approval",
                    "tool_name": "scan_sql_injection",
                    "endpoint_ref": "http://fixture.local/search",
                    "side_effect_class": "mutation",
                    "risk": "high_risk",
                    "requires_approval": False,
                    "cleanup_ref": "",
                },
            ],
            known_targets={"http://fixture.local/search"},
            known_evidence={"obs-1"},
            known_tools={"scan_sql_injection"},
            model_id="offline-stub",
        )
        self.assertEqual(len(traces), 2)
        self.assertFalse(traces[0].valid)
        self.assertTrue(traces[0].invented_evidence)
        self.assertFalse(traces[1].valid)
        self.assertTrue(traces[1].unsafe_mutation)

    def test_reasoning_persistence_whitelists_contract_metadata(self):
        planner = AdaptiveHypothesisPlanner({"max_proposals": 1})
        result = planner.build_reasoning_cycle(
            {"session_id": "session-1", "target_url": "http://fixture.local", "attack_goal": "map the target"},
            TargetState(url="http://fixture.local", goal="map the target"),
            PlanningSnapshot(),
            "map target",
        )
        fake = _FakeStore()
        stored = StructuredRepository(fake).save_reasoning_result(
            "session-1",
            {
                "cycle": result.cycle.model_dump(mode="json"),
                "hypotheses": result.hypotheses,
                "actions": result.actions,
                "evidence_gaps": result.evidence_gaps,
                "stop_conditions": result.stop_conditions,
                "decision": result.decision,
                "model_traces": result.model_traces,
            },
        )
        self.assertEqual(stored["session_id"], "session-1")
        self.assertNotIn("schema_version", fake.sb.records["reasoning_cycles"][0])
        self.assertNotIn("source_candidate_ids", fake.sb.records["reasoning_hypotheses"][0])

    def test_report_contract_marks_only_evidence_backed_claim_as_grounded(self):
        grounded = ReportClaimV1(
            report_id="report-1", claim_type="finding", text="validated finding",
            evidence_ids=["obs-1"], validated=True, grounded=True,
        )
        ungrounded = ReportClaimV1(
            report_id="report-1", claim_type="finding", text="unproven narrative",
            validated=False, grounded=False,
        )
        narrative = ReportNarrativeV1(
            report_id="report-1", session_id="session-1", target="http://fixture.local",
            claim_ids=[grounded.claim_id, ungrounded.claim_id], grounding_complete=False,
        )
        self.assertTrue(grounded.grounded)
        self.assertFalse(ungrounded.grounded)
        self.assertFalse(narrative.grounding_complete)

    def test_legacy_report_adapter_cannot_promote_phase_text_or_candidates(self):
        generator = ReportGenerator()
        candidate = generator.generate({
            "status": "suspected", "name": "candidate", "vuln_type": "sql_injection",
            "evidence_ids": [],
        })
        narrative = generator.generate_from_phase_results(
            {"assessor": "CRITICAL: fabricated finding from model narrative"},
            "http://fixture.local",
        )
        self.assertIn("cannot enter the main report", candidate)
        self.assertIn("Diagnostic Phase Narrative", narrative)
        self.assertIn("cannot create findings", narrative)


if __name__ == "__main__":
    unittest.main()

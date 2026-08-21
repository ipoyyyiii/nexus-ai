"""Deterministic Stage 4 browser workflow and business invariant tests."""

import unittest

from core.browser_workflow_contract import BrowserStepV1, BrowserWorkflowV1, BusinessInvariantV1
from core.browser_workflow_runner import StatefulBrowserRunner
from core.business_logic_engine import business_invariant_compiler, business_invariant_engine


class TestBrowserContracts(unittest.TestCase):
    def test_workflow_fingerprint_and_mutation_detection(self):
        workflow = BrowserWorkflowV1(
            session_id="session-1",
            name="checkout",
            origin="https://example.test",
            steps=[BrowserStepV1(ordinal=0, action="submit", side_effect_class="mutation")],
            cleanup_step_ids=["cleanup-1"],
        )
        self.assertTrue(workflow.ensure_fingerprint().fingerprint)
        self.assertTrue(workflow.has_mutations())
        self.assertTrue(workflow.has_cleanup())


class TestInvariantEngine(unittest.TestCase):
    def test_typed_numeric_violation_becomes_candidate_not_validated(self):
        invariant = BusinessInvariantV1(
            session_id="session-1",
            name="server total must match expected total",
            rule_type="numeric_consistency",
            status="active",
            rule={"left": "total", "right": "expected_total", "severity": "HIGH"},
        )
        evaluation, candidate = business_invariant_engine.evaluate(
            invariant,
            transitions=[{
                "transition_id": "t-1",
                "after_state": {"total": 99, "expected_total": 10},
                "observation_ids": ["obs-1"],
            }],
        )
        self.assertEqual(evaluation.decision, "violated")
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.status, "suspected")
        self.assertIn("obs-1", candidate.observation_ids)

    def test_missing_control_is_inconclusive(self):
        invariant = BusinessInvariantV1(
            session_id="session-1",
            name="coupon is single use",
            rule_type="single_use",
            status="active",
        )
        evaluation, candidate = business_invariant_engine.evaluate(invariant, runs=[{"result": "success"}])
        self.assertEqual(evaluation.decision, "inconclusive")
        self.assertIsNone(candidate)

    def test_free_text_compiler_only_emits_supported_rule(self):
        invariant = business_invariant_compiler.compile("cross tenant ownership must be denied", "session-1")
        self.assertEqual(invariant.rule_type, "tenant_isolation")
        with self.assertRaises(ValueError):
            business_invariant_compiler.compile("make the UI nicer", "session-1")


class TestBrowserApproval(unittest.IsolatedAsyncioTestCase):
    async def test_mutating_run_requires_exact_approval(self):
        class Repo:
            def save_run(self, run):
                self.run = run

        workflow = BrowserWorkflowV1(
            session_id="session-1",
            name="mutating",
            origin="https://example.test",
            steps=[BrowserStepV1(ordinal=0, action="submit", side_effect_class="mutation")],
            cleanup_step_ids=["cleanup-1"],
        )
        repo = Repo()
        runner = StatefulBrowserRunner(repository=repo)
        run = await runner.run(workflow, session_id="session-1", target="https://example.test", bindings={})
        self.assertEqual(run.status, "approval_required")
        self.assertEqual(run.error_code, "approval_required")
        digest = runner.approval_digest(workflow, "", {}, run.approval_expires_at)
        self.assertEqual(run.approval_digest, digest)


if __name__ == "__main__":
    unittest.main()

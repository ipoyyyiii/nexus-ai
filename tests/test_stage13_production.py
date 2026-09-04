import unittest

from core.stage13_benchmark import Stage13BenchmarkEngine, load_stage13_suite
from core.supply_chain import supply_chain_report
from core.cleanup_registry import cleanup_registry
from core.execution_contract import CleanupTaskV1
from core.production_contract import WorkerHealthV1
from core.durable_execution import DurableExecutionRepository
from core.durable_execution import InMemoryExecutionRepository
from core.execution_contract import ExecutionJobV1


class _FakeTable:
    def __init__(self, calls):
        self.calls = calls

    def insert(self, row):
        self.calls.append(("insert", row))
        return self

    def upsert(self, row, **kwargs):
        self.calls.append(("upsert", row))
        return self

    def update(self, row):
        self.calls.append(("update", row))
        return self

    def eq(self, *args):
        return self

    def order(self, *args, **kwargs):
        return self

    def limit(self, *args):
        return self

    def execute(self):
        return type("Result", (), {"data": []})()


class _FakeSupabase:
    def __init__(self):
        self.calls = []

    def table(self, name):
        return _FakeTable(self.calls)


class Stage13ProductionTests(unittest.TestCase):
    def test_stage13_matrix_and_gate_are_deterministic(self):
        suite, scenarios, matrix = load_stage13_suite()
        self.assertEqual(len(suite.cases), 96)
        self.assertEqual(len(scenarios), 96)
        self.assertEqual(matrix.scenario_count, 96)
        engine = Stage13BenchmarkEngine()
        first = engine.run_suite(seed=23, trial_number=1, trial_count=3)
        second = engine.run_suite(seed=23, trial_number=2, trial_count=3)
        self.assertEqual(first[3].decision, "ready")
        self.assertEqual(first[0].status, "succeeded")
        self.assertEqual(first[0].metrics, second[0].metrics)
        self.assertEqual(
            [(item.actual_outcome, item.status) for item in first[1]],
            [(item.actual_outcome, item.status) for item in second[1]],
        )

    def test_supply_chain_manifest_is_pinned_and_no_fake_success(self):
        report = supply_chain_report()
        self.assertTrue(report["ready"], report)
        self.assertGreaterEqual(report["source_pin_count"], 6)
        self.assertGreaterEqual(report["binary_version_count"], 10)

    def test_production_contracts_redact_and_cleanup_is_serializable(self):
        health = WorkerHealthV1(worker_id="worker-1", metadata={"token": "secret"})
        self.assertNotIn("secret", str(health.model_dump()))
        task = CleanupTaskV1(session_id="session-1", handler_id="restore_baseline_callback")
        self.assertEqual(task.max_attempts, 3)
        result = cleanup_registry.execute_durable("restore_baseline_callback", {"rollback_callback": lambda: None})
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "cleanup_failed")

    def test_telemetry_adapter_drops_contract_version_before_persistence(self):
        client = _FakeSupabase()
        repository = DurableExecutionRepository(client)
        repository.record_worker_health(WorkerHealthV1(worker_id="worker-1"))
        repository.record_resource_sample(
            type(
                "Sample",
                (),
                {
                    "model_dump": lambda self, mode=None: {
                        "schema_version": "1.0",
                        "sample_id": "sample-1",
                    },
                },
            )()
        )
        persisted = [row for operation, row in client.calls if operation == "insert"]
        self.assertTrue(persisted)
        self.assertTrue(all("schema_version" not in row for row in persisted))

    def test_worker_owned_application_terminal_state_is_visible_to_api_view(self):
        repository = InMemoryExecutionRepository()
        job = ExecutionJobV1(session_id="session-1", job_id="job-1", target="http://fixture.local")
        repository.enqueue(job)

        repository.record_application_state(
            "job-1",
            session_id="session-1",
            status="error",
            message="Execution integrity failure: browser tool failed.",
            error_code="execution_integrity_failure",
            summary={"structured_tool_runs": 3},
            logs=[{"status": "failed", "tool": "browser_screenshot"}],
        )

        view = repository.get_job("job-1")
        self.assertEqual(view["application_status"], "error")
        self.assertEqual(view["message"], "Execution integrity failure: browser tool failed.")
        self.assertEqual(view["error_code"], "execution_integrity_failure")
        self.assertEqual(view["summary"]["structured_tool_runs"], 3)
        self.assertEqual(view["logs"][0]["tool"], "browser_screenshot")

    def test_production_repository_persists_worker_application_terminal_state(self):
        client = _FakeSupabase()
        repository = DurableExecutionRepository(client)

        self.assertTrue(repository.record_application_state(
            "job-1",
            session_id="session-1",
            status="error",
            message="browser tool failed",
            error_code="execution_integrity_failure",
            error_message="browser_screenshot failed",
            summary={"structured_tool_runs": 3},
            logs=[{"tool": "browser_screenshot", "status": "failed"}],
        ))

        updates = [row for operation, row in client.calls if operation == "update"]
        events = [row for operation, row in client.calls if operation == "insert"]
        self.assertTrue(updates)
        self.assertEqual(updates[-1]["error_code"], "execution_integrity_failure")
        self.assertEqual(updates[-1]["error_message"], "browser_screenshot failed")
        self.assertTrue(any(row.get("event_type") == "job_application_terminal" for row in events))


if __name__ == "__main__":
    unittest.main()

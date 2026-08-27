from types import SimpleNamespace

import pytest

from core.production_contract import SoakRunV1
from core.soak_executor import DurableSoakExecutor, SoakCancelled


class FakeDurable:
    def __init__(self, cancelled=False):
        self.cancelled = cancelled
        self.checkpoints = []
        self.events = []

    def is_cancel_requested(self, job_id):
        return self.cancelled

    def save_checkpoint(self, checkpoint):
        self.checkpoints.append(checkpoint)

    def append_event(self, event):
        self.events.append(event)


class FakeProduction:
    def __init__(self):
        self.base = SoakRunV1(soak_run_id="soak_test")
        self.events = []
        self.samples = []
        self.slos = []

    def soak_events(self, soak_run_id):
        return [event.model_dump(mode="json") for event in self.events if event.soak_run_id == soak_run_id]

    def soak_samples(self, soak_run_id):
        return [sample.model_dump(mode="json") for sample in self.samples if sample.soak_run_id == soak_run_id]

    def save_soak_event(self, event):
        self.events.append(event)

    def save_soak_sample(self, sample):
        self.samples.append(sample)

    def save_slo(self, snapshot):
        self.slos.append(snapshot)


def _job():
    return {
        "session_id": "session_test",
        "payload_redacted": {
            "soak_run_id": "soak_test",
            "duration_seconds": 60,
            "sample_interval_seconds": 15,
            "worker_count": 1,
            "simulated_worker_count": 2,
            "dry_run": True,
        },
    }

def _attempt():
    return SimpleNamespace(job_id="job_test", attempt_id="attempt_test")


def test_dry_run_persists_samples_checkpoint_slo_and_terminal_event():
    durable = FakeDurable()
    production = FakeProduction()
    status = DurableSoakExecutor(durable, production).execute(_job(), _attempt())

    assert status == "succeeded"
    assert len(production.samples) == 4
    assert len(durable.checkpoints) == len(production.samples)
    assert production.slos[0].passed is True
    assert [event.status for event in production.events] == ["running", "succeeded"]


def test_cancelled_soak_is_terminal_and_does_not_report_success():
    durable = FakeDurable(cancelled=True)
    production = FakeProduction()

    with pytest.raises(SoakCancelled):
        DurableSoakExecutor(durable, production).execute(_job(), _attempt())

    assert [event.status for event in production.events] == ["running", "cancelled"]
    assert production.slos == []

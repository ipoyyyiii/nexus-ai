from types import SimpleNamespace

import pytest

from worker import NexusWorker


class FakeRepository:
    def __init__(self):
        self.transitions = []

    def transition(self, job_id, attempt_id, worker_id, lease_token, status, **values):
        self.transitions.append({
            "job_id": job_id,
            "attempt_id": attempt_id,
            "worker_id": worker_id,
            "lease_token": lease_token,
            "status": status,
            **values,
        })
        return True


def _attempt():
    return SimpleNamespace(
        job_id="job-1",
        attempt_id="attempt-1",
        worker_id="worker-1",
        lease_token="lease-1",
    )


@pytest.mark.parametrize(
    ("handler_status", "expected_worker_status"),
    [
        ("done", "succeeded"),
        ("partial", "partial"),
        ("cancelled", "cancelled"),
        ("error", "failed"),
        ("failed", "failed"),
    ],
)
def test_pentest_worker_preserves_authoritative_terminal_status(
    monkeypatch, handler_status, expected_worker_status
):
    import api

    monkeypatch.setattr(api, "run_pentest_job", lambda *args, **kwargs: handler_status)
    repository = FakeRepository()
    worker = NexusWorker(repository, ["general"], worker_id="worker-1")

    worker._pentest(
        {"job_id": "job-1", "target": "http://fixture.local", "goal": "test", "session_id": "session-1"},
        _attempt(),
        60,
    )

    assert [item["status"] for item in repository.transitions] == [expected_worker_status]


def test_pentest_worker_fails_closed_when_handler_has_no_terminal_status(monkeypatch):
    import api

    monkeypatch.setattr(api, "run_pentest_job", lambda *args, **kwargs: None)
    repository = FakeRepository()
    worker = NexusWorker(repository, ["general"], worker_id="worker-1")

    with pytest.raises(RuntimeError, match="authoritative terminal status"):
        worker._pentest(
            {"job_id": "job-1", "target": "http://fixture.local", "goal": "test", "session_id": "session-1"},
            _attempt(),
            60,
        )

    assert repository.transitions == []


def test_heartbeat_refreshes_local_health_file_while_attempt_is_active(monkeypatch):
    import worker as worker_module

    class OneTickStop:
        def __init__(self):
            self.calls = 0

        def wait(self, _interval):
            self.calls += 1
            return self.calls > 1

    class HeartbeatRepository(FakeRepository):
        def heartbeat(self, _attempt, _lease_seconds):
            return True

    refreshed = []
    monkeypatch.setattr(
        worker_module.NexusWorker,
        "_write_health_file",
        staticmethod(lambda: refreshed.append(True)),
    )
    worker = NexusWorker(HeartbeatRepository(), ["general"], worker_id="worker-1")
    worker._heartbeat_loop(_attempt(), 60, OneTickStop())

    assert refreshed == [True]


def test_expired_job_recovery_disconnect_does_not_kill_worker(monkeypatch):
    import worker as worker_module

    class Rpc:
        def __init__(self):
            self.calls = 0

        def execute(self):
            self.calls += 1
            if self.calls == 1:
                raise ConnectionError("transient control-plane disconnect")
            return type("Result", (), {"data": 0})()

    class Repository(FakeRepository):
        def __init__(self):
            super().__init__()
            self.rpc_client = Rpc()

        class SB:
            pass

    repository = Repository()
    repository.sb = type("Supabase", (), {"rpc": lambda _self, *_args: repository.rpc_client})()
    monkeypatch.setattr(
        worker_module,
        "get_setting",
        lambda name, default=None: {
            "execution": {
                "worker_rpc_retry_attempts": 1,
                "worker_rpc_retry_backoff_seconds": 0,
            }
        }.get(name, default),
    )

    NexusWorker(repository, ["general"], worker_id="worker-1")._recover_expired()

    assert repository.rpc_client.calls == 2


def test_health_telemetry_failure_does_not_raise_or_stop_worker(monkeypatch):
    import worker as worker_module

    class TelemetryRepository(FakeRepository):
        def record_worker_health(self, _health):
            raise ConnectionError("telemetry unavailable")

    monkeypatch.setattr(worker_module.NexusWorker, "_write_health_file", staticmethod(lambda: None))
    monkeypatch.setattr(worker_module.NexusWorker, "_resource_sample", staticmethod(lambda: {}))
    monkeypatch.setattr(
        worker_module,
        "get_setting",
        lambda name, default=None: {
            "execution": {"worker_health_interval_seconds": 0}
        }.get(name, default),
    )
    worker = NexusWorker(TelemetryRepository(), ["general"], worker_id="worker-1")

    worker._publish_health()

    assert worker.stop_requested is False

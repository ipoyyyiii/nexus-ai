from types import SimpleNamespace


def test_cancellation_store_observes_durable_cancel(monkeypatch):
    from core.cancellation import CancellationStore

    class _Durable:
        def is_cancel_requested(self, job_id):
            return job_id == "job-1"

    monkeypatch.setattr(
        "core.identity_context.get_execution_context",
        lambda: SimpleNamespace(
            safety_kernel=SimpleNamespace(repository=_Durable())
        ),
    )

    store = CancellationStore()
    store.register("job-1")

    assert store.is_cancelled("job-1") is True

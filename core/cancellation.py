import threading
from typing import Optional, Dict
from contextvars import ContextVar

current_job_id: ContextVar[Optional[str]] = ContextVar("cancel_job_id", default=None)


class CancellationStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._tokens: Dict[str, threading.Event] = {}

    def register(self, job_id: str) -> threading.Event:
        """Bikin token baru for job. Dipanggil di awal run_pentest_job."""
        token = threading.Event()
        with self._lock:
            self._tokens[job_id] = token
        return token

    def cancel(self, job_id: str) -> bool:
        """Set token for job. Return False kalau job_id gak found."""
        with self._lock:
            token = self._tokens.get(job_id)
        if not token:
            return False
        token.set()
        return True

    def is_cancelled(self, job_id: str) -> bool:
        with self._lock:
            token = self._tokens.get(job_id)
        if token and token.is_set():
            return True
        # API and worker run in separate processes. The API-side cancel
        # request therefore cannot set this process-local Event. Consult the
        # durable repository carried by the active execution context so a
        # cross-process cancellation becomes visible at every existing
        # cancellation checkpoint without weakening the local fast path.
        try:
            from core.identity_context import get_execution_context

            context = get_execution_context()
            repository = getattr(getattr(context, "safety_kernel", None), "repository", None)
            if repository is not None and hasattr(repository, "is_cancel_requested"):
                return bool(repository.is_cancel_requested(job_id))
        except Exception:
            # Cancellation checks must never crash a running job. The local
            # token remains authoritative when durable status is unavailable.
            pass
        return False

    def cleanup(self, job_id: str):
        """Delete token sealready job selesai/error/cancelled."""
        with self._lock:
            self._tokens.pop(job_id, None)


cancellation_store = CancellationStore()


def check_cancelled(exec_logger=None) -> bool:
    """
    Helper that dipanggil from dalam tool senot yet eksekusi.
    Return True kalau job already di-cancel (tool must berhenti).
    """
    job_id = current_job_id.get()
    if not job_id:
        return False
    if cancellation_store.is_cancelled(job_id):
        if exec_logger:
            exec_logger.add_log(
                "CANCEL", "BLOCKED",
                "Eksekusi cancelled: job di-cancel oleh user."
            )
        return True
    return False

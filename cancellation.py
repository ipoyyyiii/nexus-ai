import threading
from typing import Optional, Dict
from contextvars import ContextVar

current_job_id: ContextVar[Optional[str]] = ContextVar("cancel_job_id", default=None)


class CancellationStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._tokens: Dict[str, threading.Event] = {}

    def register(self, job_id: str) -> threading.Event:
        """Bikin token baru buat job. Dipanggil di awal run_pentest_job."""
        token = threading.Event()
        with self._lock:
            self._tokens[job_id] = token
        return token

    def cancel(self, job_id: str) -> bool:
        """Set token buat job. Return False kalau job_id gak ditemukan."""
        with self._lock:
            token = self._tokens.get(job_id)
        if not token:
            return False
        token.set()
        return True

    def is_cancelled(self, job_id: str) -> bool:
        with self._lock:
            token = self._tokens.get(job_id)
        return bool(token and token.is_set())

    def cleanup(self, job_id: str):
        """Hapus token setelah job selesai/error/cancelled."""
        with self._lock:
            self._tokens.pop(job_id, None)


cancellation_store = CancellationStore()


def check_cancelled(exec_logger=None) -> bool:
    """
    Helper yang dipanggil dari dalam tool sebelum eksekusi.
    Return True kalau job sudah di-cancel (tool harus berhenti).
    """
    job_id = current_job_id.get()
    if not job_id:
        return False
    if cancellation_store.is_cancelled(job_id):
        if exec_logger:
            exec_logger.add_log(
                "CANCEL", "BLOCKED",
                "Eksekusi dibatalkan: job di-cancel oleh user."
            )
        return True
    return False
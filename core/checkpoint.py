import threading
from contextvars import ContextVar
from typing import Dict, Optional, Callable

current_job_id: ContextVar[Optional[str]] = ContextVar("current_job_id", default=None)


class CheckpointStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._pending: Dict[str, dict] = {}
        # callback di-set dari api.py supaya checkpoint store bisa update job
        # status tanpa harus import jobs dict langsung (hindari circular import)
        self.on_wait_start: Optional[Callable[[str, str, str], None]] = None
        self.on_wait_end: Optional[Callable[[str], None]] = None

    def request(self, job_id: str, action: str, context: str, risk: str = "high", timeout: int = 300):
        """
        Blocking call (dipanggil dari worker thread tempat crew jalan).
        Return (approved: bool, reason: str)
        """
        event = threading.Event()
        with self._lock:
            self._pending[job_id] = {
                "event": event,
                "approved": None,
                "action": action,
                "context": context,
                "risk": risk,
            }

        if self.on_wait_start:
            try:
                self.on_wait_start(job_id, action, context)
            except Exception:
                pass

        got_response = event.wait(timeout)

        with self._lock:
            entry = self._pending.pop(job_id, None)

        if self.on_wait_end:
            try:
                self.on_wait_end(job_id)
            except Exception:
                pass

        if not got_response:
            return False, "timeout (5 menit) — default DITOLAK demi safety"

        approved = bool(entry["approved"]) if entry else False
        return approved, "user responded"

    def respond(self, job_id: str, approved: bool) -> bool:
        """Dipanggil dari endpoint /checkpoint/respond ketika user klik approve/reject."""
        with self._lock:
            entry = self._pending.get(job_id)
            if not entry:
                return False
            entry["approved"] = approved
            entry["event"].set()
        return True

    def get_pending(self, job_id: str) -> Optional[dict]:
        with self._lock:
            entry = self._pending.get(job_id)
            if not entry:
                return None
            return {k: v for k, v in entry.items() if k != "event"}


checkpoint_store = CheckpointStore()


def require_approval(action: str, context: str, risk: str = "high", exec_logger=None) -> bool:
    """
    Helper yang dipanggil dari dalam tool senot yet eksekusi aksi berisiko.
    Kalau gak ada job_id di context (misal lagi dipanggil dari CLI standalone
    di agent.py tanpa API), DEFAULT REJECT dengan warning — bukan default allow,
    biar gak ada celah "lupa pasang context = bypass approval".
    """
    job_id = current_job_id.get()

    if not job_id:
        if exec_logger:
            exec_logger.add_log(
                "HITL", "BLOCKED",
                f"Aksi '{action}' rejected: gak ada job_id di context (kemungkinan running di luar API flow)."
            )
        return False

    if exec_logger:
        exec_logger.add_log("HITL", "START", f"Meminta approval untuk: {action}", {"context": context, "risk": risk})

    approved, reason = checkpoint_store.request(job_id, action, context, risk=risk)

    if exec_logger:
        exec_logger.add_log(
            "HITL", "SUCCESS" if approved else "BLOCKED",
            f"Checkpoint '{action}': approved={approved} ({reason})"
        )

    return approved
import os
import threading
from contextvars import ContextVar
from typing import Dict, Optional, Callable

current_job_id: ContextVar[Optional[str]] = ContextVar("current_job_id", default=None)


def is_auto_pilot() -> bool:
    """Read auto-pilot from the active job context, with CLI fallback."""
    try:
        from core.identity_context import get_execution_context
        context = get_execution_context()
        if context is not None:
            return bool(context.auto_pilot)
    except Exception:
        pass
    return os.environ.get("AUTO_PILOT", "0") == "1"


class CheckpointStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._pending: Dict[str, dict] = {}
        # callback set from api.py so checkpoint store can update job
        # status tanpa must import jobs dict langsung (hinfrom circular import)
        self.on_wait_start: Optional[Callable[[str, str, str], None]] = None
        self.on_wait_end: Optional[Callable[[str], None]] = None

    def request(self, job_id: str, action: str, context: str, risk: str = "high", timeout: int = 300):
        """
        Blocking call (dipanggil from worker thread tempat crew jalan).
        Return (approved: bool, reason: str)
        """
        # Auto-pilot may only skip read-only pauses. Mutation, credential,
        # upload and raw-network actions always require explicit approval.
        if is_auto_pilot() and risk == "read_only":
            if self.on_wait_start:
                try:
                    self.on_wait_start(job_id, action, context)
                except Exception:
                    pass
            if self.on_wait_end:
                try:
                    self.on_wait_end(job_id)
                except Exception:
                    pass
            return True, "auto-pilot mode enabled"

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
        """Dipanggil from endpoint /checkpoint/respond ketika user klik approve/reject."""
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
    Helper that dipanggil from dalam tool senot yet eksekusi aksi berisiko.
    Kalau gak ada job_id di context (misal lagi dipanggil from CLI standalone
    di agent.py tanpa API), DEFAULT REJECT with warning — bukan default allow,
    biar gak ada celah "lupa pasang context = bypass approval".
    """
    job_id = current_job_id.get()

    # Auto-pilot is never an approval bypass for high-risk actions.
    if is_auto_pilot() and risk == "read_only":
        if exec_logger:
            exec_logger.add_log("HITL", "AUTO-APPROVED", f"Read-only action '{action}' auto-approved")
        return True
    if is_auto_pilot() and risk != "read_only":
        if exec_logger:
            exec_logger.add_log("HITL", "BLOCKED", f"Auto-pilot cannot approve mutation/high-risk action '{action}'")
        return False

    if not job_id:
        if exec_logger:
            exec_logger.add_log(
                "HITL", "BLOCKED",
                f"Aksi '{action}' rejected: gak ada job_id di context (kemungkinan running di luar API flow)."
            )
        return False

    if exec_logger:
        exec_logger.add_log("HITL", "START", f"Requesting approval for: {action}", {"context": context, "risk": risk})

    approved, reason = checkpoint_store.request(job_id, action, context, risk=risk)

    if approved:
        try:
            from core.identity_context import get_execution_context
            active = get_execution_context()
            if active is not None:
                active.approval_granted = True
        except Exception:
            pass

    if exec_logger:
        exec_logger.add_log(
            "HITL", "SUCCESS" if approved else "BLOCKED",
            f"Checkpoint '{action}': approved={approved} ({reason})"
        )

    return approved
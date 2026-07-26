"""
AUTH CHECKPOINT
===============
HITL (Human-in-the-Loop) flow for minta credentials ke user.

Flow:
1. Tool detect login wall → panggil request_auth()
2. Auth checkpoint store kirim event ke frontend: "Butuh login"
3. User kasih: credentials (username/password) ATAU session cookies
4. Auth checkpoint store return auth info ke tool
5. Tool login atau inject session → lanjut scan

Mirip checkpoint.py, tapi khusus for authentication.
"""

import threading
from contextvars import ContextVar
from typing import Dict, Optional, Callable, Any

current_job_id: ContextVar[Optional[str]] = ContextVar("auth_job_id", default=None)


class AuthCheckpointStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._pending: Dict[str, dict] = {}
        # Callbacks set from api.py
        self.on_auth_request: Optional[Callable[[str, str, str], None]] = None
        self.on_auth_response: Optional[Callable[[str], None]] = None

    def request_auth(
        self,
        job_id: str,
        url: str,
        domain: str,
        wall_type: str,
        evidence: str,
        has_mfa: bool = False,
        timeout: int = 300,
    ) -> Optional[Dict[str, Any]]:
        """
        Blocking call — dipanggil from worker thread.
        Minta credentials/session ke user, tunggu response.

        Return:
            {
                "mode": "credentials" | "session",
                "username": "...",        # kalau mode=credentials
                "password": "...",        # kalau mode=credentials
                "cookies": "...",         # kalau mode=session (raw cookie string)
                "login_url": "...",       # optional
            }
            atau None kalau timeout/rejected
        """
        event = threading.Event()
        with self._lock:
            self._pending[job_id] = {
                "event": event,
                "response": None,
                "url": url,
                "domain": domain,
                "wall_type": wall_type,
                "evidence": evidence,
                "has_mfa": has_mfa,
            }

        if self.on_auth_request:
            try:
                self.on_auth_request(job_id, url, domain)
            except Exception:
                pass

        got_response = event.wait(timeout)

        with self._lock:
            entry = self._pending.pop(job_id, None)

        if self.on_auth_response:
            try:
                self.on_auth_response(job_id)
            except Exception:
                pass

        if not got_response:
            return None

        return entry.get("response") if entry else None

    def respond(self, job_id: str, auth_data: Optional[Dict[str, Any]]) -> bool:
        """Dipanggil from endpoint /auth/respond ketika user kasih credentials."""
        with self._lock:
            entry = self._pending.get(job_id)
            if not entry:
                return False
            entry["response"] = auth_data
            entry["event"].set()
        return True

    def get_pending(self, job_id: str) -> Optional[dict]:
        with self._lock:
            entry = self._pending.get(job_id)
            if not entry:
                return None
            return {k: v for k, v in entry.items() if k != "event"}


# Global instance
auth_checkpoint_store = AuthCheckpointStore()


def request_auth(
    url: str,
    domain: str,
    wall_type: str = "unknown",
    evidence: str = "",
    has_mfa: bool = False,
    exec_logger=None,
) -> Optional[Dict[str, Any]]:
    """
    Helper that dipanggil from dalam tool ketika login wall terdeteksi.

    Return auth_data dict atau None kalau rejected/timeout.
    """
    job_id = current_job_id.get()

    if not job_id:
        if exec_logger:
            exec_logger.add_log(
                "AUTH", "BLOCKED",
                f"Login wall terdeteksi di {domain}, tapi gak ada job_id — gak can minta credentials."
            )
        return None

    if exec_logger:
        exec_logger.add_log(
            "AUTH", "START",
            f"Login wall terdeteksi: {wall_type}",
            {"url": url, "domain": domain, "evidence": evidence, "has_mfa": has_mfa}
        )

    auth_data = auth_checkpoint_store.request_auth(
        job_id=job_id,
        url=url,
        domain=domain,
        wall_type=wall_type,
        evidence=evidence,
        has_mfa=has_mfa,
    )

    if auth_data:
        if exec_logger:
            exec_logger.add_log(
                "AUTH", "SUCCESS",
                f"Auth received: mode={auth_data.get('mode', 'unknown')}",
                {"domain": domain}
            )
    else:
        if exec_logger:
            exec_logger.add_log(
                "AUTH", "BLOCKED",
                f"Auth rejected atau timeout for {domain}"
            )

    return auth_data

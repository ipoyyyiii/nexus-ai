"""Conversation runtime contracts and cancellation state."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import threading
import uuid


@dataclass
class ChatStreamEvent:
    event: str
    message_id: str
    session_id: str
    delta: str = ""
    content: str = ""
    status: str = ""
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def new_message_id() -> str:
    return f"msg_{uuid.uuid4().hex}"


class ChatCancellation:
    def __init__(self):
        self._events: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def create(self, message_id: str) -> None:
        with self._lock:
            self._events[message_id] = threading.Event()

    def cancel(self, message_id: str) -> bool:
        with self._lock:
            event = self._events.get(message_id)
            if not event:
                return False
            event.set()
            return True

    def is_cancelled(self, message_id: str) -> bool:
        with self._lock:
            event = self._events.get(message_id)
            return event.is_set() if event else False

    def cleanup(self, message_id: str) -> None:
        with self._lock:
            self._events.pop(message_id, None)


chat_cancellation = ChatCancellation()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def classify_provider_error(error: Exception) -> str:
    text = str(error).lower()
    if any(value in text for value in ("insufficient", "quota", "credit", "402")):
        return "insufficient_credit"
    if any(value in text for value in ("rate limit", "rate_limit", "429")):
        return "rate_limited"
    if any(value in text for value in ("timeout", "timed out")):
        return "timeout"
    if any(value in text for value in ("model", "not found", "404")):
        return "invalid_model"
    return "provider_unavailable"

import threading
import time
from collections import defaultdict
from typing import Dict


class DomainRateLimiter:
    def __init__(self, requests_per_second: float = 2.0):
        self.min_interval = 1.0 / requests_per_second
        self._last_call: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()

    def wait(self, domain: str):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call[domain]
            if elapsed < self.min_interval:
                sleep_for = self.min_interval - elapsed
            else:
                sleep_for = 0
            self._last_call[domain] = now + sleep_for
        if sleep_for > 0:
            time.sleep(sleep_for)

    def set_rate(self, requests_per_second: float):
        with self._lock:
            self.min_interval = 1.0 / requests_per_second


rate_limiter = DomainRateLimiter(requests_per_second=2.0)
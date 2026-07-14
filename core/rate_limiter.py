import os
import threading
import time
from collections import defaultdict
from typing import Dict, Optional


def is_stealth_mode() -> bool:
    """Check if stealth mode is enabled."""
    return os.environ.get("STEALTH_MODE", "0") == "1"


class DomainRateLimiter:
    """
    Per-domain rate limiter.
    Default: 2 req/s per domain.
    Stealth mode: 0.5 req/s per domain (lebih lambat).
    Bisa di-override per-domain: rate_limiter.set_domain_rate("target.com", 10.0)
    """

    def __init__(self, requests_per_second: float = 2.0):
        self._default_rate = requests_per_second
        self._domain_rates: Dict[str, float] = {}
        self._last_call: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()

    def wait(self, domain: str):
        """Wait sampai rate limit untuk domain ini terpenuhi."""
        # Apply stealth mode rate if enabled
        if is_stealth_mode():
            rate = min(self._domain_rates.get(domain, self._default_rate), 0.5)
        else:
            rate = self._domain_rates.get(domain, self._default_rate)
        
        min_interval = 1.0 / rate

        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call[domain]
            if elapsed < min_interval:
                sleep_for = min_interval - elapsed
            else:
                sleep_for = 0
            self._last_call[domain] = now + sleep_for
        if sleep_for > 0:
            time.sleep(sleep_for)

    def set_rate(self, requests_per_second: float):
        """Set default rate untuk semua domain."""
        with self._lock:
            self._default_rate = requests_per_second

    def set_domain_rate(self, domain: str, requests_per_second: float):
        """Set rate khusus untuk domain tertentu."""
        with self._lock:
            self._domain_rates[domain] = requests_per_second

    def get_domain_rate(self, domain: str) -> float:
        """Ambil rate untuk domain tertentu."""
        return self._domain_rates.get(domain, self._default_rate)

    def remove_domain_rate(self, domain: str):
        """Hapus rate override untuk domain, balik ke default."""
        with self._lock:
            self._domain_rates.pop(domain, None)


rate_limiter = DomainRateLimiter(requests_per_second=2.0)
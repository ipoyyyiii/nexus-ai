import os
import threading
import time
from collections import defaultdict
from typing import Dict, Optional


def is_stealth_mode() -> bool:
    """Check if stealth mode is enabled.
    Checks environment variable and also database for persistence.
    """
    try:
        from core.identity_context import get_execution_context
        context = get_execution_context()
        if context is not None:
            return bool(context.stealth_mode)
    except Exception:
        pass
    # CLI/backward-compatible fallback.
    env_stealth = os.environ.get("STEALTH_MODE", "0")
    if env_stealth == "1":
        return True
    
    # Fallback: check if there's a global setting file
    # This handles cases where env var isn't passed to Docker
    try:
        stealth_file = "/tmp/stealth_mode_enabled"
        if os.path.exists(stealth_file):
            return True
    except:
        pass
    
    return False


def set_stealth_mode(enabled: bool):
    """Set stealth mode globally."""
    os.environ["STEALTH_MODE"] = "1" if enabled else "0"
    # Also create/remove flag file for persistence
    try:
        if enabled:
            with open("/tmp/stealth_mode_enabled", "w") as f:
                f.write("1")
        else:
            if os.path.exists("/tmp/stealth_mode_enabled"):
                os.remove("/tmp/stealth_mode_enabled")
    except:
        pass


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
        """Wait sampai rate limit for domain this terpenuhi."""
        runtime_rate = None
        try:
            from core.identity_context import get_execution_context
            context = get_execution_context()
            runtime = (context.config_snapshot or {}).get("_runtime", {}) if context else {}
            strategy = runtime.get("waf_strategy") or {}
            strategy_domain = str(strategy.get("domain") or "").lower()
            if strategy_domain and strategy_domain == str(domain).lower():
                runtime_rate = float(strategy.get("rate_limit", 0) or 0)
        except Exception:
            runtime_rate = None
        # Apply stealth mode rate if enabled
        if is_stealth_mode():
            rate = min(runtime_rate or self._domain_rates.get(domain, self._default_rate), 0.5)
        else:
            rate = runtime_rate or self._domain_rates.get(domain, self._default_rate)
        
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
        """Set default rate for all domain."""
        with self._lock:
            self._default_rate = requests_per_second

    def set_domain_rate(self, domain: str, requests_per_second: float):
        """Set rate khusus for domain tertentu."""
        with self._lock:
            self._domain_rates[domain] = requests_per_second

    def get_domain_rate(self, domain: str) -> float:
        """Ambil rate for domain tertentu."""
        return self._domain_rates.get(domain, self._default_rate)

    def remove_domain_rate(self, domain: str):
        """Delete rate override for domain, balik ke default."""
        with self._lock:
            self._domain_rates.pop(domain, None)


rate_limiter = DomainRateLimiter(requests_per_second=2.0)

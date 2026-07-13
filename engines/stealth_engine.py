"""
STEALTH ENGINE — Anti-Detection Evasion Module
=================================================
Bikin requests lo gak keliatan kayak scanner自动化.

Features:
- TLS fingerprint spoofing (mimic browser)
- Dynamic User-Agent rotation
- Randomized request timing (jitter)
- Randomized parameter order
- Browser-like header normalization
"""

import random
import time
import threading
from typing import Dict, Optional, List, Any
from urllib.parse import urlparse


# ── Real Browser User-Agents ─────────────────────────────────────────────────

USER_AGENTS = [
    # Chrome (latest stable)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Firefox (latest stable)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
]

# ── Browser-like Headers ─────────────────────────────────────────────────────

BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
}

# ── API-like Headers (untuk API endpoints) ────────────────────────────────────

API_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Origin": "",
    "Referer": "",
}


class StealthEngine:
    """
    Anti-detection engine buat bikin requests lo gak keliatan automated.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._last_request_time: Dict[str, float] = {}
        self._request_count: Dict[str, int] = {}

    def get_random_ua(self) -> str:
        """Return random real browser User-Agent."""
        return random.choice(USER_AGENTS)

    def get_browser_headers(self, url: str, is_api: bool = False) -> Dict[str, str]:
        """
        Return browser-like headers yang konsisten dengan User-Agent.
        """
        ua = self.get_random_ua()
        headers = {
            "User-Agent": ua,
        }

        if is_api:
            headers.update(API_HEADERS)
        else:
            headers.update(BROWSER_HEADERS)

        # Tambah Referer yang realistis
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        headers["Referer"] = f"{base}/"

        return headers

    def add_jitter(self, base_delay: float = 0.5, max_jitter: float = 1.5):
        """
        Add random delay biar gak keliatan automated.
        Base delay + random jitter antara 0 dan max_jitter detik.
        """
        jitter = random.uniform(0, max_jitter)
        total_delay = base_delay + jitter
        time.sleep(total_delay)

    def shuffle_params(self, params: list) -> list:
        """Shuffle parameter order biar gak predictable."""
        shuffled = params.copy()
        random.shuffle(shuffled)
        return shuffled

    def randomize_case(self, payload: str) -> str:
        """Randomize case of alphanumeric characters dalam payload."""
        result = []
        for char in payload:
            if char.isalpha() and random.random() > 0.5:
                result.append(char.swapcase())
            else:
                result.append(char)
        return "".join(result)

    def get_stealth_session(self, url: str) -> Dict[str, Any]:
        """
        Build complete stealth request config:
        - Random UA
        - Browser-like headers
        - Jitter timing
        - TLS config
        """
        parsed = urlparse(url)
        is_api = any(kw in parsed.path.lower() for kw in ["/api", "/v1", "/v2", "/graphql", "/rest"])

        headers = self.get_browser_headers(url, is_api=is_api)

        return {
            "headers": headers,
            "timeout": random.uniform(8, 15),
            "allow_redirects": True,
            "verify": False,
        }


# Try to import tls_client for better TLS fingerprinting
try:
    import tls_client
    TLS_CLIENT_AVAILABLE = True
except ImportError:
    TLS_CLIENT_AVAILABLE = False


class StealthSession:
    """
    TLS-fingerprint-aware session yang mimic browser.
    Pakai tls_client kalau available, fallback ke requests.
    """

    def __init__(self):
        self._session = None
        self._lock = threading.Lock()

    def get_session(self):
        """Get or create stealth session."""
        with self._lock:
            if self._session is None:
                if TLS_CLIENT_AVAILABLE:
                    # tls_client punya pre-built browser profiles
                    self._session = tls_client.Session(
                        client_identifier="chrome_131",
                        random_tls_extension_order=True,
                    )
                else:
                    # Fallback ke requests biasa
                    import requests as req
                    self._session = req.Session()
                    self._session.verify = False
            return self._session

    def request(self, method: str, url: str, **kwargs) -> Any:
        """
        Make request dengan TLS fingerprint spoofing.
        """
        session = self.get_session()

        # Add browser headers kalau gak ada
        if "headers" not in kwargs:
            stealth = StealthEngine()
            kwargs["headers"] = stealth.get_browser_headers(url)

        # Add jitter
        stealth = StealthEngine()
        stealth.add_jitter(base_delay=0.3, max_jitter=1.0)

        try:
            if TLS_CLIENT_AVAILABLE and hasattr(session, 'request'):
                return session.request(method, url, **kwargs)
            else:
                return session.request(method, url, **kwargs)
        except Exception:
            # Fallback ke requests biasa
            import requests as req
            return req.request(method, url, **kwargs)


# Global instances
stealth = StealthEngine()
stealth_session = StealthSession()


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


def stealth_get(url: str, **kwargs) -> Any:
    """
    Drop-in replacement buat requests.get() dengan stealth.
    Tambahkan auto-jitter, random UA, browser headers.
    """
    return stealth_session.request("GET", url, **kwargs)


def stealth_post(url: str, **kwargs) -> Any:
    """Drop-in replacement buat requests.post() dengan stealth."""
    return stealth_session.request("POST", url, **kwargs)


def stealth_request(method: str, url: str, **kwargs) -> Any:
    """Drop-in replacement buat requests.request() dengan stealth."""
    return stealth_session.request(method, url, **kwargs)

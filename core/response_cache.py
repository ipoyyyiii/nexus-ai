"""
RESPONSE CACHE — HTTP Response Caching
========================================
Cache HTTP responses buat avoid repeat requests ke target yang sama.

Usage:
    from response_cache import response_cache

    # Get cached response
    cached = response_cache.get(url, method="GET")
    if cached:
        return cached  # Use cached response

    # Make request and cache
    resp = requests.get(url)
    response_cache.set(url, resp, method="GET")
"""

import hashlib
import time
import threading
import json
from typing import Optional, Dict, Any
from urllib.parse import urlparse, urlencode


class ResponseCache:
    """
    Thread-safe HTTP response cache.
    TTL-based expiry, per-domain scoping.
    """

    def __init__(self, ttl: int = 300, max_size: int = 1000):
        """
        Args:
            ttl: Cache lifetime dalam seconds (default: 5 menit)
            max_size: Max cached responses (default: 1000)
        """
        self._cache: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        self._ttl = ttl
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    def _make_key(self, url: str, method: str = "GET", data: str = "") -> str:
        """Generate cache key dari url + method + data."""
        key_str = f"{method}:{url}:{data}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, url: str, method: str = "GET", data: str = "") -> Optional[Dict]:
        """
        Get cached response.
        
        Return cached response dict atau None kalau gak ada/expired.
        """
        key = self._make_key(url, method, data)

        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            # Check TTL
            if time.time() - entry["timestamp"] > self._ttl:
                del self._cache[key]
                self._misses += 1
                return None

            self._hits += 1
            return entry["response"]

    def set(self, url: str, response, method: str = "GET", data: str = ""):
        """
        Cache response.
        
        Args:
            url: Request URL
            response: requests.Response object atau dict
            method: HTTP method
            data: Request body (untuk POST)
        """
        key = self._make_key(url, method, data)

        # Parse response jika requests.Response object
        if hasattr(response, "status_code"):
            response_data = {
                "status_code": response.status_code,
                "text": response.text[:50000],  # Cap text
                "headers": dict(response.headers),
                "content_type": response.headers.get("Content-Type", ""),
            }
        else:
            response_data = response

        with self._lock:
            # Evict kalau cache penuh
            if len(self._cache) >= self._max_size:
                # Hapus entry tertua
                oldest_key = min(self._cache, key=lambda k: self._cache[k]["timestamp"])
                del self._cache[oldest_key]

            self._cache[key] = {
                "response": response_data,
                "timestamp": time.time(),
                "url": url,
                "method": method,
            }

    def invalidate(self, url: str, method: str = "GET"):
        """Hapus cache untuk URL tertentu."""
        key = self._make_key(url, method)
        with self._lock:
            self._cache.pop(key, None)

    def invalidate_domain(self, domain: str):
        """Hapus semua cache untuk domain tertentu."""
        with self._lock:
            keys_to_delete = [
                k for k, v in self._cache.items()
                if domain in v.get("url", "")
            ]
            for k in keys_to_delete:
                del self._cache[k]

    def clear(self):
        """Hapus semua cache."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": f"{(self._hits/total*100):.1f}%" if total > 0 else "0%",
                "ttl": self._ttl,
            }


# Global instance
response_cache = ResponseCache(ttl=300, max_size=1000)

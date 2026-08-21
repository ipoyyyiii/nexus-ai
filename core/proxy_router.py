"""Operator-configured proxy adapter.

Public proxy discovery is intentionally removed. An unset proxy means direct
guarded egress; tool code cannot silently fall back to a public proxy pool.
"""

from __future__ import annotations

import os
from typing import Dict, Optional


class ConfiguredProxyRouter:
    def __init__(self):
        self.proxies: list[str] = []

    def refresh_proxies(self) -> int:
        self.proxies = []
        return 0

    def get_proxy(self) -> Optional[Dict[str, str]]:
        # The value is a secret reference resolved by deployment, never fetched
        # from an untrusted public list.
        value = os.environ.get("NEXUS_OPERATOR_PROXY_URL", "").strip()
        if not value:
            return None
        return {"http": value, "https": value}

    def remove_dead_proxy(self, proxy_dict: Dict[str, str]) -> None:
        return None


proxy_router = ConfiguredProxyRouter()
FreeProxyRouter = ConfiguredProxyRouter

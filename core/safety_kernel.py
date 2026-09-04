"""Fail-closed scope, egress, budget, and approval boundary.

This module is one of the explicitly permitted runtime boundary modules. Tool
code must use core.tool_transport; it must not import requests/socket directly.
"""

from __future__ import annotations

import ipaddress
import fnmatch
import os
import socket
import threading
import time
from collections import defaultdict
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlsplit

import requests

from core.execution_contract import ResourceBudgetV1, SafetyDecisionV1
from core.redact import redact


_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "instance-data.ec2.internal",
    "metadata.azure.internal",
}
_METADATA_IPS = {
    ipaddress.ip_address(item)
    for item in (
        "169.254.169.254",  # AWS/GCP/Azure metadata
        "169.254.170.2",    # ECS task metadata
        "100.100.100.200",  # Alibaba metadata
        "168.63.129.16",    # Azure platform endpoint
        "fd00:ec2::254",    # AWS IMDS IPv6
    )
}


class SafetyViolation(PermissionError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


class SafetyKernel:
    """Central policy boundary shared by HTTP, browser, DNS, TLS and CLI."""

    VERSION = "1.1"

    def __init__(self, session_store: Any = None, repository: Any = None):
        self.session_store = session_store
        self.repository = repository
        self._lock = threading.Lock()
        self._usage: Dict[tuple[str, str], Dict[str, int]] = defaultdict(
            lambda: {"requests": 0, "download": 0, "upload": 0, "credentials": 0}
        )
        self._failures: Dict[tuple[str, str], int] = defaultdict(int)
        self._open_until: Dict[tuple[str, str], float] = {}

    def decide(
        self,
        session_id: str,
        action: str,
        target: str,
        *,
        job_id: str = "",
        attempt_id: str = "",
        tool_run_id: str = "",
        identity_id: str = "",
        budget: Optional[ResourceBudgetV1] = None,
        approved: bool = False,
        mutation: bool = False,
        allow_private: bool = False,
        provider_id: str = "",
    ) -> SafetyDecisionV1:
        budget = budget or ResourceBudgetV1()
        decision = "allowed"
        reason = "allowed"
        try:
            parsed_target = urlsplit(str(target))
            if self._is_metadata_target(parsed_target.hostname or "", set()):
                raise SafetyViolation("metadata_target_rejected", "Cloud metadata and link-local targets are never allowed.")
            effective_provider = provider_id or self.provider_for(target)
            if effective_provider:
                self._validate_provider(effective_provider, target)
            else:
                self._validate_url(session_id, target, allow_private=allow_private)
            origin = self.origin(target)
            with self._lock:
                if self._open_until.get((job_id or session_id, origin), 0) > time.monotonic():
                    decision, reason = "throttled", "circuit_open"
                elif mutation and not approved:
                    decision, reason = "blocked", "approval_required"
                elif self._usage[(job_id or session_id, origin)]["requests"] >= budget.max_requests:
                    decision, reason = "blocked", "request_budget_exhausted"
        except SafetyViolation as exc:
            decision, reason = "blocked", exc.reason_code

        result = SafetyDecisionV1(
            session_id=session_id,
            job_id=job_id,
            attempt_id=attempt_id,
            tool_run_id=tool_run_id,
            action=action,
            target=self._safe_target(target),
            decision=decision,
            reason_code=reason,
            policy_version=self.VERSION,
            identity_id=identity_id,
            metadata={"provider_id": (provider_id or self.provider_for(target))} if (provider_id or self.provider_for(target)) else {},
        )
        if self.repository and hasattr(self.repository, "persist_safety_decision"):
            try:
                self.repository.persist_safety_decision(result)
            except Exception:
                if decision == "allowed":
                    result.decision = "blocked"
                    result.reason_code = "audit_sink_unavailable"
        return result

    def require(self, *args: Any, **kwargs: Any) -> SafetyDecisionV1:
        decision = self.decide(*args, **kwargs)
        if decision.decision != "allowed":
            raise SafetyViolation(
                decision.reason_code,
                f"Safety kernel blocked action: {decision.reason_code}",
            )
        return decision

    def account(
        self,
        session_id: str,
        job_id: str,
        target: str,
        *,
        response_bytes: int = 0,
        upload_bytes: int = 0,
        credential_attempt: bool = False,
        budget: Optional[ResourceBudgetV1] = None,
        attempt_id: str = "",
        tool_run_id: str = "",
    ) -> None:
        budget = budget or ResourceBudgetV1()
        origin = self.origin(target)
        deltas = {
            "requests": 1,
            "download": max(0, int(response_bytes)),
            "upload": max(0, int(upload_bytes)),
            "credentials": 1 if credential_attempt else 0,
        }
        if self.repository and hasattr(self.repository, "consume_resource_budget"):
            try:
                allowed = self.repository.consume_resource_budget(
                    session_id=session_id,
                    job_id=job_id,
                    attempt_id=attempt_id,
                    tool_run_id=tool_run_id,
                    origin=origin,
                    deltas=deltas,
                    budget=budget,
                )
                if allowed is False:
                    raise SafetyViolation("budget_exhausted", "Durable safety budget exhausted.")
                return
            except SafetyViolation:
                raise
            except Exception as exc:
                raise SafetyViolation("audit_sink_unavailable", "Durable budget sink unavailable.") from exc

        key = (job_id or session_id, origin)
        with self._lock:
            usage = self._usage[key]
            for name, value in deltas.items():
                usage[name] += value
            if (
                usage["requests"] > budget.max_requests
                or usage["download"] > budget.max_download_bytes
                or usage["upload"] > budget.max_upload_bytes
                or usage["credentials"] > budget.max_credential_attempts
            ):
                raise SafetyViolation("budget_exhausted", "Per-job safety budget exhausted.")

    def record_response(self, session_id: str, job_id: str, target: str, status_code: int) -> None:
        origin = self.origin(target)
        key = (job_id or session_id, origin)
        with self._lock:
            if int(status_code) in {429, 503}:
                self._failures[key] += 1
            else:
                self._failures[key] = max(0, self._failures[key] - 1)
            if self._failures[key] >= 5:
                self._open_until[key] = time.monotonic() + 30.0

    def check_redirect(
        self,
        session_id: str,
        current_url: str,
        location: str,
        allow_private: bool = False,
        *,
        job_id: str = "",
        attempt_id: str = "",
        tool_run_id: str = "",
        approved: bool = False,
        mutation: bool = False,
    ) -> str:
        target = urljoin(current_url, location)
        self.require(
            session_id,
            "http_redirect",
            target,
            job_id=job_id,
            attempt_id=attempt_id,
            tool_run_id=tool_run_id,
            approved=approved,
            mutation=mutation,
            allow_private=allow_private,
        )
        return target

    def provider_for(self, target: str) -> str:
        providers = {}
        try:
            from core.config_loader import get_config
            providers = (get_config().get("safety", {}) or {}).get("egress_providers", {}) or {}
        except Exception:
            return ""
        origin = self.origin(target)
        for provider_id, configured in providers.items():
            if str(provider_id) == "oob" and self._oob_target_allowed(target):
                return "oob"
            allowed_origins = self._provider_origins(provider_id, configured)
            if origin in allowed_origins:
                return str(provider_id)
        return ""

    @staticmethod
    def _oob_target_allowed(target: str) -> bool:
        """Allow only the configured OOB host and its generated subdomains."""
        configured_url = os.environ.get("OOB_SERVER_URL", "").strip()
        configured_domain = os.environ.get("OOB_DOMAIN", "").strip().lower().rstrip(".")
        if configured_url:
            configured = urlsplit(configured_url)
            scheme = configured.scheme.lower()
            hostname = (configured.hostname or "").lower().rstrip(".")
        else:
            scheme = "http"
            hostname = configured_domain
        parsed = urlsplit(str(target or ""))
        candidate = (parsed.hostname or "").lower().rstrip(".")
        if not hostname or parsed.scheme.lower() != scheme:
            return False
        return candidate == hostname or candidate.endswith("." + hostname)

    @staticmethod
    def _provider_origins(provider_id: str, configured: Any) -> set[str]:
        """Resolve provider origins, including the operator-owned OOB URL.

        OOB registration/polling is control-plane traffic, not target egress.
        The origin is still exact and comes from the deployment environment;
        an empty static ``oob.origins`` list therefore cannot accidentally
        authorize arbitrary internet destinations.
        """
        allowed_origins = configured if isinstance(configured, list) else (configured or {}).get("origins", [])
        origins = {str(item).rstrip("/").lower() for item in allowed_origins if item}
        if str(provider_id) == "oob":
            configured_url = os.environ.get("OOB_SERVER_URL", "").strip()
            configured_domain = os.environ.get("OOB_DOMAIN", "").strip()
            if configured_url:
                origins.add(SafetyKernel.origin(configured_url))
            elif configured_domain:
                origins.add(SafetyKernel.origin(f"http://{configured_domain}"))
        return origins

    def _validate_provider(self, provider_id: str, target: str) -> None:
        providers = {}
        try:
            from core.config_loader import get_config
            providers = (get_config().get("safety", {}) or {}).get("egress_providers", {}) or {}
        except Exception:
            providers = {}
        configured = providers.get(provider_id)
        if configured is None:
            raise SafetyViolation("provider_not_allowlisted", f"Provider '{provider_id}' is not allowlisted.")
        if str(provider_id) == "oob" and self._oob_target_allowed(target):
            self._validate_provider_addresses(target)
            return
        if self.origin(target) not in self._provider_origins(provider_id, configured):
            raise SafetyViolation("provider_origin_rejected", "Provider origin is not allowlisted.")
        self._validate_provider_addresses(target)

    def _validate_provider_addresses(self, target: str) -> None:
        """Prevent allowlisted provider names from resolving into private space."""
        parsed = urlsplit(str(target))
        if not parsed.hostname:
            raise SafetyViolation("invalid_target", "Provider target has no hostname.")
        try:
            addresses = {
                item[4][0]
                for item in socket.getaddrinfo(
                    parsed.hostname,
                    parsed.port or (443 if parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
            }
        except OSError as exc:
            raise SafetyViolation("dns_failed", f"Provider DNS resolution failed: {redact(str(exc))[:300]}") from exc
        if self._is_metadata_target(parsed.hostname, addresses):
            raise SafetyViolation("metadata_target_rejected", "Provider target resolved to metadata or link-local space.")
        if any(self._is_private_or_reserved(item) for item in addresses):
            raise SafetyViolation("private_ip_rejected", "Provider target resolved to a private or reserved IP.")

    def _validate_url(self, session_id: str, target: str, allow_private: bool = False) -> None:
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise SafetyViolation("invalid_target", "Only HTTP(S) URLs with a hostname are allowed.")
        if self.session_store and session_id:
            allowed, reason = self.session_store.validate_active_scope(session_id, target)
            if not allowed:
                raise SafetyViolation("scope_rejected", reason)
        try:
            addresses = {
                item[4][0]
                for item in socket.getaddrinfo(
                    parsed.hostname,
                    parsed.port or (443 if parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
            }
        except OSError as exc:
            raise SafetyViolation("dns_failed", f"DNS resolution failed: {redact(str(exc))[:300]}") from exc
        if self._is_metadata_target(parsed.hostname, addresses):
            raise SafetyViolation("metadata_target_rejected", "Cloud metadata and link-local targets are never allowed.")
        # The caller-provided flag is intentionally ignored. Private access
        # must come from the active session scope, otherwise a tool or a
        # redirect could turn it into an SSRF bypass.
        scope_allows_private = self._scope_explicitly_allows_private(session_id, parsed.hostname)
        if not scope_allows_private and any(self._is_private_or_reserved(item) for item in addresses):
            raise SafetyViolation("private_ip_rejected", "Resolved target includes a private or reserved IP.")

    def _scope_explicitly_allows_private(self, session_id: str, hostname: str) -> bool:
        """Allow private addresses only with an explicit session rule.

        The global safety default remains deny. Any private target—including a
        non-lab internal service—must be covered by an exact session allow rule
        carrying ``allow_private: true``. The flag is never inferred from the
        target or from a public DNS result.
        """
        if not self.session_store or not session_id:
            return False
        try:
            context = self.session_store.get(session_id) or {}
        except Exception:
            return False
        for rule in context.get("scope_rules") or []:
            if (
                rule.get("rule_type") == "allow"
                and bool(rule.get("allow_private", False))
                and self._scope_rule_matches_host(hostname, rule)
            ):
                return True
        return False

    @staticmethod
    def _scope_rule_matches_host(hostname: str, rule: Dict[str, Any]) -> bool:
        """Match an explicit hostname, IP, or CIDR scope rule."""
        host = str(hostname or "").lower().rstrip(".")
        pattern = str(rule.get("pattern") or "").strip().lower().rstrip(".")
        if pattern and fnmatch.fnmatch(host, pattern):
            return True
        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            host_ip = None
        patterns = list(rule.get("private_cidrs") or [])
        if pattern and "/" in pattern:
            patterns.append(pattern)
        if host_ip is None:
            return False
        for cidr in patterns:
            try:
                if host_ip in ipaddress.ip_network(str(cidr).strip(), strict=False):
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _is_metadata_target(hostname: str, addresses: set[str]) -> bool:
        candidate = str(hostname or "").lower().rstrip(".")
        if candidate in _METADATA_HOSTS or candidate.endswith(".metadata.google.internal"):
            return True
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if ip in _METADATA_IPS or ip.is_link_local:
                return True
        return False

    @staticmethod
    def _is_private_or_reserved(value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
            return bool(
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            )
        except ValueError:
            return True

    @staticmethod
    def _safe_target(value: str) -> str:
        parsed = urlsplit(str(value))
        if not parsed.scheme or not parsed.netloc:
            return redact(str(value))[:500]
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path[:300]}"

    @staticmethod
    def origin(url: str) -> str:
        parsed = urlsplit(url)
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


class GuardedHttpClient:
    """Requests-compatible client with per-context scope and budget checks."""

    def __init__(
        self,
        kernel: SafetyKernel,
        session_id: str,
        job_id: str = "",
        attempt_id: str = "",
        tool_run_id: str = "",
        budget: Optional[ResourceBudgetV1] = None,
    ):
        self.kernel = kernel
        self.session_id = session_id
        self.job_id = job_id
        self.attempt_id = attempt_id
        self.tool_run_id = tool_run_id
        self.budget = budget or ResourceBudgetV1()
        # Requests honours HTTP(S)_PROXY from the worker environment unless a
        # session opts out.  That made a direct local-lab request appear as a
        # proxy failure even though the target was reachable.  The egress
        # decision must be made by Nexus, never inherited from the host.
        self._session = requests.Session()
        self._session.trust_env = False

    @staticmethod
    def _validated_proxy(value: Any) -> Optional[Dict[str, str]]:
        """Allow only the exact operator-configured proxy reference."""
        if value in (None, {}, ""):
            return None
        if not isinstance(value, dict):
            raise SafetyViolation(
                "proxy_not_configured",
                "Proxy configuration must be an operator-configured mapping.",
            )
        configured = os.environ.get("NEXUS_OPERATOR_PROXY_URL", "").strip()
        expected = {"http": configured, "https": configured} if configured else None
        normalized = {str(key): str(item) for key, item in value.items()}
        if expected is None or normalized != expected:
            raise SafetyViolation(
                "proxy_not_configured",
                "Arbitrary proxy use is disabled; use the operator-configured egress reference.",
            )
        return expected

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        headers = kwargs.pop("headers", {}) or {}
        mutation = method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
        approved = bool(kwargs.pop("approved", False))
        allow_private = bool(kwargs.pop("allow_private", False))
        provider_id = str(kwargs.pop("provider_id", "") or "")
        credential_attempt = bool(kwargs.pop("credential_attempt", False))
        requested_redirects = bool(kwargs.pop("allow_redirects", False))
        configured_proxy = self._validated_proxy(kwargs.pop("proxies", None))
        kwargs["verify"] = True
        kwargs["headers"] = headers
        kwargs.setdefault("timeout", 10)
        kwargs["allow_redirects"] = False
        if configured_proxy:
            kwargs["proxies"] = configured_proxy

        current_url = url
        for _hop in range(6):
            self.kernel.require(
                self.session_id,
                f"http_{method.lower()}",
                current_url,
                job_id=self.job_id,
                attempt_id=self.attempt_id,
                tool_run_id=self.tool_run_id,
                budget=self.budget,
                approved=approved,
                mutation=mutation,
                allow_private=allow_private,
                provider_id=provider_id,
            )
            response = self._session.request(method, current_url, **kwargs)
            captured = min(len(response.content), self.budget.max_response_bytes)
            self.kernel.account(
                self.session_id,
                self.job_id,
                current_url,
                response_bytes=captured,
                upload_bytes=self._upload_bytes(kwargs),
                credential_attempt=credential_attempt,
                budget=self.budget,
                attempt_id=self.attempt_id,
                tool_run_id=self.tool_run_id,
            )
            self.kernel.record_response(self.session_id, self.job_id, current_url, response.status_code)
            location = response.headers.get("Location")
            if not requested_redirects or not location:
                return response
            current_url = self.kernel.check_redirect(
                self.session_id,
                current_url,
                location,
                allow_private=allow_private,
                job_id=self.job_id,
                attempt_id=self.attempt_id,
                tool_run_id=self.tool_run_id,
                approved=approved,
                mutation=mutation,
            )
        raise SafetyViolation("redirect_limit", "Redirect limit exceeded.")

    @staticmethod
    def _upload_bytes(kwargs: Dict[str, Any]) -> int:
        body = kwargs.get("data", kwargs.get("json", b""))
        if body is None:
            return 0
        if isinstance(body, (bytes, bytearray, str)):
            return len(body)
        try:
            import json
            return len(json.dumps(body, default=str).encode())
        except Exception:
            return 0

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("DELETE", url, **kwargs)


def build_safety_kernel(session_store: Any = None, repository: Any = None) -> SafetyKernel:
    return SafetyKernel(session_store=session_store, repository=repository)

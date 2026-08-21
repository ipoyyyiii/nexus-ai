"""Fail-closed scope, egress, budget, and approval boundary.

This module is one of the explicitly permitted runtime boundary modules. Tool
code must use core.tool_transport; it must not import requests/socket directly.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections import defaultdict
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlsplit

import requests

from core.execution_contract import ResourceBudgetV1, SafetyDecisionV1
from core.redact import redact


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
            allowed_origins = configured if isinstance(configured, list) else configured.get("origins", [])
            if origin in {str(item).rstrip("/").lower() for item in allowed_origins}:
                return str(provider_id)
        return ""

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
        allowed_origins = configured if isinstance(configured, list) else configured.get("origins", [])
        if self.origin(target) not in {str(item).rstrip("/").lower() for item in allowed_origins}:
            raise SafetyViolation("provider_origin_rejected", "Provider origin is not allowlisted.")

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
        if not allow_private and any(self._is_private_or_reserved(item) for item in addresses):
            raise SafetyViolation("private_ip_rejected", "Resolved target includes a private or reserved IP.")

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

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        headers = kwargs.pop("headers", {}) or {}
        mutation = method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
        approved = bool(kwargs.pop("approved", False))
        allow_private = bool(kwargs.pop("allow_private", False))
        provider_id = str(kwargs.pop("provider_id", "") or "")
        credential_attempt = bool(kwargs.pop("credential_attempt", False))
        requested_redirects = bool(kwargs.pop("allow_redirects", False))
        kwargs["verify"] = True
        kwargs["headers"] = headers
        kwargs.setdefault("timeout", 10)
        kwargs["allow_redirects"] = False

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
            response = requests.request(method, current_url, **kwargs)
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

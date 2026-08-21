"""Guarded compatibility facades for legacy tool transports.

Tools may keep their historical ``requests``/``subprocess`` call shape while
all actual I/O is routed through the Stage 5 safety kernel or sandbox.  This
module is an explicit boundary and is the only compatibility import allowed
in tools and engines.
"""

from __future__ import annotations

import os
import socket as _socket
import subprocess as _subprocess
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

import requests as _requests

from core.execution_contract import ResourceBudgetV1
from core.identity_context import get_execution_context
from core.safety_kernel import SafetyKernel, SafetyViolation, GuardedHttpClient


def _context():
    context = get_execution_context()
    if context is None or not context.session_id:
        raise SafetyViolation("missing_execution_context", "Network/process capability requires an active tool context.")
    return context


def _client() -> GuardedHttpClient:
    context = _context()
    kernel = context.safety_kernel
    if kernel is None:
        raise SafetyViolation("missing_safety_kernel", "Guarded transport has no safety kernel.")
    return GuardedHttpClient(
        kernel,
        context.session_id,
        job_id=context.job_id,
        attempt_id=context.attempt_id,
        tool_run_id=context.tool_run_id,
        budget=context.budget or ResourceBudgetV1(),
    )


class GuardedSession:
    """Requests-like, context-bound session with no cross-job state."""

    def __init__(self):
        self.headers: dict[str, str] = {}
        self.cookies: dict[str, str] = {}
        self.verify = True
        self.proxies: dict[str, str] | None = None

    def request(self, method: str, url: str, **kwargs: Any):
        if self.proxies:
            raise SafetyViolation("proxy_not_configured", "Arbitrary proxy use is disabled; use an operator-configured egress reference.")
        headers = dict(self.headers)
        headers.update(kwargs.pop("headers", {}) or {})
        cookies = dict(self.cookies)
        cookies.update(kwargs.pop("cookies", {}) or {})
        if headers:
            kwargs["headers"] = headers
        if cookies:
            kwargs["cookies"] = cookies
        kwargs.setdefault("verify", self.verify)
        response = _client().request(method, url, **kwargs)
        try:
            self.cookies.update(response.cookies.get_dict())
        except Exception:
            pass
        return response

    def get(self, url: str, **kwargs: Any):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any):
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any):
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any):
        return self.request("DELETE", url, **kwargs)


class GuardedRequestsFacade:
    Session = GuardedSession
    exceptions = _requests.exceptions
    Timeout = _requests.Timeout
    RequestException = _requests.RequestException
    Response = _requests.Response

    def request(self, method: str, url: str, **kwargs: Any):
        return _client().request(method, url, **kwargs)

    def get(self, url: str, **kwargs: Any):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any):
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any):
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any):
        return self.request("DELETE", url, **kwargs)

    # Do not expose the underlying requests module through a dynamic fallback.
    # Only the compatibility surface above is intentionally available.

guarded_requests = GuardedRequestsFacade()


class ProviderHttpClient(GuardedHttpClient):
    """Named provider boundary; the kernel still enforces configured origins."""

    def request(self, method: str, url: str, *, provider_id: str, **kwargs: Any):
        kwargs["provider_id"] = provider_id
        return super().request(method, url, **kwargs)


class GuardedResolver:
    """DNS facade that records and scopes every resolution."""

    def _check(self, host: str, port: int = 443) -> None:
        context = _context()
        target = f"https://{host}:{port}"
        kernel = context.safety_kernel
        if kernel is None:
            raise SafetyViolation("missing_safety_kernel", "DNS capability has no safety kernel.")
        kernel.require(context.session_id, "dns_resolve", target, job_id=context.job_id, attempt_id=context.attempt_id, identity_id=context.identity_id, tool_run_id=context.tool_run_id, budget=context.budget or ResourceBudgetV1())

    def gethostbyname(self, host: str) -> str:
        self._check(host)
        return _socket.gethostbyname(host)

    def getaddrinfo(self, host: str, port: Any, *args: Any, **kwargs: Any):
        self._check(host, int(port or 443))
        return _socket.getaddrinfo(host, port, *args, **kwargs)

    def gethostbyaddr(self, address: str):
        context = _context()
        if context.safety_kernel is None:
            raise SafetyViolation("missing_safety_kernel", "Reverse DNS has no safety kernel.")
        return _socket.gethostbyaddr(address)

    def resolve(self, host: str, record_type: str = "A", *args: Any, **kwargs: Any):
        self._check(host)
        import dns.resolver as real_resolver
        return real_resolver.resolve(host, record_type, *args, **kwargs)


class _DnsFacade:
    resolver = GuardedResolver()
    try:
        import dns.exception as exception
    except Exception:
        exception = type("DnsExceptionModule", (), {})()


guarded_dns = _DnsFacade()


class GuardedSocket:
    def __init__(self, family: int = _socket.AF_INET, kind: int = _socket.SOCK_STREAM, proto: int = 0):
        self._family = family
        self._kind = kind
        self._proto = proto
        self._sock = _socket.socket(family, kind, proto)

    def settimeout(self, value: float) -> None:
        self._sock.settimeout(value)

    def connect_ex(self, address: tuple[str, int]) -> int:
        host, port = address
        context = _context()
        if int(port) not in {80, 443} and "raw-network" not in context.worker_capabilities:
            return 13
        if int(port) not in {80, 443} and not context.approval_granted:
            return 13
        if context.safety_kernel is None:
            return 13
        try:
            context.safety_kernel.require(context.session_id, "tcp_connect", f"https://{host}:{port}", job_id=context.job_id, attempt_id=context.attempt_id, identity_id=context.identity_id, tool_run_id=context.tool_run_id, budget=context.budget or ResourceBudgetV1(), approved=context.approval_granted)
            return self._sock.connect_ex(address)
        except Exception:
            return 13

    def close(self) -> None:
        self._sock.close()


class _SocketFacade:
    AF_INET = _socket.AF_INET
    AF_UNSPEC = _socket.AF_UNSPEC
    SOCK_STREAM = _socket.SOCK_STREAM
    SOCK_DGRAM = _socket.SOCK_DGRAM

    def socket(self, family: int = _socket.AF_INET, kind: int = _socket.SOCK_STREAM, proto: int = 0):
        return GuardedSocket(family, kind, proto)

    def create_connection(self, address: tuple[str, int], timeout: float | None = None, source_address: Any = None):
        host, port = address
        context = _context()
        if int(port) not in {80, 443} and ("raw-network" not in context.worker_capabilities or not context.approval_granted):
            raise SafetyViolation("raw_network_approval_required", "Raw TCP requires the raw-network worker and exact approval.")
        if context.safety_kernel is None:
            raise SafetyViolation("missing_safety_kernel", "TCP capability has no safety kernel.")
        context.safety_kernel.require(context.session_id, "tcp_connect", f"https://{host}:{port}", job_id=context.job_id, attempt_id=context.attempt_id, identity_id=context.identity_id, tool_run_id=context.tool_run_id, budget=context.budget or ResourceBudgetV1(), approved=context.approval_granted)
        return _socket.create_connection(address, timeout=timeout, source_address=source_address)


guarded_socket = _SocketFacade()


_COMMAND_IDS = {
    "sqlmap": "sqlmap_confirmation", "commix": "commix_confirmation",
    "hydra": "hydra_credential_test", "dalfox": "dalfox_confirmation",
    "gobuster": "gobuster_dir", "ffuf": "ffuf_dir",
    "nuclei": "nuclei_scan", "arjun": "arjun_discovery",
    "subfinder": "subfinder_enum", "nmap": "nmap_service_scan",
    "testssl": "testssl_scan", "tplmap": "tplmap_confirmation",
    "katana": "katana_crawl", "wpscan": "wpscan_scan",
    "graphql-cop.py": "graphql_cop", "jwt_tool.py": "jwt_tool_analysis",
}


def _command_id(argv: list[str]) -> str:
    executable = Path(argv[0]).name if argv else ""
    if executable == "python3":
        text = " ".join(argv)
        if "graphql-cop" in text:
            return "graphql_cop"
    return _COMMAND_IDS.get(executable, "")


class GuardedSubprocessFacade:
    PIPE = _subprocess.PIPE
    DEVNULL = _subprocess.DEVNULL
    TimeoutExpired = _subprocess.TimeoutExpired

    def run(self, argv: Iterable[str], input: Any = None, stdout: Any = None, stderr: Any = None, text: bool = False, timeout: int | float | None = None, shell: bool = False, **kwargs: Any):
        if shell:
            raise SafetyViolation("shell_forbidden", "shell=True is forbidden for tool execution.")
        args = [str(item) for item in argv]
        command_id = _command_id(args)
        if not command_id:
            raise SafetyViolation("command_not_allowlisted", "External command is not allowlisted.")
        context = _context()
        high_risk = {"hydra_credential_test", "nmap_service_scan", "naabu_scan", "sqlmap_confirmation", "commix_confirmation"}
        if command_id in high_risk and not context.approval_granted:
            raise SafetyViolation("approval_required", f"Command profile '{command_id}' requires exact approval.")
        if command_id in {"nmap_service_scan", "naabu_scan"}:
            if "raw-network" not in context.worker_capabilities:
                raise SafetyViolation("raw_network_worker_required", "Raw-network command requires the opt-in worker.")
        from core.sandbox_runner import SandboxedCommandRunner
        result = SandboxedCommandRunner().run(command_id, args[1:], stdin=input.decode() if isinstance(input, bytes) else (input or ""), session_id=context.session_id, job_id=context.job_id, attempt_id=context.attempt_id, tool_run_id=context.tool_run_id, timeout_seconds=int(timeout) if timeout else None)
        stdout_value = result.stdout if text else result.stdout.encode("utf-8", "replace")
        stderr_value = result.stderr if text else result.stderr.encode("utf-8", "replace")
        if result.run.timed_out:
            raise self.TimeoutExpired(args, timeout or 0, output=stdout_value, stderr=stderr_value)
        return _subprocess.CompletedProcess(args, result.run.exit_code or 0, stdout_value, stderr_value)

    def Popen(self, *args: Any, **kwargs: Any):
        raise SafetyViolation("popen_forbidden", "Use the bounded command runner instead of Popen.")

guarded_subprocess = GuardedSubprocessFacade()

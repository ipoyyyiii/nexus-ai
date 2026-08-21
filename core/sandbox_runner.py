"""Allowlisted, process-group based external command runner."""

from __future__ import annotations

import hashlib
import os
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from core.execution_contract import SandboxRunV1
from core.redact import redact


class SandboxViolation(PermissionError):
    pass


@dataclass(frozen=True)
class CommandDefinition:
    command_id: str
    executable: str
    fixed_args: tuple[str, ...] = ()
    timeout_seconds: int = 120


COMMANDS: Dict[str, CommandDefinition] = {
    "httpx_probe": CommandDefinition("httpx_probe", "httpx", ("-silent", "-status-code", "-title", "-tech-detect", "-timeout", "8")),
    "naabu_scan": CommandDefinition("naabu_scan", "naabu", ("-top-ports", "1000", "-silent"), 120),
    "gowitness_shot": CommandDefinition("gowitness_shot", "gowitness", ("single", "--disable-db"), 120),
    "gau_urls": CommandDefinition("gau_urls", "gau", ("--threads", "5"), 120),
    "hakrawler_crawl": CommandDefinition("hakrawler_crawl", "hakrawler", ("-depth", "2", "-plain"), 120),
    "amass_enum": CommandDefinition("amass_enum", "amass", ("enum", "-passive", "-timeout", "2"), 180),
    "sqlmap_confirmation": CommandDefinition("sqlmap_confirmation", "sqlmap", ("--batch", "--disable-coloring"), 180),
    "commix_confirmation": CommandDefinition("commix_confirmation", "commix", ("--batch",), 180),
    "hydra_credential_test": CommandDefinition("hydra_credential_test", "hydra", (), 180),
    "dalfox_confirmation": CommandDefinition("dalfox_confirmation", "dalfox", ("pipe",), 180),
    "gobuster_dir": CommandDefinition("gobuster_dir", "gobuster", ("dir",), 180),
    "ffuf_dir": CommandDefinition("ffuf_dir", "ffuf", (), 180),
    "graphql_cop": CommandDefinition("graphql_cop", "python3", (), 180),
    "nuclei_scan": CommandDefinition("nuclei_scan", "nuclei", ("-jsonl", "-no-color"), 300),
    "arjun_discovery": CommandDefinition("arjun_discovery", "arjun", (), 180),
    "subfinder_enum": CommandDefinition("subfinder_enum", "subfinder", ("-silent",), 180),
    "nmap_service_scan": CommandDefinition("nmap_service_scan", "nmap", ("-Pn", "-T2"), 300),
    "testssl_scan": CommandDefinition("testssl_scan", "testssl", ("--quiet",), 300),
    "tplmap_confirmation": CommandDefinition("tplmap_confirmation", "tplmap", (), 180),
    "katana_crawl": CommandDefinition("katana_crawl", "katana", ("-silent",), 180),
    "wpscan_scan": CommandDefinition("wpscan_scan", "wpscan", ("--no-update",), 300),
}


@dataclass
class SandboxResult:
    run: SandboxRunV1
    stdout: str
    stderr: str


def _limits(memory_bytes: int, cpu_seconds: int, output_bytes: int, process_limit: int):
    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 2))
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_bytes, output_bytes))
        resource.setrlimit(resource.RLIMIT_NPROC, (process_limit, process_limit))
    return apply


class SandboxedCommandRunner:
    def __init__(self, command_registry: Optional[Dict[str, CommandDefinition]] = None, output_limit: int = 8 * 1024 * 1024):
        self.commands = command_registry or COMMANDS
        self.output_limit = max(1024, int(output_limit))

    def run(
        self,
        command_id: str,
        args: Iterable[str] = (),
        *,
        stdin: str = "",
        session_id: str = "",
        job_id: str = "",
        attempt_id: str = "",
        tool_run_id: str = "",
        timeout_seconds: Optional[int] = None,
        memory_bytes: int = 1024 * 1024 * 1024,
        process_limit: int = 64,
    ) -> SandboxResult:
        if self.commands is COMMANDS:
            try:
                from core.identity_context import get_execution_context
                if get_execution_context() is None:
                    raise SandboxViolation("missing_execution_context")
            except ImportError:
                raise SandboxViolation("missing_execution_context")
        definition = self.commands.get(command_id)
        if not definition:
            raise SandboxViolation(f"Command '{command_id}' is not allowlisted.")
        user_args = [str(item) for item in args]
        if any("\x00" in item for item in user_args):
            raise SandboxViolation("NUL bytes are not valid command arguments.")
        executable = shutil.which(definition.executable)
        if not executable:
            raise FileNotFoundError(definition.executable)
        argv = [executable, *definition.fixed_args, *user_args]
        run = SandboxRunV1(
            session_id=session_id, job_id=job_id, attempt_id=attempt_id,
            tool_run_id=tool_run_id, command_id=command_id, argv_redacted=[definition.executable, *user_args],
        )
        started = time.monotonic()
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp/nexus-home", "LC_ALL": "C"}
        with tempfile.TemporaryDirectory(prefix="nexus-sandbox-") as cwd:
            try:
                proc = subprocess.Popen(
                    argv,
                    stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd,
                    env=env,
                    text=True,
                    shell=False,
                    start_new_session=True,
                    preexec_fn=_limits(memory_bytes, max(1, int(timeout_seconds or definition.timeout_seconds)), self.output_limit, process_limit),
                )
                try:
                    stdout, stderr = proc.communicate(stdin, timeout=max(1, int(timeout_seconds or definition.timeout_seconds)))
                except subprocess.TimeoutExpired:
                    run.timed_out = True
                    os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        stdout, stderr = proc.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        stdout, stderr = proc.communicate()
                stdout = stdout or ""
                stderr = stderr or ""
                output = (stdout + stderr).encode("utf-8", "replace")[: self.output_limit]
                run.exit_code = proc.returncode
                run.status = "timed_out" if run.timed_out else ("succeeded" if proc.returncode == 0 else "failed")
                run.output_bytes = len(output)
                run.sha256 = hashlib.sha256(output).hexdigest()
                context = None
                try:
                    from core.identity_context import get_execution_context
                    context = get_execution_context()
                    audit_repository = context.repository if context else None
                    if (not audit_repository or not hasattr(audit_repository, "persist_sandbox_run")) and context and context.safety_kernel:
                        audit_repository = getattr(context.safety_kernel, "repository", None)
                    if audit_repository and hasattr(audit_repository, "persist_sandbox_run"):
                        audit_repository.persist_sandbox_run(run)
                except Exception as exc:
                    if context and (context.repository or (context.safety_kernel and context.safety_kernel.repository)):
                        raise SandboxViolation("sandbox_audit_unavailable") from exc
                return SandboxResult(run=run, stdout=redact(stdout)[: self.output_limit], stderr=redact(stderr)[: self.output_limit])
            except Exception as exc:
                run.status = "failed"
                run.error_code = type(exc).__name__
                raise


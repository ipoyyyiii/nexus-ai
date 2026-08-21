"""Canonical versioned registry for all public Nexus tools.

The source of truth is the public @tool name in tools/*.py. AST discovery is
used for startup/CI so registry compliance does not require live OOB/provider
credentials. Runtime resolution is lazy and never executes a tool.
"""

from __future__ import annotations

import ast
import functools
import importlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.redact import redact


class ToolCapabilityV1(BaseModel):
    schema_version: str = "1.0"
    tool_id: str
    public_name: str
    module: str
    function_name: str
    category: str = "unknown"
    archetype: str = "scanner"
    risk: str = "read_only"
    side_effect_class: str = "none"
    transports: List[str] = Field(default_factory=list)
    queue: str = "general"
    requires_identity: bool = False
    requires_approval: bool = False
    requires_cleanup: bool = False
    command_profile: str = ""
    output_contract: str = "ToolResultV1"
    tool_version: str = "1.0"
    policy_version: str = "1.0"
    enabled: bool = True
    model_config = ConfigDict(extra="ignore")


class RegistryIssue(BaseModel):
    tool_id: str = ""
    public_name: str = ""
    kind: str
    detail: str


def _tool_name(decorator: ast.AST) -> Optional[str]:
    if not isinstance(decorator, ast.Call):
        return None
    fn = decorator.func
    if not ((isinstance(fn, ast.Name) and fn.id == "tool") or (isinstance(fn, ast.Attribute) and fn.attr == "tool")):
        return None
    if decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
        return decorator.args[0].value
    for kw in decorator.keywords:
        if kw.arg in {"name", "tool_name"} and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def _infer(name: str, module: str) -> Dict[str, Any]:
    text = f"{name} {module}".lower()
    transports = ["target_http"]
    category = "scanner"
    archetype = "http_scanner"
    risk = "read_only"
    side_effect = "none"
    queue = "general"
    identity = any(x in text for x in ("auth", "access_control", "idor", "credential", "session", "oauth"))
    requires_approval = False
    cleanup = False
    command_profile = ""

    if any(x in text for x in ("httpx", "naabu", "gowitness", "gau", "hakrawler", "amass", "nuclei", "subfinder", "dir_bruteforce", "crawler")):
        transports = ["cli"]
        archetype = "external_cli"
    if any(x in text for x in ("dns", "subdomain", "takeover")):
        transports = ["dns"]
        archetype = "recon"
    if any(x in text for x in ("ssl", "tls", "certificate")):
        transports = ["tls"]
        archetype = "tls"
    if any(x in text for x in ("shodan", "censys", "github", "wayback", "crt", "bgp", "ip_api")):
        transports = ["provider_http"]
        archetype = "provider"
    if any(x in text for x in ("browser", "playwright", "human_recon")):
        transports = ["browser"]
        archetype = "browser"
    if any(x in text for x in ("race", "upload", "stored", "csrf", "mass_assignment", "command_injection", "xxe", "ssrf", "credential", "password_reset", "session_fixation", "method_tampering", "file_upload")):
        risk = "high"
        side_effect = "mutation_or_external_effect"
        requires_approval = True
        cleanup = True
    if any(x in text for x in ("credential", "hydra", "password")):
        risk = "critical"
        side_effect = "credential_attempt"
        requires_approval = True
        cleanup = False
    if "raw-network" in text or any(x in text for x in ("naabu", "nmap", "port_scan")):
        queue = "raw-network"
        transports = ["raw_network"] if "target_http" not in transports else transports + ["raw_network"]
        risk = "high"
        requires_approval = True
    if archetype == "external_cli":
        command_profile = name
    if any(x in text for x in ("recon", "discovery", "endpoint", "parameter", "js_analysis", "fingerprint", "waf", "misconfiguration", "header")):
        category = "recon"
        archetype = "recon" if archetype == "http_scanner" else archetype
    elif any(x in text for x in ("xss", "sqli", "injection", "ssti", "xxe", "ssrf", "deserialization", "cors", "redirect")):
        category = "injection"
    elif identity:
        category = "access_control"
    return {
        "category": category, "archetype": archetype, "risk": risk,
        "side_effect_class": side_effect, "transports": transports,
        "queue": queue, "requires_identity": identity,
        "requires_approval": requires_approval, "requires_cleanup": cleanup,
        "command_profile": command_profile,
    }


def discover_tool_registry(source_root: Optional[Path] = None) -> List[ToolCapabilityV1]:
    source_root = source_root or (Path(__file__).resolve().parent.parent / "tools")
    entries: List[ToolCapabilityV1] = []
    for path in sorted(source_root.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        module = f"tools.{path.stem}"
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                public_name = _tool_name(decorator)
                if not public_name:
                    continue
                inferred = _infer(public_name, module)
                entries.append(ToolCapabilityV1(
                    tool_id=f"tool.{public_name}",
                    public_name=public_name,
                    module=module,
                    function_name=node.name,
                    **inferred,
                ))
                break
    return entries


def validate_tool_registry(entries: Optional[Iterable[ToolCapabilityV1]] = None) -> List[RegistryIssue]:
    entries = list(entries if entries is not None else discover_tool_registry())
    issues: List[RegistryIssue] = []
    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    for entry in entries:
        if entry.tool_id in seen_ids:
            issues.append(RegistryIssue(tool_id=entry.tool_id, public_name=entry.public_name, kind="duplicate_id", detail="duplicate stable tool id"))
        seen_ids.add(entry.tool_id)
        if entry.public_name in seen_names:
            issues.append(RegistryIssue(tool_id=entry.tool_id, public_name=entry.public_name, kind="duplicate_name", detail="duplicate public name"))
        seen_names.add(entry.public_name)
        if entry.output_contract != "ToolResultV1":
            issues.append(RegistryIssue(tool_id=entry.tool_id, public_name=entry.public_name, kind="output_contract", detail="new tools must emit ToolResultV1"))
        if entry.requires_approval and entry.risk == "read_only":
            issues.append(RegistryIssue(tool_id=entry.tool_id, public_name=entry.public_name, kind="risk_policy", detail="approval-required tool cannot be read_only"))
    if len(entries) != 90:
        issues.append(RegistryIssue(kind="registry_count", detail=f"expected 90 public tools, found {len(entries)}"))
    return issues


@functools.lru_cache(maxsize=1)
def get_tool_registry() -> tuple[ToolCapabilityV1, ...]:
    entries = discover_tool_registry()
    issues = validate_tool_registry(entries)
    if issues and _strict_registry_mode():
        raise RuntimeError("Tool registry invalid: " + "; ".join(issue.detail for issue in issues))
    return tuple(entries)


def _strict_registry_mode() -> bool:
    try:
        from core.config_loader import get_setting
        return str(get_setting("tool_boundary_mode", "shadow")).lower() == "strict"
    except Exception:
        return False


def get_tool_capability(public_name: str) -> Optional[ToolCapabilityV1]:
    return next((entry for entry in get_tool_registry() if entry.public_name == public_name), None)


def resolve_tool(capability: ToolCapabilityV1) -> Any:
    module = importlib.import_module(capability.module)
    value = getattr(module, capability.function_name)
    return value

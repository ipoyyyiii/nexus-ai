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


# Bare ``@tool`` declarations use the Python function name as their public
# name.  The previous registry parser only handled ``@tool("name")`` and
# silently omitted those capabilities.
EXPECTED_PUBLIC_TOOL_COUNT = 103


# The planner speaks in stable Python-like capability names, while a handful
# of legacy tools still expose human-facing public names through @tool("...").
# Keep the public registry unchanged and resolve those names at the execution
# boundary instead of making every planner/consumer know both vocabularies.
TOOL_NAME_ALIASES = {
    "recon_target": "Active Recon Target",
    "scan_sql_injection": "SQL Injection Scanner",
    "detect_xss_csrf": "XSS & CSRF Detector",
    "scan_lfi_rfi": "LFI/RFI Scanner",
    "test_header_injection": "Header Injection Tester",
    "enumerate_subdomains": "DNS & Subdomain Enumerator",
    "analyze_ssl_tls": "SSL/TLS Analyzer",
    "test_api_security": "API Security Tester",
}


# This is an explicit execution policy, not a guess based on a tool/module
# name.  The entries below were audited against the tool implementations: each
# tool calls ``require_approval`` before it sends a probe, submits a form, or
# performs a potentially expensive/credentialed operation.  Keeping this list
# at the registry boundary prevents an autonomous caller from accidentally
# treating a legacy raw-string tool as safe merely because its name looks like
# a scanner.
APPROVAL_REQUIRED_TOOL_POLICY: Dict[str, Dict[str, Any]] = {
    name: {
        "requires_approval": True,
        "risk": "medium",
        "side_effect_class": "approval_controlled",
        "policy_version": "2.0",
    }
    for name in (
        "csrf_exploit_scanner",
        "mass_assignment_scanner",
        "http_method_tampering_scanner",
        "race_condition_scanner",
        "file_upload_scanner",
        "test_auth_rate_limiting",
        "command_injection_scanner",
        "cors_tester",
        "credential_reuse_scanner",
        "SQL Injection Scanner",
        "XSS & CSRF Detector",
        "LFI/RFI Scanner",
        "Header Injection Tester",
        "Tembak Request HTTP",
        "insecure_deserialization_scanner",
        "ssrf_advanced_scanner",
        "dir_bruteforce_scanner",
        "graphql_tester",
        "hpp_scanner",
        "html_injection_scanner",
        "blind_sqli_scanner",
        "nosql_injection_scanner",
        "oauth_flow_tester",
        "open_redirect_scanner",
        "param_discovery_post",
        "password_storage_analyzer",
        "login_automator",
        "browser_simulate_form",
        "ssi_injection_scanner",
        "ssl_scanner",
        "scan_ssrf",
        "scan_idor",
        "ssti_tester",
        "wp_scanner",
        "stored_xss_scanner",
        "xxe_tester",
    )
}

# These tools retain an in-tool checkpoint so a non-autonomous run can pause
# for operator review, but they are strictly GET-only.  In auto-pilot they are
# therefore admitted as read-only capabilities; the checkpoint helper itself
# still records the action and blocks when no execution context is present.
APPROVAL_REQUIRED_TOOL_POLICY.update({
    name: {
        "requires_approval": False,
        "risk": "read_only",
        "side_effect_class": "none",
        "policy_version": "2.1",
    }
    for name in (
        "param_discovery_get",
        "param_discovery_headers",
        "web_crawler",
    )
})


# Inference remains useful for legacy metadata, but these tools have a
# contract-level identity requirement.  The explicit values also correct
# false positives from the old substring heuristic (for example an ASN mapper
# living in auth_recon_tools).
IDENTITY_REQUIRED_TOOL_POLICY = {
    "access_control_scanner": True,
    "twofa_bypass_scanner": True,
    "idor_uuid_scanner": True,
    "session_management_scanner": True,
    "test_jwt_weakness": True,
    "jwt_tool_analysis": True,
    "authorization_differential_replay": True,
    "oauth_flow_tester": True,
    "inject_session": True,
    "scan_idor": True,
    "mixed_content_scanner": False,
    "postmessage_vulnerability_scanner": False,
    "asn_ip_mapper": False,
}


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
                if public_name is None and isinstance(decorator, ast.Name) and decorator.id == "tool":
                    public_name = node.name
                if not public_name:
                    continue
                inferred = _infer(public_name, module)
                inferred.update(APPROVAL_REQUIRED_TOOL_POLICY.get(public_name, {}))
                if public_name in IDENTITY_REQUIRED_TOOL_POLICY:
                    inferred["requires_identity"] = IDENTITY_REQUIRED_TOOL_POLICY[public_name]
                entries.append(ToolCapabilityV1(
                    tool_id=f"tool.{public_name}",
                    public_name=public_name,
                    module=module,
                    function_name=node.name,
                    **inferred,
                ))
                break
    return entries


def _checkpoint_tool_names(source_root: Path) -> set[str]:
    """Find tool declarations that call the approval checkpoint.

    This is a validation aid only. Runtime policy comes from the explicit
    ``APPROVAL_REQUIRED_TOOL_POLICY`` map above; AST inspection makes a future
    tool addition fail CI/strict startup instead of silently becoming an
    unreviewed autonomous capability.
    """
    names: set[str] = set()
    for path in sorted(source_root.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(isinstance(item, ast.Name) and item.id == "require_approval" for item in ast.walk(node)):
                continue
            public_name = node.name
            for decorator in node.decorator_list:
                declared = _tool_name(decorator)
                if declared:
                    public_name = declared
                    break
            names.add(public_name)
    return names


def validate_tool_registry(
    entries: Optional[Iterable[ToolCapabilityV1]] = None,
    source_root: Optional[Path] = None,
) -> List[RegistryIssue]:
    validate_source_policy = entries is None or source_root is not None
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
    if len(entries) != EXPECTED_PUBLIC_TOOL_COUNT:
        issues.append(RegistryIssue(kind="registry_count", detail=f"expected {EXPECTED_PUBLIC_TOOL_COUNT} public tools, found {len(entries)}"))
    if validate_source_policy:
        source_root = source_root or (Path(__file__).resolve().parent.parent / "tools")
        declared_checkpoint_tools = _checkpoint_tool_names(source_root)
        registry_names = {entry.public_name for entry in entries}
        for public_name in sorted(declared_checkpoint_tools - registry_names):
            issues.append(RegistryIssue(public_name=public_name, kind="checkpoint_unregistered", detail="approval-checkpoint tool is missing from the public registry"))
        for public_name in sorted(declared_checkpoint_tools & registry_names):
            if public_name not in APPROVAL_REQUIRED_TOOL_POLICY:
                issues.append(RegistryIssue(public_name=public_name, kind="checkpoint_policy_missing", detail="tool calls require_approval but has no explicit registry policy"))
    return issues


@functools.lru_cache(maxsize=1)
def get_tool_registry() -> tuple[ToolCapabilityV1, ...]:
    entries = discover_tool_registry()
    issues = validate_tool_registry(entries, source_root=Path(__file__).resolve().parent.parent / "tools")
    if issues:
        raise RuntimeError("Tool registry invalid: " + "; ".join(issue.detail for issue in issues))
    return tuple(entries)


def canonical_tool_name(public_name: str) -> str:
    """Return the registry-facing name for a planner/tool alias."""
    return TOOL_NAME_ALIASES.get(str(public_name or ""), str(public_name or ""))


def get_tool_capability(public_name: str) -> Optional[ToolCapabilityV1]:
    canonical = canonical_tool_name(public_name)
    return next((entry for entry in get_tool_registry() if entry.public_name == canonical), None)


def resolve_tool(capability: ToolCapabilityV1) -> Any:
    module = importlib.import_module(capability.module)
    value = getattr(module, capability.function_name)
    return value

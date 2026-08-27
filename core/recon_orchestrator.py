"""Deterministic multi-lane reconnaissance orchestration.

The project already has the reconnaissance tools.  This module is the missing
execution boundary that turns those tools into one auditable recon mission.
It deliberately does not create findings and it never treats an LLM message
as proof that a tool ran.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

from core.redact import redact
from core.structured_contract import ObservationV1, ToolErrorV1, ToolResultV1
from core.tool_registry import get_tool_capability, resolve_tool
from core.execution_contract import stable_digest
from core.identity_context import ToolExecutionContext, use_execution_context
from core.knowledge_graph_contract import (
    ApplicationContractInventoryV1,
    ApiOperationV1,
    InputSemanticV1,
    SurfaceEndpointV1,
    SurfaceInventoryV1,
    SurfaceParameterV1,
    TechnologyCapabilityV1,
    TechnologyFingerprintV1,
    TechnologySignalV1,
)


RECON_MISSION_SENTINEL = "__recon_mission__"

DEFAULT_FOLLOWUP_TOOLS = (
    "browser_extract_surface",
    "browser_intercept_requests",
    "browser_check_security_headers",
    "analyze_js_deep",
    "param_discovery_get",
    "client_side_security_scanner",
    "mixed_content_scanner",
    "postmessage_vulnerability_scanner",
)

# These capabilities describe public perimeter/internet intelligence.  They
# are not meaningful for a deliberately local Docker lab and, when run
# against an internal service name, can turn a harmless name-resolution or
# TLS refusal into a recon-wide circuit-breaker event.
LOCAL_LAB_PERIMETER_TOOLS = frozenset({
    "SSL/TLS Analyzer",
    "DNS & Subdomain Enumerator",
    "asn_ip_mapper",
    "amass_enum",
    "detect_subdomain_takeover",
    "gau_urls",
})


@dataclass(frozen=True)
class ReconToolSpec:
    public_name: str
    lane: str
    risk: str = "read_only"
    provider: bool = False
    r2: bool = False
    raw_network: bool = False
    approval_required: bool = False
    mutation: bool = False
    internal: bool = False


def _specs() -> tuple[ReconToolSpec, ...]:
    """Return the existing tools that are eligible for web/API recon.

    Vulnerability scanners, credential tools, race tools, and exploit tools
    intentionally do not belong here.  They are consumed by later phases.
    """
    names: list[ReconToolSpec] = [
        # WAF profiling is the perimeter seed.  It must run before the other
        # lanes so its bounded strategy can affect scheduling.
        ReconToolSpec("waf_behavior_profile", "perimeter", internal=True),
        # This legacy composite also performs raw TCP port checks.  Keep it
        # available as an explicitly approved R2 capability instead of
        # allowing a recon-only preset to silently scan infrastructure.
        ReconToolSpec("Active Recon Target", "perimeter", r2=True, raw_network=True, approval_required=True),
        ReconToolSpec("SSL/TLS Analyzer", "perimeter"),
        ReconToolSpec("ssl_scanner", "perimeter", r2=True, approval_required=True),
        ReconToolSpec("DNS & Subdomain Enumerator", "perimeter"),
        ReconToolSpec("asn_ip_mapper", "perimeter"),
        ReconToolSpec("httpx_probe", "perimeter"),
        ReconToolSpec("amass_enum", "perimeter"),
        ReconToolSpec("detect_subdomain_takeover", "perimeter"),
        ReconToolSpec("human_recon_crawl", "browser"),
        ReconToolSpec("browser_screenshot", "browser"),
        ReconToolSpec("browser_extract_surface", "browser"),
        ReconToolSpec("browser_intercept_requests", "browser"),
        ReconToolSpec("browser_extract_js_secrets", "browser"),
        ReconToolSpec("browser_check_security_headers", "browser"),
        ReconToolSpec("browser_storage_security_scanner", "browser"),
        ReconToolSpec("browser_cookie_inspector", "browser"),
        ReconToolSpec("browser_storage_inspector", "browser"),
        ReconToolSpec("browser_js_debugger", "browser"),
        ReconToolSpec("browser_workflow_discovery", "browser"),
        ReconToolSpec("web_crawler", "content"),
        ReconToolSpec("hakrawler_crawl", "content"),
        ReconToolSpec("gowitness_shot", "content"),
        ReconToolSpec("analyze_js_deep", "application"),
        ReconToolSpec("param_discovery_get", "application"),
        ReconToolSpec("param_discovery_headers", "application"),
        ReconToolSpec("client_side_security_scanner", "application"),
        ReconToolSpec("mixed_content_scanner", "application"),
        ReconToolSpec("postmessage_vulnerability_scanner", "application"),
        ReconToolSpec("misconfiguration_scanner", "application"),
        ReconToolSpec("gau_urls", "historical"),
        ReconToolSpec("wayback_scraper", "historical", provider=True),
        ReconToolSpec("github_dorking", "historical", provider=True),
        ReconToolSpec("shodan_scanner", "historical", provider=True),
        ReconToolSpec("censys_scanner", "historical", provider=True),
        # These are deliberately planned but gated.  recon_advanced contains
        # network discovery internally and param_discovery_post can mutate.
        ReconToolSpec("recon_advanced", "perimeter", r2=True),
        ReconToolSpec("naabu_scan", "perimeter", r2=True, raw_network=True, approval_required=True),
        ReconToolSpec("dir_bruteforce_scanner", "content", r2=True, approval_required=True),
        ReconToolSpec("wp_scanner", "content", r2=True, approval_required=True),
        ReconToolSpec("param_discovery_post", "application", r2=True, approval_required=True, mutation=True),
    ]
    return tuple(names)


def recon_tool_specs() -> tuple[ReconToolSpec, ...]:
    return _specs()


def recon_tool_names() -> list[str]:
    return [item.public_name for item in _specs()]


def _host(target: str) -> str:
    parsed = urlsplit(target)
    return (parsed.hostname or target).lower()


def _safe_key(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("_")[:80]


def _is_local_lab_target(target: str) -> bool:
    """Identify local fixture targets without weakening safety policy."""
    try:
        hostname = (urlsplit(str(target)).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if not hostname:
        return False
    if hostname in {"localhost", "host.docker.internal"} or "." not in hostname:
        return True
    if hostname.endswith((".local", ".test", ".internal", ".invalid")):
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return bool(address.is_private or address.is_loopback or address.is_link_local or address.is_reserved)


class ReconOrchestrator:
    """Plan and execute the current recon capability set through one boundary."""

    def __init__(
        self,
        *,
        session_store: Any = None,
        repository: Any = None,
        safety_kernel: Any = None,
        config: Optional[Dict[str, Any]] = None,
        registry_lookup: Callable[[str], Any] = get_tool_capability,
        tool_resolver: Callable[[Any], Any] = resolve_tool,
        runner: Any = None,
    ):
        self.session_store = session_store
        self.repository = repository
        self.safety_kernel = safety_kernel
        self.config = config or {}
        self.registry_lookup = registry_lookup
        self.tool_resolver = tool_resolver
        self.runner = runner
        self._waf_strategy: Dict[str, Any] = {}

    def _recon_config(self) -> Dict[str, Any]:
        configured = dict(self.config.get("recon") or {})
        try:
            from core.config_loader import get_config

            loaded = dict(get_config().get("recon") or {})
            loaded.update(configured)
            return loaded
        except Exception:
            return configured

    def _waf_config(self) -> Dict[str, Any]:
        configured = dict(self.config.get("waf_testing") or {})
        try:
            from core.config_loader import get_config

            loaded = dict(get_config().get("waf_testing") or {})
            loaded.update(configured)
            return loaded
        except Exception:
            return configured

    def _waf_suppresses(self, public_name: str) -> bool:
        suppressed = {str(item) for item in (self._waf_strategy.get("skip_tools") or [])}
        return public_name in suppressed

    @staticmethod
    def _waf_block_signal(result: ToolResultV1) -> bool:
        statuses = {int(item.status_code) for item in result.observations if item.status_code is not None}
        if statuses & {429, 503}:
            return True
        return bool(statuses & {403, 406} and result.tool_name != "waf_behavior_profile")

    def _explicit_local_lab_scope(self, target: str, session_id: str) -> bool:
        """Require the session's explicit private-scope opt-in for local skips.

        This is intentionally narrower than the global ``allow_private``
        safety switch.  A local target is only treated as a lab target when
        the active session both points at a local hostname and explicitly
        allows private addressing in a matching allow rule.
        """
        if not session_id or not self.session_store or not _is_local_lab_target(target):
            return False
        try:
            context = self.session_store.get(session_id) or {}
        except Exception:
            return False
        hostname = (urlsplit(str(target)).hostname or "").lower().rstrip(".")
        for rule in context.get("scope_rules") or []:
            if not isinstance(rule, dict):
                continue
            pattern = str(rule.get("pattern") or "").strip().lower()
            if (
                rule.get("rule_type") == "allow"
                and bool(rule.get("allow_private", False))
                and pattern
                and fnmatch.fnmatch(hostname, pattern)
            ):
                return True
        return False

    def is_mutating_recon_tool(self, public_name: str) -> bool:
        return any(item.public_name == public_name and item.mutation for item in _specs())

    def plan(
        self,
        target: str,
        session_id: str,
        *,
        selected_tools: Optional[Iterable[str]] = None,
        approval_granted: bool = False,
    ) -> List[Dict[str, Any]]:
        config = self._recon_config()
        selected = set(selected_tools) if selected_tools is not None else None
        output: list[dict[str, Any]] = []
        max_tools = max(1, int(config.get("max_tools", len(_specs())) or len(_specs())))
        eligible_count = 0
        local_lab_scope = self._explicit_local_lab_scope(target, session_id)

        for spec in _specs():
            if selected is not None and spec.public_name not in selected:
                continue

            row = {
                "schema_version": "1.0",
                "public_name": spec.public_name,
                "lane": spec.lane,
                "risk": spec.risk,
                "provider": spec.provider,
                "r2": spec.r2,
                "raw_network": spec.raw_network,
                "approval_required": spec.approval_required,
                "status": "eligible",
                "reason": "eligible",
            }

            if local_lab_scope and spec.public_name in LOCAL_LAB_PERIMETER_TOOLS:
                row.update(status="skipped", reason="local_lab_not_applicable")
            elif spec.internal:
                waf = self._waf_config()
                if not waf.get("enabled", True):
                    row.update(status="skipped", reason="waf_testing_disabled")
            elif self.registry_lookup(spec.public_name) is None:
                row.update(status="unavailable", reason="tool_not_registered")
            elif spec.provider and not bool(config.get("provider_queries_enabled", False)):
                row.update(status="skipped", reason="provider_queries_disabled")
            elif spec.raw_network and not bool(config.get("raw_network_enabled", False)):
                row.update(status="skipped", reason="raw_network_disabled")
            elif spec.r2 and not bool(config.get("r2_active_enabled", False)):
                row.update(status="skipped", reason="r2_active_disabled")
            elif spec.approval_required and not approval_granted:
                row.update(status="waiting_approval", reason="exact_approval_required")

            if row["status"] == "eligible":
                if eligible_count >= max_tools:
                    row.update(status="skipped", reason="recon_tool_budget_exhausted")
                else:
                    eligible_count += 1

            output.append(row)

        # A selected unknown tool is never silently ignored.
        if selected is not None:
            known = {item.public_name for item in _specs()}
            for name in sorted(selected - known):
                output.append({
                    "schema_version": "1.0",
                    "public_name": name,
                    "lane": "unknown",
                    "risk": "unknown",
                    "status": "unavailable",
                    "reason": "not_recon_capability",
                })
        return output

    def tool_kwargs(self, public_name: str, target: str, session_id: str, goal: str = "") -> Dict[str, Any]:
        host = _host(target)
        if public_name == "Active Recon Target":
            return {"url": target}
        if public_name == "SSL/TLS Analyzer":
            return {"domain": host}
        if public_name in {"ssl_scanner", "wp_scanner"}:
            return {"url": target}
        if public_name == "DNS & Subdomain Enumerator":
            return {"domain": host}
        if public_name == "asn_ip_mapper":
            return {"domain_or_ip": host}
        if public_name in {"httpx_probe", "gau_urls", "hakrawler_crawl", "amass_enum", "gowitness_shot"}:
            return {"target": target}
        if public_name == "detect_subdomain_takeover":
            return {"subdomain": host}
        if public_name == "human_recon_crawl":
            return {"url": target, "goal": goal, "session_id": session_id, "structured": True}
        if public_name == "browser_workflow_discovery":
            return {"url": target, "goal": goal, "session_id": session_id, "captures": "[]", "identity_ids": "[]"}
        if public_name == "web_crawler":
            return {"url": target, "depth": 2, "scope": "subdomain"}
        if public_name == "param_discovery_get":
            return {"url": target, "tech_stack": ""}
        if public_name == "param_discovery_post":
            return {"url": target, "content_type": "application/x-www-form-urlencoded"}
        if public_name == "github_dorking":
            return {"target_org": host}
        if public_name in {"wayback_scraper", "shodan_scanner", "censys_scanner"}:
            key = "domain" if public_name == "wayback_scraper" else "target"
            return {key: host}
        if public_name == "recon_advanced":
            return {"domain": host}
        if public_name == "naabu_scan":
            return {"target": target}
        if public_name == "dir_bruteforce_scanner":
            return {"url": target, "wordlist": "common"}
        return {"url": target}

    @staticmethod
    def _skip_result(plan: Dict[str, Any], target: str) -> ToolResultV1:
        reason = str(plan.get("reason") or "not_scheduled")
        return ToolResultV1(
            tool_name=str(plan.get("public_name") or "unknown"),
            category="recon",
            target=target,
            status="skipped" if plan.get("status") == "skipped" else "partial",
            summary=f"Recon capability not executed: {reason}.",
            errors=[ToolErrorV1(code=f"recon_{reason}", message=f"Recon capability not executed: {reason}.")],
        )

    def _runner(self) -> Any:
        if self.runner is not None:
            return self.runner
        from core.structured_runner import StructuredToolRunner

        self.runner = StructuredToolRunner(
            session_store=self.session_store,
            repository=self.repository,
            safety_kernel=self.safety_kernel,
        )
        return self.runner

    def _persist_skip(self, session_id: str, result: ToolResultV1) -> None:
        if session_id and self.repository:
            try:
                self.repository.persist(session_id, result, [])
            except Exception:
                # The execution result remains visible in the mission output;
                # persistence failures must not turn a skip into a false pass.
                pass

    def _run_waf_profile(self, target: str, session_id: str, job_id: str, approval_granted: bool) -> ToolResultV1:
        config = self._waf_config()
        recon_config = self._recon_config()
        active = bool(
            config.get("authorized", False)
            and config.get("mode") == "adaptive"
            and recon_config.get("r2_active_enabled", False)
            and approval_granted
        )
        tool_run_id = f"run_{uuid.uuid4().hex}"
        try:
            from tools.waf_detector import waf_detector

            kernel = self.safety_kernel
            if kernel is None:
                from core.safety_kernel import SafetyKernel
                kernel = SafetyKernel(session_store=self.session_store, repository=self.repository)
            context = ToolExecutionContext(
                session_id=session_id,
                job_id=job_id,
                target_origin=target,
                tool_run_id=tool_run_id,
                tool_name="waf_behavior_profile",
                config_snapshot={**self._recon_config(), "waf_testing": config},
                safety_kernel=kernel,
                repository=self.repository,
                approval_granted=approval_granted,
            )
            with use_execution_context(context):
                result = waf_detector.detect(
                    target,
                    active=active,
                    authorized=bool(config.get("authorized", False)),
                    approval_granted=approval_granted,
                )
            confidence_level = str(result.get("confidence", "none"))
            confidence = {"high": 0.9, "medium": 0.65, "low": 0.35, "none": 0.0}.get(confidence_level, 0.0)
            strategy = dict(result.get("strategy") or {})
            self._waf_strategy = {
                "domain": result.get("domain") or _host(target),
                "profile_id": result.get("profile_id", ""),
                **strategy,
            }
            summary = json.dumps(redact(result), sort_keys=True, default=str)
            observation = ObservationV1(
                role="baseline" if not active else "test",
                kind="waf_behavior",
                summary=summary[:2000],
                target_url=target,
                metadata={
                    "waf": result.get("waf", "unknown"),
                    "confidence": confidence,
                    "confidence_level": confidence_level,
                    "active_behavior_test": active,
                    "decision": "observation_only",
                    "asset_kind": "waf_profile",
                    "freshness": "live",
                    "strategy": strategy,
                    "profile_id": result.get("profile_id", ""),
                },
            )
            output = ToolResultV1(
                tool_run_id=tool_run_id,
                tool_name="waf_behavior_profile",
                category="recon",
                target=target,
                summary="WAF behavior profile collected; no vulnerability decision was made.",
                observations=[observation],
                metrics={
                    "waf": result.get("waf", "unknown"),
                    "confidence": confidence,
                    "confidence_level": confidence_level,
                    "active_behavior_test": active,
                    "strategy": strategy,
                    "active_requested": bool(result.get("active_requested", active)),
                    "active_blocked_without_approval": bool(result.get("active_blocked_without_approval", False)),
                },
            )
            if session_id and self.repository:
                self.repository.persist(session_id, output, [])
            return output
        except Exception as exc:
            return ToolResultV1(
                tool_name="waf_behavior_profile",
                category="recon",
                target=target,
                status="failed",
                summary="WAF behavior profile failed.",
                errors=[ToolErrorV1(code="waf_profile_error", message=str(exc))],
            )

    @staticmethod
    def knowledge_sources(target: str, plan: List[Dict[str, Any]], results: List[ToolResultV1], session_id: str = "") -> Dict[str, Any]:
        origins = [{"reference_id": "recon-origin", "url": target, "status": "observed"}]
        capabilities = []
        observations = []
        endpoints = []
        coverage = []
        assets = []
        ip_addresses = []
        certificates = []
        dns_records = []
        redirects = []
        technologies = []
        waf_profiles = []
        provider_observations = []
        parameters = []
        schemas = []
        static_assets = []
        graph_edges = []
        seen_endpoints: set[tuple[str, str]] = set()
        endpoint_refs: Dict[tuple[str, str], str] = {}
        seen_parameters: set[tuple[str, str, str]] = set()
        seen_schemas: set[str] = set()
        seen_static_assets: set[str] = set()
        seen_assets: set[tuple[str, str]] = set()

        def add_asset(reference_id: str, locator: str, asset_kind: str, *, status: str = "observed", source: str = "", freshness: str = "unknown", confidence: float = 0.5, evidence_ids: Optional[List[str]] = None, source_ids: Optional[List[str]] = None, metadata: Optional[Dict[str, Any]] = None) -> str:
            ref = _safe_key(reference_id or locator)
            key = (asset_kind, ref.lower())
            if not ref or key in seen_assets:
                return ""
            seen_assets.add(key)
            item = {
                "reference_id": f"asset-{ref}",
                "url": locator,
                "label": locator,
                "status": status,
                "evidence_ids": list(dict.fromkeys(evidence_ids or [])),
                "source_ids": list(dict.fromkeys(source_ids or [])),
                "metadata": {
                    "asset_kind": asset_kind,
                    "source": source,
                    "freshness": freshness,
                    "confidence": max(0.0, min(1.0, float(confidence))),
                    **(metadata or {}),
                },
            }
            if asset_kind == "hostname":
                assets.append(item)
            if asset_kind == "ip_address":
                ip_addresses.append({**item, "node_type": "ip_address"})
            elif asset_kind == "certificate":
                certificates.append({**item, "node_type": "certificate"})
            elif asset_kind == "dns_record":
                dns_records.append({**item, "node_type": "dns_record"})
            elif asset_kind == "redirect":
                redirects.append({**item, "node_type": "redirect"})
            elif asset_kind == "technology":
                technologies.append({**item, "node_type": "technology"})
            graph_edges.append({
                "source_reference_id": "recon-origin",
                "target_reference_id": item["reference_id"],
                "relation": "resolves_to" if asset_kind in {"hostname", "ip_address", "dns_record"} else "derived_from",
                "status": "supported" if item["evidence_ids"] else "hypothesized",
                "evidence_ids": item["evidence_ids"],
                "source_ids": item["source_ids"],
            })
            return item["reference_id"]

        def parse_json_summary(result: ToolResultV1) -> Dict[str, Any]:
            try:
                value = json.loads(str(result.summary or ""))
                return value if isinstance(value, dict) else {}
            except (TypeError, ValueError):
                return {}

        def endpoint_kind(url: str, method: str = "GET", resource_type: str = "", hint: str = "") -> str:
            value = f"{url} {hint}".lower()
            resource = str(resource_type or "").lower()
            if resource == "websocket" or value.startswith(("ws://", "wss://")):
                return "websocket"
            if "event-stream" in value or any(token in value for token in ("/sse", "/events", "/stream")):
                return "sse"
            if "graphql" in value:
                return "graphql"
            if any(token in value for token in ("openapi", "swagger", "api-docs")):
                return "schema"
            if resource in {"xhr", "fetch"} or any(token in value for token in ("/api/", "/v1/", "/v2/", "/rest/", ".json")):
                return "api"
            if value.endswith((".js", ".mjs", ".map")) or resource == "script":
                return "script"
            if value.endswith((".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")):
                return "static"
            if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and hint == "form":
                return "form"
            return "page"

        def add_endpoint(
            url: str,
            method: str,
            evidence_ids: List[str],
            source_id: str,
            *,
            kind: str = "",
            resource_type: str = "",
            hint: str = "",
            content_type: str = "",
            freshness: str = "live",
            confidence: float = 0.75,
            metadata: Optional[Dict[str, Any]] = None,
        ) -> str:
            canonical = ReconOrchestrator._same_origin_endpoint(url, target)
            if not canonical or len(endpoints) >= 500:
                return ""
            normalized_method = str(method or "GET").upper()
            key = (normalized_method, canonical)
            evidence = list(dict.fromkeys(item for item in evidence_ids if item))
            source_ids = [source_id] if source_id else []
            resolved_kind = kind or endpoint_kind(canonical, normalized_method, resource_type, hint)
            existing_ref = endpoint_refs.get(key)
            if existing_ref:
                existing = next((item for item in endpoints if item.get("reference_id") == existing_ref), None)
                if existing:
                    existing["evidence_ids"] = sorted(set(existing.get("evidence_ids", []) + evidence))
                    existing["source_ids"] = sorted(set(existing.get("source_ids", []) + source_ids))
                    existing["metadata"] = redact({**existing.get("metadata", {}), **(metadata or {}), "endpoint_kind": resolved_kind, "freshness": freshness, "confidence": max(float(existing.get("metadata", {}).get("confidence", 0.0) or 0.0), float(confidence))})
                return existing_ref
            endpoint_ref = f"endpoint-{stable_digest({'method': normalized_method, 'url': canonical}, 24)}"
            seen_endpoints.add(key)
            endpoint_refs[key] = endpoint_ref
            typed = SurfaceEndpointV1(
                reference_id=endpoint_ref,
                locator=canonical,
                method=normalized_method,
                endpoint_kind=resolved_kind,
                freshness="historical" if freshness == "historical" else "live",
                confidence=max(0.0, min(1.0, float(confidence))),
                content_type=content_type,
                evidence_ids=evidence,
                source_ids=source_ids,
                metadata=redact({**(metadata or {}), "endpoint_kind": resolved_kind, "freshness": freshness}),
            )
            item = typed.as_graph_source()
            item["metadata"] = redact({**item.get("metadata", {}), "endpoint_kind": resolved_kind, "freshness": freshness, "confidence": typed.confidence})
            endpoints.append(item)
            graph_edges.append({
                "source_reference_id": "recon-origin",
                "target_reference_id": endpoint_ref,
                "relation": "exposes",
                "status": "supported" if evidence else "hypothesized",
                "evidence_ids": evidence,
                "source_ids": source_ids,
            })
            return endpoint_ref

        def add_parameter(
            endpoint_url: str,
            method: str,
            name: str,
            location: str,
            evidence_ids: List[str],
            source_id: str,
            *,
            required: bool = False,
            data_type: str = "unknown",
            metadata: Optional[Dict[str, Any]] = None,
        ) -> None:
            clean_name = redact(str(name or "")).strip()[:200]
            if not clean_name:
                return
            endpoint_ref = add_endpoint(endpoint_url, method, evidence_ids, source_id, hint="api")
            if not endpoint_ref:
                return
            clean_location = str(location or "unknown").lower()
            if clean_location not in {"query", "path", "body", "header", "cookie", "form", "unknown"}:
                clean_location = "unknown"
            key = (endpoint_ref, clean_location, clean_name.lower())
            if key in seen_parameters:
                return
            seen_parameters.add(key)
            typed = SurfaceParameterV1(
                reference_id=f"parameter-{stable_digest({'endpoint': endpoint_ref, 'location': clean_location, 'name': clean_name}, 24)}",
                endpoint_reference_id=endpoint_ref,
                name=clean_name,
                location=clean_location,
                method=str(method or "GET").upper(),
                required=bool(required),
                data_type=redact(str(data_type or "unknown"))[:100],
                evidence_ids=list(dict.fromkeys(evidence_ids)),
                source_ids=[source_id] if source_id else [],
                metadata=redact(metadata or {}),
            )
            parameters.append(typed.as_graph_source())

        def add_schema(endpoint_url: str, source_id: str, evidence_ids: List[str], schema_format: str, metadata: Optional[Dict[str, Any]] = None) -> None:
            endpoint_ref = add_endpoint(endpoint_url, "GET", evidence_ids, source_id, kind="schema", hint="openapi")
            if not endpoint_ref:
                return
            ref = f"schema-{stable_digest({'endpoint': endpoint_ref, 'format': schema_format}, 24)}"
            if ref in seen_schemas:
                return
            seen_schemas.add(ref)
            schemas.append({
                "reference_id": ref,
                "node_type": "schema",
                "url": endpoint_url,
                "label": redact(schema_format)[:100],
                "status": "observed",
                "evidence_ids": list(dict.fromkeys(evidence_ids)),
                "source_ids": [source_id] if source_id else [],
                "metadata": redact({"endpoint_reference_id": endpoint_ref, "format": schema_format, **(metadata or {})}),
            })

        def add_static_asset(url: str, source_id: str, evidence_ids: List[str], asset_kind: str = "script") -> None:
            canonical = ReconOrchestrator._same_origin_endpoint(url, target)
            if not canonical or canonical in seen_static_assets or len(static_assets) >= 300:
                return
            seen_static_assets.add(canonical)
            static_assets.append({
                "reference_id": f"static-{stable_digest(canonical, 24)}",
                "node_type": "asset",
                "url": canonical,
                "label": canonical.rsplit("/", 1)[-1][:120],
                "status": "observed",
                "evidence_ids": list(dict.fromkeys(evidence_ids)),
                "source_ids": [source_id] if source_id else [],
                "metadata": {"asset_kind": asset_kind},
            })

        for item in plan:
            name = str(item.get("public_name") or "")
            capability_key = name
            if item.get("is_followup"):
                capability_key = f"{name}-{item.get('target', '')}-{item.get('depth', 0)}"
            capabilities.append({
                "reference_id": f"recon-capability-{_safe_key(capability_key)}",
                "label": name,
                "status": "observed" if item.get("status") == "eligible" else str(item.get("status")),
                "metadata": {"lane": item.get("lane"), "reason": item.get("reason")},
            })

        for result in results:
            parsed_summary = parse_json_summary(result)
            result_source = result.tool_run_id or result.tool_name
            evidence_ids = [item.observation_id for item in result.observations]
            if result.tool_name == "DNS & Subdomain Enumerator":
                domain = str(parsed_summary.get("domain") or _host(target)).lower()
                for record_type in ("A_records", "AAAA_records", "MX_records", "NS_records", "TXT_records"):
                    for value in parsed_summary.get(record_type) or []:
                        dns_ref = f"{domain}:{record_type}:{value}"
                        add_asset(dns_ref, f"dns://{domain}/{record_type}/{value}", "dns_record", source=result.tool_name, freshness="live", evidence_ids=evidence_ids, source_ids=[result_source], metadata={"record_type": record_type, "value": str(value)})
                        if record_type in {"A_records", "AAAA_records"}:
                            add_asset(str(value), f"https://{value}", "ip_address", source=result.tool_name, freshness="live", evidence_ids=evidence_ids, source_ids=[result_source], metadata={"resolved_from": domain, "record_type": record_type})
                for subdomain in parsed_summary.get("subdomains") or []:
                    host = str(subdomain).lower().rstrip(".")
                    add_asset(host, f"https://{host}", "hostname", source=result.tool_name, freshness="live", evidence_ids=evidence_ids, source_ids=[result_source], metadata={"parent_domain": domain})
            if result.tool_name in {"recon_advanced", "Advanced Recon"}:
                ct = parsed_summary.get("certificate_transparency") or {}
                for subdomain in ct.get("subdomains") or []:
                    host = str(subdomain).lower().rstrip(".")
                    add_asset(host, f"https://{host}", "hostname", status="observed", source="crt.sh", freshness="historical", confidence=0.75, evidence_ids=evidence_ids, source_ids=[result_source], metadata={"revalidation_required": True})
                    add_asset(f"cert:{host}", f"cert://{host}", "certificate", source="crt.sh", freshness="historical", confidence=0.75, evidence_ids=evidence_ids, source_ids=[result_source], metadata={"san": host, "revalidation_required": True})
            if result.tool_name in {"shodan_scanner", "censys_scanner", "wayback_scraper", "github_dorking"}:
                provider_observations.append({
                    "reference_id": f"provider-{_safe_key(result_source)}",
                    "node_type": "provider_observation",
                    "url": target,
                    "status": "stale" if result.tool_name in {"wayback_scraper", "github_dorking", "shodan_scanner", "censys_scanner"} else "observed",
                    "evidence_ids": evidence_ids,
                    "source_ids": [result_source],
                    "metadata": {"provider": result.tool_name, "freshness": "historical", "revalidation_required": True},
                })
            base_url = next((item.target_url for item in result.observations if item.target_url), target)
            if result.tool_name == "browser_extract_surface":
                for value in (parsed_summary.get("internal_links") or []) + (parsed_summary.get("api_endpoints_detected") or []):
                    add_endpoint(str(value), "GET", evidence_ids, result_source, hint="api" if "/api/" in str(value).lower() else "")
                for script_url in parsed_summary.get("script_sources") or []:
                    add_static_asset(urljoin(base_url, str(script_url)), result_source, evidence_ids, "script")
                for form in parsed_summary.get("forms") or []:
                    if not isinstance(form, dict):
                        continue
                    action = urljoin(base_url, str(form.get("action") or base_url))
                    method = str(form.get("method") or "GET").upper()
                    form_ref = add_endpoint(action, method, evidence_ids, result_source, hint="form", metadata={"source_surface": "html_form"})
                    for field in form.get("inputs") or []:
                        if isinstance(field, dict):
                            add_parameter(action, method, field.get("name") or field.get("id") or "", "form", evidence_ids, result_source, data_type=field.get("type") or "unknown", metadata={"form_endpoint_reference_id": form_ref})
                for field in parsed_summary.get("all_inputs") or []:
                    if isinstance(field, dict):
                        add_parameter(base_url, "GET", field.get("name") or field.get("id") or "", "form", evidence_ids, result_source, data_type=field.get("type") or "unknown", metadata={"outside_form": True})
            elif result.tool_name == "browser_intercept_requests":
                captures = []
                for key in ("captures", "xhr_and_fetch_requests", "api_flagged_requests"):
                    captures.extend(item for item in (parsed_summary.get(key) or []) if isinstance(item, dict))
                seen_capture_keys: set[tuple[str, str]] = set()
                for capture in captures:
                    capture_url = str(capture.get("url") or "")
                    method = str(capture.get("method") or "GET").upper()
                    capture_key = (method, capture_url)
                    if not capture_url or capture_key in seen_capture_keys:
                        continue
                    seen_capture_keys.add(capture_key)
                    response_headers = capture.get("response_headers") or {}
                    content_type = str(response_headers.get("content-type") or response_headers.get("Content-Type") or "")
                    ref = add_endpoint(capture_url, method, evidence_ids, result_source, resource_type=str(capture.get("resource_type") or ""), content_type=content_type, metadata={"response_status": capture.get("response_status"), "resource_type": capture.get("resource_type", "")})
                    post_data = str(capture.get("post_data") or "")
                    for name in re.findall(r"(?:^|[&,{])\s*[\"']?([A-Za-z_][A-Za-z0-9_.-]{0,80})[\"']?\s*[:=]", post_data):
                        add_parameter(capture_url, method, name, "body", evidence_ids, result_source, metadata={"request_capture": True, "endpoint_reference_id": ref})
                    if any(token in capture_url.lower() for token in ("openapi", "swagger", "api-docs")) or "openapi" in content_type.lower():
                        add_schema(capture_url, result_source, evidence_ids, "openapi_or_swagger", {"content_type": content_type})
            elif result.tool_name in {"analyze_js_deep", "Deep JS Analyzer"}:
                for value in parsed_summary.get("api_endpoints") or []:
                    value = urljoin(base_url, str(value))
                    add_endpoint(value, "GET", evidence_ids, result_source, hint="api", metadata={"source_surface": "javascript"})
                for value in parsed_summary.get("spa_routes") or []:
                    add_endpoint(urljoin(base_url, str(value)), "GET", evidence_ids, result_source, hint="spa_route", metadata={"source_surface": "javascript"})
                for hint in parsed_summary.get("graphql_hints") or []:
                    if isinstance(hint, dict):
                        gql_url = hint.get("endpoint") or hint.get("url") or base_url
                        add_endpoint(urljoin(base_url, str(gql_url)), "POST", evidence_ids, result_source, kind="graphql", metadata={"source_surface": "javascript", "introspection_observed": bool(hint.get("introspection_enabled", False))})
                for source_map in parsed_summary.get("source_maps") or []:
                    if isinstance(source_map, dict):
                        add_static_asset(urljoin(base_url, str(source_map.get("source_map") or source_map.get("js_file") or "")), result_source, evidence_ids, "source_map")
            elif result.tool_name == "param_discovery_get":
                for found in parsed_summary.get("discovered_params") or []:
                    if isinstance(found, dict):
                        add_parameter(base_url, "GET", found.get("parameter") or "", "query", evidence_ids, result_source, metadata={"discovery": "parameter_wordlist", "response_status": found.get("found_status")})
            elif result.tool_name == "web_crawler":
                for value in ReconOrchestrator.discovered_endpoints(result, target):
                    add_endpoint(value, "GET", evidence_ids, result_source, hint="crawler")
            for observation in result.observations:
                if observation.kind == "waf_behavior":
                    waf_profiles.append({
                        "reference_id": f"waf-{stable_digest({'target': observation.target_url or target, 'summary': observation.summary}, 24)}",
                        "node_type": "waf_profile",
                        "url": observation.target_url or target,
                        "label": str(observation.metadata.get("waf") or "unknown"),
                        "status": "observed",
                        "evidence_ids": [observation.observation_id],
                        "source_ids": [result.tool_run_id],
                        "metadata": redact(dict(observation.metadata)),
                    })
            for index, observation in enumerate(result.observations):
                source_id = result.tool_run_id
                ref = f"{source_id}-{index}"
                observations.append({
                    "reference_id": ref,
                    "label": result.tool_name,
                    "kind": observation.kind,
                    "url": observation.target_url or target,
                    "method": observation.method,
                    "status": "observed",
                    "evidence_ids": [observation.observation_id],
                    "source_ids": [source_id],
                    "metadata": observation.metadata,
                })
                endpoint = observation.target_url or ""
                add_endpoint(endpoint, observation.method or "GET", [observation.observation_id], source_id)

            for discovered in ReconOrchestrator.discovered_endpoints(result, target):
                add_endpoint(
                    discovered,
                    "GET",
                    [item.observation_id for item in result.observations],
                    result.tool_run_id,
                )

        # Stage 24 enriches the same canonical source set after all lanes have
        # been parsed.  This allows headers, browser assets, protocol captures,
        # TLS, schema, and WAF observations to be correlated deterministically.
        technology = ReconOrchestrator.technology_sources(target, results, endpoints)
        technologies.extend(technology.get("technology_fingerprints") or [])
        for capability in technology.get("technology_capabilities") or []:
            capabilities.append({
                "reference_id": capability.get("capability_id", ""),
                "label": capability.get("capability", ""),
                "status": capability.get("status", "suggested"),
                "metadata": redact({
                    "stage": 24,
                    "reason": capability.get("reason", ""),
                    "risk": capability.get("risk", "read_only"),
                    "approval_required": capability.get("approval_required", False),
                    "prerequisites": capability.get("prerequisites", []),
                    "fingerprint_ids": capability.get("fingerprint_ids", []),
                    "evidence_ids": capability.get("evidence_ids", []),
                }),
            })
        for fingerprint in technology.get("technology_fingerprints") or []:
            graph_edges.append({
                "source_reference_id": "recon-origin",
                "target_reference_id": fingerprint.get("reference_id", ""),
                "relation": "uses_technology",
                "status": "supported" if fingerprint.get("status") == "supported" else "hypothesized",
                "evidence_ids": fingerprint.get("evidence_ids", []),
                "source_ids": fingerprint.get("source_ids", []),
            })

        # Stage 25 derives semantic operations and input meanings from the
        # already canonicalized Stage 23 surface.  It is intentionally
        # read-only and feeds planning metadata, never a finding decision.
        contract = ReconOrchestrator.application_contract_sources(
            target,
            results,
            endpoints=endpoints,
            parameters=parameters,
            schemas=schemas,
        )
        # Stage 26 correlates the same passive captures into identity/session
        # and workflow intelligence. It never authenticates, submits forms, or
        # turns auth labels into authorization proof.
        identity_workflow = ReconOrchestrator.identity_workflow_sources(
            target, results, session_id=session_id, identity_id=""
        )
        graph_edges.extend(identity_workflow.get("identity_workflow_edges") or [])
        for auth_surface in identity_workflow.get("auth_surfaces") or []:
            graph_edges.append({
                "source_reference_id": "recon-origin",
                "target_reference_id": auth_surface.get("reference_id", ""),
                "relation": "guards",
                "status": "supported" if auth_surface.get("evidence_ids") else "hypothesized",
                "evidence_ids": auth_surface.get("evidence_ids", []),
                "source_ids": auth_surface.get("source_ids", []),
            })
        for prerequisite in identity_workflow.get("workflow_prerequisites") or []:
            graph_edges.append({
                "source_reference_id": prerequisite.get("reference_id", ""),
                "target_reference_id": prerequisite.get("workflow_id", ""),
                "relation": "prerequisite_for",
                "status": "inconclusive" if prerequisite.get("status") in {"missing", "inconclusive", "stale"} else "observed",
                "evidence_ids": prerequisite.get("evidence_ids", []),
                "source_ids": prerequisite.get("source_ids", []),
            })
        for operation in contract.get("application_operations") or []:
            graph_edges.append({
                "source_reference_id": operation.get("metadata", {}).get("endpoint_reference_id", ""),
                "target_reference_id": operation.get("reference_id", ""),
                "relation": "exposes",
                "status": "inconclusive" if operation.get("status") == "inconclusive" else "supported",
                "evidence_ids": operation.get("evidence_ids", []),
                "source_ids": operation.get("source_ids", []),
            })
        for semantic in contract.get("input_semantics") or []:
            graph_edges.append({
                "source_reference_id": semantic.get("metadata", {}).get("endpoint_reference_id", ""),
                "target_reference_id": semantic.get("reference_id", ""),
                "relation": "accepts",
                "status": "supported",
                "evidence_ids": semantic.get("evidence_ids", []),
                "source_ids": semantic.get("source_ids", []),
            })

        for endpoint in endpoints:
            coverage.append({
                "endpoint_reference_id": endpoint["reference_id"],
                "protocol": "http",
                "policy_id": "recon.surface.v1",
                "status": "tested" if endpoint.get("evidence_ids") else "untested",
                "evidence_ids": endpoint.get("evidence_ids", []),
                "source_ids": endpoint.get("source_ids", []),
            })
        for parameter in parameters:
            coverage.append({
                "endpoint_reference_id": parameter.get("metadata", {}).get("endpoint_reference_id", ""),
                "parameter_reference_id": parameter.get("reference_id", ""),
                "protocol": "http",
                "policy_id": "recon.surface.parameter.v1",
                "status": "untested",
                "evidence_ids": parameter.get("evidence_ids", []),
                "source_ids": parameter.get("source_ids", []),
            })
        inventory = SurfaceInventoryV1(
            target=target,
            endpoints=endpoints,
            parameters=parameters,
            schemas=schemas,
            static_assets=static_assets,
            source_ids=sorted({str(item.tool_run_id or item.tool_name) for item in results if item.tool_run_id or item.tool_name}),
            evidence_ids=sorted({item.observation_id for result in results for item in result.observations}),
        ).finalize()
        # Stage 27 consumes one explicit manifest instead of guessing which
        # recon lanes ran from free-form tool text.  This is metadata only;
        # it never dispatches a tool or promotes an observation to a finding.
        lane_manifest = {
            "perimeter": {
                "origins": len(origins), "assets": len(assets),
                "dns_records": len(dns_records), "certificates": len(certificates),
                "redirects": len(redirects), "waf_profiles": len(waf_profiles),
                "provider_observations": len(provider_observations),
            },
            "surface": {
                "endpoints": len(endpoints), "parameters": len(parameters),
                "schemas": len(schemas), "static_assets": len(static_assets),
            },
            "technology": {
                "fingerprints": len(technology.get("technology_fingerprints") or technologies),
                "signals": len(technology.get("technology_signals") or []),
                "capabilities": len(technology.get("technology_capabilities") or capabilities),
            },
            "application_contract": {
                "operations": len(contract.get("application_operations") or []),
                "inputs": len(contract.get("input_semantics") or []),
                "schemas": len(contract.get("application_schemas") or schemas),
                "flows": len(contract.get("data_flows") or []),
            },
            "identity_workflow": {
                "identities": len(identity_workflow.get("identities") or []),
                "auth_surfaces": len(identity_workflow.get("auth_surfaces") or []),
                "session_transitions": len(identity_workflow.get("session_transitions") or []),
                "workflows": len(identity_workflow.get("workflows") or []),
                "prerequisites": len(identity_workflow.get("workflow_prerequisites") or []),
            },
        }
        return {
            "origins": origins,
            "capabilities": capabilities,
            "observations": observations,
            "endpoints": endpoints,
            "coverage": coverage,
            "assets": assets,
            "ip_addresses": ip_addresses,
            "certificates": certificates,
            "dns_records": dns_records,
            "redirects": redirects,
            "technologies": technologies,
            "waf_profiles": waf_profiles,
            "provider_observations": provider_observations,
            "parameters": parameters,
            "schemas": schemas,
            "static_assets": static_assets,
            "surface_inventory": inventory.model_dump(mode="json"),
            **technology,
            **contract,
            **identity_workflow,
            "recon_lane_manifest": lane_manifest,
            "recon_source_digest": stable_digest(lane_manifest, 64),
            "edges": graph_edges,
        }

    @staticmethod
    def technology_sources(
        target: str,
        results: List[ToolResultV1],
        endpoints: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Compile technology/deployment intelligence from existing recon output.

        This is intentionally a correlation layer, not a second crawler.  It
        consumes typed observations already produced by browser, HTTP, TLS,
        schema, and WAF tools.  Only small, redacted signals are retained;
        raw headers, cookie values, response bodies, and tokens never become
        technology evidence.
        """
        signal_by_id: Dict[str, TechnologySignalV1] = {}
        endpoint_refs = {}
        for endpoint in endpoints or []:
            endpoint_refs[(str(endpoint.get("method") or "GET").upper(), str(endpoint.get("url") or ""))] = str(endpoint.get("reference_id") or "")

        def parse_summary(result: ToolResultV1) -> Dict[str, Any]:
            try:
                value = json.loads(str(result.summary or ""))
                return value if isinstance(value, dict) else {}
            except (TypeError, ValueError):
                return {}

        def source_ids(result: ToolResultV1) -> List[str]:
            return [str(result.tool_run_id or result.tool_name)]

        def evidence_ids(result: ToolResultV1) -> List[str]:
            return [str(item.observation_id) for item in result.observations if item.observation_id]

        def endpoint_ref(url: str, method: str = "GET") -> str:
            canonical = ReconOrchestrator._same_origin_endpoint(url, target)
            return endpoint_refs.get((str(method or "GET").upper(), canonical), "") if canonical else ""

        def add_signal(
            result: ToolResultV1,
            category: str,
            technology_name: str,
            source_kind: str,
            *,
            reliability: float,
            version: str = "",
            url: str = "",
            method: str = "GET",
            metadata: Optional[Dict[str, Any]] = None,
        ) -> None:
            if url and not ReconOrchestrator._same_origin_endpoint(url, target):
                return
            name = redact(str(technology_name or "")).strip().lower()[:120]
            if not name:
                return
            clean_version = redact(str(version or "")).strip()[:80]
            signal_material = {
                "target": ReconOrchestrator._same_origin_endpoint(url, target) or target,
                "category": category,
                "technology": name,
                "source_kind": source_kind,
                "version": clean_version,
                "source": source_ids(result),
                "endpoint": endpoint_ref(url, method),
            }
            signal_id = f"tsignal_{stable_digest(signal_material, 32)}"
            if signal_id in signal_by_id:
                return
            signal_by_id[signal_id] = TechnologySignalV1(
                signal_id=signal_id,
                category=category if category in {
                    "server", "runtime", "framework", "cms", "library", "cdn", "waf",
                    "auth", "protocol", "database", "deployment", "security_control",
                    "tls", "cache", "unknown",
                } else "unknown",
                name=category,
                value=name,
                source_kind=source_kind if source_kind in {
                    "header", "cookie_metadata", "html", "asset_path", "javascript",
                    "protocol", "schema", "tls", "waf_behavior", "tool_summary", "unknown",
                } else "unknown",
                target=ReconOrchestrator._same_origin_endpoint(url, target) or target,
                endpoint_reference_id=endpoint_ref(url, method),
                reliability=max(0.0, min(1.0, float(reliability))),
                freshness="live",
                evidence_ids=evidence_ids(result),
                source_ids=source_ids(result),
                metadata=redact({
                    "technology_name": name,
                    "version": clean_version,
                    **(metadata or {}),
                }),
            )

        def add_known_from_text(result: ToolResultV1, text: str, source_kind: str, *, reliability: float, url: str = "") -> None:
            if url and not ReconOrchestrator._same_origin_endpoint(url, target):
                return
            value = redact(str(text or "")).lower()
            signatures = (
                ("cms", "wordpress", ("wp-content", "wp-includes", "wordpress")),
                ("cms", "drupal", ("/sites/default/", "drupal")),
                ("cms", "joomla", ("/media/system/", "joomla")),
                ("framework", "next.js", ("_next/static", "__next_f", "next/data")),
                ("framework", "nuxt", ("__nuxt__", "_nuxt/")),
                ("framework", "angular", ("ng-version", "ng-app")),
                ("framework", "react", ("reactroot", "react.development", "react-dom")),
                ("framework", "vue", ("vue.runtime", "data-v-")),
                ("library", "jquery", ("jquery.min.js", "jquery-")),
                ("deployment", "source-map", (".js.map", "source_maps", "source map")),
                ("auth", "oauth", ("oauth", "/authorize", "/token", "openid")),
                ("auth", "oidc", ("openid-configuration", "oidc")),
                ("auth", "pkce", (("code_challenge", "code_verifier"))),
                ("security_control", "csrf", (("csrf", "xsrf"))),
            )
            for category, name, needles in signatures:
                if any(needle in value for needle in needles):
                    add_signal(result, category, name, source_kind, reliability=reliability, url=url)

        def parse_headers(result: ToolResultV1, summary: Dict[str, Any]) -> None:
            headers: Dict[str, Any] = {}
            for key in ("headers", "response_headers", "responseHeaders", "security_headers"):
                value = summary.get(key)
                if isinstance(value, dict):
                    headers.update(value)
            for observation in result.observations:
                for key in ("headers", "response_headers", "responseHeaders"):
                    value = observation.metadata.get(key)
                    if isinstance(value, dict):
                        headers.update(value)
            base_url = next((item.target_url for item in result.observations if item.target_url), target)
            for raw_key, raw_value in headers.items():
                key = str(raw_key or "").lower().strip()
                value = str(raw_value or "")
                if key in {"authorization", "proxy-authorization", "cookie", "x-api-key"}:
                    continue
                if key in {"set-cookie", "set_cookie"}:
                    # Preserve names and security attributes only; never the
                    # cookie value or an entire Set-Cookie header.
                    for cookie in re.split(r"[,\n]", value):
                        match = re.match(r"\s*([^=;\s]+)", cookie)
                        if not match:
                            continue
                        raw_cookie_name = match.group(1).lower()
                        safe_cookie_names = {
                            "laravel_session": "laravel-session",
                            "connect.sid": "express-session",
                            "sessionid": "django-session",
                            "csrftoken": "csrf-token",
                            "xsrf-token": "csrf-token",
                            "jsessionid": "java-session",
                            "next-auth.session-token": "next-auth-session",
                        }
                        cookie_name = safe_cookie_names.get(raw_cookie_name, f"cookie-{stable_digest(raw_cookie_name, 10)}")
                        attrs = {flag for flag in ("secure", "httponly", "samesite") if re.search(rf"\b{flag}\b", cookie, re.I)}
                        add_signal(result, "auth", f"cookie:{cookie_name}", "cookie_metadata", reliability=0.85, url=base_url, metadata={"attributes": sorted(attrs)})
                    continue
                lower_value = value.lower()
                if key == "server":
                    for name, tokens in (("cloudflare", ("cloudflare", "cloudflare")), ("nginx", ("nginx",)), ("apache", ("apache",)), ("iis", ("microsoft-iis", "iis"))):
                        if any(token in lower_value for token in tokens):
                            version_match = re.search(r"\b\d+(?:\.\d+){1,3}\b", value)
                            add_signal(result, "cdn" if name == "cloudflare" else "server", name, "header", reliability=0.9, version=version_match.group(0) if version_match else "", url=base_url)
                elif key == "x-powered-by":
                    for name, tokens, category in (("php", ("php",), "runtime"), ("express", ("express",), "framework"), ("asp.net", ("asp.net",), "runtime"), ("next.js", ("next",), "framework")):
                        if any(token in lower_value for token in tokens):
                            version_match = re.search(r"\b\d+(?:\.\d+){1,3}\b", value)
                            add_signal(result, category, name, "header", reliability=0.9, version=version_match.group(0) if version_match else "", url=base_url)
                elif key in {"cf-ray", "x-amz-cf-id", "x-cache", "via"}:
                    if "cf-ray" in key:
                        add_signal(result, "cdn", "cloudflare", "header", reliability=0.95, url=base_url)
                    elif "amz-cf" in key or "cloudfront" in lower_value:
                        add_signal(result, "cdn", "cloudfront", "header", reliability=0.95, url=base_url)
                    elif "hit" in lower_value or "miss" in lower_value or "cache" in lower_value:
                        add_signal(result, "cache", "http-cache", "header", reliability=0.75, url=base_url)
                elif key in {"content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"}:
                    add_signal(result, "security_control", key, "header", reliability=0.9, url=base_url)
                elif key in {"www-authenticate", "access-control-allow-origin"}:
                    if key == "www-authenticate":
                        add_signal(result, "auth", "http-auth", "header", reliability=0.85, url=base_url)
                elif key in {"cache-control", "age", "etag", "vary"}:
                    add_signal(result, "cache", key, "header", reliability=0.7, url=base_url)
            add_known_from_text(result, json.dumps(summary, default=str), "tool_summary", reliability=0.65, url=base_url)

        for result in results:
            summary = parse_summary(result)
            parse_headers(result, summary)
            base_url = next((item.target_url for item in result.observations if item.target_url), target)
            summary_text = json.dumps(summary, default=str)
            if result.tool_name in {"browser_extract_surface", "web_crawler", "hakrawler_crawl"}:
                add_known_from_text(result, summary_text, "html", reliability=0.75, url=base_url)
                for asset in (summary.get("script_sources") or []) + (summary.get("static_assets") or []):
                    asset_url = urljoin(base_url, str(asset))
                    add_known_from_text(result, asset_url, "asset_path", reliability=0.75, url=asset_url)
            if result.tool_name in {"analyze_js_deep", "Deep JS Analyzer"}:
                add_known_from_text(result, summary_text, "javascript", reliability=0.8, url=base_url)
                for key in ("frameworks", "libraries", "detected_technologies", "technology_hints"):
                    values = summary.get(key) or []
                    if isinstance(values, dict):
                        values = list(values.values())
                    for value in values if isinstance(values, list) else [values]:
                        if isinstance(value, dict):
                            value = value.get("name") or value.get("technology") or value.get("value")
                        if value:
                            add_signal(result, "library", str(value), "javascript", reliability=0.8, url=base_url)
            if result.tool_name == "browser_intercept_requests":
                captures = []
                for key in ("captures", "xhr_and_fetch_requests", "api_flagged_requests"):
                    captures.extend(item for item in (summary.get(key) or []) if isinstance(item, dict))
                for capture in captures:
                    capture_url = str(capture.get("url") or "")
                    method = str(capture.get("method") or "GET").upper()
                    ref = endpoint_ref(capture_url, method)
                    resource_type = str(capture.get("resource_type") or "").lower()
                    content_type = str((capture.get("response_headers") or {}).get("content-type") or "").lower()
                    lower_url = capture_url.lower()
                    if "graphql" in lower_url or "graphql" in content_type:
                        add_signal(result, "protocol", "graphql", "protocol", reliability=0.9, url=capture_url, method=method, metadata={"endpoint_reference_id": ref})
                    if resource_type == "websocket" or lower_url.startswith(("ws://", "wss://")):
                        add_signal(result, "protocol", "websocket", "protocol", reliability=0.95, url=capture_url, method=method, metadata={"endpoint_reference_id": ref})
                    if resource_type == "eventsource" or "text/event-stream" in content_type:
                        add_signal(result, "protocol", "sse", "protocol", reliability=0.95, url=capture_url, method=method, metadata={"endpoint_reference_id": ref})
                    if "openapi" in lower_url or "swagger" in lower_url or "api-docs" in lower_url:
                        add_signal(result, "protocol", "openapi", "schema", reliability=0.9, url=capture_url, method=method, metadata={"endpoint_reference_id": ref})
            if result.tool_name in {"SSL/TLS Analyzer", "ssl_scanner", "testssl"}:
                for key in ("protocol", "tls_version", "version", "issuer", "certificate_issuer"):
                    if summary.get(key):
                        add_signal(result, "tls", key, "tls", reliability=0.8, version=str(summary[key]) if "version" in key else "", url=base_url)
            if result.tool_name == "waf_behavior_profile":
                for observation in result.observations:
                    if observation.kind == "waf_behavior":
                        waf = observation.metadata.get("waf") or "unknown"
                        add_signal(result, "waf", str(waf), "waf_behavior", reliability=float(observation.metadata.get("confidence") or 0.5), url=base_url)
            # Structured tool summaries can explicitly provide technology
            # names; this is safer than guessing from arbitrary prose.
            for item in summary.get("technologies") or summary.get("technology_hints") or []:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("technology") or item.get("value")
                    version = item.get("version") or ""
                    category = item.get("category") or "unknown"
                else:
                    name, version, category = item, "", "unknown"
                if name:
                    add_signal(result, str(category), str(name), "tool_summary", reliability=0.85, version=str(version), url=base_url)

        signals = list(signal_by_id.values())
        grouped: Dict[tuple[str, str], List[TechnologySignalV1]] = {}
        for signal in signals:
            technology_name = str(signal.metadata.get("technology_name") or signal.value).lower()
            grouped.setdefault((signal.category, technology_name), []).append(signal)

        exclusive = {"server", "runtime", "cdn", "waf", "cms", "database"}
        family_values: Dict[str, set[str]] = {}
        for (family, name), group in grouped.items():
            if family in exclusive:
                family_values.setdefault(family, set()).add(name)
        conflicts = {family: sorted(values) for family, values in family_values.items() if len(values) > 1}
        fingerprints: List[TechnologyFingerprintV1] = []
        for (family, name), group in sorted(grouped.items()):
            sources = sorted({source for signal in group for source in signal.source_ids})
            evidence = sorted({item for signal in group for item in signal.evidence_ids})
            versions = sorted({str(signal.metadata.get("version")) for signal in group if signal.metadata.get("version")})
            version_status = "unknown"
            version = ""
            if len(versions) == 1:
                version = versions[0]
                # A single header/tool is still an inference.  Exact version
                # confirmation requires independent source IDs so a spoofed or
                # stale banner cannot become a canonical fact.
                version_status = "confirmed" if len(sources) > 1 else "inferred"
            elif len(versions) > 1:
                version_status = "conflicted"
            confidence = min(0.99, max(signal.reliability for signal in group) + min(0.25, 0.1 * (len(sources) - 1)))
            status = "contradictory" if family in conflicts or version_status == "conflicted" else ("supported" if confidence >= 0.75 else "inconclusive")
            fingerprint_id = f"techfp_{stable_digest({'target': target, 'family': family, 'name': name}, 32)}"
            fingerprints.append(TechnologyFingerprintV1(
                fingerprint_id=fingerprint_id,
                target=target,
                family=family if family in {"server", "runtime", "framework", "cms", "library", "cdn", "waf", "auth", "protocol", "database", "deployment", "security_control", "tls", "cache", "unknown"} else "unknown",
                name=name,
                version=version,
                version_status=version_status,
                status=status,
                confidence=confidence,
                signal_ids=[signal.signal_id for signal in group],
                evidence_ids=evidence,
                source_ids=sources,
                capability_hints=[],
                metadata={"conflict_family": family if family in conflicts else "", "signal_count": len(group)},
            ))

        capabilities: List[TechnologyCapabilityV1] = []
        capability_rules = {
            ("protocol", "graphql"): ("graphql_surface", "GraphQL protocol observed.", "read_only", False, ["surface_inventory"]),
            ("protocol", "websocket"): ("websocket_authorization", "WebSocket protocol observed.", "read_only", False, ["surface_inventory"]),
            ("protocol", "sse"): ("sse_access_control", "Server-sent events observed.", "read_only", False, ["surface_inventory"]),
            ("protocol", "openapi"): ("api_schema_validation", "OpenAPI/Swagger surface observed.", "read_only", False, ["surface_inventory"]),
            ("auth", "oauth"): ("oauth_lifecycle", "OAuth indicators observed.", "read_only", False, ["identity_context"]),
            ("auth", "oidc"): ("oidc_lifecycle", "OIDC indicators observed.", "read_only", False, ["identity_context"]),
            ("auth", "pkce"): ("pkce_binding", "PKCE indicators observed.", "read_only", False, ["identity_context"]),
            ("deployment", "source-map"): ("source_map_review", "Source-map exposure indicator observed.", "read_only", False, ["scope"]),
            ("waf", "cloudflare"): ("waf_aware_pacing", "Cloudflare-like behavior observed; tune pacing and record blocks.", "read_only", False, ["waf_profile"]),
            ("cache", "http-cache"): ("cache_behavior_review", "HTTP cache behavior observed.", "read_only", False, ["surface_inventory"]),
            ("auth", "cookie:laravel-session"): ("session_security", "Laravel session cookie metadata observed.", "read_only", False, ["identity_context"]),
            ("auth", "cookie:express-session"): ("session_security", "Express session cookie metadata observed.", "read_only", False, ["identity_context"]),
        }
        for fingerprint in fingerprints:
            key = (fingerprint.family, fingerprint.name)
            rule = capability_rules.get(key)
            if not rule:
                continue
            capability, reason, risk, approval, prerequisites = rule
            fingerprint.capability_hints.append(capability)
            capabilities.append(TechnologyCapabilityV1(
                capability_id=f"techcap_{stable_digest({'capability': capability, 'fingerprint': fingerprint.fingerprint_id}, 32)}",
                capability=capability,
                reason=reason,
                risk=risk,
                approval_required=approval,
                prerequisites=prerequisites,
                fingerprint_ids=[fingerprint.fingerprint_id],
                evidence_ids=fingerprint.evidence_ids,
                status="inconclusive" if fingerprint.status in {"contradictory", "inconclusive"} else "suggested",
            ))

        contradiction_records = [
            {
                "reference_id": f"tech-contradiction-{stable_digest({'family': family, 'values': values}, 24)}",
                "family": family,
                "values": values,
                "status": "inconclusive",
                "reason": "Exclusive technology family has conflicting independent signals.",
                "evidence_ids": sorted({item for fingerprint in fingerprints if fingerprint.family == family for item in fingerprint.evidence_ids}),
            }
            for family, values in sorted(conflicts.items())
        ]
        inventory = {
            "schema_version": "24.0",
            "target": redact(target)[:2000],
            "fingerprints": [item.model_dump(mode="json") for item in fingerprints],
            "signals": [item.model_dump(mode="json") for item in signals],
            "capabilities": [item.model_dump(mode="json") for item in capabilities],
            "contradictions": contradiction_records,
            "digest": stable_digest({
                "target": target,
                "fingerprints": [item.model_dump(mode="json") for item in fingerprints],
                "signals": [item.model_dump(mode="json") for item in signals],
                "capabilities": [item.model_dump(mode="json") for item in capabilities],
                "contradictions": contradiction_records,
            }, 64),
        }
        return {
            "technology_signals": [item.as_graph_source() for item in signals],
            "technology_fingerprints": [item.as_graph_source() for item in fingerprints],
            "technology_capabilities": [item.model_dump(mode="json") for item in capabilities],
            "technology_contradictions": contradiction_records,
            "technology_inventory": inventory,
            "technology_inventory_digest": inventory["digest"],
        }

    @staticmethod
    def application_contract_sources(
        target: str,
        results: List[ToolResultV1],
        endpoints: Optional[List[Dict[str, Any]]] = None,
        parameters: Optional[List[Dict[str, Any]]] = None,
        schemas: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Compile semantic API/application contracts from observed surfaces.

        Stage 23 records *where* a surface exists and Stage 24 records
        technology signals.  This layer records what an observed operation
        appears to do and what its inputs likely mean.  It never sends a
        request, treats a heuristic as a finding, or authorizes mutation.
        """
        endpoint_rows = list(endpoints or [])
        parameter_rows = list(parameters or [])
        schema_rows = list(schemas or [])
        endpoint_by_key: Dict[tuple[str, str], Dict[str, Any]] = {}
        endpoint_by_ref: Dict[str, Dict[str, Any]] = {}
        for endpoint in endpoint_rows:
            method = str(endpoint.get("method") or "GET").upper()
            locator = ReconOrchestrator._same_origin_endpoint(str(endpoint.get("url") or ""), target)
            if not locator:
                continue
            row = {**endpoint, "url": locator, "method": method}
            endpoint_by_key[(method, locator)] = row
            if row.get("reference_id"):
                endpoint_by_ref[str(row["reference_id"])] = row

        def parse_summary(result: ToolResultV1) -> Dict[str, Any]:
            try:
                value = json.loads(str(result.summary or ""))
                return value if isinstance(value, dict) else {}
            except (TypeError, ValueError):
                return {}

        def evidence_for(result: ToolResultV1) -> List[str]:
            return [str(item.observation_id) for item in result.observations if item.observation_id]

        def source_for(result: ToolResultV1) -> List[str]:
            return [str(result.tool_run_id or result.tool_name)]

        def normalize_name(value: Any) -> str:
            return redact(str(value or "")).strip()[:200]

        def classify_input(name: str) -> tuple[str, str, str, float]:
            value = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
            tokens = set(value.split("_"))
            rules = (
                ({"csrf", "xsrf", "nonce"}, "csrf", "secret_like", "possible"),
                ({"password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "code_verifier"}, "credential", "secret_like", "likely"),
                ({"tenant", "tenant_id", "org", "org_id", "workspace", "account_id"}, "tenant", "privileged", "likely"),
                ({"role", "permission", "privilege", "admin", "scope"}, "role", "privileged", "likely"),
                ({"status", "state", "action", "transition", "approve", "approval"}, "state", "privileged", "likely"),
                ({"price", "amount", "total", "balance", "coupon", "discount", "quantity", "currency"}, "money", "user_scoped", "likely"),
                ({"redirect", "redirect_uri", "return_url", "return_to", "next", "continue", "callback", "callback_url"}, "redirect", "user_scoped", "possible"),
                ({"file", "filename", "upload", "attachment", "document"}, "file", "user_scoped", "likely"),
                ({"search", "query", "keyword", "q", "filter"}, "search", "public", "possible"),
                ({"page", "offset", "limit", "cursor", "sort", "order"}, "pagination", "public", "possible"),
                ({"user", "user_id", "owner", "owner_id", "actor", "actor_id", "email", "username"}, "identity", "user_scoped", "possible"),
                ({"id", "uuid", "object_id", "resource_id", "item_id", "slug", "ref", "reference"}, "identifier", "user_scoped", "possible"),
            )
            for names, semantic, sensitivity, mutation in rules:
                if value in names or tokens.intersection(names) or any(value.endswith(f"_{item}") for item in names):
                    return semantic, sensitivity, mutation, 0.92
            return "unknown", "unknown", "unknown", 0.45

        def operation_kind(path: str, method: str, endpoint_kind: str = "") -> str:
            lower = path.lower()
            method = method.upper()
            if endpoint_kind in {"websocket", "sse"}:
                return "stream"
            if endpoint_kind == "schema":
                return "schema"
            if any(token in lower for token in ("/login", "/logout", "/signin", "/sign-in", "/oauth", "/authorize", "/token", "/session")):
                return "auth"
            if re.search(r"(?:^|/)(?:upload|uploads|attachment|import|file)(?:/|$)", lower):
                return "upload"
            if any(token in lower for token in ("approve", "approval", "transition", "checkout", "/publish", "/reset")):
                return "transition"
            return {
                "GET": "read", "HEAD": "read", "OPTIONS": "read",
                "POST": "create", "PUT": "update", "PATCH": "update",
                "DELETE": "delete",
            }.get(method, "unknown")

        def auth_expectation(path: str, metadata: Dict[str, Any], params: List[Dict[str, Any]]) -> str:
            if "auth_required" in metadata:
                return "authenticated" if bool(metadata.get("auth_required")) else "anonymous"
            lower = path.lower()
            if any(token in lower for token in ("/login", "/signin", "/sign-in", "/authorize", "/register", "/signup")):
                return "anonymous"
            if any(item.get("semantic_type") in {"credential", "csrf"} for item in params):
                return "ambiguous"
            if any(token in lower for token in ("/admin", "/account", "/profile", "/orders", "/settings", "/me/")):
                return "authenticated"
            return "unknown"

        semantic_rows: List[InputSemanticV1] = []
        semantic_by_param: Dict[str, InputSemanticV1] = {}
        for parameter in parameter_rows:
            parameter_id = str(parameter.get("reference_id") or "")
            endpoint_ref = str(parameter.get("metadata", {}).get("endpoint_reference_id") or "")
            name = normalize_name(parameter.get("parameter_name") or parameter.get("url") or "")
            if not parameter_id or not endpoint_ref or not name:
                continue
            semantic, sensitivity, mutation, confidence = classify_input(name)
            item = InputSemanticV1(
                semantic_id=f"inputsem_{stable_digest({'parameter': parameter_id, 'semantic': semantic}, 32)}",
                parameter_reference_id=parameter_id,
                endpoint_reference_id=endpoint_ref,
                name=name,
                location=str(parameter.get("parameter_location") or "unknown"),
                semantic_type=semantic,
                sensitivity=sensitivity,
                mutation_relevance=mutation,
                evidence_ids=list(dict.fromkeys(parameter.get("evidence_ids") or [])),
                source_ids=list(dict.fromkeys(parameter.get("source_ids") or [])),
                confidence=confidence,
                metadata={"classification": "name_and_location_heuristic", "stage": 25},
            )
            semantic_rows.append(item)
            semantic_by_param[parameter_id] = item

        operations_by_key: Dict[tuple[str, str], ApiOperationV1] = {}
        for endpoint in endpoint_by_key.values():
            method = str(endpoint.get("method") or "GET").upper()
            path = str(endpoint.get("url") or "/")
            endpoint_ref = str(endpoint.get("reference_id") or "")
            metadata = dict(endpoint.get("metadata") or {})
            endpoint_kind = str(metadata.get("endpoint_kind") or "unknown")
            linked_params = [item for item in semantic_rows if item.endpoint_reference_id == endpoint_ref]
            param_ids = [item.parameter_reference_id for item in linked_params]
            classified_kind = operation_kind(path, method, endpoint_kind)
            if classified_kind in {"create", "update"} and any(item.semantic_type == "state" for item in linked_params):
                classified_kind = "transition"
            operation = ApiOperationV1(
                operation_id=f"operation_{stable_digest({'method': method, 'path': path}, 32)}",
                endpoint_reference_id=endpoint_ref,
                method=method,
                path=path,
                operation_kind=classified_kind,
                auth_expectation=auth_expectation(path, metadata, [item.model_dump(mode="json") for item in linked_params]),
                side_effect="none" if method in {"GET", "HEAD", "OPTIONS"} or endpoint_kind in {"script", "static", "schema"} else ("state_change" if method in {"POST", "PUT", "PATCH", "DELETE"} else "unknown"),
                identity_hints=sorted({item.name for item in linked_params if item.semantic_type == "identity"}),
                tenant_hints=sorted({item.name for item in linked_params if item.semantic_type == "tenant"}),
                entity_hints=sorted({item.name for item in linked_params if item.semantic_type == "identifier"}),
                parameter_reference_ids=param_ids,
                schema_reference_ids=[],
                prerequisite_capabilities=([] if auth_expectation(path, metadata, [item.model_dump(mode="json") for item in linked_params]) == "anonymous" else ["identity_context"]),
                evidence_ids=list(dict.fromkeys(endpoint.get("evidence_ids") or [])),
                source_ids=list(dict.fromkeys(endpoint.get("source_ids") or [])),
                confidence=0.85 if endpoint.get("evidence_ids") else 0.5,
                metadata={"endpoint_kind": endpoint_kind, "stage": 25},
            )
            operations_by_key[(method, path)] = operation

        # Explicit structured operation/schema metadata can refine, but never
        # override, the scope and evidence guarantees of the surface rows.
        for result in results:
            summary = parse_summary(result)
            result_evidence = evidence_for(result)
            result_sources = source_for(result)
            for raw in (summary.get("operations") or summary.get("api_operations") or []):
                if not isinstance(raw, dict):
                    continue
                raw_url = str(raw.get("url") or raw.get("path") or "")
                method = str(raw.get("method") or "GET").upper()
                path = ReconOrchestrator._same_origin_endpoint(raw_url, target)
                if not path:
                    continue
                operation = operations_by_key.get((method, path))
                if operation is None:
                    continue
                metadata = dict(operation.metadata)
                if "auth_required" in raw:
                    metadata["auth_required"] = bool(raw.get("auth_required"))
                if raw.get("entity"):
                    operation.entity_hints = sorted(set(operation.entity_hints + [normalize_name(raw.get("entity"))]))
                operation.metadata = redact({**metadata, "structured_source": result.tool_name})
                operation.evidence_ids = sorted(set(operation.evidence_ids + result_evidence))
                operation.source_ids = sorted(set(operation.source_ids + result_sources))
                operation.auth_expectation = auth_expectation(operation.path, operation.metadata, [item.model_dump(mode="json") for item in semantic_rows if item.endpoint_reference_id == operation.endpoint_reference_id])

        for schema in schema_rows:
            endpoint_ref = str(schema.get("metadata", {}).get("endpoint_reference_id") or "")
            if not endpoint_ref:
                continue
            for operation in operations_by_key.values():
                if operation.endpoint_reference_id == endpoint_ref:
                    operation.schema_reference_ids = sorted(set(operation.schema_reference_ids + [str(schema.get("reference_id") or "")]))

        contradictions: List[Dict[str, Any]] = []
        # Same endpoint can be observed with incompatible explicit auth hints.
        # Keep the operation usable, but surface the ambiguity for the planner.
        explicit_auth: Dict[tuple[str, str], set[bool]] = {}
        for result in results:
            summary = parse_summary(result)
            for raw in (summary.get("operations") or summary.get("api_operations") or []):
                if not isinstance(raw, dict) or "auth_required" not in raw:
                    continue
                path = ReconOrchestrator._same_origin_endpoint(str(raw.get("url") or raw.get("path") or ""), target)
                if not path:
                    continue
                key = (str(raw.get("method") or "GET").upper(), path)
                explicit_auth.setdefault(key, set()).add(bool(raw.get("auth_required")))
        for key, values in sorted(explicit_auth.items()):
            if len(values) > 1:
                operation = operations_by_key.get(key)
                evidence_ids = list(operation.evidence_ids) if operation else []
                contradictions.append({
                    "reference_id": f"contract-contradiction-{stable_digest({'key': key, 'values': sorted(values)}, 24)}",
                    "subject": operation.operation_id if operation else f"{key[0]} {key[1]}",
                    "predicate": "auth_expectation",
                    "values": sorted(values),
                    "status": "inconclusive",
                    "reason": "Observed auth requirements disagree across structured sources.",
                    "evidence_ids": sorted(set(evidence_ids)),
                })
                if operation:
                    operation.auth_expectation = "ambiguous"
                    operation.status = "inconclusive"

        flows: List[Dict[str, Any]] = []
        for operation in sorted(operations_by_key.values(), key=lambda item: item.operation_id):
            flows.append({
                "reference_id": f"flow-{stable_digest({'operation': operation.operation_id, 'kind': operation.operation_kind}, 24)}",
                "node_type": "data_flow",
                "source_reference_id": operation.endpoint_reference_id,
                "target_reference_id": operation.operation_id,
                "relation": "exposes_operation",
                "status": "inconclusive" if operation.status == "inconclusive" else "observed",
                "evidence_ids": operation.evidence_ids,
                "source_ids": operation.source_ids,
                "metadata": redact({"operation_kind": operation.operation_kind, "side_effect": operation.side_effect}),
            })
            for semantic in semantic_rows:
                if semantic.endpoint_reference_id != operation.endpoint_reference_id:
                    continue
                flows.append({
                    "reference_id": f"flow-{stable_digest({'parameter': semantic.semantic_id, 'operation': operation.operation_id}, 24)}",
                    "node_type": "data_flow",
                    "source_reference_id": semantic.semantic_id,
                    "target_reference_id": operation.operation_id,
                    "relation": "accepted_by",
                    "status": "observed",
                    "evidence_ids": semantic.evidence_ids,
                    "source_ids": semantic.source_ids,
                    "metadata": redact({"semantic_type": semantic.semantic_type, "sensitivity": semantic.sensitivity}),
                })

        capability_hints: List[Dict[str, Any]] = []
        seen_capabilities: set[str] = set()
        for operation in operations_by_key.values():
            capability = "contract_readonly_mapping"
            if operation.operation_kind in {"create", "update", "delete", "transition", "upload"}:
                capability = "approved_operation_replay"
            elif operation.operation_kind == "auth":
                capability = "identity_flow_mapping"
            elif operation.operation_kind == "stream":
                capability = "realtime_subscription_mapping"
            if capability in seen_capabilities:
                continue
            seen_capabilities.add(capability)
            capability_hints.append({
                "reference_id": f"contract-capability-{stable_digest(capability, 24)}",
                "capability": capability,
                "risk": "mutation" if capability == "approved_operation_replay" else "read_only",
                "approval_required": capability == "approved_operation_replay",
                "status": "inconclusive" if contradictions else "suggested",
                "prerequisites": ["exact_approval", "cleanup_plan"] if capability == "approved_operation_replay" else ["surface_inventory"],
                "operation_count": len(operations_by_key),
            })

        operation_models = [item for item in sorted(operations_by_key.values(), key=lambda item: item.operation_id)]
        inventory = ApplicationContractInventoryV1(
            target=target,
            operations=[item.model_dump(mode="json") for item in operation_models],
            input_semantics=[item.model_dump(mode="json") for item in sorted(semantic_rows, key=lambda item: item.semantic_id)],
            schemas=redact(schema_rows),
            data_flows=flows,
            contradictions=contradictions,
            capability_hints=capability_hints,
            source_ids=sorted({str(result.tool_run_id or result.tool_name) for result in results}),
            evidence_ids=sorted({item.observation_id for result in results for item in result.observations}),
        ).finalize()
        return {
            "application_operations": [item.as_graph_source() for item in operation_models],
            "input_semantics": [item.as_graph_source() for item in semantic_rows],
            "data_flows": flows,
            "contract_contradictions": contradictions,
            "contract_capabilities": capability_hints,
            "application_contract_inventory": inventory.model_dump(mode="json"),
            "application_contract_digest": inventory.digest,
        }

    @staticmethod
    def identity_workflow_sources(
        target: str,
        results: List[ToolResultV1],
        *,
        session_id: str = "",
        identity_id: str = "",
        identity_ids: Optional[List[str]] = None,
        goal: str = "",
    ) -> Dict[str, Any]:
        """Compile passive auth/session/workflow intelligence.

        This is the Stage 26 counterpart to ``application_contract_sources``:
        it consumes typed observations and redacted summaries already present
        in the run. No network client, browser action, credential resolver, or
        approval bypass is reachable from this function.
        """
        from core.authorization_discovery import capture_auth_surface
        from core.workflow_discovery import workflow_discovery_service

        captures: List[Dict[str, Any]] = []
        for result in results or []:
            try:
                summary = json.loads(str(result.summary or ""))
            except (TypeError, ValueError):
                summary = {}
            if isinstance(summary, dict):
                for raw in summary.get("captures") or summary.get("network_captures") or []:
                    if isinstance(raw, dict):
                        captures.append(redact(raw))
                for page in summary.get("pages_detail") or []:
                    if isinstance(page, dict):
                        captures.append(redact({
                            "url": page.get("url") or target,
                            "forms": page.get("forms_detail") or page.get("forms") or [],
                            "buttons": page.get("buttons") or [],
                            "observation_id": page.get("observation_id"),
                        }))
            for observation in result.observations:
                metadata = dict(observation.metadata or {})
                if any(key in metadata for key in ("forms", "forms_detail", "buttons", "network", "requests", "auth_event")):
                    captures.append(redact({
                        "url": observation.target_url or target,
                        "method": observation.method or "GET",
                        "observation_id": observation.observation_id,
                        **metadata,
                    }))

        # Target content is untrusted. Keep only same-origin captures before
        # auth/workflow compilation so external redirects or provider traffic
        # cannot become identity or session facts.
        captures = [
            item for item in captures
            if ReconOrchestrator._same_origin_endpoint(str(item.get("url") or target), target)
        ]

        auth_surfaces, transitions, auth_gaps = capture_auth_surface(
            captures, session_id, identity_id=identity_id,
            source_ids=[str(result.tool_run_id or result.tool_name) for result in results if result.tool_run_id or result.tool_name],
        )
        workflow_intelligence = workflow_discovery_service.discover_intelligence(
            session_id=session_id, origin=target, goal=goal,
            captures=captures, identity_ids=list(identity_ids or ([identity_id] if identity_id else [])),
        )
        workflow = dict(workflow_intelligence.get("workflow") or {})
        workflow_id = str(workflow.get("workflow_id") or "")
        workflow_node = {
            **workflow,
            "reference_id": workflow_id or f"workflow-{stable_digest({'target': target, 'goal': goal}, 24)}",
            "node_type": "workflow",
            "url": target,
            "status": "observed",
            "evidence_ids": workflow.get("source_observation_ids", []),
            "source_ids": workflow.get("source_observation_ids", []),
            "metadata": redact({
                "workflow_class": workflow.get("workflow_class", "unknown"),
                "identity_requirements": workflow.get("identity_requirements", []),
                "required_role_labels": workflow.get("required_role_labels", []),
                "required_tenant_labels": workflow.get("required_tenant_labels", []),
                "state_graph": workflow.get("state_graph", {}),
                "auth_surface_ids": [item.observation_id for item in auth_surfaces],
                "prerequisite_ids": [item.get("prerequisite_id") for item in workflow_intelligence.get("prerequisites", [])],
                "mutating": bool(workflow_intelligence.get("mutating")),
                "approval_required": bool(workflow_intelligence.get("approval_required")),
            }),
        }
        auth_graph = []
        for item in auth_surfaces:
            metadata = dict(item.metadata or {})
            path = str(metadata.get("path") or "/")
            url = item.origin.rstrip("/") + (path if path.startswith("/") else "/" + path)
            auth_graph.append({
                "reference_id": item.observation_id,
                "node_type": "auth_surface",
                "url": url,
                "method": str(metadata.get("method") or "GET"),
                "status": "inconclusive" if item.status == "inconclusive" else "observed",
                "evidence_ids": item.evidence_ids,
                "source_ids": item.source_ids,
                "metadata": redact(item.model_dump(mode="json")),
            })
        transition_graph = []
        for item in transitions:
            transition_graph.append({
                "reference_id": item.transition_id,
                "node_type": "session_transition",
                "url": item.origin or target,
                "status": "observed",
                "evidence_ids": item.evidence_ids,
                "source_ids": item.source_ids,
                "metadata": redact(item.model_dump(mode="json")),
            })
        prerequisite_graph = []
        for raw in workflow_intelligence.get("prerequisites") or []:
            item = dict(raw)
            item.update({
                "reference_id": item.get("prerequisite_id") or f"prereq-{stable_digest(item, 24)}",
                "node_type": "prerequisite",
                "url": target,
                "status": "inconclusive" if item.get("status") in {"missing", "inconclusive", "stale"} else "observed",
                "metadata": redact(item),
            })
            prerequisite_graph.append(item)
        edges: List[Dict[str, Any]] = []
        if workflow_node.get("reference_id"):
            for item in auth_graph:
                edges.append({
                    "source_reference_id": item["reference_id"],
                    "target_reference_id": workflow_node["reference_id"],
                    "relation": "guards",
                    "status": item.get("status", "observed"),
                    "evidence_ids": item.get("evidence_ids", []),
                    "source_ids": item.get("source_ids", []),
                })
            for item in prerequisite_graph:
                edges.append({
                    "source_reference_id": item["reference_id"],
                    "target_reference_id": workflow_node["reference_id"],
                    "relation": "prerequisite_for",
                    "status": item.get("status", "observed"),
                    "evidence_ids": item.get("evidence_ids", []),
                    "source_ids": item.get("source_ids", []),
                })
        inventory = {
            "schema_version": "26.0",
            "target": redact(target)[:2000],
            "workflow_id": workflow_node.get("reference_id", ""),
            "auth_surfaces": [item.model_dump(mode="json") for item in auth_surfaces],
            "session_transitions": [item.model_dump(mode="json") for item in transitions],
            "workflow": workflow,
            "prerequisites": [redact(item) for item in workflow_intelligence.get("prerequisites") or []],
            "gaps": sorted(set(auth_gaps + list(workflow_intelligence.get("gaps") or []))),
            "digest": stable_digest({
                "target": target, "auth_surfaces": [item.model_dump(mode="json") for item in auth_surfaces],
                "session_transitions": [item.model_dump(mode="json") for item in transitions],
                "workflow": workflow, "prerequisites": workflow_intelligence.get("prerequisites") or [],
            }, 64),
        }
        return {
            "auth_surfaces": auth_graph,
            "session_transitions": transition_graph,
            "workflows": [workflow_node] if workflow_node.get("reference_id") else [],
            "workflow_prerequisites": prerequisite_graph,
            "identity_workflow_inventory": inventory,
            "identity_workflow_digest": inventory["digest"],
            "identity_workflow_gaps": inventory["gaps"],
            "identity_workflow_edges": edges,
        }

    @staticmethod
    def _same_origin_endpoint(value: str, target: str) -> str:
        """Return a redacted same-origin endpoint, or an empty string.

        Recon output is untrusted.  This function is intentionally stricter
        than the HTTP scope matcher: it accepts the target host and its
        subdomains, rejects credentials/unsupported schemes, and never stores
        query values harvested from legacy output.
        """
        try:
            candidate = urlsplit(str(value).strip())
            origin = urlsplit(str(target).strip())
            if candidate.scheme not in {"http", "https", "ws", "wss"} or origin.scheme not in {"http", "https", "ws", "wss"}:
                return ""
            if candidate.username or candidate.password or not candidate.hostname or not origin.hostname:
                return ""
            candidate_host = candidate.hostname.lower().rstrip(".")
            origin_host = origin.hostname.lower().rstrip(".")
            if candidate_host != origin_host and not candidate_host.endswith(f".{origin_host}"):
                return ""
            host = candidate.hostname
            if candidate.port:
                host = f"{host}:{candidate.port}"
            path = candidate.path or "/"
            return urlunsplit((candidate.scheme.lower(), host, path, "", ""))
        except (TypeError, ValueError):
            return ""

    @staticmethod
    def discovered_endpoints(result: ToolResultV1, target: str) -> List[str]:
        """Extract bounded same-origin endpoints from one tool result.

        This is deliberately an observation extractor, not a finding parser.
        Legacy text is treated as untrusted and only absolute HTTP(S) URLs
        matching the target host/subdomains are returned.  Query values are
        removed by ``_same_origin_endpoint`` before they can enter the graph
        or the follow-up queue.
        """
        values: set[str] = set()
        for observation in result.observations:
            if observation.target_url:
                values.add(observation.target_url)
            for text in (observation.summary, observation.response_excerpt):
                values.update(re.findall(r"https?://[^\s<>\"']+", str(text or ""), flags=re.IGNORECASE))
        text = redact(str(result.summary or ""))[:24000]
        values.update(re.findall(r"https?://[^\s<>\"']+", text, flags=re.IGNORECASE))
        endpoints = {
            ReconOrchestrator._same_origin_endpoint(str(value).rstrip(".,);]"), target)
            for value in values
        }
        return sorted(item for item in endpoints if item)[:250]

    def _compile_graph(self, session_id: str, target: str, sources: Dict[str, Any], scope: Any = None) -> Dict[str, Any]:
        try:
            from api import knowledge_graph_engine, knowledge_graph_repository

            current = knowledge_graph_repository.current(session_id) or {}
            version = int(current.get("version", 0) or 0) + 1
            compiled = knowledge_graph_engine.compile(
                session_id,
                target,
                sources,
                scope=scope or {"allow": [target]},
                version=version,
                parent_graph_id=str(current.get("graph_id") or ""),
            )
            knowledge_graph_repository.save_compiled(compiled)
            try:
                from core.target_state import get_target_state

                state = get_target_state()
                if state:
                    state.apply_knowledge_graph(compiled)
                    state.apply_technology_inventory(sources.get("technology_inventory") or {})
                    state.apply_application_contract(sources.get("application_contract_inventory") or {})
                    state.apply_identity_workflow_intelligence(sources.get("identity_workflow_inventory") or {})
            except Exception:
                pass
            return {
                "status": "succeeded",
                "graph_id": compiled.get("graph", {}).get("graph_id", ""),
                "graph_version": compiled.get("graph", {}).get("version", 0),
                "digest": compiled.get("graph", {}).get("digest", ""),
                "nodes": len(compiled.get("nodes") or []),
                "edges": len(compiled.get("edges") or []),
                "coverage": len(compiled.get("coverage") or []),
                "gaps": len(compiled.get("gaps") or []),
            }
        except Exception as exc:
            print(f"[KNOWLEDGE] graph persistence failed: {type(exc).__name__}: {str(exc)[:500]}")
            return {"status": "failed", "reason": "knowledge_graph_persistence", "error": str(exc)[:500]}

    def execute(
        self,
        target: str,
        session_id: str,
        *,
        goal: str = "map the web/API attack surface",
        job_id: str = "",
        selected_tools: Optional[Iterable[str]] = None,
        approval_granted: bool = False,
        scope: Any = None,
    ) -> Dict[str, Any]:
        config = self._recon_config()
        self._waf_strategy = {}
        plan = self.plan(target, session_id, selected_tools=selected_tools, approval_granted=approval_granted)
        results: list[ToolResultV1] = []
        runner = self._runner()
        attempted = 0
        failures = 0
        error_threshold = float(config.get("stop_on_error_rate", 0.50) or 0.50)
        max_runs = max(1, int(config.get("max_runs", 128) or 128))
        max_endpoints = max(1, int(config.get("max_endpoints", 100) or 100))
        max_depth = max(0, int(config.get("max_depth", 2) or 2))
        max_followups = max(0, int(config.get("max_followups_per_endpoint", 8) or 8))
        circuit_open = False

        selected = set(selected_tools) if selected_tools is not None else None
        configured_followups = config.get("followup_tools") or DEFAULT_FOLLOWUP_TOOLS
        # An explicit planner/operator selection is a bounded execution
        # contract.  Do not silently fan it out into additional browser or
        # crawler runs; callers that want adaptive expansion use the full
        # mission (selected=None) or configure a separate bounded plan.
        followup_names = [] if selected is not None else [
            str(name) for name in configured_followups if str(name)
        ]
        # An explicit operator/tool pack is already a bounded plan.  Persisting
        # a full append-only knowledge-graph version after every tool makes a
        # large recon pack spend most of its time in redundant database writes.
        # Keep incremental graph updates for adaptive missions, and always
        # compile the authoritative final snapshot below.
        incremental_graph_updates = bool(config.get("incremental_graph_updates", True)) and selected is None
        eligible_initial_names = {
            str(item.get("public_name"))
            for item in plan
            if item.get("status") == "eligible"
        }

        target_endpoint = self._same_origin_endpoint(target, target) or target
        discovered: set[str] = {target_endpoint}
        task_queue: list[Dict[str, Any]] = []
        seen_tasks: set[tuple[str, str]] = set()
        trace: list[Dict[str, Any]] = []
        graph_updates: list[Dict[str, Any]] = []
        scheduled_followups = 0
        max_depth_reached = 0
        waf_circuit_open = False
        waf_actions = 0

        # Non-eligible initial capabilities are explicit records, never silent
        # omissions.  Eligible capabilities become deterministic FIFO tasks.
        for item in plan:
            if item.get("status") != "eligible":
                skipped = self._skip_result(item, target)
                results.append(skipped)
                self._persist_skip(session_id, skipped)
                continue
            task_queue.append({
                "public_name": str(item["public_name"]),
                "target": target_endpoint,
                "depth": 0,
                "parent_tool_run_id": "",
                "plan_item": item,
            })

        while task_queue:
            task = task_queue.pop(0)
            name = str(task["public_name"])
            task_target = str(task["target"])
            depth = int(task.get("depth", 0) or 0)
            task_key = (name, task_target)
            if task_key in seen_tasks:
                continue
            seen_tasks.add(task_key)
            max_depth_reached = max(max_depth_reached, depth)

            if depth > 0:
                item = {
                    "schema_version": "1.0",
                    "public_name": name,
                    "lane": next((spec.lane for spec in _specs() if spec.public_name == name), "unknown"),
                    "risk": "read_only",
                    "provider": False,
                    "r2": False,
                    "raw_network": False,
                    "approval_required": False,
                    "status": "eligible",
                    "reason": "recursive_followup",
                    "target": task_target,
                    "depth": depth,
                    "parent_tool_run_id": str(task.get("parent_tool_run_id") or ""),
                    "is_followup": True,
                }
                plan.append(item)
            else:
                item = task["plan_item"]

            if circuit_open:
                item.update(status="skipped", reason="recon_circuit_breaker_open")
                skipped = self._skip_result(item, task_target)
                results.append(skipped)
                self._persist_skip(session_id, skipped)
                continue
            if name != "waf_behavior_profile" and self._waf_suppresses(name):
                item.update(status="skipped", reason="waf_strategy_suppressed")
                skipped = self._skip_result(item, task_target)
                results.append(skipped)
                self._persist_skip(session_id, skipped)
                trace.append({
                    "sequence": len(trace) + 1,
                    "tool_run_id": skipped.tool_run_id,
                    "tool_name": name,
                    "target": task_target,
                    "depth": depth,
                    "parent_tool_run_id": str(task.get("parent_tool_run_id") or ""),
                    "role": "followup" if depth else "seed",
                    "status": skipped.status,
                    "reason": "waf_strategy_suppressed",
                    "waf_profile_id": self._waf_strategy.get("profile_id", ""),
                    "queue_remaining": len(task_queue),
                })
                continue
            max_waf_requests = int(self._waf_strategy.get("max_requests_before_block", 0) or 0)
            if name != "waf_behavior_profile" and max_waf_requests and waf_actions >= max_waf_requests:
                item.update(status="skipped", reason="waf_request_budget_reached")
                skipped = self._skip_result(item, task_target)
                results.append(skipped)
                self._persist_skip(session_id, skipped)
                continue
            if name != "waf_behavior_profile" and waf_circuit_open:
                item.update(status="skipped", reason="waf_circuit_breaker_open")
                skipped = self._skip_result(item, task_target)
                results.append(skipped)
                self._persist_skip(session_id, skipped)
                continue
            if attempted >= max_runs:
                item.update(status="skipped", reason="recon_run_budget_exhausted")
                skipped = self._skip_result(item, task_target)
                results.append(skipped)
                self._persist_skip(session_id, skipped)
                continue

            attempted += 1
            if name == "waf_behavior_profile":
                # WAF profiling is a perimeter seed operation; it is never
                # recursively replayed against every discovered path.
                result = self._run_waf_profile(task_target, session_id, job_id, approval_granted)
            else:
                capability = self.registry_lookup(name)
                if capability is None:
                    item.update(status="unavailable", reason="tool_not_registered")
                    result = self._skip_result(item, task_target)
                    self._persist_skip(session_id, result)
                else:
                    try:
                        tool = self.tool_resolver(capability)
                        result = runner.execute(
                            tool,
                            self.tool_kwargs(name, task_target, session_id, goal),
                            target=task_target,
                            session_id=session_id,
                            category="recon",
                            job_id=job_id,
                            runtime_config={
                                "waf_strategy": dict(self._waf_strategy),
                            } if self._waf_strategy else None,
                        )
                    except Exception as exc:
                        result = ToolResultV1(
                            tool_name=name,
                            category="recon",
                            target=task_target,
                            status="failed",
                            summary=f"Recon capability {name} failed.",
                            errors=[ToolErrorV1(code="recon_dispatch_error", message=str(exc))],
                        )

            results.append(result)
            if name != "waf_behavior_profile":
                waf_actions += 1
            if result.status in {"failed", "partial"}:
                failures += 1
            if self._waf_block_signal(result):
                waf_circuit_open = True
            if name == "waf_behavior_profile":
                # The profile is the policy seed; a passive profile is still
                # useful even when no vendor is identified.
                waf_circuit_open = False
            if attempted >= 3 and failures / attempted >= error_threshold:
                circuit_open = True

            trace.append({
                "sequence": len(trace) + 1,
                "tool_run_id": result.tool_run_id,
                "tool_name": name,
                "target": task_target,
                "depth": depth,
                "parent_tool_run_id": str(task.get("parent_tool_run_id") or ""),
                "role": "followup" if depth else "seed",
                "status": result.status,
                "waf_profile_id": self._waf_strategy.get("profile_id", ""),
                "waf_rate_limit": self._waf_strategy.get("rate_limit"),
                "queue_remaining": len(task_queue),
            })

            # Refresh the graph after every completed task when enabled.  The
            # final refresh below remains the source of the returned snapshot.
            if session_id and incremental_graph_updates:
                sources = self.knowledge_sources(target, plan, results, session_id=session_id)
                graph_updates.append(self._compile_graph(session_id, target, sources, scope=scope))

            if circuit_open or depth >= max_depth or not followup_names:
                continue

            candidates = [
                endpoint for endpoint in self.discovered_endpoints(result, target)
                if endpoint not in discovered and len(discovered) < max_endpoints
            ]
            for endpoint in candidates:
                if len(discovered) >= max_endpoints:
                    break
                discovered.add(endpoint)
                for followup_name in followup_names[:max_followups]:
                    if followup_name not in eligible_initial_names:
                        continue
                    if (followup_name, endpoint) in seen_tasks:
                        continue
                    task_queue.append({
                        "public_name": followup_name,
                        "target": endpoint,
                        "depth": depth + 1,
                        "parent_tool_run_id": result.tool_run_id,
                        "plan_item": None,
                    })
                    scheduled_followups += 1

        sources = self.knowledge_sources(target, plan, results, session_id=session_id)
        if session_id:
            if incremental_graph_updates and graph_updates:
                graph = self._compile_graph(session_id, target, sources, scope=scope)
            else:
                graph = self._compile_graph(session_id, target, sources, scope=scope)
        else:
            graph = {"status": "not_persisted"}
        counts: Dict[str, int] = {}
        for item in plan:
            status = str(item.get("status") or "unknown")
            counts[status] = counts.get(status, 0) + 1
        summaries = []
        for result in results:
            summary = result.llm_summary()
            summaries.append(json.loads(summary) if summary.startswith("{") else summary)
        return {
            "schema_version": "1.0",
            "mission_id": f"recon_{uuid.uuid4().hex}",
            "target": target,
            "status": "succeeded" if all(item.status not in {"failed", "partial"} for item in results) else "partial",
            "plan": plan,
            "counts": counts,
            "execution": {
                "attempted": attempted,
                "failures": failures,
                "error_rate": round(failures / attempted, 4) if attempted else 0.0,
                "circuit_breaker_open": circuit_open,
                "waf_circuit_breaker_open": waf_circuit_open,
                "waf_strategy": redact(dict(self._waf_strategy)),
                "max_runs": max_runs,
                "max_depth": max_depth,
            },
            "fanout": {
                "discovered_endpoints": len(discovered),
                "scheduled_followups": scheduled_followups,
                "completed_followups": sum(1 for item in trace if item["role"] == "followup"),
                "max_depth_reached": max_depth_reached,
                "graph_updates": len(graph_updates),
            },
            "trace": trace,
            "results": summaries,
            "graph": graph,
            "source_count": len(sources.get("observations", [])),
        }

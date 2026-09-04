"""Safety-gated live matrix for locally owned web security labs.

The matrix is intentionally narrower than a pentest.  It verifies that each
authorized lab is reachable and that Nexus can capture bounded surface
signals through the guarded transport.  It never promotes a finding, sends a
mutation, submits credentials, or treats an unavailable lab as a negative
security result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

import yaml

from core.execution_contract import ResourceBudgetV1, stable_digest
from core.identity_context import ToolExecutionContext, use_execution_context
from core.redact import redact
from core.safety_kernel import SafetyKernel, SafetyViolation
from core.tool_transport import guarded_requests


MATRIX_PATH = Path(__file__).resolve().parent.parent / "benchmarks" / "live-labs" / "web_lab_matrix.yaml"
MATRIX_VERSION = "1.0"


@dataclass(frozen=True)
class LiveLabProfile:
    profile_id: str
    name: str
    target: str
    safe_probe_path: str = "/"
    expected_surfaces: tuple[str, ...] = ()
    notes: str = ""
    configured: bool = True

    @property
    def probe_url(self) -> str:
        base = self.target.rstrip("/")
        path = self.safe_probe_path or "/"
        return f"{base}{path if path.startswith('/') else '/' + path}"


@dataclass
class LiveLabMatrixRunner:
    """Run bounded, read-only probes against explicit local lab profiles."""

    probe: Optional[Callable[[LiveLabProfile], Dict[str, Any]]] = None
    manifest_path: Path = MATRIX_PATH

    def profiles(self, selected: Optional[Iterable[str]] = None) -> List[LiveLabProfile]:
        wanted = {str(item).strip() for item in (selected or []) if str(item).strip()}
        rows = self._load_manifest()
        output: List[LiveLabProfile] = []
        for row in rows:
            profile_id = str(row.get("id") or "").strip()
            if not profile_id or (wanted and profile_id not in wanted):
                continue
            env_var = str(row.get("env_var") or "").strip()
            configured_target = os.environ.get(env_var, "").strip() if env_var else ""
            target = configured_target or str(row.get("default_target") or "").strip()
            output.append(LiveLabProfile(
                profile_id=profile_id,
                name=str(row.get("name") or profile_id)[:200],
                target=target,
                safe_probe_path=str(row.get("safe_probe_path") or "/"),
                expected_surfaces=tuple(str(item) for item in (row.get("expected_surfaces") or [])),
                notes=redact(str(row.get("notes") or ""))[:500],
                configured=bool(target),
            ))
        if wanted:
            known = {item.profile_id for item in output}
            unknown = sorted(wanted - known)
            if unknown:
                raise ValueError(f"Unknown live-lab profile(s): {', '.join(unknown)}")
        return output

    def run(self, selected: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        profiles = self.profiles(selected)
        started = time.monotonic()
        results: List[Dict[str, Any]] = []
        for profile in profiles:
            if not profile.configured:
                results.append(self._not_configured(profile))
                continue
            if not self._is_local_target(profile.probe_url):
                results.append(self._blocked(profile, "non_local_target"))
                continue
            try:
                result = (self.probe or self._default_probe)(profile)
            except SafetyViolation as exc:
                result = (
                    self._unavailable(profile, exc.reason_code)
                    if exc.reason_code in {"dns_failed"}
                    else self._blocked(profile, exc.reason_code)
                )
            except Exception as exc:
                result = {
                    "profile_id": profile.profile_id,
                    "name": profile.name,
                    "target": self._safe_target(profile.probe_url),
                    "status": "unavailable",
                    "reason": "probe_error",
                    "error_type": type(exc).__name__,
                    "evidence_digest": stable_digest({"profile": profile.profile_id, "error": type(exc).__name__}, 32),
                }
            results.append(redact(result))

        configured = [item for item in results if item.get("status") != "not_configured"]
        available = [item for item in configured if item.get("status") == "available"]
        blocked = [item for item in configured if item.get("status") == "blocked"]
        signal_ready = [item for item in available if item.get("surface_signals")]
        all_configured = len(profiles) > 0 and all(item.get("status") != "not_configured" for item in results)
        matrix_ready = bool(profiles) and all_configured and len(available) == len(profiles)
        return {
            "schema_version": "nexus.live_lab_matrix.v1",
            "suite_id": "nexus-live-web-lab-matrix",
            "suite_version": MATRIX_VERSION,
            "status": "succeeded" if matrix_ready else "partial",
            "release_gate": "ready" if matrix_ready else "not_ready",
            "scope": "local authorized labs; read-only availability and surface probes",
            "results": results,
            "totals": {
                "profiles": len(profiles),
                "configured": len(configured),
                "available": len(available),
                "unavailable": sum(item.get("status") == "unavailable" for item in results),
                "blocked": len(blocked),
                "not_configured": sum(item.get("status") == "not_configured" for item in results),
                "surface_signal_ready": len(signal_ready),
            },
            "metrics": {
                "configuration_rate": round(len(configured) / len(profiles), 4) if profiles else 0.0,
                "reachability_rate": round(len(available) / len(configured), 4) if configured else 0.0,
                "surface_signal_rate": round(len(signal_ready) / len(available), 4) if available else 0.0,
            },
            "limitations": [
                "This matrix does not assert or disprove vulnerabilities.",
                "No credentials, mutations, uploads, race tests, or exploit payloads are sent.",
                "A not_configured or unavailable lab is a coverage gap, not a negative finding.",
            ],
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }

    def _default_probe(self, profile: LiveLabProfile) -> Dict[str, Any]:
        started = time.monotonic()
        response = guarded_requests.get(
            profile.probe_url,
            timeout=12,
            allow_redirects=False,
        )
        body = response.text[:200_000]
        signals = self._surface_signals(body, response.headers)
        headers = {
            key: str(response.headers.get(key, ""))[:200]
            for key in ("content-type", "server", "location", "x-powered-by", "strict-transport-security")
            if response.headers.get(key)
        }
        digest = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:32]
        evidence_digest = stable_digest({
            "profile_id": profile.profile_id,
            "status": response.status_code,
            "body_digest": digest,
            "signals": signals,
        }, 32)
        return {
            "profile_id": profile.profile_id,
            "name": profile.name,
            "target": self._safe_target(profile.probe_url),
            "status": "available" if int(response.status_code) < 500 else "unavailable",
            "http_status": int(response.status_code),
            "content_type": str(response.headers.get("content-type", ""))[:200],
            "response_bytes": len(response.content),
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
            "title": self._title(body),
            "headers": headers,
            "surface_signals": signals,
            "evidence_digest": evidence_digest,
            "finding_assertion": "none",
        }

    @staticmethod
    def _surface_signals(body: str, headers: Any) -> List[str]:
        lower = body.lower()
        signals: List[str] = []
        rules = (
            ("forms", r"<form\b"),
            ("auth", r"login|sign[ -]?in|password|authenticate"),
            ("api", r"/api/|xhr|fetch\(|application/json"),
            ("graphql", r"graphql"),
            ("upload", r"type=[\"']file|upload|multipart/form-data"),
            ("websocket", r"websocket|ws://|wss://"),
            ("csrf", r"csrf|xsrf|anti[-_ ]forgery"),
            ("spa", r"__next|ng-version|react|vue|angular|webpack"),
            ("openapi", r"openapi|swagger"),
            ("search", r"search|query|keyword|filter"),
            ("business", r"cart|order|coupon|payment|vehicle|shop"),
        )
        for name, pattern in rules:
            if re.search(pattern, lower):
                signals.append(name)
        content_type = str(getattr(headers, "get", lambda *_: "")("content-type", "")).lower()
        if "json" in content_type and "api" not in signals:
            signals.append("api")
        return sorted(set(signals))

    @staticmethod
    def _title(body: str) -> str:
        matched = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
        return redact(re.sub(r"\s+", " ", matched.group(1)).strip())[:200] if matched else ""

    @staticmethod
    def _not_configured(profile: LiveLabProfile) -> Dict[str, Any]:
        return {
            "profile_id": profile.profile_id,
            "name": profile.name,
            "target": "",
            "status": "not_configured",
            "reason": "explicit_lab_url_required",
            "evidence_digest": stable_digest({"profile": profile.profile_id, "status": "not_configured"}, 32),
        }

    @staticmethod
    def _blocked(profile: LiveLabProfile, reason: str) -> Dict[str, Any]:
        return {
            "profile_id": profile.profile_id,
            "name": profile.name,
            "target": LiveLabMatrixRunner._safe_target(profile.probe_url),
            "status": "blocked",
            "reason": redact(reason)[:200],
            "evidence_digest": stable_digest({"profile": profile.profile_id, "status": "blocked", "reason": reason}, 32),
        }

    @staticmethod
    def _unavailable(profile: LiveLabProfile, reason: str) -> Dict[str, Any]:
        return {
            "profile_id": profile.profile_id,
            "name": profile.name,
            "target": LiveLabMatrixRunner._safe_target(profile.probe_url),
            "status": "unavailable",
            "reason": redact(reason)[:200],
            "evidence_digest": stable_digest({"profile": profile.profile_id, "status": "unavailable", "reason": reason}, 32),
        }

    @staticmethod
    def _safe_target(value: str) -> str:
        parsed = urlsplit(str(value))
        if not parsed.scheme or not parsed.netloc:
            return redact(str(value))[:500]
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path[:300]}"

    @staticmethod
    def _is_local_target(value: str) -> bool:
        hostname = (urlsplit(value).hostname or "").lower().rstrip(".")
        if not hostname:
            return False
        if hostname in {"localhost", "host.docker.internal"} or hostname.endswith((".local", ".test", ".internal")):
            return True
        if hostname.startswith("127.") or hostname.startswith("10.") or hostname.startswith("192.168."):
            return True
        if hostname.startswith("172."):
            try:
                return 16 <= int(hostname.split(".")[1]) <= 31
            except (IndexError, ValueError):
                return False
        return False

    def _load_manifest(self) -> List[Dict[str, Any]]:
        try:
            payload = yaml.safe_load(self.manifest_path.read_text(encoding="utf-8")) or {}
            rows = payload.get("profiles") if isinstance(payload, dict) else []
            return [dict(item) for item in rows if isinstance(item, dict)]
        except (OSError, TypeError, ValueError, yaml.YAMLError):
            return []


class _LocalLabScope:
    """Ephemeral scope store used only by the explicit live-matrix CLI."""

    def get(self, session_id: str) -> Dict[str, Any]:
        return {
            "session_id": session_id,
            "scope_rules": [{
                "pattern": "*",
                "rule_type": "allow",
                "allow_private": True,
            }],
        }

    def validate_active_scope(self, session_id: str, target: str) -> tuple[bool, str]:
        return (LiveLabMatrixRunner._is_local_target(target), "local live-lab matrix scope")


def run_authorized_live_matrix(selected: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Run the matrix under the same guarded transport used by tools."""
    session_id = "live-lab-matrix"
    scope = _LocalLabScope()
    kernel = SafetyKernel(session_store=scope)
    context = ToolExecutionContext(
        session_id=session_id,
        job_id=session_id,
        tool_run_id=session_id,
        target_origin="http://host.docker.internal",
        budget=ResourceBudgetV1(max_requests=50, max_download_bytes=20_000_000, max_response_bytes=2_000_000),
        safety_kernel=kernel,
        approval_granted=False,
    )
    with use_execution_context(context):
        return LiveLabMatrixRunner().run(selected)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run Nexus read-only local web-lab matrix.")
    parser.add_argument("--profile", action="append", dest="profiles", help="Profile ID; repeat for a subset.")
    parser.add_argument("--confirm", action="store_true", help="Confirm the operator-owned local lab scope.")
    args = parser.parse_args(argv)
    if not args.confirm and os.environ.get("NEXUS_LIVE_LAB_CONFIRM") != "1":
        parser.error("Explicit confirmation required: pass --confirm or set NEXUS_LIVE_LAB_CONFIRM=1")
    print(json.dumps(run_authorized_live_matrix(args.profiles), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["LiveLabProfile", "LiveLabMatrixRunner", "run_authorized_live_matrix", "main"]

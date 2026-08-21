"""Versioned contract for tool execution and evidence.

The contract deliberately separates observations from candidate findings.  A
tool may report a signal, but only the validation engine can promote it to a
validated finding.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.redact import redact
from core.config_loader import get_setting


ToolStatus = Literal["running", "succeeded", "partial", "skipped", "failed", "cancelled"]
CandidateStatus = Literal[
    "suspected", "validating", "validated", "validated_override",
    "disproven", "inconclusive",
]
ObservationRole = Literal[
    "baseline", "test", "negative_control", "positive_control",
    "reproduction", "oob", "browser", "external",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_target(value: str) -> str:
    parsed = urlsplit(value.strip())
    if not parsed.scheme or not parsed.netloc:
        return value.strip().lower().rstrip("/")
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def make_fingerprint(
    vuln_type: str,
    target_url: str,
    method: str = "GET",
    parameter: str = "",
    injection_point: str = "",
) -> str:
    canonical = "|".join((
        vuln_type.strip().lower(),
        normalize_target(target_url),
        method.strip().upper(),
        parameter.strip().lower(),
        injection_point.strip().lower(),
    ))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ObservationV1(ContractModel):
    observation_id: str = Field(default_factory=lambda: f"obs_{uuid.uuid4().hex}")
    role: ObservationRole = "test"
    kind: str = "http_exchange"
    summary: str = ""
    target_url: str = ""
    method: str = "GET"
    request_excerpt: str = ""
    response_excerpt: str = ""
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    payload_hash: str = ""
    artifact_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("summary", "request_excerpt", "response_excerpt", mode="before")
    @classmethod
    def redact_text(cls, value: Any) -> str:
        return redact(str(value or ""))


class ArtifactV1(ContractModel):
    artifact_id: str = Field(default_factory=lambda: f"art_{uuid.uuid4().hex}")
    kind: str = "text"
    mime_type: str = "text/plain"
    sha256: str = ""
    size_bytes: int = 0
    excerpt: str = ""
    storage_uri: str = ""
    redacted: bool = True
    retention_until: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("excerpt", mode="before")
    @classmethod
    def redact_excerpt(cls, value: Any) -> str:
        return redact(str(value or ""))[:8000]


class CandidateFindingV1(ContractModel):
    candidate_id: str = Field(default_factory=lambda: f"cand_{uuid.uuid4().hex}")
    title: str
    vuln_type: str
    severity: str = "INFO"
    target_url: str = ""
    method: str = "GET"
    parameter: str = ""
    injection_point: str = ""
    fingerprint: str = ""
    status: CandidateStatus = "suspected"
    confidence_score: float = 0.5
    confidence_reasons: List[str] = Field(default_factory=list)
    observation_ids: List[str] = Field(default_factory=list)
    remediation: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)

    @field_validator("confidence_score")
    @classmethod
    def confidence_range(cls, value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    @field_validator("title", "remediation", mode="before")
    @classmethod
    def redact_finding_text(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def ensure_fingerprint(self) -> "CandidateFindingV1":
        if not self.fingerprint:
            self.fingerprint = make_fingerprint(
                self.vuln_type, self.target_url, self.method,
                self.parameter, self.injection_point,
            )
        return self


class ToolErrorV1(ContractModel):
    code: str = "tool_error"
    message: str = ""
    retryable: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("message", mode="before")
    @classmethod
    def redact_message(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class ToolResultV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    tool_run_id: str = Field(default_factory=lambda: f"run_{uuid.uuid4().hex}")
    tool_name: str
    tool_version: str = "1"
    category: str = "unknown"
    target: str = ""
    started_at: str = Field(default_factory=now_iso)
    finished_at: Optional[str] = None
    status: ToolStatus = "succeeded"
    inputs_redacted: Dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    observations: List[ObservationV1] = Field(default_factory=list)
    artifacts: List[ArtifactV1] = Field(default_factory=list)
    candidate_findings: List[CandidateFindingV1] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    errors: List[ToolErrorV1] = Field(default_factory=list)
    side_effects: List[Dict[str, Any]] = Field(default_factory=list)
    cleanup_refs: List[str] = Field(default_factory=list)
    legacy_source: bool = False

    @field_validator("summary", mode="before")
    @classmethod
    def redact_summary(cls, value: Any) -> str:
        return redact(str(value or ""))[:4000]

    def model_post_init(self, __context: Any) -> None:
        self.inputs_redacted = redact(self.inputs_redacted)
        self.metrics = redact(self.metrics)
        self.side_effects = redact(self.side_effects)
        self.cleanup_refs = redact(self.cleanup_refs)
        for observation in self.observations:
            observation.metadata = redact(observation.metadata)
        for artifact in self.artifacts:
            artifact.metadata = redact(artifact.metadata)
        for finding in self.candidate_findings:
            finding.metadata = redact(finding.metadata)
            if not finding.target_url:
                finding.target_url = self.target
            finding.ensure_fingerprint()
        if not self.finished_at and self.status != "running":
            self.finished_at = now_iso()

    def llm_summary(self) -> str:
        """Safe, bounded representation for model prompts and UI logs."""
        payload = {
            "schema_version": self.schema_version,
            "tool": self.tool_name,
            "status": self.status,
            "summary": self.summary[:1000],
            "observations": [
                {
                    "id": item.observation_id,
                    "role": item.role,
                    "kind": item.kind,
                    "summary": item.summary[:500],
                    "status_code": item.status_code,
                }
                for item in self.observations[:30]
            ],
            "candidates": [
                {
                    "id": item.candidate_id,
                    "title": item.title[:300],
                    "type": item.vuln_type,
                    "severity": item.severity,
                    "status": item.status,
                    "confidence": item.confidence_score,
                    "observation_ids": item.observation_ids,
                }
                for item in self.candidate_findings
            ],
            "errors": [item.model_dump() for item in self.errors],
        }
        return json.dumps(payload, ensure_ascii=False)


def result_from_legacy(tool_name: str, target: str, output: Any, tool_run_id: str = "") -> ToolResultV1:
    """Convert old scanner output without treating text severity markers as truth.

    JSON objects with explicit finding/vulnerability arrays become candidates.
    Free-form text becomes an observation only.
    """
    raw = output if isinstance(output, str) else json.dumps(output, default=str)
    parsed: Any = None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        pass

    observations = [ObservationV1(
        role="external" if isinstance(parsed, dict) and parsed.get("external_tool") else "test",
        kind="legacy_output",
        summary=redact(raw)[:2000],
        target_url=target,
        response_excerpt=redact(raw)[:8000],
        metadata={"legacy": True},
    )]
    candidates: List[CandidateFindingV1] = []
    access_control_legacy = {
        "scan_idor", "idor_uuid_scanner", "access_control_scanner",
        "IDOR Scanner", "IDOR UUID Scanner", "Access Control Scanner",
    }
    # The old ID mutation scanners do not possess identity/ownership/control
    # evidence. In strict mode their output remains historical observation
    # only; the authorization replay engine is the sole finding producer.
    legacy_candidate_allowed = not (
        tool_name in access_control_legacy
        and str(get_setting("structured_evidence_mode", "strict")).lower() == "strict"
    )
    items: List[Any] = []
    if isinstance(parsed, dict):
        for key in ("findings", "vulnerabilities", "candidates"):
            value = parsed.get(key)
            if isinstance(value, list):
                items.extend(value)
        if parsed.get("finding") and isinstance(parsed["finding"], dict):
            items.append(parsed["finding"])
    elif isinstance(parsed, list):
        items = parsed

    for item in items:
        if not isinstance(item, dict):
            continue
        title = item.get("title") or item.get("name") or item.get("type")
        vuln_type = item.get("vuln_type") or item.get("type") or item.get("category")
        if not title or not vuln_type:
            continue
        candidate = CandidateFindingV1(
            title=str(title),
            vuln_type=str(vuln_type),
            severity=str(item.get("severity", "INFO")).upper(),
            target_url=str(item.get("url") or item.get("target_url") or target),
            method=str(item.get("method", "GET")),
            parameter=str(item.get("parameter") or item.get("param") or ""),
            injection_point=str(item.get("injection_point") or ""),
            confidence_score=float(item.get("confidence_score", 0.5) or 0.5),
            confidence_reasons=["Legacy scanner output; deterministic validation required."],
            observation_ids=[observations[0].observation_id],
            remediation=str(item.get("remediation") or item.get("recommendation") or ""),
            metadata={"legacy_item": True},
        )
        if legacy_candidate_allowed:
            candidates.append(candidate.ensure_fingerprint())

    return ToolResultV1(
        tool_run_id=tool_run_id or f"run_{uuid.uuid4().hex}",
        tool_name=tool_name,
        category="legacy",
        target=target,
        inputs_redacted={},
        summary=redact(raw)[:4000],
        observations=observations,
        candidate_findings=candidates,
        legacy_source=True,
    )

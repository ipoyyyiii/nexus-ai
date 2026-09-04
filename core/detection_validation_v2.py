"""Versioned, fail-closed validation for Stage 9.

The legacy ``ValidationEngine`` remains available for Stage 1/6 compatibility.
This module is the Stage 9 authority: it never promotes a candidate from a
confidence score, response status, or response length alone.  A policy must
match, evidence must be linked explicitly, and every mandatory check is
recorded in an immutable trace-shaped result.
"""

from __future__ import annotations

import hashlib
import json
import re
import statistics
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.redact import redact
from core.structured_contract import (
    CandidateFindingV1,
    ObservationV1,
    ProtocolExchangeV1,
    SemanticComparisonV1,
    ToolResultV1,
)


Decision = Literal["validated", "disproven", "inconclusive"]
FailureClass = Literal[
    "missing_evidence",
    "missing_control",
    "unstable_signal",
    "unsupported_policy",
    "execution_error",
    "cleanup_error",
    "stale_evidence",
    "scope_error",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(value: Any, length: int = 64) -> str:
    payload = json.dumps(redact(value), sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


class DetectionContract(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ValidationPolicyV2(DetectionContract):
    schema_version: Literal["2.0"] = "2.0"
    policy_id: str
    version: str = "2.0"
    vulnerability_family: str
    subtypes: List[str] = Field(default_factory=list)
    mandatory_observation_roles: List[str] = Field(default_factory=list)
    minimum_iterations: int = Field(default=1, ge=1, le=100)
    requires_baseline: bool = True
    requires_control: bool = True
    requires_clean_reproduction: bool = True
    requires_cleanup: bool = False
    required_evidence_kinds: List[str] = Field(default_factory=list)
    failure_classification: FailureClass = "missing_evidence"
    thresholds: Dict[str, float] = Field(default_factory=dict)
    noise_tolerance: float = Field(default=0.0, ge=0.0, le=1.0)
    description: str = ""
    active: bool = True

    @field_validator("description", mode="before")
    @classmethod
    def _clean_description(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    def fingerprint(self) -> str:
        return _digest(self.model_dump(mode="json"))


class ValidationContextV2(DetectionContract):
    schema_version: Literal["2.0"] = "2.0"
    candidate_id: str
    policy_id: str
    policy_version: str
    input_digest: str
    observation_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    identity_ids: List[str] = Field(default_factory=list)
    iteration_count: int = 0
    # Legacy values are accepted when loading old validation traces. New
    # validation is always authoritative and uses ``autonomous``.
    mode: Literal["autonomous", "shadow", "strict"] = "autonomous"
    created_at: str = Field(default_factory=_now)


class ValidationCheckV2(DetectionContract):
    schema_version: Literal["2.0"] = "2.0"
    check_id: str
    required: bool = True
    passed: bool = False
    reason: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    observation_ids: List[str] = Field(default_factory=list)
    input_digest: str = ""
    failure_classification: Optional[FailureClass] = None

    @field_validator("reason", mode="before")
    @classmethod
    def _clean_reason(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]

    @property
    def name(self) -> str:
        """Compatibility alias for the pre-V2 check dictionary shape."""
        return self.check_id


class ValidationDecisionV2(DetectionContract):
    schema_version: Literal["2.0"] = "2.0"
    validation_run_id: str = Field(default_factory=lambda: f"val2_{uuid.uuid4().hex}")
    candidate_id: str
    policy_id: str
    policy_version: str
    decision: Decision
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = ""
    checks: List[ValidationCheckV2] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    observation_ids: List[str] = Field(default_factory=list)
    input_digest: str = ""
    failure_classification: Optional[FailureClass] = None
    mode: Literal["autonomous", "shadow", "strict"] = "autonomous"
    promoted: bool = False
    created_at: str = Field(default_factory=_now)

    @field_validator("reason", mode="before")
    @classmethod
    def _clean_reason(cls, value: Any) -> str:
        return redact(str(value or ""))[:2000]


class ValidationTraceV2(DetectionContract):
    schema_version: Literal["2.0"] = "2.0"
    trace_id: str = Field(default_factory=lambda: f"trace2_{uuid.uuid4().hex}")
    candidate_id: str
    policy_id: str
    policy_version: str
    validator_version: str = "2.0"
    context: ValidationContextV2
    checks: List[ValidationCheckV2] = Field(default_factory=list)
    decision: Decision = "inconclusive"
    evidence_ids: List[str] = Field(default_factory=list)
    shadow_decision: Optional[Decision] = None
    created_at: str = Field(default_factory=_now)


def _policy(
    policy_id: str,
    family: str,
    *,
    roles: Sequence[str],
    subtypes: Sequence[str] = (),
    iterations: int = 1,
    cleanup: bool = False,
    kinds: Sequence[str] = (),
    thresholds: Optional[Dict[str, float]] = None,
    description: str = "",
) -> ValidationPolicyV2:
    return ValidationPolicyV2(
        policy_id=policy_id,
        vulnerability_family=family,
        subtypes=list(subtypes),
        mandatory_observation_roles=list(roles),
        minimum_iterations=iterations,
        requires_baseline="baseline" in roles,
        requires_control=any(item in roles for item in ("negative_control", "positive_control")),
        requires_clean_reproduction="reproduction" in roles,
        requires_cleanup=cleanup,
        required_evidence_kinds=list(kinds),
        thresholds=thresholds or {},
        description=description,
    )


class ValidationPolicyRegistryV2:
    """Static, versioned policy registry; target-specific values stay in evidence."""

    VERSION = "2.0"

    def __init__(self, policies: Optional[Iterable[ValidationPolicyV2]] = None) -> None:
        self._policies = {item.policy_id: item for item in (policies or self._default_policies())}
        if len(self._policies) != len(list(policies or self._default_policies())):
            raise ValueError("Duplicate Stage 9 validation policy id")

    @staticmethod
    def _default_policies() -> List[ValidationPolicyV2]:
        return [
            _policy("command_injection.ssti.v2", "command_injection", roles=("baseline", "test", "negative_control", "reproduction"), iterations=3, thresholds={"max_jitter_ratio": 0.25}, description="Harmless marker/arithmetic or timing signal with controls and clean reproduction."),
            _policy("idor.tenant_isolation.v2", "authorization", subtypes=("idor", "bola", "tenant_isolation"), roles=("baseline", "test", "negative_control", "reproduction"), kinds=("resource_state", "identity_comparison"), description="Two explicit identities and semantic same-resource comparison."),
            _policy("auth.session_oauth.v2", "authentication", roles=("baseline", "test", "negative_control", "reproduction"), kinds=("state_transition",), description="Pre/action/post state with negative control for session and OAuth invariants."),
            _policy("cors.v2", "cors", roles=("baseline", "test", "negative_control"), kinds=("credentialed_response",), description="Credentialed sensitive response must be readable by attacker origin and denied to control."),
            _policy("misconfiguration.exposure.v2", "misconfiguration", roles=("test",), kinds=("http_exchange", "legacy_finding"), description="Directly observed configuration exposure with typed scanner evidence; no exploit claim is inferred from severity alone."),
            _policy("open_redirect.v2", "open_redirect", roles=("baseline", "test", "negative_control", "reproduction"), kinds=("navigation",), description="Actual external navigation with internal control and reproduction."),
            _policy("api_schema_mass_assignment.v2", "api_schema", roles=("baseline", "test", "negative_control", "reproduction"), kinds=("entity_state",), description="Server-side entity state diff, field classification, control, and reproduction."),
            _policy("business_logic.v2", "business_logic", roles=("baseline", "test", "negative_control", "reproduction"), cleanup=True, kinds=("state_transition", "invariant_check"), description="Typed invariant violation with state evidence and cleanup."),
            _policy("sqli.lfi.v2", "injection", roles=("baseline", "test", "negative_control", "reproduction"), iterations=2, thresholds={"max_jitter_ratio": 0.25}, description="Error, boolean, and time-based injection requires differential controls."),
            _policy("xss.reflected_stored.v2", "xss", roles=("test", "browser", "negative_control", "reproduction"), cleanup=True, kinds=("browser_execution",), description="Executable-context reflection or storage plus browser execution and cleanup."),
            _policy("ssrf.xxe_oob.v2", "oob", roles=("test", "oob", "negative_control", "reproduction"), kinds=("oob_correlation",), description="Dynamic OOB correlation, attribution, stale rejection, control, and reproduction."),
            _policy("race_condition.v2", "race_condition", roles=("baseline", "test", "negative_control", "reproduction"), iterations=1, cleanup=True, kinds=("server_state",), description="Synchronized server-side effect difference with clean reproduction and cleanup."),
            _policy("graphql.schema_and_authorization.v2", "graphql", subtypes=("schema", "authorization", "idor"), roles=("baseline", "test", "negative_control", "reproduction"), kinds=("schema_diff", "authorization_diff", "entity_state"), description="GraphQL schema and field/object authorization require semantic identity comparison."),
            _policy("graphql.query_abuse.v2", "graphql", subtypes=("batch", "depth", "alias", "parser"), roles=("baseline", "test", "negative_control", "reproduction"), kinds=("resource_state", "query_cost"), description="GraphQL query abuse requires bounded cost or server-side impact, not acceptance alone."),
            _policy("websocket.authorization.v2", "websocket", roles=("baseline", "test", "negative_control", "reproduction"), kinds=("message_authorization", "entity_state"), description="WebSocket handshake and per-message authorization across identities."),
            _policy("sse.access_control.v2", "sse", roles=("baseline", "test", "negative_control", "reproduction"), kinds=("stream_access", "event_state"), description="SSE stream and event filtering must be compared across clean identities."),
            _policy("grpc_web.authorization.v2", "grpc_web", roles=("baseline", "test", "negative_control", "reproduction"), kinds=("method_authorization", "entity_state"), description="gRPC-web method and metadata authorization with typed frame evidence."),
            _policy("oauth_oidc.lifecycle.v2", "oauth", subtypes=("oauth", "oidc", "state", "pkce", "redirect", "replay"), roles=("baseline", "test", "negative_control", "reproduction"), kinds=("state_transition", "credential_binding"), description="OAuth/OIDC lifecycle invariants require pre/action/post state and negative controls."),
            _policy("jwt.signed_url.integrity.v2", "authentication", subtypes=("jwt", "signed_url"), roles=("baseline", "test", "negative_control", "reproduction"), kinds=("claim_validation", "authorization_diff"), description="JWT and signed URL integrity requires a server-side authorization effect."),
            _policy("webhook.replay_authentication.v2", "webhook", roles=("baseline", "test", "negative_control", "reproduction"), kinds=("signature_check", "state_transition"), description="Webhook signatures, freshness, tenant binding, and replay controls."),
            _policy("async_job.authorization_idempotency.v2", "async_job", roles=("baseline", "test", "negative_control", "reproduction"), cleanup=True, kinds=("job_state", "entity_state"), description="Async job ownership, replay, and idempotency require server-side state evidence."),
            _policy("gateway.normalization.v2", "gateway", roles=("baseline", "test", "negative_control", "reproduction"), kinds=("route_resolution", "authorization_diff"), description="Gateway/origin normalization requires a differential authorization impact."),
            _policy("cache.identity_separation.v2", "cache", roles=("baseline", "test", "negative_control", "reproduction"), cleanup=True, kinds=("cache_state", "sensitive_response"), description="Cache behavior must demonstrate cross-identity data exposure and clean invalidation."),
            _policy("upload.pipeline.v2", "upload", roles=("baseline", "test", "negative_control", "reproduction"), cleanup=True, kinds=("entity_state", "retrieval_authorization"), description="Upload pipeline validation uses harmless canaries, storage state, retrieval auth, and cleanup."),
            _policy("schema.type_confusion.v2", "api_schema", subtypes=("type_confusion", "unknown_field", "method_schema"), roles=("baseline", "test", "negative_control", "reproduction"), kinds=("entity_state",), description="Typed schema mutation requires a reproducible unauthorized server-side state change."),
            _policy("parser.context_mutation.v2", "parser", roles=("baseline", "test", "negative_control", "reproduction"), kinds=("parser_state", "entity_state"), description="Parser/context differential requires typed input and semantic state evidence."),
        ]

    def list(self, active_only: bool = True) -> List[ValidationPolicyV2]:
        values = list(self._policies.values())
        return [item for item in values if item.active] if active_only else values

    def get(self, policy_id: str) -> Optional[ValidationPolicyV2]:
        return self._policies.get(policy_id)

    def fingerprint(self) -> str:
        return _digest([item.model_dump(mode="json") for item in self.list(False)])

    def resolve(self, candidate: CandidateFindingV1 | str, subtype: str = "") -> Optional[ValidationPolicyV2]:
        # Keep the candidate-based resolver as the canonical path, while
        # allowing diagnostics/API callers to resolve a typed family directly.
        # This does not create a generic policy: it still traverses the exact
        # versioned registry below.
        if isinstance(candidate, str):
            candidate = CandidateFindingV1(
                title=candidate,
                vuln_type=candidate,
                metadata={"protocol_family": candidate, "subtype": subtype},
            )
        vuln = candidate.vuln_type.lower().replace("-", "_").replace(" ", "_")
        metadata = candidate.metadata or {}
        subtype = str(metadata.get("subtype") or "").lower()
        protocol = str(metadata.get("protocol_family") or metadata.get("protocol") or metadata.get("protocol_name") or "").lower()
        protocol = {
            "parser-context": "parser", "semantic-comparison": "parser",
            "gateway-normalization": "gateway", "upload-pipeline": "upload",
            "schema-type-confusion": "schema", "evidence-scope-cleanup": "parser",
            "graphql-schema": "graphql", "graphql-query-abuse": "graphql",
            "websocket-authorization": "websocket", "sse-access-control": "sse",
            "grpc-web-authorization": "grpc_web", "oauth-oidc-lifecycle": "oauth",
            "jwt-signed-url": "signed_url", "webhook-replay": "webhook",
            "async-job": "async_job", "cache-identity-separation": "cache",
        }.get(protocol, protocol)
        if protocol == "graphql":
            return self.get("graphql.query_abuse.v2" if subtype in {"batch", "depth", "alias", "parser", "query_abuse"} else "graphql.schema_and_authorization.v2")
        if protocol == "websocket":
            return self.get("websocket.authorization.v2")
        if protocol == "sse":
            return self.get("sse.access_control.v2")
        if protocol == "grpc_web":
            return self.get("grpc_web.authorization.v2")
        if protocol in {"oauth", "oidc"}:
            return self.get("oauth_oidc.lifecycle.v2")
        if protocol in {"jwt", "signed_url"} or subtype in {"jwt", "signed_url"}:
            return self.get("jwt.signed_url.integrity.v2")
        if protocol == "webhook":
            return self.get("webhook.replay_authentication.v2")
        if protocol == "async_job":
            return self.get("async_job.authorization_idempotency.v2")
        if protocol == "cache":
            return self.get("cache.identity_separation.v2")
        if protocol == "gateway":
            return self.get("gateway.normalization.v2")
        if protocol == "upload":
            return self.get("upload.pipeline.v2")
        if protocol == "parser":
            return self.get("parser.context_mutation.v2")
        if protocol == "gateway":
            return self.get("gateway.normalization.v2")
        if protocol == "upload":
            return self.get("upload.pipeline.v2")
        if protocol in {"schema", "type_confusion"}:
            return self.get("schema.type_confusion.v2")
        if subtype in {
            "missing_security_header", "weak_security_header", "server_version_disclosure",
            "sensitive_file_exposure", "backup_file_exposure", "admin_panel_exposure",
            "debug_disclosure", "clickjacking", "insecure_cookie",
        }:
            return self.get("misconfiguration.exposure.v2")
        if any(item in vuln for item in (
            "missing security header", "weak security header", "server version disclosure",
            "sensitive file", "backup file", "exposed admin", "admin panel",
            "debug mode", "verbose error", "clickjacking", "insecure cookie",
        )):
            return self.get("misconfiguration.exposure.v2")
        if any(item in vuln for item in ("command_injection", "command injection", "ssti", "server_side_template")):
            return self.get("command_injection.ssti.v2")
        if any(item in vuln for item in ("idor", "bola", "tenant", "authorization", "access_control")):
            return self.get("idor.tenant_isolation.v2")
        if any(item in vuln for item in ("oauth", "session", "authentication", "auth")):
            return self.get("auth.session_oauth.v2")
        if "cors" in vuln:
            return self.get("cors.v2")
        if "redirect" in vuln:
            return self.get("open_redirect.v2")
        if any(item in vuln for item in ("mass_assignment", "api_schema", "schema")):
            return self.get("api_schema_mass_assignment.v2")
        if "business" in vuln or "invariant" in vuln:
            return self.get("business_logic.v2")
        if any(item in vuln for item in ("race", "concurrency", "double_submit")):
            return self.get("race_condition.v2")
        if any(item in vuln for item in ("xss", "cross_site")):
            return self.get("xss.reflected_stored.v2")
        if any(item in vuln for item in ("ssrf", "xxe", "blind_rce", "oob")):
            return self.get("ssrf.xxe_oob.v2")
        if any(item in vuln for item in ("sql", "sqli", "lfi", "file_inclusion", "path_traversal")):
            return self.get("sqli.lfi.v2")
        # Subtype can be supplied by a neutral candidate category without
        # creating a generic policy. It is only used for known families.
        if subtype in {"cors", "open_redirect", "idor", "ssti"}:
            return self.get({"cors": "cors.v2", "open_redirect": "open_redirect.v2", "idor": "idor.tenant_isolation.v2", "ssti": "command_injection.ssti.v2"}[subtype])
        return None


class ValidationEngineV2:
    """Fail-closed deterministic validator with complete check trace."""

    VERSION = "2.0"
    _ERROR_SIGNATURES = re.compile(r"sql syntax|sqlstate|mysql|postgresql|sqlite|ora-\d+|odbc|root:x:0:0|/etc/passwd", re.I)

    def __init__(self, mode: Optional[str] = None, registry: Optional[ValidationPolicyRegistryV2] = None) -> None:
        # Validation is not a selectable shadow/strict lane. Candidates are
        # always evaluated by the authoritative evidence policy.
        self.mode = "autonomous"
        self.registry = registry or ValidationPolicyRegistryV2()
        self.last_traces: List[ValidationTraceV2] = []

    def validate(self, result: ToolResultV1, *, mode: Optional[str] = None, apply_status: Optional[bool] = None) -> List[ValidationDecisionV2]:
        effective_mode = "autonomous"
        promote = True if apply_status is None else bool(apply_status)
        observations = {item.observation_id: item for item in result.observations}
        decisions: List[ValidationDecisionV2] = []
        self.last_traces = []
        for candidate in result.candidate_findings:
            policy = self.registry.resolve(candidate)
            decision, trace = self._validate_candidate(candidate, policy, observations, effective_mode, promote)
            decisions.append(decision)
            self.last_traces.append(trace)
            if promote:
                candidate.status = decision.decision if decision.decision in {"validated", "disproven", "inconclusive"} else "inconclusive"
                candidate.confidence_score = min(candidate.confidence_score, decision.score)
                candidate.confidence_reasons.append(f"V2 {decision.policy_id}: {decision.reason}")
        return decisions

    def _validate_candidate(self, candidate: CandidateFindingV1, policy: Optional[ValidationPolicyV2], observations: Dict[str, ObservationV1], mode: str, promote: bool) -> tuple[ValidationDecisionV2, ValidationTraceV2]:
        linked = [observations[item] for item in candidate.observation_ids if item in observations]
        input_digest = _digest({"candidate": candidate.model_dump(mode="json"), "observations": [item.model_dump(mode="json") for item in linked]})
        if policy is None:
            context = ValidationContextV2(candidate_id=candidate.candidate_id, policy_id="unsupported", policy_version=self.VERSION, input_digest=input_digest, observation_ids=[item.observation_id for item in linked], mode=mode)
            check = ValidationCheckV2(check_id="policy_supported", passed=False, reason="No versioned deterministic policy matches this candidate.", input_digest=input_digest, failure_classification="unsupported_policy")
            decision = ValidationDecisionV2(candidate_id=candidate.candidate_id, policy_id="unsupported", policy_version=self.VERSION, decision="inconclusive", score=0.0, reason="No versioned deterministic policy matches this candidate.", checks=[check], input_digest=input_digest, mode=mode, promoted=False)
            return decision, ValidationTraceV2(candidate_id=candidate.candidate_id, policy_id="unsupported", policy_version=self.VERSION, context=context, checks=[check], decision="inconclusive", input_digest=input_digest)

        role_map = {role: [item for item in linked if item.role == role] for role in set(policy.mandatory_observation_roles)}
        checks: List[ValidationCheckV2] = []
        evidence = [item.observation_id for item in linked]
        linked_ok = bool(candidate.observation_ids) and bool(linked) and len(linked) == len(set(candidate.observation_ids))
        checks.append(self._check("candidate_evidence_linked", linked_ok, "Candidate must link to persisted observations explicitly.", linked, input_digest, "missing_evidence"))
        for role in policy.mandatory_observation_roles:
            checks.append(self._check(f"role_{role}", bool(role_map.get(role)), f"Mandatory observation role '{role}' is required.", role_map.get(role, []), input_digest, "missing_control" if "control" in role else "missing_evidence"))
        iterations = self._iterations(candidate, linked)
        if policy.minimum_iterations > 1:
            checks.append(ValidationCheckV2(check_id="minimum_iterations", required=True, passed=iterations >= policy.minimum_iterations, reason=f"Observed {iterations} iterations; required {policy.minimum_iterations}.", evidence_ids=evidence, observation_ids=evidence, input_digest=input_digest, failure_classification="unstable_signal" if iterations else "missing_evidence"))
        if policy.requires_cleanup:
            cleanup = bool((candidate.metadata or {}).get("cleanup_verified")) or any(bool(item.metadata.get("cleanup_verified")) for item in linked)
            checks.append(self._check("cleanup_verified", cleanup, "Cleanup must be explicitly verified.", linked, input_digest, "cleanup_error"))

        signal, signal_checks, signal_reason, signal_failure = self._family_checks(candidate, policy, linked, role_map, input_digest)
        checks.extend(signal_checks)
        mandatory_pass = all(item.passed for item in checks if item.required)
        score = sum(bool(item.passed) for item in checks) / max(1, len(checks))
        expected_safe = bool((candidate.metadata or {}).get("signal_absent") or (candidate.metadata or {}).get("expected_safe"))
        if mandatory_pass and signal is True:
            final: Decision = "validated"
            reason = signal_reason or "All mandatory deterministic checks passed."
            failure = None
        elif mandatory_pass and (signal is False or expected_safe):
            final = "disproven"
            reason = signal_reason or "Controls and evidence show the candidate signal is absent."
            failure = None
        else:
            final = "inconclusive"
            reason = signal_reason or "Mandatory evidence or control checks are incomplete."
            failure = signal_failure or next((item.failure_classification for item in checks if not item.passed and item.failure_classification), "missing_evidence")
        context = ValidationContextV2(candidate_id=candidate.candidate_id, policy_id=policy.policy_id, policy_version=policy.version, input_digest=input_digest, observation_ids=evidence, evidence_ids=evidence, identity_ids=sorted({str(item.metadata.get("identity_id")) for item in linked if item.metadata.get("identity_id")}), iteration_count=iterations, mode=mode)
        decision = ValidationDecisionV2(candidate_id=candidate.candidate_id, policy_id=policy.policy_id, policy_version=policy.version, decision=final, score=score, reason=reason, checks=checks, evidence_ids=evidence, observation_ids=evidence, input_digest=input_digest, failure_classification=failure, mode=mode, promoted=promote and final in {"validated", "disproven", "inconclusive"})
        trace = ValidationTraceV2(candidate_id=candidate.candidate_id, policy_id=policy.policy_id, policy_version=policy.version, context=context, checks=checks, decision=final, evidence_ids=evidence)
        return decision, trace

    @staticmethod
    def _iterations(candidate: CandidateFindingV1, observations: Sequence[ObservationV1]) -> int:
        value = (candidate.metadata or {}).get("iterations")
        if isinstance(value, int):
            return max(0, value)
        values = {item.metadata.get("iteration") for item in observations if item.metadata.get("iteration") is not None}
        return len(values) or (1 if observations else 0)

    @staticmethod
    def _check(check_id: str, passed: bool, reason: str, observations: Sequence[ObservationV1], digest: str, failure: FailureClass) -> ValidationCheckV2:
        ids = [item.observation_id for item in observations]
        return ValidationCheckV2(check_id=check_id, passed=passed, reason=reason, evidence_ids=ids if passed else ids, observation_ids=ids, input_digest=digest, failure_classification=None if passed else failure)

    def _family_checks(self, candidate: CandidateFindingV1, policy: ValidationPolicyV2, linked: Sequence[ObservationV1], roles: Dict[str, List[ObservationV1]], digest: str) -> tuple[Optional[bool], List[ValidationCheckV2], str, Optional[FailureClass]]:
        meta = candidate.metadata or {}
        text = lambda item: f"{item.summary} {item.response_excerpt}".strip()
        def has_text(items: Sequence[ObservationV1], pattern: str) -> bool:
            return any(re.search(pattern, text(item), re.I) for item in items)
        def add(cid: str, passed: bool, reason: str, items: Sequence[ObservationV1], failure: FailureClass = "missing_evidence") -> ValidationCheckV2:
            return self._check(cid, passed, reason, items, digest, failure)

        if policy.policy_id == "misconfiguration.exposure.v2":
            # This policy validates the narrower claim "the configured
            # exposure was observed".  It must never be interpreted as proof
            # of exploitability or business impact.
            subtype = str(meta.get("subtype") or "").lower()
            detail = " ".join(
                f"{item.summary} {item.response_excerpt}" for item in linked
            ).lower()
            header_present = meta.get("header_present")
            header_signal = subtype in {"missing_security_header", "weak_security_header"} and (
                header_present is False or bool(meta.get("header_weak"))
            )
            version_signal = subtype == "server_version_disclosure" and bool(
                re.search(r"\b\d+\.\d+(?:\.\d+)?\b", detail)
            )
            admin_signal = subtype == "admin_panel_exposure" and (
                bool(meta.get("accessible"))
                or "accessible without pre-auth" in detail
                or (meta.get("status_code") == 200 and any(
                    marker in detail for marker in ("login", "username", "password", "admin")
                ))
            )
            debug_signal = subtype == "debug_disclosure" and any(
                marker in detail for marker in ("traceback", "stack trace", "werkzeug", "debug=true", "exception")
            )
            browser_signal = subtype == "clickjacking" and bool(
                meta.get("vulnerable")
                or meta.get("marker_executed")
                or meta.get("x_frame_options") in {"", "MISSING"}
            )
            cookie_signal = subtype == "insecure_cookie" and bool(
                meta.get("insecure") or meta.get("cookie_insecure") or "missing secure" in detail
            )
            file_signal = subtype in {"sensitive_file_exposure", "backup_file_exposure"} and bool(
                meta.get("content_verified")
                and str(meta.get("status_code") or meta.get("found_status") or "") == "200"
            )
            signal = any((header_signal, version_signal, admin_signal, debug_signal, browser_signal, cookie_signal, file_signal))
            checks = [
                add("typed_exposure_record", bool(meta.get("finding_type")) and bool(linked), "A typed scanner record and linked observation are required.", linked),
                add("exposure_signal", signal, "The claimed exposure must be explicitly represented by typed evidence; severity text alone is insufficient.", linked),
            ]
            return signal, checks, (
                "Directly observed configuration exposure reproduced."
                if signal else
                "Configuration exposure lacks typed evidence sufficient for validation."
            ), None

        if policy.policy_id == "sqli.lfi.v2":
            baseline, test, control, repro = roles.get("baseline", []), roles.get("test", []), roles.get("negative_control", []), roles.get("reproduction", [])
            subtype = str(meta.get("subtype", "error")).lower()
            checks = [add("error_absent_baseline", not any(self._ERROR_SIGNATURES.search(text(item)) for item in baseline), "Injection signature must be absent from baseline.", baseline, "unstable_signal"), add("error_absent_control", not any(self._ERROR_SIGNATURES.search(text(item)) for item in control), "Injection signature must be absent from negative control.", control, "unstable_signal")]
            if "boolean" in subtype:
                checks.extend([add("boolean_true_matches_baseline", bool(meta.get("true_condition_matches_baseline")), "True condition must resemble baseline.", test, "unstable_signal"), add("boolean_false_differs", bool(meta.get("false_condition_differs")), "False condition must differ from baseline.", test, "unstable_signal")])
                signal = bool(meta.get("true_condition_matches_baseline")) and bool(meta.get("false_condition_differs"))
            elif "time" in subtype:
                stable = self._timing_stable(meta, policy)
                checks.append(add("timing_delta_stable", stable, "Randomized baseline/test/control timing must exceed jitter threshold.", linked, "unstable_signal"))
                signal = stable
            else:
                signal = bool(has_text(test, self._ERROR_SIGNATURES.pattern) and has_text(repro, self._ERROR_SIGNATURES.pattern))
                checks.append(add("error_signature_test_and_reproduction", signal, "Error signature must appear in test and clean reproduction.", list(test) + list(repro), "missing_evidence"))
            return signal, checks, "SQL/LFI differential checks evaluated." if signal else "SQL/LFI signal was not reproducible under controls.", None

        if policy.policy_id == "command_injection.ssti.v2":
            marker = str(meta.get("marker") or "")
            arithmetic = bool(meta.get("arithmetic_result_match"))
            marker_seen = bool(meta.get("marker_seen")) or (bool(marker) and any(marker in text(item) for item in roles.get("test", []) + roles.get("reproduction", [])))
            baseline_clean = not (marker and any(marker in text(item) for item in roles.get("baseline", []) + roles.get("negative_control", [])))
            timing = self._timing_stable(meta, policy) if meta.get("timing_samples") else True
            checks = [add("harmless_marker_or_expression", marker_seen or arithmetic, "Only a unique harmless marker or arithmetic expression can establish the signal.", list(roles.get("test", [])) + list(roles.get("reproduction", []))), add("marker_absent_controls", baseline_clean, "Marker must be absent from baseline and control.", list(roles.get("baseline", [])) + list(roles.get("negative_control", [])), "unstable_signal"), add("timing_stable", timing, "Timing signal must be stable across randomized controls.", linked, "unstable_signal")]
            signal = (marker_seen or arithmetic) and baseline_clean and timing
            return signal, checks, "Command/SSTI harmless signal reproduced." if signal else "Command/SSTI signal lacks a controlled harmless reproduction.", "unstable_signal" if meta.get("timing_samples") and not timing else None

        if policy.policy_id == "idor.tenant_isolation.v2":
            identities = {str(item.metadata.get("identity_id")) for item in linked if item.metadata.get("identity_id")}
            resources = {str(item.metadata.get("resource_fingerprint")) for item in linked if item.metadata.get("resource_fingerprint")}
            unexpected = any(str(item.metadata.get("semantic_result", "")).lower() in {"allow", "unexpected_allow"} for item in roles.get("test", [])) or bool(meta.get("unexpected_allow"))
            expectation = bool(meta.get("private_canary") or meta.get("deny_expectation") or meta.get("expectation_id"))
            checks = [add("two_explicit_identities", len(identities) >= 2, "Owner and non-owner identity contexts are mandatory.", linked, "missing_evidence"), add("same_resource_fingerprint", len(resources) == 1 and bool(resources), "Owner and non-owner requests must address the same resource.", linked, "missing_evidence"), add("deny_expectation_or_canary", expectation, "An explicit deny expectation or private canary is required.", roles.get("negative_control", []), "missing_control"), add("semantic_resource_comparison", any(bool(item.metadata.get("resource_semantically_present")) for item in roles.get("test", [])) or bool(meta.get("semantic_comparison")), "Response status/length alone is insufficient; resource semantics are required.", roles.get("test", []), "missing_evidence"), add("non_owner_reproduction", bool(roles.get("reproduction")) and any(item.metadata.get("identity_id") for item in roles.get("reproduction", [])), "Non-owner access must reproduce from a clean context.", roles.get("reproduction", []), "missing_evidence")]
            signal = unexpected
            return signal, checks, "Unauthorized semantic resource access reproduced." if signal else "Authorization boundary was not shown to be bypassed.", None

        if policy.policy_id == "auth.session_oauth.v2":
            subtype = str(meta.get("subtype", "")).lower()
            required_flag = {"session_rotation": "session_rotated", "logout_invalidation": "logout_invalidated", "session_fixation": "fixation_rejected", "oauth_state": "state_bound", "pkce": "pkce_bound", "redirect_uri": "redirect_uri_exact", "token_claims": "token_claims_valid", "code_replay": "code_replay_rejected"}.get(subtype, "auth_invariant_holds")
            passed = required_flag in meta
            checks = [add("pre_state_present", bool(meta.get("pre_state")) or bool(roles.get("baseline")), "Pre-state is required.", roles.get("baseline", [])), add("action_and_post_state", bool(meta.get("action")) and (bool(meta.get("post_state")) or bool(roles.get("test"))), "Action and post-state are required.", roles.get("test", [])), add("negative_control", bool(roles.get("negative_control")), "A negative control is mandatory.", roles.get("negative_control", []), "missing_control"), add("typed_auth_invariant", passed, f"Typed auth invariant '{required_flag}' must be checked.", linked, "missing_evidence")]
            signal = bool(meta.get("unexpected_allow") or meta.get("invariant_violated"))
            return signal, checks, "Authentication/session invariant was violated." if signal else "Authentication/session invariant held or was not demonstrated as violated.", None

        if policy.policy_id == "cors.v2":
            attacker = bool(meta.get("attacker_origin_accepted"))
            credentialed = bool(meta.get("credentialed_request_allowed"))
            readable = bool(meta.get("sensitive_response_readable"))
            control = bool(meta.get("origin_control_rejected"))
            checks = [add("attacker_origin_accepted", attacker, "Attacker origin must be accepted.", roles.get("test", [])), add("credentialed_request_allowed", credentialed, "Credentialed cross-origin request must be allowed.", roles.get("test", [])), add("sensitive_response_readable", readable, "Sensitive response must actually be readable.", roles.get("test", [])), add("origin_control_rejected", control, "A control origin must be rejected.", roles.get("negative_control", []), "missing_control")]
            signal = attacker and credentialed and readable and control
            return signal, checks, "Credentialed CORS data exposure reproduced." if signal else "CORS header weakness lacks a complete credentialed impact chain.", None

        if policy.policy_id == "open_redirect.v2":
            target_host = (urlsplit(candidate.target_url).hostname or "").lower()
            external = False
            for item in roles.get("test", []) + roles.get("reproduction", []):
                location = str(item.metadata.get("location") or item.metadata.get("redirect_url") or "")
                host = (urlsplit(location).hostname or "").lower()
                if host and target_host and host != target_host:
                    external = True
            external = external or bool(meta.get("external_navigation"))
            control = bool(meta.get("same_origin_control") or meta.get("internal_control_passed"))
            checks = [add("actual_external_navigation", external, "Actual external Location or browser navigation is required.", roles.get("test", []) + roles.get("reproduction", [])), add("same_origin_control", control, "Internal/same-origin control must remain internal.", roles.get("negative_control", []), "missing_control")]
            signal = external and control
            return signal, checks, "External redirect reproduced with canonicalization control." if signal else "Redirect impact was not reproduced with a safe control.", None

        if policy.policy_id == "api_schema_mass_assignment.v2":
            state_changed = bool(meta.get("server_state_changed"))
            privileged = bool(meta.get("privileged_field_changed"))
            field_typed = str(meta.get("field_class", "")) in {"unknown", "read_only", "privileged", "type_confusion"}
            reproduced = bool(meta.get("reproduced"))
            checks = [add("entity_state_baseline", bool(meta.get("baseline_entity_state")), "Server-side baseline state is required.", roles.get("baseline", [])), add("typed_field_probe", field_typed, "Field probes must use a typed field class.", roles.get("test", [])), add("server_state_diff", state_changed, "Finding cannot be based on response text alone.", roles.get("test", [])), add("negative_control_state", bool(meta.get("negative_control_state")), "Negative control state must be captured.", roles.get("negative_control", []), "missing_control"), add("clean_reproduction", reproduced, "State change must reproduce from clean context.", roles.get("reproduction", []))]
            signal = state_changed and privileged and reproduced
            return signal, checks, "Unauthorized server-side field mutation reproduced." if signal else "API schema probe did not show a reproducible privileged state change.", None

        if policy.policy_id == "business_logic.v2":
            typed = str(meta.get("rule_type") or "") != "" and bool(meta.get("typed_rule", True))
            state = bool(meta.get("state_transition_evidence")) or any(item.kind in {"state_transition", "business_state"} for item in linked)
            violated = bool(meta.get("invariant_violated"))
            identity_ids = set(str(item) for item in (meta.get("identity_ids") or []) if item)
            identity_ids.update(str(item.metadata.get("identity_id")) for item in linked if item.metadata.get("identity_id"))
            checks = [
                add("typed_rule_compiled", typed, "Only a compiled typed rule can validate business logic.", linked, "unsupported_policy"),
                add("state_transition_evidence", state, "Before/after server state evidence is required.", linked),
                add("evaluation_id", bool(meta.get("evaluation_id")), "Deterministic invariant evaluation ID is required.", linked),
                add("identity_graph_context", bool(meta.get("graph_id")) and bool(identity_ids), "Identity graph and identity context are required.", linked, "missing_evidence"),
                add("workflow_entity_mapping", bool(meta.get("workflow_matrix_id")) and bool(meta.get("entity_fingerprint")), "The invariant must bind to a published workflow matrix and entity fingerprint.", linked, "missing_evidence"),
                add("clean_reproduction", bool(meta.get("reproduced", True)), "Violation must reproduce from a clean context.", roles.get("reproduction", [])),
                add("cleanup_verified", bool(meta.get("cleanup_verified")) or any(bool(item.metadata.get("cleanup_verified")) for item in linked), "Side effects must be cleaned and verified.", linked, "cleanup_error"),
            ]
            return violated, checks, "Typed business invariant violation reproduced." if violated else "Typed business invariant held or was not shown violated.", None

        if policy.policy_id == "xss.reflected_stored.v2":
            context = str(meta.get("reflection_context") or "") in {"html", "attribute", "script", "url", "dom"}
            escaped_control = bool(meta.get("escaped_control")) or any(
                bool(item.metadata.get("escaped_control"))
                or "escaped" in text(item).lower()
                for item in roles.get("negative_control", [])
            )
            executed = any(bool(item.metadata.get("marker_executed") or item.metadata.get("script_executed")) for item in roles.get("browser", []))
            stored_clean = bool(meta.get("stored_retrieval_clean_session")) if meta.get("stored_retrieval_clean_session") is not None else True
            checks = [add("executable_context", context, "Reflection must be in an executable context.", roles.get("test", [])), add("escaped_negative_control", escaped_control, "Escaped/encoded control must not execute.", roles.get("negative_control", []), "missing_control"), add("unique_marker_executed", executed, "A unique marker must execute in a browser context.", roles.get("browser", [])), add("clean_session_retrieval", stored_clean, "Stored XSS must execute when retrieved from a clean session.", roles.get("reproduction", [])), add("cleanup_verified", bool(meta.get("cleanup_verified")) or not bool(meta.get("stored", False)), "Stored payload cleanup must be verified.", linked, "cleanup_error")]
            signal = context and executed and stored_clean
            return signal, checks, "Executable XSS impact reproduced." if signal else "Reflection did not produce browser execution under controls.", None

        if policy.policy_id == "ssrf.xxe_oob.v2":
            correlation = bool(meta.get("correlation_id")) or any(item.metadata.get("correlation_id") or item.metadata.get("oob_correlation_id") for item in roles.get("oob", []))
            attributed = bool(meta.get("target_attributed")) or any(bool(item.metadata.get("target_attributed")) for item in roles.get("oob", []))
            stale = bool(meta.get("stale_callback")) or any(bool(item.metadata.get("stale_callback")) for item in roles.get("oob", []))
            callback_control = bool(meta.get("control_without_callback")) or bool(roles.get("negative_control"))
            checks = [add("dynamic_correlation", correlation, "OOB evidence must have a dynamic correlation ID.", roles.get("oob", [])), add("target_attribution", attributed, "Callback must be attributed to this tool run/target.", roles.get("oob", [])), add("stale_callback_rejected", not stale, "Stale callbacks cannot validate a current candidate.", roles.get("oob", []), "stale_evidence"), add("negative_callback_control", callback_control, "A control without callback is mandatory.", roles.get("negative_control", []), "missing_control")]
            signal = correlation and attributed and not stale
            return signal, checks, "Correlated OOB interaction reproduced." if signal else "Blind interaction lacks fresh attributed OOB evidence.", "stale_evidence" if stale else None

        if policy.policy_id == "race_condition.v2":
            synchronized = bool(meta.get("synchronized"))
            effect = bool(meta.get("effect_violation")) and int(meta.get("unique_effect_count", 2)) > int(meta.get("expected_effect_count", 1))
            reproduced = bool(meta.get("clean_reproduction", True))
            checks = [add("synchronized_test", synchronized, "Race test must use a synchronized barrier.", roles.get("test", [])), add("server_side_effect_difference", effect, "Server-side unique effect state must exceed the expected count.", roles.get("test", []), "missing_evidence"), add("clean_reproduction", reproduced, "Race effect must reproduce from clean context.", roles.get("reproduction", [])), add("cleanup_verified", bool(meta.get("cleanup_verified")) or any(bool(item.metadata.get("cleanup_verified")) for item in linked), "Race side effects must be cleaned and verified.", linked, "cleanup_error")]
            signal = synchronized and effect and reproduced
            return signal, checks, "Deterministic race effect reproduced." if signal else "Concurrent response difference did not establish a server-side race effect.", None

        modern_ids = {
            "graphql.schema_and_authorization.v2", "graphql.query_abuse.v2",
            "websocket.authorization.v2", "sse.access_control.v2",
            "grpc_web.authorization.v2", "oauth_oidc.lifecycle.v2",
            "jwt.signed_url.integrity.v2", "webhook.replay_authentication.v2",
            "async_job.authorization_idempotency.v2", "gateway.normalization.v2",
            "cache.identity_separation.v2", "upload.pipeline.v2",
            "schema.type_confusion.v2", "parser.context_mutation.v2",
        }
        if policy.policy_id in modern_ids:
            # All modern protocol families share the same evidence invariant:
            # the transport signal must be tied to semantic state, identity,
            # or a typed parser result.  A status/length change alone cannot
            # enter the signal path.
            semantic = bool(
                meta.get("semantic_comparison")
                or meta.get("semantic_impact")
                or meta.get("server_state_changed")
                or meta.get("entity_state_changed")
                or meta.get("authorization_diff")
            )
            typed = bool(
                meta.get("typed_probe")
                or meta.get("parser_context")
                or meta.get("schema_digest")
                or meta.get("operation_schema")
            )
            replay_stable = bool(meta.get("replay_stable", True))
            checks = [
                add("typed_protocol_input", typed, "A protocol/parser-aware input description is required.", linked, "missing_evidence"),
                add("semantic_comparison", semantic, "Protocol validation requires semantic or server-state comparison; status/length alone is insufficient.", linked, "missing_evidence"),
                add("replay_stable", replay_stable, "The protocol signal must be stable across replay.", linked, "unstable_signal"),
            ]
            if policy.policy_id in {"graphql.schema_and_authorization.v2", "websocket.authorization.v2", "sse.access_control.v2", "grpc_web.authorization.v2"}:
                identities = {str(item.metadata.get("identity_id")) for item in linked if item.metadata.get("identity_id")}
                checks.append(add("identity_contexts", len(identities) >= 2 or bool(meta.get("identity_matrix")), "Cross-identity protocol behavior requires explicit identity context.", linked, "missing_evidence"))
            if policy.policy_id in {"oauth_oidc.lifecycle.v2", "jwt.signed_url.integrity.v2", "webhook.replay_authentication.v2"}:
                checks.append(add("typed_lifecycle_state", bool(meta.get("pre_state") or meta.get("state_transition") or meta.get("claim_validation")), "Authentication protocol checks require typed pre/action/post or claim state.", linked, "missing_evidence"))
            if policy.requires_cleanup:
                checks.append(add("protocol_cleanup_verified", bool(meta.get("cleanup_verified")) or any(bool(item.metadata.get("cleanup_verified")) for item in linked), "Protocol side effects must have verified cleanup.", linked, "cleanup_error"))

            signal_keys = {
                "unauthorized_access", "unexpected_allow", "sensitive_field_exposed",
                "resource_impact", "cost_violation", "unauthorized_message",
                "unauthorized_event", "stream_exposed", "method_unauthorized",
                "invariant_violated", "replay_accepted", "state_unbound",
                "pkce_missing", "redirect_bypass", "claim_tamper_accepted",
                "signature_bypass", "duplicate_effect", "origin_mismatch",
                "cross_identity_exposure", "unsafe_retrieval", "unsafe_state_change",
                "type_confusion_impact", "parser_confusion_impact",
            }
            signal = any(bool(meta.get(key)) for key in signal_keys)
            reason = "Modern protocol semantic impact reproduced." if signal else "Modern protocol signal was not shown to create an unauthorized semantic impact."
            return signal, checks, reason, "unstable_signal" if not replay_stable else None

        return None, [add("known_family_signal", False, "Policy family has no deterministic signal evaluator.", linked, "unsupported_policy")], "Policy family is not supported by this validator version.", "unsupported_policy"

    @staticmethod
    def _timing_stable(metadata: Dict[str, Any], policy: ValidationPolicyV2) -> bool:
        raw = metadata.get("timing_samples") or {}
        if not isinstance(raw, dict):
            return False
        baseline = [float(item) for item in raw.get("baseline", []) if isinstance(item, (int, float))]
        test = [float(item) for item in raw.get("test", []) if isinstance(item, (int, float))]
        control = [float(item) for item in raw.get("control", []) if isinstance(item, (int, float))]
        if len(baseline) < 2 or len(test) < 2 or len(control) < 2:
            return False
        base = statistics.median(baseline)
        delta = statistics.median(test) - base
        jitter = max(statistics.pstdev(baseline), statistics.pstdev(control), 0.001)
        threshold = float(policy.thresholds.get("min_median_delta_ms", 100.0))
        max_ratio = float(policy.thresholds.get("max_jitter_ratio", 0.25))
        return delta >= threshold and jitter / max(abs(delta), 1.0) <= max_ratio


_DYNAMIC_KEYS = {
    "timestamp", "time", "request_id", "trace_id", "span_id", "nonce",
    "csrf", "csrf_token", "server_time", "date", "etag",
}
_TRANSPORT_KEYS = {"status_code", "response_length", "response_time_ms", "headers", "content_length"}


def _semantic_normalize(value: Any) -> Any:
    """Normalize transport noise while retaining security-relevant semantics."""
    if isinstance(value, dict):
        return {
            str(key): _semantic_normalize(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key).lower() not in _DYNAMIC_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_semantic_normalize(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"\b(?:request|trace|span|corr)[-_]?[a-f0-9]{6,}\b", "<dynamic>", value, flags=re.I)
    return value


def semantic_response_compare(
    baseline: Dict[str, Any],
    test: Dict[str, Any],
    control: Optional[Dict[str, Any]] = None,
    *,
    protocol: str = "http",
    operation_id: str = "",
    evidence_ids: Optional[List[str]] = None,
) -> SemanticComparisonV1:
    """Compare protocol responses without promoting a finding.

    The comparator deliberately reports a signal only when a semantic field,
    authorization result, or server-state digest differs from both the safe
    baseline/control context.  Status and length are recorded as metadata but
    never count as semantic impact by themselves.
    """
    base = _semantic_normalize(baseline or {})
    test_without_replay = dict(test or {}) if isinstance(test, dict) else {}
    replay = test_without_replay.pop("replay", None)
    candidate = _semantic_normalize(test_without_replay)
    safe_control = _semantic_normalize(control or baseline or {})
    keys = set(base) | set(candidate) | set(safe_control)
    transport_only = _TRANSPORT_KEYS
    changed = sorted(key for key in keys if base.get(key) != candidate.get(key))
    control_changed = sorted(key for key in keys if safe_control.get(key) != candidate.get(key))
    changed_dimensions = sorted((set(changed) & set(control_changed) or set(control_changed)) - transport_only)
    status_only = not changed_dimensions and baseline.get("status_code") != test.get("status_code")
    length_only = not changed_dimensions and baseline.get("response_length") != test.get("response_length")
    noise_fields = {"timestamp", "request_id", "trace_id", "date", "etag"}
    noise_count = sum(1 for key in changed_dimensions if str(key).lower() in noise_fields)
    noise_ratio = noise_count / max(1, len(changed_dimensions))
    semantic = bool(changed_dimensions) and noise_ratio < 1.0
    if replay is None:
        stable = True
    else:
        replay_normalized = _semantic_normalize(replay)
        stable = _semantic_normalize({key: value for key, value in candidate.items() if str(key).lower() not in _TRANSPORT_KEYS}) == _semantic_normalize({key: value for key, value in replay_normalized.items() if str(key).lower() not in _TRANSPORT_KEYS})
    input_digest = hashlib.sha256(json.dumps({"baseline": base, "test": candidate, "control": safe_control}, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()
    return SemanticComparisonV1(
        operation_id=operation_id,
        protocol=protocol if protocol in {"http", "graphql", "websocket", "sse", "grpc_web", "oauth", "oidc", "browser", "webhook", "async_job", "cache"} else "http",
        changed_dimensions=changed_dimensions,
        stable_dimensions=sorted(set(keys) - set(changed_dimensions)),
        noise_ratio=min(1.0, noise_ratio),
        signal_strength=1.0 if semantic else 0.0,
        semantic_signal=semantic,
        status_only_signal=status_only,
        length_only_signal=length_only,
        replay_stable=stable,
        evidence_ids=list(evidence_ids or []),
        input_digest=input_digest,
        metadata={"control_changed_dimensions": control_changed, "baseline_status": baseline.get("status_code"), "test_status": test.get("status_code")},
    )


compare_protocol_semantics = semantic_response_compare


validation_policy_registry_v2 = ValidationPolicyRegistryV2()
validation_engine_v2 = ValidationEngineV2(registry=validation_policy_registry_v2)


__all__ = [
    "ValidationPolicyV2", "ValidationContextV2", "ValidationCheckV2",
    "ValidationDecisionV2", "ValidationTraceV2", "ValidationPolicyRegistryV2",
    "ValidationEngineV2", "validation_policy_registry_v2", "validation_engine_v2",
]

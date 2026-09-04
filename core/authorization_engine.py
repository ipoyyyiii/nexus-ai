"""Dynamic authorization discovery helpers and differential replay engine."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin, urlencode, urlsplit, urlunsplit

from core.tool_transport import guarded_requests as requests

from core.auth_store import auth_store
from core.authorization_contract import (
    AuthorizationExpectationV1,
    AuthorizationReplayRunV1,
    IdentityCoveragePlanV1,
    IdentityGraphV1,
    IdentityV1,
    IdentityRelationV1,
    ReplayAttemptV1,
    RequestTemplateV1,
    ResourceInstanceV1,
)
from core.identity_context import ToolExecutionContext, use_execution_context, get_execution_context
from core.redact import redact
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolErrorV1, ToolResultV1


_LOGIN_RE = re.compile(r"(?:/login|/signin|/sign-in|/auth(?:enticate)?)(?:[/?#]|$)", re.I)


@dataclass
class ResponseSnapshot:
    status_code: int
    url: str
    headers: Dict[str, str]
    body: str
    elapsed_ms: float

    @property
    def is_login_wall(self) -> bool:
        location = self.headers.get("location", "")
        body = self.body[:5000]
        return bool(_LOGIN_RE.search(location or self.url) or re.search(r"<input[^>]+type=[\"']password", body, re.I))


def _json_shape(body: str) -> Any:
    try:
        value = json.loads(body)
    except Exception:
        return None
    def scrub(item: Any) -> Any:
        if isinstance(item, dict):
            return {key: scrub(value) for key, value in sorted(item.items()) if key.lower() not in {"timestamp", "request_id", "trace_id"}}
        if isinstance(item, list):
            return [scrub(value) for value in item[:50]]
        if isinstance(item, (str, int, float, bool)) or item is None:
            return item
        return str(item)
    return scrub(value)


def compare_responses(baseline: ResponseSnapshot, test: ResponseSnapshot, unique_marker: str = "") -> Dict[str, Any]:
    baseline_json = _json_shape(baseline.body)
    test_json = _json_shape(test.body)
    marker_seen = bool(unique_marker and unique_marker in test.body)
    baseline_marker_seen = bool(unique_marker and unique_marker in baseline.body)
    same_json = baseline_json is not None and test_json is not None and baseline_json == test_json
    same_body_hash = hashlib.sha256(baseline.body.encode(errors="ignore")).hexdigest() == hashlib.sha256(test.body.encode(errors="ignore")).hexdigest()
    test_has_resource = (
        bool(test.body.strip())
        and test.status_code not in {401, 403, 404}
        and not test.is_login_wall
        and not re.search(r"(?:not found|forbidden|unauthorized|access denied)", test.body[:5000], re.I)
    )
    return {
        "status_changed": baseline.status_code != test.status_code,
        "baseline_status": baseline.status_code,
        "test_status": test.status_code,
        "same_json": same_json,
        "same_body_hash": same_body_hash,
        "baseline_login_wall": baseline.is_login_wall,
        "test_login_wall": test.is_login_wall,
        "unique_marker_seen": marker_seen,
        "baseline_marker_seen": baseline_marker_seen,
        "resource_semantically_present": test_has_resource,
        "response_delta": abs(len(baseline.body) - len(test.body)),
    }


def _replace(value: Any, bindings: Dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: _replace(item, bindings) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace(item, bindings) for item in value]
    if isinstance(value, str):
        result = value
        for name, replacement in bindings.items():
            result = result.replace("{" + name + "}", str(replacement))
        return result
    return value


class AuthorizationReplayEngine:
    """Replay one observed operation across explicitly selected identities."""

    def __init__(self, target: str = "", timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.last_run: Optional[AuthorizationReplayRunV1] = None

    @staticmethod
    def _url(template: RequestTemplateV1) -> str:
        return urljoin(template.origin.rstrip("/") + "/", template.path_template.lstrip("/"))

    def _request(
        self,
        template: RequestTemplateV1,
        identity_id: str,
        session_id: str,
        bindings: Dict[str, Any],
        approved: bool,
        auth_context_id: str = "",
    ) -> ResponseSnapshot:
        side_effect = template.side_effect_class
        if side_effect in {"mutation", "unknown"} and not approved:
            raise PermissionError("Authorization replay requires approval for mutation or unknown side effects.")
        url = self._url(template)
        query = _replace(template.query_template, bindings)
        if query:
            url = urlunsplit((*urlsplit(url)[:3], urlencode(query, doseq=True), ""))
        headers = {key: str(value) for key, value in _replace(template.header_template, bindings).items()}
        headers.setdefault("Cache-Control", "no-cache")
        headers["X-Nexus-Replay"] = uuid.uuid4().hex
        body = _replace(copy.deepcopy(template.body_template), bindings)
        inherited = get_execution_context()
        with use_execution_context(ToolExecutionContext(
            session_id=session_id, job_id=inherited.job_id if inherited else "",
            identity_id=identity_id, auth_context_id=auth_context_id,
            target_origin=template.origin,
            attempt_id=inherited.attempt_id if inherited else "",
            tool_run_id=inherited.tool_run_id if inherited else "",
            tool_name="authorization_differential_replay",
            budget=inherited.budget if inherited else None,
            config_snapshot=inherited.config_snapshot if inherited else None,
            safety_kernel=inherited.safety_kernel if inherited else None,
            repository=inherited.repository if inherited else None,
            secret_vault=inherited.secret_vault if inherited else None,
            worker_capabilities=inherited.worker_capabilities if inherited else (),
            approval_ref=inherited.approval_ref if inherited else "",
            approval_digest=inherited.approval_digest if inherited else "",
            approval_granted=bool(approved or (inherited and inherited.approval_granted)),
            authorized_lab_mode=inherited.authorized_lab_mode if inherited else False,
            authorized_lab_origin=inherited.authorized_lab_origin if inherited else "",
            suite_preapproval_id=inherited.suite_preapproval_id if inherited else "",
        )):
            # TLS verification is a safety invariant.  A target-specific
            # exception must be represented by the safety kernel, never by a
            # replay helper silently disabling verification.
            request_kwargs: Dict[str, Any] = {"headers": headers, "timeout": self.timeout, "verify": True, "allow_redirects": False}
            request_kwargs = auth_store.inject_into_kwargs(
                template.origin.split("//", 1)[-1].split("/", 1)[0],
                request_kwargs,
                session_id=session_id,
                identity_id=identity_id,
                auth_context_id=auth_context_id,
            )
            if body is not None:
                if template.protocol == "graphql" or isinstance(body, (dict, list)):
                    request_kwargs["json"] = body
                else:
                    request_kwargs["data"] = body
            started = time.monotonic()
            response = requests.request(template.method.upper(), url, **request_kwargs)
        return ResponseSnapshot(
            status_code=response.status_code, url=response.url,
            headers={str(k).lower(): str(v) for k, v in response.headers.items()},
            body=response.text[:120000], elapsed_ms=round((time.monotonic() - started) * 1000, 2),
        )

    def run_differential(
        self,
        session_id: str,
        template: RequestTemplateV1,
        resource: ResourceInstanceV1,
        owner_identity_id: str,
        test_identity_ids: Iterable[str],
        expectations: Iterable[AuthorizationExpectationV1],
        bindings: Optional[Dict[str, Any]] = None,
        approved: bool = False,
        replay_run: Optional[AuthorizationReplayRunV1] = None,
        auth_contexts: Optional[Dict[str, str]] = None,
        negative_control_identity_id: str = "",
    ) -> ToolResultV1:
        bindings = dict(bindings or {})
        expectations = list(expectations)
        test_identity_ids = [str(item) for item in test_identity_ids if str(item)]
        auth_contexts = {
            str(identity_id): str(auth_context_id)
            for identity_id, auth_context_id in (auth_contexts or {}).items()
            if identity_id and auth_context_id
        }
        selected_identity_ids = [str(owner_identity_id), *test_identity_ids]
        missing_contexts = sorted({
            identity_id for identity_id in selected_identity_ids
            if not auth_contexts.get(identity_id)
        })
        if not test_identity_ids:
            return ToolResultV1(
                tool_name="authorization_replay", category="access_control", target=self._url(template),
                status="failed", summary="Authorization replay requires an owner and at least one non-owner identity.",
                errors=[ToolErrorV1(code="missing_test_identity", message="No non-owner identity was supplied.")],
            )
        if negative_control_identity_id and negative_control_identity_id not in test_identity_ids:
            return ToolResultV1(
                tool_name="authorization_replay", category="access_control", target=self._url(template),
                status="failed", summary="The negative control must be one of the selected non-owner identities.",
                errors=[ToolErrorV1(code="invalid_negative_control", message="Negative control identity is outside the selected test identities.")],
            )
        if missing_contexts:
            return ToolResultV1(
                tool_name="authorization_replay", category="access_control", target=self._url(template),
                status="failed", summary="Authorization replay requires explicit isolated auth contexts.",
                errors=[ToolErrorV1(code="missing_auth_context", message="Missing auth context for: " + ", ".join(missing_contexts))],
            )
        resource_value = resource.metadata.get("runtime_locator", resource.locator_redacted)
        if resource_value is not None:
            bindings.setdefault("resource_id", resource_value)
        marker = str(resource.metadata.get("unique_marker", ""))
        expectation_map = {(item.subject_identity_id, item.action, item.resource_fingerprint): item for item in expectations}
        control_expectation = expectation_map.get(
            (negative_control_identity_id, template.method.upper(), resource.fingerprint)
        ) if negative_control_identity_id else None
        if negative_control_identity_id and not resource.private_canary and not (
            control_expectation and control_expectation.expected == "deny"
        ):
            return ToolResultV1(
                tool_name="authorization_replay", category="access_control", target=self._url(template),
                status="failed", summary="The negative control has no explicit deny expectation for this resource.",
                errors=[ToolErrorV1(code="missing_negative_control_expectation", message="Provide an observed deny expectation or mark the observed resource as a private canary.")],
            )
        run = replay_run or AuthorizationReplayRunV1(
            session_id=session_id, template_id=template.template_id,
            resource_fingerprint=resource.fingerprint, owner_identity_id=owner_identity_id,
            test_identity_ids=list(test_identity_ids),
            negative_control_identity_id=negative_control_identity_id,
            mutation_approved=approved,
        )
        if negative_control_identity_id:
            run.negative_control_identity_id = negative_control_identity_id
        self.last_run = run
        observations: List[ObservationV1] = []
        attempts: List[ReplayAttemptV1] = []
        try:
            baseline = self._request(
                template, owner_identity_id, session_id, bindings, approved,
                auth_context_id=auth_contexts.get(owner_identity_id, ""),
            )
            observations.append(self._observation(
                "baseline", template, owner_identity_id, baseline, run.replay_run_id,
                resource.fingerprint, auth_context_id=auth_contexts.get(owner_identity_id, ""),
            ))
        except Exception as exc:
            run.status = "failed"
            return ToolResultV1(
                tool_name="authorization_replay", category="access_control", target=self._url(template),
                status="failed", summary="Owner baseline request failed.",
                errors=[{"code": "baseline_failed", "message": str(exc)}],
            )

        unexpected: List[str] = []
        for identity_id in run.test_identity_ids:
            attempt = ReplayAttemptV1(
                replay_run_id=run.replay_run_id, identity_id=identity_id,
                template_id=template.template_id, resource_fingerprint=resource.fingerprint,
                auth_context_id=auth_contexts.get(identity_id, ""),
                status="running",
            )
            try:
                tested = self._request(
                    template, identity_id, session_id, bindings, approved,
                    auth_context_id=auth_contexts.get(identity_id, ""),
                )
                comparison = compare_responses(baseline, tested, marker)
                expected = expectation_map.get((identity_id, template.method.upper(), resource.fingerprint))
                semantic = "allow" if comparison["test_login_wall"] or not comparison["resource_semantically_present"] else "unexpected_allow"
                if expected and expected.expected == "allow":
                    semantic = "allow"
                attempt.status = "succeeded"
                attempt.response_status = tested.status_code
                attempt.semantic_result = semantic
                attempt.comparison = comparison
                observation_role = "negative_control" if identity_id == negative_control_identity_id else "test"
                test_observation = self._observation(
                    observation_role, template, identity_id, tested, run.replay_run_id,
                    resource.fingerprint, comparison,
                    auth_context_id=auth_contexts.get(identity_id, ""),
                )
                test_observation.metadata["semantic_result"] = semantic
                attempt.observation_id = test_observation.observation_id
                observations.append(test_observation)
                expected_deny = expected and expected.expected == "deny"
                if semantic == "unexpected_allow" and (expected_deny or resource.private_canary):
                    unexpected.append(identity_id)
                    # A read-only unexpected allow gets a second clean replay
                    # so transient cache/race behavior cannot validate a
                    # finding. Mutations stay inconclusive unless a human
                    # supplies a separate reproduction plan.
                    if template.side_effect_class == "read":
                        reproduced = self._request(
                            template, identity_id, session_id, bindings, approved,
                            auth_context_id=auth_contexts.get(identity_id, ""),
                        )
                        reproduction_comparison = compare_responses(baseline, reproduced, marker)
                        observations.append(self._observation(
                            "reproduction", template, identity_id, reproduced,
                            run.replay_run_id, resource.fingerprint, reproduction_comparison,
                            auth_context_id=auth_contexts.get(identity_id, ""),
                        ))
                        observations[-1].metadata["semantic_result"] = semantic
            except Exception as exc:
                attempt.status = "failed"
                attempt.comparison = {"error": str(exc)}
            attempts.append(attempt)

        candidate_findings = []
        if unexpected:
            candidate = CandidateFindingV1(
                title="Authorization boundary violation candidate",
                vuln_type="BOLA/IDOR",
                severity="HIGH",
                target_url=self._url(template), method=template.method.upper(),
                parameter="resource_id", injection_point="authorization_replay",
                status="suspected", observation_ids=[item.observation_id for item in observations],
                confidence_score=0.75,
                confidence_reasons=["Same observed action replayed with an identity that was expected to be denied."],
                metadata={
                    "replay_run_id": run.replay_run_id,
                    "template_id": template.template_id,
                    "resource_fingerprint": resource.fingerprint,
                    "private_canary": resource.private_canary,
                    "owner_identity_id": owner_identity_id,
                    "unexpected_identity_ids": unexpected,
                    "unexpected_allow": bool(unexpected),
                    "negative_control_identity_id": negative_control_identity_id,
                    "deny_expectation": any(
                        item.expected == "deny" and item.subject_identity_id in unexpected
                        for item in expectations
                    ),
                    "expectation_id": next(
                        (
                            item.expectation_id for item in expectations
                            if item.subject_identity_id in unexpected
                            and item.action == template.method.upper()
                            and item.resource_fingerprint == resource.fingerprint
                            and item.expected == "deny"
                        ),
                        "",
                    ),
                    "expectation_ids": [item.expectation_id for item in expectations],
                    "expected_deny_required": True,
                },
            )
            candidate_findings.append(candidate)
        run.attempts = attempts
        run.status = "succeeded" if all(item.status == "succeeded" for item in attempts) else "partial"
        return ToolResultV1(
            tool_name="authorization_replay", tool_version="1", category="access_control",
            target=self._url(template), status="succeeded", summary="Dynamic authorization differential replay completed.",
            observations=observations, candidate_findings=candidate_findings,
            metrics={"identity_count": len(run.test_identity_ids) + 1, "unexpected_allow_count": len(unexpected)},
            side_effects=[] if template.side_effect_class == "read" else [{"type": "mutation", "approved": approved}],
        )

    @staticmethod
    def _observation(
        role: str,
        template: RequestTemplateV1,
        identity_id: str,
        response: ResponseSnapshot,
        replay_run_id: str,
        resource_fingerprint: str = "",
        comparison: Optional[Dict[str, Any]] = None,
        auth_context_id: str = "",
    ) -> ObservationV1:
        return ObservationV1(
            role=role, kind="authorization_replay", target_url=response.url,
            method=template.method.upper(), response_excerpt=redact(response.body)[:8000],
            status_code=response.status_code, response_time_ms=response.elapsed_ms,
            metadata={
                "identity_id": identity_id,
                "auth_context_id": auth_context_id,
                "template_id": template.template_id,
                "replay_run_id": replay_run_id,
                "resource_fingerprint": resource_fingerprint,
                "comparison": comparison or {},
                # Keep the deterministic semantic flags at the observation
                # boundary as well as inside the raw comparison object. V2
                # validation must not need to infer them from transport data.
                **{
                    key: value for key, value in (comparison or {}).items()
                    if key in {"resource_semantically_present", "same_json", "same_body_hash", "status_changed"}
                },
            },
        )


def build_identity_graph(
    session_id: str,
    identities: Iterable[IdentityV1 | Dict[str, Any]],
    claims: Iterable[Dict[str, Any]] = (),
    auth_contexts: Iterable[Dict[str, Any]] = (),
    previous_version: int = 0,
) -> IdentityGraphV1:
    """Build a deterministic graph snapshot from session-local records.

    This function does not infer permissions from labels.  It records only
    explicit auth-context and claim relations, leaving access/ownership edges
    to observed evidence or operator input.
    """
    nodes = []
    for item in identities:
        row = item if isinstance(item, dict) else item.model_dump(mode="json")
        if str(row.get("session_id", session_id)) != session_id:
            continue
        identity_id = str(row.get("identity_id", ""))
        if identity_id:
            nodes.append(identity_id)
    relations: List[IdentityRelationV1] = []
    evidence: List[str] = []
    for item in auth_contexts:
        if str(item.get("identity_id", "")) not in nodes:
            continue
        relation = IdentityRelationV1(
            session_id=session_id,
            graph_version=previous_version + 1,
            subject_id=str(item["identity_id"]),
            relation="auth_context_for",
            object_id=str(item.get("auth_context_id", "")),
            evidence_ids=[],
            source="observation",
            confidence=1.0 if item.get("status") == "active" else 0.0,
            status="active" if item.get("status") == "active" else "proposed",
        )
        relations.append(relation)
    for item in claims:
        identity_id = str(item.get("identity_id", ""))
        if identity_id not in nodes:
            continue
        name = str(item.get("name", "")).lower()
        value = str(item.get("value_redacted", ""))
        relation_name = "member_of_tenant" if "tenant" in name else "role_of" if "role" in name else "derived_from"
        if value:
            relations.append(IdentityRelationV1(
                session_id=session_id,
                graph_version=previous_version + 1,
                subject_id=identity_id,
                relation=relation_name,
                object_id=value,
                evidence_ids=list(item.get("evidence_ids") or []),
                source="observation",
                confidence=float(item.get("confidence", 0.5)),
                status="active" if item.get("evidence_ids") else "proposed",
            ))
            evidence.extend(item.get("evidence_ids") or [])
    gaps = []
    if len(nodes) < 2:
        gaps.append("two_isolated_identities_required")
    if not any(item.relation == "auth_context_for" and item.status == "active" for item in relations):
        gaps.append("active_auth_context_required")
    graph = IdentityGraphV1(
        session_id=session_id,
        version=previous_version + 1,
        node_ids=sorted(set(nodes)),
        relations=relations,
        evidence_ids=sorted(set(evidence)),
        gaps=sorted(set(gaps)),
    )
    return graph.ensure_digest()


def plan_identity_coverage(
    session_id: str,
    graph: IdentityGraphV1,
    required_identity_ids: Iterable[str],
    required_resource_fingerprints: Iterable[str] = (),
) -> IdentityCoveragePlanV1:
    required = sorted(set(str(item) for item in required_identity_ids if item))
    graph_nodes = set(graph.node_ids)
    missing = [f"identity_missing:{item}" for item in required if item not in graph_nodes]
    active_auth = {
        item.object_id for item in graph.relations
        if item.relation == "auth_context_for" and item.status == "active"
    }
    required_auth = [item.object_id for item in graph.relations if item.relation == "auth_context_for" and item.subject_id in required]
    missing.extend(f"auth_context_missing:{item}" for item in required_auth if item not in active_auth)
    if len(required) < 2:
        missing.append("two_isolated_identities_required")
    status = "ready" if not missing and not graph.gaps else "blocked"
    return IdentityCoveragePlanV1(
        session_id=session_id,
        graph_id=graph.graph_id,
        required_identity_ids=required,
        required_relations=["auth_context_for", "same_resource_comparison"],
        required_resource_fingerprints=sorted(set(str(item) for item in required_resource_fingerprints if item)),
        required_auth_context_ids=required_auth,
        missing_requirements=sorted(set(missing + list(graph.gaps))),
        status=status,
    )

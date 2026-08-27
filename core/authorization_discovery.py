"""Turn runtime browser/API traffic into dynamic authorization contracts."""

from __future__ import annotations

import json
import hashlib
import re
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qs, urlsplit

from core.authorization_contract import (
    AuthSurfaceObservationV1,
    RequestTemplateV1,
    ResourceInstanceV1,
    SessionTransitionV1,
)
from core.redact import redact


_ID_SEGMENT = re.compile(r"^(?:\d{1,20}|[0-9a-f]{8}-[0-9a-f-]{20,}|[0-9a-f]{16,64})$", re.I)
_SECRET_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token"}
_AUTH_PATHS = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|register|signup|sign-up|logout|signout|"
    r"auth|oauth|oidc|authorize|callback|token|refresh|revoke|reset|password|"
    r"mfa|2fa|verify|session)(?:/|$|\?)",
    re.I,
)
_PATH_EVENT_WORDS = (
    ("logout", "logout"), ("signout", "logout"), ("revoke", "revoke"),
    ("refresh", "token_refresh"), ("callback", "oauth_callback"),
    ("authorize", "oauth_authorize"), ("oauth", "oauth_authorize"),
    ("oidc", "oauth_authorize"), ("token", "token_issue"),
    ("register", "register"), ("signup", "register"),
    ("reset", "reset"), ("password-reset", "reset"),
    ("mfa", "mfa"), ("2fa", "mfa"), ("login", "login"),
    ("signin", "login"), ("sign-in", "login"),
)


def _value_digest(value: Any) -> str:
    """Hash a sensitive observed value without retaining the value."""
    text = str(value or "")
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:32] if text else ""


def _header_map(capture: Dict[str, Any], response: bool = False) -> Dict[str, str]:
    key = "response_headers" if response else "headers"
    return {str(k).lower(): str(v) for k, v in (capture.get(key) or {}).items()}


def _auth_event(path: str, method: str, body: Any) -> str:
    # Prefer explicit path semantics. A login request commonly contains a
    # ``password`` field; body-first matching would incorrectly classify it
    # as a password-reset surface.
    path_value = str(path or "").lower()
    for token, event in _PATH_EVENT_WORDS:
        if re.search(rf"(?:^|[/_.-]){re.escape(token)}(?:$|[/_.?-])", path_value):
            return event
    value = f"{path} {method} {json.dumps(body, sort_keys=True, default=str) if isinstance(body, (dict, list)) else body or ''}".lower()
    for token, event in _PATH_EVENT_WORDS:
        if token in value:
            return event
    return "unknown"


def _auth_mechanism(path: str, headers: Dict[str, str], body: Any, response_headers: Dict[str, str]) -> str:
    blob = " ".join([path, json.dumps(body, sort_keys=True, default=str) if isinstance(body, (dict, list)) else str(body or ""), " ".join(headers), " ".join(response_headers)]).lower()
    has_bearer = "authorization" in headers or "bearer" in blob or "access_token" in blob
    has_cookie = "cookie" in headers or "set-cookie" in response_headers or "session" in blob
    if "pkce" in blob or "code_challenge" in blob or "code_verifier" in blob:
        return "pkce"
    if "openid" in blob or "oidc" in blob:
        return "oidc"
    if "oauth" in blob or "/authorize" in path:
        return "oauth"
    if "mfa" in blob or "2fa" in blob or "otp" in blob:
        return "mfa"
    if has_bearer and has_cookie:
        return "mixed"
    if has_bearer:
        return "bearer"
    if has_cookie:
        return "session_cookie"
    if "api-key" in blob or "x-api-key" in blob:
        return "api_key"
    if "basic" in blob:
        return "basic"
    if any(word in blob for word in ("password", "username", "email")):
        return "password"
    return "unknown"


def _auth_state(capture: Dict[str, Any], event: str, response_headers: Dict[str, str], response_body: Any) -> str:
    explicit = str(capture.get("auth_state") or "").lower()
    if explicit in {"anonymous", "authenticated", "unknown"}:
        return explicit
    status = int(capture.get("response_status", capture.get("status_code", 0)) or 0)
    body_text = json.dumps(response_body, sort_keys=True, default=str).lower() if isinstance(response_body, (dict, list)) else str(response_body or "").lower()
    if event in {"login", "register", "token_issue", "oauth_callback", "token_refresh"} and 200 <= status < 400:
        return "authenticated"
    if event in {"logout", "revoke", "reset"} and 200 <= status < 400:
        return "anonymous"
    if status in {401, 403} or any(word in body_text for word in ("unauthorized", "sign in", "login required")):
        return "anonymous"
    if "set-cookie" in response_headers or "access_token" in body_text or "id_token" in body_text:
        return "authenticated"
    return "unknown"


def capture_auth_surface(
    captures: Iterable[Dict[str, Any]],
    session_id: str,
    *,
    identity_id: str = "",
    auth_context_id: str = "",
    source_ids: Iterable[str] = (),
) -> Tuple[List[AuthSurfaceObservationV1], List[SessionTransitionV1], List[str]]:
    """Extract auth/session boundaries from already captured traffic.

    This function is intentionally passive. It never submits credentials,
    follows an OAuth redirect, mutates a session, or treats a URL name as
    proof of an authentication bug.
    """
    surfaces: List[AuthSurfaceObservationV1] = []
    transitions: List[SessionTransitionV1] = []
    gaps: List[str] = []
    seen = set()
    previous_state = "anonymous"
    for index, capture in enumerate(captures or []):
        raw_url = str(capture.get("url") or "")
        parsed = urlsplit(raw_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        path = parsed.path or "/"
        body = _parse_body(capture.get("post_data", capture.get("body")))
        response_body = _parse_body(capture.get("response_body"))
        headers = _header_map(capture)
        response_headers = _header_map(capture, response=True)
        event = _auth_event(path, str(capture.get("method", "GET")).upper(), body)
        if event == "unknown" and not _AUTH_PATHS.search(path):
            continue
        mechanism = _auth_mechanism(path, headers, body, response_headers)
        state = _auth_state(capture, event, response_headers, response_body)
        evidence = [str(capture.get("observation_id") or capture.get("evidence_id") or f"auth-capture-{index}")]
        source = [str(item) for item in source_ids if item]
        endpoint_ref = str(capture.get("endpoint_reference_id") or f"auth-endpoint-{_value_digest(parsed.path)[:20]}")
        redirect = response_headers.get("location") or headers.get("redirect_uri") or ""
        blob = json.dumps({"path": parsed.path, "method": capture.get("method", "GET"), "event": event, "mechanism": mechanism, "state": state}, sort_keys=True)
        observation_id = f"authobs_{_value_digest(blob)}"
        if observation_id in seen:
            continue
        seen.add(observation_id)
        surface = AuthSurfaceObservationV1(
            observation_id=observation_id,
            session_id=session_id,
            origin=f"{parsed.scheme}://{parsed.netloc}",
            endpoint_reference_id=endpoint_ref,
            event=event,
            mechanism=mechanism,
            auth_state=state,
            identity_id=identity_id,
            auth_context_id=auth_context_id,
            redirect_uri_digest=_value_digest(redirect),
            issuer_digest=_value_digest((response_body or {}).get("iss") if isinstance(response_body, dict) else ""),
            audience_digest=_value_digest((response_body or {}).get("aud") if isinstance(response_body, dict) else ""),
            evidence_ids=evidence,
            source_ids=source,
            status="observed" if state != "unknown" or event != "unknown" else "inconclusive",
            confidence=0.85 if state != "unknown" else 0.55,
            metadata={
                "path": redact(path)[:300],
                "method": str(capture.get("method", "GET")).upper(),
                "response_status": int(capture.get("response_status", capture.get("status_code", 0)) or 0),
                "has_redirect": bool(redirect),
                "has_response_cookie": "set-cookie" in response_headers,
                "raw_values_persisted": False,
            },
        )
        surfaces.append(surface)
        transition_event = {
            "login": "login", "register": "session_created", "token_issue": "session_created",
            "oauth_callback": "login", "token_refresh": "refresh", "logout": "logout",
            "revoke": "revoke", "reset": "invalid",
        }.get(event)
        if transition_event:
            after = "active" if state == "authenticated" else "anonymous" if state == "anonymous" else "unknown"
            transitions.append(SessionTransitionV1(
                session_id=session_id, identity_id=identity_id, auth_context_id=auth_context_id,
                origin=surface.origin, event=transition_event,
                before_status=previous_state, after_status=after,
                evidence_ids=evidence, source_ids=source,
                clean_context=bool(capture.get("clean_context", False)),
                state_digest=_value_digest(f"{previous_state}:{after}:{transition_event}"),
                metadata={"observation_id": surface.observation_id, "raw_values_persisted": False},
            ))
            previous_state = after
    if not surfaces:
        gaps.append("auth_surface_not_observed")
    if surfaces and not any(item.event == "logout" for item in surfaces):
        gaps.append("logout_invalidation_not_observed")
    if any(item.mechanism in {"oauth", "oidc", "pkce"} for item in surfaces) and not any(item.event == "oauth_callback" for item in surfaces):
        gaps.append("oauth_callback_not_observed")
    if any(item.event in {"login", "token_issue"} for item in surfaces) and not any(item.event == "token_refresh" for item in surfaces):
        gaps.append("token_refresh_not_observed")
    return surfaces, transitions, sorted(set(gaps))


def _side_effect(method: str, body: Any, protocol: str) -> str:
    if protocol == "graphql":
        query = str((body or {}).get("query", "")) if isinstance(body, dict) else str(body or "")
        if re.search(r"\bmutation\b", query, re.I):
            return "mutation"
        if re.search(r"\b(query|introspection)\b", query, re.I) or query:
            return "read"
    if method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return "read"
    return "unknown"


def _safe_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    return {
        str(key): redact(str(value))[:500]
        for key, value in (headers or {}).items()
        if str(key).lower() not in _SECRET_HEADERS
    }


def _parse_body(value: Any) -> Any:
    if not value:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except Exception:
        return redact(str(value))[:4000]


def _response_resource_values(value: Any, parent_key: str = "object") -> Iterable[Tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in {"id", "uuid"} or key_text.lower().endswith("_id"):
                if isinstance(item, (str, int)) and str(item):
                    yield key_text.removesuffix("_id") or parent_key, item
            yield from _response_resource_values(item, key_text)
    elif isinstance(value, list):
        for item in value[:50]:
            yield from _response_resource_values(item, parent_key)


def capture_to_contracts(
    captures: Iterable[Dict[str, Any]],
    session_id: str,
    identity_id: str,
    source_observation_ids: List[str] | None = None,
) -> Tuple[List[RequestTemplateV1], List[ResourceInstanceV1]]:
    templates: List[RequestTemplateV1] = []
    resources: List[ResourceInstanceV1] = []
    seen_templates = set()
    seen_resources = set()
    source_observation_ids = source_observation_ids or []

    for capture in captures:
        raw_url = str(capture.get("url", ""))
        parsed = urlsplit(raw_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        method = str(capture.get("method", "GET")).upper()
        body = _parse_body(capture.get("post_data", capture.get("body")))
        protocol = "graphql" if isinstance(body, dict) and "query" in body else "http"
        segments = [segment for segment in parsed.path.split("/") if segment]
        path_parts = []
        bindings: Dict[str, Dict[str, Any]] = {}
        local_resources = []
        for index, segment in enumerate(segments):
            if _ID_SEGMENT.match(segment):
                binding_name = "resource_id" if not local_resources else f"resource_id_{len(local_resources) + 1}"
                path_parts.append("{" + binding_name + "}")
                local_resources.append((binding_name, segment, segments[index - 1] if index else "object"))
                bindings[binding_name] = {"source": "resource_locator", "original_fingerprint": segment}
            else:
                path_parts.append(segment)
        path_template = "/" + "/".join(path_parts)
        query_template = {key: values[0] if len(values) == 1 else values for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}
        template = RequestTemplateV1(
            session_id=session_id, origin=f"{parsed.scheme}://{parsed.netloc}", method=method,
            path_template=path_template, query_template=query_template, body_template=body,
            header_template=_safe_headers(capture.get("headers", {})), variable_bindings=bindings,
            operation_name=str((body or {}).get("operationName", "")) if isinstance(body, dict) else "",
            protocol=protocol, side_effect_class=_side_effect(method, body, protocol),
            source_observation_ids=source_observation_ids,
        ).ensure_fingerprint()
        if template.fingerprint not in seen_templates:
            templates.append(template)
            seen_templates.add(template.fingerprint)

        for binding_name, locator, resource_type in local_resources:
            resource = ResourceInstanceV1(
                session_id=session_id, resource_type=resource_type.rstrip("s") or "object",
                origin=template.origin, locator_redacted=redact(locator), owner_identity_id=identity_id,
                source_observation_ids=source_observation_ids,
                metadata={"binding_name": binding_name, "runtime_locator": locator},
            ).ensure_fingerprint()
            if resource.fingerprint not in seen_resources:
                resources.append(resource)
                seen_resources.add(resource.fingerprint)
        response_body = _parse_body(capture.get("response_body"))
        for resource_type, locator in _response_resource_values(response_body):
            resource = ResourceInstanceV1(
                session_id=session_id, resource_type=resource_type or "object",
                origin=template.origin, locator_redacted=redact(locator), owner_identity_id=identity_id,
                source_observation_ids=source_observation_ids,
                metadata={"source": "response_object"},
            ).ensure_fingerprint()
            if resource.fingerprint not in seen_resources:
                resources.append(resource)
                seen_resources.add(resource.fingerprint)
    return templates, resources

"""Turn runtime browser/API traffic into dynamic authorization contracts."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qs, urlsplit

from core.authorization_contract import RequestTemplateV1, ResourceInstanceV1
from core.redact import redact


_ID_SEGMENT = re.compile(r"^(?:\d{1,20}|[0-9a-f]{8}-[0-9a-f-]{20,}|[0-9a-f]{16,64})$", re.I)
_SECRET_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token"}


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

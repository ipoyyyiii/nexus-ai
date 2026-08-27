"""Target-agnostic browser workflow discovery from DOM/network captures."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List
import json
import re
import hashlib
from urllib.parse import urlsplit

from core.browser_workflow_contract import (
    BrowserStepV1,
    BrowserWorkflowV1,
    InputBinding,
    SemanticLocator,
    WorkflowCondition,
)
from core.authorization_contract import WorkflowPrerequisiteV1


def _workflow_class(value: str) -> str:
    text = str(value or "").lower()
    mapping = (
        ("checkout", "checkout"), ("cart", "checkout"), ("payment", "checkout"),
        ("approve", "approval"), ("approval", "approval"), ("invite", "approval"),
        ("role", "role_change"), ("permission", "role_change"),
        ("upload", "upload"), ("attachment", "upload"),
        ("reset", "reset"), ("password", "reset"),
        ("login", "authentication"), ("signin", "authentication"), ("auth", "authentication"),
        ("status", "state_transition"), ("workflow", "state_transition"),
        ("create", "resource"), ("update", "resource"), ("delete", "resource"),
    )
    for token, result in mapping:
        if token in text:
            return result
    return "unknown"


def _input_name(field: Dict[str, Any]) -> str:
    return str(field.get("name") or field.get("id") or field.get("label") or "").strip().lower()


def _prereq_kind(name: str) -> str:
    if any(token in name for token in ("password", "token", "secret", "otp", "code", "csrf")):
        return "auth_context"
    if any(token in name for token in ("role", "permission", "admin")):
        return "role"
    if any(token in name for token in ("tenant", "org", "workspace", "account")):
        return "tenant"
    if any(token in name for token in ("id", "uuid", "slug", "order", "object", "resource")):
        return "entity"
    if any(token in name for token in ("status", "state", "action", "step")):
        return "state"
    return "operator_input"


def _same_origin_capture(value: str, origin: str) -> bool:
    """Return whether a capture belongs to the workflow origin.

    Relative paths are accepted. Absolute external/provider URLs are rejected
    before they can become workflow steps, prerequisites, or state edges.
    """
    candidate = urlsplit(str(value or "").strip())
    base = urlsplit(str(origin or "").strip())
    if not candidate.scheme and not candidate.netloc:
        return True
    if candidate.scheme not in {"http", "https"} or not candidate.netloc:
        return False
    return (
        candidate.hostname or ""
    ).lower().rstrip(".") == (base.hostname or "").lower().rstrip(".") and (
        candidate.port or (443 if candidate.scheme == "https" else 80)
    ) == (base.port or (443 if base.scheme == "https" else 80))


class WorkflowDiscoveryService:
    def discover(
        self,
        session_id: str,
        origin: str,
        goal: str = "",
        captures: Iterable[Dict[str, Any]] = (),
        identity_ids: List[str] | None = None,
    ) -> BrowserWorkflowV1:
        captures = [
            dict(item) for item in (captures or [])
            if isinstance(item, dict)
            and _same_origin_capture(str(item.get("url") or origin), origin)
        ]
        steps: List[BrowserStepV1] = []
        seen_urls = set()
        ordinal = 0
        for capture in captures:
            url = str(capture.get("url") or origin)
            if url not in seen_urls:
                steps.append(BrowserStepV1(
                    ordinal=ordinal,
                    action="navigate",
                    args={"url": url, "wait_until": "domcontentloaded"},
                    postconditions=[WorkflowCondition(kind="url_matches", value=url)],
                    description="Navigate to a discovered in-scope page.",
                ))
                ordinal += 1
                seen_urls.add(url)
            for form in (capture.get("forms") or []):
                form_action = str(form.get("action") or "")
                form_text = f"{form_action} {form.get('name', '')} {form.get('id', '')}"
                form_class = _workflow_class(form_text)
                for field in (form.get("inputs") or [])[:10]:
                    name = str(field.get("name") or field.get("id") or field.get("label") or "").strip()
                    if not name:
                        continue
                    lower_name = name.lower()
                    binding_source = "secret_ref" if any(token in lower_name for token in ("password", "token", "secret", "otp", "code")) else "operator"
                    locator = SemanticLocator(
                        label=name,
                        css=f"[name={json.dumps(name)}]" if field.get("name") else f"#{field.get('id')}",
                    )
                    steps.append(BrowserStepV1(
                        ordinal=ordinal,
                        action="fill",
                        locator=locator,
                        input_bindings={name: InputBinding(name=name, source=binding_source, required=binding_source == "secret_ref")},
                        args={"binding": name},
                        preconditions=[WorkflowCondition(kind="element_visible", locator=locator)],
                        metadata={"workflow_class": form_class, "semantic_input": _prereq_kind(lower_name), "secret_value_persisted": False},
                        description="Fill a discovered form field; value supplied at run time.",
                    ))
                    ordinal += 1
                if form.get("action"):
                    steps.append(BrowserStepV1(
                        ordinal=ordinal,
                        action="submit",
                        locator=SemanticLocator(css="button[type=submit]", expected_count=1),
                        side_effect_class="mutation",
                        risk="medium",
                        preconditions=[WorkflowCondition(kind="element_present", locator=SemanticLocator(css="button[type=submit]", expected_count=1))],
                        metadata={"workflow_class": form_class, "semantic_event": form_class or "form_submit", "exact_approval_required": True},
                        description="Submit a discovered form after explicit approval.",
                    ))
                    ordinal += 1
            for button in (capture.get("buttons") or [])[:10]:
                text = str(button.get("text") or "").strip()
                selector = str(button.get("selector") or "").strip()
                if not text and not selector:
                    continue
                mutating_words = {"submit", "save", "create", "delete", "remove", "approve", "invite", "upload", "checkout", "confirm", "change role"}
                is_mutation = bool(button.get("mutating")) or any(word in text.lower() for word in mutating_words)
                steps.append(BrowserStepV1(
                    ordinal=ordinal,
                    action="click",
                    locator=SemanticLocator(text=text, css=selector),
                    side_effect_class="mutation" if is_mutation else "read",
                    risk="medium" if is_mutation else "low",
                    metadata={"workflow_class": _workflow_class(text), "exact_approval_required": is_mutation},
                    description="Click a discovered semantic control.",
                ))
                ordinal += 1
        if not steps:
            steps.append(BrowserStepV1(
                ordinal=0,
                action="navigate",
                args={"url": origin, "wait_until": "domcontentloaded"},
                postconditions=[WorkflowCondition(kind="url_matches", value=origin)],
                description="Seed workflow from target origin.",
            ))
        combined_text = " ".join(
            [str(capture.get("url") or "") for capture in captures]
            + [str(form.get("action") or "") for capture in captures for form in (capture.get("forms") or [])]
            + [str(button.get("text") or "") for capture in captures for button in (capture.get("buttons") or [])]
        )
        workflow = BrowserWorkflowV1(
            session_id=session_id,
            name=f"Discovered workflow for {origin}",
            origin=origin,
            goal=goal,
            identity_requirements=list(identity_ids or []),
            workflow_class=_workflow_class(f"{goal} {combined_text}"),
            steps=steps,
            source_observation_ids=[
                str(item.get("observation_id"))
                for item in captures if item.get("observation_id")
            ],
        )
        return workflow.ensure_fingerprint()

    def discover_intelligence(
        self,
        session_id: str,
        origin: str,
        goal: str = "",
        captures: Iterable[Dict[str, Any]] = (),
        identity_ids: List[str] | None = None,
    ) -> Dict[str, Any]:
        """Compile a workflow plus explicit prerequisites and state hints.

        This is a passive compiler over DOM/network observations. It does not
        log in, submit a form, infer a role from a label, or mark a workflow
        ready for mutation.
        """
        captures = [
            dict(item) for item in (captures or [])
            if isinstance(item, dict)
            and _same_origin_capture(str(item.get("url") or origin), origin)
        ]
        workflow = self.discover(session_id, origin, goal, captures, identity_ids)
        prerequisites: List[WorkflowPrerequisiteV1] = []
        gaps: List[str] = []
        states: Dict[str, List[str]] = {}
        auth_surface_ids: List[str] = []
        for index, capture in enumerate(captures):
            url = str(capture.get("url") or origin)
            page_state = str(capture.get("state") or capture.get("state_label") or "observed").lower()
            next_states = [str(item) for item in (capture.get("next_states") or []) if item]
            if next_states:
                states.setdefault(page_state, [])
                states[page_state].extend(next_states)
            for form in capture.get("forms") or []:
                form_action = str(form.get("action") or url)
                class_hint = _workflow_class(form_action)
                for field in form.get("inputs") or []:
                    name = _input_name(field)
                    if not name:
                        continue
                    kind = _prereq_kind(name)
                    status = "observed"
                    if kind == "auth_context" and not any(item in name for item in ("csrf", "nonce")):
                        status = "missing" if not identity_ids else "observed"
                    prerequisites.append(WorkflowPrerequisiteV1(
                        session_id=session_id,
                        workflow_id=workflow.workflow_id,
                        workflow_version=workflow.version,
                        kind=kind,
                        reference_id=name,
                        label=f"{class_hint or 'workflow'} requires {kind}",
                        required=True,
                        status=status,
                        evidence_ids=[str(capture.get("observation_id") or f"workflow-capture-{index}")],
                        source_ids=[str(capture.get("source_id"))] if capture.get("source_id") else [],
                        metadata={"field_name_redacted": True, "url_path": url.split("?", 1)[0], "raw_value_persisted": False},
                    ))
            for network in capture.get("network") or capture.get("requests") or []:
                event = str(network.get("auth_event") or network.get("event") or "").lower()
                if event:
                    auth_surface_ids.append(str(network.get("auth_surface_id") or "authobs_" + hashlib.sha256(f"{url}:{event}".encode()).hexdigest()[:20]))
                    if event in {"login", "oauth_callback", "token_issue"} and not identity_ids:
                        gaps.append("auth_identity_binding_missing")
        if not workflow.identity_requirements and any(item.kind == "auth_context" for item in prerequisites):
            gaps.append("identity_required_for_auth_workflow")
        if workflow.has_mutations() and not workflow.has_cleanup():
            gaps.append("cleanup_workflow_required_for_mutation")
        for key in list(states):
            states[key] = sorted(set(states[key]))
        workflow.state_graph = {key: value for key, value in sorted(states.items())}
        workflow.auth_surface_ids = sorted(set(auth_surface_ids))
        workflow.prerequisite_ids = [item.prerequisite_id for item in prerequisites]
        workflow.ambiguity_reasons = sorted(set(gaps))
        workflow.ensure_fingerprint()
        return {
            "workflow": workflow.model_dump(mode="json"),
            "prerequisites": [item.model_dump(mode="json") for item in prerequisites],
            "state_graph": workflow.state_graph,
            "auth_surface_ids": workflow.auth_surface_ids,
            "gaps": sorted(set(gaps)),
            "mutating": workflow.has_mutations(),
            "approval_required": workflow.has_mutations(),
        }

    def from_human_recon(
        self,
        session_id: str,
        origin: str,
        goal: str,
        result: Dict[str, Any],
        identity_ids: List[str] | None = None,
    ) -> BrowserWorkflowV1:
        captures = []
        for page in result.get("pages_detail", []):
            captures.append({
                "url": page.get("url") or origin,
                "forms": page.get("forms_detail") or [],
                "buttons": page.get("buttons") or [],
                "observation_id": page.get("observation_id"),
            })
        return self.discover(session_id, origin, goal, captures, identity_ids)


workflow_discovery_service = WorkflowDiscoveryService()

"""Target-agnostic browser workflow discovery from DOM/network captures."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List
import json

from core.browser_workflow_contract import (
    BrowserStepV1,
    BrowserWorkflowV1,
    InputBinding,
    SemanticLocator,
    WorkflowCondition,
)


class WorkflowDiscoveryService:
    def discover(
        self,
        session_id: str,
        origin: str,
        goal: str = "",
        captures: Iterable[Dict[str, Any]] = (),
        identity_ids: List[str] | None = None,
    ) -> BrowserWorkflowV1:
        captures = list(captures or [])
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
                for field in (form.get("inputs") or [])[:10]:
                    name = str(field.get("name") or field.get("id") or "").strip()
                    if not name:
                        continue
                    locator = SemanticLocator(
                        label=name,
                        css=f"[name={json.dumps(name)}]" if field.get("name") else f"#{field.get('id')}",
                    )
                    steps.append(BrowserStepV1(
                        ordinal=ordinal,
                        action="fill",
                        locator=locator,
                        input_bindings={name: InputBinding(name=name, source="operator", required=False)},
                        args={"binding": name},
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
        workflow = BrowserWorkflowV1(
            session_id=session_id,
            name=f"Discovered workflow for {origin}",
            origin=origin,
            goal=goal,
            identity_requirements=list(identity_ids or []),
            steps=steps,
            source_observation_ids=[
                str(item.get("observation_id"))
                for item in captures if item.get("observation_id")
            ],
        )
        return workflow.ensure_fingerprint()

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

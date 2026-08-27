"""Bounded, identity-scoped Playwright workflow runner."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from core.artifact_store import ArtifactStore, ArtifactStorageError
from core.browser_workflow_contract import (
    BrowserRunV1,
    BrowserStateSnapshotV1,
    BrowserStepRunV1,
    BrowserWorkflowV1,
    WorkflowCondition,
)
from core.cancellation import check_cancelled
from core.identity_context import ToolExecutionContext, use_execution_context, get_execution_context
from core.redact import redact
from core.config_loader import get_setting


class WorkflowApprovalRequired(RuntimeError):
    def __init__(self, run: BrowserRunV1):
        super().__init__("This browser workflow contains mutation steps and requires per-run approval.")
        self.run = run


class WorkflowStale(RuntimeError):
    pass


class WorkflowScopeViolation(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:40]


class StatefulBrowserRunner:
    def __init__(
        self,
        session_store: Any = None,
        repository: Any = None,
        artifact_store: Optional[ArtifactStore] = None,
    ):
        self.session_store = session_store
        self.repository = repository
        self.artifact_store = artifact_store

    def approval_digest(
        self,
        workflow: BrowserWorkflowV1,
        identity_id: str,
        bindings: Dict[str, Any],
        approval_expires_at: str = "",
    ) -> str:
        return _digest({
            "workflow_id": workflow.workflow_id,
            "version": workflow.version,
            "fingerprint": workflow.fingerprint,
            "identity_id": identity_id,
            "bindings": redact(bindings),
            "mutations": [
                {"step_id": step.step_id, "action": step.action, "risk": step.risk, "side_effect_class": step.side_effect_class, "cleanup_step_id": step.cleanup_step_id}
                for step in workflow.steps if step.is_mutation()
            ],
            "cleanup_step_ids": list(workflow.cleanup_step_ids),
            "approval_expires_at": approval_expires_at,
        })

    def requires_approval(self, workflow: BrowserWorkflowV1) -> bool:
        return workflow.has_mutations()

    def _scope(self, session_id: str, url: str) -> None:
        if self.session_store and session_id:
            allowed, reason = self.session_store.validate_active_scope(session_id, url)
            if not allowed:
                raise WorkflowScopeViolation(reason)

    async def run(
        self,
        workflow: BrowserWorkflowV1,
        *,
        session_id: str,
        target: str,
        identity_id: str = "",
        auth_context_id: str = "",
        role: str = "baseline",
        bindings: Optional[Dict[str, Any]] = None,
        approved: bool = False,
        approval_digest: str = "",
        parent_run_id: str = "",
        resume_from: Optional[BrowserRunV1] = None,
        graph_id: str = "",
        matrix_id: str = "",
        entity_fingerprints: Optional[list[str]] = None,
        clean_context: bool = False,
    ) -> BrowserRunV1:
        workflow.ensure_fingerprint()
        bindings = dict(bindings or {})
        run = resume_from or BrowserRunV1(
            session_id=session_id,
            workflow_id=workflow.workflow_id,
            workflow_version=workflow.version,
            identity_id=identity_id,
            auth_context_id=auth_context_id,
            role=role,
            total_steps=len(workflow.steps),
            parent_run_id=parent_run_id,
            graph_id=graph_id,
            matrix_id=matrix_id,
            entity_fingerprints=list(entity_fingerprints or []),
            clean_context=clean_context,
        )
        if graph_id and not run.graph_id:
            run.graph_id = graph_id
        if matrix_id and not run.matrix_id:
            run.matrix_id = matrix_id
        if entity_fingerprints and not run.entity_fingerprints:
            run.entity_fingerprints = list(entity_fingerprints)
        run.clean_context = bool(clean_context or run.clean_context)
        if not run.approval_expires_at:
            ttl_minutes = max(1, int((get_setting("browser_workflow", {}) or {}).get("approval_ttl_minutes", 30)))
            run.approval_expires_at = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat()
        run.cleanup_refs = list(workflow.cleanup_step_ids)
        expected_digest = self.approval_digest(workflow, identity_id, bindings, run.approval_expires_at)
        browser_cfg = get_setting("browser_workflow", {}) or {}
        max_steps = max(1, int(browser_cfg.get("max_steps", 30)))
        max_mutations = max(0, int(browser_cfg.get("max_mutations_per_run", 3)))
        if len(workflow.steps) > max_steps or sum(1 for step in workflow.steps if step.is_mutation()) > max_mutations:
            run.status = "failed"
            run.error_code = "workflow_budget_exceeded"
            run.error_message = "Workflow exceeds the configured step or mutation budget."
            return self._persist_run(run)
        run.approval_digest = expected_digest
        if approved and run.approval_expires_at and datetime.fromisoformat(run.approval_expires_at) <= datetime.now(timezone.utc):
            run.status = "failed"
            run.error_code = "approval_expired"
            run.error_message = "The per-run mutation approval has expired."
            return self._persist_run(run)
        if workflow.has_mutations():
            if not workflow.has_cleanup():
                run.status = "failed"
                run.error_code = "cleanup_required"
                run.error_message = "Mutating workflow has no registered cleanup step."
                return self._persist_run(run)
            if not approved or approval_digest != expected_digest:
                run.status = "approval_required"
                run.error_code = "approval_required"
                run.error_message = "Exact workflow version, identity, and bindings approval is required."
                return self._persist_run(run)
        try:
            self._scope(session_id, target)
        except Exception as exc:
            run.status = "failed"
            run.error_code = "scope_rejected"
            run.error_message = str(exc)
            return self._persist_run(run)

        run.status = "running"
        run.started_at = run.started_at or _now()
        self._persist_run(run)
        page = None
        ctx = None
        network: list[dict] = []
        network_urls: list[str] = []
        response_status: Dict[str, int] = {}
        try:
            from tools.playwright_tools import _get_browser, _new_page
            browser = await _get_browser()
            inherited = get_execution_context()
            context = ToolExecutionContext(
                session_id=session_id,
                job_id=inherited.job_id if inherited else "",
                identity_id=identity_id or (inherited.identity_id if inherited else "anonymous"),
                auth_context_id=auth_context_id or (inherited.auth_context_id if inherited else ""),
                target_origin=target,
                attempt_id=inherited.attempt_id if inherited else "",
                tool_run_id=inherited.tool_run_id if inherited else run.run_id,
                tool_name="stateful_browser_workflow",
                budget=inherited.budget if inherited else None,
                config_snapshot=inherited.config_snapshot if inherited else None,
                safety_kernel=inherited.safety_kernel if inherited else None,
                repository=inherited.repository if inherited else None,
                secret_vault=inherited.secret_vault if inherited else None,
                worker_capabilities=inherited.worker_capabilities if inherited else (),
                approval_ref=inherited.approval_ref if inherited else "",
                approval_digest=inherited.approval_digest if inherited else "",
                approval_granted=inherited.approval_granted if inherited else False,
            )
            context_manager = use_execution_context(context)
            with context_manager:
                page, ctx = await _new_page(browser, origin=target)
                page.on("request", lambda request: network_urls.append(request.url) or network.append({
                    "method": request.method,
                    "url": redact(request.url),
                    "resource_type": request.resource_type,
                }))
                page.on("response", lambda response: response_status.update({
                     redact(response.url): response.status
                }))
                if resume_from and run.current_step > 0 and run.checkpoint_snapshot_id and self.repository:
                    previous = [item for item in self.repository.list_snapshots(session_id, run.run_id) if item.get("snapshot_id") == run.checkpoint_snapshot_id]
                    if not previous or not previous[0].get("url"):
                        raise WorkflowStale("Resume checkpoint is unavailable; rediscovery is required.")
                    checkpoint = previous[0]
                    self._scope(session_id, checkpoint["url"])
                    await page.goto(checkpoint["url"], wait_until="domcontentloaded")
                    current_dom_hash = hashlib.sha256((await page.content()).encode("utf-8", "ignore")).hexdigest()
                    if current_dom_hash != checkpoint.get("dom_hash"):
                        raise WorkflowStale("Resume checkpoint state changed; rediscovery is required.")
                for index, step in enumerate(workflow.steps):
                    if index < run.current_step:
                        continue
                    if check_cancelled(None):
                        run.status = "cancelled"
                        run.error_code = "cancelled"
                        break
                    step_run = BrowserStepRunV1(
                        run_id=run.run_id, step_id=step.step_id, ordinal=step.ordinal, status="running"
                    )
                    before = await self._snapshot(page, run, step_run, network, response_status)
                    step_run.before_snapshot_id = before.snapshot_id
                    self._persist_snapshot(before)
                    if not await self._conditions(page, step.preconditions, response_status, network):
                        raise WorkflowStale(f"Precondition failed for step {step.step_id}.")
                    try:
                        await self._execute_step(page, step, bindings, target, session_id)
                        for observed_url in network_urls[-50:]:
                            self._scope(session_id, observed_url)
                        for opened_page in getattr(ctx, "pages", []):
                            if getattr(opened_page, "url", ""):
                                self._scope(session_id, opened_page.url)
                    except Exception as exc:
                        step_run.status = "failed"
                        step_run.error_code = "step_error"
                        step_run.error_message = str(exc)
                        step_run.finished_at = _now()
                        self._persist_step(step_run)
                        raise
                    if not await self._conditions(page, step.postconditions, response_status, network):
                        raise WorkflowStale(f"Postcondition failed for step {step.step_id}.")
                    after = await self._snapshot(page, run, step_run, network, response_status)
                    step_run.after_snapshot_id = after.snapshot_id
                    step_run.status = "succeeded"
                    step_run.attempts = 1
                    step_run.finished_at = _now()
                    self._persist_snapshot(after)
                    self._persist_step(step_run)
                    run.current_step = index + 1
                    run.checkpoint_snapshot_id = after.snapshot_id
                    run.state_digest = _digest({
                        "url": after.url, "dom_hash": after.dom_hash,
                        "step": run.current_step,
                    })
                    self._persist_run(run)
                if run.status == "running":
                    run.status = "succeeded"
        except WorkflowScopeViolation as exc:
            run.status = "failed"
            run.error_code = "scope_rejected"
            run.error_message = str(exc)
        except WorkflowStale as exc:
            run.status = "stale"
            run.error_code = "stale_state"
            run.error_message = str(exc)
        except asyncio.CancelledError:
            run.status = "cancelled"
            run.error_code = "cancelled"
        except ArtifactStorageError as exc:
            run.status = "partial"
            run.error_code = "artifact_storage_error"
            run.error_message = str(exc)
        except Exception as exc:
            run.status = "failed"
            run.error_code = "browser_execution_error"
            run.error_message = str(exc)
        finally:
            if ctx is not None:
                try:
                    await ctx.close()
                except Exception:
                    pass
            run.finished_at = _now()
            self._persist_run(run)
        return run

    async def _execute_step(self, page: Any, step: Any, bindings: Dict[str, Any], target: str, session_id: str = "") -> Any:
        locator = await self._resolve_locator(page, step.locator) if step.locator else None
        args = dict(step.args or {})
        if step.action == "navigate":
            url = str(args.get("url") or target)
            self._scope(session_id, url)
            return await page.goto(url, wait_until=str(args.get("wait_until", "domcontentloaded")))
        if step.action == "click":
            return await locator.click(timeout=step.timeout_ms)
        if step.action == "fill":
            value = args.get("value")
            binding = args.get("binding")
            if binding:
                value = bindings.get(binding)
            if value is None:
                raise ValueError("Fill step has no runtime binding.")
            return await locator.fill(str(value))
        if step.action == "select":
            value = args.get("value")
            if args.get("binding"):
                value = bindings.get(args["binding"])
            return await locator.select_option(str(value))
        if step.action == "check":
            return await locator.check()
        if step.action == "submit":
            return await locator.click(timeout=step.timeout_ms)
        if step.action == "wait_for":
            if locator:
                return await locator.wait_for(state=str(args.get("state", "visible")), timeout=step.timeout_ms)
            return await page.wait_for_timeout(min(step.timeout_ms, int(args.get("milliseconds", 500))))
        if step.action == "assert":
            if not await self._conditions(page, step.postconditions, {}, []):
                raise WorkflowStale("Assertion step failed.")
            return None
        if step.action == "extract":
            if not locator:
                raise ValueError("Extract step requires a locator.")
            return await locator.inner_text(timeout=step.timeout_ms)
        if step.action == "screenshot":
            return await page.screenshot()
        raise ValueError(f"Unsupported browser action: {step.action}")

    async def _resolve_locator(self, page: Any, locator_spec: Any) -> Any:
        if locator_spec is None:
            raise ValueError("This browser action requires a semantic locator.")
        root = page
        for frame_selector in locator_spec.frame:
            root = root.frame_locator(frame_selector)
        candidates = []
        if locator_spec.role:
            candidates.append(root.get_by_role(locator_spec.role, name=locator_spec.name or None))
        if locator_spec.label:
            candidates.append(root.get_by_label(locator_spec.label))
        if locator_spec.test_id:
            candidates.append(root.get_by_test_id(locator_spec.test_id))
        if locator_spec.text:
            candidates.append(root.get_by_text(locator_spec.text, exact=True))
        if locator_spec.css:
            candidates.append(root.locator(locator_spec.css))
        for candidate in candidates:
            count = await candidate.count()
            if count == locator_spec.expected_count:
                return candidate.nth(locator_spec.nth)
        raise WorkflowStale("Semantic locator was missing or ambiguous.")

    async def _conditions(self, page: Any, conditions: Any, response_status: Dict[str, int], network: list[dict]) -> bool:
        for condition in conditions or []:
            passed = True
            if condition.kind == "url_matches":
                passed = bool(re.search(str(condition.value or ""), page.url))
            elif condition.kind in {"element_present", "element_visible"}:
                try:
                    locator = await self._resolve_locator(page, condition.locator)
                    passed = await locator.count() > 0
                    if condition.kind == "element_visible":
                        passed = passed and await locator.is_visible()
                except Exception:
                    passed = False
            elif condition.kind == "text_contains":
                passed = str(condition.value or "").lower() in (await page.locator("body").inner_text()).lower()
            elif condition.kind == "network_seen":
                passed = any(str(condition.value or "") in item.get("url", "") for item in network)
            elif condition.kind == "status_code":
                passed = int(condition.value) in response_status.values()
            elif condition.kind == "state_hash":
                passed = bool(condition.value)
            if condition.negate:
                passed = not passed
            if not passed:
                return False
        return True

    async def _snapshot(self, page: Any, run: BrowserRunV1, step_run: BrowserStepRunV1, network: list[dict], response_status: Dict[str, int]) -> BrowserStateSnapshotV1:
        content = await page.content()
        dom_hash = hashlib.sha256(content.encode("utf-8", "ignore")).hexdigest()
        title = await page.title()
        text = await page.locator("body").inner_text()
        visible = [line.strip()[:180] for line in text.splitlines() if line.strip()][:30]
        storage = await page.evaluate("() => ({local: Object.keys(localStorage), session: Object.keys(sessionStorage)})")
        artifacts = []
        if self.artifact_store:
            screenshot = await page.screenshot(full_page=True)
            artifact = self.artifact_store.put_bytes(run.session_id, screenshot, "browser_screenshot", "image/png", "png")
            if self.repository and hasattr(self.repository, "save_artifact"):
                self.repository.save_artifact(run.session_id, artifact, run.run_id)
            artifacts.append(artifact.artifact_id)
        return BrowserStateSnapshotV1(
            session_id=run.session_id,
            run_id=run.run_id,
            step_run_id=step_run.step_run_id,
            identity_id=run.identity_id,
            graph_id=run.graph_id,
            state_digest=_digest({"url": page.url, "dom_hash": dom_hash, "step": run.current_step}),
            url=redact(page.url),
            title=redact(title),
            dom_hash=dom_hash,
            visible_landmarks=visible,
            network_fingerprints=network[-30:],
            storage_metadata=storage,
            artifact_ids=artifacts,
        )

    def _persist_run(self, run: BrowserRunV1) -> BrowserRunV1:
        if self.repository:
            self.repository.save_run(run)
        return run

    def _persist_step(self, step_run: BrowserStepRunV1) -> None:
        if self.repository:
            self.repository.save_step_run(step_run)

    def _persist_snapshot(self, snapshot: BrowserStateSnapshotV1) -> None:
        if self.repository:
            self.repository.save_snapshot(snapshot)

import asyncio
import contextvars
import inspect
import json
import re
import time
from typing import Optional
from urllib.parse import (
    parse_qsl,
    unquote,
    urlencode,
    urljoin,
    urlparse,
    urlsplit,
    urlunsplit,
)
from core.proxy_router import proxy_router
from core.tool_decorator import crewai_tool as tool
from core.cancellation import check_cancelled
from core.rate_limiter import rate_limiter
from core.redact import redact
from core.structured_contract import (
    CandidateFindingV1,
    ObservationV1,
    ToolErrorV1,
    ToolResultV1,
)

try:
    from playwright.async_api import async_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    class PWTimeout(TimeoutError):
        """Fallback timeout type when Playwright is not installed."""

        pass


# ── Shared browser context (lazy init) ────────────────────────────────────────

_browser = None
_playwright = None
_browser_loop = None
ASYNC_INVOCATION_TIMEOUT_SECONDS = 90


def _browser_context() -> object:
    """Return the current typed execution context without importing at module load."""
    try:
        from core.identity_context import get_execution_context

        return get_execution_context()
    except Exception:
        return None


def _tls_errors_ignored() -> bool:
    """Honor the central TLS policy; verification is enabled by default."""
    try:
        from core.config_loader import get_setting

        safety = get_setting("safety", {}) or {}
        return not bool(safety.get("tls_verify", True))
    except Exception:
        return False


def _browser_workflow_setting(name: str, default):
    """Read a browser setting without making browser tools config-dependent."""
    try:
        from core.config_loader import get_config

        return (get_config().get("browser_workflow") or {}).get(name, default)
    except Exception:
        return default


def _require_browser_url(url: str) -> None:
    """Apply the same scope/egress policy to browser requests as HTTP tools."""
    parsed = urlparse(str(url))
    if parsed.scheme not in {"http", "https"}:
        return
    context = _browser_context()
    if not context or not context.session_id or not context.safety_kernel:
        from core.safety_kernel import SafetyViolation
        raise SafetyViolation("missing_execution_context", "Browser request requires an active scoped execution context.")
    from core.execution_contract import ResourceBudgetV1
    from core.safety_kernel import SafetyKernel

    # Browser requests must receive the same exact local-lab authorization as
    # guarded HTTP. Previously the browser route called ``require`` without
    # ``allow_private``, so an allowlisted Docker lab could work for requests
    # but fail for Playwright navigation/subresources with a misleading
    # private-IP rejection.
    allow_private = bool(
        context.authorized_lab_mode
        and context.authorized_lab_origin
        and SafetyKernel.origin(str(url))
        == str(context.authorized_lab_origin).rstrip("/").lower()
    )

    context.safety_kernel.require(
        context.session_id,
        "browser_request",
        str(url),
        job_id=context.job_id,
        attempt_id=context.attempt_id,
        tool_run_id=context.tool_run_id,
        identity_id=getattr(context, "identity_id", ""),
        budget=context.budget or ResourceBudgetV1(),
        approved=context.approval_granted,
        mutation=False,
        allow_private=allow_private,
    )


def _account_browser_request(url: str, method: str, upload_bytes: int = 0) -> None:
    """Account browser traffic through the same durable budget as HTTP tools."""
    parsed = urlparse(str(url))
    if parsed.scheme not in {"http", "https"}:
        return
    context = _browser_context()
    if not context or not context.session_id or not context.safety_kernel:
        return
    from core.execution_contract import ResourceBudgetV1

    context.safety_kernel.account(
        context.session_id,
        context.job_id,
        str(url),
        upload_bytes=max(0, int(upload_bytes)),
        budget=context.budget or ResourceBudgetV1(),
        attempt_id=context.attempt_id,
        tool_run_id=context.tool_run_id,
    )


async def _install_browser_guard(context: object, origin: str = "") -> None:
    """Abort out-of-scope navigations, redirects, and subresource requests."""
    execution_context = _browser_context()
    scoped_origin = origin or getattr(execution_context, "target_origin", "")
    if scoped_origin:
        _require_browser_url(scoped_origin)

    async def guard(route):
        request_url = route.request.url
        try:
            # Both scope and budget may hit synchronous durable Supabase
            # methods. Keep them off the Playwright event loop so a slow audit
            # sink cannot make navigation/screenshot time out.
            await asyncio.to_thread(_require_browser_url, request_url)
            post_data = route.request.post_data or ""
            upload_bytes = len(post_data.encode("utf-8", errors="ignore"))
            await asyncio.to_thread(
                _account_browser_request,
                request_url,
                route.request.method,
                upload_bytes,
            )
        except Exception:
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    await context.route("**/*", guard)

    def record_response(response) -> None:
        response_url = getattr(response, "url", "")
        if not response_url:
            return
        active = _browser_context()
        kernel = getattr(active, "safety_kernel", None) if active else None
        if not kernel or not getattr(active, "session_id", ""):
            return
        try:
            kernel.record_response(
                active.session_id,
                active.job_id,
                response_url,
                int(response.status),
            )
        except Exception:
            # Response accounting is best effort; the request budget is
            # authoritative and already accounted before continuation.
            return

    context.on("response", record_response)


async def _get_browser():
    global _browser, _playwright, _browser_loop
    if not PLAYWRIGHT_AVAILABLE:
        raise RuntimeError(
            "Playwright not yet diinstall. Jalankan:\n"
            "  pip install playwright --break-system-packages\n"
            "  playwright install chromium"
        )
    current_loop = asyncio.get_running_loop()
    browser_is_usable = False
    if _browser is not None and _browser_loop is current_loop:
        try:
            browser_is_usable = bool(_browser.is_connected())
        except Exception:
            browser_is_usable = False

    # Async Playwright objects are bound to the event loop that created them.
    # The legacy recon tools are synchronous wrappers and may be invoked from
    # different worker threads, so a browser from a previous loop must never
    # be reused.  The managed runner below closes the normal previous
    # instance; this branch also fails safe if a loop died unexpectedly.
    if not browser_is_usable:
        _browser = None
        _playwright = None
        _browser_loop = current_loop
        _playwright = await async_playwright().start()
        _browser = await _playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ]
        )
    return _browser


async def _close_browser_for_current_loop() -> None:
    """Release browser resources before the invocation's loop is closed."""
    global _browser, _playwright, _browser_loop
    current_loop = asyncio.get_running_loop()
    if _browser_loop is not current_loop:
        return
    browser, playwright = _browser, _playwright
    _browser = None
    _playwright = None
    _browser_loop = None
    if browser is not None:
        try:
            await asyncio.wait_for(browser.close(), timeout=5)
        except asyncio.TimeoutError:
            # A renderer that wedged during a screenshot must not hold the
            # worker forever.  The browser process will be reaped with the
            # loop/worker lifecycle if Playwright cannot close it cleanly.
            pass
        finally:
            if playwright is not None:
                await playwright.stop()
    elif playwright is not None:
        await playwright.stop()


async def _new_page(browser, timeout_ms: int = 15000, origin: str = ""):
    """Buat page baru with stealth settings dasar."""
    proxy_dict = proxy_router.get_proxy()
    proxy_server = proxy_dict["http"] if proxy_dict else None

    context_args = {
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "viewport": {"width": 1280, "height": 800},
        "ignore_https_errors": _tls_errors_ignored(),
    }

    # Each browser context is bound to the active identity. Never reuse a
    # shared browser context across identities.
    try:
        from core.auth_store import auth_store
        from core.identity_context import get_execution_context
        context = get_execution_context()
        domain = _domain_of(origin or (context.target_origin if context else ""))
        auth_session = auth_store.get_session(
            domain,
            session_id=context.session_id if context else "",
            identity_id=context.identity_id if context else "",
        ) if domain else None
        if context and context.auth_context_id and auth_session and auth_session.auth_context_id not in {"", context.auth_context_id}:
            auth_session = None
        if auth_session:
            if auth_session.storage_state:
                context_args["storage_state"] = auth_session.storage_state
            elif auth_session.cookies:
                context_args["storage_state"] = {
                    "cookies": [
                        {"name": name, "value": value, "domain": domain, "path": "/"}
                        for name, value in auth_session.cookies.items()
                    ],
                    "origins": [],
                }
            if auth_session.headers:
                context_args["extra_http_headers"] = auth_session.headers
    except Exception:
        pass
    
    if proxy_server:
        context_args["proxy"] = {"server": proxy_server}

    ctx = await browser.new_context(**context_args)
    await _install_browser_guard(ctx, origin=origin)
    page = await ctx.new_page()
    page.set_default_timeout(timeout_ms)

    # Basic anti-detection: hapus webdriver fingerprint
    await page.add_init_script(
        "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
    )
    return page, ctx


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


def _authorization_headers_from_storage_state(storage_state: dict) -> dict[str, str]:
    """Extract a browser JWT for HTTP tools without exposing its value.

    SPAs commonly keep their bearer token in localStorage rather than a
    cookie. Only token-named entries with a JWT-shaped value are promoted to
    an Authorization header; arbitrary localStorage secrets are never copied
    into request headers or logs.
    """
    if not isinstance(storage_state, dict):
        return {}
    token_keys = {"token", "jwt", "access_token", "access-token", "id_token", "id-token"}
    jwt_pattern = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
    for origin in storage_state.get("origins") or []:
        if not isinstance(origin, dict):
            continue
        for item in origin.get("localStorage") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip().lower()
            value = str(item.get("value") or "").strip()
            if name in token_keys and jwt_pattern.fullmatch(value):
                return {"Authorization": f"Bearer {value}"}
    return {}


def _is_download_navigation_error(exc: BaseException) -> bool:
    """Recognize a browser navigation that intentionally starts a download.

    Playwright raises instead of returning a document when a URL has a
    download disposition (for example an exposed ``.env`` or source map).
    That is still valid network/surface evidence; it must not be promoted to
    an authoritative tool failure merely because no DOM was created.
    """
    return "download is starting" in str(exc).lower()


def _is_recoverable_navigation_error(exc: BaseException) -> bool:
    """Recognize one bounded navigation timeout without losing prior evidence."""
    text = str(exc).lower()
    return "timeout" in text and ("page.goto" in text or "navigation" in text)


async def _goto_browser_page(
    page,
    url: str,
    *,
    timeout_ms: int = 15000,
    wait_until: str = "domcontentloaded",
):
    """Navigate without making SPA lifecycle events a hard dependency.

    ``domcontentloaded`` and especially ``load`` are not reliable readiness
    signals for applications with polling, analytics, or websocket-like work.
    Establish the response at ``commit`` first, then wait for the requested
    lifecycle only as a best-effort signal. The caller performs its own
    bounded DOM/readiness probe afterwards.
    """
    timeout_ms = max(1000, int(timeout_ms))
    if wait_until == "commit":
        return await page.goto(url, wait_until="commit", timeout=timeout_ms)

    started = time.monotonic()
    try:
        response = await page.goto(url, wait_until="commit", timeout=timeout_ms)
    except PWTimeout as first_error:
        # A response may already have produced a usable document even when
        # Playwright cannot complete the commit lifecycle. Keep the legacy
        # fallback for that narrow case; normal SPA navigation never reaches
        # it because commit returns promptly.
        try:
            content = await asyncio.wait_for(page.content(), timeout=2)
        except Exception:
            content = ""
        if content and len(content.strip()) > 32:
            return None
        raise first_error
    elapsed_ms = int((time.monotonic() - started) * 1000)
    remaining_ms = max(250, timeout_ms - elapsed_ms)
    wait_for_load_state = getattr(page, "wait_for_load_state", None)
    if callable(wait_for_load_state):
        try:
            await wait_for_load_state(
                wait_until,
                timeout=max(250, min(3000, remaining_ms)),
            )
        except (PWTimeout, TimeoutError):
            # Commit plus the caller's DOM probe is sufficient for a usable
            # SPA surface. Keep the delayed lifecycle observable in caller
            # metrics/logs, but do not discard the page.
            pass
    return response


def _run_async(coro, timeout_seconds=None):
    """Run async coroutine from sync tool context."""
    timeout = ASYNC_INVOCATION_TIMEOUT_SECONDS if timeout_seconds is None else float(timeout_seconds)

    async def managed():
        try:
            return await coro
        finally:
            await _close_browser_for_current_loop()

    async def bounded():
        return await asyncio.wait_for(
            managed(), timeout=timeout
        )

    try:
        running_loop = asyncio.get_running_loop()
    except RuntimeError:
        running_loop = None

    if running_loop is not None:
        import concurrent.futures

        # Browser tools are synchronous at the public boundary but may be
        # called from an async API thread.  Propagate ContextVars (job
        # cancellation, scope, identity) into the loop thread and make the
        # coroutine itself own the timeout.  A future timeout alone is not
        # sufficient because Executor.__exit__ waits for the worker thread.
        execution_context = contextvars.copy_context()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(execution_context.run, asyncio.run, bounded())
        try:
            return future.result(timeout=timeout + 5)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
    return asyncio.run(bounded())


def _bounded_redirect_budget() -> tuple[float, int, Optional[int]]:
    """Return an explicit, adaptive budget for the redirect probe.

    ``auto`` derives the probe deadline from the public invocation watchdog
    and leaves parameter coverage uncapped. An operator can still provide a
    smaller mission budget, but there is no hidden parameter/action ceiling.
    """
    timeout_seconds = max(1.0, ASYNC_INVOCATION_TIMEOUT_SECONDS - 15)
    navigation_timeout_ms = 3000
    max_parameters: Optional[int] = None
    try:
        from core.config_loader import get_config

        configured = get_config().get("browser_workflow", {}) or {}
        configured_timeout = int(configured.get("redirect_probe_navigation_timeout_ms", navigation_timeout_ms))
        navigation_timeout_ms = max(1000, min(5000, configured_timeout))
        configured_budget = configured.get("redirect_probe_timeout_seconds", "auto")
        if configured_budget is not None and str(configured_budget).strip().lower() not in {
            "", "auto", "unlimited", "none", "null",
        }:
            timeout_seconds = max(1.0, min(timeout_seconds, float(configured_budget)))
        configured_parameters = configured.get("redirect_probe_max_parameters", "auto")
        if configured_parameters is None or str(configured_parameters).strip().lower() in {
            "auto", "all", "unlimited", "none",
        }:
            max_parameters = None
        else:
            # The configured value is an explicit resource budget. Do not add
            # another hidden hard ceiling here; the probe clamps it to the
            # number of cases it actually plans below.
            max_parameters = max(1, int(configured_parameters))
    except (TypeError, ValueError, AttributeError):
        pass
    return timeout_seconds, navigation_timeout_ms, max_parameters


def _append_query_parameter(url: str, parameter: str, value: str) -> str:
    """Add one encoded query value without corrupting an existing URL."""
    parsed = urlsplit(str(url))
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append((str(parameter), str(value)))
    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        urlencode(query, doseq=True),
        parsed.fragment,
    ))


def _response_value(response: object, name: str, default=None):
    """Read a Playwright response property while remaining test-double friendly."""
    value = getattr(response, name, default)
    return value() if callable(value) else value


async def _response_headers(response: object) -> dict[str, str]:
    """Return normalized response headers without requiring one Playwright API."""
    for name in ("all_headers", "headers"):
        value = getattr(response, name, None)
        if value is None:
            continue
        try:
            value = value() if callable(value) else value
            if inspect.isawaitable(value):
                value = await value
            if isinstance(value, dict):
                return {str(key).lower(): str(item) for key, item in value.items()}
        except Exception:
            continue
    return {}


def _is_external_canary_url(value: object, canary: str) -> bool:
    """Match the canary host, not an occurrence in a normal query string."""
    canary_text = str(canary or "").strip()
    # The OOB engine returns a host without a scheme. ``urlparse`` treats that
    # as a path, so parse it as an authority first; otherwise every canary
    # check silently returned false and the interceptor could not prove a
    # redirect.
    canary_host = (
        urlparse(canary_text if "://" in canary_text else f"//{canary_text}").hostname
        or ""
    ).lower().rstrip(".")
    if not canary_host:
        return False
    raw = str(value or "")
    for candidate in (raw, unquote(raw)):
        try:
            hostname = (urlparse(candidate).hostname or "").lower().rstrip(".")
        except ValueError:
            hostname = ""
        if hostname == canary_host:
            return True
    return False


async def _install_redirect_probe_interceptor(page, canary: str, case_ref: dict) -> object:
    """Capture and abort only the external canary navigation.

    ``_new_page`` already installs the regular scope guard. This page-level
    handler repeats that check so the redirect probe remains safe even when
    Playwright gives page routes precedence over context routes.
    """
    route_method = getattr(page, "route", None)
    if not callable(route_method):
        return None

    async def intercept(route):
        request = getattr(route, "request", None)
        request_url = str(getattr(request, "url", "") or "")
        if _is_external_canary_url(request_url, canary):
            case = case_ref.get("case")
            if case is not None:
                case.setdefault("canary_requests", []).append({
                    "url": request_url,
                    "resource_type": str(getattr(request, "resource_type", "") or ""),
                    "redirected_from": bool(getattr(request, "redirected_from", None)),
                })
            await route.abort("blockedbyclient")
            return

        try:
            _require_browser_url(request_url)
        except Exception:
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    await route_method("**/*", intercept)
    return intercept


# ── Exec logger accessor (sama kayak custom_tools.py) ─────────────────────────

def _logger():
    try:
        from tools.custom_tools import exec_logger
        return exec_logger
    except Exception:
        return None


def _browser_cancelled_result(tool_name: str, url: str) -> ToolResultV1:
    """Return a typed cancellation result instead of legacy plain text."""
    return ToolResultV1(
        tool_name=tool_name,
        category="recon",
        target=url,
        status="cancelled",
        summary=f"{tool_name} cancelled before completion.",
        errors=[ToolErrorV1(
            code="browser_cancelled",
            message="Browser operation was cancelled by the active job.",
            retryable=True,
        )],
        metrics={"termination_reason": "cancelled"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — Screenshot + visual analysis
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_screenshot(url: str) -> ToolResultV1:
    """
    Buka URL di headless browser, ambil screenshot full-page, dan extract
    informasi dasar (title, meta, visible text snippet).
    Berguna buat: verify target accessible, detect login wall, lihat struktur
    halaman, nemuin error message atau debug info that exposed.

    Args:
        url: URL target that mau di-screenshot
    Returns:
        A typed browser observation. The PNG is stored as a private evidence
        artifact and referenced by artifact ID; raw image bytes never enter
        model prompts or execution logs.
    """
    logger = _logger()
    tool_name = "Browser Screenshot"

    if check_cancelled(logger):
        return _browser_cancelled_result(tool_name, url)

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser, origin=url)

        captured = {
            "title": "",
            "meta_description": "",
            "visible_text_preview": "",
            "navigation_status": "not_started",
        }
        phase_started = time.monotonic()
        phase_timings = {}

        async def close_context_safely():
            try:
                await asyncio.wait_for(ctx.close(), timeout=3)
            except Exception:
                # Screenshot is optional evidence.  A stuck renderer must
                # not turn the whole pentest into a failed job.
                pass

        def build_result(
            status: str,
            *,
            error_code: str = "",
            reason: str = "",
            artifact=None,
        ) -> ToolResultV1:
            artifact_ids = [artifact.artifact_id] if artifact is not None else []
            summary = (
                f"Browser page captured: {captured['title'] or '(untitled)'}"
                if status == "succeeded"
                else f"Browser page capture partial: {reason}"
            )
            observation = ObservationV1(
                role="browser",
                kind="browser_page_capture",
                summary=summary,
                target_url=url,
                response_excerpt=captured["visible_text_preview"],
                artifact_ids=artifact_ids,
                metadata={
                    "title": captured["title"],
                    "meta_description": captured["meta_description"],
                    "navigation_status": captured["navigation_status"],
                    "screenshot_available": bool(artifact),
                    "screenshot_artifact_id": artifact.artifact_id if artifact else "",
                },
            )
            errors = []
            if error_code:
                errors.append(ToolErrorV1(
                    code=error_code,
                    message=reason,
                    retryable=error_code in {
                        "browser_navigation_timeout",
                        "browser_screenshot_timeout",
                        "browser_artifact_persistence_error",
                    },
                    details={
                        "navigation_status": captured["navigation_status"],
                        "screenshot_available": bool(artifact),
                    },
                ))
            if logger:
                logger.add_log(
                    tool_name,
                    "SUCCESS" if status == "succeeded" else "PARTIAL",
                    summary,
                )
            return ToolResultV1(
                tool_name=tool_name,
                category="recon",
                target=url,
                status=status,
                summary=summary,
                observations=[observation],
                artifacts=[artifact] if artifact else [],
                errors=errors,
                metrics={
                    "navigation_status": captured["navigation_status"],
                    "screenshot_available": bool(artifact),
                    "phase_timings_ms": dict(phase_timings),
                },
            )

        def persist_screenshot(screenshot_bytes: bytes):
            """Persist screenshot through the active structured evidence store."""
            context = _browser_context()
            repository = getattr(context, "repository", None) if context else None
            if repository is None or not getattr(context, "session_id", ""):
                raise RuntimeError("active structured artifact store unavailable")
            from core.artifact_store import ArtifactStore

            store = ArtifactStore(getattr(repository, "sb", None))
            return store.put_bytes(
                context.session_id,
                screenshot_bytes,
                "browser_screenshot",
                "image/png",
                "png",
                metadata={
                    "target_url": url,
                    "capture_mode": "viewport",
                    "title": captured["title"],
                },
            )

        try:
            try:
                await _goto_browser_page(
                    page,
                    url,
                    timeout_ms=int(_browser_workflow_setting("navigation_timeout_ms", 10000)),
                )
                captured["navigation_status"] = "succeeded"
                phase_timings["navigation_ms"] = round((time.monotonic() - phase_started) * 1000, 2)
            except PWTimeout as exc:
                captured["navigation_status"] = "timeout"
                return build_result(
                    "partial",
                    error_code="browser_navigation_timeout",
                    reason=f"Navigation timeout: {type(exc).__name__}",
                )
            except Exception as exc:
                captured["navigation_status"] = "failed"
                return build_result(
                    "partial",
                    error_code="browser_navigation_failed",
                    reason=f"Navigation failed: {type(exc).__name__}",
                )

            # A short DOM settle window is more reliable for SPAs than
            # networkidle, which may never happen while polling/websocket
            # connections remain open.
            await page.wait_for_timeout(
                max(0, min(5000, int(_browser_workflow_setting("dom_settle_ms", 1000))))
            )
            phase_timings["dom_settle_ms"] = round((time.monotonic() - phase_started) * 1000, 2)

            captured["title"] = await page.title()
            captured["meta_description"] = await page.evaluate(
                "() => document.querySelector('meta[name=\"description\"]')?.content ?? ''"
            )
            captured["visible_text_preview"] = await page.evaluate(
                "() => document.body?.innerText?.slice(0, 500) ?? ''"
            )
            phase_timings["metadata_ms"] = round((time.monotonic() - phase_started) * 1000, 2)

            screenshot_timeout_ms = max(
                1000,
                min(30000, int(_browser_workflow_setting("screenshot_timeout_ms", 15000))),
            )
            screenshot_bytes = await asyncio.wait_for(
                page.screenshot(full_page=False, timeout=screenshot_timeout_ms),
                timeout=(screenshot_timeout_ms / 1000.0) + 0.5,
            )
            phase_timings["screenshot_ms"] = round((time.monotonic() - phase_started) * 1000, 2)
            if check_cancelled(logger):
                return _browser_cancelled_result(tool_name, url)
            try:
                # Supabase storage is synchronous. Never run it on the
                # Playwright event loop: a slow storage endpoint must not
                # make browser cleanup and cancellation look like a capture
                # timeout. Keep this persistence boundary bounded as well.
                artifact_timeout = max(
                    3.0,
                    min(30.0, float(_browser_workflow_setting("artifact_persistence_timeout_seconds", 15))),
                )
                artifact = await asyncio.wait_for(
                    asyncio.to_thread(persist_screenshot, screenshot_bytes),
                    timeout=artifact_timeout,
                )
                phase_timings["artifact_persistence_ms"] = round((time.monotonic() - phase_started) * 1000, 2)
            except Exception as exc:
                return build_result(
                    "partial",
                    error_code="browser_artifact_persistence_error",
                    reason=f"Screenshot captured but artifact persistence failed: {type(exc).__name__}",
                )
            return build_result("succeeded", artifact=artifact)
        except PWTimeout:
            return build_result(
                "partial",
                error_code="browser_screenshot_timeout",
                reason=f"Screenshot timeout saat capture {url}",
            )
        except asyncio.TimeoutError:
            return build_result(
                "partial",
                error_code="browser_screenshot_timeout",
                reason=f"Screenshot timeout saat capture {url}",
            )
        except Exception as e:
            return build_result(
                "partial",
                error_code="browser_capture_unavailable",
                reason=f"Browser capture unavailable: {type(e).__name__}",
            )
        finally:
            await close_context_safely()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 14 — Unencrypted Storage Scanner
# ═══════════════════════════════════════════════════════════════════════════════

@tool("browser_storage_security_scanner")
def browser_storage_security_scanner(url: str) -> str:
    """
    Comprehensive storage security scanner:
    - Cookie flags (HttpOnly, Secure, SameSite)
    - localStorage sensitive data
    - sessionStorage sensitive data
    - IndexedDB sensitive data
    - Cache-Control headers for sensitive pages
    - Mixed content (HTTP resources on HTTPS page)
    """
    logger = _logger()
    tool_name = "Storage Security Scanner"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser, origin=url)
        try:
            # SPAs may keep XHR/WebSocket activity open indefinitely.  A
            # recon primitive must not wait for global network idleness;
            # DOM readiness is the bounded signal and the caller can still
            # perform its explicit short wait below.
            # SPA login pages can finish loading the application shell after
            # the generic browser step timeout on a constrained lab runner.
            await _goto_browser_page(page, url, timeout_ms=30000)
            await page.wait_for_timeout(2000)

            findings = []

            # ── 1. Cookie security analysis ──────────────────────────────────
            cookies = await page.context.cookies()
            for cookie in cookies:
                issues = []
                if not cookie.get("httpOnly"):
                    issues.append("Missing HttpOnly — accessible via JavaScript (XSS risk)")
                if not cookie.get("secure"):
                    issues.append("Missing Secure — transmitted over HTTP")
                if cookie.get("sameSite") == "None":
                    issues.append("SameSite=None — vulnerable to CSRF")
                if cookie.get("expires", -1) == -1 and not cookie.get("httpOnly"):
                    issues.append("Session cookie without HttpOnly — persistent XSS risk")

                if issues:
                    findings.append({
                        "type": "Insecure Cookie",
                        "cookie": cookie.get("name"),
                        "issues": issues,
                        "severity": "High" if len(issues) >= 2 else "Medium",
                    })

            # ── 2. localStorage sensitive data ────────────────────────────────
            local_storage = await page.evaluate("""
                () => {
                    const items = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        items[key] = localStorage.getItem(key);
                    }
                    return items;
                }
            """)

            sensitive_patterns = ["token", "jwt", "password", "secret", "key", "api_key", "auth"]
            for key, value in local_storage.items():
                key_lower = key.lower()
                if any(p in key_lower for p in sensitive_patterns):
                    findings.append({
                        "type": "Sensitive Data in localStorage",
                        "key": key,
                        "severity": "High",
                        "detail": "Sensitive data stored in localStorage — accessible via XSS, persists across sessions",
                    })

            # ── 3. Cache-Control analysis ─────────────────────────────────────
            try:
                resp = await page.evaluate("() => fetch(window.location.href).then(r => r.headers)")
                cache_control = resp.get("cache-control", "") if resp else ""

                is_sensitive = any(p in url.lower() for p in ["/profile", "/account", "/dashboard", "/settings", "/payment"])
                if is_sensitive and "no-store" not in cache_control:
                    findings.append({
                        "type": "Sensitive Page Caching",
                        "severity": "Medium",
                        "detail": f"Sensitive page missing no-store Cache-Control: {cache_control or 'MISSING'}",
                    })
            except Exception:
                pass

            # ── 4. Mixed content check ────────────────────────────────────────
            if url.startswith("https://"):
                http_resources = await page.evaluate("""
                    () => {
                        const resources = [];
                        document.querySelectorAll('[src], [href]').forEach(el => {
                            const src = el.src || el.href;
                            if (src && src.startsWith('http://')) {
                                resources.push(src);
                            }
                        });
                        return resources;
                    }
                """)

                if http_resources:
                    findings.append({
                        "type": "Mixed Content",
                        "severity": "Medium",
                        "detail": f"HTTPS page loads {len(http_resources)} HTTP resources",
                        "resources": http_resources[:5],
                    })

            result = {
                "url": url,
                "total_cookies": len(cookies),
                "findings": findings,
                "count": len(findings),
                "status": "success"
            }

            if logger:
                logger.add_log(tool_name, "SUCCESS",
                    f"Storage security scan: {len(cookies)} cookies, {len(findings)} findings")
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 8 — Automated Login (Authenticated Scanning)
# ═══════════════════════════════════════════════════════════════════════════════

@tool("login_automator")
def login_automator(
    url: str,
    username: str,
    password: str,
    username_selector: str = "",
    password_selector: str = "",
    submit_selector: str = "",
    success_indicator: str = "",
    session_id: str = "",
    identity_id: str = "",
    auth_context_id: str = "",
) -> str:
    """
    Automated login using Playwright. Login ke target, capture session
    cookies, dan simpen ke auth_store for dipake tools lain.

    Flow:
    1. Buka login page
    2. Isi username & password
    3. Submit form
    4. Verifikasi login success (cek redirect atau success indicator)
    5. Capture cookies → simpen ke auth_store

    Args:
        url: Login page URL (e.g., https://target.com/login)
        username: Username/email for login
        password: Password for login
        username_selector: CSS selector for input username (auto-detect kalau kosong)
        password_selector: CSS selector for input password (auto-detect kalau kosong)
        submit_selector: CSS selector for tombol submit (auto-detect kalau kosong)
        success_indicator: Text/URL that muncul kalau login success (opsional)
    Returns:
        JSON berisi status login, cookies that didapat, dan session info
    """
    logger = _logger()
    tool_name = "Login Automator"

    from core.auth_store import auth_store, AuthSession
    from core.cancellation import check_cancelled

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    # HITL approval senot yet login
    from core.checkpoint import require_approval
    approved = require_approval(
        action=f"Automated login ke {url}",
        context=f"Username: {username[:3]}***. Login ke {url} for authenticated scanning.",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval rejected atau timeout."

    domain = _domain_of(url)
    logger.add_log(tool_name, "START", f"Starting automated login ke {url}")

    # The selector arguments are used as auto-detect fallbacks below.  Keep
    # per-invocation state in explicitly named locals so the nested coroutine
    # does not shadow the function arguments (which previously caused an
    # UnboundLocalError whenever auto-detection was requested).
    resolved_username_selector = username_selector
    resolved_password_selector = password_selector
    resolved_submit_selector = submit_selector

    async def _run():
        nonlocal resolved_username_selector, resolved_password_selector, resolved_submit_selector
        browser = await _get_browser()
        page, ctx = await _new_page(browser, origin=url)
        try:
            # ── 1. Buka login page ────────────────────────────────────────────
            logger.add_log(tool_name, "PROCESSING", f"Opening {url}")
            # SPA login pages can finish loading the application shell after
            # the generic browser step timeout on a constrained lab runner.
            await _goto_browser_page(page, url, timeout_ms=30000)
            await page.wait_for_timeout(2000)

            # ── 2. Detect & isi username field ────────────────────────────────
            logger.add_log(tool_name, "PROCESSING", "Searching input fields")

            # Auto-detect selectors kalau gak di-specify
            if not resolved_username_selector:
                # Coba common selectors
                for sel in [
                    'input[type="email"]',
                    'input[name="email"]',
                    'input[name="username"]',
                    'input[name="user"]',
                    'input[name="login"]',
                    'input[id*="email"]',
                    'input[id*="user"]',
                    'input[placeholder*="email" i]',
                    'input[placeholder*="user" i]',
                    'input[type="text"]:first-of-type',
                ]:
                    try:
                        if await page.locator(sel).count() > 0:
                            resolved_username_selector = sel
                            break
                    except Exception:
                        continue

            if not resolved_password_selector:
                for sel in [
                    'input[type="password"]',
                    'input[name="password"]',
                    'input[name="pass"]',
                    'input[name="pwd"]',
                ]:
                    try:
                        if await page.locator(sel).count() > 0:
                            resolved_password_selector = sel
                            break
                    except Exception:
                        continue

            if not resolved_submit_selector:
                for sel in [
                    'button[type="submit"]',
                    'input[type="submit"]',
                    'button:has-text("Login")',
                    'button:has-text("Sign in")',
                    'button:has-text("Log in")',
                    'button:has-text("Submit")',
                ]:
                    try:
                        if await page.locator(sel).count() > 0:
                            resolved_submit_selector = sel
                            break
                    except Exception:
                        continue

            if not resolved_username_selector or not resolved_password_selector:
                return json.dumps({
                    "status": "FAILED",
                    "error": "Failed auto-detect login form fields",
                    "hint": "Coba specify username_selector dan password_selector manual",
                    "page_title": await page.title(),
                    "page_url": page.url,
                })

            # ── 3. Isi credentials ───────────────────────────────────────────
            logger.add_log(tool_name, "PROCESSING", f"Filling form: {resolved_username_selector}, {resolved_password_selector}")

            await page.fill(resolved_username_selector, username)
            await page.wait_for_timeout(500)
            await page.fill(resolved_password_selector, password)
            await page.wait_for_timeout(500)

            # ── 4. Submit ─────────────────────────────────────────────────────
            logger.add_log(tool_name, "PROCESSING", "Submitting login form")

            if resolved_submit_selector:
                try:
                    await page.click(resolved_submit_selector)
                except PWTimeout:
                    # Some intentionally vulnerable SPAs show a first-visit
                    # overlay that intercepts pointer events. The login
                    # action is already behind the explicit approval above;
                    # force the same submit control rather than treating the
                    # overlay as a credential failure.
                    logger.add_log(
                        tool_name,
                        "WARNING",
                        "Submit overlay intercepted pointer; retrying approved click with force",
                    )
                    await page.locator(resolved_submit_selector).click(force=True)
            else:
                # Fallback: tekan Enter di password field
                await page.press(resolved_password_selector, "Enter")

            # Tunggu navigasi
            await page.wait_for_timeout(3000)

            # ── 5. Verifikasi login success ──────────────────────────────────
            final_url = page.url
            page_title = await page.title()
            body_text = await page.evaluate("() => document.body?.innerText?.slice(0, 2000) ?? ''")

            # Cek indikator login success
            login_success = False

            if success_indicator:
                # User specify success indicator
                login_success = success_indicator.lower() in body_text.lower() or success_indicator.lower() in final_url.lower()
            else:
                # Auto-detect: cek apakah masih di login page
                login_indicators = ["login", "signin", "sign-in", "auth"]
                still_on_login = any(ind in final_url.lower() for ind in login_indicators)

                # Cek apakah ada error message
                error_indicators = [
                    "invalid credentials",
                    "wrong password",
                    "incorrect password",
                    "login failed",
                    "authentication failed",
                    "user not found",
                    "account not found",
                ]
                has_error = any(err in body_text.lower() for err in error_indicators)

                # Cek apakah ada dashboard/protected content indicators
                success_indicators = [
                    "dashboard",
                    "welcome",
                    "logout",
                    "sign out",
                    "profile",
                    "settings",
                    "account",
                ]
                has_success_content = any(ind in body_text.lower() for ind in success_indicators)

                login_success = (not still_on_login and not has_error) or has_success_content

            # ── 6. Capture browser auth state ───────────────────────────────
            cookies = await page.context.cookies()
            cookie_dict = {c["name"]: c["value"] for c in cookies if c.get("domain", "").endswith(domain.replace(".", ""))}

            # Juga capture from all cookies (fallback)
            if not cookie_dict:
                cookie_dict = {c["name"]: c["value"] for c in cookies}

            storage_state = await page.context.storage_state()
            auth_headers = _authorization_headers_from_storage_state(storage_state)
            browser_state_present = bool(cookie_dict or storage_state.get("origins"))

            # ── 7. Simpen ke auth_store ───────────────────────────────────────
            if login_success and browser_state_present:
                auth_session = AuthSession(
                    domain=domain,
                    cookies=cookie_dict,
                    headers=auth_headers,
                    source="auto_login",
                    login_url=url,
                    credentials={"username": username},
                    session_id=session_id,
                    identity_id=identity_id,
                    auth_context_id=auth_context_id,
                    storage_state=storage_state,
                )
                auth_store.save_session(
                    domain,
                    auth_session,
                    session_id=session_id,
                    identity_id=identity_id,
                )
                logger.add_log(tool_name, "SUCCESS",
                    f"Login success! Browser auth state saved: {len(cookie_dict)} cookies, {len(auth_headers)} derived auth headers")
            elif not login_success:
                logger.add_log(tool_name, "WARNING",
                    "Login failed — not found success indicator that terdeteksi")

            result = {
                "status": "SUCCESS" if login_success else "FAILED",
                "final_url": final_url,
                "page_title": page_title,
                "cookies_captured": len(cookie_dict),
                "cookie_names": list(cookie_dict.keys())[:10],
                "storage_origins_captured": len(storage_state.get("origins") or []),
                "auth_headers_captured": len(auth_headers),
                "session_stored": login_success and browser_state_present,
                "body_preview": body_text[:500],
            }

            return json.dumps(redact(result), indent=2)

        except Exception as e:
            logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"status": "ERROR", "error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 9 — Inject Session (Manual Cookie Injection)
# ═══════════════════════════════════════════════════════════════════════════════

@tool("inject_session")
def inject_session(
    url: str,
    cookies: str,
    headers: str = "",
    session_id: str = "",
    identity_id: str = "",
    auth_context_id: str = "",
) -> str:
    """
    Inject session cookies/headers to auth_store. Used when user provides
    session manual (misal sealready login manual + MFA).

    Flow:
    1. User login manual di browser
    2. User copy cookies from DevTools/Burp
    3. User paste ke tool ini
    4. Cookies saved ke auth_store → tools lain can pake

    Args:
        url: Target URL (for extract domain)
        cookies: Raw cookie string (e.g., "session=abc123; token=xyz; csrftoken=123")
                 ATAU JSON string: {"session": "abc123", "token": "xyz"}
        headers: Optional JSON string of headers (e.g., '{"Authorization": "Bearer xyz"}')
    Returns:
        JSON berisi status dan info session that saved
    """
    logger = _logger()
    tool_name = "Session Injector"

    from core.auth_store import auth_store, AuthSession

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    logger.add_log(tool_name, "START", f"Injecting session for {domain}")

    # Parse cookies
    cookie_dict = {}
    try:
        # Coba JSON dulu
        cookie_dict = json.loads(cookies)
    except (json.JSONDecodeError, TypeError):
        # Parse sebagai raw cookie string: "key1=val1; key2=val2"
        for part in cookies.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    if not cookie_dict:
        return json.dumps({
            "status": "FAILED",
            "error": "Failed parse cookies. Format: 'session=abc123; token=xyz' atau JSON",
        })

    # Parse headers
    header_dict = {}
    if headers:
        try:
            header_dict = json.loads(headers)
        except (json.JSONDecodeError, TypeError):
            pass

    # Simpen ke auth_store
    auth_session = AuthSession(
        domain=domain,
        cookies=cookie_dict,
        headers=header_dict,
        source="user",
        session_id=session_id,
        identity_id=identity_id,
        auth_context_id=auth_context_id,
    )
    auth_store.save_session(
        domain,
        auth_session,
        session_id=session_id,
        identity_id=identity_id,
    )

    logger.add_log(tool_name, "SUCCESS",
        f"Session saved for {domain}: {len(cookie_dict)} cookies, {len(header_dict)} headers")

    result = {
        "status": "SUCCESS",
        "domain": domain,
        "cookies_stored": len(cookie_dict),
        "headers_stored": len(header_dict),
        "cookie_names": list(cookie_dict.keys()),
        "source": "user_manual",
    }

    return json.dumps(redact(result), indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — Extract attack surface
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_extract_surface(url: str) -> str:
    """
    Buka halaman di headless browser dan extract all attack surface:
    - Semua link (internal & eksternal)
    - Semua form (action URL, method, input fields)
    - Semua input element with name/id/type
    - Script src URLs (JS files)
    - API-like URLs that kedeteksi from href/action
    Berguna buat: mapping attack surface senot yet scanning, nemuin endpoint
    tersembunyi that cuma muncul sealready browser render JS.

    Args:
        url: URL halaman that mau di-extract
    Returns:
        JSON berisi links, forms, inputs, scripts, dan api_endpoints
    """
    logger = _logger()
    tool_name = "Browser Extract Surface"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser, origin=url)
        try:
            # A discovered asset such as main.js is a valid surface target,
            # but it does not always produce a DOMContentLoaded lifecycle
            # event.  ``commit`` is the correct bounded signal for both HTML
            # documents and static scripts/stylesheets.
            page.set_default_navigation_timeout(30000)
            try:
                await _goto_browser_page(page, url, timeout_ms=30000, wait_until="commit")
            except Exception as exc:
                if not _is_download_navigation_error(exc):
                    raise
                # A download has no DOM to inspect, but the URL itself is a
                # meaningful observed surface. Keep the result explicit and
                # non-fatal so the mission can continue to validate it with
                # the appropriate HTTP/file-content capability.
                if logger:
                    logger.add_log(
                        tool_name,
                        "WARNING",
                        "Navigation started a download; recorded URL as partial surface evidence",
                    )
                return json.dumps(redact({
                    "url": url,
                    "base_url": f"{urlparse(url).scheme}://{urlparse(url).netloc}",
                    "total_links": 0,
                    "internal_links": [],
                    "external_links": [],
                    "api_endpoints_detected": [],
                    "forms": [],
                    "all_inputs": [],
                    "script_sources": [],
                    "download_detected": True,
                    "status": "partial",
                    "error": "navigation_started_download",
                }), indent=2)
            await page.wait_for_timeout(1500)

            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

            # Extract links
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter((v, i, arr) => arr.indexOf(v) === i)
                    .slice(0, 100)
            """)

            # Extract forms
            forms = await page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action || '',
                    method: f.method || 'get',
                    inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                        .map(i => ({name: i.name, id: i.id, type: i.type}))
                }))
            """)

            # Extract all inputs (termasuk that di luar form)
            inputs = await page.evaluate("""
                () => Array.from(document.querySelectorAll('input,select,textarea'))
                    .map(i => ({name: i.name, id: i.id, type: i.type, placeholder: i.placeholder}))
                    .filter(i => i.name || i.id)
                    .slice(0, 50)
            """)

            # Extract script sources
            scripts = await page.evaluate("""
                () => Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter((v, i, arr) => arr.indexOf(v) === i)
            """)

            # Filter API-looking endpoints
            api_patterns = re.compile(r'/api/|/v\d+/|/graphql|/rest/|/json|/data/', re.I)
            api_endpoints = [l for l in links if api_patterns.search(l)]

            result = {
                "url": url,
                "base_url": base,
                "total_links": len(links),
                "internal_links": [l for l in links if base in l][:30],
                "external_links": [l for l in links if base not in l][:20],
                "api_endpoints_detected": api_endpoints,
                "forms": forms,
                "all_inputs": inputs,
                "script_sources": scripts,
                "status": "success"
            }

            if logger:
                logger.add_log(
                    tool_name, "SUCCESS",
                    f"Extracted {len(links)} links, {len(forms)} forms, {len(api_endpoints)} API endpoints"
                )
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 10 — Cookie & Session Inspector
# ═══════════════════════════════════════════════════════════════════════════════

@tool("browser_cookie_inspector")
def browser_cookie_inspector(url: str) -> str:
    """
    Inspect all cookies that set oleh halaman target.
    Cek security flags (HttpOnly, Secure, SameSite) dan analisa
    potensi cookie-based attacks (session fixation, CSRF, dll).
    """
    logger = _logger()
    tool_name = "Browser Cookie Inspector"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        try:
            await _goto_browser_page(page, url)
            await page.wait_for_timeout(2000)

            cookies = await page.context.cookies()
            cookie_analysis = []
            issues = []

            for cookie in cookies:
                analysis = {
                    "name": cookie.get("name", ""),
                    "value": cookie.get("value", "")[:100] + "..." if len(cookie.get("value", "")) > 100 else cookie.get("value", ""),
                    "domain": cookie.get("domain", ""),
                    "path": cookie.get("path", "/"),
                    "expires": cookie.get("expires", -1),
                    "httpOnly": cookie.get("httpOnly", False),
                    "secure": cookie.get("secure", False),
                    "sameSite": cookie.get("sameSite", "None"),
                }

                # Check security flags
                cookie_issues = []
                if not analysis["httpOnly"]:
                    cookie_issues.append("Missing HttpOnly — cookie accessible via JavaScript (XSS risk)")
                if not analysis["secure"]:
                    cookie_issues.append("Missing Secure — cookie transmitted over HTTP")
                if analysis["sameSite"] == "None":
                    cookie_issues.append("SameSite=None — vulnerable to CSRF")

                if cookie_issues:
                    issues.append({
                        "cookie": analysis["name"],
                        "issues": cookie_issues,
                        "severity": "Medium" if len(cookie_issues) == 1 else "High"
                    })

                # Session cookie detection
                if any(kw in analysis["name"].lower() for kw in ["session", "sess", "sid", "token", "auth"]):
                    analysis["is_session"] = True
                    if len(cookie.get("value", "")) < 16:
                        issues.append({
                            "cookie": analysis["name"],
                            "issues": [f"Short session ID ({len(cookie.get('value', ''))} chars) — potentially predictable"],
                            "severity": "High"
                        })

                cookie_analysis.append(analysis)

            result = {
                "url": url,
                "total_cookies": len(cookies),
                "cookies": cookie_analysis,
                "issues": issues,
                "security_summary": {
                    "http_only_count": sum(1 for c in cookies if c.get("httpOnly")),
                    "secure_count": sum(1 for c in cookies if c.get("secure")),
                    "samesite_none_count": sum(1 for c in cookies if c.get("sameSite") == "None"),
                    "session_cookies": sum(1 for c in cookie_analysis if c.get("is_session")),
                },
                "status": "success"
            }

            if logger:
                logger.add_log(tool_name, "SUCCESS",
                    f"Inspected {len(cookies)} cookies. Issues: {len(issues)}")
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 11 — LocalStorage & SessionStorage Inspector
# ═══════════════════════════════════════════════════════════════════════════════

@tool("browser_storage_inspector")
def browser_storage_inspector(url: str) -> str:
    """
    Inspect localStorage dan sessionStorage for nemuin:
    - Sensitive data (tokens, API keys, PII)
    - Insecure storage patterns
    - Client-side auth tokens
    - Debug info that exposed
    """
    logger = _logger()
    tool_name = "Browser Storage Inspector"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        try:
            await _goto_browser_page(page, url)
            await page.wait_for_timeout(2000)

            # Extract localStorage
            local_storage = await page.evaluate("""
                () => {
                    const items = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        items[key] = localStorage.getItem(key);
                    }
                    return items;
                }
            """)

            # Extract sessionStorage
            session_storage = await page.evaluate("""
                () => {
                    const items = {};
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        items[key] = sessionStorage.getItem(key);
                    }
                    return items;
                }
            """)

            # Analyze for sensitive data
            sensitive_patterns = {
                "token": ["token", "jwt", "access_token", "refresh_token", "auth"],
                "credentials": ["password", "secret", "key", "credential"],
                "pii": ["email", "phone", "address", "ssn", "credit"],
                "debug": ["debug", "test", "dev", "console", "trace"],
                "config": ["api_key", "apikey", "endpoint", "url", "base_url"],
            }

            findings = []

            for storage_name, storage_data in [("localStorage", local_storage), ("sessionStorage", session_storage)]:
                for key, value in storage_data.items():
                    key_lower = key.lower()
                    value_lower = str(value).lower()

                    for category, keywords in sensitive_patterns.items():
                        if any(kw in key_lower for kw in keywords):
                            findings.append({
                                "storage": storage_name,
                                "key": key,
                                "category": category,
                                "value_preview": str(value)[:100],
                                "severity": "High" if category in ["token", "credentials"] else "Medium",
                            })
                            break

            result = {
                "url": url,
                "localStorage_count": len(local_storage),
                "sessionStorage_count": len(session_storage),
                "localStorage": local_storage,
                "sessionStorage": session_storage,
                "findings": findings,
                "status": "success"
            }

            if logger:
                logger.add_log(tool_name, "SUCCESS",
                    f"Storage inspected. Local: {len(local_storage)}, Session: {len(session_storage)}, Findings: {len(findings)}")
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 12 — JavaScript Debugger & Console Interceptor
# ═══════════════════════════════════════════════════════════════════════════════

@tool("browser_js_debugger")
def browser_js_debugger(url: str) -> str:
    """
    Load halaman dan intercept all JavaScript output:
    - console.log/error/warn
    - JavaScript errors
    - Unhandled promise rejections
    - eval() calls
    - document.write calls
    - window.location changes
    Berguna for debug client-side logic dan nemuin info sensitif
    that di-expose via console.
    """
    logger = _logger()
    tool_name = "Browser JS Debugger"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        console_logs = []
        js_errors = []

        # Intercept console
        def on_console(msg):
            console_logs.append({
                "type": msg.type,
                "text": msg.text[:500],
            })

        page.on("console", on_console)

        # Intercept page errors
        def on_error(error):
            js_errors.append({
                "message": str(error)[:500],
            })

        page.on("pageerror", on_error)

        try:
            await _goto_browser_page(page, url)
            await page.wait_for_timeout(3000)

            # Check for eval() calls in page source
            eval_calls = await page.evaluate("""
                () => {
                    const script = document.createElement('script');
                    script.textContent = 'window.__evalDetected = (typeof eval === "function")';
                    document.head.appendChild(script);
                    return window.__evalDetected || false;
                }
            """)

            # Check for document.write calls
            doc_write = await page.evaluate("""
                () => {
                    const original = document.write;
                    let detected = false;
                    document.write = function() { detected = true; };
                    document.write('test');
                    document.write = original;
                    return detected;
                }
            """)

            result = {
                "url": url,
                "console_logs": console_logs[:50],
                "console_log_count": len(console_logs),
                "js_errors": js_errors[:20],
                "js_error_count": len(js_errors),
                "eval_detected": eval_calls,
                "document_write_detected": doc_write,
                "console_warnings": [l for l in console_logs if l["type"] == "warning"],
                "console_errors": [l for l in console_logs if l["type"] == "error"],
                "status": "success"
            }

            if logger:
                logger.add_log(tool_name, "SUCCESS",
                    f"JS debug: {len(console_logs)} console, {len(js_errors)} errors")
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 13 — Network Request Modifier
# ═══════════════════════════════════════════════════════════════════════════════

@tool("browser_network_modifier")
def browser_network_modifier(url: str, modify_headers: str = "") -> str:
    """
    Load halaman with modified headers. Berguna buat:
    - Test bypass via custom headers (X-Forwarded-For, X-Original-URL)
    - Inject auth tokens ke request
    - Test CORS with custom Origin
    modify_headers: JSON string {"header_name": "value", ...}
    """
    logger = _logger()
    tool_name = "Browser Network Modifier"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()

        # Parse headers
        custom_headers = {}
        if modify_headers:
            try:
                custom_headers = json.loads(modify_headers)
            except Exception:
                pass

        # Create context with extra headers
        context_args = {
            "extra_http_headers": custom_headers,
            "ignore_https_errors": _tls_errors_ignored(),
        }

        _require_browser_url(url)
        ctx = await browser.new_context(**context_args)
        await _install_browser_guard(ctx, origin=url)
        page = await ctx.new_page()
        page.set_default_timeout(15000)

        try:
            response = await _goto_browser_page(page, url)
            await page.wait_for_timeout(2000)

            title = await page.title()
            body_text = await page.evaluate("() => document.body?.innerText?.slice(0, 1000) ?? ''")

            result = {
                "url": url,
                "final_url": page.url,
                "status_code": response.status if response else 0,
                "title": title,
                "body_preview": body_text[:500],
                "headers_sent": custom_headers,
                "status": "success"
            }

            if logger:
                logger.add_log(tool_name, "SUCCESS",
                    f"Modified request: status {response.status if response else 'N/A'}")
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — Intercept network requests
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_intercept_requests(url: str) -> str:
    """
    Load halaman di browser sambil intercept SEMUA network request that created
    — termasuk XHR, fetch, WebSocket handshake, dan asset requests.
    Ini cara terbaik nemuin hidden API endpoints that cuma dipanggil pas
    JS jalan di browser, bukan from HTML source.

    Args:
        url: URL halaman that mau dimonitor request-nya
    Returns:
        JSON berisi all request that tertangkap (URL, method, headers, type)
    """
    logger = _logger()
    tool_name = "Browser Intercept Requests"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        captured = []
        request_index = {}

        async def on_request(request):
            item = {
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type,
                "headers": redact(dict(list(request.headers.items())[:20])),
                "post_data": redact((request.post_data or "")[:12000]),
            }
            captured.append(item)
            request_index.setdefault((request.url, request.method), []).append(item)

        async def on_response(response):
            key = (response.url, response.request.method)
            items = request_index.get(key) or []
            if not items:
                return
            item = items[-1]
            item["response_status"] = response.status
            item["response_headers"] = redact(dict(list(response.headers.items())[:20]))
            try:
                item["response_body"] = redact((await response.text())[:12000])
            except Exception:
                item["response_body"] = ""

        page.on("request", on_request)
        page.on("response", on_response)

        try:
            try:
                await _goto_browser_page(page, url)
            except Exception as exc:
                if not _is_download_navigation_error(exc):
                    raise
                # Preserve request/response captures for downloadable
                # resources. There is no DOM, but the network observation is
                # complete enough for this tool to succeed.
                await page.wait_for_timeout(500)
                api_requests = [r for r in captured if r["resource_type"] in {"xhr", "fetch", "websocket", "document"}]
                api_pattern = re.compile(r'/api/|/v\d+/|/graphql|/rest/|\.json|/data/', re.I)
                flagged = [r for r in captured if api_pattern.search(r["url"])]
                result = {
                    "url": url,
                    "total_requests_captured": len(captured),
                    "captures": captured[:120],
                    "xhr_and_fetch_requests": api_requests[:40],
                    "api_flagged_requests": flagged[:20],
                    "unique_domains_contacted": list(set(urlparse(r["url"]).netloc for r in captured)),
                    "download_detected": True,
                    "status": "success",
                }
                if logger:
                    logger.add_log(
                        tool_name,
                        "SUCCESS",
                        f"Captured downloadable resource request: {url}",
                    )
                return json.dumps(redact(result), indent=2)
            await page.wait_for_timeout(3000)  # Extra wait for lazy-loaded requests

            # Scroll ke bawah for trigger lazy load
            await page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(1000)

            # Filter that interesting (exclude assets statis)
            interesting_types = {"xhr", "fetch", "websocket", "document"}
            api_requests = [r for r in captured if r["resource_type"] in interesting_types]

            # Juga flag request that URL-nya API-looking
            api_pattern = re.compile(r'/api/|/v\d+/|/graphql|/rest/|\.json|/data/', re.I)
            flagged = [r for r in captured if api_pattern.search(r["url"])]

            result = {
                "url": url,
                "total_requests_captured": len(captured),
                "captures": captured[:120],
                "xhr_and_fetch_requests": api_requests[:40],
                "api_flagged_requests": flagged[:20],
                "unique_domains_contacted": list(set(
                    urlparse(r["url"]).netloc for r in captured
                )),
                "status": "success"
            }

            if logger:
                logger.add_log(
                    tool_name, "SUCCESS",
                    f"Captured {len(captured)} requests, {len(api_requests)} XHR/fetch, {len(flagged)} API-flagged"
                )
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 4 — Extract JS secrets & hidden endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_extract_js_secrets(url: str) -> str:
    """
    Download dan scan all file JavaScript from halaman target.
    Nyari: API keys that hardcoded, endpoint tersembunyi, token, config values,
    internal URL, dan credential that sering nyangkut di JS bundle.

    Args:
        url: URL halaman awal (bukan JS file langsung)
    Returns:
        JSON berisi findings per JS file
    """
    logger = _logger()
    tool_name = "Browser JS Secret Scanner"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    # Pattern for deteksi secrets & endpoints di JS
    SECRET_PATTERNS = {
        "api_key": re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
        "token": re.compile(r'(?:token|secret|password)\s*[:=]\s*["\']([A-Za-z0-9_\-]{10,})["\']', re.I),
        "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "internal_url": re.compile(r'https?://(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)[^\s"\']+'),
        "hidden_endpoint": re.compile(r'["\'](/(?:api|admin|internal|v\d+|debug|test|dev)/[^"\']+)["\']'),
        "graphql": re.compile(r'["\']([^"\']*graphql[^"\']*)["\']', re.I),
        "firebase": re.compile(r'firebaseConfig\s*=\s*\{[^}]+\}', re.I),
    }

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)

        try:
            # Ambil daftar JS files from halaman
            await _goto_browser_page(page, url)
            script_urls = await page.evaluate("""
                () => Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(s => s.startsWith('http'))
            """)

            findings = {}
            base_domain = _domain_of(url)

            for js_url in script_urls[:10]:  # Max 10 JS files biar gak lama
                if check_cancelled(logger):
                    break

                # Cuma scan JS from domain that sama (atau CDN-nya)
                js_domain = _domain_of(js_url)
                rate_limiter.wait(js_domain)

                try:
                    # ``page.request`` is an independent API request context
                    # and does not pass through the page route handler.
                    # Enforce the typed scope before fetching each script.
                    _require_browser_url(js_url)
                    js_response = await page.request.get(js_url)
                    js_content = await js_response.text()

                    file_findings = {}
                    for pattern_name, pattern in SECRET_PATTERNS.items():
                        matches = pattern.findall(js_content)
                        if matches:
                            # Redact actual values — cukup tau ada, jangan log nilainya
                            file_findings[pattern_name] = {
                                "found": True,
                                "count": len(matches),
                                "sample": "[REDACTED — ada di file JS, perlu review manual]"
                            }

                    if file_findings:
                        findings[js_url] = file_findings

                except Exception:
                    continue

            result = {
                "url": url,
                "js_files_scanned": len(script_urls[:10]),
                "js_files_with_findings": len(findings),
                "findings": findings,
                "note": "Actual value di-redact. Review file JS secara manual for konfirmasi.",
                "status": "success" if not check_cancelled(logger) else "cancelled"
            }

            if logger:
                logger.add_log(
                    tool_name, "SUCCESS" if findings else "INFO",
                    f"Scanned {len(script_urls[:10])} JS files. Findings di {len(findings)} file."
                )
            return json.dumps(result, indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 5 — Security headers analysis
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_check_security_headers(url: str) -> str:
    """
    Load halaman dan analisa security headers that ada/not ada.
    Cek: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy, CORS headers, cookies security flags.

    Args:
        url: URL target
    Returns:
        JSON berisi header analysis with severity per missing/misconfigured header
    """
    logger = _logger()
    tool_name = "Browser Security Headers"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    REQUIRED_HEADERS = {
        "content-security-policy": {
            "severity": "HIGH",
            "description": "Mencegah XSS dan injection attacks"
        },
        "strict-transport-security": {
            "severity": "HIGH",
            "description": "Enforce HTTPS, mencegah SSL stripping"
        },
        "x-frame-options": {
            "severity": "MEDIUM",
            "description": "Mencegah clickjacking via iframe"
        },
        "x-content-type-options": {
            "severity": "LOW",
            "description": "Mencegah MIME type sniffing"
        },
        "referrer-policy": {
            "severity": "LOW",
            "description": "Kontrol informasi di Referer header"
        },
        "permissions-policy": {
            "severity": "LOW",
            "description": "Restrict browser features (camera, mic, dll)"
        },
    }

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        try:
            response = await _goto_browser_page(page, url)
            headers = dict(response.headers) if response else {}

            # Analisa per header
            analysis = {}
            missing_high = []
            missing_medium = []

            for header_name, meta in REQUIRED_HEADERS.items():
                value = headers.get(header_name)
                if value:
                    analysis[header_name] = {
                        "status": "PRESENT",
                        "value": value,
                        "severity": "OK"
                    }
                else:
                    analysis[header_name] = {
                        "status": "MISSING",
                        "severity": meta["severity"],
                        "description": meta["description"]
                    }
                    if meta["severity"] == "HIGH":
                        missing_high.append(header_name)
                    elif meta["severity"] == "MEDIUM":
                        missing_medium.append(header_name)

            # Cek cookies security flags
            cookies = await page.context.cookies()
            cookie_issues = []
            for cookie in cookies:
                issues = []
                if not cookie.get("secure"):
                    issues.append("missing Secure flag")
                if not cookie.get("httpOnly"):
                    issues.append("missing HttpOnly flag")
                if not cookie.get("sameSite") or cookie.get("sameSite") == "None":
                    issues.append("SameSite=None (potential CSRF risk)")
                if issues:
                    cookie_issues.append({
                        "name": cookie["name"],
                        "issues": issues
                    })

            result = {
                "url": url,
                "headers_analysis": analysis,
                "missing_critical": missing_high,
                "missing_medium": missing_medium,
                "cookie_issues": cookie_issues,
                "overall_score": (
                    "POOR" if missing_high else
                    "FAIR" if missing_medium else
                    "GOOD"
                ),
                "status": "success"
            }

            if logger:
                logger.add_log(
                    tool_name,
                    "WARNING" if missing_high else "SUCCESS",
                    f"Headers analysis done. Missing critical: {missing_high or 'none'}"
                )
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 6 — Simulate form interaction
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_simulate_form(url: str, form_data: str) -> str:
    """
    Isi dan submit form di halaman target using headless browser.
    Berguna buat: test login form, test search input with XSS payload,
    test upload form, atau interact with form multi-step.

    CATATAN: This tool butuh HITL approval karena mengirim data ke target.

    Args:
        url: URL halaman that berisi form
        form_data: JSON string berisi {selector: value} pairs.
                   Contoh: '{"#username": "test", "#password": "test123"}'
                   Bisa juga: '{"input[name=q]": "<script>alert(1)</script>"}'
    Returns:
        JSON berisi: response URL sealready submit, title, visible text, dan
        apakah payload ter-reflect di response
    """
    logger = _logger()
    tool_name = "Browser Form Simulator"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    # HITL approval senot yet interact with form
    from core.checkpoint import require_approval
    approved = require_approval(
        action=f"Simulate form interaction di {url}",
        context=f"Form data: {form_data[:200]}",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval rejected atau timeout."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        try:
            await _goto_browser_page(page, url)
            await page.wait_for_timeout(1000)

            try:
                fields = json.loads(form_data)
            except Exception:
                return json.dumps({"error": "form_data must berupa JSON string valid"})

            # Isi tiap field
            for selector, value in fields.items():
                try:
                    await page.fill(selector, str(value))
                except Exception as e:
                    if logger:
                        logger.add_log(tool_name, "WARNING", f"Failed isi field {selector}: {e}")

            # Submit — coba beberapa cara
            submitted = False
            for submit_selector in ['button[type=submit]', 'input[type=submit]', 'button:has-text("Login")', 'button:has-text("Submit")', 'button:has-text("Search")']:
                try:
                    await page.click(submit_selector)
                    submitted = True
                    break
                except Exception:
                    continue

            if not submitted:
                # Fallback: tekan Enter di field terakhir
                try:
                    last_selector = list(fields.keys())[-1]
                    await page.press(last_selector, "Enter")
                    submitted = True
                except Exception:
                    pass

            await page.wait_for_timeout(2000)

            final_url = page.url
            title = await page.title()
            body_text = await page.evaluate("() => document.body?.innerText?.slice(0, 1000) ?? ''")

            # Cek apakah payload ter-reflect (basic XSS indicator)
            xss_reflected = any(
                str(v) in body_text
                for v in fields.values()
                if "<" in str(v) or "'" in str(v)
            )

            result = {
                "original_url": url,
                "final_url": final_url,
                "redirected": url != final_url,
                "page_title": title,
                "visible_text_preview": body_text[:500],
                "form_submitted": submitted,
                "xss_payload_reflected": xss_reflected,
                "status": "success"
            }

            if logger:
                logger.add_log(
                    tool_name,
                    "WARNING" if xss_reflected else "SUCCESS",
                    f"Form submitted. Final URL: {final_url}. XSS reflected: {xss_reflected}"
                )
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 7 — Open redirect finder
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_find_open_redirect(url: str) -> ToolResultV1:
    """
    Test all link dan parameter di halaman target for open redirect vulnerability.
    Open redirect sering valid di H1 karena can dipake for phishing dan
    bypass referrer-based access control.

    Args:
        url: URL halaman that mau dites
    Returns:
        Typed browser observations, candidate findings, case accounting, and
        diagnostics for the redirect probe.
    """
    logger = _logger()
    tool_name = "Browser Open Redirect Finder"

    if check_cancelled(logger):
        return _browser_cancelled_result(tool_name, url)

    # OOB canary domain from the configured Interactsh server. The canary is
    # only used as a destination marker; the browser never waits for it to
    # resolve or sends a request to it.
    from engines.oob_engine import oob_engine

    redirect_cid = oob_engine.generate_correlation_id("redirect")
    canary = f"{redirect_cid}.{oob_engine.domain}"
    redirect_payloads = [
        f"https://{canary}",
        f"//{canary}",
        f"https://{canary}%2F%2F",
        f"https://example.com@{canary}",
    ]
    redirect_params = [
        "next", "redirect", "redirect_to", "redirect_url", "url",
        "return", "return_url", "returnTo", "goto", "go", "target",
        "destination", "redir", "r", "u", "link", "callback",
    ]

    budget_seconds, navigation_timeout_ms, max_parameters = _bounded_redirect_budget()
    planned_parameters = redirect_params if max_parameters is None else redirect_params[:max_parameters]
    planned_cases = [
        (parameter, payload)
        for parameter in planned_parameters
        for payload in redirect_payloads
    ]
    configured_budget = _browser_workflow_setting("redirect_probe_timeout_seconds", "auto")
    budget_is_auto = configured_budget is None or str(configured_budget).strip().lower() in {
        "", "auto", "unlimited", "none", "null",
    }
    budget_source = "configured"
    if budget_is_auto and budget_seconds >= 1.0:
        # Derive the deadline from the actual workload. Dividing one global
        # deadline across all cases used to reduce 72 cases to ~1 second each
        # before the rate limiter and browser lifecycle had run.
        try:
            from core.config_loader import get_config

            safety = get_config().get("safety", {}) or {}
            requests_per_second = max(0.1, float(safety.get("requests_per_second", 2.0) or 2.0))
        except (TypeError, ValueError, AttributeError):
            requests_per_second = 2.0
        derived_minimum = (
            len(planned_cases) * (navigation_timeout_ms / 1000.0 + 1.0 / requests_per_second)
            + 15.0
        )
        budget_seconds = max(float(budget_seconds), derived_minimum)
        budget_source = "auto_from_case_workload"
    probe_timeout = max(
        0.1,
        float(budget_seconds),
    )
    deadline = time.monotonic() + probe_timeout
    page = None
    ctx = None
    interceptor = None
    case_ref = {"case": None}
    case_records = []
    observations = []
    candidates = []
    candidate_keys = set()
    errors = []
    termination_reason = "completed"

    def _typed_result(status: str, *, error_type: str = "") -> ToolResultV1:
        metrics = {
            "parameters_tested": planned_parameters,
            "payloads_used": redirect_payloads,
            "total_cases": len(planned_cases),
            "cases_planned": len(planned_cases),
            "cases_attempted": len(case_records),
            "cases_completed": len(case_records),
            "cases_remaining": max(0, len(planned_cases) - len(case_records)),
            "case_accounting": {
                "planned": len(planned_cases),
                "attempted": len(case_records),
                "completed": len(case_records),
                "remaining": max(0, len(planned_cases) - len(case_records)),
            },
            "case_results": case_records,
            "redirects_observed": sum(
                1 for item in case_records if item.get("outcome") == "redirect_observed"
            ),
            "canary_navigations_aborted": sum(
                int(item.get("canary_requests", 0)) for item in case_records
            ),
            "budget_seconds": budget_seconds,
            "budget_source": budget_source,
            "navigation_timeout_ms": navigation_timeout_ms,
            "termination_reason": termination_reason,
            "truncated": termination_reason != "completed",
            "timed_out": termination_reason in {"probe_budget_timeout", "navigation_timeout"},
            "adaptive_case_accounting": True,
            "note": "External canary navigation is intercepted and aborted after redirect observation.",
        }
        if error_type:
            metrics["error_type"] = error_type
        return ToolResultV1(
            tool_name=tool_name,
            category="recon",
            target=url,
            status=status,
            inputs_redacted={
                "url": url,
                "parameter_count": len(planned_parameters),
                "payload_count": len(redirect_payloads),
            },
            summary=(
                f"Open redirect probe {status}: {len(case_records)}/"
                f"{len(planned_cases)} cases completed; "
                f"{len(candidates)} redirect(s) observed."
            ),
            observations=observations,
            candidate_findings=candidates,
            metrics=metrics,
            errors=errors,
        )

    async def _wait_rate_limit(target_url: str) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError("redirect probe budget expired")
        await asyncio.wait_for(
            asyncio.to_thread(rate_limiter.wait, _domain_of(target_url)),
            timeout=remaining,
        )

    def _capture_request(request) -> None:
        case = case_ref.get("case")
        if case is not None:
            case.setdefault("requests", []).append(request)

    def _capture_response(response) -> None:
        case = case_ref.get("case")
        if case is not None:
            case.setdefault("responses", []).append(response)

    async def _inspect_case(case: dict, returned_response=None) -> dict:
        responses = list(case.get("responses") or [])
        if returned_response is not None and returned_response not in responses:
            responses.append(returned_response)

        for response in responses:
            response_url = str(_response_value(response, "url", "") or "")
            status_code = _response_value(response, "status", None)
            try:
                status_code = int(status_code) if status_code is not None else None
            except (TypeError, ValueError):
                status_code = None
            headers = await _response_headers(response)
            location = headers.get("location", "").strip()
            destination = urljoin(response_url or case["test_url"], location) if location else ""
            if destination and _is_external_canary_url(destination, canary):
                return {
                    "outcome": "redirect_observed",
                    "observed_via": "response_location",
                    "status_code": status_code,
                    "response_url": response_url,
                    "location": location,
                    "redirected_to": destination,
                }

            if (
                status_code is not None
                and 300 <= status_code < 400
                and _is_external_canary_url(response_url, canary)
            ):
                return {
                    "outcome": "redirect_observed",
                    "observed_via": "redirect_response",
                    "status_code": status_code,
                    "response_url": response_url,
                    "location": location,
                    "redirected_to": response_url,
                }

        # A redirect can be observable as a navigation request even when the
        # canary request is immediately aborted and Playwright raises from
        # page.goto. Require a redirect source or a document navigation; a
        # canary in the original query string alone is never evidence.
        for request in case.get("requests") or []:
            request_url = str(getattr(request, "url", "") or "")
            if not _is_external_canary_url(request_url, canary):
                continue
            redirected_from = getattr(request, "redirected_from", None)
            resource_type = str(getattr(request, "resource_type", "") or "").lower()
            if redirected_from or resource_type in {"document", "main_frame"}:
                return {
                    "outcome": "redirect_observed",
                    "observed_via": "navigation_request",
                    "status_code": None,
                    "response_url": "",
                    "location": "",
                    "redirected_to": request_url,
                }

        final_url = str(getattr(page, "url", "") or "")
        if _is_external_canary_url(final_url, canary):
            return {
                "outcome": "redirect_observed",
                "observed_via": "final_navigation_url",
                "status_code": None,
                "response_url": "",
                "location": "",
                "redirected_to": final_url,
            }

        status_code = None
        response_url = ""
        if responses:
            status_code = _response_value(responses[-1], "status", None)
            response_url = str(_response_value(responses[-1], "url", "") or "")
        return {
            "outcome": "no_redirect",
            "observed_via": "response_observation" if responses else "navigation_completed",
            "status_code": status_code,
            "response_url": response_url,
            "location": "",
            "redirected_to": "",
        }

    def _append_observation(case: dict, outcome: dict) -> ObservationV1:
        evidence = {
            "case_index": case["case_index"],
            "parameter": case["parameter"],
            "payload": case["payload"],
            "test_url": case["test_url"],
            "outcome": outcome.get("outcome"),
            "observed_via": outcome.get("observed_via"),
            "status_code": outcome.get("status_code"),
            "response_url": outcome.get("response_url", ""),
            "location": outcome.get("location", ""),
            "redirected_to": outcome.get("redirected_to", ""),
            "canary_requests_aborted": len(case.get("canary_requests") or []),
        }
        observation = ObservationV1(
            role="browser",
            kind="browser_redirect_probe",
            summary=(
                f"{case['parameter']} case: {outcome.get('outcome')} "
                f"via {outcome.get('observed_via')}."
            ),
            target_url=case["test_url"],
            method="GET",
            request_excerpt=case["test_url"],
            response_excerpt=json.dumps(evidence, ensure_ascii=False),
            status_code=outcome.get("status_code"),
            metadata=evidence,
        )
        observations.append(observation)
        return observation

    def _append_case_error(case: dict, code: str, exc: BaseException) -> None:
        errors.append(ToolErrorV1(
            code=code,
            message=str(exc)[:2000],
            retryable=True,
            details={
                "case_index": case["case_index"],
                "parameter": case["parameter"],
                "test_url": case["test_url"],
                "failure_class": "browser_redirect_case",
            },
        ))

    async def _probe():
        nonlocal page, ctx, interceptor, termination_reason
        browser = await _get_browser()
        page, ctx = await _new_page(
            browser,
            timeout_ms=navigation_timeout_ms,
            origin=url,
        )
        page.set_default_navigation_timeout(navigation_timeout_ms)
        case_ref["case"] = None
        interceptor = await _install_redirect_probe_interceptor(page, canary, case_ref)
        page.on("request", _capture_request)
        page.on("response", _capture_response)

        for case_index, (parameter, payload) in enumerate(planned_cases):
            if check_cancelled(logger):
                termination_reason = "cancelled"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError("redirect probe budget expired")

            test_url = _append_query_parameter(url, parameter, payload)
            case = {
                "case_index": case_index,
                "parameter": parameter,
                "payload": payload,
                "test_url": test_url,
                "requests": [],
                "responses": [],
                "canary_requests": [],
            }
            case_ref["case"] = case
            await _wait_rate_limit(test_url)
            case_timeout_ms = max(
                1000,
                min(
                    navigation_timeout_ms,
                    int((deadline - time.monotonic()) * 1000),
                ),
            )
            returned_response = None
            try:
                # ``commit`` observes the response without waiting for load,
                # network-idle, or an external canary navigation to finish.
                returned_response = await page.goto(
                    test_url,
                    wait_until="commit",
                    timeout=case_timeout_ms,
                )
                outcome = await _inspect_case(case, returned_response)
            except (PWTimeout, TimeoutError) as exc:
                outcome = await _inspect_case(case, returned_response)
                if outcome.get("outcome") != "redirect_observed":
                    outcome.update({
                        "outcome": "case_error",
                        "observed_via": "navigation_timeout",
                    })
                    _append_case_error(case, "browser_redirect_case_timeout", exc)
            except Exception as exc:
                outcome = await _inspect_case(case, returned_response)
                if outcome.get("outcome") != "redirect_observed":
                    outcome.update({
                        "outcome": "case_error",
                        "observed_via": "navigation_error",
                    })
                    _append_case_error(case, "browser_redirect_case_error", exc)

            observation = _append_observation(case, outcome)
            case_record = {
                "case_index": case_index,
                "parameter": parameter,
                "test_url": test_url,
                "outcome": outcome.get("outcome"),
                "observed_via": outcome.get("observed_via"),
                "status_code": outcome.get("status_code"),
                "location": outcome.get("location", ""),
                "redirected_to": outcome.get("redirected_to", ""),
                "observation_id": observation.observation_id,
                "canary_requests": len(case.get("canary_requests") or []),
            }
            case_records.append(case_record)
            if outcome.get("outcome") == "redirect_observed":
                candidate_key = (url, parameter.lower())
                if candidate_key not in candidate_keys:
                    candidate_keys.add(candidate_key)
                    candidates.append(CandidateFindingV1(
                        title="Potential Open Redirect",
                        vuln_type="open_redirect",
                        severity="MEDIUM",
                        target_url=url,
                        method="GET",
                        parameter=parameter,
                        injection_point="query",
                        status="suspected",
                        confidence_score=0.9,
                        confidence_reasons=[
                            "External canary observed in a redirect response or navigation request.",
                        ],
                        observation_ids=[observation.observation_id],
                        metadata={
                            "test_url": test_url,
                            "redirected_to": outcome.get("redirected_to", ""),
                            "observed_via": outcome.get("observed_via", ""),
                        },
                    ))

        if termination_reason == "completed" and len(case_records) != len(planned_cases):
            termination_reason = "cancelled" if check_cancelled(logger) else "probe_budget_timeout"

    async def _run():
        nonlocal termination_reason
        try:
            await asyncio.wait_for(_probe(), timeout=probe_timeout)
            if termination_reason == "cancelled":
                result = _typed_result("cancelled", error_type="browser_cancelled")
                result.errors.append(ToolErrorV1(
                    code="browser_cancelled",
                    message="Browser operation was cancelled by the active job.",
                    retryable=True,
                ))
            elif errors:
                result = _typed_result("partial", error_type=errors[0].code)
            else:
                result = _typed_result("succeeded")
            if logger:
                logger.add_log(
                    tool_name,
                    "WARNING" if result.status != "succeeded" else "SUCCESS",
                    result.summary,
                )
            return result
        except asyncio.TimeoutError as exc:
            termination_reason = "probe_budget_timeout"
            errors.append(ToolErrorV1(
                code="browser_redirect_probe_timeout",
                message=str(exc),
                retryable=True,
                details={
                    "failure_class": "browser_redirect_probe",
                    "cases_attempted": len(case_records),
                    "cases_planned": len(planned_cases),
                },
            ))
            return _typed_result("partial", error_type="browser_redirect_probe_timeout")
        except Exception as exc:
            termination_reason = "probe_failed"
            errors.append(ToolErrorV1(
                code="browser_redirect_probe_failed",
                message=str(exc)[:2000],
                retryable=_is_recoverable_navigation_error(exc),
                details={
                    "exception_type": type(exc).__name__,
                    "failure_class": "browser_redirect_probe",
                },
            ))
            if logger:
                logger.add_log(tool_name, "ERROR", str(exc))
            return _typed_result("failed", error_type="browser_redirect_probe_failed")
        finally:
            if page is not None and interceptor is not None:
                try:
                    unroute = getattr(page, "unroute", None)
                    if callable(unroute):
                        await unroute("**/*", interceptor)
                except Exception:
                    pass
            if page is not None:
                for event_name, listener in (("request", _capture_request), ("response", _capture_response)):
                    try:
                        remove_listener = getattr(page, "remove_listener", None)
                        if callable(remove_listener):
                            remove_listener(event_name, listener)
                    except Exception:
                        pass
            if ctx is not None:
                try:
                    await asyncio.wait_for(ctx.close(), timeout=3)
                except Exception:
                    pass

    return _run_async(_run(), timeout_seconds=probe_timeout + 8)

import asyncio
from urllib.parse import parse_qs, unquote, urlsplit
from pathlib import Path
from types import SimpleNamespace

from core.structured_contract import ArtifactV1, ToolResultV1


def test_browser_screenshot_has_bounded_partial_fallback():
    source = Path("tools/playwright_tools.py").read_text(encoding="utf-8")

    assert 'error_code="browser_screenshot_timeout"' in source
    assert "asyncio.wait_for(" in source
    assert "full_page=False" in source
    assert '"SUCCESS" if status == "succeeded" else "PARTIAL"' in source


class _FakeContext:
    async def close(self):
        return None


class _FakePage:
    def __init__(self, *, screenshot=None):
        self.screenshot_value = screenshot
        self.goto_calls = []
        self.url = "http://target.test/"
        self.listeners = {}
        self.route_handler = None
        self.aborted_urls = []

    def on(self, event, listener):
        self.listeners.setdefault(event, []).append(listener)

    def remove_listener(self, event, listener):
        listeners = self.listeners.get(event, [])
        if listener in listeners:
            listeners.remove(listener)

    async def route(self, _pattern, handler):
        self.route_handler = handler

    async def unroute(self, _pattern, _handler):
        self.route_handler = None

    def emit(self, event, value):
        for listener in list(self.listeners.get(event, [])):
            listener(value)

    async def goto(self, url, **kwargs):
        self.goto_calls.append((url, kwargs))

    async def wait_for_timeout(self, _ms):
        return None

    def set_default_navigation_timeout(self, _timeout_ms):
        return None

    async def title(self):
        return "Juice Shop"

    async def evaluate(self, script):
        if "meta[name" in script:
            return "Juice Shop description"
        return "Juice Shop body"

    async def screenshot(self, **_kwargs):
        if isinstance(self.screenshot_value, BaseException):
            raise self.screenshot_value
        if callable(self.screenshot_value):
            return await self.screenshot_value()
        return self.screenshot_value or b"png-bytes"


class _SlowRedirectPage(_FakePage):
    def set_default_navigation_timeout(self, _timeout_ms):
        return None

    async def goto(self, url, **kwargs):
        self.goto_calls.append((url, kwargs))
        await asyncio.sleep(2.0)
        self.url = url
        return SimpleNamespace(url=url)


class _RedirectResponse:
    def __init__(self, url, status, location=""):
        self.url = url
        self.status = status
        self._headers = {"location": location} if location else {}

    async def all_headers(self):
        return self._headers


class _RedirectRequest:
    def __init__(self, url, *, resource_type="document", redirected_from=None):
        self.url = url
        self.resource_type = resource_type
        self.redirected_from = redirected_from


class _RedirectRoute:
    def __init__(self, request, page):
        self.request = request
        self.page = page

    async def abort(self, _reason):
        self.page.aborted_urls.append(self.request.url)

    async def continue_(self):
        return None


class _RedirectPage(_FakePage):
    def __init__(self, *, redirect):
        super().__init__()
        self.redirect = redirect

    async def goto(self, url, **kwargs):
        self.goto_calls.append((url, kwargs))
        self.url = url
        request = _RedirectRequest(url)
        self.emit("request", request)

        query = parse_qs(urlsplit(url).query)
        destination = unquote(query.get("next", [""])[0])
        if self.redirect and destination.startswith(("https://", "//")):
            response = _RedirectResponse(url, 302, destination)
            self.emit("response", response)
            canary_request = _RedirectRequest(
                destination,
                resource_type="document",
                redirected_from=request,
            )
            self.emit("request", canary_request)
            if self.route_handler is not None:
                await self.route_handler(_RedirectRoute(canary_request, self))
            return response

        response = _RedirectResponse(url, 200)
        self.emit("response", response)
        return response


def _patch_browser(monkeypatch, page):
    import tools.playwright_tools as playwright_tools

    async def get_browser():
        return object()

    async def new_page(_browser, **_kwargs):
        return page, _FakeContext()

    monkeypatch.setattr(playwright_tools, "_get_browser", get_browser)
    monkeypatch.setattr(playwright_tools, "_new_page", new_page)
    monkeypatch.setattr(
        playwright_tools,
        "_browser_context",
        lambda: SimpleNamespace(
            session_id="00000000-0000-0000-0000-000000000001",
            repository=SimpleNamespace(sb=object()),
        ),
    )
    return playwright_tools


def test_browser_screenshot_persists_a_real_typed_artifact(monkeypatch):
    import core.artifact_store as artifact_store

    page = _FakePage(screenshot=b"real-png")
    playwright_tools = _patch_browser(monkeypatch, page)

    def put_bytes(_self, _session_id, data, *_args, **_kwargs):
        assert data == b"real-png"
        return ArtifactV1(
            artifact_id="art_test_screenshot",
            kind="browser_screenshot",
            mime_type="image/png",
            sha256="digest",
            size_bytes=len(data),
            storage_uri="supabase://nexus-evidence/test.png",
        )

    monkeypatch.setattr(artifact_store.ArtifactStore, "put_bytes", put_bytes)

    result = playwright_tools.browser_screenshot.func("http://target.test/")

    assert isinstance(result, ToolResultV1)
    assert result.status == "succeeded"
    assert [item.artifact_id for item in result.artifacts] == ["art_test_screenshot"]
    assert result.observations[0].artifact_ids == ["art_test_screenshot"]
    assert result.observations[0].metadata["title"] == "Juice Shop"
    assert result.observations[0].metadata["screenshot_available"] is True


def test_browser_screenshot_timeout_preserves_dom_metadata(monkeypatch):
    import tools.playwright_tools as playwright_tools

    async def slow_screenshot():
        await asyncio.sleep(2.0)
        return b"late"

    page = _FakePage(screenshot=slow_screenshot)
    _patch_browser(monkeypatch, page)
    monkeypatch.setattr(
        playwright_tools,
        "_browser_workflow_setting",
        lambda name, default: 1000 if name == "screenshot_timeout_ms" else default,
    )

    result = playwright_tools.browser_screenshot.func("http://target.test/")

    assert isinstance(result, ToolResultV1)
    assert result.status == "partial"
    assert result.errors[0].code == "browser_screenshot_timeout"
    assert result.observations[0].metadata["title"] == "Juice Shop"
    assert result.observations[0].metadata["meta_description"] == "Juice Shop description"
    assert result.observations[0].metadata["screenshot_available"] is False


def test_browser_screenshot_cancellation_is_typed(monkeypatch):
    import tools.playwright_tools as playwright_tools

    monkeypatch.setattr(playwright_tools, "check_cancelled", lambda _logger: True)

    result = playwright_tools.browser_screenshot.func("http://target.test/")

    assert isinstance(result, ToolResultV1)
    assert result.status == "cancelled"
    assert result.errors[0].code == "browser_cancelled"


def test_browser_scope_uses_exact_allowlisted_local_lab_authorization(monkeypatch):
    import tools.playwright_tools as playwright_tools

    class Kernel:
        def __init__(self):
            self.calls = []

        def require(self, *args, **kwargs):
            self.calls.append((args, kwargs))

    kernel = Kernel()
    monkeypatch.setattr(
        playwright_tools,
        "_browser_context",
        lambda: SimpleNamespace(
            session_id="session-1",
            job_id="job-1",
            attempt_id="attempt-1",
            tool_run_id="run-1",
            identity_id="anonymous",
            budget=None,
            approval_granted=True,
            authorized_lab_mode=True,
            authorized_lab_origin="http://host.docker.internal:8446",
            safety_kernel=kernel,
        ),
    )

    playwright_tools._require_browser_url("http://host.docker.internal:8446/benchmark/")

    assert kernel.calls[-1][1]["allow_private"] is True


def test_browser_route_accounts_requests_and_records_responses(monkeypatch):
    import tools.playwright_tools as playwright_tools

    class Kernel:
        def __init__(self):
            self.required = []
            self.accounted = []
            self.responses = []

        def require(self, *args, **kwargs):
            self.required.append((args, kwargs))

        def account(self, *args, **kwargs):
            self.accounted.append((args, kwargs))

        def record_response(self, *args):
            self.responses.append(args)

    class Context:
        def __init__(self):
            self.route_handler = None
            self.response_handler = None

        async def route(self, _pattern, handler):
            self.route_handler = handler

        def on(self, event, handler):
            assert event == "response"
            self.response_handler = handler

    class Request:
        url = "http://target.test/api"
        method = "POST"
        post_data = "x=123"

    class Route:
        request = Request()

        def __init__(self):
            self.continued = False

        async def continue_(self):
            self.continued = True

        async def abort(self, _reason):
            raise AssertionError("route should not be aborted")

    kernel = Kernel()
    monkeypatch.setattr(
        playwright_tools,
        "_browser_context",
        lambda: SimpleNamespace(
            session_id="session-1",
            job_id="job-1",
            attempt_id="attempt-1",
            tool_run_id="run-1",
            budget=None,
            approval_granted=True,
            authorized_lab_mode=False,
            authorized_lab_origin="",
            target_origin="http://target.test",
            safety_kernel=kernel,
        ),
    )

    context = Context()
    asyncio.run(playwright_tools._install_browser_guard(context, origin="http://target.test"))
    route = Route()
    asyncio.run(context.route_handler(route))
    context.response_handler(SimpleNamespace(url="http://target.test/api", status=200))

    assert route.continued is True
    assert kernel.accounted[-1][1]["upload_bytes"] == len("x=123")
    assert kernel.responses[-1][-1] == 200


def test_open_redirect_budget_returns_partial_instead_of_watchdog_failure(monkeypatch):
    import tools.playwright_tools as playwright_tools

    page = _SlowRedirectPage()
    _patch_browser(monkeypatch, page)
    monkeypatch.setattr(
        playwright_tools,
        "_bounded_redirect_budget",
        lambda: (0.1, 1000, 1),
    )
    monkeypatch.setattr(playwright_tools.rate_limiter, "wait", lambda _domain: None)

    raw = playwright_tools.browser_find_open_redirect.func("http://target.test/")

    # The redirect tool returns the authoritative typed contract even when its
    # public CrewAI wrapper is invoked through ``.func``.
    assert isinstance(raw, ToolResultV1)
    assert raw.status == "partial"
    assert raw.errors[0].code == "browser_redirect_probe_timeout"
    assert raw.errors[0].retryable is True
    assert "partial" in raw.summary


def test_open_redirect_observes_location_and_aborts_canary_without_waiting(monkeypatch):
    import tools.playwright_tools as playwright_tools

    page = _RedirectPage(redirect=True)
    _patch_browser(monkeypatch, page)
    monkeypatch.setattr(
        playwright_tools,
        "_bounded_redirect_budget",
        lambda: (5.0, 3000, 1),
    )
    monkeypatch.setattr(playwright_tools.rate_limiter, "wait", lambda _domain: None)

    result = playwright_tools.browser_find_open_redirect.func("http://target.test/path?existing=value")

    assert isinstance(result, ToolResultV1)
    assert result.status == "succeeded"
    assert result.metrics["total_cases"] == 4
    assert result.metrics["cases_completed"] == 4
    assert result.metrics["cases_remaining"] == 0
    assert result.metrics["redirects_observed"] == 4, result.metrics["case_results"]
    assert result.metrics["canary_navigations_aborted"] == 4
    assert len(result.candidate_findings) == 1
    assert all("next=" in call[0] and "%" in call[0] for call in page.goto_calls)
    assert len(page.aborted_urls) == 4
    assert result.metrics["budget_source"] == "auto_from_case_workload"
    assert result.metrics["budget_seconds"] > 5.0


def test_open_redirect_does_not_treat_canary_in_reflected_query_as_redirect(monkeypatch):
    import tools.playwright_tools as playwright_tools

    page = _RedirectPage(redirect=False)
    _patch_browser(monkeypatch, page)
    monkeypatch.setattr(
        playwright_tools,
        "_bounded_redirect_budget",
        lambda: (5.0, 3000, 1),
    )
    monkeypatch.setattr(playwright_tools.rate_limiter, "wait", lambda _domain: None)

    result = playwright_tools.browser_find_open_redirect.func("http://target.test/")

    assert result.status == "succeeded"
    assert result.metrics["cases_completed"] == result.metrics["total_cases"] == 4
    assert result.metrics["redirects_observed"] == 0
    assert result.candidate_findings == []
    assert page.aborted_urls == []


def test_artifact_store_uses_private_local_fallback_when_storage_rls_denies(monkeypatch, tmp_path):
    import core.artifact_store as artifact_store

    class _Storage:
        def from_(self, _bucket):
            return self

        def upload(self, *_args, **_kwargs):
            raise RuntimeError("403 row-level security policy")

    class _Supabase:
        storage = _Storage()

    monkeypatch.setattr(
        artifact_store,
        "get_config",
        lambda: {
            "artifact_storage": {
                "bucket": "nexus-evidence",
                "local_fallback_enabled": True,
                "local_root": str(tmp_path),
                "retention_days": 30,
                "signed_url_ttl_seconds": 300,
            },
            "browser_workflow": {},
        },
    )

    store = artifact_store.ArtifactStore(_Supabase())
    artifact = store.put_bytes(
        "00000000-0000-0000-0000-000000000001",
        b"real-png",
        "browser_screenshot",
        "image/png",
        "png",
    )

    assert artifact.storage_uri.startswith("local://nexus-evidence/")
    assert artifact.metadata["storage_backend"] == "local_fallback"
    relative = artifact.storage_uri.split("/", 3)[-1]
    assert (tmp_path / relative).read_bytes() == b"real-png"

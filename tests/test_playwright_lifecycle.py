import asyncio

import pytest


def test_playwright_invocation_releases_loop_bound_browser(monkeypatch):
    import tools.playwright_tools as playwright_tools

    class FakeBrowser:
        def __init__(self):
            self.closed = False

        async def close(self):
            self.closed = True

    class FakePlaywright:
        def __init__(self):
            self.stopped = False

        async def stop(self):
            self.stopped = True

    browser = FakeBrowser()
    playwright = FakePlaywright()

    async def operation():
        playwright_tools._browser = browser
        playwright_tools._playwright = playwright
        playwright_tools._browser_loop = asyncio.get_running_loop()
        return "ok"

    monkeypatch.setattr(playwright_tools, "_browser", None)
    monkeypatch.setattr(playwright_tools, "_playwright", None)
    monkeypatch.setattr(playwright_tools, "_browser_loop", None)

    assert playwright_tools._run_async(operation()) == "ok"
    assert browser.closed is True
    assert playwright.stopped is True
    assert playwright_tools._browser is None
    assert playwright_tools._playwright is None
    assert playwright_tools._browser_loop is None


def test_playwright_async_timeout_does_not_wait_for_executor_shutdown(monkeypatch):
    import tools.playwright_tools as playwright_tools

    async def slow_operation():
        await asyncio.sleep(0.2)
        return "late"

    monkeypatch.setattr(playwright_tools, "ASYNC_INVOCATION_TIMEOUT_SECONDS", 0.01)

    with pytest.raises(asyncio.TimeoutError):
        playwright_tools._run_async(slow_operation())


@pytest.mark.parametrize(
    "message, expected",
    [
        ("Page.goto: Download is starting", True),
        ("Page.goto: Timeout 30000ms exceeded", False),
        ("", False),
    ],
)
def test_download_navigation_is_distinguished_from_browser_failure(message, expected):
    import tools.playwright_tools as playwright_tools

    assert playwright_tools._is_download_navigation_error(RuntimeError(message)) is expected


@pytest.mark.parametrize(
    "message, expected",
    [
        ("Page.goto: Timeout 3000ms exceeded", True),
        ("navigation timeout", True),
        ("connection refused", False),
    ],
)
def test_navigation_timeout_is_recoverable_for_bounded_probe(message, expected):
    import tools.playwright_tools as playwright_tools

    assert playwright_tools._is_recoverable_navigation_error(RuntimeError(message)) is expected


def test_browser_navigation_uses_existing_dom_after_lifecycle_timeout():
    import tools.playwright_tools as playwright_tools

    class FakePage:
        def __init__(self):
            self.goto_calls = []

        async def goto(self, url, **kwargs):
            self.goto_calls.append((url, kwargs))
            raise playwright_tools.PWTimeout("Page.goto: Timeout 8000ms exceeded")

        async def content(self):
            return "<html><body>Juice Shop shell</body></html>"

    page = FakePage()
    result = asyncio.run(
        playwright_tools._goto_browser_page(page, "http://host.docker.internal:3001", timeout_ms=8000)
    )

    assert result is None
    assert len(page.goto_calls) == 1

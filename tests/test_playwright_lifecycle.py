import asyncio


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

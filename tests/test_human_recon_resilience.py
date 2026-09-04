import time


class _FakeContext:
    def __init__(self):
        self.pages = []

    async def close(self):
        return None


class _FakeLocator:
    async def count(self):
        return 0


class _FakePage:
    def __init__(self):
        self.goto_calls = []
        self.context = _FakeContext()
        self.url = "http://target.test/"

    def on(self, *_args):
        return None

    async def goto(self, url, **kwargs):
        self.goto_calls.append((url, kwargs))
        self.url = url

    async def wait_for_timeout(self, _ms):
        return None

    async def content(self):
        return "<html><body>target body</body></html>"

    def locator(self, _selector):
        return _FakeLocator()

    async def title(self):
        return "Target"

    async def evaluate(self, script):
        if "querySelectorAll('a[href]')" in script:
            return []
        if "querySelectorAll('form')" in script:
            return []
        if "querySelectorAll('input" in script:
            return []
        if "querySelectorAll('script" in script:
            return []
        if "querySelectorAll('button" in script:
            return []
        return "target body"


def _scope():
    return [{
        "rule_type": "allow",
        "pattern": "target.test",
        "allow_private": False,
    }]


def test_human_recon_uses_dom_ready_not_network_idle(monkeypatch):
    import core.human_recon.engine as engine_module
    import tools.playwright_tools as playwright_tools

    page = _FakePage()
    context = _FakeContext()

    async def get_browser():
        return object()

    async def new_page(_browser, **_kwargs):
        return page, context

    monkeypatch.setattr(playwright_tools, "_get_browser", get_browser)
    monkeypatch.setattr(playwright_tools, "_new_page", new_page)
    monkeypatch.setattr(engine_module, "llm_next", lambda *_args, **_kwargs: {"next_action": {"type": "done"}})

    engine = engine_module.HumanReconEngine(
        session_id="session",
        target="http://target.test/",
        goal="recon",
        scope_rules=_scope(),
        max_pages=1,
        invocation_timeout_seconds=15,
        llm_timeout_seconds=1,
    )
    result = engine.run()

    assert result["status"] == "succeeded"
    assert result["pages_visited"] == 1
    assert page.goto_calls[0][1]["wait_until"] == "commit"


def test_human_recon_falls_back_when_model_planner_times_out(monkeypatch):
    import core.human_recon.engine as engine_module
    import tools.playwright_tools as playwright_tools

    page = _FakePage()
    context = _FakeContext()

    async def get_browser():
        return object()

    async def new_page(_browser, **_kwargs):
        return page, context

    def slow_planner(*_args, **_kwargs):
        time.sleep(1.2)
        return {"next_action": {"type": "done"}}

    monkeypatch.setattr(playwright_tools, "_get_browser", get_browser)
    monkeypatch.setattr(playwright_tools, "_new_page", new_page)
    monkeypatch.setattr(engine_module, "llm_next", slow_planner)

    engine = engine_module.HumanReconEngine(
        session_id="session",
        target="http://target.test/",
        goal="recon",
        scope_rules=_scope(),
        max_pages=1,
        invocation_timeout_seconds=15,
        llm_timeout_seconds=1,
    )
    result = engine.run()

    assert result["status"] == "succeeded"
    assert result["pages_visited"] == 1
    assert result["metrics"]["llm_timeouts"] == 1
    assert any(item["type"] == "llm_timeout" for item in result["interaction_log"])


def test_human_recon_cancellation_is_typed(monkeypatch):
    import tools.human_recon_crawl as human_tool

    monkeypatch.setattr(human_tool, "check_cancelled", lambda _logger: True)

    result = human_tool.human_recon_crawl.func("http://target.test/")

    assert result.status == "cancelled"
    assert result.errors[0].code == "browser_cancelled"

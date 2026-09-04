from types import SimpleNamespace


def test_param_discovery_baseline_transport_failure_is_typed(monkeypatch):
    import tools.param_discovery as module

    class FailingSession:
        verify = True

        def get(self, *_args, **_kwargs):
            raise module.requests.exceptions.ProxyError("proxy unavailable")

    monkeypatch.setattr(module, "_logger", lambda: None)
    monkeypatch.setattr(module, "check_cancelled", lambda _logger: False)
    monkeypatch.setattr(module, "require_approval", lambda **_kwargs: True)
    monkeypatch.setattr(module, "_auth_session", lambda _url: FailingSession())
    monkeypatch.setattr(module.rate_limiter, "wait", lambda _domain: None)

    result = module.param_discovery_get.func("http://fixture.local/")

    assert result.status == "failed"
    assert result.errors[0].code == "tool_transport_error"
    assert result.errors[0].retryable is True
    assert result.metrics["baseline_request_failed"] is True
    assert "legacy_tool_failed" not in result.metrics


def test_param_discovery_direct_baseline_does_not_receive_a_none_proxy(monkeypatch):
    import tools.param_discovery as module

    calls = []

    class Session:
        verify = True

        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            response = SimpleNamespace(
                text="fixture",
                status_code=200,
            )
            return response

    monkeypatch.setattr(module, "_logger", lambda: None)
    monkeypatch.setattr(module, "check_cancelled", lambda _logger: False)
    monkeypatch.setattr(module, "require_approval", lambda **_kwargs: True)
    monkeypatch.setattr(module, "_auth_session", lambda _url: Session())
    monkeypatch.setattr(module, "_run_arjun_discovery", lambda _url, _logger: [])
    monkeypatch.setattr(module.rate_limiter, "wait", lambda _domain: None)
    monkeypatch.setattr(module.proxy_router, "get_proxy", lambda: None)

    result = module.param_discovery_get.func("http://fixture.local/")

    assert result.status == "succeeded"
    assert calls
    assert all("proxies" not in kwargs for _, kwargs in calls)

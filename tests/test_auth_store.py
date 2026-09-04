from core.auth_store import AuthSession, AuthStore
from core.identity_context import ToolExecutionContext, use_execution_context


def test_jwt_storage_state_can_be_promoted_to_auth_header_without_logging_value():
    from tools.playwright_tools import _authorization_headers_from_storage_state

    token = "a" * 16 + "." + "b" * 16 + "." + "c" * 16
    headers = _authorization_headers_from_storage_state({
        "origins": [{"origin": "http://lab.test", "localStorage": [{"name": "token", "value": token}]}],
    })

    assert headers == {"Authorization": f"Bearer {token}"}


def test_non_jwt_storage_values_are_not_promoted_to_headers():
    from tools.playwright_tools import _authorization_headers_from_storage_state

    assert _authorization_headers_from_storage_state({
        "origins": [{"localStorage": [{"name": "token", "value": "not-a-jwt"}]}],
    }) == {}


def _session(context_id: str, token: str) -> AuthSession:
    return AuthSession(
        domain="app.test",
        headers={"Authorization": f"Bearer {token}"},
        identity_id="owner",
        session_id="job-1",
        auth_context_id=context_id,
    )


def test_auth_contexts_are_stored_and_selected_independently():
    store = AuthStore()

    with use_execution_context(
        ToolExecutionContext(
            session_id="job-1",
            identity_id="owner",
            auth_context_id="ctx-owner-browser",
        )
    ):
        store.save_session("app.test", _session("ctx-owner-browser", "owner"))

    with use_execution_context(
        ToolExecutionContext(
            session_id="job-1",
            identity_id="owner",
            auth_context_id="ctx-owner-api",
        )
    ):
        store.save_session("app.test", _session("ctx-owner-api", "api"))

    browser = store.get_session(
        "app.test",
        session_id="job-1",
        identity_id="owner",
        auth_context_id="ctx-owner-browser",
    )
    api = store.get_session(
        "app.test",
        session_id="job-1",
        identity_id="owner",
        auth_context_id="ctx-owner-api",
    )

    assert browser is not None
    assert browser.headers["Authorization"] == "Bearer owner"
    assert api is not None
    assert api.headers["Authorization"] == "Bearer api"


def test_auth_context_mismatch_fails_closed_and_ambiguous_lookup_is_rejected():
    store = AuthStore()

    store.save_session(
        "app.test",
        _session("ctx-owner-browser", "owner"),
        session_id="job-1",
        identity_id="owner",
    )
    store.save_session(
        "app.test",
        _session("ctx-owner-api", "api"),
        session_id="job-1",
        identity_id="owner",
    )

    assert (
        store.get_session(
            "app.test",
            session_id="job-1",
            identity_id="owner",
            auth_context_id="ctx-other",
        )
        is None
    )
    assert (
        store.get_session(
            "app.test",
            session_id="job-1",
            identity_id="owner",
        )
        is None
    )


def test_clear_session_can_remove_one_auth_context_without_removing_siblings():
    store = AuthStore()
    store.save_session(
        "app.test",
        _session("ctx-owner-browser", "owner"),
        session_id="job-1",
        identity_id="owner",
    )
    store.save_session(
        "app.test",
        _session("ctx-owner-api", "api"),
        session_id="job-1",
        identity_id="owner",
    )

    store.clear_session(
        "app.test",
        session_id="job-1",
        identity_id="owner",
        auth_context_id="ctx-owner-browser",
    )

    assert (
        store.get_session(
            "app.test",
            session_id="job-1",
            identity_id="owner",
            auth_context_id="ctx-owner-browser",
        )
        is None
    )
    assert (
        store.get_session(
            "app.test",
            session_id="job-1",
            identity_id="owner",
            auth_context_id="ctx-owner-api",
        )
        is not None
    )


def test_request_injection_uses_the_exact_auth_context():
    store = AuthStore()
    store.save_session(
        "app.test",
        _session("ctx-owner-browser", "owner"),
        session_id="job-1",
        identity_id="owner",
    )
    store.save_session(
        "app.test",
        _session("ctx-owner-api", "api"),
        session_id="job-1",
        identity_id="owner",
    )

    kwargs = store.inject_into_kwargs(
        "app.test",
        {},
        session_id="job-1",
        identity_id="owner",
        auth_context_id="ctx-owner-api",
    )
    assert kwargs["headers"]["Authorization"] == "Bearer api"

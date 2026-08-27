from core.model_registry import build_llm


def test_local_crewai_llm_keeps_ngrok_header_out_of_request_params(monkeypatch):
    monkeypatch.setenv("NEXUS_LOCAL_LLM_ENABLED", "true")
    monkeypatch.setenv(
        "NEXUS_LOCAL_LLM_BASE_URL",
        "https://provider.example/v1",
    )
    monkeypatch.setenv("NEXUS_LOCAL_LLM_API_KEY", "test-key")
    monkeypatch.setenv("NEXUS_LOCAL_LLM_MODELS", "ravenx-cyberagent")

    llm = build_llm("local-ravenx-cyberagent")

    assert "additional_params" not in llm.additional_params
    assert llm.default_headers == {
        "ngrok-skip-browser-warning": "true",
    }


def test_raw_provider_model_id_cannot_fall_back_to_openrouter(monkeypatch):
    monkeypatch.setenv("NEXUS_LOCAL_LLM_ENABLED", "true")
    monkeypatch.setenv(
        "NEXUS_LOCAL_LLM_BASE_URL",
        "https://provider.example/v1",
    )
    monkeypatch.setenv("NEXUS_LOCAL_LLM_API_KEY", "test-key")
    monkeypatch.setenv("NEXUS_LOCAL_LLM_MODELS", "ravenx-cyberagent")
    monkeypatch.setenv("OPENROUTER_API_KEY", "should-not-be-used")

    llm = build_llm("ravenx-cyberagent")

    assert llm.model == "ravenx-cyberagent"
    assert llm.base_url == "https://provider.example/v1"

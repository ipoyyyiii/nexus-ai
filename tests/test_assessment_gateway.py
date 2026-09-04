from types import SimpleNamespace

from core import assessment_gateway


class _Dump:
    def __init__(self, payload):
        self.payload = payload

    def model_dump(self, **_kwargs):
        return dict(self.payload)


class _Repository:
    def __init__(self):
        self.saved = []

    def save_reasoning_result(self, session_id, result):
        self.saved.append((session_id, result))
        return {"reasoning_cycles": 1, "reasoning_model_calls": len(result["model_calls"])}


def test_assessment_uses_gateway_and_persists_model_call(monkeypatch):
    monkeypatch.setattr(
        assessment_gateway,
        "get_config",
        lambda: {"reasoning": {"primary_model_id": "local-dolphin3-cyber", "fallback_model_ids": []}},
    )

    response = SimpleNamespace(
        success=True,
        status="succeeded",
        model_id="local-dolphin3-cyber",
        provider="local",
        request_digest="request-digest",
        output_digest="output-digest",
        hypotheses=[_Dump({"hypothesis_id": "h-1", "session_id": "s-1", "claim": "Observed signal requires review."})],
        actions=[],
        stop=_Dump({"stop_condition_id": "stop-1", "cycle_id": "assessment-1", "kind": "operator", "triggered": True, "reason": "assessment complete", "evidence_ids": []}),
        failure=None,
        attempts=[_Dump({
            "attempt": 1,
            "model_id": "local-dolphin3-cyber",
            "provider": "local",
            "status": "succeeded",
            "latency_ms": 25,
            "output_bytes": 100,
            "output_digest": "output-digest",
            "error_type": "",
        })],
    )

    class _Gateway:
        def __init__(self, **_kwargs):
            pass

        def reason(self, **_kwargs):
            return response

    monkeypatch.setattr(assessment_gateway, "ReasoningGateway", _Gateway)
    repository = _Repository()

    result = assessment_gateway.run_gateway_assessment(
        session_id="s-1",
        job_id="j-1",
        target="http://fixture.local",
        goal="assess evidence",
        phase_results={"analis": "structured observation"},
        repository=repository,
    )

    assert result["status"] == "succeeded"
    assert result["model_calls"][0]["status"] == "succeeded"
    assert repository.saved[0][1]["cycle"]["status"] == "succeeded"
    assert repository.saved[0][1]["model_calls"][0]["job_id"] == "j-1"


def test_assessment_fails_explicitly_without_model_configuration(monkeypatch):
    monkeypatch.setattr(assessment_gateway, "get_config", lambda: {"reasoning": {}})
    monkeypatch.delenv("NEXUS_REASONING_MODEL_ID", raising=False)
    monkeypatch.delenv("NEXUS_LOCAL_LLM_MODELS", raising=False)

    result = assessment_gateway.run_gateway_assessment(
        session_id="s-1",
        job_id="j-1",
        target="http://fixture.local",
        goal="assess evidence",
        phase_results={},
        repository=_Repository(),
    )

    assert result["status"] == "failed"
    assert result["error_code"] == "assessment_model_not_configured"

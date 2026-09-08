"""Focused tests for the bounded Phase 1 reasoning gateway."""

import json
import time

from core.reasoning_gateway import (
    ReasoningGateway,
    ReasoningGatewayLimits,
    reasoning_gateway_limits,
)


class FakeResponse:
    def __init__(self, content):
        self.content = content


class FakeLLM:
    def __init__(self, response=None, error=None, provider="fake"):
        self.response = response
        self.error = error
        self.provider = provider
        self.calls = []

    def invoke(self, messages):
        self.calls.append(messages)
        if self.error:
            raise self.error
        return FakeResponse(self.response)


class StreamingLLM(FakeLLM):
    def __init__(self, chunks, provider="stream-local", base_url="http://provider.test/v1"):
        super().__init__(provider=provider)
        self.chunks = list(chunks)
        self.base_url = base_url

    def stream(self, messages):
        self.calls.append(messages)
        for chunk in self.chunks:
            yield FakeResponse(chunk)

    def invoke(self, messages):
        raise AssertionError("streaming path should not call invoke")


class StreamRejectedLLM(FakeLLM):
    def __init__(self):
        super().__init__(provider="stream-fallback")
        self.base_url = "http://provider-stream-disabled.test/v1"

    def stream(self, messages):
        self.calls.append(("stream", messages))
        raise ValueError("HTTP 400: streaming is disabled")

    def invoke(self, messages):
        self.calls.append(("invoke", messages))
        return FakeResponse(json.dumps(valid_payload()))


class SlowLLM(FakeLLM):
    def invoke(self, messages):
        self.calls.append(messages)
        time.sleep(0.2)
        return FakeResponse(json.dumps(valid_payload()))


class SequenceLLM(FakeLLM):
    def __init__(self, responses):
        super().__init__(provider="local")
        self.responses = list(responses)

    def invoke(self, messages):
        self.calls.append(messages)
        if not self.responses:
            raise RuntimeError("sequence exhausted")
        return FakeResponse(self.responses.pop(0))


def valid_payload(action_count=1):
    return {
        "hypotheses": [
            {
                "claim": "The observed search parameter may be reflected.",
                "category": "xss",
                "target_url": "http://lab.test/search",
            }
        ],
        "actions": [
            {
                "action_type": "observe",
                "tool_name": "browser_extract_surface",
                "endpoint_ref": "http://lab.test/search",
                "risk": "read_only",
                "side_effect_class": "read",
            }
            for _ in range(action_count)
        ],
        "stop": {"triggered": False, "kind": "operator", "reason": "More evidence is needed."},
    }


def make_gateway(factory, **kwargs):
    return ReasoningGateway(
        "primary-model",
        ["fallback-model"],
        llm_factory=factory,
        **kwargs,
    )


def test_valid_json_is_typed_and_request_is_structured_json_only():
    llm = FakeLLM(json.dumps(valid_payload()))
    gateway = make_gateway(lambda model_id: llm)

    result = gateway.reason(
        goal="Find reflected input issues",
        structured_context={"target": "http://lab.test", "observations": [{"status": 200}]},
        available_capabilities=[{"name": "browser_extract_surface", "side_effect_class": "read"}],
        session_id="session-1",
        cycle_id="cycle-1",
    )

    assert result.success is True
    assert result.model_id == "primary-model"
    assert result.provider == "fake"
    assert len(result.hypotheses) == 1
    assert len(result.actions) == 1
    assert result.actions[0].status == "proposed"
    assert result.actions[0].source == "model"
    assert result.actions[0].approval_digest == ""
    assert json.loads(llm.calls[0][1]["content"])["protocol"] == "nexus.reasoning.v1"
    assert "response_schema" in json.loads(llm.calls[0][1]["content"])


def test_executable_phase_prompt_requires_non_empty_linked_action():
    payload = {
        "hypotheses": [{
            "hypothesis_id": "h1",
            "claim": "The target has an observable web surface.",
        }],
        "actions": [{
            "action_type": "run_read_only",
            "tool_name": "httpx_probe",
            "hypothesis_id": "h1",
        }],
        "stop": {"triggered": False},
    }
    llm = FakeLLM(json.dumps(payload))
    result = make_gateway(lambda model_id: llm).reason(
        goal="Choose the first recon action",
        structured_context={"target": "http://lab.test"},
        available_capabilities=[{"tool_name": "httpx_probe", "risk": "read_only"}],
        mission_phase="recon",
        required_action_types=("observe", "run_read_only"),
        require_executable_action=True,
    )

    assert result.success is True
    prompt = json.loads(llm.calls[0][1]["content"])
    schema = prompt["response_schema"]
    assert schema["properties"]["hypotheses"]["minItems"] == 1
    assert schema["properties"]["actions"]["minItems"] == 1
    assert schema["properties"]["actions"]["items"]["required"] == [
        "action_type", "tool_name", "hypothesis_id",
    ]
    assert "empty hypotheses/actions is INVALID" in llm.calls[0][0]["content"]


def test_gateway_preserves_lineage_for_every_reasoning_action_type():
    action_types = (
        "observe",
        "hypothesize",
        "run_read_only",
        "propose_payload",
        "request_approval",
        "stop",
    )
    payload = {
        "hypotheses": [{
            "hypothesis_id": "model-hypothesis-1",
            "claim": "The observed endpoint may expose a testable security behavior.",
            "category": "web",
            "target_url": "http://lab.test/search",
        }],
        "actions": [
            {
                "action_id": f"model-action-{index}",
                "cycle_id": "model-supplied-cycle-must-not-win",
                "action_type": action_type,
                "tool_name": "browser_extract_surface" if action_type not in {"hypothesize", "stop"} else "",
                "endpoint_ref": "http://lab.test/search" if action_type not in {"hypothesize", "stop"} else "",
                "hypothesis_id": "model-hypothesis-1",
                "risk": "read_only",
                "side_effect_class": "read",
                "rationale": f"Bounded reasoning action: {action_type}",
            }
            for index, action_type in enumerate(action_types, start=1)
        ],
        "stop": {"triggered": False, "kind": "operator", "reason": "Continue bounded reasoning."},
    }
    llm = FakeLLM(json.dumps(payload))
    result = make_gateway(lambda model_id: llm).reason(
        goal="Exercise the complete reasoning action protocol",
        structured_context={"target": "http://lab.test"},
        available_capabilities=[{"name": "browser_extract_surface", "side_effect_class": "read"}],
        session_id="session-lineage-1",
        cycle_id="cycle-lineage-1",
    )

    assert result.success is True
    assert [item.action_type for item in result.actions] == list(action_types)
    assert result.stop.cycle_id == "cycle-lineage-1"
    assert all(item.session_id == "session-lineage-1" for item in result.hypotheses)
    assert all(item.cycle_id == "cycle-lineage-1" for item in result.hypotheses)
    assert all(item.source == "model" for item in result.hypotheses)
    assert all(item.cycle_id == "cycle-lineage-1" for item in result.actions)
    assert all(item.hypothesis_id == "model-hypothesis-1" for item in result.actions)
    assert all(item.source == "model" and item.status == "proposed" for item in result.actions)


def test_malformed_json_returns_typed_failure_without_raising():
    llm = FakeLLM("not-json")
    result = make_gateway(lambda model_id: llm).reason(
        goal="Inspect the lab",
        structured_context={},
        available_capabilities=[],
    )

    assert result.success is False
    assert result.failure is not None
    assert result.failure.code == "all_ai_providers_failed"
    assert result.failure.last_error_type == "JSONDecodeError"
    assert result.trace.attempt_count == 2


def test_gateway_accepts_common_local_model_json_wrappers():
    payload = json.dumps(valid_payload())
    wrapped_outputs = (
        f"<think>Reasoning scratchpad that must not become an action.</think>\n```json\n{payload}\n```",
        f"Here is the requested object:\n{payload}\nDone.",
    )

    for wrapped in wrapped_outputs:
        llm = FakeLLM(wrapped)
        result = make_gateway(lambda model_id, llm=llm: llm).reason(
            goal="Parse a local instruct-model response",
            structured_context={},
            available_capabilities=[],
        )

        assert result.success is True
        assert len(result.hypotheses) == 1
        assert len(result.actions) == 1


def test_gateway_still_rejects_json_array_and_schema_invalid_wrapper():
    llm = FakeLLM("prefix [1, 2, 3] suffix")
    result = make_gateway(lambda model_id: llm).reason(
        goal="Reject a non-object model response",
        structured_context={},
        available_capabilities=[],
    )

    assert result.success is False
    assert result.failure is not None
    assert result.failure.last_error_type == "JSONDecodeError"


def test_provider_error_uses_only_explicit_fallback_model():
    primary = FakeLLM(error=TimeoutError("provider down"), provider="primary-provider")
    fallback = FakeLLM(json.dumps(valid_payload()), provider="fallback-provider")
    seen = []

    def factory(model_id):
        seen.append(model_id)
        return {"primary-model": primary, "fallback-model": fallback}[model_id]

    result = make_gateway(factory).reason(
        goal="Explore the lab",
        structured_context={},
        available_capabilities=[],
    )

    assert result.success is True
    assert seen == ["primary-model", "fallback-model"]
    assert result.model_id == "fallback-model"
    assert result.attempt == 2
    assert result.trace.fallback_used is True
    assert [item.status for item in result.trace.attempts] == ["failed", "succeeded"]


def test_response_bounds_hypotheses_and_actions_and_marks_truncation():
    llm = FakeLLM(json.dumps(valid_payload(action_count=5)))
    limits = ReasoningGatewayLimits(max_hypotheses=1, max_actions=2)
    result = make_gateway(lambda model_id: llm, limits=limits).reason(
        goal="Bound the proposed work",
        structured_context={},
        available_capabilities=[],
    )

    assert result.success is True
    assert len(result.hypotheses) <= 1
    assert len(result.actions) <= 2
    assert result.trace.output_truncated is True


def test_default_gateway_does_not_silently_discard_many_actions():
    llm = FakeLLM(json.dumps(valid_payload(action_count=40)))
    result = make_gateway(lambda model_id: llm).reason(
        goal="Keep all valid model proposals",
        structured_context={},
        available_capabilities=[],
    )

    assert result.success is True
    assert len(result.actions) == 40
    assert result.trace.output_truncated is False


def test_default_gateway_does_not_silently_discard_many_hypotheses():
    payload = valid_payload(action_count=0)
    payload["hypotheses"] = [
        {"claim": f"inspect signal {index}"}
        for index in range(40)
    ]
    llm = FakeLLM(json.dumps(payload))
    result = make_gateway(lambda model_id: llm).reason(
        goal="Keep all valid model hypotheses",
        structured_context={},
        available_capabilities=[],
    )

    assert result.success is True
    assert len(result.hypotheses) == 40
    assert result.trace.output_truncated is False


def test_gateway_limits_are_config_driven_and_separate_from_execution_budget():
    limits = reasoning_gateway_limits({
        "max_model_actions": 20,
        "context_max_chars": 12000,
        "model_output_max_chars": 18000,
    })

    assert limits.max_actions == 20
    assert limits.max_context_chars == 12000
    assert limits.max_response_bytes == 72000
    assert limits.invoke_timeout_seconds == 600
    assert reasoning_gateway_limits({}).max_actions is None


def test_production_factory_receives_gateway_timeout(monkeypatch):
    import core.model_registry as model_registry

    seen = {}

    def fake_build_chat_llm(model_id, *, timeout_seconds=None):
        seen["model_id"] = model_id
        seen["timeout_seconds"] = timeout_seconds
        return FakeLLM(json.dumps(valid_payload()), provider="local")

    monkeypatch.setattr(model_registry, "build_chat_llm", fake_build_chat_llm)

    gateway = ReasoningGateway(
        "local-dolphin3-cyber",
        fallback_model_ids=[],
        limits=ReasoningGatewayLimits(invoke_timeout_seconds=17.0),
    )
    result = gateway.reason(
        goal="Verify production timeout propagation",
        structured_context={},
        available_capabilities=[],
    )

    assert result.success is True
    assert seen == {
        "model_id": "local-dolphin3-cyber",
        "timeout_seconds": 17.0,
    }


def test_gateway_records_timeout_and_tries_the_explicit_fallback():
    primary = SlowLLM()
    fallback = FakeLLM(json.dumps(valid_payload()), provider="fallback")
    gateway = make_gateway(
        lambda model_id: primary if model_id == "primary-model" else fallback,
        limits=ReasoningGatewayLimits(
            invoke_timeout_seconds=0.1,
            provider_retry_attempts=0,
        ),
    )

    result = gateway.reason(goal="bounded timeout", structured_context={}, available_capabilities=[])

    assert result.success is True
    assert result.model_id == "fallback-model"
    assert [item.status for item in result.trace.attempts] == ["failed", "succeeded"]
    assert result.trace.attempts[0].error_type == "TimeoutError"
    # The watchdog cannot kill the fake's background thread. Wait for its
    # explicit completion before the next test reuses the provider key.
    time.sleep(0.25)


def test_gateway_retries_transient_provider_timeout_before_fallback():
    class FlakyLLM(FakeLLM):
        def __init__(self):
            super().__init__(provider="local")
            self.invocation_count = 0

        def invoke(self, messages):
            self.calls.append(messages)
            self.invocation_count += 1
            if self.invocation_count == 1:
                raise TimeoutError("temporary provider timeout")
            return FakeResponse(json.dumps(valid_payload()))

    flaky = FlakyLLM()
    result = ReasoningGateway(
        "primary-model",
        ["fallback-model"],
        llm_factory=lambda model_id: flaky,
        limits=ReasoningGatewayLimits(
            provider_retry_attempts=1,
            provider_retry_backoff_seconds=0,
            retry_on_timeout=True,
        ),
    ).reason(goal="retry transient transport", structured_context={}, available_capabilities=[])

    assert result.success is True
    assert result.model_id == "primary-model"
    assert flaky.invocation_count == 2
    assert [item.status for item in result.attempts] == ["failed", "succeeded"]
    assert [item.retry_index for item in result.attempts] == [0, 1]
    assert all(item.fallback_index == 0 for item in result.attempts)
    assert result.trace.fallback_used is False


def test_gateway_does_not_retry_protocol_errors():
    llm = FakeLLM("not-json")
    result = ReasoningGateway(
        "primary-model",
        [],
        llm_factory=lambda model_id: llm,
        limits=ReasoningGatewayLimits(
            provider_retry_attempts=3,
            provider_retry_backoff_seconds=0,
        ),
    ).reason(goal="do not retry malformed output", structured_context={}, available_capabilities=[])

    assert result.success is False
    assert len(llm.calls) == 1
    assert len(result.attempts) == 1


def test_response_byte_bound_is_fail_closed():
    llm = FakeLLM(json.dumps(valid_payload()))
    limits = ReasoningGatewayLimits(max_response_bytes=8)
    result = make_gateway(lambda model_id: llm, limits=limits).reason(
        goal="Reject an oversized model response",
        structured_context={},
        available_capabilities=[],
    )

    assert result.success is False
    assert result.failure is not None
    assert result.failure.last_error_type == "_GatewayProtocolError"
    assert all(item.output_bytes > limits.max_response_bytes for item in result.trace.attempts)


def test_stop_with_actions_is_rejected_instead_of_being_ambiguous():
    payload = valid_payload()
    payload["stop"]["triggered"] = True
    llm = FakeLLM(json.dumps(payload))

    result = make_gateway(lambda model_id: llm).reason(
        goal="Stop cleanly",
        structured_context={},
        available_capabilities=[],
    )

    assert result.success is False
    assert result.failure is not None
    assert result.failure.last_error_type == "_GatewayProtocolError"
    assert result.trace.attempt_count == 2


def test_structured_context_has_an_explicit_total_size_bound():
    llm = FakeLLM(json.dumps(valid_payload()))
    limits = ReasoningGatewayLimits(max_context_chars=32)
    gateway = make_gateway(lambda model_id: llm, limits=limits)
    result = gateway.reason(
        goal="Keep context bounded",
        structured_context={"observations": ["x" * 1000]},
        available_capabilities=[],
    )

    assert result.success is True
    prompt = json.loads(llm.calls[0][1]["content"])
    assert prompt["structured_context"]["_context_manifest"]["compacted"] is True
    assert len(json.dumps(prompt["structured_context"])) < 256


def test_trace_contains_digests_only_and_never_raw_secret_or_response():
    secret = "super-secret-token-value"
    raw_response = json.dumps({
        "hypotheses": [{"claim": "inspect", "metadata": {"token": secret}}],
        "actions": [{"action_type": "observe", "tool_name": "surface", "input_bindings": {"token": secret}}],
        "stop": False,
    })
    llm = FakeLLM(raw_response)
    result = make_gateway(lambda model_id: llm).reason(
        goal="Use this secret only as redaction test",
        structured_context={"api_key": secret, "headers": {"Authorization": f"Bearer {secret}"}},
        available_capabilities=[{"name": "surface", "token": secret}],
    )

    trace_json = result.trace.model_dump_json()
    assert secret not in trace_json
    assert raw_response not in trace_json
    assert result.trace.request_digest
    assert result.trace.response_digest
    prompt_json = llm.calls[0][1]["content"]
    assert secret not in prompt_json


def test_phase_contract_repairs_model_action_semantics_with_ai_only_retry():
    bad = {
        "hypotheses": [{
            "hypothesis_id": "h-recon-1",
            "claim": "The target may expose a browser surface.",
            "target_url": "http://lab.test",
        }],
        "actions": [{
            "action_type": "hypothesize",
            "tool_name": "",
            "hypothesis_id": "",
            "metadata": {"tool_name": "browser_extract_surface"},
        }],
        "stop": {"triggered": False, "kind": "operator"},
    }
    good = {
        "hypotheses": [{
            "hypothesis_id": "h-recon-1",
            "claim": "The target may expose a browser surface.",
            "target_url": "http://lab.test",
        }],
        "actions": [{
            "action_type": "run_read_only",
            "tool_name": "browser_extract_surface",
            "endpoint_ref": "http://lab.test",
            "hypothesis_id": "h-recon-1",
            "risk": "read_only",
            "side_effect_class": "read",
        }],
        "stop": {"triggered": False, "kind": "operator"},
    }
    llm = SequenceLLM([json.dumps(bad), json.dumps(good)])
    result = ReasoningGateway(
        "primary-model",
        [],
        llm_factory=lambda model_id: llm,
        limits=ReasoningGatewayLimits(
            semantic_retry_attempts=1,
            provider_retry_attempts=0,
        ),
    ).reason(
        goal="Map the target surface",
        structured_context={"target": "http://lab.test"},
        available_capabilities=[{"tool_name": "browser_extract_surface"}],
        mission_phase="recon",
        required_action_types=("observe", "run_read_only"),
        require_executable_action=True,
    )

    assert result.success is True
    assert result.actions[0].tool_name == "browser_extract_surface"
    assert result.actions[0].hypothesis_id == "h-recon-1"
    assert len(llm.calls) == 2
    assert [item.status for item in result.attempts] == ["failed", "succeeded"]
    assert "Semantic protocol correction" in llm.calls[1][-1]["content"]


def test_gateway_rejects_provider_invented_evidence_references():
    payload = valid_payload()
    payload["hypotheses"][0]["supporting_evidence_ids"] = ["evidence-not-in-context"]
    llm = FakeLLM(json.dumps(payload))
    result = ReasoningGateway(
        "primary-model",
        [],
        llm_factory=lambda model_id: llm,
        limits=ReasoningGatewayLimits(provider_retry_attempts=0),
    ).reason(
        goal="Reject invented evidence",
        structured_context={"observations": [{"observation_id": "obs-real"}]},
        available_capabilities=[],
    )

    assert result.success is False
    assert result.failure is not None
    assert result.failure.last_error_type == "_GatewayProtocolError"
    assert len(llm.calls) == 1


def test_adaptive_deadline_is_phase_and_prompt_aware():
    limits = ReasoningGatewayLimits(
        timeout_mode="adaptive",
        invoke_timeout_seconds=600,
        max_invoke_timeout_seconds=1800,
        phase_timeout_seconds={"vulnerability_analysis": 900},
        prompt_kib_timeout_seconds=2,
    )

    assert limits.timeout_for("vulnerability_analysis", 8 * 1024) == 900
    assert limits.timeout_for("vulnerability_analysis", 18 * 1024) == 920
    assert limits.timeout_for("unknown", 0) == 600


def test_streaming_progress_is_recorded_and_preserves_token_whitespace():
    payload = json.dumps(valid_payload())
    llm = StreamingLLM([payload[:40], payload[40:]])
    events = []
    result = ReasoningGateway(
        "stream-model",
        [],
        llm_factory=lambda _model_id: llm,
        limits=ReasoningGatewayLimits(stream_progress_mode="auto"),
    ).reason(
        goal="Use streaming progress",
        structured_context={},
        available_capabilities=[],
        mission_phase="recon",
        progress_callback=events.append,
    )

    assert result.success is True
    attempt = result.attempts[0]
    assert attempt.transport_mode == "stream"
    assert attempt.progress_events == 2
    assert any(item.get("status") == "progress" for item in events)


def test_streaming_rejection_falls_back_once_to_sync_without_retrying_the_model():
    llm = StreamRejectedLLM()
    result = ReasoningGateway(
        "stream-disabled-model",
        [],
        llm_factory=lambda _model_id: llm,
        limits=ReasoningGatewayLimits(stream_progress_mode="auto"),
    ).reason(
        goal="Use provider sync fallback",
        structured_context={},
        available_capabilities=[],
    )

    assert result.success is True
    assert result.attempts[0].transport_mode == "stream_to_sync"
    assert [kind for kind, _ in llm.calls] == ["stream", "invoke"]


def test_context_compaction_keeps_recent_evidence_rows_and_manifest():
    llm = FakeLLM(json.dumps(valid_payload()))
    gateway = make_gateway(
        lambda _model_id: llm,
        limits=ReasoningGatewayLimits(max_context_chars=1_200),
    )
    result = gateway.reason(
        goal="Preserve evidence while compacting",
        structured_context={
            "target": "http://lab.test",
            "observations": [
                {"observation_id": f"obs-{index}", "summary": "x" * 500}
                for index in range(12)
            ],
            "candidates": [{"candidate_id": "candidate-1", "observation_ids": ["obs-11"]}],
        },
        available_capabilities=[],
    )

    assert result.success is True
    context = json.loads(llm.calls[0][1]["content"])["structured_context"]
    assert context["_context_manifest"]["compacted"] is True
    assert context["observations"]
    assert context["observations"][-1]["observation_id"] == "obs-11"

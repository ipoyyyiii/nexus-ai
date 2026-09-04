from types import SimpleNamespace
import json

import core.interactive_flow as flow


def test_autopilot_skips_interactive_phase_and_proceeds_to_assessor(monkeypatch):
    updates = []
    saved = []

    monkeypatch.setattr(
        flow,
        "get_execution_context",
        lambda: SimpleNamespace(auto_pilot=True),
        raising=False,
    )

    class _Cancellation:
        def is_cancelled(self, _job_id):
            return False

    def save_message(*args):
        saved.append(args)

    result = flow.run_phase2_interactive(
        "job-1",
        "session-1",
        "http://fixture.local",
        True,
        _Cancellation(),
        object(),
        lambda job_id, **kwargs: updates.append((job_id, kwargs)),
        save_message,
        {},
    )

    assert result is True
    assert saved == []
    assert updates == [
        (
            "job-1",
            {
                "status": "running",
                "message": "Phase 2 skipped. Auto-Pilot: proceeding to final assessment.",
            },
        )
    ]


def test_strict_recon_uses_ai_lane_selection_with_bounded_followups(monkeypatch):
    calls = []

    monkeypatch.setattr(
        "core.config_loader.get_config",
        lambda: {"reasoning_mode": "strict", "reasoning": {"fallback_model_ids": []}},
    )

    class FakeGateway:
        def __init__(self, **kwargs):
            calls.append(("gateway_init", kwargs))

        def reason(self, **kwargs):
            calls.append(("reason", kwargs))
            return {
                "status": "succeeded",
                "cycle_id": "ai-recon-cycle",
                "model_id": "local-recon-model",
                "provider": "local",
                "hypotheses": [],
                "actions": [{
                    "action_type": "observe",
                    "tool_name": "browser_extract_surface",
                    "endpoint_ref": "http://fixture.local",
                    "side_effect_class": "read",
                    "rationale": "Inspect the browser surface discovered at the target.",
                }],
                "stop": {"triggered": False, "kind": "operator"},
            }

    class FakeMission:
        def __init__(self, **kwargs):
            pass

        def execute(self, target, session_id, **kwargs):
            calls.append(("mission", target, session_id, kwargs))
            return {"status": "succeeded", "plan": [], "counts": {}, "execution": {}}

    monkeypatch.setattr("core.reasoning_gateway.ReasoningGateway", FakeGateway)
    monkeypatch.setattr("core.recon_orchestrator.ReconOrchestrator", FakeMission)
    monkeypatch.setattr("api.session_store", object(), raising=False)
    monkeypatch.setattr("api.structured_repository", object(), raising=False)

    result = flow._run_approved_recon_action(
        action_tools=["__recon_mission__"],
        target="http://fixture.local",
        goal="map the browser surface",
        session_id="session-recon",
        job_id="job-recon",
        reasoning_model_id="local-recon-model",
    )
    payload = json.loads(result)

    assert payload["reasoning"]["planner_source"] == "model"
    assert payload["reasoning"]["selected_tools"] == ["browser_extract_surface"]
    mission_call = next(item for item in calls if item[0] == "mission")
    assert mission_call[3]["selected_tools"] == ["browser_extract_surface"]
    assert mission_call[3]["adaptive_selection"] is True

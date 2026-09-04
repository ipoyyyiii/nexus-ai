import os

from core.authorization_contract import (
    AuthorizationExpectationV1,
    IdentityV1,
    RequestTemplateV1,
    ResourceInstanceV1,
)
from core.authorization_engine import AuthorizationReplayEngine, ResponseSnapshot, compare_responses
from core.authorization_discovery import capture_to_contracts
from core.secret_vault import SecretVault
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1
from core.validation_engine import ValidationEngine
from core.detection_validation_v2 import validation_engine_v2


def test_semantic_comparator_does_not_use_status_or_length_alone():
    baseline = ResponseSnapshot(200, "https://lab.test/item/1", {}, '{"id":1,"owner":"a"}', 10)
    same_body = ResponseSnapshot(200, "https://lab.test/item/1", {}, '{"id":1,"owner":"a"}', 11)
    denied = ResponseSnapshot(200, "https://lab.test/item/1", {}, '{"error":"access denied"}', 11)
    assert compare_responses(baseline, same_body)["resource_semantically_present"] is True
    assert compare_responses(baseline, denied)["resource_semantically_present"] is False


def test_authorization_policy_requires_isolated_identity_and_reproduction():
    result = ToolResultV1(
        tool_name="authorization_replay",
        target="https://lab.test/item/1",
        observations=[
            ObservationV1(role="baseline", metadata={"identity_id": "owner"}),
            ObservationV1(role="test", metadata={"identity_id": "other", "comparison": {"resource_semantically_present": True}}),
        ],
        candidate_findings=[CandidateFindingV1(
            title="BOLA candidate", vuln_type="BOLA/IDOR",
            metadata={"expectation_ids": ["expect_1"]},
        )],
    )
    decision = ValidationEngine().validate(result)[0]
    assert decision.decision == "inconclusive"
    assert any(check["name"] == "reproduction_present" and not check["passed"] for check in decision.checks)


def test_authorization_policy_validates_reproduced_private_access():
    result = ToolResultV1(
        tool_name="authorization_replay",
        target="https://lab.test/item/1",
        observations=[
            ObservationV1(role="baseline", metadata={"identity_id": "owner"}),
            ObservationV1(role="test", metadata={"identity_id": "other", "comparison": {"resource_semantically_present": True}}),
            ObservationV1(role="reproduction", metadata={"identity_id": "other", "comparison": {"resource_semantically_present": True}}),
        ],
        candidate_findings=[CandidateFindingV1(
            title="BOLA candidate", vuln_type="BOLA/IDOR",
            metadata={"expectation_ids": ["expect_1"]},
        )],
    )
    decision = ValidationEngine(authorization_graph_mode="strict").validate(result)[0]
    assert decision.decision == "validated"


def test_vault_round_trip_never_exposes_plaintext_metadata(monkeypatch):
    monkeypatch.setenv("NEXUS_AUTH_VAULT_KEY", "test-development-key")
    vault = SecretVault()
    metadata = vault.put("session-1", "identity-1", "auth", {"cookies": {"session": "secret-value"}})
    assert "secret-value" not in str(metadata)
    assert vault.get(metadata["secret_ref"], "session-1", "identity-1")["cookies"]["session"] == "secret-value"


def test_dynamic_contracts_do_not_require_target_specific_names():
    identity = IdentityV1(label="tenant-x", role_label="custom-role")
    template = RequestTemplateV1(session_id="s", origin="https://random.example", path_template="/v9/object/{resource_id}")
    resource = ResourceInstanceV1(session_id="s", resource_type="opaque-object", origin="https://random.example", locator_redacted="opaque-abc", owner_identity_id=identity.identity_id)
    assert identity.label == "tenant-x"
    assert template.ensure_fingerprint().fingerprint
    assert resource.ensure_fingerprint().fingerprint


def test_runtime_discovery_extracts_random_path_and_response_resources():
    templates, resources = capture_to_contracts([
        {
            "url": "https://random.example/v9/records/7f2d9a1e-3b2c-4d5e-8f90-123456789abc",
            "method": "GET",
            "headers": {"Authorization": "Bearer secret"},
            "response_body": '{"id":"7f2d9a1e-3b2c-4d5e-8f90-123456789abc","owner_id":"user-a"}',
        }
    ], "s", "identity-a")
    assert templates[0].path_template == "/v9/records/{resource_id}"
    assert any(item.resource_type == "owner" for item in resources)
    assert all("secret" not in str(item.model_dump()) for item in templates)


def test_differential_replay_keeps_auth_contexts_isolated():
    class SpyReplay(AuthorizationReplayEngine):
        def __init__(self):
            super().__init__(target="https://random.example")
            self.contexts = []

        def _request(self, template, identity_id, session_id, bindings, approved, auth_context_id=""):
            self.contexts.append((identity_id, auth_context_id))
            body = '{"id":"opaque"}' if identity_id == "owner" else '{"error":"forbidden"}'
            return ResponseSnapshot(200, "https://random.example/item/opaque", {}, body, 1)

    template = RequestTemplateV1(
        session_id="s", origin="https://random.example", path_template="/item/{resource_id}",
        side_effect_class="read",
    )
    resource = ResourceInstanceV1(
        session_id="s", resource_type="item", origin="https://random.example",
        locator_redacted="opaque", owner_identity_id="owner",
    ).ensure_fingerprint()
    replay = SpyReplay()
    result = replay.run_differential(
        "s", template, resource, "owner", ["other"], [],
        auth_contexts={"owner": "ctx-owner", "other": "ctx-other"},
    )
    assert result.status == "succeeded"
    assert replay.contexts == [("owner", "ctx-owner"), ("other", "ctx-other")]
    assert result.observations[0].metadata["auth_context_id"] == "ctx-owner"
    assert result.observations[1].metadata["auth_context_id"] == "ctx-other"


def test_differential_replay_requires_and_records_an_explicit_negative_control():
    class ControlAwareReplay(AuthorizationReplayEngine):
        def _request(self, template, identity_id, session_id, bindings, approved, auth_context_id=""):
            if identity_id == "owner":
                body = '{"id":"opaque","owner":"owner"}'
            elif identity_id == "other":
                body = '{"id":"opaque","owner":"owner"}'
            else:
                body = '{"error":"forbidden"}'
            return ResponseSnapshot(200, "https://random.example/item/opaque", {}, body, 1)

    template = RequestTemplateV1(
        session_id="s", origin="https://random.example", path_template="/item/{resource_id}",
        side_effect_class="read",
    )
    resource = ResourceInstanceV1(
        session_id="s", resource_type="item", origin="https://random.example",
        locator_redacted="opaque", owner_identity_id="owner",
    ).ensure_fingerprint()
    expectations = [
        AuthorizationExpectationV1(
            session_id="s", subject_identity_id="other", action="GET",
            resource_fingerprint=resource.fingerprint, expected="deny",
        ),
        AuthorizationExpectationV1(
            session_id="s", subject_identity_id="control", action="GET",
            resource_fingerprint=resource.fingerprint, expected="deny",
        ),
    ]
    result = ControlAwareReplay().run_differential(
        "s", template, resource, "owner", ["other", "control"], expectations,
        auth_contexts={"owner": "ctx-owner", "other": "ctx-other", "control": "ctx-control"},
        negative_control_identity_id="control",
    )

    assert result.status == "succeeded"
    assert [item.role for item in result.observations] == [
        "baseline", "test", "reproduction", "negative_control",
    ]
    candidate = result.candidate_findings[0]
    assert candidate.metadata["negative_control_identity_id"] == "control"
    assert candidate.metadata["deny_expectation"] is True
    decision = validation_engine_v2.validate(result, mode="strict", apply_status=True)[0]
    assert decision.decision == "validated"


def test_differential_replay_rejects_a_control_without_an_explicit_deny_expectation():
    template = RequestTemplateV1(
        session_id="s", origin="https://random.example", path_template="/item/{resource_id}",
        side_effect_class="read",
    )
    resource = ResourceInstanceV1(
        session_id="s", resource_type="item", origin="https://random.example",
        locator_redacted="opaque", owner_identity_id="owner",
    ).ensure_fingerprint()
    result = AuthorizationReplayEngine(target=template.origin).run_differential(
        "s", template, resource, "owner", ["control"], [],
        auth_contexts={"owner": "ctx-owner", "control": "ctx-control"},
        negative_control_identity_id="control",
    )
    assert result.status == "failed"
    assert result.errors[0].code == "missing_negative_control_expectation"

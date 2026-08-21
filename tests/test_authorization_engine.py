import os

from core.authorization_contract import (
    AuthorizationExpectationV1,
    IdentityV1,
    RequestTemplateV1,
    ResourceInstanceV1,
)
from core.authorization_engine import ResponseSnapshot, compare_responses
from core.authorization_discovery import capture_to_contracts
from core.secret_vault import SecretVault
from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1
from core.validation_engine import ValidationEngine


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

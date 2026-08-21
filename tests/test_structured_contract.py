import json

from core.structured_contract import (
    CandidateFindingV1,
    ObservationV1,
    ToolResultV1,
    make_fingerprint,
    result_from_legacy,
)
from core.validation_engine import ValidationEngine


def test_contract_redacts_secrets_and_creates_stable_fingerprint():
    result = ToolResultV1(
        tool_name="test_tool",
        target="https://example.test/search",
        summary='Authorization: Bearer abcdefghijklmnopqrstuvwxyz',
        observations=[ObservationV1(response_excerpt='Cookie: session=secretvalue')],
        candidate_findings=[CandidateFindingV1(title="SQL error", vuln_type="SQL Injection", target_url="https://example.test/search", parameter="q")],
    )
    assert "secretvalue" not in result.observations[0].response_excerpt
    assert "abcdefghijklmnopqrstuvwxyz" not in result.summary
    assert result.candidate_findings[0].fingerprint == make_fingerprint("SQL Injection", "https://example.test/search", "GET", "q", "")


def test_legacy_text_is_observation_only():
    result = result_from_legacy("legacy", "https://example.test", "[HIGH] SQL Injection suspected")
    assert result.legacy_source is True
    assert result.candidate_findings == []
    assert result.observations[0].kind == "legacy_output"


def test_legacy_json_becomes_candidate_but_not_validated():
    result = result_from_legacy("scanner", "https://example.test", json.dumps({"findings": [{"title": "SQL error", "type": "SQL Injection", "severity": "HIGH"}]}))
    assert len(result.candidate_findings) == 1
    assert result.candidate_findings[0].status == "suspected"


def test_error_policy_requires_controls_and_reproduction():
    result = ToolResultV1(
        tool_name="sqli",
        target="https://example.test/item",
        observations=[
            ObservationV1(role="baseline", response_excerpt="normal response"),
            ObservationV1(role="test", response_excerpt="You have an error in your SQL syntax"),
            ObservationV1(role="reproduction", response_excerpt="SQLSTATE[42000] syntax error"),
            ObservationV1(role="negative_control", response_excerpt="normal response"),
        ],
        candidate_findings=[CandidateFindingV1(title="SQL error", vuln_type="SQL Injection", target_url="https://example.test/item")],
    )
    decisions = ValidationEngine().validate(result)
    assert decisions[0].decision == "validated"
    assert result.candidate_findings[0].status == "validated"


def test_xss_reflection_without_browser_execution_stays_inconclusive():
    result = ToolResultV1(
        tool_name="xss",
        target="https://example.test/search",
        observations=[ObservationV1(role="test", response_excerpt="<script>marker</script>")],
        candidate_findings=[CandidateFindingV1(title="Reflected XSS", vuln_type="XSS", target_url="https://example.test/search")],
    )
    decisions = ValidationEngine().validate(result)
    assert decisions[0].decision == "inconclusive"
    assert result.candidate_findings[0].status == "inconclusive"

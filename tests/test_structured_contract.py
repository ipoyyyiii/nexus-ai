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


def test_explicit_legacy_count_block_becomes_unvalidated_candidates():
    result = result_from_legacy(
        "cors_tester",
        "http://fixture.local",
        "[🟡 MEDIUM] 2 finding(s)\n"
        "  ▸ Arbitrary Origin\n"
        "    Detail         : origin reflected\n"
        "  ▸ Null Origin\n"
        "    Detail         : null accepted\n",
    )

    assert len(result.candidate_findings) == 2
    assert all(item.status == "suspected" for item in result.candidate_findings)
    assert all(item.metadata["legacy_text_heuristic"] for item in result.candidate_findings)
    assert all(item.metadata["validation_required"] for item in result.candidate_findings)


def test_access_control_bucket_without_repeated_type_is_preserved_as_candidate():
    result = result_from_legacy(
        "access_control_scanner",
        "http://fixture.local",
        json.dumps({
            "findings": {
                "forced_browsing": [{
                    "url": "http://fixture.local/api/admin",
                    "status": 200,
                    "size": 512,
                    "severity": "High",
                }],
            },
        }),
    )

    assert len(result.candidate_findings) == 1
    candidate = result.candidate_findings[0]
    assert candidate.vuln_type == "Broken Access Control"
    assert candidate.status == "suspected"
    assert candidate.metadata["synthetic_finding_type"] is True


def test_legacy_summary_records_are_ingested_without_validation_promotion():
    result = result_from_legacy(
        "Session Management Scanner",
        "http://fixture.local",
        json.dumps({
            "summary": [{
                "type": "Missing Security Header: CSP",
                "detail": "Header 'CSP' missing",
                "severity": "Medium",
            }],
        }),
    )

    assert len(result.candidate_findings) == 1
    assert result.candidate_findings[0].status == "suspected"
    assert result.candidate_findings[0].metadata["subtype"] == "missing_security_header"


def test_legacy_json_becomes_candidate_but_not_validated():
    result = result_from_legacy("scanner", "https://example.test", json.dumps({"findings": [{"title": "SQL error", "type": "SQL Injection", "severity": "HIGH"}]}))
    assert len(result.candidate_findings) == 1
    assert result.candidate_findings[0].status == "suspected"


def test_legacy_nested_and_bucketed_findings_are_preserved_as_candidates():
    result = result_from_legacy(
        "misconfiguration_scanner",
        "http://fixture.local/login",
        json.dumps({
            "critical": [{"type": ".env File Exposed", "url": "http://fixture.local/.env", "severity": "Critical"}],
            "medium": [{"type": "Missing Security Header: CSP", "severity": "Medium"}],
        }),
    )
    assert {item.vuln_type for item in result.candidate_findings} == {
        ".env File Exposed",
        "Missing Security Header: CSP",
    }
    assert all(item.observation_ids for item in result.candidate_findings)
    assert all(item.status == "suspected" for item in result.candidate_findings)
    assert result.candidate_findings[0].metadata["legacy_bucket"] in {"critical", "medium"}
    assert all(item.metadata.get("finding_type") for item in result.candidate_findings)
    assert all(item.metadata.get("subtype") == "missing_security_header" or item.vuln_type == ".env File Exposed" for item in result.candidate_findings)
    assert len(result.observations) == 3
    assert sum(item.kind == "legacy_finding" for item in result.observations) == 2


def test_legacy_nested_vulnerabilities_are_deduplicated_by_fingerprint():
    result = result_from_legacy(
        "client_side_security_scanner",
        "http://fixture.local/",
        json.dumps({
            "status": "VULNERABLE",
            "findings": {
                "vulnerabilities": [
                    {"type": "Clickjacking", "severity": "Medium"},
                    {"type": "Clickjacking", "severity": "Medium"},
                ],
            },
        }),
    )
    assert len(result.candidate_findings) == 1
    assert result.candidate_findings[0].vuln_type == "Clickjacking"


def test_legacy_adapter_preserves_typed_active_detector_evidence():
    result = result_from_legacy(
        "SQL Injection Scanner",
        "http://fixture.local/search",
        json.dumps({
            "status": "VULNERABLE",
            "vulnerabilities": [{
                "type": "SQL Injection (MySQL)",
                "parameter": "q",
                "status_code": 500,
                "semantic_test": "passed",
                "sqlmap_confirmed": True,
                "evidence": "Controlled error reproduced",
                "payload": "secret-payload-must-not-be-copied",
            }],
        }),
    )
    candidate = result.candidate_findings[0]
    assert candidate.metadata["sqlmap_confirmed"] is True
    assert candidate.metadata["semantic_test"] == "passed"
    assert candidate.metadata["status_code"] == 500
    assert "payload" not in candidate.metadata
    finding_observation = next(item for item in result.observations if item.kind == "legacy_finding")
    assert finding_observation.metadata["parameter"] == "q"


def test_legacy_tool_specific_vulnerability_lists_are_admitted():
    result = result_from_legacy(
        "XSS & CSRF Detector",
        "http://fixture.local/search",
        json.dumps({
            "xss_vulnerabilities": [{
                "type": "Reflected XSS",
                "status_code": 200,
                "reflection_context": "html",
                "marker_executed": True,
                "stored": False,
                "cleanup_verified": True,
            }],
            "csrf_findings": [{"type": "Missing CSRF Token", "severity": "Medium"}],
        }),
    )
    assert {item.vuln_type for item in result.candidate_findings} == {
        "Reflected XSS",
        "Missing CSRF Token",
    }


def test_legacy_json_error_is_failed_not_successful_observation():
    result = result_from_legacy(
        "browser_tool",
        "http://fixture.local/login",
        json.dumps({"error": "navigation timed out"}),
    )
    assert result.status == "failed"
    assert result.observations == []
    assert result.errors[0].code == "legacy_tool_failed"


def test_legacy_cancellation_markers_are_cancelled_not_successful_observations():
    for marker in (
        "DIBATALKAN: job di-cancel oleh user.",
        "SCAN DIBATALKAN: approval rejected atau timeout.",
        "CANCELLED: job cancelled by user.",
        "EKSEKUSI DIBATALKAN: approval rejected.",
    ):
        result = result_from_legacy("legacy_tool", "http://fixture.local", marker)
        assert result.status == "cancelled"
        assert result.observations == []
        assert result.errors[0].code == "legacy_cancelled"


def test_legacy_success_with_error_signal_is_not_normalized_as_success():
    for payload in (
        {"status": "SUCCESS", "error": "artifact capture timed out"},
        {"status": "SUCCESS", "errors": [{"code": "timeout"}]},
        {"status": "SUCCESS", "ok": False},
        {"status": "SUCCESS", "success": False},
    ):
        result = result_from_legacy(
            "legacy_tool",
            "http://fixture.local",
            json.dumps(payload),
        )

        assert result.status == "failed"
        assert result.observations == []
        assert result.errors[0].code == "legacy_tool_failed"


def test_legacy_partial_with_error_signal_keeps_partial_status():
    result = result_from_legacy(
        "legacy_tool",
        "http://fixture.local",
        json.dumps({"status": "PARTIAL", "errors": ["one request timed out"]}),
    )

    assert result.status == "partial"
    assert result.errors[0].code == "legacy_tool_partial"
    assert result.errors[0].retryable is True


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

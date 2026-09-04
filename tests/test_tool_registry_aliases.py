from core.tool_registry import (
    EXPECTED_PUBLIC_TOOL_COUNT,
    canonical_tool_name,
    get_tool_capability,
    get_tool_registry,
    validate_tool_registry,
)


def test_planner_aliases_resolve_without_changing_public_registry():
    entries = get_tool_registry()
    assert len(entries) == EXPECTED_PUBLIC_TOOL_COUNT
    assert canonical_tool_name("scan_sql_injection") == "SQL Injection Scanner"
    assert canonical_tool_name("detect_xss_csrf") == "XSS & CSRF Detector"
    assert canonical_tool_name("scan_lfi_rfi") == "LFI/RFI Scanner"
    assert get_tool_capability("scan_sql_injection").public_name == "SQL Injection Scanner"
    assert get_tool_capability("detect_xss_csrf").public_name == "XSS & CSRF Detector"
    assert get_tool_capability("scan_lfi_rfi").public_name == "LFI/RFI Scanner"


def test_approval_policy_is_explicit_for_legacy_probe_tools():
    # These implementations call require_approval themselves. The registry
    # must agree before the autonomous admission gate is reached.
    assert get_tool_capability("scan_sql_injection").requires_approval is True
    assert get_tool_capability("graphql_tester").requires_approval is True
    assert get_tool_capability("open_redirect_scanner").requires_approval is True
    assert get_tool_capability("scan_sql_injection").side_effect_class == "approval_controlled"


def test_checkpoint_tools_have_explicit_policy_coverage():
    assert validate_tool_registry() == []

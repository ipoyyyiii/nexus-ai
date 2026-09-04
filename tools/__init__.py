"""Public tool namespace with lazy compatibility re-exports.

The canonical runtime imports individual tool modules through the registry.
The previous initializer imported every scanner whenever one tool was needed,
which pulled in Playwright, mitmproxy, and external-tool adapters during API
and worker startup. Keep ``from tools import <name>`` compatibility while
loading only the requested tool module.
"""

from importlib import import_module


_LAZY_EXPORTS = {
    # Custom tools
    "baca_log_burp": ("tools.custom_tools", "baca_log_burp"),
    "tembak_payload": ("tools.custom_tools", "tembak_payload"),
    "recon_target": ("tools.custom_tools", "recon_target"),
    "scan_sql_injection": ("tools.custom_tools", "scan_sql_injection"),
    "detect_xss_csrf": ("tools.custom_tools", "detect_xss_csrf"),
    "analyze_ssl_tls": ("tools.custom_tools", "analyze_ssl_tls"),
    "enumerate_dns_subdomains": ("tools.custom_tools", "enumerate_dns_subdomains"),
    "analyze_password_strength": ("tools.custom_tools", "analyze_password_strength"),
    "test_api_security": ("tools.custom_tools", "test_api_security"),
    "scan_lfi_rfi": ("tools.custom_tools", "scan_lfi_rfi"),
    "test_header_injection": ("tools.custom_tools", "test_header_injection"),
    "get_execution_logs": ("tools.custom_tools", "get_execution_logs"),
    "clear_execution_logs": ("tools.custom_tools", "clear_execution_logs"),
    "report_new_endpoint": ("tools.custom_tools", "report_new_endpoint"),
    "exec_logger": ("tools.custom_tools", "exec_logger"),
    # Browser tools
    "browser_screenshot": ("tools.playwright_tools", "browser_screenshot"),
    "browser_extract_surface": ("tools.playwright_tools", "browser_extract_surface"),
    "browser_intercept_requests": ("tools.playwright_tools", "browser_intercept_requests"),
    "browser_extract_js_secrets": ("tools.playwright_tools", "browser_extract_js_secrets"),
    "browser_check_security_headers": ("tools.playwright_tools", "browser_check_security_headers"),
    "browser_simulate_form": ("tools.playwright_tools", "browser_simulate_form"),
    "browser_find_open_redirect": ("tools.playwright_tools", "browser_find_open_redirect"),
    "login_automator": ("tools.playwright_tools", "login_automator"),
    "inject_session": ("tools.playwright_tools", "inject_session"),
    "browser_cookie_inspector": ("tools.playwright_tools", "browser_cookie_inspector"),
    "browser_storage_inspector": ("tools.playwright_tools", "browser_storage_inspector"),
    "browser_js_debugger": ("tools.playwright_tools", "browser_js_debugger"),
    "browser_network_modifier": ("tools.playwright_tools", "browser_network_modifier"),
    # Core/protocol tools
    "scan_ssrf": ("tools.ssrf_idor_tools", "scan_ssrf"),
    "scan_idor": ("tools.ssrf_idor_tools", "scan_idor"),
    "authorization_differential_replay": ("tools.authorization_tools", "authorization_differential_replay"),
    "param_discovery_get": ("tools.param_discovery", "param_discovery_get"),
    "param_discovery_post": ("tools.param_discovery", "param_discovery_post"),
    "param_discovery_headers": ("tools.param_discovery", "param_discovery_headers"),
    "analyze_js_deep": ("tools.js_analysis", "analyze_js_deep"),
    "run_nuclei_scan": ("tools.nuclei_tool", "run_nuclei_scan"),
    "detect_subdomain_takeover": ("tools.subdomain_takeover", "detect_subdomain_takeover"),
    "test_jwt_weakness": ("tools.auth_testing", "test_jwt_weakness"),
    "test_auth_rate_limiting": ("tools.auth_testing", "test_auth_rate_limiting"),
    "wayback_scraper": ("tools.wayback_tool", "wayback_scraper"),
    "github_dorking": ("tools.github_dork", "github_dorking"),
    "oauth_flow_tester": ("tools.oauth_tester", "oauth_flow_tester"),
    "graphql_tester": ("tools.graphql_tester", "graphql_tester"),
    "cors_tester": ("tools.cors_tester", "cors_tester"),
    "ssti_tester": ("tools.ssti_tester", "ssti_tester"),
    "xxe_tester": ("tools.xxe_tester", "xxe_tester"),
    "misconfiguration_scanner": ("tools.misconfiguration_scanner", "misconfiguration_scanner"),
    # Injection and access-control tools
    "command_injection_scanner": ("tools.command_injection", "command_injection_scanner"),
    "log_injection_scanner": ("tools.command_injection", "log_injection_scanner"),
    "csv_injection_scanner": ("tools.command_injection", "csv_injection_scanner"),
    "stored_xss_scanner": ("tools.xss_advanced", "stored_xss_scanner"),
    "dom_xss_scanner": ("tools.xss_advanced", "dom_xss_scanner"),
    "jsonp_injection_scanner": ("tools.xss_advanced", "jsonp_injection_scanner"),
    "session_management_scanner": ("tools.auth_session_advanced", "session_management_scanner"),
    "password_reset_tester": ("tools.auth_session_advanced", "password_reset_tester"),
    "blind_sqli_scanner": ("tools.injection_advanced", "blind_sqli_scanner"),
    "nosql_injection_scanner": ("tools.injection_advanced", "nosql_injection_scanner"),
    "ldap_injection_scanner": ("tools.injection_advanced", "ldap_injection_scanner"),
    "xpath_injection_scanner": ("tools.injection_advanced", "xpath_injection_scanner"),
    "access_control_scanner": ("tools.access_control_advanced", "access_control_scanner"),
    "csrf_exploit_scanner": ("tools.access_control_scanners", "csrf_exploit_scanner"),
    "mass_assignment_scanner": ("tools.access_control_scanners", "mass_assignment_scanner"),
    "http_method_tampering_scanner": ("tools.access_control_scanners", "http_method_tampering_scanner"),
    # Client-side and advanced attacks
    "client_side_security_scanner": ("tools.client_side_advanced", "client_side_security_scanner"),
    "prototype_pollution_scanner": ("tools.client_side_advanced", "prototype_pollution_scanner"),
    "host_header_injection_scanner": ("tools.advanced_web_attacks", "host_header_injection_scanner"),
    "race_condition_scanner": ("tools.advanced_web_attacks", "race_condition_scanner"),
    "file_upload_scanner": ("tools.advanced_web_attacks", "file_upload_scanner"),
    "http_request_smuggling_scanner": ("tools.advanced_web_attacks", "http_request_smuggling_scanner"),
    "websocket_security_scanner": ("tools.advanced_web_attacks", "websocket_security_scanner"),
    "recon_advanced": ("tools.recon_advanced", "recon_advanced"),
    "email_header_injection_scanner": ("tools.recon_advanced", "email_header_injection_scanner"),
    "insecure_deserialization_scanner": ("tools.deserialization_cache_tools", "insecure_deserialization_scanner"),
    "web_cache_poisoning_scanner": ("tools.deserialization_cache_tools", "web_cache_poisoning_scanner"),
    "cache_deception_scanner": ("tools.deserialization_cache_tools", "cache_deception_scanner"),
    "ssrf_advanced_scanner": ("tools.deserialization_cache_tools", "ssrf_advanced_scanner"),
    # Auth/recon/provider adapters
    "twofa_bypass_scanner": ("tools.auth_recon_tools", "twofa_bypass_scanner"),
    "credential_stuffing_scanner": ("tools.auth_recon_tools", "credential_stuffing_scanner"),
    "mixed_content_scanner": ("tools.auth_recon_tools", "mixed_content_scanner"),
    "idor_uuid_scanner": ("tools.auth_recon_tools", "idor_uuid_scanner"),
    "postmessage_vulnerability_scanner": ("tools.auth_recon_tools", "postmessage_vulnerability_scanner"),
    "asn_ip_mapper": ("tools.auth_recon_tools", "asn_ip_mapper"),
    "shodan_scanner": ("tools.shodan_censys_tools", "shodan_scanner"),
    "censys_scanner": ("tools.shodan_censys_tools", "censys_scanner"),
    "waf_detector": ("tools.waf_detector", "waf_detector"),
    "report_generator": ("tools.report_generator", "report_generator"),
    # New scanners and hunter pipeline
    "html_injection_scanner": ("tools.html_injection_scanner", "html_injection_scanner"),
    "ssi_injection_scanner": ("tools.ssi_injection_scanner", "ssi_injection_scanner"),
    "hpp_scanner": ("tools.hpp_scanner", "hpp_scanner"),
    "password_storage_analyzer": ("tools.password_storage_analyzer", "password_storage_analyzer"),
    "credential_reuse_scanner": ("tools.credential_reuse_scanner", "credential_reuse_scanner"),
    "httpx_probe": ("tools.hunter_pipeline", "httpx_probe"),
    "naabu_scan": ("tools.hunter_pipeline", "naabu_scan"),
    "gowitness_shot": ("tools.hunter_pipeline", "gowitness_shot"),
    "gau_urls": ("tools.hunter_pipeline", "gau_urls"),
    "hakrawler_crawl": ("tools.hunter_pipeline", "hakrawler_crawl"),
    "amass_enum": ("tools.hunter_pipeline", "amass_enum"),
    # Stateful browser/business tools
    "browser_workflow_discovery": ("tools.browser_workflow_tools", "browser_workflow_discovery"),
    "stateful_browser_workflow": ("tools.browser_workflow_tools", "stateful_browser_workflow"),
    "business_invariant_evaluator": ("tools.browser_workflow_tools", "business_invariant_evaluator"),
    "normalize_protocol_capture": ("tools.modern_protocol_tools", "normalize_protocol_capture"),
}


def __getattr__(name: str):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


__all__ = sorted(_LAZY_EXPORTS)

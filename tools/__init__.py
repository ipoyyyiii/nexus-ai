"""
Tools Package
==============
Re-exports semua tool functions buat clean imports.
"""

# ── Custom Tools (core scanners) ─────────────────────────────────────────────
from tools.custom_tools import (
    baca_log_burp, tembak_payload, recon_target,
    scan_sql_injection, detect_xss_csrf, analyze_ssl_tls,
    enumerate_dns_subdomains, analyze_password_strength,
    test_api_security, scan_lfi_rfi, test_header_injection,
    get_execution_logs, clear_execution_logs, report_new_endpoint,
    exec_logger,
)

# ── Playwright Tools (browser-based) ─────────────────────────────────────────
from tools.playwright_tools import (
    browser_screenshot, browser_extract_surface,
    browser_intercept_requests, browser_extract_js_secrets,
    browser_check_security_headers, browser_simulate_form,
    browser_find_open_redirect, login_automator, inject_session,
    browser_cookie_inspector, browser_storage_inspector,
    browser_js_debugger, browser_network_modifier,
)

# ── SSRF & IDOR ──────────────────────────────────────────────────────────────
from tools.ssrf_idor_tools import scan_ssrf, scan_idor

# ── Parameter Discovery ──────────────────────────────────────────────────────
from tools.param_discovery import param_discovery_get, param_discovery_post, param_discovery_headers

# ── JS Analysis ──────────────────────────────────────────────────────────────
from tools.js_analysis import analyze_js_deep

# ── Nuclei ───────────────────────────────────────────────────────────────────
from tools.nuclei_tool import run_nuclei_scan

# ── Subdomain Takeover ───────────────────────────────────────────────────────
from tools.subdomain_takeover import detect_subdomain_takeover

# ── Auth Testing ──────────────────────────────────────────────────────────────
from tools.auth_testing import test_jwt_weakness, test_auth_rate_limiting

# ── Wayback ──────────────────────────────────────────────────────────────────
from tools.wayback_tool import wayback_scraper

# ── GitHub Dorking ────────────────────────────────────────────────────────────
from tools.github_dork import github_dorking

# ── OAuth ─────────────────────────────────────────────────────────────────────
from tools.oauth_tester import oauth_flow_tester

# ── GraphQL ───────────────────────────────────────────────────────────────────
from tools.graphql_tester import graphql_tester

# ── CORS ──────────────────────────────────────────────────────────────────────
from tools.cors_tester import cors_tester

# ── SSTI ──────────────────────────────────────────────────────────────────────
from tools.ssti_tester import ssti_tester

# ── XXE ───────────────────────────────────────────────────────────────────────
from tools.xxe_tester import xxe_tester

# ── Misconfiguration ──────────────────────────────────────────────────────────
from tools.misconfiguration_scanner import misconfiguration_scanner

# ── Command Injection ─────────────────────────────────────────────────────────
from tools.command_injection import command_injection_scanner, log_injection_scanner, csv_injection_scanner

# ── XSS Advanced ──────────────────────────────────────────────────────────────
from tools.xss_advanced import stored_xss_scanner, dom_xss_scanner, jsonp_injection_scanner

# ── Auth Session Advanced ─────────────────────────────────────────────────────
from tools.auth_session_advanced import session_management_scanner, password_reset_tester

# ── Injection Advanced ────────────────────────────────────────────────────────
from tools.injection_advanced import blind_sqli_scanner, nosql_injection_scanner, ldap_injection_scanner, xpath_injection_scanner

# ── Access Control ────────────────────────────────────────────────────────────
from tools.access_control_advanced import access_control_scanner
from tools.access_control_scanners import csrf_exploit_scanner, mass_assignment_scanner, http_method_tampering_scanner

# ── Client Side ───────────────────────────────────────────────────────────────
from tools.client_side_advanced import client_side_security_scanner, prototype_pollution_scanner

# ── Advanced Web Attacks ──────────────────────────────────────────────────────
from tools.advanced_web_attacks import host_header_injection_scanner, race_condition_scanner, file_upload_scanner, http_request_smuggling_scanner, websocket_security_scanner

# ── Recon Advanced ────────────────────────────────────────────────────────────
from tools.recon_advanced import recon_advanced, email_header_injection_scanner

# ── Deserialization & Cache ───────────────────────────────────────────────────
from tools.deserialization_cache_tools import insecure_deserialization_scanner, web_cache_poisoning_scanner, cache_deception_scanner, ssrf_advanced_scanner

# ── Auth Recon ────────────────────────────────────────────────────────────────
from tools.auth_recon_tools import twofa_bypass_scanner, credential_stuffing_scanner, mixed_content_scanner, idor_uuid_scanner, postmessage_vulnerability_scanner, asn_ip_mapper

# ── Shodan & Censys ──────────────────────────────────────────────────────────
from tools.shodan_censys_tools import shodan_scanner, censys_scanner

# ── WAF Detector ──────────────────────────────────────────────────────────────
from tools.waf_detector import waf_detector

# ── Report Generator ──────────────────────────────────────────────────────────
from tools.report_generator import report_generator

# ── New Vulnerability Scanners (2026 Benchmark) ──────────────────────────────
from tools.html_injection_scanner import html_injection_scanner
from tools.ssi_injection_scanner import ssi_injection_scanner
from tools.hpp_scanner import hpp_scanner
from tools.password_storage_analyzer import password_storage_analyzer
from tools.credential_reuse_scanner import credential_reuse_scanner

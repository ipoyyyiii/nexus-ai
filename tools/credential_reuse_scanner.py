"""
CREDENTIAL REUSE SCANNER
========================
Test for credential reuse across multiple endpoints.

Usage:
    from tools.credential_reuse_scanner import credential_reuse_scanner
"""

import json
import requests
import re
from urllib.parse import quote, urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from core.auth_store import get_auth_kwargs
from engines.stealth_engine import stealth

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


def _logger():
    from tools.custom_tools import exec_logger
    return exec_logger


@tool("credential_reuse_scanner")
def credential_reuse_scanner(url: str, credentials: str = "") -> str:
    """
    Test for credential reuse across multiple endpoints.
    Tests if same credentials work on different auth endpoints.

    Args:
        url: Target base URL
        credentials: JSON string with username/password (optional)
    """
    tool_name = "Credential Reuse Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Testing credential reuse on {url}")
    if check_cancelled(logger): return "CANCELLED: job cancelled by user."

    approved = require_approval(
        action=f"Credential reuse test on {url}",
        context="Testing if credentials work across multiple auth endpoints",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "CANCELLED: approval rejected or timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")

    # Parse credentials
    creds = {}
    if credentials:
        try:
            creds = json.loads(credentials)
        except Exception:
            pass

    if not creds.get("username") or not creds.get("password"):
        return json.dumps({
            "status": "SKIPPED",
            "reason": "No credentials provided. Pass credentials as JSON: {\"username\": \"...\", \"password\": \"...\"}",
        })

    username = creds["username"]
    password = creds["password"]

    findings = []

    # ── 1. Find all auth endpoints ────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Discovering auth endpoints")

    auth_endpoints = []
    auth_paths = [
        "/login", "/signin", "/sign-in", "/auth/login", "/auth/signin",
        "/api/login", "/api/auth", "/api/v1/login", "/api/v1/auth",
        "/user/login", "/user/auth", "/account/login",
        "/wp-login.php", "/wp-admin",  # WordPress
        "/administrator",  # Joomla
        "/admin/login", "/admin/auth",
        "/sso/login", "/saml/login",  # SSO/SAML
        "/oauth/login", "/oauth2/login",
    ]

    for path in auth_paths:
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{path}", timeout=5, verify=False, **auth_kwargs)
            if r.status_code in [200, 405, 401, 403]:
                auth_endpoints.append(f"{base}{path}")
        except Exception:
            pass

    if not auth_endpoints:
        return json.dumps({
            "status": "SKIPPED",
            "reason": "No auth endpoints discovered",
        })

    logger.add_log(tool_name, "SUCCESS", f"Found {len(auth_endpoints)} auth endpoints")

    # ── 2. Test credentials on each endpoint ──────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", f"Testing credentials on {len(auth_endpoints)} endpoints")

    successful_endpoints = []

    for endpoint in auth_endpoints:
        if check_cancelled(logger): break

        try:
            rate_limiter.wait(domain)

            # Try different auth methods
            auth_methods = [
                # POST with form data
                {"method": "POST", "data": {"username": username, "password": password}},
                # POST with JSON
                {"method": "POST", "json": {"username": username, "password": password}},
                # POST with email field
                {"method": "POST", "data": {"email": username, "password": password}},
                # Basic Auth
                {"method": "GET", "auth": (username, password)},
            ]

            for auth_method in auth_methods:
                try:
                    method = auth_method.pop("method")
                    resp = requests.request(
                        method, endpoint,
                        headers=stealth.get_browser_headers(endpoint),
                        timeout=5, verify=False, **auth_method, **auth_kwargs,
                    )

                    # Check if login successful
                    if resp.status_code in [200, 201, 302]:
                        # Check for dashboard/success indicators
                        success_indicators = [
                            "dashboard", "welcome", "logout", "sign out",
                            "profile", "settings", "account", "home",
                        ]
                        error_indicators = [
                            "invalid", "incorrect", "wrong", "failed",
                            "error", "denied", "forbidden",
                        ]

                        has_success = any(ind in resp.text.lower() for ind in success_indicators)
                        has_error = any(ind in resp.text.lower() for ind in error_indicators)

                        if has_success and not has_error:
                            successful_endpoints.append({
                                "endpoint": endpoint,
                                "method": method,
                                "status_code": resp.status_code,
                                "severity": "High",
                            })
                            logger.add_log(tool_name, "WARNING",
                                f"Credential reuse: {endpoint} ({method})")
                            break  # Found working auth, skip other methods

                except Exception:
                    continue

        except Exception:
            pass

    # ── 3. Analyze results ────────────────────────────────────────────────────
    if successful_endpoints:
        # Check if credentials work on multiple endpoints
        unique_endpoints = list(set(ep["endpoint"] for ep in successful_endpoints))

        if len(unique_endpoints) > 1:
            findings.append({
                "type": "Credential Reuse Across Endpoints",
                "severity": "High",
                "detail": f"Same credentials work on {len(unique_endpoints)} different auth endpoints",
                "endpoints": unique_endpoints,
                "evidence": "Multiple endpoints accept the same credentials — indicates shared auth backend or credential reuse",
            })
            logger.add_log(tool_name, "WARNING",
                f"Credential reuse detected: {len(unique_endpoints)} endpoints")
        else:
            findings.append({
                "type": "Single Endpoint Auth Success",
                "severity": "Info",
                "detail": f"Credentials work on {unique_endpoints[0]}",
                "endpoint": unique_endpoints[0],
            })

    result = {
        "status": "VULNERABLE" if findings else "SAFE",
        "findings": findings,
        "auth_endpoints_found": len(auth_endpoints),
        "successful_endpoints": len(successful_endpoints),
        "total_endpoints_tested": len(auth_endpoints),
    }

    logger.add_log(tool_name, "SUCCESS",
        f"Credential reuse test complete. {len(auth_endpoints)} endpoints tested")
    return json.dumps(result, indent=2)

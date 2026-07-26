import json
import requests
import re
import urllib3
from urllib.parse import quote, urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.auth_store import auth_get, auth_post
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from core.auth_store import inject_into_session, auth_store

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url

def _logger():
    from tools.custom_tools import exec_logger
    return exec_logger


# ==========================================
# TOOL 1: Access Control Scanner
# ==========================================
@tool("access_control_scanner")
def access_control_scanner(url: str, cookies: str = "", auth_header: str = "") -> str:
    """
    Scan for Broken Access Control vulnerabilities:
    - Forced browsing (unauth endpoint discovery)
    - HTTP method bypass (PUT/DELETE/PATCH)
    - Mass assignment (extra params injection)
    - Advanced path traversal (double encoding, unicode)
    - Privilege escalation via parameter tampering
    url: target base URL
    cookies: optional - session cookies string (e.g. "session=abc123")
    auth_header: optional - auth header value (e.g. "Bearer token123")
    """
    tool_name = "Access Control Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting access control scan on {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    base = url.rstrip("/")

    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header
    cookie_dict = {}
    if cookies:
        for part in cookies.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    # Inject from auth_store jika ada session
    auth_session = auth_store.get_session(domain)
    if auth_session:
        if auth_session.headers:
            headers.update(auth_session.headers)
        if auth_session.cookies:
            cookie_dict.update(auth_session.cookies)

    findings = {
        "forced_browsing": [],
        "http_method_bypass": [],
        "mass_assignment": [],
        "path_traversal_advanced": [],
        "parameter_tampering": []
    }

    # ── 1. Forced Browsing ────────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing forced browsing (unauth endpoint discovery)")
    sensitive_paths = [
        "/api/users", "/api/admin", "/api/config", "/api/keys",
        "/api/v1/users", "/api/v2/admin", "/admin/api",
        "/internal", "/private", "/secret", "/hidden",
        "/config", "/settings", "/env", "/debug",
        "/api/export", "/api/backup", "/api/dump",
        "/swagger", "/swagger-ui", "/api-docs", "/openapi.json",
        "/graphql", "/graphiql", "/.well-known/security.txt",
        "/server-status", "/server-info", "/phpinfo.php",
        "/actuator", "/actuator/env", "/actuator/beans",  # Spring Boot
        "/metrics", "/health", "/info",  # common monitoring
    ]
    for path in sensitive_paths:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            r = auth_get(f"{base}{path}", headers=headers, cookies=cookie_dict, timeout=5, verify=False)
            if r.status_code == 200 and len(r.content) > 100:
                findings["forced_browsing"].append({
                    "url": f"{base}{path}",
                    "status": r.status_code,
                    "size": len(r.content),
                    "content_type": r.headers.get("Content-Type", ""),
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", f"Sensitive endpoint accessible: {path}")
        except Exception:
            pass

    # ── 2. HTTP Method Bypass ─────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing HTTP method bypass")
    dangerous_methods = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD"]
    test_paths = ["/", "/api", "/api/v1", "/admin"]
    for path in test_paths[:2]:
        for method in dangerous_methods:
            if check_cancelled(logger): break
            try:
                rate_limiter.wait(domain)
                r = requests.request(
                    method, f"{base}{path}",
                    headers=headers, cookies=cookie_dict,
                    timeout=5, verify=False
                )
                if r.status_code not in [405, 404, 501, 403]:
                    findings["http_method_bypass"].append({
                        "method": method,
                        "url": f"{base}{path}",
                        "status": r.status_code,
                        "severity": "Medium" if method in ["OPTIONS", "HEAD"] else "High"
                    })
                    logger.add_log(tool_name, "WARNING", f"Method {method} allowed at {path}: {r.status_code}")
            except Exception:
                pass

    # ── 3. Mass Assignment ────────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing mass assignment")
    mass_assignment_payloads = [
        {"isAdmin": "true", "role": "admin", "admin": "true", "is_admin": 1},
        {"role": "administrator", "permissions": "all", "privilege": "high"},
        {"user_type": "admin", "account_type": "premium", "verified": "true"},
        {"_isAdmin": True, "isStaff": True, "isSuperuser": True},
    ]
    register_paths = ["/api/register", "/api/users", "/register", "/signup", "/api/signup", "/api/v1/users"]
    for rp in register_paths[:3]:
        for payload in mass_assignment_payloads[:2]:
            if check_cancelled(logger): break
            try:
                rate_limiter.wait(domain)
                r = auth_post(
                    f"{base}{rp}",
                    json={**payload, "username": "testuser_nexus", "password": "Test123!", "email": "test@nexus.com"},
                    headers={**headers, "Content-Type": "application/json"},
                    cookies=cookie_dict, timeout=5, verify=False
                )
                if r.status_code in [200, 201]:
                    # Check if any of the admin params are in the response
                    resp_lower = r.text.lower()
                    if any(k.lower() in resp_lower for k in payload.keys()):
                        findings["mass_assignment"].append({
                            "endpoint": f"{base}{rp}",
                            "injected_params": list(payload.keys()),
                            "status": r.status_code,
                            "type": "Mass Assignment",
                            "severity": "High",
                            "note": "Admin/privilege params accepted in registration — manual verification needed"
                        })
                        logger.add_log(tool_name, "WARNING", f"Mass assignment possible: {rp}")
                        break
            except Exception:
                pass

    # ── 4. Advanced Path Traversal ────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing advanced path traversal encodings")
    traversal_payloads = [
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",         # double URL encode
        "%252e%252e/%252e%252e/etc/passwd",          # double encode
        "..%2F..%2F..%2Fetc%2Fpasswd",              # mixed encode
        "....//....//....//etc/passwd",              # doubled dots
        "..%c0%af..%c0%af..%c0%afetc/passwd",       # UTF-8 overlong
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",  # unicode fullwidth
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",  # Windows
    ]
    traversal_params = ["file", "path", "filename", "page", "template", "lang", "include", "src", "url"]
    for param in traversal_params[:5]:
        for tp in traversal_payloads[:4]:
            if check_cancelled(logger): break
            try:
                rate_limiter.wait(domain)
                r = auth_get(f"{base}?{param}={tp}", headers=headers, cookies=cookie_dict, timeout=5, verify=False)
                if any(sig in r.text for sig in ["root:x:", "bin/bash", "[fonts]", "boot loader"]):
                    findings["path_traversal_advanced"].append({
                        "parameter": param,
                        "payload": tp,
                        "type": "Path Traversal (Advanced Encoding)",
                        "evidence": r.text[:100],
                        "severity": "Critical"
                    })
                    logger.add_log(tool_name, "WARNING", f"Path traversal (advanced): param={param}")
                    break
            except Exception:
                pass

    # ── 5. Privilege Escalation via Parameter Tampering ───────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing parameter tampering for privilege escalation")
    escalation_params = [
        ("user_id", ["1", "0", "admin"]),
        ("userId", ["1", "0", "admin"]),
        ("account_id", ["1", "100", "999"]),
        ("role", ["user", "admin", "superadmin", "moderator"]),
        ("access_level", ["0", "1", "99", "255"]),
        ("group", ["user", "admin", "staff"]),
    ]
    for param, values in escalation_params:
        for val in values:
            if check_cancelled(logger): break
            try:
                rate_limiter.wait(domain)
                r = auth_get(
                    f"{base}?{param}={val}",
                    headers=headers, cookies=cookie_dict, timeout=5, verify=False
                )
                if r.status_code == 200 and any(kw in r.text.lower() for kw in
                    ["admin", "dashboard", "manage", "control panel", "administrator"]):
                    findings["parameter_tampering"].append({
                        "parameter": param,
                        "value": val,
                        "type": "Parameter Tampering / Privilege Escalation",
                        "severity": "High",
                        "note": "Manual verification needed to confirm actual escalation"
                    })
                    logger.add_log(tool_name, "WARNING", f"Parameter tampering: {param}={val}")
                    break
            except Exception:
                pass

    total = sum(len(v) for v in findings.values())

    # ── 6. Privilege Escalation — Horizontal & Vertical ───────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing privilege escalation (horizontal + vertical)")

    # Horizontal: access other user's resources
    idor_endpoints = [
        "/api/users/1", "/api/users/2", "/api/profile/1",
        "/api/orders/1", "/api/invoices/1", "/api/documents/1",
        "/api/v1/users/1", "/api/v1/profiles/1",
    ]
    for endpoint in idor_endpoints[:4]:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            r = auth_get(
                f"{base}{endpoint}",
                headers=headers, cookies=cookie_dict, timeout=5, verify=False
            )
            if r.status_code == 200:
                # Check if response contains other user's data
                resp_lower = r.text.lower()
                if any(kw in resp_lower for kw in ["email", "phone", "address", "ssn", "credit", "password"]):
                    findings["parameter_tampering"].append({
                        "type": "Horizontal Privilege Escalation (IDOR)",
                        "endpoint": endpoint,
                        "severity": "Critical",
                        "evidence": f"Other user's data accessible: {r.text[:200]}",
                    })
                    logger.add_log(tool_name, "WARNING", f"Horizontal PE: {endpoint}")
        except Exception:
            pass

    # Vertical: access admin endpoints without admin role
    admin_endpoints = [
        "/admin", "/admin/", "/api/admin", "/api/admin/users",
        "/dashboard", "/api/dashboard", "/management",
        "/api/v1/admin", "/api/internal", "/api/system",
    ]
    for endpoint in admin_endpoints[:5]:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            r = auth_get(
                f"{base}{endpoint}",
                headers=headers, cookies=cookie_dict, timeout=5, verify=False
            )
            if r.status_code == 200 and len(r.text) > 100:
                resp_lower = r.text.lower()
                if any(kw in resp_lower for kw in
                    ["admin", "manage", "delete", "edit", "create", "config", "setting", "user list"]):
                    findings["parameter_tampering"].append({
                        "type": "Vertical Privilege Escalation",
                        "endpoint": endpoint,
                        "severity": "Critical",
                        "evidence": f"Admin panel accessible without admin role: {r.text[:200]}",
                    })
                    logger.add_log(tool_name, "WARNING", f"Vertical PE: {endpoint}")
        except Exception:
            pass

    total = sum(len(v) for v in findings.values())
    result = {
        "status": "VULNERABLE" if total > 0 else "SAFE",
        "findings": findings,
        "total_issues": total
    }
    logger.add_log(tool_name, "SUCCESS", f"Access control scan complete. Issues: {total}")
    return json.dumps(result, indent=2)

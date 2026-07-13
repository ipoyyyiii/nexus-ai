"""
CSRF EXPLOIT, MASS ASSIGNMENT & HTTP METHOD TAMPERING SCANNER
==============================================================
3 tools baru buat nutup gap vulnerability coverage.

1. csrf_exploit_scanner — test state-changing requests tanpa/dengan token palsu
2. mass_assignment_scanner — test extra params (admin=true, price=0)
3. http_method_tampering_scanner — PUT/PATCH/DELETE + _method override
"""

import json
import re
import requests
import urllib3
from urllib.parse import quote, urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.cancellation import check_cancelled
from core.checkpoint import require_approval

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.auth_store import get_auth_kwargs


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


def _logger():
    from tools.custom_tools import exec_logger
    return exec_logger


# ==========================================
# TOOL 1: CSRF Exploit Scanner
# ==========================================
@tool("csrf_exploit_scanner")
def csrf_exploit_scanner(url: str, method: str = "POST", body: str = "", params: str = "") -> str:
    """
    Test CSRF protection pada state-changing endpoints.
    Kirim request TANPA token, dengan token palsu, dan dengan method override.

    Yang di-test:
    - Request tanpa CSRF token sama sekali
    - Request dengan CSRF token palsu/random
    - Request dengan token dari session lain
    - Cookie-based CSRF bypass (SameSite=None)
    - Referer/Origin header bypass

    url: target endpoint (e.g., https://target.com/api/change-password)
    method: HTTP method (POST/PUT/DELETE)
    body: request body (e.g., '{"new_password":"hacked123"}')
    params: comma-separated param names yang mungkin berisi CSRF token
    """
    tool_name = "CSRF Exploit Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting CSRF exploit test pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"CSRF exploit test pada {url}",
        context=f"Testing state-changing request tanpa/dengan token palsu. Method: {method}",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval rejected atau timeout."

    domain = _domain_of(url)
    auth_kw = get_auth_kwargs(domain)
    findings = []

    # Common CSRF token parameter names
    token_params = [p.strip() for p in params.split(",")] if params else [
        "csrf_token", "csrf", "_token", "authenticity_token",
        "__RequestVerificationToken", "xsrf-token", "_csrf",
        "token", "nonce", "csrfmiddlewaretoken",
    ]

    # Parse body
    body_dict = {}
    if body:
        try:
            body_dict = json.loads(body)
        except Exception:
            pass

    # ── 1. Request TANPA token (baseline) ─────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing request tanpa CSRF token")
    try:
        rate_limiter.wait(domain)
        if method.upper() == "GET":
            resp_baseline = requests.get(url, **auth_kw, timeout=8, verify=False)
        else:
            resp_baseline = requests.request(
                method.upper(), url,
                json=body_dict if body_dict else None,
                data=body if body and not body_dict else None,
                **auth_kw,
                timeout=8, verify=False
            )
        baseline_status = resp_baseline.status_code
        baseline_len = len(resp_baseline.text)
    except Exception:
        baseline_status = 0
        baseline_len = 0

    # ── 2. Request dengan token palsu ─────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing request dengan CSRF token palsu")
    for param in token_params[:5]:
        if check_cancelled(logger): break
        try:
            fake_token = "FAKE_CSRF_TOKEN_12345"
            test_body = {**body_dict, param: fake_token} if body_dict else {param: fake_token}

            rate_limiter.wait(domain)
            if method.upper() == "GET":
                test_url = f"{url}?{param}={fake_token}"
                resp = requests.get(test_url, **auth_kw, timeout=8, verify=False)
            else:
                resp = requests.request(
                    method.upper(), url,
                    json=test_body,
                    **auth_kw,
                    timeout=8, verify=False
                )

            # Jika response SAMA dengan baseline (gak rejected), mungkin vulnerable
            if resp.status_code == baseline_status and abs(len(resp.text) - baseline_len) < 100:
                # Cek apakah request success (200/301/302) — token gak validated
                if resp.status_code in [200, 201, 202, 301, 302]:
                    findings.append({
                        "type": "CSRF Token Not Validated",
                        "severity": "High",
                        "detail": f"Request dengan fake token '{param}={fake_token}' received (status {resp.status_code})",
                        "token_param": param,
                        "evidence": f"Baseline: {baseline_status}, With fake token: {resp.status_code}"
                    })
                    logger.add_log(tool_name, "WARNING", f"CSRF token gak validated: {param}")
                    break
        except Exception:
            pass

    # ── 3. Request tanpa body token sama sekali ───────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing request tanpa token di body")
    try:
        rate_limiter.wait(domain)
        if method.upper() == "GET":
            resp_no_token = requests.get(url, **auth_kw, timeout=8, verify=False)
        else:
            # Kirim body TANPA token param
            clean_body = {k: v for k, v in body_dict.items() if k not in token_params}
            resp_no_token = requests.request(
                method.upper(), url,
                json=clean_body if clean_body else None,
                **auth_kw,
                timeout=8, verify=False
            )

        if resp_no_token.status_code in [200, 201, 202, 301, 302]:
            if resp_no_token.status_code == baseline_status:
                findings.append({
                    "type": "CSRF Missing Token Check",
                    "severity": "High",
                    "detail": f"Request tanpa token di body received (status {resp_no_token.status_code})",
                    "evidence": f"Server gak require token di body"
                })
                logger.add_log(tool_name, "WARNING", "CSRF: Server gak require token di body")
    except Exception:
        pass

    # ── 4. SameSite cookie check ──────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking SameSite cookie attribute")
    try:
        rate_limiter.wait(domain)
        resp = requests.get(url, **auth_kw, timeout=5, verify=False, allow_redirects=False)
        set_cookie_headers = resp.headers.get("Set-Cookie", "")
        if set_cookie_headers:
            if "SameSite" not in set_cookie_headers:
                findings.append({
                    "type": "Missing SameSite Cookie",
                    "severity": "Medium",
                    "detail": "Cookies not punya SameSite attribute — rentan CSRF via cross-site request",
                    "evidence": set_cookie_headers[:200]
                })
                logger.add_log(tool_name, "WARNING", "Missing SameSite on cookies")
            elif "SameSite=None" in set_cookie_headers:
                findings.append({
                    "type": "SameSite=None Cookie",
                    "severity": "Medium",
                    "detail": "Cookies using SameSite=None — bisa sent dari cross-origin",
                })
    except Exception:
        pass

    # ── 5. Referer/Origin bypass ──────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing Referer/Origin bypass")
    bypass_headers_list = [
        {"Referer": "https://attacker.com"},
        {"Origin": "https://attacker.com"},
        {"Referer": "https://attacker.com/path"},
        {"Origin": "null"},
    ]
    for bypass_headers in bypass_headers_list:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            all_headers = {**auth_kw.get("headers", {}), **bypass_headers}
            if method.upper() == "GET":
                resp = requests.get(url, headers=all_headers, cookies=auth_kw.get("cookies"), timeout=5, verify=False)
            else:
                resp = requests.request(
                    method.upper(), url,
                    json=body_dict if body_dict else None,
                    headers=all_headers,
                    cookies=auth_kw.get("cookies"),
                    timeout=5, verify=False
                )

            if resp.status_code in [200, 201, 202, 301, 302]:
                header_name = list(bypass_headers.keys())[0]
                findings.append({
                    "type": f"CSRF {header_name} Not Validated",
                    "severity": "Medium",
                    "detail": f"Request received dengan {header_name}: {bypass_headers[header_name]}",
                    "evidence": f"Status: {resp.status_code}"
                })
                logger.add_log(tool_name, "WARNING", f"CSRF: {header_name} gak validated")
                break
        except Exception:
            pass

    result = {
        "status": "VULNERABLE" if findings else "PROTECTED",
        "target": url,
        "method": method,
        "findings": findings,
        "note": "CSRF exploitation membutuhkan victim interaction (click link, visit page). Results di atas menunjukkan apakah server memvalidasi token/origin."
    }
    logger.add_log(tool_name, "SUCCESS", f"CSRF test selesai. Findings: {len(findings)}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 2: Mass Assignment Scanner
# ==========================================
@tool("mass_assignment_scanner")
def mass_assignment_scanner(url: str, body: str = "", params: str = "") -> str:
    """
    Test untuk Mass Assignment / Over-Posting vulnerability.
    Kirim request dengan extra parameters yang gak seharusnya bisa di-set user.

    Yang di-test:
    - Role escalation (admin=true, role=admin)
    - Price/amount manipulation (price=0, amount=0)
    - IDOR via body params (user_id=other_user)
    - Internal field injection (verified=true, balance=999999)

    url: target API endpoint
    body: original request body (JSON)
    params: comma-separated original param names (biar tau mana yang boleh di-change)
    """
    tool_name = "Mass Assignment Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting mass assignment test pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"Mass assignment test pada {url}",
        context=f"Sending request dengan extra sensitive parameters ke API endpoint",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval rejected atau timeout."

    domain = _domain_of(url)
    auth_kw = get_auth_kwargs(domain)
    findings = []

    # Parse original body
    body_dict = {}
    if body:
        try:
            body_dict = json.loads(body)
        except Exception:
            pass

    allowed_params = [p.strip() for p in params.split(",")] if params else list(body_dict.keys())

    # ── Payloads: sensitive fields yang bisa di-inject ────────────────────────
    mass_assignment_payloads = [
        # Role/privilege escalation
        {"field": "admin", "values": [True, "true", 1, "1", "yes"], "category": "privilege"},
        {"field": "role", "values": ["admin", "administrator", "superuser", "root"], "category": "privilege"},
        {"field": "is_admin", "values": [True, "true", 1], "category": "privilege"},
        {"field": "is_staff", "values": [True, "true", 1], "category": "privilege"},
        {"field": "is_superuser", "values": [True, "true", 1], "category": "privilege"},
        {"field": "user_type", "values": ["admin", "staff", "superadmin"], "category": "privilege"},

        # Price/amount manipulation
        {"field": "price", "values": [0, 0.01, -1, "0"], "category": "financial"},
        {"field": "amount", "values": [0, 0.01, -1, 999999], "category": "financial"},
        {"field": "total", "values": [0, 0.01, -1], "category": "financial"},
        {"field": "discount", "values": [100, "100%", 999999], "category": "financial"},
        {"field": "quantity", "values": [999999, -1, 0], "category": "financial"},

        # Account manipulation
        {"field": "verified", "values": [True, "true", 1], "category": "account"},
        {"field": "email_verified", "values": [True, "true", 1], "category": "account"},
        {"field": "active", "values": [True, "true", 1], "category": "account"},
        {"field": "balance", "values": [999999, 999999999], "category": "account"},
        {"field": "credits", "values": [999999, 999999999], "category": "account"},

        # IDOR via body
        {"field": "user_id", "values": ["1", "admin", "2"], "category": "idor"},
        {"field": "account_id", "values": ["1", "2", "admin"], "category": "idor"},
        {"field": "id", "values": ["1", "admin"], "category": "idor"},
        {"field": "owner_id", "values": ["1", "2"], "category": "idor"},

        # Internal fields
        {"field": "created_at", "values": ["2000-01-01"], "category": "internal"},
        {"field": "updated_at", "values": ["2000-01-01"], "category": "internal"},
        {"field": "internal_note", "values": ["mass_assignment_test"], "category": "internal"},
        {"field": "debug", "values": [True, "true"], "category": "internal"},
    ]

    # ── Test setiap payload ───────────────────────────────────────────────────
    total_tested = 0
    for payload_config in mass_assignment_payloads:
        if check_cancelled(logger): break
        field = payload_config["field"]

        # Skip kalau field ini emang di-allow
        if field in allowed_params:
            continue

        for value in payload_config["values"]:
            try:
                test_body = {**body_dict, field: value}
                rate_limiter.wait(domain)

                resp = requests.post(
                    url,
                    json=test_body,
                    **auth_kw,
                    timeout=8,
                    verify=False
                )
                total_tested += 1

                # Deteksi apakah field received:
                # - Response beda dari baseline (gak ada field = ignore)
                # - Response sukses (200/201) padahal field gak seharusnya ada
                if resp.status_code in [200, 201, 202]:
                    # Cek apakah response body berisi field yang di-inject
                    try:
                        resp_json = resp.json()
                        if field in resp_json:
                            findings.append({
                                "type": "Mass Assignment Accepted",
                                "severity": "High",
                                "field": field,
                                "injected_value": value,
                                "category": payload_config["category"],
                                "response_status": resp.status_code,
                                "evidence": f"Field '{field}'={value} received dan muncul di response",
                                "response_preview": json.dumps(resp_json)[:300]
                            })
                            logger.add_log(tool_name, "WARNING",
                                f"Mass assignment accepted: {field}={value}")
                            break  # Cukup 1 bukti per field
                    except Exception:
                        # Response bukan JSON — cek apakah gak error
                        if "error" not in resp.text.lower():
                            findings.append({
                                "type": "Mass Assignment (Non-JSON Response)",
                                "severity": "Medium",
                                "field": field,
                                "injected_value": value,
                                "category": payload_config["category"],
                                "response_status": resp.status_code,
                                "evidence": f"Request dengan {field}={value} gak menghasilkan error",
                            })
                            break

            except Exception:
                pass

    result = {
        "status": "VULNERABLE" if findings else "PROTECTED",
        "target": url,
        "total_tested": total_tested,
        "findings": findings,
        "categories_tested": ["privilege", "financial", "account", "idor", "internal"],
        "note": "Mass assignment vulnerable kalau server menerima dan menyimpan field yang gak di-allow."
    }
    logger.add_log(tool_name, "SUCCESS", f"Mass assignment test selesai. Tested: {total_tested}, Findings: {len(findings)}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 3: HTTP Method Tampering Scanner
# ==========================================
@tool("http_method_tampering_scanner")
def http_method_tampering_scanner(url: str) -> str:
    """
    Test HTTP Method Tampering dan Method Override vulnerabilities.

    Yang di-test:
    - PUT/PATCH/DELETE di endpoints yang seharusnya GET/POST
    - _method override (POST + _method=DELETE)
    - X-HTTP-Method-Override header
    - X-HTTP-Method header
    - __method parameter
    - OPTIONS response (CORS methods disclosure)

    url: target URL (e.g., https://target.com/api/users/1)
    """
    tool_name = "HTTP Method Tampering Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting HTTP method tampering test pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"HTTP method tampering test pada {url}",
        context="Testing PUT/PATCH/DELETE + method override headers",
        risk="low",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval rejected atau timeout."

    domain = _domain_of(url)
    auth_kw = get_auth_kwargs(domain)
    findings = []

    # ── 1. Direct method testing ──────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing direct HTTP methods")
    methods_to_test = ["PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

    baseline_get = None
    try:
        rate_limiter.wait(domain)
        baseline_get = requests.get(url, **auth_kw, timeout=8, verify=False)
    except Exception:
        pass

    for method in methods_to_test:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            resp = requests.request(
                method, url,
                **auth_kw,
                timeout=8,
                verify=False,
                allow_redirects=False
            )

            # DELETE success = kritis
            if method == "DELETE" and resp.status_code in [200, 201, 202, 204]:
                findings.append({
                    "type": "DELETE Method Allowed",
                    "severity": "Critical",
                    "detail": f"DELETE method success di-exec (status {resp.status_code})",
                    "method": method,
                    "status_code": resp.status_code,
                    "response_preview": resp.text[:200]
                })
                logger.add_log(tool_name, "WARNING", f"DELETE method allowed: {resp.status_code}")

            # PUT/PATCH success = high
            elif method in ["PUT", "PATCH"] and resp.status_code in [200, 201, 202]:
                if baseline_get and resp.status_code != baseline_get.status_code:
                    findings.append({
                        "type": f"{method} Method Allowed",
                        "severity": "High",
                        "detail": f"{method} method received (status {resp.status_code})",
                        "method": method,
                        "status_code": resp.status_code
                    })
                    logger.add_log(tool_name, "WARNING", f"{method} method allowed: {resp.status_code}")

            # TRACE = XST vulnerability
            elif method == "TRACE" and resp.status_code == 200:
                findings.append({
                    "type": "TRACE Method Enabled (XST)",
                    "severity": "Medium",
                    "detail": "TRACE method aktif — rentan Cross-Site Tracing (XST)",
                    "method": method,
                    "status_code": resp.status_code
                })
                logger.add_log(tool_name, "WARNING", "TRACE method enabled (XST risk)")

            # OPTIONS = disclosure
            elif method == "OPTIONS" and resp.status_code == 200:
                allow_header = resp.headers.get("Allow", "")
                if allow_header:
                    logger.add_log(tool_name, "INFO", f"OPTIONS Allow: {allow_header}")
                    # Cek apakah dangerous methods di-allow
                    dangerous = [m for m in ["PUT", "PATCH", "DELETE", "TRACE"]
                                if m in allow_header.upper()]
                    if dangerous:
                        findings.append({
                            "type": "Dangerous Methods in OPTIONS",
                            "severity": "Medium",
                            "detail": f"OPTIONS mengungkapkan methods: {allow_header}",
                            "dangerous_methods": dangerous,
                        })

        except Exception:
            pass

    # ── 2. Method Override via _method parameter ──────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing _method override via POST body")
    override_methods = ["DELETE", "PUT", "PATCH"]
    override_fields = ["_method", "__method", "X-HTTP-Method-Override"]

    for override_field in override_fields[:2]:  # _method and __method
        for target_method in override_methods:
            if check_cancelled(logger): break
            try:
                rate_limiter.wait(domain)
                # POST dengan _method=DELETE di body
                resp = requests.post(
                    url,
                    json={override_field: target_method},
                    **auth_kw,
                    timeout=8,
                    verify=False
                )
                if resp.status_code in [200, 201, 202, 204]:
                    findings.append({
                        "type": f"Method Override via {override_field}",
                        "severity": "High",
                        "detail": f"POST + {override_field}={target_method} success (status {resp.status_code})",
                        "override_field": override_field,
                        "target_method": target_method,
                        "status_code": resp.status_code
                    })
                    logger.add_log(tool_name, "WARNING",
                        f"Method override accepted: {override_field}={target_method}")
                    break
            except Exception:
                pass

    # ── 3. Method Override via headers ────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing method override via headers")
    header_overrides = [
        {"X-HTTP-Method-Override": "DELETE"},
        {"X-HTTP-Method": "DELETE"},
        {"X-HTTP-Method-Override": "PUT"},
    ]

    for header_override in header_overrides:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            resp = requests.post(
                url,
                headers=header_override,
                **auth_kw,
                timeout=8,
                verify=False
            )
            if resp.status_code in [200, 201, 202, 204]:
                header_name = list(header_override.keys())[0]
                findings.append({
                    "type": f"Method Override via {header_name}",
                    "severity": "High",
                    "detail": f"POST + {header_name}: {header_override[header_name]} success (status {resp.status_code})",
                    "header": header_name,
                    "status_code": resp.status_code
                })
                logger.add_log(tool_name, "WARNING",
                    f"Method override via header accepted: {header_name}")
                break
        except Exception:
            pass

    # ── 4. Path traversal via method override ─────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing path manipulation with methods")
    path_variations = [
        url.rstrip("/") + "/",
        url.rstrip("/") + "/.",
        url.rstrip("/") + "/..;/",
        url + "%20",
        url + "%09",
    ]

    for alt_url in path_variations[:3]:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            for method in ["DELETE", "PUT"]:
                resp = requests.request(
                    method, alt_url,
                    **auth_kw,
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )
                if resp.status_code in [200, 201, 202, 204]:
                    if baseline_get and resp.status_code != baseline_get.status_code:
                        findings.append({
                            "type": "Path Manipulation Bypass",
                            "severity": "High",
                            "detail": f"{method} ke {alt_url} success (status {resp.status_code})",
                            "method": method,
                            "modified_url": alt_url
                        })
                        logger.add_log(tool_name, "WARNING",
                            f"Path manipulation bypass: {method} {alt_url}")
                        break
        except Exception:
            pass

    result = {
        "status": "VULNERABLE" if findings else "PROTECTED",
        "target": url,
        "findings": findings,
        "methods_tested": methods_to_test + ["POST+_method", "POST+header_override"],
        "note": "Method tampering bisa lead to unauthorized CRUD operations, data deletion, atau privilege escalation."
    }
    logger.add_log(tool_name, "SUCCESS", f"HTTP method tampering test selesai. Findings: {len(findings)}")
    return json.dumps(result, indent=2)

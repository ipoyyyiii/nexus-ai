import json
import requests
import re
import time
import uuid
import urllib3
from urllib.parse import quote, urlparse
from langchain.tools import tool
from rate_limiter import rate_limiter
from cancellation import check_cancelled
from auth_store import get_auth_kwargs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url

def _logger():
    from custom_tools import exec_logger
    return exec_logger


# ==========================================
# TOOL 1: 2FA Bypass Scanner
# ==========================================
@tool("twofa_bypass_scanner")
def twofa_bypass_scanner(url: str, login_url: str = "", username: str = "", password: str = "") -> str:
    """
    Scan untuk 2FA (Two-Factor Authentication) bypass vulnerabilities:
    - 2FA endpoint rate limiting (brute force OTP)
    - OTP code reuse (same code usable multiple times)
    - 2FA skip/bypass via direct navigation
    - Backup code exposure
    - OTP length/entropy check
    url: target base URL
    login_url: login endpoint (e.g., /login)
    username/password: credentials untuk test (opsional — test tanpa auth juga dilakukan)
    """
    tool_name = "2FA Bypass Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Memulai 2FA bypass scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")
    findings = {"vulnerabilities": [], "info": []}

    # ── 1. Find 2FA endpoints ─────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Finding 2FA/OTP endpoints")
    twofa_paths = [
        "/verify", "/otp", "/2fa", "/mfa", "/totp",
        "/verify-otp", "/verify-email", "/confirm",
        "/auth/2fa", "/api/verify", "/api/otp",
        "/security/verify", "/login/verify",
    ]
    found_endpoints = []
    for path in twofa_paths:
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{path}", timeout=4, verify=False)
            if r.status_code in [200, 401, 403] and any(kw in r.text.lower() for kw in
                ["otp", "verification", "code", "token", "2fa", "authenticator", "verify"]):
                found_endpoints.append(f"{base}{path}")
                findings["info"].append({"found_2fa_endpoint": f"{base}{path}"})
                logger.add_log(tool_name, "SUCCESS", f"2FA endpoint found: {path}")
        except Exception:
            pass

    # ── 2. Rate limiting check pada 2FA endpoint ──────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking rate limiting on 2FA endpoints")
    for endpoint in found_endpoints[:2]:
        if check_cancelled(logger): break
        responses = []
        # Send 10 rapid requests dengan wrong OTP
        for i in range(10):
            try:
                rate_limiter.wait(domain)
                r = requests.post(
                    endpoint,
                    data={"otp": f"{i:06d}", "code": f"{i:06d}", "token": f"{i:06d}"},
                    timeout=4, verify=False
                )
                responses.append(r.status_code)
            except Exception:
                pass

        # Jika tidak ada 429 atau lockout setelah 10 attempts = no rate limiting
        has_lockout = any(s in [429, 423, 403] for s in responses)
        if not has_lockout and len(responses) >= 8:
            findings["vulnerabilities"].append({
                "type": "Missing 2FA Rate Limiting",
                "endpoint": endpoint,
                "evidence": f"Sent {len(responses)} OTP attempts, no lockout/rate-limit (status codes: {set(responses)})",
                "severity": "High",
                "impact": "Attacker can brute-force 6-digit OTP (1M combinations) without lockout"
            })
            logger.add_log(tool_name, "WARNING", f"No 2FA rate limiting: {endpoint}")

    # ── 3. 2FA skip/bypass check ──────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing 2FA bypass via direct navigation")
    # Kalau ada session, coba akses protected pages langsung tanpa complete 2FA
    protected_paths = ["/dashboard", "/profile", "/settings", "/api/user", "/home", "/account"]
    if username and password and login_url:
        try:
            sess = requests.Session()
            rate_limiter.wait(domain)
            # Login tapi jangan complete 2FA
            sess.post(
                f"{base}{login_url}" if not login_url.startswith("http") else login_url,
                data={"username": username, "password": password},
                timeout=5, verify=False
            )
            # Try to access protected page directly
            for pp in protected_paths[:3]:
                try:
                    rate_limiter.wait(domain)
                    r = sess.get(f"{base}{pp}", timeout=4, verify=False, allow_redirects=False)
                    if r.status_code == 200 and any(kw in r.text.lower() for kw in
                        ["welcome", "dashboard", "profile", "logout"]):
                        findings["vulnerabilities"].append({
                            "type": "2FA Bypass via Direct Navigation",
                            "endpoint": f"{base}{pp}",
                            "evidence": "Accessed protected page without completing 2FA",
                            "severity": "Critical"
                        })
                        logger.add_log(tool_name, "WARNING", f"2FA bypass: direct access to {pp}")
                        break
                except Exception:
                    pass
        except Exception:
            pass

    # ── 4. Check backup codes exposure ────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking backup code exposure")
    backup_paths = [
        "/backup-codes", "/recovery-codes", "/api/backup-codes",
        "/settings/security/backup", "/account/recovery",
        "/2fa/backup", "/auth/backup-codes",
    ]
    for bp in backup_paths:
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{bp}", timeout=4, verify=False)
            if r.status_code == 200 and any(kw in r.text.lower() for kw in
                ["backup", "recovery", "code"]):
                # Check if codes are exposed without auth
                code_pattern = re.findall(r'\b[A-Z0-9]{4,8}(?:[-\s][A-Z0-9]{4,8})?\b', r.text)
                if code_pattern:
                    findings["vulnerabilities"].append({
                        "type": "Backup Codes Exposed Without Auth",
                        "endpoint": f"{base}{bp}",
                        "severity": "Critical"
                    })
                    logger.add_log(tool_name, "WARNING", f"Backup codes exposed: {bp}")
        except Exception:
            pass

    # ── 5. OTP entropy check ──────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking OTP entropy hints")
    for endpoint in found_endpoints[:1]:
        findings["info"].append({
            "otp_entropy_note": "Standard 6-digit OTP has 1M combinations. Without rate limiting, bruttable in minutes.",
            "endpoint": endpoint
        })

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else "SAFE",
        "findings": findings,
        "endpoints_found": found_endpoints
    }
    logger.add_log(tool_name, "SUCCESS", f"2FA bypass scan complete. Issues: {len(findings['vulnerabilities'])}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 2: Credential Stuffing Exposure Scanner
# ==========================================
@tool("credential_stuffing_scanner")
def credential_stuffing_scanner(url: str, login_url: str = "") -> str:
    """
    Scan untuk credential stuffing exposure — apakah login endpoint
    rentan terhadap serangan credential stuffing:
    - No rate limiting
    - No account lockout
    - No CAPTCHA
    - No IP-based blocking
    - Response timing yang konsisten (username enumeration)
    url: target base URL
    login_url: login endpoint path (e.g., /login, /api/auth)
    """
    tool_name = "Credential Stuffing Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Memulai credential stuffing scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")
    findings = {"vulnerabilities": [], "info": []}

    # Find login endpoint
    login_endpoint = None
    if login_url:
        login_endpoint = f"{base}{login_url}" if not login_url.startswith("http") else login_url
    else:
        for lp in ["/login", "/signin", "/api/login", "/api/auth", "/auth/login", "/api/v1/login"]:
            try:
                rate_limiter.wait(domain)
                r = requests.get(f"{base}{lp}", timeout=4, verify=False)
                if r.status_code in [200, 405] and any(kw in r.text.lower() for kw in
                    ["login", "password", "username", "signin"]):
                    login_endpoint = f"{base}{lp}"
                    logger.add_log(tool_name, "SUCCESS", f"Login endpoint found: {lp}")
                    break
            except Exception:
                pass

    if not login_endpoint:
        return json.dumps({"status": "SKIPPED", "reason": "No login endpoint detected"})

    findings["info"].append({"login_endpoint": login_endpoint})

    # ── 1. Rate limiting check ────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing rate limiting (15 rapid login attempts)")
    responses = []
    import time as _time
    start_time = _time.monotonic()

    for i in range(15):
        if check_cancelled(logger): break
        try:
            r = requests.post(
                login_endpoint,
                data={
                    "username": f"testuser{i}@example.com",
                    "email": f"testuser{i}@example.com",
                    "password": "WrongPass123!"
                },
                timeout=5, verify=False
            )
            responses.append({
                "attempt": i + 1,
                "status": r.status_code,
                "length": len(r.content)
            })
        except Exception:
            pass

    total_time = _time.monotonic() - start_time
    status_codes = [r["status"] for r in responses]
    has_rate_limit = any(s in [429, 423, 503] for s in status_codes)
    has_lockout = 403 in status_codes[5:]  # lockout setelah beberapa attempt

    if not has_rate_limit and not has_lockout and len(responses) >= 10:
        findings["vulnerabilities"].append({
            "type": "No Rate Limiting on Login",
            "evidence": f"{len(responses)} attempts in {total_time:.1f}s, no lockout (status codes: {set(status_codes)})",
            "severity": "High",
            "impact": "Credential stuffing attacks possible — attacker can try millions of creds"
        })
        logger.add_log(tool_name, "WARNING", "No rate limiting on login endpoint!")

    # ── 2. CAPTCHA check ──────────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking CAPTCHA presence")
    try:
        rate_limiter.wait(domain)
        r = requests.get(login_endpoint, timeout=5, verify=False)
        captcha_indicators = [
            "captcha", "recaptcha", "hcaptcha", "turnstile",
            "g-recaptcha", "cf-turnstile", "funcaptcha"
        ]
        has_captcha = any(ci in r.text.lower() for ci in captcha_indicators)
        if not has_captcha:
            findings["vulnerabilities"].append({
                "type": "No CAPTCHA on Login",
                "severity": "Medium",
                "impact": "Automated credential stuffing not blocked by CAPTCHA"
            })
            logger.add_log(tool_name, "WARNING", "No CAPTCHA detected on login page")
        else:
            findings["info"].append({"captcha": "CAPTCHA detected on login page"})
    except Exception:
        pass

    # ── 3. Account lockout check ───────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking account lockout policy")
    lockout_threshold_responses = responses[:10]
    locked_out = any(r["status"] in [423, 429] for r in lockout_threshold_responses[5:])
    if not locked_out and len(lockout_threshold_responses) >= 8:
        findings["vulnerabilities"].append({
            "type": "No Account Lockout Policy",
            "severity": "Medium",
            "evidence": f"10 failed attempts without account lockout",
            "impact": "Brute force attacks not mitigated by lockout"
        })

    # ── 4. Response consistency (timing attack) ────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking response timing consistency")
    try:
        times_valid_user = []
        times_invalid_user = []
        for _ in range(3):
            rate_limiter.wait(domain)
            t_start = _time.monotonic()
            requests.post(login_endpoint, data={"username": "admin", "password": "WrongPass"}, timeout=5, verify=False)
            times_valid_user.append(_time.monotonic() - t_start)

            rate_limiter.wait(domain)
            t_start = _time.monotonic()
            requests.post(login_endpoint, data={"username": "nonexistent_xyz999@fake.com", "password": "WrongPass"}, timeout=5, verify=False)
            times_invalid_user.append(_time.monotonic() - t_start)

        avg_valid = sum(times_valid_user) / len(times_valid_user)
        avg_invalid = sum(times_invalid_user) / len(times_invalid_user)
        timing_diff = abs(avg_valid - avg_invalid)

        if timing_diff > 0.3:  # >300ms difference = timing oracle
            findings["vulnerabilities"].append({
                "type": "Timing-Based Username Enumeration",
                "evidence": f"Response time diff: {timing_diff:.2f}s (valid: {avg_valid:.2f}s vs invalid: {avg_invalid:.2f}s)",
                "severity": "Medium"
            })
            logger.add_log(tool_name, "WARNING", f"Timing oracle: {timing_diff:.2f}s diff")
    except Exception:
        pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else "SAFE",
        "findings": findings
    }
    logger.add_log(tool_name, "SUCCESS", f"Credential stuffing scan complete. Issues: {len(findings['vulnerabilities'])}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 3: Mixed Content Scanner
# ==========================================
@tool("mixed_content_scanner")
def mixed_content_scanner(url: str) -> str:
    """
    Scan untuk Mixed Content vulnerability.
    HTTPS page yang load HTTP resources (scripts, images, iframes)
    rentan terhadap MITM dan content injection.
    url: HTTPS URL target
    """
    tool_name = "Mixed Content Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Memulai mixed content scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    findings = {"active_mixed_content": [], "passive_mixed_content": [], "info": {}}

    if not url.startswith("https://"):
        return json.dumps({
            "status": "SKIPPED",
            "reason": "Target is not HTTPS — mixed content only applies to HTTPS pages"
        })

    try:
        rate_limiter.wait(domain)
        r = requests.get(url, timeout=8, verify=False)
        body = r.text

        # Active mixed content (scripts, iframes, objects) — HIGH RISK
        # These can intercept/modify page behavior
        active_patterns = {
            "Script (HTTP)": re.findall(r'<script[^>]+src=["\']http://[^"\']+["\']', body, re.IGNORECASE),
            "Iframe (HTTP)": re.findall(r'<iframe[^>]+src=["\']http://[^"\']+["\']', body, re.IGNORECASE),
            "Form Action (HTTP)": re.findall(r'<form[^>]+action=["\']http://[^"\']+["\']', body, re.IGNORECASE),
            "Object/Embed (HTTP)": re.findall(r'<(?:object|embed)[^>]+(?:src|data)=["\']http://[^"\']+["\']', body, re.IGNORECASE),
            "Link preload (HTTP)": re.findall(r'<link[^>]+href=["\']http://[^"\']+["\'][^>]*rel=["\']preload["\']', body, re.IGNORECASE),
        }

        for content_type, matches in active_patterns.items():
            for match in matches[:5]:  # max 5 per type
                src = re.search(r'(?:src|data|href|action)=["\']([^"\']+)["\']', match)
                if src and src.group(1).startswith("http://"):
                    findings["active_mixed_content"].append({
                        "type": content_type,
                        "url": src.group(1)[:200],
                        "severity": "High",
                        "risk": "Attacker can MITM HTTP resource and inject malicious code"
                    })

        # Passive mixed content (images, audio, video) — MEDIUM RISK
        passive_patterns = {
            "Image (HTTP)": re.findall(r'<img[^>]+src=["\']http://[^"\']+["\']', body, re.IGNORECASE),
            "Audio (HTTP)": re.findall(r'<audio[^>]+src=["\']http://[^"\']+["\']', body, re.IGNORECASE),
            "Video (HTTP)": re.findall(r'<video[^>]+src=["\']http://[^"\']+["\']', body, re.IGNORECASE),
            "CSS (HTTP)": re.findall(r'<link[^>]+href=["\']http://[^"\']+\.css["\']', body, re.IGNORECASE),
        }

        for content_type, matches in passive_patterns.items():
            for match in matches[:5]:
                src = re.search(r'(?:src|href)=["\']([^"\']+)["\']', match)
                if src and src.group(1).startswith("http://"):
                    findings["passive_mixed_content"].append({
                        "type": content_type,
                        "url": src.group(1)[:200],
                        "severity": "Medium",
                        "risk": "Attacker can replace HTTP resource (image swapping, etc)"
                    })

        # Check CSP upgrade-insecure-requests
        csp = r.headers.get("Content-Security-Policy", "")
        upgrade_requests = "upgrade-insecure-requests" in csp
        findings["info"] = {
            "upgrade_insecure_requests": upgrade_requests,
            "total_active": len(findings["active_mixed_content"]),
            "total_passive": len(findings["passive_mixed_content"])
        }

        if not upgrade_requests and (findings["active_mixed_content"] or findings["passive_mixed_content"]):
            logger.add_log(tool_name, "WARNING",
                f"Mixed content: {len(findings['active_mixed_content'])} active, {len(findings['passive_mixed_content'])} passive")

    except Exception as e:
        logger.add_log(tool_name, "ERROR", f"Mixed content scan error: {e}")
        findings["error"] = str(e)

    total = len(findings["active_mixed_content"]) + len(findings["passive_mixed_content"])
    result = {
        "status": "VULNERABLE" if total > 0 else "SAFE",
        "findings": findings,
        "total_mixed_content": total
    }
    logger.add_log(tool_name, "SUCCESS", f"Mixed content scan complete. Found: {total}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 4: IDOR via Hash/UUID Scanner
# ==========================================
@tool("idor_uuid_scanner")
def idor_uuid_scanner(url: str, cookies: str = "", auth_header: str = "") -> str:
    """
    Scan untuk IDOR menggunakan UUID/Hash manipulation:
    - Sequential UUID prediction
    - Hash-based ID bruteforce hints
    - UUID v1 (timestamp-based) predictability
    - Weak hash patterns (MD5, SHA1 of integer)
    - API endpoint ID enumeration
    url: target URL yang mengandung ID (e.g., /api/user/550e8400-e29b-41d4-a716-446655440000)
    cookies: optional session cookies
    auth_header: optional Authorization header value
    """
    tool_name = "IDOR UUID Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Memulai IDOR UUID scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    findings = {"vulnerabilities": [], "info": [], "uuid_analysis": {}}

    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header
    cookie_dict = {}
    if cookies:
        for part in cookies.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    # ── 1. Analyze UUID in URL ────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Analyzing UUID patterns in URL")
    uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f]{4})-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
    uuid_matches = uuid_pattern.findall(url)

    if uuid_matches:
        for version_hex in uuid_matches:
            version = int(version_hex[0], 16)
            findings["uuid_analysis"]["version"] = version
            if version == 1:
                findings["info"].append({
                    "issue": "UUID v1 detected (timestamp-based)",
                    "detail": "UUID v1 encodes timestamp — sequential UUIDs are predictable. Attacker can predict other valid UUIDs.",
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", "UUID v1 (timestamp-based) detected — predictable!")

    # ── 2. ID pattern detection in URL ────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Detecting ID patterns in URL")
    # Extract numeric IDs
    numeric_id_match = re.search(r'/(\d+)(?:/|$|\?)', url)
    # Extract hash-looking IDs (MD5/SHA1)
    hash_id_match = re.search(r'/([a-f0-9]{32}|[a-f0-9]{40})(?:/|$|\?)', url, re.IGNORECASE)

    if numeric_id_match:
        current_id = int(numeric_id_match.group(1))
        findings["info"].append({
            "type": "Numeric ID in URL",
            "value": current_id,
            "note": "Sequential numeric IDs are most commonly exploitable for IDOR"
        })

        # Test adjacent IDs
        base_url_template = url.replace(str(current_id), "{ID}", 1)
        logger.add_log(tool_name, "PROCESSING", f"Testing adjacent IDs around {current_id}")

        accessible_ids = []
        test_ids = list(range(max(1, current_id - 5), current_id)) + list(range(current_id + 1, current_id + 6))

        for test_id in test_ids:
            if check_cancelled(logger): break
            try:
                test_url = base_url_template.replace("{ID}", str(test_id))
                rate_limiter.wait(domain)
                r = requests.get(test_url, headers=headers, cookies=cookie_dict, timeout=5, verify=False)

                if r.status_code == 200 and len(r.content) > 50:
                    accessible_ids.append({
                        "id": test_id,
                        "url": test_url,
                        "size": len(r.content),
                        "status": 200
                    })
            except Exception:
                pass

        if accessible_ids:
            findings["vulnerabilities"].append({
                "type": "IDOR via Sequential Numeric ID",
                "current_id": current_id,
                "accessible_other_ids": accessible_ids,
                "count": len(accessible_ids),
                "severity": "High",
                "detail": f"Accessed {len(accessible_ids)} other records by changing numeric ID"
            })
            logger.add_log(tool_name, "WARNING",
                f"IDOR confirmed: {len(accessible_ids)} IDs accessible around ID {current_id}")

    if hash_id_match:
        hash_val = hash_id_match.group(1)
        hash_len = len(hash_val)
        hash_type = "MD5" if hash_len == 32 else "SHA1"
        findings["info"].append({
            "type": f"{hash_type} Hash ID in URL",
            "value": hash_val,
            "note": f"{hash_type} of integer IDs is easily reversible — attacker can hash integers 1,2,3... to enumerate"
        })

        # Check if it's MD5 of small integers (common mistake)
        import hashlib
        for i in range(1, 1000):
            if hashlib.md5(str(i).encode()).hexdigest() == hash_val.lower():
                findings["vulnerabilities"].append({
                    "type": "Weak Hash IDOR (MD5 of integer)",
                    "hash": hash_val,
                    "original_id": i,
                    "severity": "High",
                    "detail": f"Hash is MD5({i}) — trivially enumerable"
                })
                logger.add_log(tool_name, "WARNING", f"Weak hash IDOR: MD5({i}) = {hash_val}")
                break
            if hashlib.sha1(str(i).encode()).hexdigest() == hash_val.lower():
                findings["vulnerabilities"].append({
                    "type": "Weak Hash IDOR (SHA1 of integer)",
                    "hash": hash_val,
                    "original_id": i,
                    "severity": "High"
                })
                break

    # ── 3. Common API patterns ────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing common IDOR API patterns")
    base = url.rstrip("/")
    api_patterns = [
        f"{base}?id=1", f"{base}?user_id=1", f"{base}?account=1",
        f"{base}?order_id=1", f"{base}?invoice=1",
    ]
    for api_url in api_patterns:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            r = requests.get(api_url, headers=headers, cookies=cookie_dict, timeout=4, verify=False)
            if r.status_code == 200 and len(r.content) > 100:
                findings["info"].append({
                    "accessible_with_id_1": api_url,
                    "status": 200,
                    "note": "Resource accessible with id=1 — test with different user's ID for IDOR"
                })
        except Exception:
            pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else "SAFE",
        "findings": findings
    }
    logger.add_log(tool_name, "SUCCESS", f"IDOR UUID scan complete. Issues: {len(findings['vulnerabilities'])}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 5: Postmessage Vulnerability Scanner
# ==========================================
@tool("postmessage_vulnerability_scanner")
def postmessage_vulnerability_scanner(url: str) -> str:
    """
    Scan untuk postMessage vulnerability:
    - window.addEventListener('message') tanpa origin check
    - Insecure postMessage usage di JavaScript
    - Cross-origin message injection potential
    url: target URL
    """
    tool_name = "PostMessage Vulnerability Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Memulai postMessage scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    findings = {"vulnerabilities": [], "suspicious": [], "postmessage_usage": []}

    try:
        rate_limiter.wait(domain)
        r = requests.get(url, timeout=8, verify=False)
        body = r.text

        # ── 1. Find postMessage listeners ────────────────────────────────────
        logger.add_log(tool_name, "PROCESSING", "Analyzing JavaScript for postMessage usage")

        # Pattern: addEventListener('message', ...) tanpa origin check
        listener_pattern = re.findall(
            r'addEventListener\s*\(\s*["\']message["\'].*?(?:function|\()',
            body, re.IGNORECASE | re.DOTALL
        )

        for match in listener_pattern[:10]:
            findings["postmessage_usage"].append({
                "code_snippet": match[:200].strip()
            })

        # Pattern: window.onmessage
        onmessage_pattern = re.findall(r'(?:window\.)?onmessage\s*=', body, re.IGNORECASE)
        if onmessage_pattern:
            findings["postmessage_usage"].append({"type": "window.onmessage assignment found"})

        # ── 2. Check for missing origin validation ────────────────────────────
        logger.add_log(tool_name, "PROCESSING", "Checking for missing origin validation")

        # Dangerous pattern: message listener exists but no origin/source check nearby
        has_message_listener = bool(listener_pattern or onmessage_pattern)
        has_origin_check = bool(re.search(
            r'(?:event|e|msg)\.origin\s*(?:===|!==|==)',
            body, re.IGNORECASE
        ))
        has_source_check = bool(re.search(
            r'(?:event|e|msg)\.source',
            body, re.IGNORECASE
        ))

        if has_message_listener and not has_origin_check:
            findings["vulnerabilities"].append({
                "type": "PostMessage Without Origin Check",
                "severity": "High",
                "detail": "window.addEventListener('message') found without origin validation",
                "impact": "Any cross-origin page can send malicious messages to this page",
                "recommendation": "Add: if (event.origin !== 'https://trusted-domain.com') return;"
            })
            logger.add_log(tool_name, "WARNING", "postMessage listener without origin check!")
        elif has_message_listener:
            findings["suspicious"].append({
                "type": "PostMessage with Partial Origin Check",
                "has_origin_check": has_origin_check,
                "has_source_check": has_source_check,
                "note": "Origin check detected but manual verification needed"
            })

        # ── 3. Check for postMessage senders (potential data leaks) ───────────
        logger.add_log(tool_name, "PROCESSING", "Checking postMessage senders")
        sender_pattern = re.findall(
            r'(?:parent|opener|top|window)\.postMessage\s*\([^)]+\)',
            body, re.IGNORECASE
        )
        for sender in sender_pattern[:5]:
            findings["suspicious"].append({
                "type": "postMessage Sender Found",
                "code": sender[:150],
                "note": "Check if sensitive data is being sent via postMessage"
            })

        # ── 4. Check for wildcard postMessage target origin ───────────────────
        wildcard_sender = re.findall(
            r'\.postMessage\s*\([^,]+,\s*["\']?\*["\']?\s*\)',
            body, re.IGNORECASE
        )
        for ws in wildcard_sender:
            findings["vulnerabilities"].append({
                "type": "postMessage with Wildcard Target Origin (*)",
                "code": ws[:150],
                "severity": "Medium",
                "detail": "Data sent to '*' can be intercepted by any iframe or opener window"
            })
            logger.add_log(tool_name, "WARNING", "postMessage with wildcard target origin!")

    except Exception as e:
        logger.add_log(tool_name, "ERROR", f"PostMessage scan error: {e}")
        findings["error"] = str(e)

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else (
            "SUSPICIOUS" if findings["suspicious"] else "SAFE"
        ),
        "findings": findings,
        "note": "postMessage vulns require manual browser testing to confirm exploitability"
    }
    logger.add_log(tool_name, "SUCCESS", "PostMessage scan complete")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 6: ASN / IP Range Mapper
# ==========================================
@tool("asn_ip_mapper")
def asn_ip_mapper(domain_or_ip: str) -> str:
    """
    Map ASN (Autonomous System Number) dan IP ranges untuk target.
    Berguna buat expand attack surface — temukan semua IP/subnet yang dimiliki
    organisasi target (bisa ada server lain yang gak diketahui).
    domain_or_ip: target domain atau IP address (e.g., "example.com" atau "93.184.216.34")
    """
    tool_name = "ASN IP Mapper"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Memulai ASN mapping untuk {domain_or_ip}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    import socket
    findings = {
        "ip_addresses": [],
        "asn_info": {},
        "ip_ranges": [],
        "related_domains": [],
        "additional_ips": []
    }

    # ── 1. Resolve domain to IP ───────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Resolving domain to IP addresses")
    target_ip = domain_or_ip
    try:
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_or_ip):
            # It's a domain — resolve all IPs
            all_ips = socket.getaddrinfo(domain_or_ip, None)
            unique_ips = list(set(info[4][0] for info in all_ips if ':' not in info[4][0]))  # IPv4 only
            findings["ip_addresses"] = unique_ips
            target_ip = unique_ips[0] if unique_ips else domain_or_ip
            logger.add_log(tool_name, "SUCCESS", f"Resolved {domain_or_ip} → {unique_ips}")
        else:
            findings["ip_addresses"] = [domain_or_ip]
    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"DNS resolution failed: {e}")

    # ── 2. ASN lookup via ip-api.com ──────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Querying ASN information")
    try:
        rate_limiter.wait("ip-api.com")
        r = requests.get(
            f"http://ip-api.com/json/{target_ip}?fields=status,country,regionName,city,isp,org,as,asname,query",
            timeout=8
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                findings["asn_info"] = {
                    "ip": data.get("query"),
                    "asn": data.get("as"),
                    "asn_name": data.get("asname"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "country": data.get("country"),
                    "city": data.get("city"),
                }
                logger.add_log(tool_name, "SUCCESS", f"ASN: {data.get('as')} ({data.get('asname')})")
    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"ASN lookup failed: {e}")

    # ── 3. IP range lookup via BGPView API ────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Querying BGPView for IP ranges")
    try:
        asn_number = None
        if findings["asn_info"].get("asn"):
            asn_match = re.search(r'AS(\d+)', findings["asn_info"]["asn"])
            if asn_match:
                asn_number = asn_match.group(1)

        if asn_number:
            rate_limiter.wait("bgpview.io")
            r = requests.get(
                f"https://api.bgpview.io/asn/{asn_number}/prefixes",
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if r.status_code == 200:
                data = r.json()
                prefixes = data.get("data", {}).get("ipv4_prefixes", [])
                findings["ip_ranges"] = [
                    {
                        "prefix": p.get("prefix"),
                        "name": p.get("name"),
                        "description": p.get("description", "")[:100]
                    }
                    for p in prefixes[:20]  # limit to 20
                ]
                logger.add_log(tool_name, "SUCCESS",
                    f"Found {len(prefixes)} IP ranges for AS{asn_number}")
    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"BGPView lookup failed: {e}")

    # ── 4. Reverse DNS on target IP ───────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Reverse DNS lookup")
    try:
        hostname = socket.gethostbyaddr(target_ip)
        if hostname[0] != domain_or_ip:
            findings["related_domains"].append({
                "domain": hostname[0],
                "source": "Reverse DNS",
                "ip": target_ip
            })
            logger.add_log(tool_name, "SUCCESS", f"Reverse DNS: {target_ip} → {hostname[0]}")
    except Exception:
        pass

    # ── 5. Summary for pentest ────────────────────────────────────────────────
    findings["pentest_summary"] = {
        "total_ip_ranges": len(findings["ip_ranges"]),
        "note": "Use IP ranges above to discover additional hosts owned by the same organization. Tools: nmap, masscan",
        "next_steps": [
            "Scan IP ranges with nmap/masscan for live hosts",
            "Check each live host for same vulnerabilities",
            "Look for internal-only services exposed on non-standard ports"
        ]
    }

    logger.add_log(tool_name, "SUCCESS",
        f"ASN mapping complete. ASN: {findings['asn_info'].get('asn', 'N/A')}, Ranges: {len(findings['ip_ranges'])}")
    return json.dumps(findings, indent=2)

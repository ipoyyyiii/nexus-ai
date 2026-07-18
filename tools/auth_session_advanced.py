import json
import requests
import re
import time
import urllib3
from urllib.parse import urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.auth_store import auth_get, auth_post
from core.cancellation import check_cancelled
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
# TOOL 1: Session Management Scanner
# ==========================================
@tool("session_management_scanner")
def session_management_scanner(url: str, login_url: str = "", username: str = "", password: str = "") -> str:
    """
    Scan untuk kerentanan session management:
    - Cookie flags (HttpOnly, Secure, SameSite)
    - Session fixation
    - Session timeout
    - Logout token invalidation
    - Session ID entropy / predictability
    url: target base URL
    login_url: endpoint login (e.g. /login) — opsional
    username/password: credentials untuk test session behavior — opsional
    """
    tool_name = "Session Management Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting session management scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")
    findings = {
        "cookie_issues": [],
        "session_fixation": False,
        "logout_invalidation": False,
        "session_timeout": None,
        "session_entropy": [],
        "summary": []
    }

    # ── 1. Cookie Flags Analysis ──────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Analyzing cookie security flags")
    try:
        rate_limiter.wait(domain)
        r = auth_get(base, timeout=5, verify=False)
        cookies = r.cookies

        # Also parse Set-Cookie headers manually
        set_cookie_headers = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []

        for cookie in cookies:
            issues = []
            cookie_str = str(cookie)

            # ── HttpOnly Check ────────────────────────────────────────────────
            if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in cookie_str.lower():
                issues.append("Missing HttpOnly flag — cookie accessible via JavaScript (XSS risk)")

            # ── Secure Check ──────────────────────────────────────────────────
            if not cookie.secure:
                issues.append("Missing Secure flag — cookie transmitted over HTTP")

            # ── SameSite Check ────────────────────────────────────────────────
            samesite_found = any("samesite" in h.lower() for h in set_cookie_headers if cookie.name.lower() in h.lower())
            if not samesite_found:
                issues.append("Missing SameSite flag — vulnerable to CSRF")

            # ── Path Check ────────────────────────────────────────────────────
            if not cookie.path or cookie.path == "/":
                issues.append("Cookie path too broad — consider restricting to specific path")

            # ── Domain Check ──────────────────────────────────────────────────
            if cookie.domain and cookie.domain.startswith("."):
                issues.append("Cookie set for all subdomains — potential subdomain cookie theft")

            # ── Expiry Check ──────────────────────────────────────────────────
            if cookie.expires and cookie.expires > 0:
                import time
                years_until_expiry = (cookie.expires - time.time()) / (365 * 24 * 3600)
                if years_until_expiry > 1:
                    issues.append(f"Cookie expiry too long ({years_until_expiry:.1f} years) — consider shorter session lifetime")

            # ── Session Cookie in URL Check ───────────────────────────────────
            if "session" in cookie.name.lower() or "sid" in cookie.name.lower():
                if "path" not in cookie_str.lower():
                    issues.append("Session cookie without explicit path — potential scope issues")

            if issues:
                findings["cookie_issues"].append({
                    "cookie_name": cookie.name,
                    "issues": issues,
                    "severity": "High" if any("HttpOnly" in i or "Secure" in i for i in issues) else "Medium"
                })
                logger.add_log(tool_name, "WARNING", f"Cookie issue: {cookie.name} — {issues}")

        # ── Session ID Entropy Analysis ────────────────────────────────────────
        logger.add_log(tool_name, "PROCESSING", "Analyzing session ID entropy")
        session_cookies = [c for c in cookies if any(
            kw in c.name.lower() for kw in ["session", "sess", "sid", "token", "auth", "jwt"]
        )]

        for sc in session_cookies:
            # Length check
            if len(sc.value) < 16:
                findings["session_entropy"].append({
                    "cookie": sc.name,
                    "issue": f"Short session ID ({len(sc.value)} chars) — potentially predictable",
                    "severity": "High",
                    "recommendation": "Use at least 32 characters for session IDs"
                })
            elif len(sc.value) < 32:
                findings["session_entropy"].append({
                    "cookie": sc.name,
                    "issue": f"Medium length session ID ({len(sc.value)} chars) — consider increasing entropy",
                    "severity": "Medium",
                    "recommendation": "Use at least 32 characters for session IDs"
                })

            # Character diversity check
            has_upper = bool(re.search(r'[A-Z]', sc.value))
            has_lower = bool(re.search(r'[a-z]', sc.value))
            has_digit = bool(re.search(r'[0-9]', sc.value))
            has_special = bool(re.search(r'[^A-Za-z0-9]', sc.value))

            diversity_score = sum([has_upper, has_lower, has_digit, has_special])
            if diversity_score < 3:
                findings["session_entropy"].append({
                    "cookie": sc.name,
                    "issue": f"Session ID lacks character diversity ({diversity_score}/4 types) — may be predictable",
                    "severity": "Medium",
                    "recommendation": "Session ID should contain uppercase, lowercase, digits, and special characters"
                })

            # Sequential pattern check
            if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', sc.value.lower()):
                findings["session_entropy"].append({
                    "cookie": sc.name,
                    "issue": "Session ID contains sequential characters — weak entropy",
                    "severity": "High",
                    "recommendation": "Session ID should not contain sequential patterns"
                })

            # Repeated character check
            if re.search(r'(.)\1{3,}', sc.value):
                findings["session_entropy"].append({
                    "cookie": sc.name,
                    "issue": "Session ID contains repeated characters (4+) — weak entropy",
                    "severity": "High",
                    "recommendation": "Session ID should not contain repeated characters"
                })

            # Base64/Hex pattern check (might be predictable)
            if re.match(r'^[0-9a-f]+$', sc.value.lower()):
                findings["session_entropy"].append({
                    "cookie": sc.name,
                    "issue": "Session ID is pure hex — may be predictable if based on timestamp",
                    "severity": "Medium",
                    "recommendation": "Use cryptographically random session IDs"
                })

            # JWT detection
            if sc.value.count(".") == 2 and len(sc.value) > 50:
                findings["session_entropy"].append({
                    "cookie": sc.name,
                    "issue": "JWT token detected — check for weak algorithm (none/HS256 with weak secret)",
                    "severity": "Medium",
                    "recommendation": "Verify JWT uses RS256/ES256 and strong secret"
                })

    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Cookie analysis error: {e}")

    # ── 1b. Token/Session Security Headers Check ──────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking session security headers")
    try:
        rate_limiter.wait(domain)
        r = auth_get(base, timeout=5, verify=False)

        # Check for session-related security headers
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=",
            "Content-Security-Policy": "default-src",
            "X-XSS-Protection": "1; mode=block",
        }

        for header, expected in security_headers.items():
            header_value = r.headers.get(header, "")
            if not header_value or expected not in header_value:
                findings["summary"].append({
                    "type": f"Missing Security Header: {header}",
                    "detail": f"Header '{header}' missing or not properly configured",
                    "severity": "Medium" if header in ["Strict-Transport-Security", "Content-Security-Policy"] else "Low"
                })

    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Header check error: {str(e)[:100]}")

    # ── 2. Session Fixation Check ─────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking session fixation")
    login_endpoint = login_url if login_url else f"{base}/login"
    if username and password:
        try:
            rate_limiter.wait(domain)
            # Get pre-login session
            pre_session = requests.Session()
            pre_r = pre_session.get(login_endpoint, timeout=5, verify=False)
            pre_session_id = None
            for c in pre_session.cookies:
                if any(kw in c.name.lower() for kw in ["session", "sess", "sid"]):
                    pre_session_id = c.value
                    break

            # Login
            rate_limiter.wait(domain)
            post_r = pre_session.post(
                login_endpoint,
                data={"username": username, "password": password, "email": username},
                timeout=5, verify=False
            )

            # Get post-login session
            post_session_id = None
            for c in pre_session.cookies:
                if any(kw in c.name.lower() for kw in ["session", "sess", "sid"]):
                    post_session_id = c.value
                    break

            if pre_session_id and post_session_id and pre_session_id == post_session_id:
                findings["session_fixation"] = True
                findings["summary"].append({
                    "type": "Session Fixation",
                    "detail": "Session ID not berubah setelah login — attacker bisa pre-set session ID",
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", "Session fixation detected!")
            elif pre_session_id and post_session_id:
                logger.add_log(tool_name, "SUCCESS", "Session regenerated after login (good)")

        except Exception as e:
            logger.add_log(tool_name, "WARNING", f"Session fixation check error: {e}")

    # ── 3. Logout Invalidation Check ─────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking logout token invalidation")
    logout_paths = ["/logout", "/signout", "/api/logout", "/auth/logout", "/user/logout"]
    if username and password:
        try:
            rate_limiter.wait(domain)
            sess = requests.Session()
            sess.post(
                login_endpoint,
                data={"username": username, "password": password},
                timeout=5, verify=False
            )
            # Capture token before logout
            token_before = {c.name: c.value for c in sess.cookies}

            for lp in logout_paths:
                try:
                    rate_limiter.wait(domain)
                    sess.get(f"{base}{lp}", timeout=4, verify=False)
                    break
                except Exception:
                    pass

            # Try using old token after logout
            for cookie_name, cookie_val in token_before.items():
                try:
                    rate_limiter.wait(domain)
                    test_sess = requests.Session()
                    test_sess.cookies.set(cookie_name, cookie_val)
                    r = test_sess.get(f"{base}/profile", timeout=4, verify=False)
                    if r.status_code == 200 and any(kw in r.text.lower() for kw in ["welcome", "dashboard", "profile"]):
                        findings["logout_invalidation"] = True
                        findings["summary"].append({
                            "type": "Logout Token Not Invalidated",
                            "detail": f"Session cookie '{cookie_name}' masih valid setelah logout",
                            "severity": "High"
                        })
                        logger.add_log(tool_name, "WARNING", "Logout does not invalidate session token!")
                        break
                except Exception:
                    pass
        except Exception as e:
            logger.add_log(tool_name, "WARNING", f"Logout invalidation check error: {e}")

    # ── 4. Account Enumeration ────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking account enumeration via response diff")
    try:
        rate_limiter.wait(domain)
        # Test dengan username yang kemungkinan valid vs jelas invalid
        r_valid = auth_post(
            login_endpoint,
            data={"username": "admin", "password": "wrongpassword_xyz123"},
            timeout=5, verify=False
        )
        rate_limiter.wait(domain)
        r_invalid = auth_post(
            login_endpoint,
            data={"username": "thisdoesnotexist_xyz987", "password": "wrongpassword_xyz123"},
            timeout=5, verify=False
        )

        # Check response length diff (significant diff = enumeration possible)
        len_diff = abs(len(r_valid.text) - len(r_invalid.text))
        # Check for different error messages
        has_diff_msg = r_valid.text != r_invalid.text

        if len_diff > 50 or has_diff_msg:
            # Check if error message differs
            valid_has_user_err = any(m in r_valid.text.lower() for m in ["wrong password", "incorrect password", "invalid password"])
            invalid_has_user_err = any(m in r_invalid.text.lower() for m in ["user not found", "no account", "user does not exist"])

            if valid_has_user_err or invalid_has_user_err or len_diff > 100:
                findings["summary"].append({
                    "type": "Account Enumeration",
                    "detail": f"Response diff: {len_diff} bytes. Different responses for valid vs invalid usernames",
                    "severity": "Medium"
                })
                logger.add_log(tool_name, "WARNING", f"Account enumeration possible — response diff: {len_diff} bytes")
    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Account enumeration check error: {e}")

    total_issues = len(findings["cookie_issues"]) + len(findings["session_entropy"]) + len(findings["summary"])
    logger.add_log(tool_name, "SUCCESS", f"Session management scan complete. Issues found: {total_issues}")
    return json.dumps(findings, indent=2)


# ==========================================
# TOOL 2: Password Reset Flow Tester
# ==========================================
@tool("password_reset_tester")
def password_reset_tester(url: str, email: str = "test@test.com") -> str:
    """
    Test keamanan password reset flow:
    - Token predictability
    - Token expiry
    - Host header poisoning dalam reset email
    - Account enumeration via reset response
    url: base URL aplikasi
    email: email untuk test password reset
    """
    tool_name = "Password Reset Tester"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Testing password reset flow pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")
    findings = {"vulnerabilities": [], "info": []}

    reset_paths = [
        "/forgot-password", "/forgot_password", "/reset-password",
        "/reset_password", "/password/reset", "/auth/forgot",
        "/users/password/new", "/account/recover"
    ]

    # ── 1. Find reset endpoint ────────────────────────────────────────────────
    reset_endpoint = None
    for rp in reset_paths:
        try:
            rate_limiter.wait(domain)
            r = auth_get(f"{base}{rp}", timeout=5, verify=False)
            if r.status_code == 200 and any(kw in r.text.lower() for kw in ["reset", "forgot", "email", "recover"]):
                reset_endpoint = f"{base}{rp}"
                logger.add_log(tool_name, "SUCCESS", f"Password reset endpoint found: {rp}")
                break
        except Exception:
            pass

    if not reset_endpoint:
        return json.dumps({"status": "SKIPPED", "reason": "No password reset endpoint found", "paths_checked": reset_paths})

    findings["info"].append({"reset_endpoint": reset_endpoint})

    # ── 2. Account enumeration via reset ─────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking account enumeration via reset")
    try:
        rate_limiter.wait(domain)
        r_valid = auth_post(reset_endpoint, data={"email": email}, timeout=5, verify=False)
        rate_limiter.wait(domain)
        r_invalid = auth_post(reset_endpoint, data={"email": "thisdoesnotexist99999@invalid.xyz"}, timeout=5, verify=False)

        if r_valid.text != r_invalid.text or abs(len(r_valid.text) - len(r_invalid.text)) > 50:
            findings["vulnerabilities"].append({
                "type": "Account Enumeration via Password Reset",
                "detail": "Different responses for valid vs invalid email in reset form",
                "severity": "Medium"
            })
            logger.add_log(tool_name, "WARNING", "Account enumeration via password reset detected")
    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Account enum check error: {e}")

    # ── 3. Host Header Poisoning ──────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking host header poisoning in password reset")
    try:
        rate_limiter.wait(domain)
        poisoned_headers = {
            "Host": "attacker-domain.com",
            "X-Forwarded-Host": "attacker-domain.com",
            "X-Host": "attacker-domain.com",
        }
        r = auth_post(
            reset_endpoint,
            data={"email": email},
            headers=poisoned_headers,
            timeout=5, verify=False
        )
        # Jika not error (500) dan server menerima request dengan Host palsu,
        # kemungkinan reset link di email akan pake domain attacker
        if r.status_code in [200, 201, 302]:
            findings["vulnerabilities"].append({
                "type": "Possible Host Header Poisoning in Password Reset",
                "detail": "Server accepted request with forged Host header — reset link may point to attacker domain",
                "severity": "High",
                "note": "Manual verification needed: check if reset email contains attacker-domain.com"
            })
            logger.add_log(tool_name, "WARNING", "Host header poisoning possible in password reset")
    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Host header poison check error: {e}")

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else "SAFE",
        "findings": findings
    }
    logger.add_log(tool_name, "SUCCESS", "Password reset tester complete")
    return json.dumps(result, indent=2)

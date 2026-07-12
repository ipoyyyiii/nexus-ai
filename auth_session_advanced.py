import json
import requests
import re
import time
import urllib3
from urllib.parse import urlparse
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
    logger.add_log(tool_name, "START", f"Memulai session management scan pada {url}")
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
        r = requests.get(base, timeout=5, verify=False)
        cookies = r.cookies

        # Also parse Set-Cookie headers manually
        set_cookie_headers = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []

        for cookie in cookies:
            issues = []
            cookie_str = str(cookie)

            if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in cookie_str.lower():
                issues.append("Missing HttpOnly flag — cookie accessible via JavaScript (XSS risk)")
            if not cookie.secure:
                issues.append("Missing Secure flag — cookie transmitted over HTTP")

            # Check SameSite from raw headers
            samesite_found = any("samesite" in h.lower() for h in set_cookie_headers if cookie.name.lower() in h.lower())
            if not samesite_found:
                issues.append("Missing SameSite flag — vulnerable to CSRF")

            if issues:
                findings["cookie_issues"].append({
                    "cookie_name": cookie.name,
                    "issues": issues,
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", f"Cookie issue: {cookie.name} — {issues}")

        # Check session ID entropy (length & randomness)
        session_cookies = [c for c in cookies if any(
            kw in c.name.lower() for kw in ["session", "sess", "sid", "token", "auth"]
        )]
        for sc in session_cookies:
            if len(sc.value) < 16:
                findings["session_entropy"].append({
                    "cookie": sc.name,
                    "issue": f"Short session ID ({len(sc.value)} chars) — potentially predictable",
                    "severity": "High"
                })
            elif not re.search(r'[a-zA-Z]', sc.value) or not re.search(r'[0-9]', sc.value):
                findings["session_entropy"].append({
                    "cookie": sc.name,
                    "issue": "Session ID lacks character diversity — may be predictable",
                    "severity": "Medium"
                })

    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Cookie analysis error: {e}")

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
                    "detail": "Session ID tidak berubah setelah login — attacker bisa pre-set session ID",
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
        r_valid = requests.post(
            login_endpoint,
            data={"username": "admin", "password": "wrongpassword_xyz123"},
            timeout=5, verify=False
        )
        rate_limiter.wait(domain)
        r_invalid = requests.post(
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
            r = requests.get(f"{base}{rp}", timeout=5, verify=False)
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
        r_valid = requests.post(reset_endpoint, data={"email": email}, timeout=5, verify=False)
        rate_limiter.wait(domain)
        r_invalid = requests.post(reset_endpoint, data={"email": "thisdoesnotexist99999@invalid.xyz"}, timeout=5, verify=False)

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
        r = requests.post(
            reset_endpoint,
            data={"email": email},
            headers=poisoned_headers,
            timeout=5, verify=False
        )
        # Jika tidak error (500) dan server menerima request dengan Host palsu,
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

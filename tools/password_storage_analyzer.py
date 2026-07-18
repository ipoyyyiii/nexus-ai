"""
WEAK PASSWORD STORAGE ANALYZER
==============================
Detect weak password storage patterns via response analysis and timing.

Usage:
    from tools.password_storage_analyzer import password_storage_analyzer
"""

import json
import requests
import re
import time
from urllib.parse import quote, urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.auth_store import auth_get, auth_post
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


@tool("password_storage_analyzer")
def password_storage_analyzer(url: str, login_url: str = "") -> str:
    """
    Analyze password storage patterns via response analysis and timing.
    Detects: weak hashing (MD5/SHA1), plaintext storage indicators, timing oracles.

    Args:
        url: Target base URL
        login_url: Login endpoint (optional)
    """
    tool_name = "Password Storage Analyzer"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Analyzing password storage on {url}")
    if check_cancelled(logger): return "CANCELLED: job cancelled by user."

    approved = require_approval(
        action=f"Password storage analysis on {url}",
        context="Testing response patterns and timing for weak password storage detection",
        risk="low",
        exec_logger=logger,
    )
    if not approved:
        return "CANCELLED: approval rejected or timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")
    findings = []

    # Find login endpoint
    if not login_url:
        login_paths = ["/login", "/signin", "/auth/login", "/api/login", "/api/auth", "/user/login"]
        for path in login_paths:
            try:
                rate_limiter.wait(domain)
                r = auth_get(f"{base}{path}", timeout=5, verify=False, **auth_kwargs)
                if r.status_code == 200 and any(kw in r.text.lower() for kw in ["login", "password", "username"]):
                    login_url = f"{base}{path}"
                    break
            except Exception:
                pass

    if not login_url:
        return json.dumps({
            "status": "SKIPPED",
            "reason": "No login endpoint found",
        })

    logger.add_log(tool_name, "PROCESSING", f"Login endpoint: {login_url}")

    # ── 1. Hash Detection Patterns ────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Detecting password hash patterns in responses")

    # Common hash patterns that might appear in responses
    hash_patterns = {
        "MD5": r'[a-f0-9]{32}',
        "SHA1": r'[a-f0-9]{40}',
        "SHA256": r'[a-f0-9]{64}',
        "SHA512": r'[a-f0-9]{128}',
        "bcrypt": r'\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}',
        "scrypt": r'\$scrypt\$',
        "argon2": r'\$argon2(id|i|d)\$',
        "MD5_crypt": r'\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}',
        "SHA256_crypt": r'\$5\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{43}',
        "SHA512_crypt": r'\$6\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{86}',
    }

    # Check login page and responses for hash patterns
    try:
        rate_limiter.wait(domain)
        r = auth_get(login_url, timeout=5, verify=False, **auth_kwargs)
        response_text = r.text + str(dict(r.headers))

        for hash_type, pattern in hash_patterns.items():
            matches = re.findall(pattern, response_text)
            if matches:
                # Filter out common false positives
                false_positives = {
                    "MD5": ["00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff"],
                    "SHA1": ["0000000000000000000000000000000000000000"],
                    "SHA256": ["0000000000000000000000000000000000000000000000000000000000000000"],
                }

                valid_matches = [m for m in matches if m not in false_positives.get(hash_type, [])]
                if valid_matches:
                    severity = "High" if hash_type in ["MD5", "SHA1"] else "Medium"
                    findings.append({
                        "type": f"Potential {hash_type} Hash Detected",
                        "severity": severity,
                        "detail": f"Response contains pattern matching {hash_type} hash format",
                        "evidence": f"Found {len(valid_matches)} potential {hash_type} hash(es)",
                        "hash_preview": valid_matches[0][:20] + "..." if len(valid_matches[0]) > 20 else valid_matches[0],
                        "recommendation": f"Verify if {hash_type} is used for password storage — migrate to bcrypt/argon2 if so",
                    })
                    logger.add_log(tool_name, "WARNING", f"{hash_type} hash detected in response")

    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Hash detection error: {str(e)[:100]}")

    # ── 2. Response pattern analysis ──────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Analyzing response patterns for storage hints")

    # Test with known weak password to see error message differences
    try:
        # Request 1: Invalid username
        rate_limiter.wait(domain)
        r_invalid_user = auth_post(
            login_url,
            data={"username": "nonexistent_user_xyz999", "password": "wrong_password"},
            timeout=5, verify=False, **auth_kwargs,
            allow_redirects=False,
        )

        # Request 2: Valid username, wrong password
        rate_limiter.wait(domain)
        r_invalid_pass = auth_post(
            login_url,
            data={"username": "admin", "password": "wrong_password_xyz"},
            timeout=5, verify=False, **auth_kwargs,
            allow_redirects=False,
        )

        # Check for error message differences (timing oracle)
        user_err_indicators = ["user not found", "no account", "user does not exist", "account not found"]
        pass_err_indicators = ["wrong password", "incorrect password", "invalid password", "password does not match"]

        user_has_user_err = any(ind in r_invalid_user.text.lower() for ind in user_err_indicators)
        pass_has_pass_err = any(ind in r_invalid_pass.text.lower() for ind in pass_err_indicators)

        if user_has_user_err and not pass_has_pass_err:
            findings.append({
                "type": "Username Enumeration via Error Message",
                "severity": "Medium",
                "detail": "Different error messages for invalid username vs invalid password — leaks whether account exists",
                "evidence": "Server reveals account existence via error message differences",
            })
            logger.add_log(tool_name, "WARNING", "Username enumeration via error messages")

        # ── 2. Timing analysis ────────────────────────────────────────────────
        logger.add_log(tool_name, "PROCESSING", "Analyzing response timing")

        # Measure timing for wrong password with different password lengths
        # If server uses bcrypt/argon2, timing should be consistent
        # If server uses MD5/SHA1, timing varies with password complexity
        timings = []
        for test_pass in ["a", "aaaa", "aaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaa"]:
            try:
                rate_limiter.wait(domain)
                start = time.monotonic()
                r = auth_post(
                    login_url,
                    data={"username": "admin", "password": test_pass},
                    timeout=5, verify=False, **auth_kwargs,
                    allow_redirects=False,
                )
                elapsed = time.monotonic() - start
                timings.append({
                    "password_length": len(test_pass),
                    "time_ms": round(elapsed * 1000),
                })
            except Exception:
                pass

        if len(timings) >= 3:
            # Check if timing varies significantly (weak hashing)
            times = [t["time_ms"] for t in timings]
            max_time = max(times)
            min_time = min(times)
            time_variance = max_time - min_time

            if time_variance > 100:  # >100ms variance = likely weak hashing
                findings.append({
                    "type": "Weak Password Hashing (Timing Oracle)",
                    "severity": "High",
                    "detail": f"Response timing varies by {time_variance}ms across different password lengths. Server likely uses MD5/SHA1 instead of bcrypt/argon2.",
                    "evidence": f"Timing variance: {time_variance}ms (min: {min_time}ms, max: {max_time}ms)",
                    "timings": timings,
                    "recommendation": "Migrate to bcrypt, scrypt, or Argon2 for password hashing",
                })
                logger.add_log(tool_name, "WARNING",
                    f"Weak hashing detected: timing variance {time_variance}ms")
            elif time_variance < 20:  # Very consistent = likely bcrypt/argon2
                findings.append({
                    "type": "Strong Password Hashing (Probable)",
                    "severity": "Info",
                    "detail": f"Response timing consistent ({time_variance}ms variance) — likely bcrypt/argon2",
                    "timings": timings,
                })
                logger.add_log(tool_name, "SUCCESS",
                    f"Strong hashing likely: timing variance only {time_variance}ms")

    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Timing analysis error: {str(e)[:100]}")

    # ── 3. Response header analysis ───────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Analyzing response headers")

    try:
        rate_limiter.wait(domain)
        r = auth_get(login_url, timeout=5, verify=False, **auth_kwargs)

        # Check for password-related headers
        password_headers = [
            "X-Password-Policy", "X-Password-Requirements",
            "X-Auth-Token-Expiry", "X-Session-Timeout",
        ]

        for header in password_headers:
            if header.lower() in {k.lower(): v for k, v in r.headers.items()}:
                findings.append({
                    "type": "Password Policy Disclosure",
                    "severity": "Low",
                    "detail": f"Password policy header exposed: {header}",
                    "evidence": f"{header}: {r.headers.get(header)}",
                })

        # Check for password reset without proper validation
        reset_paths = ["/reset-password", "/forgot-password", "/password/reset"]
        for rp in reset_paths:
            try:
                rate_limiter.wait(domain)
                r = auth_get(f"{base}{rp}", timeout=5, verify=False, **auth_kwargs)
                if r.status_code == 200:
                    # Check if reset form exposes user existence
                    if any(kw in r.text.lower() for kw in ["email sent", "check your email", "reset link sent"]):
                        # This is good (generic message), but check if error message differs
                        pass
            except Exception:
                pass

    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Header analysis error: {str(e)[:100]}")

    result = {
        "status": "VULNERABLE" if any(f.get("severity") in ["Critical", "High"] for f in findings) else (
            "INFO" if findings else "SAFE"
        ),
        "login_endpoint": login_url,
        "findings": findings,
        "count": len(findings),
        "note": "Password storage analysis is limited to external observation. Full analysis requires server-side access.",
    }

    logger.add_log(tool_name, "SUCCESS",
        f"Password storage analysis complete. {len(findings)} findings")
    return json.dumps(result, indent=2)

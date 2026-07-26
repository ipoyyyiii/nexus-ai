"""
AUTH DETECTION
==============
Detect login walls from HTTP responses.

Indikator login wall:
- Status 401 / 403
- Redirect ke /login, /signin, /auth
- Login form di response body
- "Unauthorized" / "Please sign in" text di response

Used by tools to decide: continue scan or trigger auth checkpoint.
"""

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

# Login page URL patterns
LOGIN_URL_PATTERNS = [
    r"/login",
    r"/signin",
    r"/sign-in",
    r"/auth",
    r"/authentication",
    r"/sso",
    r"/saml",
    r"/oauth/authorize",
    r"/oauth2/authorize",
    r"/cas/login",
]

# Login form HTML patterns
LOGIN_FORM_PATTERNS = [
    r'<form[^>]*>.*?(?:password|passwd|pwd).*?</form>',
    r'<input[^>]*type=["\']password["\'][^>]*>',
    r'<input[^>]*name=["\'](?:password|passwd|pwd)["\'][^>]*>',
    r'<input[^>]*type=["\'](?:text|email)["\'][^>]*>.*?<input[^>]*type=["\']password["\']',
]

# Login-related text indicators
LOGIN_TEXT_INDICATORS = [
    r"please\s+(?:sign\s+in|log\s+in|login)",
    r"you\s+(?:must|need\s+to|have\s+to)\s+(?:sign\s+in|log\s+in|login|authenticate)",
    r"access\s+denied",
    r"unauthorized",
    r"authentication\s+required",
    r"sign\s+in\s+to\s+(?:continue|access)",
    r"log\s+in\s+to\s+(?:continue|access)",
    r"please\s+enter\s+your\s+(?:credentials|username|password)",
    r"session\s+expired",
    r"please\s+authenticate",
]

# MFA/2FA indicators
MFA_INDICATORS = [
    r"two[- ]factor",
    r"2fa",
    r"mfa",
    r"multi[- ]factor",
    r"verification\s+code",
    r"enter\s+your\s+(?:otp|code|token)",
    r"authenticator",
    r"totp",
    r"sms\s+code",
    r"email\s+code",
]


class LoginWallResult:
    """Result from login wall detection."""

    def __init__(
        self,
        detected: bool = False,
        wall_type: str = "",  # "status" | "redirect" | "form" | "text"
        evidence: str = "",
        has_mfa: bool = False,
        login_url: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[dict] = None,
    ):
        self.detected = detected
        self.wall_type = wall_type
        self.evidence = evidence
        self.has_mfa = has_mfa
        self.login_url = login_url
        self.status_code = status_code
        self.details = details or {}

    def to_dict(self):
        return {
            "detected": self.detected,
            "wall_type": self.wall_type,
            "evidence": self.evidence,
            "has_mfa": self.has_mfa,
            "login_url": self.login_url,
            "status_code": self.status_code,
            "details": self.details,
        }


def detect_login_wall(
    response,
    url: str,
    body: Optional[str] = None,
) -> LoginWallResult:
    """
    Detect apakah response is login wall.

    Args:
        response: requests.Response object
        url: URL that di-request
        body: response body text (optional, can di-pass biar gak double-read)

    Returns:
        LoginWallResult
    """
    if body is None:
        try:
            body = response.text
        except Exception:
            body = ""

    body_lower = body.lower()
    status = response.status_code
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # ── 1. Check status code ──────────────────────────────────────────────────
    if status in (401, 403):
        return LoginWallResult(
            detected=True,
            wall_type="status",
            evidence=f"Status {status} — {'Unauthorized' if status == 401 else 'Forbidden'}",
            status_code=status,
        )

    # ── 2. Check redirect ke login page ───────────────────────────────────────
    if status in (301, 302, 303, 307, 308):
        location = response.headers.get("Location", "")
        location_lower = location.lower()

        for pattern in LOGIN_URL_PATTERNS:
            if re.search(pattern, location_lower):
                # Build absolute login URL
                if location.startswith("/"):
                    login_url = base_url + location
                elif location.startswith("http"):
                    login_url = location
                else:
                    login_url = base_url + "/" + location

                return LoginWallResult(
                    detected=True,
                    wall_type="redirect",
                    evidence=f"Redirect ke login page: {location}",
                    login_url=login_url,
                    status_code=status,
                )

    # ── 3. Check login form di response body ──────────────────────────────────
    if status == 200 and body:
        # Cek login form
        for pattern in LOGIN_FORM_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if match:
                return LoginWallResult(
                    detected=True,
                    wall_type="form",
                    evidence=f"Login form terdeteksi di response body",
                    status_code=status,
                )

        # Cek login text indicators
        for pattern in LOGIN_TEXT_INDICATORS:
            match = re.search(pattern, body_lower)
            if match:
                return LoginWallResult(
                    detected=True,
                    wall_type="text",
                    evidence=f"Login indicator text: '{match.group()}'",
                    status_code=status,
                )

    # ── 4. Check MFA indicators (kalau login wall terdeteksi) ─────────────────
    # Ini cek di response that mungkin udah login page
    if body:
        for pattern in MFA_INDICATORS:
            if re.search(pattern, body_lower):
                # MFA terdeteksi — return info tapi gak set detected=True
                # (karena this bukan login wall, tapi MFA wall)
                return LoginWallResult(
                    detected=True,
                    wall_type="mfa",
                    evidence=f"MFA/2FA terdeteksi: '{re.search(pattern, body_lower).group()}'",
                    has_mfa=True,
                    status_code=status,
                )

    return LoginWallResult(detected=False)


def needs_auth(response, url: str) -> Tuple[bool, Optional[LoginWallResult]]:
    """
    Convenience function: cek apakah response butuh auth.

    Returns:
        (needs_auth: bool, result: LoginWallResult atau None)
    """
    result = detect_login_wall(response, url)
    return result.detected, result if result.detected else None

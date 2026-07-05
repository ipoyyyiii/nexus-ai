import re
from typing import Any

# ── Pattern definitions ────────────────────────────────────────────────────────

_PATTERNS = [
    # JWT
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), '[REDACTED:JWT]'),
    # Bearer token
    (re.compile(r'(Bearer\s+)[A-Za-z0-9\-._~+/]{20,}', re.IGNORECASE), r'\1[REDACTED:BEARER]'),
    # Basic auth
    (re.compile(r'(Basic\s+)[A-Za-z0-9+/=]{10,}', re.IGNORECASE), r'\1[REDACTED:BASIC_AUTH]'),
    # Authorization header value
    (re.compile(r'(Authorization:\s*)[^\r\n]{8,}', re.IGNORECASE), r'\1[REDACTED:AUTH_HEADER]'),
    # Cookie header
    (re.compile(r'(Cookie:\s*)[^\r\n]{4,}', re.IGNORECASE), r'\1[REDACTED:COOKIE]'),
    # Set-Cookie value
    (re.compile(r'(Set-Cookie:\s*\S+=)[^\r\n;]{4,}', re.IGNORECASE), r'\1[REDACTED:COOKIE_VALUE]'),
    # password/secret/token/key fields in JSON or form data
    (re.compile(
        r'("(?:password|passwd|secret|token|api_key|apikey|access_token|refresh_token|private_key|client_secret)":\s*")[^"]{4,}(")',
        re.IGNORECASE
    ), r'\1[REDACTED:SECRET]\2'),
    # password= in query string / form
    (re.compile(
        r'((?:password|passwd|secret|token|api_key|access_token)=)[^&\s"\']{4,}',
        re.IGNORECASE
    ), r'\1[REDACTED:SECRET]'),
    # AWS access key
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), '[REDACTED:AWS_KEY]'),
    # AWS secret key (40 char base64-ish after known prefixes)
    (re.compile(r'(aws_secret_access_key["\s:=]+)[A-Za-z0-9/+=]{30,}', re.IGNORECASE), r'\1[REDACTED:AWS_SECRET]'),
    # PEM private key block
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.DOTALL), '[REDACTED:PRIVATE_KEY]'),
    # Session / CSRF token patterns (common header names)
    (re.compile(r'(X-CSRF-Token|X-Auth-Token|X-Session-Token):\s*\S{8,}', re.IGNORECASE), r'\1: [REDACTED:TOKEN]'),
    # Credit card (basic Luhn-ish pattern, 13–19 digits with optional spaces/dashes)
    (re.compile(r'\b(?:\d[ -]?){13,18}\d\b'), '[REDACTED:CARD_NUMBER]'),
]

# ── Public API ─────────────────────────────────────────────────────────────────

def redact(value: Any) -> Any:
    """
    Rekursif — bisa nerima str, dict, list, atau tipe lain.
    Non-string dikembalikan apa adanya (int, bool, None, dst).
    """
    if isinstance(value, str):
        return _redact_str(value)
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def _redact_str(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
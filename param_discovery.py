"""
PARAMETER DISCOVERY
====================
Nemuin hidden parameter di endpoint yang gak keliatan dari HTML/JS surface.
Banyak vuln (SQLi, XSS, IDOR, SSRF) cuma bisa dieksploit kalau lo tau
parameter apa yang diterima server — termasuk yang gak ada di form/docs.

Strategy:
1. Wordlist bruteforce — test ratusan common parameter names
2. Response analysis — bandingkan response length/status buat detect param yang "nyambung"
3. Technology-aware — prioritize parameter sesuai tech stack target
4. Arjun-style heuristic — detect parameter via reflection atau error behavior

Tools:
- param_discovery_get  — discover GET parameters
- param_discovery_post — discover POST body parameters
- param_discover_headers — discover custom header parameters
"""

import json
import time
from typing import Optional
from urllib.parse import urlparse, urlencode

import requests
import urllib3
from crewai.tools import tool

from cancellation import check_cancelled
from checkpoint import require_approval
from rate_limiter import rate_limiter
from redact import redact

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SESSION = requests.Session()
SESSION.verify = False
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
}

def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url

def _logger():
    try:
        from custom_tools import exec_logger
        return exec_logger
    except Exception:
        return None


# ── Wordlists ─────────────────────────────────────────────────────────────────

# Common GET parameters — Arjun-inspired wordlist
COMMON_GET_PARAMS = [
    # Auth & session
    "token", "key", "api_key", "apikey", "secret", "password", "pass",
    "auth", "access_token", "refresh_token", "session", "csrf", "nonce",

    # User & identity
    "id", "user_id", "uid", "user", "username", "email", "account",
    "profile_id", "member_id", "customer_id", "admin", "role",

    # Navigation & redirect
    "next", "redirect", "return", "url", "goto", "target", "page",
    "ref", "referrer", "callback", "continue", "forward",

    # Data & content
    "q", "query", "search", "s", "keyword", "term", "filter",
    "sort", "order", "limit", "offset", "page_size", "per_page",
    "format", "type", "category", "tag", "lang", "locale",

    # Debug & internal
    "debug", "test", "dev", "mode", "verbose", "trace", "log",
    "preview", "draft", "version", "v", "env", "config",

    # File & path
    "file", "path", "dir", "folder", "document", "doc", "pdf",
    "image", "img", "src", "source", "load", "include",

    # API specific
    "fields", "expand", "include", "exclude", "embed", "select",
    "scope", "grant_type", "response_type", "client_id",

    # Common CMS
    "p", "post", "article", "slug", "feed", "attachment_id",
    "cat", "tag_id", "author", "m", "year", "month",

    # PHP specific
    "action", "module", "controller", "view", "template",
    "cmd", "exec", "command", "op", "do", "func",

    # Generic
    "data", "value", "input", "output", "name", "title",
    "content", "body", "message", "text", "info", "detail",
    "status", "state", "code", "error", "success",
]

# Common POST body parameters
COMMON_POST_PARAMS = [
    "username", "password", "email", "user", "pass", "login",
    "name", "first_name", "last_name", "phone", "address",
    "message", "content", "body", "text", "comment",
    "title", "subject", "description", "notes",
    "token", "csrf_token", "nonce", "auth_token",
    "file", "upload", "attachment", "image",
    "action", "type", "method", "format",
    "id", "user_id", "account_id", "record_id",
    "data", "payload", "json", "xml",
    "redirect_url", "return_url", "next",
    "code", "otp", "pin", "verification_code",
    "old_password", "new_password", "confirm_password",
    "search", "query", "q", "filter",
    "page", "limit", "offset", "sort",
]

# Tech-stack specific parameters
TECH_SPECIFIC = {
    "php": ["phpMyAdmin", "PHPSESSID", "php_errormsg"],
    "wordpress": ["p", "page_id", "cat", "m", "paged", "attachment_id"],
    "django": ["csrfmiddlewaretoken", "next", "format"],
    "laravel": ["_token", "_method", "remember"],
    "spring": ["_csrf", "redirect", "spring_security_remember_me_cookie"],
    "graphql": ["query", "mutation", "variables", "operationName"],
    "rest_api": ["fields", "expand", "include", "filter", "sort", "page", "per_page"],
}


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — GET Parameter Discovery
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def param_discovery_get(url: str, tech_stack: str = "") -> str:
    """
    Discover hidden GET parameters di endpoint target menggunakan wordlist bruteforce.
    Teknik: bandingkan response baseline vs response dengan parameter tambahan.
    Parameter yang "nyambung" biasanya menghasilkan:
    - Response length yang berbeda dari baseline
    - Status code berbeda (400 Bad Request = server kenal param-nya)
    - Error message yang mention parameter name
    - Redirect behavior yang berbeda

    Args:
        url: Target URL endpoint yang mau di-discover
        tech_stack: Tech stack target (php/wordpress/django/laravel/spring/graphql/rest_api)
                    untuk prioritize wordlist yang relevan
    Returns:
        JSON berisi discovered parameters dan evidence kenapa mereka interesting
    """
    logger = _logger()
    tool_name = "GET Parameter Discovery"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"GET parameter discovery pada {url}",
        context=f"Bruteforce {len(COMMON_GET_PARAMS)} common parameters. Tech stack: {tech_stack or 'unknown'}",
        risk="low",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval ditolak atau timeout."

    domain = _domain_of(url)

    # Build wordlist — tambah tech-specific params kalau ada
    wordlist = list(COMMON_GET_PARAMS)
    if tech_stack and tech_stack.lower() in TECH_SPECIFIC:
        tech_params = TECH_SPECIFIC[tech_stack.lower()]
        wordlist = tech_params + [p for p in wordlist if p not in tech_params]

    # ── Baseline request ──────────────────────────────────────────────────────
    rate_limiter.wait(domain)
    try:
        baseline = SESSION.get(url, headers=HEADERS, timeout=10)
        baseline_length = len(baseline.text)
        baseline_status = baseline.status_code
    except Exception as e:
        return json.dumps({"error": f"Baseline request gagal: {str(e)}"})

    if logger:
        logger.add_log(tool_name, "PROCESSING",
            f"Baseline: status={baseline_status}, length={baseline_length}. Testing {len(wordlist)} params...")

    discovered = []
    tested = 0

    # ── Bruteforce in batches ─────────────────────────────────────────────────
    # Test 5 params sekaligus dulu buat efficiency, kalau ada yang interesting
    # baru test satu-satu untuk isolasi
    batch_size = 5
    interesting_batches = []

    for i in range(0, len(wordlist), batch_size):
        if check_cancelled(logger):
            break

        batch = wordlist[i:i+batch_size]
        # Inject semua params di batch dengan value unik
        batch_params = {p: f"nexus_test_{p}_1337" for p in batch}
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{urlencode(batch_params)}"

        rate_limiter.wait(domain)
        try:
            resp = SESSION.get(test_url, headers=HEADERS, timeout=10)
            tested += 1

            length_diff = abs(len(resp.text) - baseline_length)
            status_diff = resp.status_code != baseline_status

            # Kalau ada perbedaan signifikan di batch ini, flag buat individual test
            if length_diff > 100 or status_diff:
                interesting_batches.append(batch)

        except Exception:
            continue

    # ── Individual test untuk batch yang interesting ───────────────────────────
    for batch in interesting_batches:
        for param in batch:
            if check_cancelled(logger):
                break

            test_value = f"nexus_test_1337"
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={test_value}"

            rate_limiter.wait(domain)
            try:
                resp = SESSION.get(test_url, headers=HEADERS, timeout=10)
                tested += 1

                resp_length = len(resp.text)
                length_diff = abs(resp_length - baseline_length)
                status_diff = resp.status_code != baseline_status

                evidence = []

                # Heuristic 1: length difference
                if length_diff > 150:
                    evidence.append(f"Response length berbeda: {baseline_length} → {resp_length} (diff: {length_diff})")

                # Heuristic 2: status code difference
                if status_diff:
                    evidence.append(f"Status code berbeda: {baseline_status} → {resp.status_code}")

                # Heuristic 3: parameter name reflected di error
                if param.lower() in resp.text.lower() and param.lower() not in baseline.text.lower():
                    evidence.append(f"Parameter name '{param}' ter-reflect di response")

                # Heuristic 4: 400/422 = server kenal param tapi value salah
                if resp.status_code in (400, 422):
                    evidence.append(f"Status {resp.status_code} = server mengenali parameter ini")

                if evidence:
                    discovered.append({
                        "parameter": param,
                        "evidence": evidence,
                        "baseline_status": baseline_status,
                        "found_status": resp.status_code,
                        "baseline_length": baseline_length,
                        "found_length": resp_length,
                        "test_url": test_url,
                    })

            except Exception:
                continue

    result = {
        "url": url,
        "tech_stack": tech_stack or "unknown",
        "total_params_tested": tested,
        "discovered_params": discovered,
        "total_discovered": len(discovered),
        "wordlist_size": len(wordlist),
        "status": "success" if not check_cancelled(logger) else "cancelled"
    }

    if logger:
        logger.add_log(
            tool_name,
            "SUCCESS" if discovered else "INFO",
            f"Discovery selesai. {tested} params tested, {len(discovered)} discovered."
        )
    return json.dumps(redact(result), indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — POST Parameter Discovery
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def param_discovery_post(url: str, content_type: str = "application/x-www-form-urlencoded") -> str:
    """
    Discover hidden POST body parameters di endpoint target.
    Support dua content type: form-urlencoded dan JSON body.

    Args:
        url: Target POST endpoint
        content_type: "form" untuk application/x-www-form-urlencoded,
                      "json" untuk application/json
    Returns:
        JSON berisi discovered POST parameters
    """
    logger = _logger()
    tool_name = "POST Parameter Discovery"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"POST parameter discovery pada {url}",
        context=f"Test {len(COMMON_POST_PARAMS)} common POST params dengan content-type: {content_type}",
        risk="low",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval ditolak atau timeout."

    domain = _domain_of(url)
    use_json = "json" in content_type.lower()

    # Baseline POST request
    rate_limiter.wait(domain)
    try:
        if use_json:
            baseline = SESSION.post(url, json={}, headers={**HEADERS, "Content-Type": "application/json"}, timeout=10)
        else:
            baseline = SESSION.post(url, data={}, headers=HEADERS, timeout=10)
        baseline_length = len(baseline.text)
        baseline_status = baseline.status_code
    except Exception as e:
        return json.dumps({"error": f"Baseline POST gagal: {str(e)}"})

    discovered = []
    tested = 0

    for param in COMMON_POST_PARAMS:
        if check_cancelled(logger):
            break

        rate_limiter.wait(domain)
        try:
            test_value = "nexus_test_1337"
            if use_json:
                resp = SESSION.post(
                    url,
                    json={param: test_value},
                    headers={**HEADERS, "Content-Type": "application/json"},
                    timeout=10
                )
            else:
                resp = SESSION.post(
                    url,
                    data={param: test_value},
                    headers=HEADERS,
                    timeout=10
                )
            tested += 1

            resp_length = len(resp.text)
            length_diff = abs(resp_length - baseline_length)
            evidence = []

            if length_diff > 150:
                evidence.append(f"Response length berbeda: {baseline_length} → {resp_length}")
            if resp.status_code != baseline_status:
                evidence.append(f"Status berbeda: {baseline_status} → {resp.status_code}")
            if param.lower() in resp.text.lower() and param.lower() not in baseline.text.lower():
                evidence.append(f"Parameter '{param}' ter-reflect di response")
            if resp.status_code in (400, 422):
                evidence.append(f"Status {resp.status_code} = server mengenali parameter ini")

            if evidence:
                discovered.append({
                    "parameter": param,
                    "content_type": "json" if use_json else "form",
                    "evidence": evidence,
                    "baseline_status": baseline_status,
                    "found_status": resp.status_code,
                })

        except Exception:
            continue

    result = {
        "url": url,
        "method": "POST",
        "content_type": "json" if use_json else "form",
        "total_tested": tested,
        "discovered_params": discovered,
        "total_discovered": len(discovered),
        "status": "success" if not check_cancelled(logger) else "cancelled"
    }

    if logger:
        logger.add_log(
            tool_name,
            "SUCCESS" if discovered else "INFO",
            f"POST discovery selesai. {tested} tested, {len(discovered)} discovered."
        )
    return json.dumps(redact(result), indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — Header Parameter Discovery
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def param_discovery_headers(url: str) -> str:
    """
    Discover custom HTTP headers yang diterima server.
    Banyak backend punya hidden behavior waktu nerima header tertentu:
    debug mode, internal routing, bypass access control, dll.

    Args:
        url: Target URL
    Returns:
        JSON berisi headers yang menghasilkan response berbeda
    """
    logger = _logger()
    tool_name = "Header Parameter Discovery"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    INTERESTING_HEADERS = [
        # Debug & internal
        "X-Debug", "X-Debug-Mode", "X-Dev-Mode", "X-Internal",
        "X-Test", "X-Admin", "X-Forwarded-User",

        # Access control bypass
        "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
        "X-Forwarded-For", "X-Real-IP", "X-Remote-IP",
        "X-Originating-IP", "X-Remote-Addr",

        # Auth bypass
        "X-Auth-Token", "X-API-Key", "Authorization",
        "X-User-ID", "X-User-Role", "X-Admin-Token",
        "X-Bypass-Auth", "X-Internal-Auth",

        # Routing
        "X-Forwarded-Host", "X-Host", "X-Custom-Host",
        "X-Override-URL", "X-Forwarded-Path",

        # Feature flags
        "X-Feature-Flag", "X-Beta", "X-Preview",
        "X-Version", "X-API-Version",

        # Common framework headers
        "X-CSRF-Token", "X-Requested-With",
        "X-HTTP-Method-Override", "X-Method-Override",
    ]

    domain = _domain_of(url)

    # Baseline
    rate_limiter.wait(domain)
    try:
        baseline = SESSION.get(url, headers=HEADERS, timeout=10)
        baseline_length = len(baseline.text)
        baseline_status = baseline.status_code
    except Exception as e:
        return json.dumps({"error": f"Baseline gagal: {str(e)}"})

    interesting_headers = []
    tested = 0

    for header in INTERESTING_HEADERS:
        if check_cancelled(logger):
            break

        rate_limiter.wait(domain)
        try:
            test_headers = {**HEADERS, header: "nexus-test-1337"}
            resp = SESSION.get(url, headers=test_headers, timeout=10)
            tested += 1

            length_diff = abs(len(resp.text) - baseline_length)
            status_diff = resp.status_code != baseline_status

            if length_diff > 100 or status_diff:
                interesting_headers.append({
                    "header": header,
                    "test_value": "nexus-test-1337",
                    "baseline_status": baseline_status,
                    "found_status": resp.status_code,
                    "length_diff": length_diff,
                    "evidence": f"Response berbeda: status {baseline_status}→{resp.status_code}, length diff {length_diff}",
                })

        except Exception:
            continue

    result = {
        "url": url,
        "total_tested": tested,
        "interesting_headers": interesting_headers,
        "total_found": len(interesting_headers),
        "status": "success" if not check_cancelled(logger) else "cancelled"
    }

    if logger:
        logger.add_log(
            tool_name,
            "WARNING" if interesting_headers else "INFO",
            f"Header discovery selesai. {tested} tested, {len(interesting_headers)} interesting."
        )
    return json.dumps(redact(result), indent=2)
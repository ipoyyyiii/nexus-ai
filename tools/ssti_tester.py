import requests
import re
from langchain.tools import tool
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from tools.custom_tools import exec_logger
from core.rate_limiter import rate_limiter
from core.auth_store import auth_get, auth_post
from core.auth_store import get_auth_kwargs

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


# Payload per template engine
SSTI_PAYLOADS = [
    # Generic math — kalau balik 49 = vulnerable
    ("{{7*7}}", "49", "Jinja2/Twig/Generic"),
    ("${7*7}", "49", "Java EL/Freemarker"),
    ("#{7*7}", "49", "Spring EL"),
    ("<%= 7*7 %>", "49", "ERB (Ruby)"),
    ("{{7*'7'}}", "7777777", "Jinja2 specific"),
    ("${{7*7}}", "49", "Pebble/Jinja2"),
    ("{7*7}", "49", "Smarty/Generic"),
    ("@(7*7)", "49", "Razor (ASP.NET)"),
    ("*{7*7}", "49", "Spring EL alternative"),
    ("{{=7*7}}", "49", "Slim/Pug"),
]


def _test_ssti_on_param(url: str, param: str, method: str = "GET") -> list:
    """Test SSTI on satu parameter."""
    findings = []
    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)

    for payload, expected, engine in SSTI_PAYLOADS:
        if not payload:
            continue
        try:
            rate_limiter.wait(domain)

            if method.upper() == "GET":
                from urllib.parse import quote
                test_url = f"{url}?{param}={quote(payload)}"
                resp = auth_get(test_url, timeout=5, verify=False)
            else:
                resp = auth_post(
                    url,
                    data={param: payload},
                    timeout=5,
                    verify=False,
                )

            # Cek apakah hasil evaluasi ada di response
            if expected in resp.text:
                findings.append({
                    "parameter": param,
                    "payload": payload,
                    "expected": expected,
                    "engine": engine,
                    "method": method,
                    "severity": "Critical",
                    "detail": (
                        f"SSTI confirmed on parameter '{param}' — "
                        f"payload '{payload}' dievaluasi jadi '{expected}'. "
                        f"Template engine: {engine}. "
                        f"Potensi RCE (Remote Code Execution)."
                    )
                })
                exec_logger.add_log(
                    "SSTI Tester", "WARNING",
                    f"SSTI found: {engine} on param '{param}'"
                )
                break  # Cukup satu confirmed payload per param

        except Exception:
            continue

    return findings


def _run_tplmap_confirmation(url: str, params: list, logger) -> dict:
    """
    Run tplmap sebagai confirmation step for SSTI.
    Return dict with is_confirmed, evidence, severity.
    """
    import subprocess
    import tempfile
    import os

    tool_name = "SSTI Confirmation (tplmap)"
    logger.add_log(tool_name, "PROCESSING", f"Running tplmap on {url}")

    try:
        # Create temp output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = f.name

        # Run tplmap
        cmd = [
            "tplmap",
            "-u", url,
            "--level", "3",
            "-o", output_file,
        ]

        # Add parameters if specified
        if params:
            for param in params[:3]:  # Limit to 3 params
                cmd.extend(["-p", param])

        # Apply stealth mode if enabled
        if os.environ.get("STEALTH_MODE", "0") == "1":
            cmd.extend(["--delay", "1"])

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,  # 2 minute timeout
        )

        # Parse tplmap output
        output = result.stdout + result.stderr

        # Check for SSTI indicators
        ssti_indicators = [
            "Template engine:",
            "Confirmed",
            "VULNERABLE",
            "RCE",
            "command execution",
            "file read",
        ]

        is_vulnerable = any(indicator.lower() in output.lower() for indicator in ssti_indicators)

        # Extract template engine if found
        engine = "Unknown"
        for line in output.split('\n'):
            if 'template engine:' in line.lower():
                engine = line.split(':')[-1].strip()
                break

        # Cleanup
        try:
            os.unlink(output_file)
        except:
            pass

        if is_vulnerable:
            evidence = output[:500]
            logger.add_log(tool_name, "WARNING", f"tplmap CONFIRMED SSTI ({engine})")
            return {
                "is_confirmed": True,
                "severity": "Critical",
                "engine": engine,
                "evidence": evidence,
                "tool": "tplmap",
            }
        else:
            logger.add_log(tool_name, "INFO", "tplmap did not confirm SSTI")
            return {
                "is_confirmed": False,
                "severity": "Low",
                "tool": "tplmap",
                "note": "tplmap could not confirm vulnerability",
            }

    except subprocess.TimeoutExpired:
        logger.add_log(tool_name, "WARNING", "tplmap timed out after 120s")
        return {
            "is_confirmed": False,
            "severity": "Low",
            "tool": "tplmap",
            "note": "tplmap execution timed out",
        }
    except FileNotFoundError:
        logger.add_log(tool_name, "WARNING", "tplmap not found - skipping external confirmation")
        return {
            "is_confirmed": False,
            "severity": "Low",
            "tool": "tplmap",
            "note": "tplmap not installed",
        }
    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"tplmap error: {str(e)[:100]}")
        return {
            "is_confirmed": False,
            "severity": "Low",
            "tool": "tplmap",
            "note": f"tplmap error: {str(e)[:100]}",
        }


@tool("ssti_tester")
def ssti_tester(target_url: str, params: str = "") -> str:
    """
    Testing Server-Side Template Injection (SSTI) on target.
    SSTI can berujung ke Remote Code Execution (RCE) — salah satu
    vuln paling critical di bug bounty.
    
    Supports: Jinja2, Twig, Freemarker, ERB, Spring EL, Razor, Smarty, Pebble.
    
    Args:
        target_url: URL target (contoh: https://target.com/search)
        params: Comma-separated parameter names (contoh: "q,name,template").
                Kalau kosong, auto-discover from URL dan common params.
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"SSTI testing on {target_url}",
        context=f"Inject template expression payloads ke parameter: {params or 'auto-detect'}",
        risk="medium",
        exec_logger=exec_logger,
    )
    if not approved:
        return "TEST DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    exec_logger.add_log("SSTI Tester", "START", f"Starting SSTI testing on {target_url}")

    # Resolve parameter list
    if params:
        param_list = [p.strip() for p in params.split(",") if p.strip()]
    else:
        # Auto-detect from URL query string
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target_url)
        param_list = list(parse_qs(parsed.query).keys())

        # Tambah common params kalau gak ada di URL
        common_params = ["q", "search", "query", "name", "template", "page",
                        "lang", "redirect", "url", "path", "file", "view",
                        "theme", "layout", "format", "type", "id", "msg"]

        for p in common_params:
            if p not in param_list:
                param_list.append(p)

    exec_logger.add_log("SSTI Tester", "PROCESSING", f"Testing {len(param_list)} parameters")

    all_findings = []

    for param in param_list:
        if check_cancelled(exec_logger):
            break

        # Test GET
        findings_get = _test_ssti_on_param(target_url, param, "GET")
        all_findings.extend(findings_get)

        # Test POST juga kalau GET clean
        if not findings_get:
            findings_post = _test_ssti_on_param(target_url, param, "POST")
            all_findings.extend(findings_post)

    exec_logger.add_log("SSTI Tester", "SUCCESS", f"SSTI testing selesai. Findings: {len(all_findings)}")

    # ── TPLMAP CONFIRMATION STEP ──────────────────────────────────────────────
    if all_findings:
        tplmap_result = _run_tplmap_confirmation(target_url, param_list, exec_logger)
        if tplmap_result.get("is_confirmed"):
            for finding in all_findings:
                finding["tplmap_confirmed"] = True
                finding["tplmap_evidence"] = tplmap_result.get("evidence", "")
                finding["severity"] = "Critical"
            exec_logger.add_log("SSTI Tester", "WARNING", "tplmap CONFIRMED SSTI vulnerability")
        else:
            for finding in all_findings:
                finding["tplmap_confirmed"] = False
                finding["note"] = "Detected by custom scanner, not confirmed by tplmap"
            exec_logger.add_log("SSTI Tester", "INFO", "tplmap did not confirm SSTI — keeping as medium confidence")

    output = f"=== SSTI TEST RESULTS FOR {target_url} ===\n\n"
    output += f"Parameters tested: {', '.join(param_list[:20])}\n\n"

    if not all_findings:
        output += "[✅] Not found SSTI vulnerability. Target not mengevaluasi template expressions.\n"
        return output

    output += f"[🔴 CRITICAL] {len(all_findings)} SSTI finding(s) — POTENSI RCE!\n\n"
    for f in all_findings:
        output += f"  ▸ Parameter  : {f['parameter']}\n"
        output += f"    Engine     : {f['engine']}\n"
        output += f"    Payload    : {f['payload']}\n"
        output += f"    Evaluated  : {f['expected']}\n"
        output += f"    Method     : {f['method']}\n"
        output += f"    Detail     : {f['detail']}\n"
        if f.get("tplmap_confirmed"):
            output += f"    ✅ tplmap CONFIRMED\n"
        output += "\n"

    output += "⚠️  SSTI confirmed — lakukan manual exploitation for verify RCE impact senot yet report ke H1.\n"

    return output
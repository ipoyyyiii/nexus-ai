import requests
import re
from langchain.tools import tool
from cancellation import check_cancelled
from checkpoint import require_approval
from custom_tools import exec_logger
from rate_limiter import rate_limiter
from auth_store import get_auth_kwargs

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
    """Test SSTI pada satu parameter."""
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
                resp = requests.get(test_url, timeout=5, verify=False)
            else:
                resp = requests.post(
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
                        f"SSTI confirmed pada parameter '{param}' — "
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


@tool("ssti_tester")
def ssti_tester(target_url: str, params: str = "") -> str:
    """
    Menguji Server-Side Template Injection (SSTI) pada target.
    SSTI bisa berujung ke Remote Code Execution (RCE) — salah satu
    vuln paling critical di bug bounty.
    
    Supports: Jinja2, Twig, Freemarker, ERB, Spring EL, Razor, Smarty, Pebble.
    
    Args:
        target_url: URL target (contoh: https://target.com/search)
        params: Comma-separated parameter names (contoh: "q,name,template").
                Kalau kosong, auto-discover dari URL dan common params.
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"SSTI testing pada {target_url}",
        context=f"Inject template expression payloads ke parameter: {params or 'auto-detect'}",
        risk="medium",
        exec_logger=exec_logger,
    )
    if not approved:
        return "TEST DIBATALKAN: human-in-the-loop approval ditolak atau timeout."

    exec_logger.add_log("SSTI Tester", "START", f"Memulai SSTI testing pada {target_url}")

    # Resolve parameter list
    if params:
        param_list = [p.strip() for p in params.split(",") if p.strip()]
    else:
        # Auto-detect dari URL query string
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

    output = f"=== SSTI TEST RESULTS FOR {target_url} ===\n\n"
    output += f"Parameters tested: {', '.join(param_list[:20])}\n\n"

    if not all_findings:
        output += "[✅] Tidak ditemukan SSTI vulnerability. Target tidak mengevaluasi template expressions.\n"
        return output

    output += f"[🔴 CRITICAL] {len(all_findings)} SSTI finding(s) — POTENSI RCE!\n\n"
    for f in all_findings:
        output += f"  ▸ Parameter  : {f['parameter']}\n"
        output += f"    Engine     : {f['engine']}\n"
        output += f"    Payload    : {f['payload']}\n"
        output += f"    Evaluated  : {f['expected']}\n"
        output += f"    Method     : {f['method']}\n"
        output += f"    Detail     : {f['detail']}\n\n"

    output += "⚠️  SSTI confirmed — lakukan manual exploitation untuk verify RCE impact sebelum report ke H1.\n"

    return output
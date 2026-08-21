from core.tool_transport import guarded_requests as requests
from core.tool_decorator import langchain_tool as tool
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


@tool("cors_tester")
def cors_tester(target_url: str) -> str:
    """
    Testing implementasi CORS on target for menemukan misconfiguration:
    - Arbitrary origin reflection
    - Null origin accepted
    - Subdomain wildcard bypass
    - HTTPS → HTTP downgrade
    - Credentials + wildcard misconfiguration
    
    Args:
        target_url: URL target (contoh: https://target.com)
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"CORS misconfiguration test on {target_url}",
        context="Sending request with berbagai Origin header for test CORS policy",
        risk="low",
        exec_logger=exec_logger,
    )
    if not approved:
        return "TEST DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    exec_logger.add_log("CORS Tester", "START", f"Starting CORS testing on {target_url}")

    domain = _domain_of(target_url)
    auth_kwargs = get_auth_kwargs(domain)

    # Payload origins that will ditest
    test_origins = [
        # Arbitrary domain
        ("https://evil.com", "Arbitrary Origin"),
        # Null origin
        ("null", "Null Origin"),
        # Subdomain of target
        (f"https://evil.{domain}", "Subdomain Bypass"),
        # Target domain prefix
        (f"https://{domain}.evil.com", "Domain Prefix Bypass"),
        # HTTP downgrade
        (f"http://{domain}", "HTTPS to HTTP Downgrade"),
        # Trusted domain with typo
        (f"https://{domain}evil.com", "Domain Suffix Bypass"),
    ]

    findings = []

    for origin, test_name in test_origins:
        if check_cancelled(exec_logger):
            break

        try:
            rate_limiter.wait(domain)

            # Test GET request with origin
            resp = auth_get(
                target_url,
                headers={
                    "Origin": origin,
                    "User-Agent": "Mozilla/5.0",
                },
                timeout=5,
                verify=False,
            )

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            # Cek apakah origin di-reflect
            if acao == origin or acao == "*":
                severity = "Critical" if acac.lower() == "true" else "High"

                finding = {
                    "test": test_name,
                    "origin_sent": origin,
                    "acao_header": acao,
                    "acac_header": acac,
                    "severity": severity,
                }

                # Critical kalau credentials juga diallow
                if acac.lower() == "true" and acao != "*":
                    finding["detail"] = (
                        f"CORS misconfiguration KRITIS: Origin '{origin}' di-reflect "
                        f"with Access-Control-Allow-Credentials: true — "
                        f"attacker can baca response authenticated request korban"
                    )
                elif acao == "*":
                    finding["severity"] = "Medium"
                    finding["detail"] = (
                        f"Wildcard CORS (*) — all domain can access this resource. "
                        f"Berbahaya kalau endpoint return data sensitif."
                    )
                else:
                    finding["detail"] = (
                        f"Origin '{origin}' di-reflect di ACAO header tanpa credentials — "
                        f"medium risk, can eskalasi kalau ada sensitive data"
                    )

                findings.append(finding)
                exec_logger.add_log("CORS Tester", "WARNING", f"CORS vuln: {test_name} — {severity}")

        except Exception as e:
            exec_logger.add_log("CORS Tester", "WARNING", f"Test {test_name} failed: {str(e)}")
            continue

    # Build report
    exec_logger.add_log("CORS Tester", "SUCCESS", f"CORS testing selesai. Findings: {len(findings)}")

    output = f"=== CORS MISCONFIGURATION TEST RESULTS FOR {target_url} ===\n\n"

    if not findings:
        output += "[✅] CORS policy tampak aman. Not ada origin bypass that success.\n"
        return output

    critical = [f for f in findings if f["severity"] == "Critical"]
    high = [f for f in findings if f["severity"] == "High"]
    medium = [f for f in findings if f["severity"] == "Medium"]

    if critical:
        output += f"[🔴 CRITICAL] {len(critical)} finding(s)\n"
        for f in critical:
            output += f"  ▸ {f['test']}\n"
            output += f"    Origin sent    : {f['origin_sent']}\n"
            output += f"    ACAO header    : {f['acao_header']}\n"
            output += f"    ACAC header    : {f['acac_header']}\n"
            output += f"    Detail         : {f['detail']}\n\n"

    if high:
        output += f"[🟠 HIGH] {len(high)} finding(s)\n"
        for f in high:
            output += f"  ▸ {f['test']}\n"
            output += f"    Origin sent    : {f['origin_sent']}\n"
            output += f"    ACAO header    : {f['acao_header']}\n"
            output += f"    Detail         : {f['detail']}\n\n"

    if medium:
        output += f"[🟡 MEDIUM] {len(medium)} finding(s)\n"
        for f in medium:
            output += f"  ▸ {f['test']}\n"
            output += f"    Detail         : {f['detail']}\n\n"

    output += "⚠️  Manual verification required for confirmation impact sebenarnya.\n"

    return output
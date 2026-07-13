import requests
import re
import time
import urllib.parse
from langchain.tools import tool
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from tools.custom_tools import exec_logger
from core.rate_limiter import rate_limiter
from core.auth_store import get_auth_kwargs

urllib3_imported = False
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    urllib3_imported = True
except ImportError:
    pass


def _domain_of(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


def _detect_oauth_endpoints(base_url: str) -> list:
    """Auto-detect OAuth endpoints dari target."""
    common_oauth_paths = [
        "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
        "/connect/authorize", "/openid/authorize",
        "/oauth/token", "/oauth2/token", "/auth/token",
        "/login/oauth/authorize",  # GitHub style
        "/.well-known/openid-configuration",  # OIDC discovery
    ]

    domain = _domain_of(base_url)
    auth_kw = get_auth_kwargs(domain)
    found = []
    for path in common_oauth_paths:
        try:
            rate_limiter.wait(_domain_of(base_url))
            resp = requests.get(
                f"{base_url.rstrip('/')}{path}",
                **auth_kw,
                timeout=5,
                verify=False,
                allow_redirects=False,
            )
            # 200, 302, 400 (missing params) semua ngindikasiin endpoint exist
            if resp.status_code in (200, 302, 400, 401, 403):
                found.append(f"{base_url.rstrip('/')}{path}")
                exec_logger.add_log("OAuth Tester", "SUCCESS", f"OAuth endpoint found: {path}")
        except Exception:
            pass

    return found


def _test_state_parameter(authorize_url: str, client_id: str) -> dict:
    """Test apakah state parameter validated."""
    findings = []

    # Test 1: Tanpa state sama sekali
    try:
        rate_limiter.wait(_domain_of(authorize_url))
        resp = requests.get(
            authorize_url,
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "https://localhost/callback",
            },
            timeout=5, verify=False, allow_redirects=False
        )
        # Kalau redirect tanpa minta state = potentially vulnerable
        if resp.status_code == 302 and "state" not in resp.headers.get("Location", ""):
            findings.append({
                "type": "Missing State Parameter",
                "severity": "High",
                "detail": "Server not memvalidasi/meminta state parameter — rentan CSRF pada OAuth flow"
            })
    except Exception:
        pass

    # Test 2: State predictable (angka kecil)
    try:
        rate_limiter.wait(_domain_of(authorize_url))
        resp = requests.get(
            authorize_url,
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "https://localhost/callback",
                "state": "1234",  # Predictable state
            },
            timeout=5, verify=False, allow_redirects=False
        )
        if resp.status_code == 302:
            location = resp.headers.get("Location", "")
            if "state=1234" in location:
                findings.append({
                    "type": "Weak State Parameter",
                    "severity": "Medium",
                    "detail": "Server menerima state predictable tanpa validasi entropy"
                })
    except Exception:
        pass

    return findings


def _test_redirect_uri_bypass(authorize_url: str, client_id: str, legit_redirect: str) -> list:
    """Test berbagai teknik bypass redirect_uri."""
    findings = []
    domain = urllib.parse.urlparse(legit_redirect).netloc

    bypass_payloads = [
        # Open redirect
        ("https://evil.com", "Open Redirect"),
        # Subdomain confusion
        (f"https://{domain}.evil.com", "Subdomain Confusion"),
        # @ bypass
        (f"https://{domain}@evil.com", "@ Character Bypass"),
        # Path traversal
        (f"{legit_redirect}/../../evil", "Path Traversal"),
        # Fragment bypass
        (f"https://evil.com#{domain}", "Fragment Bypass"),
        # URL encoded
        (f"https://evil%2Ecom", "URL Encoded Dot"),
        # Double slash
        (f"https://evil.com///{domain}", "Double Slash Bypass"),
    ]

    for payload_url, bypass_type in bypass_payloads:
        try:
            rate_limiter.wait(_domain_of(authorize_url))
            resp = requests.get(
                authorize_url,
                params={
                    "client_id": client_id,
                    "response_type": "code",
                    "redirect_uri": payload_url,
                    "state": "nexus_test_xyz",
                },
                timeout=5, verify=False, allow_redirects=False
            )

            location = resp.headers.get("Location", "")

            # Kalau server redirect ke payload kita = vulnerable
            if resp.status_code == 302 and "evil.com" in location:
                findings.append({
                    "type": f"Redirect URI Bypass — {bypass_type}",
                    "severity": "Critical",
                    "payload": payload_url,
                    "detail": f"Server menerima redirect ke domain not terdaftar via {bypass_type}"
                })
                exec_logger.add_log("OAuth Tester", "WARNING", f"Redirect URI bypass: {bypass_type}")

        except Exception:
            pass

    return findings


def _test_pkce_missing(authorize_url: str, client_id: str) -> list:
    """Test apakah PKCE di-enforce untuk public clients."""
    findings = []

    try:
        rate_limiter.wait(_domain_of(authorize_url))
        # Request tanpa code_challenge (PKCE) — harusnya rejected kalau PKCE di-enforce
        resp = requests.get(
            authorize_url,
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "https://localhost/callback",
                "state": "nexus_pkce_test",
                # Sengaja gak kirim code_challenge dan code_challenge_method
            },
            timeout=5, verify=False, allow_redirects=False
        )

        # Kalau server tetap lanjut tanpa PKCE = vulnerable (terutama buat SPA/mobile)
        if resp.status_code in (200, 302):
            findings.append({
                "type": "PKCE Not Enforced",
                "severity": "Medium",
                "detail": "Server not mewajibkan PKCE — authorization code rentan di-intercept pada public clients (SPA/mobile apps)"
            })
    except Exception:
        pass

    return findings


def _test_token_leakage(authorize_url: str) -> list:
    """Test apakah token bisa leak via response_type=token (implicit flow)."""
    findings = []

    try:
        rate_limiter.wait(_domain_of(authorize_url))
        resp = requests.get(
            authorize_url,
            params={
                "response_type": "token",  # Implicit flow — deprecated tapi masih sering diallow
                "redirect_uri": "https://localhost/callback",
                "state": "nexus_leak_test",
            },
            timeout=5, verify=False, allow_redirects=False
        )

        location = resp.headers.get("Location", "")
        if resp.status_code == 302 and "access_token=" in location:
            findings.append({
                "type": "Implicit Flow Enabled",
                "severity": "High",
                "detail": "Server masih mendukung OAuth implicit flow — access token ter-expose di URL fragment, rentan leak via Referrer header atau browser history"
            })
            exec_logger.add_log("OAuth Tester", "WARNING", "Implicit flow masih aktif — token di URL")
    except Exception:
        pass

    return findings


@tool("oauth_flow_tester")
def oauth_flow_tester(target_url: str, client_id: str = "", redirect_uri: str = "") -> str:
    """
    Testing implementasi OAuth/SSO pada target untuk menemukan kerentanan umum:
    - Missing/weak state parameter (CSRF)
    - Redirect URI bypass (token hijacking)
    - PKCE not enforced (code interception)
    - Implicit flow enabled (token leakage)
    - OAuth endpoint discovery
    
    Args:
        target_url: Base URL target (contoh: https://target.com)
        client_id: OAuth client_id kalau udah diketahui (opsional)
        redirect_uri: Legitimate redirect URI kalau udah diketahui (opsional)
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"OAuth flow testing pada {target_url}",
        context=f"Test: state CSRF, redirect URI bypass, PKCE, implicit flow. client_id={client_id or 'auto-detect'}",
        risk="medium",
        exec_logger=exec_logger,
    )
    if not approved:
        return "TEST DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    exec_logger.add_log("OAuth Tester", "START", f"Starting OAuth flow testing pada {target_url}")

    all_findings = []

    # Step 1: Auto-detect OAuth endpoints
    exec_logger.add_log("OAuth Tester", "PROCESSING", "Auto-detecting OAuth endpoints")
    oauth_endpoints = _detect_oauth_endpoints(target_url)

    if not oauth_endpoints:
        return f"[+] Not found OAuth/SSO endpoint standar pada {target_url}. Target mungkin pake custom auth flow atau not mengimplementasi OAuth."

    exec_logger.add_log("OAuth Tester", "SUCCESS", f"Found {len(oauth_endpoints)} OAuth endpoints")

    # Fokus ke authorize endpoint
    authorize_endpoint = next(
        (ep for ep in oauth_endpoints if "authorize" in ep or "auth" in ep),
        oauth_endpoints[0]
    )

    # Fallback client_id dan redirect_uri kalau gak dikasih
    test_client_id = client_id or "test_client"
    test_redirect = redirect_uri or f"{target_url}/callback"

    # Step 2: Run semua tests
    exec_logger.add_log("OAuth Tester", "PROCESSING", "Testing state parameter")
    state_findings = _test_state_parameter(authorize_endpoint, test_client_id)
    all_findings.extend(state_findings)

    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."

    exec_logger.add_log("OAuth Tester", "PROCESSING", "Testing redirect URI bypass")
    redirect_findings = _test_redirect_uri_bypass(authorize_endpoint, test_client_id, test_redirect)
    all_findings.extend(redirect_findings)

    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."

    exec_logger.add_log("OAuth Tester", "PROCESSING", "Testing PKCE enforcement")
    pkce_findings = _test_pkce_missing(authorize_endpoint, test_client_id)
    all_findings.extend(pkce_findings)

    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."

    exec_logger.add_log("OAuth Tester", "PROCESSING", "Testing implicit flow / token leakage")
    token_findings = _test_token_leakage(authorize_endpoint)
    all_findings.extend(token_findings)

    # Step 3: Build report
    exec_logger.add_log("OAuth Tester", "SUCCESS", f"OAuth testing selesai. Total findings: {len(all_findings)}")

    output = f"=== OAUTH/SSO FLOW TEST RESULTS FOR {target_url} ===\n\n"
    output += f"Endpoints found: {', '.join(oauth_endpoints)}\n"
    output += f"Authorize endpoint yang ditest: {authorize_endpoint}\n\n"

    if not all_findings:
        output += "[+] Not found kerentanan OAuth yang obvious. Manual testing tetap disarankan untuk edge cases.\n"
        return output

    # Group by severity
    critical = [f for f in all_findings if f["severity"] == "Critical"]
    high = [f for f in all_findings if f["severity"] == "High"]
    medium = [f for f in all_findings if f["severity"] == "Medium"]

    if critical:
        output += f"[🔴 CRITICAL] {len(critical)} finding(s)\n"
        for f in critical:
            output += f"  ▸ {f['type']}\n"
            output += f"    {f['detail']}\n"
            if 'payload' in f:
                output += f"    Payload: {f['payload']}\n"

    if high:
        output += f"\n[🟠 HIGH] {len(high)} finding(s)\n"
        for f in high:
            output += f"  ▸ {f['type']}\n"
            output += f"    {f['detail']}\n"

    if medium:
        output += f"\n[🟡 MEDIUM] {len(medium)} finding(s)\n"
        for f in medium:
            output += f"  ▸ {f['type']}\n"
            output += f"    {f['detail']}\n"

    output += f"\n⚠️  Manual verification required untuk konfirmasi semua findings di atas.\n"

    return output
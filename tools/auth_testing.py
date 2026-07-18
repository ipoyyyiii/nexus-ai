import requests
import base64
import json
import time
from langchain.tools import tool
from core.checkpoint import require_approval
from core.cancellation import check_cancelled
from tools.custom_tools import exec_logger
from core.auth_store import get_auth_kwargs

@tool("test_jwt_weakness")
def test_jwt_weakness(jwt_token: str) -> str:
    """
    Menganalisa struktur token JWT untuk mendeteksi miskonfigurasi 
    seperti penggunaan 'alg': 'none' yang bisa memicu otentikasi bypass.
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."
    
    token = jwt_token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        return "[-] Format token bukan JWT yang valid (harus terdiri dari 3 bagian yang dipisah titik)."

    findings = []

    try:
        # ── Header Analysis ───────────────────────────────────────────────────
        header_padding = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header_json = base64.urlsafe_b64decode(header_padding).decode('utf-8')
        header = json.loads(header_json)
        alg = header.get('alg', '').lower()
        
        # ── Alg None Check ────────────────────────────────────────────────────
        if alg == 'none':
            findings.append("[CRITICAL] JWT VULNERABILITY: 'alg': 'none' — signature bypass possible!")
            findings.append(f"  Mockup bypass token: {parts[0]}.{parts[1]}.")
        
        # ── Alg HS256 with Weak Secret ────────────────────────────────────────
        elif alg in ['hs256', 'hs384', 'hs512']:
            findings.append(f"[HIGH] JWT uses HMAC algorithm ({alg.upper()})")
            findings.append("  Risk: If secret is weak/leaked, attacker can forge tokens")
            findings.append("  Recommendation: Use RS256 or ES256 for asymmetric signing")
        
        # ── Alg RS256 (Good) ──────────────────────────────────────────────────
        elif alg in ['rs256', 'rs384', 'rs512', 'es256', 'es384', 'es512']:
            findings.append(f"[OK] JWT uses asymmetric algorithm ({alg.upper()}) — more secure")
        
        # ── Alg Specific Confusion Check ──────────────────────────────────────
        if alg in ['hs256', 'hs384', 'hs512', 'rs256', 'rs384', 'rs512', 'es256', 'es384', 'es512']:
            # Test algorithm confusion (RS256 → HS256)
            findings.append("[INFO] Testing algorithm confusion attack...")
            findings.append("  If server accepts HS256 with public key as secret → vulnerable")
        
        # ── Header k=none variation bypass ────────────────────────────────────
        mock_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode('utf-8').rstrip('=')
        mock_payload = parts[1]
        mock_token = f"{mock_header}.{mock_payload}."
        findings.append(f"\n[TEST] Alg-none bypass token: {mock_token}")
        
        # ── Kid Parameter Injection ───────────────────────────────────────────
        kid = header.get('kid', '')
        if kid:
            findings.append(f"\n[INFO] JWT 'kid' parameter: {kid}")
            # Check for path traversal in kid
            if '..' in kid or '/' in kid or '\\' in kid:
                findings.append("[HIGH] 'kid' parameter contains path traversal — potential key confusion attack")
            # Check for SQL injection in kid
            if "'" in kid or '"' in kid or ';' in kid:
                findings.append("[HIGH] 'kid' parameter contains special characters — potential SQL injection")
        
        # ── Payload Analysis ──────────────────────────────────────────────────
        payload_padding = parts[1] + '=' * (4 - len(parts[1]) % 4)
        try:
            payload_json = base64.urlsafe_b64decode(payload_padding).decode('utf-8')
            payload = json.loads(payload_json)
            
            # Check expiration
            exp = payload.get('exp')
            if exp:
                import time
                if exp < time.time():
                    findings.append(f"\n[INFO] JWT is EXPIRED (exp: {exp})")
                else:
                    remaining = exp - time.time()
                    if remaining > 365 * 24 * 3600:
                        findings.append(f"\n[WARNING] JWT expiry too long: {remaining / (365 * 24 * 3600):.1f} years")
                    else:
                        findings.append(f"\n[OK] JWT expires in {remaining / 3600:.1f} hours")
            
            # Check issuer
            iss = payload.get('iss')
            if iss:
                findings.append(f"[INFO] JWT issuer: {iss}")
            
            # Check audience
            aud = payload.get('aud')
            if aud:
                findings.append(f"[INFO] JWT audience: {aud}")
            
            # Check for sensitive claims
            sensitive_claims = ['admin', 'role', 'permissions', 'is_admin', 'is_staff']
            for claim in sensitive_claims:
                if claim in payload:
                    findings.append(f"[WARNING] JWT contains sensitive claim: {claim} = {payload[claim]}")
            
        except Exception:
            findings.append("[INFO] Could not decode JWT payload")
        
        # ── Summary ───────────────────────────────────────────────────────────
        findings.insert(0, f"=== JWT ANALYSIS ===\nAlgorithm: {alg}\n")
        
        if any("[CRITICAL]" in f or "[HIGH]" in f for f in findings):
            findings.append("\n[RECOMMENDATION] Token ini vulnerable — segera rotate JWT secret dan perbaiki konfigurasi.")
        
        return "\n".join(findings)
        
    except Exception as e:
        return f"[-] Failed menganalisa JWT: {str(e)}"

@tool("test_auth_rate_limiting")
def test_auth_rate_limiting(login_url: str) -> str:
    """
    Testing keberadaan rate limiting pada endpoint otentikasi (login/password-reset) 
    dengan mengirimkan 10 request cepat secara beruntun.
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"Auth rate limiting test pada {login_url}",
        context="Sending 10 request login beruntun dengan kredensial dummy",
        risk="medium",
        exec_logger=exec_logger,
    )
    if not approved:
        return "TEST DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    url = login_url.strip()
    headers = {"User-Agent": "Mozilla/5.0 NexusAI-Auth-Tester"}
    payload = {"username": "admin_test_nexus", "password": "password_test_nexus"}
    
    status_codes = []
    for _ in range(10):
        try:
            res = auth_post(url, json=payload, headers=headers, timeout=5)
            status_codes.append(res.status_code)
            time.sleep(0.1)
        except requests.RequestException:
            status_codes.append("ERR")

    rate_limited = status_codes.count(429)
    
    if rate_limited > 0:
        return f"[+] Target memiliki Rate Limiting aktif pada endpoint {url}. Terdeteksi status code 429 sebanyak {rate_limited} kali."
    
    distinct_codes = set(status_codes)
    return f"[WARN] POTENTIAL MISSING RATE LIMITING: Endpoint {url} menerima 10 request beruntun tanpa proteksi 429. Respon yang received: {list(distinct_codes)}. Rentan terhadap Brute Force."


@tool("jwt_tool_analysis")
def jwt_tool_analysis(jwt_token: str, target_url: str = "") -> str:
    """
    Comprehensive JWT analysis using jwt_tool.
    Tests for algorithm confusion, weak secrets, and other JWT vulnerabilities.
    
    Args:
        jwt_token: JWT token to analyze
        target_url: Target URL for testing (optional)
    """
    import subprocess
    import tempfile
    import os

    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    exec_logger.add_log("JWT Tool", "START", "Running jwt_tool analysis")

    try:
        # Create temp output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = f.name

        # Run jwt_tool
        cmd = [
            "python3",
            "/opt/jwt_tool/jwt_tool.py",
            jwt_token,
            "-M", "at",  # Test all attacks
            "-o", output_file,
        ]

        # Add target URL if provided
        if target_url:
            cmd.extend(["-t", target_url])

        # Apply stealth mode
        if os.environ.get("STEALTH_MODE", "0") == "1":
            cmd.append("--timeout")

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )

        # Parse output
        output = result.stdout + result.stderr

        # Check for vulnerability indicators
        vuln_indicators = [
            "VULNERABLE",
            "alg:none",
            "weak secret",
            "key confusion",
            "exploitable",
        ]

        is_vulnerable = any(indicator.lower() in output.lower() for indicator in vuln_indicators)

        # Build report
        report = f"=== JWT TOOL ANALYSIS ===\n\n"

        if is_vulnerable:
            report += "[🔴 VULNERABLE] jwt_tool detected potential vulnerabilities!\n\n"
            report += output[:2000]
        else:
            report += "[✅] No obvious JWT vulnerabilities detected by jwt_tool.\n\n"
            report += "Output summary:\n"
            report += output[:1000]

        # Cleanup
        try:
            os.unlink(output_file)
        except:
            pass

        exec_logger.add_log("JWT Tool", "SUCCESS", "jwt_tool analysis complete")
        return report

    except subprocess.TimeoutExpired:
        return "ERROR: jwt_tool timed out after 2 minutes"
    except FileNotFoundError:
        return "ERROR: jwt_tool not found. Install: git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool"
    except Exception as e:
        return f"ERROR: jwt_tool failed: {str(e)}"
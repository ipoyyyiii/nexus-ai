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

    try:
        header_padding = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header_json = base64.urlsafe_b64decode(header_padding).decode('utf-8')
        header = json.loads(header_json)
        alg = header.get('alg', '').lower()
        
        if alg == 'none':
            return "[CRITICAL] JWT VULNERABILITY: Target menerima signature dengan 'alg': 'none'. Token ini rentan terhadap tampering bypass!"
            
        mock_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode('utf-8').rstrip('=')
        mock_payload = parts[1]
        mock_token = f"{mock_header}.{mock_payload}."
        
        return f"[+] Hasil analisa JWT:\n    - Algorithm saat ini: {header.get('alg')}\n    - Mockup token bypass (alg none): {mock_token}\n    - Silakan tes mockup token tersebut ke server target untuk validasi."
        
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
            res = requests.post(url, json=payload, headers=headers, timeout=5)
            status_codes.append(res.status_code)
            time.sleep(0.1)
        except requests.RequestException:
            status_codes.append("ERR")

    rate_limited = status_codes.count(429)
    
    if rate_limited > 0:
        return f"[+] Target memiliki Rate Limiting aktif pada endpoint {url}. Terdeteksi status code 429 sebanyak {rate_limited} kali."
    
    distinct_codes = set(status_codes)
    return f"[WARN] POTENTIAL MISSING RATE LIMITING: Endpoint {url} menerima 10 request beruntun tanpa proteksi 429. Respon yang received: {list(distinct_codes)}. Rentan terhadap Brute Force."
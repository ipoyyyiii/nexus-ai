import requests
import base64
import json
import time
from langchain.tools import tool

@tool("test_jwt_weakness")
def test_jwt_weakness(jwt_token: str) -> str:
    """
    Menganalisa struktur token JWT untuk mendeteksi miskonfigurasi 
    seperti penggunaan 'alg': 'none' yang bisa memicu otentikasi bypass.
    """
    token = jwt_token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        return "[-] Format token bukan JWT yang valid (harus terdiri dari 3 bagian yang dipisah titik)."

    try:
        # Decode header JWT
        header_padding = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header_json = base64.urlsafe_b64decode(header_padding).decode('utf-8')
        header = json.loads(header_json)
        
        alg = header.get('alg', '').lower()
        
        if alg == 'none':
            return "[CRITICAL] JWT VULNERABILITY: Target menerima signature dengan 'alg': 'none'. Token ini rentan terhadap tampering bypass!"
            
        # Coba buat mockup token dengan alg none untuk testing manual berikutnya
        mock_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode('utf-8').rstrip('=')
        mock_payload = parts[1]
        mock_token = f"{mock_header}.{mock_payload}."
        
        return f"[+] Hasil analisa JWT:\n    - Algorithm saat ini: {header.get('alg')}\n    - Mockup token bypass (alg none): {mock_token}\n    - Silakan tes mockup token tersebut ke server target untuk validasi."
        
    except Exception as e:
        return f"[-] Gagal menganalisa JWT: {str(e)}"

@tool("test_auth_rate_limiting")
def test_auth_rate_limiting(login_url: str) -> str:
    """
    Menguji keberadaan rate limiting pada endpoint otentikasi (login/password-reset) 
    dengan mengirimkan 10 request cepat secara beruntun.
    """
    url = login_url.strip()
    headers = {"User-Agent": "Mozilla/5.0 NexusAI-Auth-Tester"}
    payload = {"username": "admin_test_nexus", "password": "password_test_nexus"}
    
    status_codes = []
    
    # Kirim 10 request secara cepat untuk melihat perubahan response code
    for _ in range(10):
        try:
            res = requests.post(url, json=payload, headers=headers, timeout=5)
            status_codes.append(res.status_code)
            time.sleep(0.1)  # Jeda sangat singkat
        except requests.RequestException:
            status_codes.append("ERR")

    # Hitung kemunculan status code 429 (Too Many Requests)
    rate_limited = status_codes.count(429)
    
    if rate_limited > 0:
        return f"[+] Target memiliki Rate Limiting aktif pada endpoint {url}. Terdeteksi status code 429 sebanyak {rate_limited} kali."
    
    # Jika semua request tembus dengan 200/401 tanpa ada tanda blocking
    distinct_codes = set(status_codes)
    return f"[WARN] POTENTIAL MISSING RATE LIMITING: Endpoint {url} menerima 10 request beruntun tanpa proteksi 429. Respon yang diterima: {list(distinct_codes)}. Rentan terhadap Brute Force."
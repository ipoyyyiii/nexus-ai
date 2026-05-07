import json
import requests
from crewai.tools import tool

# ==========================================
# TOOL 1: Buat Recon & Analisis
# ==========================================
@tool("Baca Log Burp Suite")
def baca_log_burp(file_path: str) -> str:
    """
    Berguna untuk membaca file hasil export HTTP History dari Burp Suite (format JSON).
    Gunakan tool ini kapanpun kamu butuh menganalisis data request/response target.
    """
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            
        hasil_parsing = []
        for item in data[:5]: 
            req_data = {
                "url": item.get("url", ""),
                "method": item.get("method", ""),
                "headers": item.get("request", {}).get("headers", ""),
                "body": item.get("request", {}).get("body", "")
            }
            hasil_parsing.append(req_data)
            
        return json.dumps(hasil_parsing, indent=2)
            
    except Exception as e:
        return f"Waduh, ada error pas baca file log nih men: {e}"


# ==========================================
# TOOL 2: (Buat Eksekusi Payload)
# ==========================================
@tool("Tembak Request HTTP")
def tembak_payload(url: str, method: str, headers_json: str, body_data: str) -> str:
    """
    Tool eksekutor untuk mengirim HTTP request secara langsung ke server target.
    Input:
    - url: URL target lengkap dengan http/https
    - method: 'GET', 'POST', 'PUT', 'DELETE', dll.
    - headers_json: string JSON berisi headers kustom (opsional, wajib set "{}" jika kosong)
    - body_data: string payload untuk body request (opsional, set "" jika kosong)
    """
    try:
        headers = json.loads(headers_json) if headers_json else {}
        
        if "User-Agent" not in headers:
            headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)"

        print(f"\n[🚀 SYSTEM ALERT] Menembakkan payload {method} ke {url}...")
        
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=10)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, data=body_data, timeout=10)
        elif method.upper() == 'PUT':
            response = requests.put(url, headers=headers, data=body_data, timeout=10)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=headers, timeout=10)
        else:
            return f"Method {method} belum disupport tool ini."
            
        hasil = f"Status Code: {response.status_code}\nResponse Body (terpotong 1000 char): {response.text[:1000]}" 
        return hasil
        
    except Exception as e:
        return f"Request gagal total, error: {e}"
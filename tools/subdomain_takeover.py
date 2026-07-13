import dns.resolver
import requests
from langchain.tools import tool
from core.auth_store import get_auth_kwargs

# Fingerprints populer untuk Subdomain Takeover
FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "herokucdn.com/error-pages/no-such-app.html",
    "cloudfront.net": "Bad Gateway: The proxy server received an invalid response",
    "s3.amazonaws.com": "The specified bucket does not exist",
    "wordpress.com": "Do you want to register",
    "ghost.io": "The thing you were looking for is no longer here",
}

@tool("detect_subdomain_takeover")
def detect_subdomain_takeover(subdomain: str) -> str:
    """
    Nge-cek apakah sebuah subdomain rentan terhadap Subdomain Takeover 
    dengan menganalisa DNS CNAME dan fingerprint response HTTP-nya.
    """
    subdomain = subdomain.strip().replace("http://", "").replace("https://", "").split("/")[0]
    
    try:
        # 1. Cek CNAME Record
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        cname_target = str(answers[0].target).lower()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return f"[+] {subdomain}: Not memiliki CNAME record yang mengarah ke external service (Aman)."

    # 2. Cek apakah CNAME mengarah ke cloud provider yang kita kenal
    matched_provider = None
    for provider, sig in FINGERPRINTS.items():
        if provider in cname_target:
            matched_provider = provider
            break
            
    if not matched_provider:
        return f"[+] {subdomain}: Memiliki CNAME ke {cname_target}, tapi not cocok dengan signature takeover yang diketahui."

    # 3. Kirim request HTTP untuk konfirmasi Fingerprint (Vulnerable atau Nggak)
    try:
        # Kirim request ke HTTP dan HTTPS dengan timeout cepat
        url = f"http://{subdomain}"
        auth_kw = get_auth_kwargs(subdomain)
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"}, **auth_kw)
        response_text = response.text
        
        expected_fingerprint = FINGERPRINTS[matched_provider]
        if expected_fingerprint in response_text:
            return f"[CRITICAL] VULNERABLE TO SUBDOMAIN TAKEOVER! Subdomain '{subdomain}' mengarah ke CNAME '{cname_target}' dan mengembalikan fingerprint '{expected_fingerprint}'. Segera klaim atau laporkan!"
            
        return f"[+] {subdomain}: Mengarah ke {matched_provider} ({cname_target}), tetapi layanannya tampaknya aktif / already diklaim."
        
    except requests.RequestException:
        return f"[-] {subdomain}: Failed memvalidasi HTTP response untuk CNAME {cname_target} (Server down / RTO)."
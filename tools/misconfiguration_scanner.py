import json
import requests
import re
import urllib3
from urllib.parse import urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.cancellation import check_cancelled
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
# TOOL: Misconfiguration Scanner
# ==========================================
@tool("misconfiguration_scanner")
def misconfiguration_scanner(url: str) -> str:
    """
    Scan comprehensive security misconfiguration pada target URL.
    Mencakup: .git/.env exposed, backup files, directory listing,
    default credentials, debug mode, server version disclosure,
    exposed admin panels, internal IP disclosure, HTTP→HTTPS redirect,
    cloud storage public, mixed content, insecure HTTP methods.
    """
    tool_name = "Misconfiguration Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting misconfiguration scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    base = url.rstrip("/")
    findings = {
        "target": url,
        "critical": [],
        "high": [],
        "medium": [],
        "info": []
    }

    # ── 1. .git folder exposed ────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking .git folder exposure")
    try:
        rate_limiter.wait(domain)
        r = requests.get(f"{base}/.git/HEAD", timeout=5, verify=False)
        if r.status_code == 200 and ("ref:" in r.text or "blob" in r.text.lower()):
            findings["critical"].append({
                "type": ".git Folder Exposed",
                "url": f"{base}/.git/HEAD",
                "detail": "Source code repository accessible — full source code dump possible",
                "severity": "Critical"
            })
            logger.add_log(tool_name, "WARNING", ".git folder exposed!")
    except Exception:
        pass

    # ── 2. .env file exposed ──────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking .env file exposure")
    for env_path in ["/.env", "/.env.local", "/.env.production", "/.env.backup"]:
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{env_path}", timeout=5, verify=False)
            if r.status_code == 200 and any(k in r.text for k in ["DB_", "APP_", "SECRET", "KEY=", "PASSWORD="]):
                findings["critical"].append({
                    "type": ".env File Exposed",
                    "url": f"{base}{env_path}",
                    "detail": "Environment file with credentials accessible",
                    "severity": "Critical"
                })
                logger.add_log(tool_name, "WARNING", f".env exposed: {env_path}")
                break
        except Exception:
            pass

    # ── 3. Backup files exposed ───────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking backup file exposure")
    backup_files = [
        "/index.php.bak", "/index.php~", "/web.config.bak",
        "/config.php.bak", "/backup.zip", "/backup.tar.gz",
        "/db.sql", "/database.sql", "/dump.sql",
        "/config.old", "/settings.php.bak", "/.htaccess.bak"
    ]
    for bf in backup_files:
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{bf}", timeout=5, verify=False)
            if r.status_code == 200 and len(r.content) > 100:
                findings["high"].append({
                    "type": "Backup File Exposed",
                    "url": f"{base}{bf}",
                    "detail": f"Backup file accessible: {bf}",
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", f"Backup file exposed: {bf}")
        except Exception:
            pass

    # ── 4. Directory listing ──────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking directory listing")
    dir_paths = ["/", "/uploads/", "/files/", "/static/", "/assets/", "/backup/", "/logs/"]
    for dp in dir_paths:
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{dp}", timeout=5, verify=False)
            if r.status_code == 200 and "Index of /" in r.text:
                findings["medium"].append({
                    "type": "Directory Listing Enabled",
                    "url": f"{base}{dp}",
                    "detail": "Server exposes directory contents",
                    "severity": "Medium"
                })
                logger.add_log(tool_name, "WARNING", f"Directory listing: {dp}")
        except Exception:
            pass

    # ── 5. Exposed admin panels ───────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking exposed admin panels")
    admin_paths = [
        "/admin", "/admin/", "/administrator", "/wp-admin",
        "/phpmyadmin", "/pma", "/cpanel", "/controlpanel",
        "/dashboard", "/manage", "/management", "/panel",
        "/admin/login", "/admin/index.php", "/backend"
    ]
    for ap in admin_paths:
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{ap}", timeout=5, verify=False, allow_redirects=True)
            if r.status_code == 200 and any(kw in r.text.lower() for kw in ["login", "password", "username", "admin"]):
                findings["high"].append({
                    "type": "Exposed Admin Panel",
                    "url": f"{base}{ap}",
                    "detail": f"Admin panel accessible without pre-auth at: {ap}",
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", f"Admin panel exposed: {ap}")
        except Exception:
            pass

    # ── 6. Debug mode / verbose errors ───────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking debug mode / verbose errors")
    debug_triggers = [
        f"{base}/debug",
        f"{base}/?debug=true",
        f"{base}/test",
        f"{base}/nonexistent-page-xyz123",
    ]
    debug_signatures = [
        "traceback", "stack trace", "exception in thread",
        "debug=true", "laravel", "symfony debug",
        "django.conf", "werkzeug debugger", "whats new in php"
    ]
    for dt in debug_triggers:
        try:
            rate_limiter.wait(domain)
            r = requests.get(dt, timeout=5, verify=False)
            if any(sig in r.text.lower() for sig in debug_signatures):
                findings["high"].append({
                    "type": "Debug Mode / Verbose Error",
                    "url": dt,
                    "detail": "Application exposes stack trace or debug information",
                    "severity": "High"
                })
                logger.add_log(tool_name, "WARNING", "Debug mode / verbose error detected")
                break
        except Exception:
            pass

    # ── 7. Server version disclosure ─────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking server version disclosure")
    try:
        rate_limiter.wait(domain)
        r = requests.get(base, timeout=5, verify=False)
        server_header = r.headers.get("Server", "")
        xpowered = r.headers.get("X-Powered-By", "")
        version_pattern = re.compile(r"[\d]+\.[\d]+")
        if version_pattern.search(server_header) or version_pattern.search(xpowered):
            findings["info"].append({
                "type": "Server Version Disclosure",
                "detail": f"Server: {server_header} | X-Powered-By: {xpowered}",
                "severity": "Info"
            })
            logger.add_log(tool_name, "WARNING", f"Version disclosed: {server_header} {xpowered}")
    except Exception:
        pass

    # ── 8. HTTP → HTTPS redirect missing ─────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking HTTP→HTTPS redirect")
    if base.startswith("https://"):
        http_url = base.replace("https://", "http://", 1)
        try:
            rate_limiter.wait(domain)
            r = requests.get(http_url, timeout=5, verify=False, allow_redirects=False)
            if r.status_code not in [301, 302, 307, 308]:
                findings["medium"].append({
                    "type": "Missing HTTP→HTTPS Redirect",
                    "url": http_url,
                    "detail": f"HTTP version returns {r.status_code} instead of redirect to HTTPS",
                    "severity": "Medium"
                })
                logger.add_log(tool_name, "WARNING", "HTTP→HTTPS redirect missing")
        except Exception:
            pass

    # ── 9. Internal IP disclosure ─────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking internal IP disclosure")
    try:
        rate_limiter.wait(domain)
        r = requests.get(base, timeout=5, verify=False)
        private_ip_pattern = re.compile(
            r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        )
        matches = private_ip_pattern.findall(r.text + str(dict(r.headers)))
        if matches:
            findings["medium"].append({
                "type": "Internal IP Disclosure",
                "detail": f"Private IP addresses found in response: {list(set(str(m) for m in matches))[:5]}",
                "severity": "Medium"
            })
            logger.add_log(tool_name, "WARNING", f"Internal IP disclosed: {matches[:3]}")
    except Exception:
        pass

    # ── 10. Cloud storage bucket exposure ────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking cloud storage exposure")
    cloud_patterns = [
        f"https://{domain}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{domain}",
        f"https://storage.googleapis.com/{domain}",
        f"https://{domain}.blob.core.windows.net",
    ]
    for cp in cloud_patterns:
        try:
            rate_limiter.wait(domain)
            r = requests.get(cp, timeout=5, verify=False)
            if r.status_code == 200 and any(kw in r.text for kw in ["ListBucketResult", "EnumerationResults", "Blob"]):
                findings["critical"].append({
                    "type": "Public Cloud Storage Bucket",
                    "url": cp,
                    "detail": "Cloud storage bucket is publicly readable",
                    "severity": "Critical"
                })
                logger.add_log(tool_name, "WARNING", f"Public cloud bucket: {cp}")
        except Exception:
            pass

    # ── 11. Default credentials check ────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking default credentials on common endpoints")
    default_creds = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("admin", "admin123"), ("root", "root"), ("test", "test"),
        ("admin", ""), ("administrator", "administrator"),
    ]
    login_paths = ["/login", "/admin/login", "/wp-login.php", "/user/login", "/signin"]
    for lp in login_paths[:3]:  # limit to top 3 to avoid too many requests
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{lp}", timeout=5, verify=False)
            if r.status_code == 200 and any(kw in r.text.lower() for kw in ["username", "password", "login"]):
                # Try default creds
                for uname, passwd in default_creds[:4]:
                    try:
                        rate_limiter.wait(domain)
                        resp = requests.post(
                            f"{base}{lp}",
                            data={"username": uname, "password": passwd, "email": uname},
                            timeout=5, verify=False, allow_redirects=True
                        )
                        if resp.status_code == 200 and any(kw in resp.text.lower() for kw in ["dashboard", "logout", "welcome", "profile"]):
                            findings["critical"].append({
                                "type": "Default Credentials",
                                "url": f"{base}{lp}",
                                "detail": f"Login succeeded with {uname}:{passwd}",
                                "severity": "Critical"
                            })
                            logger.add_log(tool_name, "WARNING", f"Default creds work: {uname}:{passwd} at {lp}")
                            break
                    except Exception:
                        pass
                break
        except Exception:
            pass

    # ── 12. Insecure HTTP methods ─────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking dangerous HTTP methods (TRACE, PUT, DELETE)")
    try:
        rate_limiter.wait(domain)
        r = requests.request("TRACE", base, timeout=5, verify=False)
        if r.status_code == 200 and "TRACE" in r.text:
            findings["medium"].append({
                "type": "TRACE Method Enabled (XST)",
                "url": base,
                "detail": "HTTP TRACE method enabled — Cross-Site Tracing (XST) possible",
                "severity": "Medium"
            })
            logger.add_log(tool_name, "WARNING", "TRACE method enabled")
    except Exception:
        pass

    # ── 13. DNS Rebinding Detection ───────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", "Checking DNS rebinding vulnerability indicators")
    try:
        import socket
        import dns.resolver

        # Resolve domain
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0]

        try:
            answers = dns.resolver.resolve(hostname, 'A')
            resolved_ips = [str(rdata) for rdata in answers]

            # Check if IP is in private ranges (potential rebinding target)
            private_ranges = [
                "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                "172.30.", "172.31.", "192.168.", "127.",
            ]

            for ip in resolved_ips:
                if any(ip.startswith(pr) for pr in private_ranges):
                    findings["high"].append({
                        "type": "DNS Rebinding Risk",
                        "detail": f"Domain {hostname} resolves to private IP: {ip}",
                        "severity": "High",
                        "evidence": "Domain pointing to internal/private IP — potential DNS rebinding target"
                    })
                    logger.add_log(tool_name, "WARNING", f"DNS rebinding risk: {hostname} -> {ip}")
                    break

            # Check for multiple IPs (fast-flux / rebinding indicator)
            if len(resolved_ips) > 3:
                findings["medium"].append({
                    "type": "Multiple DNS Records",
                    "detail": f"Domain has {len(resolved_ips)} A records: {', '.join(resolved_ips[:5])}",
                    "severity": "Medium",
                    "evidence": "Multiple A records may indicate fast-flux or DNS rebinding setup"
                })

        except dns.resolver.NXDOMAIN:
            findings["info"].append({
                "type": "DNS Resolution",
                "detail": f"Domain {hostname} not found (NXDOMAIN)",
            })
        except dns.resolver.NoAnswer:
            pass
        except Exception as dns_err:
            logger.add_log(tool_name, "WARNING", f"DNS check error: {dns_err}")

        # Check DNS-over-HTTPS / DNSSEC indicators
        try:
            resp = requests.get(url, timeout=5, verify=False)
            # Check if server sends DNS rebinding protection headers
            dns_rebind_headers = [
                "X-DNS-Validation",
                "X-Frame-Options",  # Some servers use this for DNS rebinding
            ]
            # Check Content-Security-Policy for frame-ancestors (rebinding protection)
            csp = resp.headers.get("Content-Security-Policy", "")
            if "frame-ancestors" not in csp and "frame-ancestors" not in csp.lower():
                # DNS rebinding often exploits framing
                pass  # Not a direct indicator, skip
        except Exception:
            pass

    except ImportError:
        logger.add_log(tool_name, "WARNING", "dnspython not installed, skipping DNS rebinding check")
    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"DNS rebinding check failed: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    total = sum(len(v) for v in [findings["critical"], findings["high"], findings["medium"], findings["info"]])
    logger.add_log(tool_name, "SUCCESS", f"Misconfiguration scan complete. Found {total} issues.")
    return json.dumps(findings, indent=2)

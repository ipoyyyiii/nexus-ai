import os
import json
import requests
import re
import urllib3
from urllib.parse import urlparse
from langchain.tools import tool
from rate_limiter import rate_limiter
from cancellation import check_cancelled
from auth_store import get_auth_kwargs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _domain_of(url_or_domain: str) -> str:
    try:
        if url_or_domain.startswith("http"):
            return urlparse(url_or_domain).netloc.split(":")[0].lower()
        return url_or_domain.lower()
    except Exception:
        return url_or_domain

def _logger():
    from custom_tools import exec_logger
    return exec_logger

def _get_shodan_key() -> str | None:
    return os.environ.get("SHODAN_API_KEY") or None

def _get_censys_pat() -> str | None:
    return os.environ.get("CENSYS_PAT") or None

# ==========================================
# TOOL 1: Shodan Intelligence Scanner
# ==========================================
@tool("shodan_scanner")
def shodan_scanner(target: str) -> str:
    """
    Recon komprehensif menggunakan Shodan API.
    Bisa menerima: domain, IP address, atau CIDR range.
    Data yang dikumpulkan:
    - Open ports & services (dengan banner info)
    - CVEs yang terdeteksi
    - Technology fingerprint (server, framework, OS)
    - SSL/TLS certificate info
    - Geolocation & ISP/ASN
    - Historical scan data
    - Related IPs (dari ASN yang sama)
    target: domain atau IP (e.g., "example.com" atau "93.184.216.34")
    """
    tool_name = "Shodan Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Memulai Shodan recon untuk {target}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    api_key = _get_shodan_key()
    if not api_key or api_key == "your_shodan_api_key_here":
        return json.dumps({
            "error": "SHODAN_API_KEY tidak di-set di .env",
            "action": "Tambahkan: SHODAN_API_KEY=your_key ke file .env"
        })

    SHODAN_BASE = "https://api.shodan.io"
    findings = {
        "target": target,
        "resolved_ip": None,
        "host_info": {},
        "open_ports": [],
        "services": [],
        "cves": [],
        "technologies": [],
        "ssl_info": {},
        "geolocation": {},
        "related_hosts": [],
        "dns_resolve": {},
        "domain_info": {}
    }

    # ── 1. Resolve domain ke IP ───────────────────────────────────────────────
    import socket
    target_ip = target
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        logger.add_log(tool_name, "PROCESSING", f"Resolving {target} → IP")
        try:
            target_ip = socket.gethostbyname(target)
            findings["resolved_ip"] = target_ip
            logger.add_log(tool_name, "SUCCESS", f"Resolved: {target} → {target_ip}")
        except Exception as e:
            logger.add_log(tool_name, "WARNING", f"DNS resolution failed: {e}")

        # ── 1b. Shodan DNS resolve ────────────────────────────────────────────
        try:
            rate_limiter.wait("api.shodan.io")
            r = requests.get(
                f"{SHODAN_BASE}/dns/resolve",
                params={"hostnames": target, "key": api_key},
                timeout=10
            )
            if r.status_code == 200:
                findings["dns_resolve"] = r.json()

            # Domain info (subdomains dari Shodan)
            rate_limiter.wait("api.shodan.io")
            r = requests.get(
                f"{SHODAN_BASE}/dns/domain/{_domain_of(target)}",
                params={"key": api_key},
                timeout=10
            )
            if r.status_code == 200:
                domain_data = r.json()
                findings["domain_info"] = {
                    "domain": domain_data.get("domain"),
                    "subdomains": domain_data.get("subdomains", [])[:30],
                    "tags": domain_data.get("tags", []),
                    "data_count": len(domain_data.get("data", []))
                }
                logger.add_log(tool_name, "SUCCESS",
                    f"Domain info: {len(domain_data.get('subdomains', []))} subdomains found")
        except Exception as e:
            logger.add_log(tool_name, "WARNING", f"Domain info error: {e}")

    # ── 2. Host lookup ────────────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", f"Fetching Shodan host info for {target_ip}")
    try:
        rate_limiter.wait("api.shodan.io")
        r = requests.get(
            f"{SHODAN_BASE}/shodan/host/{target_ip}",
            params={"key": api_key, "history": False, "minify": False},
            timeout=15
        )
        if r.status_code == 200:
            host = r.json()

            # Basic info
            findings["geolocation"] = {
                "country": host.get("country_name"),
                "city": host.get("city"),
                "region": host.get("region_code"),
                "latitude": host.get("latitude"),
                "longitude": host.get("longitude"),
                "isp": host.get("isp"),
                "org": host.get("org"),
                "asn": host.get("asn"),
            }

            findings["open_ports"] = sorted(host.get("ports", []))

            # CVEs
            vulns = host.get("vulns", {})
            if vulns:
                for cve_id, cve_info in vulns.items():
                    findings["cves"].append({
                        "cve": cve_id,
                        "cvss": cve_info.get("cvss", "N/A"),
                        "summary": cve_info.get("summary", "")[:200],
                        "references": cve_info.get("references", [])[:3]
                    })
                logger.add_log(tool_name, "WARNING",
                    f"CVEs found: {list(vulns.keys())[:5]}")

            # Services / banners
            for service in host.get("data", []):
                svc = {
                    "port": service.get("port"),
                    "transport": service.get("transport", "tcp"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "cpe": service.get("cpe", []),
                    "banner_preview": str(service.get("data", ""))[:150].strip(),
                    "timestamp": service.get("timestamp"),
                }

                # HTTP info
                if "http" in service:
                    http_info = service["http"]
                    svc["http"] = {
                        "title": http_info.get("title"),
                        "server": http_info.get("server"),
                        "status": http_info.get("status"),
                        "robots_hash": http_info.get("robots_hash"),
                        "favicon_hash": http_info.get("favicon", {}).get("hash") if isinstance(http_info.get("favicon"), dict) else None,
                        "components": list(http_info.get("components", {}).keys())[:10],
                        "headers": {k: v for k, v in (http_info.get("headers", {}) or {}).items() if k.lower() in [
                            "server", "x-powered-by", "x-frame-options",
                            "content-security-policy", "strict-transport-security"
                        ]},
                    }
                    # Collect technologies
                    for comp in http_info.get("components", {}).keys():
                        if comp not in findings["technologies"]:
                            findings["technologies"].append(comp)

                # SSL info
                if "ssl" in service:
                    ssl_data = service["ssl"]
                    cert = ssl_data.get("cert", {})
                    findings["ssl_info"] = {
                        "version": ssl_data.get("version"),
                        "cipher": ssl_data.get("cipher", {}).get("name"),
                        "subject": cert.get("subject", {}),
                        "issuer": cert.get("issuer", {}),
                        "expires": cert.get("expires"),
                        "expired": cert.get("expired", False),
                        "ja3s": ssl_data.get("ja3s"),
                        "alpn": ssl_data.get("alpn", []),
                    }

                findings["services"].append(svc)

            findings["host_info"] = {
                "ip": host.get("ip_str"),
                "hostnames": host.get("hostnames", []),
                "domains": host.get("domains", []),
                "os": host.get("os"),
                "tags": host.get("tags", []),
                "last_update": host.get("last_update"),
                "total_ports": len(findings["open_ports"]),
                "total_services": len(findings["services"]),
                "total_cves": len(findings["cves"])
            }
            logger.add_log(tool_name, "SUCCESS",
                f"Host info: {len(findings['open_ports'])} ports, {len(findings['cves'])} CVEs")

        elif r.status_code == 404:
            findings["host_info"] = {"note": "No Shodan data for this IP"}
        elif r.status_code == 401:
            return json.dumps({"error": "Invalid Shodan API key"})
        else:
            logger.add_log(tool_name, "WARNING", f"Shodan host lookup: HTTP {r.status_code}")

    except Exception as e:
        logger.add_log(tool_name, "ERROR", f"Host lookup failed: {e}")

    # ── 3. Search related hosts (same ASN / org) ──────────────────────────────
    asn = findings["geolocation"].get("asn")
    if asn:
        logger.add_log(tool_name, "PROCESSING", f"Searching related hosts in ASN {asn}")
        try:
            rate_limiter.wait("api.shodan.io")
            r = requests.get(
                f"{SHODAN_BASE}/shodan/search",
                params={
                    "key": api_key,
                    "query": f"asn:{asn}",
                    "facets": "ip,port",
                    "page": 1,
                    "minify": True
                },
                timeout=15
            )
            if r.status_code == 200:
                search_data = r.json()
                related = []
                for match in search_data.get("matches", [])[:15]:
                    ip = match.get("ip_str")
                    if ip and ip != target_ip:
                        related.append({
                            "ip": ip,
                            "port": match.get("port"),
                            "hostnames": match.get("hostnames", [])[:3],
                            "product": match.get("product"),
                        })
                findings["related_hosts"] = related
                logger.add_log(tool_name, "SUCCESS",
                    f"Related hosts in ASN {asn}: {len(related)} found")
        except Exception as e:
            logger.add_log(tool_name, "WARNING", f"ASN search error: {e}")

    # ── 4. Pentest summary ────────────────────────────────────────────────────
    critical_ports = [21, 22, 23, 25, 445, 3306, 5432, 6379, 27017, 9200, 5601]
    exposed_critical = [p for p in findings["open_ports"] if p in critical_ports]
    findings["pentest_summary"] = {
        "exposed_critical_ports": exposed_critical,
        "has_known_cves": len(findings["cves"]) > 0,
        "cve_count": len(findings["cves"]),
        "highest_cvss": max((c.get("cvss", 0) or 0 for c in findings["cves"]), default=0),
        "technologies_detected": findings["technologies"][:10],
        "attack_surface_score": (
            "HIGH" if (exposed_critical or len(findings["cves"]) > 0)
            else "MEDIUM" if len(findings["open_ports"]) > 5
            else "LOW"
        )
    }

    logger.add_log(tool_name, "SUCCESS",
        f"Shodan scan complete. Ports: {len(findings['open_ports'])}, "
        f"CVEs: {len(findings['cves'])}, Services: {len(findings['services'])}")
    return json.dumps(findings, indent=2)


# ==========================================
# TOOL 2: Censys Intelligence Scanner
# ==========================================
@tool("censys_scanner")
def censys_scanner(target: str) -> str:
    """
    Recon komprehensif menggunakan Censys API v2.
    Bisa menerima: domain atau IP address.
    Data yang dikumpulkan:
    - Open ports & protocols
    - TLS/SSL certificate detail (SAN, chain, issuer)
    - Service banners dan software versions
    - HTTP response headers dan titles
    - BGP/routing info
    - Historical certificates (buat subdomain discovery)
    - Infrastructure fingerprint
    target: domain atau IP (e.g., "example.com" atau "93.184.216.34")
    """
    tool_name = "Censys Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Memulai Censys recon untuk {target}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    pat = _get_censys_pat()
    if not pat or pat == "your_censys_pat_here":
        return json.dumps({
            "error": "CENSYS_PAT tidak di-set di .env",
            "action": "Tambahkan CENSYS_PAT=your_personal_access_token ke file .env",
            "get_pat": "Login ke https://search.censys.io → Account → Personal Access Tokens → Generate token"
        })

    CENSYS_BASE = "https://search.censys.io/api/v2"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {pat}"
    }

    findings = {
        "target": target,
        "resolved_ip": None,
        "host_info": {},
        "open_ports": [],
        "services": [],
        "tls_certificates": [],
        "subdomains_from_certs": [],
        "technologies": [],
        "routing": {},
        "autonomous_system": {}
    }

    # ── 1. Resolve domain ─────────────────────────────────────────────────────
    import socket
    target_ip = target
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        logger.add_log(tool_name, "PROCESSING", f"Resolving {target}")
        try:
            target_ip = socket.gethostbyname(target)
            findings["resolved_ip"] = target_ip
            logger.add_log(tool_name, "SUCCESS", f"Resolved: {target} → {target_ip}")
        except Exception as e:
            logger.add_log(tool_name, "WARNING", f"DNS resolution failed: {e}")

    # ── 2. Host view ──────────────────────────────────────────────────────────
    logger.add_log(tool_name, "PROCESSING", f"Fetching Censys host data for {target_ip}")
    try:
        rate_limiter.wait("search.censys.io")
        r = requests.get(
            f"{CENSYS_BASE}/hosts/{target_ip}",
            headers=headers, timeout=15
        )
        if r.status_code == 200:
            data = r.json().get("result", {})

            # Basic host info
            findings["host_info"] = {
                "ip": data.get("ip"),
                "last_updated": data.get("last_updated_at"),
                "labels": data.get("labels", []),
            }

            # Routing / BGP
            routing = data.get("routing", {})
            findings["routing"] = {
                "as_number": routing.get("as_number"),
                "as_name": routing.get("as_organization"),
                "bgp_prefix": routing.get("bgp_prefix"),
                "country": routing.get("country"),
                "country_code": routing.get("country_code"),
            }

            # Services
            for svc in data.get("services", []):
                port = svc.get("port")
                transport = svc.get("transport_protocol", "tcp")
                service_name = svc.get("service_name", "unknown")
                extended = svc.get("extended_service_name", service_name)

                svc_info = {
                    "port": port,
                    "transport": transport,
                    "service": service_name,
                    "extended_service": extended,
                    "software": [],
                    "banner": None
                }

                if port not in findings["open_ports"]:
                    findings["open_ports"].append(port)

                # Software versions
                for sw in svc.get("software", []):
                    svc_info["software"].append({
                        "product": sw.get("product"),
                        "vendor": sw.get("vendor"),
                        "version": sw.get("version"),
                        "cpe": sw.get("uniform_resource_identifier"),
                    })
                    product = sw.get("product", "")
                    if product and product not in findings["technologies"]:
                        findings["technologies"].append(product)

                # HTTP specific
                if "http" in svc:
                    http = svc["http"]
                    resp = http.get("response", {})
                    svc_info["http"] = {
                        "status_code": resp.get("status_code"),
                        "title": resp.get("html_title"),
                        "headers": {
                            k: v for k, v in (resp.get("headers", {}) or {}).items()
                            if k.lower() in [
                                "server", "x-powered-by", "x-frame-options",
                                "content-security-policy", "strict-transport-security",
                                "x-content-type-options", "set-cookie"
                            ]
                        },
                        "body_hash": resp.get("body_hash"),
                        "body_size": resp.get("body_size"),
                    }
                    if resp.get("html_title"):
                        logger.add_log(tool_name, "SUCCESS",
                            f"Port {port} title: {resp['html_title']}")

                # TLS/Certificate
                if "tls" in svc:
                    tls = svc["tls"]
                    cert = tls.get("certificates", {}).get("leaf_data", {})
                    names = cert.get("names", [])
                    svc_info["tls"] = {
                        "version": tls.get("version_selected"),
                        "cipher": tls.get("cipher_selected"),
                        "common_name": cert.get("subject_dn"),
                        "issuer": cert.get("issuer_dn"),
                        "not_before": cert.get("validity", {}).get("start"),
                        "not_after": cert.get("validity", {}).get("end"),
                        "subject_alt_names": names[:20],
                        "fingerprint": cert.get("fingerprint", {}).get("sha256"),
                    }

                    # Extract subdomains from SAN
                    domain_base = _domain_of(target)
                    for name in names:
                        name = name.lstrip("*.")
                        if domain_base in name and name not in findings["subdomains_from_certs"]:
                            findings["subdomains_from_certs"].append(name)

                    if svc_info["tls"] not in findings["tls_certificates"]:
                        findings["tls_certificates"].append(svc_info["tls"])

                findings["services"].append(svc_info)

            logger.add_log(tool_name, "SUCCESS",
                f"Host data: {len(findings['open_ports'])} ports, {len(findings['services'])} services")

        elif r.status_code == 404:
            findings["host_info"] = {"note": "No Censys data found for this IP"}
        elif r.status_code == 401:
            return json.dumps({"error": "Invalid Censys credentials"})
        elif r.status_code == 429:
            return json.dumps({"error": "Censys rate limit exceeded — wait a moment"})
        else:
            logger.add_log(tool_name, "WARNING", f"Censys host lookup: HTTP {r.status_code}")

    except Exception as e:
        logger.add_log(tool_name, "ERROR", f"Host view failed: {e}")

    # ── 3. Certificate search (subdomain discovery) ───────────────────────────
    domain_base = _domain_of(target)
    logger.add_log(tool_name, "PROCESSING", f"Searching certificates for *.{domain_base}")
    try:
        rate_limiter.wait("search.censys.io")
        r = requests.get(
            f"{CENSYS_BASE}/hosts/search",
            headers=headers,
            params={
                "q": f"services.tls.certificates.leaf_data.names: {domain_base}",
                "per_page": 25,
                "fields": ["ip", "services.port", "services.service_name",
                           "services.tls.certificates.leaf_data.names",
                           "routing.as_organization"]
            },
            timeout=15
        )
        if r.status_code == 200:
            search_data = r.json().get("result", {})
            hits = search_data.get("hits", [])

            for hit in hits:
                ip = hit.get("ip")
                if ip and ip != target_ip:
                    # Extract subdomains from this host's certs
                    for svc in hit.get("services", []):
                        for cert_name in svc.get("tls", {}).get("certificates", {}).get("leaf_data", {}).get("names", []):
                            cert_name = cert_name.lstrip("*.")
                            if domain_base in cert_name and cert_name not in findings["subdomains_from_certs"]:
                                findings["subdomains_from_certs"].append(cert_name)

            logger.add_log(tool_name, "SUCCESS",
                f"Cert search: {len(findings['subdomains_from_certs'])} unique (sub)domains found")

    except Exception as e:
        logger.add_log(tool_name, "WARNING", f"Certificate search failed: {e}")

    # ── 4. Pentest summary ────────────────────────────────────────────────────
    critical_ports = [21, 22, 23, 25, 445, 3306, 5432, 6379, 27017, 9200, 5601, 2375, 4243]
    exposed_critical = [p for p in findings["open_ports"] if p in critical_ports]
    findings["pentest_summary"] = {
        "exposed_critical_ports": exposed_critical,
        "total_open_ports": len(findings["open_ports"]),
        "total_services": len(findings["services"]),
        "subdomains_discovered": len(findings["subdomains_from_certs"]),
        "technologies_detected": findings["technologies"][:15],
        "routing": findings["routing"].get("as_name"),
        "attack_surface_score": (
            "HIGH" if exposed_critical
            else "MEDIUM" if len(findings["open_ports"]) > 5
            else "LOW"
        )
    }

    logger.add_log(tool_name, "SUCCESS",
        f"Censys scan complete. Ports: {len(findings['open_ports'])}, "
        f"Subdomains: {len(findings['subdomains_from_certs'])}")
    return json.dumps(findings, indent=2)

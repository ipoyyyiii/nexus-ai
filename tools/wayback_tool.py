import requests
import re
from urllib.parse import urlparse
from langchain.tools import tool
from core.cancellation import check_cancelled
from tools.custom_tools import exec_logger
from core.auth_store import get_auth_kwargs

INTERESTING_EXTENSIONS = {
    "sensitive_files": [".env", ".config", ".json", ".xml", ".yaml", ".yml", ".bak", ".backup", ".sql", ".db"],
    "api_endpoints": ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/admin/", "/internal/"],
    "auth_endpoints": ["/login", "/auth", "/oauth", "/token", "/reset", "/register", "/signup"],
    "debug_endpoints": ["/debug", "/test", "/dev", "/staging", "/console", "/panel"],
}

@tool("wayback_scraper")
def wayback_scraper(domain: str) -> str:
    """
    Scrape Wayback Machine (archive.org) buat nemuin semua URL historis dari target domain.
    Sangat efektif buat nemuin endpoint lama, file sensitif, dan parameter tersembunyi
    yang udah deleted dari UI tapi servernya masih aktif.
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    # Bersihin domain input
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]

    exec_logger.add_log("Wayback Scraper", "START", f"Scraping Wayback Machine untuk {domain}")

    try:
        # Hit Wayback CDX API — collapse by urlkey biar gak dobel
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*"
            f"&output=json"
            f"&fl=original,statuscode,timestamp"
            f"&collapse=urlkey"
            f"&limit=5000"
            f"&filter=statuscode:200"
        )

        exec_logger.add_log("Wayback Scraper", "PROCESSING", "Fetching URL list dari CDX API")
        resp = requests.get(cdx_url, timeout=30)
        resp.raise_for_status()

        raw = resp.json()
        if not raw or len(raw) <= 1:
            return f"Wayback Machine not punya data historis untuk {domain}."

        # Skip header row
        entries = raw[1:]
        exec_logger.add_log("Wayback Scraper", "SUCCESS", f"Total URL historis found: {len(entries)}")

        # Kategorisasi URL
        findings = {
            "sensitive_files": [],
            "api_endpoints": [],
            "auth_endpoints": [],
            "debug_endpoints": [],
            "parameters": [],
            "other_interesting": [],
        }

        seen_urls = set()
        for entry in entries:
            url = entry[0]
            if url in seen_urls:
                continue
            seen_urls.add(url)

            url_lower = url.lower()

            # Cek sensitive files
            if any(ext in url_lower for ext in INTERESTING_EXTENSIONS["sensitive_files"]):
                findings["sensitive_files"].append(url)
                continue

            # Cek API endpoints
            if any(path in url_lower for path in INTERESTING_EXTENSIONS["api_endpoints"]):
                findings["api_endpoints"].append(url)
                continue

            # Cek auth endpoints
            if any(path in url_lower for path in INTERESTING_EXTENSIONS["auth_endpoints"]):
                findings["auth_endpoints"].append(url)
                continue

            # Cek debug endpoints
            if any(path in url_lower for path in INTERESTING_EXTENSIONS["debug_endpoints"]):
                findings["debug_endpoints"].append(url)
                continue

            # Cek URL dengan parameter (potential injection points)
            if "?" in url and "=" in url:
                findings["parameters"].append(url)

        # Build output report
        total_interesting = sum(len(v) for v in findings.values())
        exec_logger.add_log("Wayback Scraper", "SUCCESS", f"Interesting URLs: {total_interesting} dari {len(entries)} total")

        output = f"=== WAYBACK MACHINE RESULTS FOR {domain} ===\n"
        output += f"Total URL historis: {len(entries)} | Interesting: {total_interesting}\n\n"

        if findings["sensitive_files"]:
            output += f"[🔴 SENSITIVE FILES] ({len(findings['sensitive_files'])} found)\n"
            for url in findings["sensitive_files"][:20]:
                output += f"  - {url}\n"

        if findings["api_endpoints"]:
            output += f"\n[🟠 API ENDPOINTS] ({len(findings['api_endpoints'])} found)\n"
            for url in findings["api_endpoints"][:20]:
                output += f"  - {url}\n"

        if findings["auth_endpoints"]:
            output += f"\n[🟡 AUTH ENDPOINTS] ({len(findings['auth_endpoints'])} found)\n"
            for url in findings["auth_endpoints"][:15]:
                output += f"  - {url}\n"

        if findings["debug_endpoints"]:
            output += f"\n[🔴 DEBUG/ADMIN ENDPOINTS] ({len(findings['debug_endpoints'])} found)\n"
            for url in findings["debug_endpoints"][:15]:
                output += f"  - {url}\n"

        if findings["parameters"]:
            output += f"\n[🟢 URLS WITH PARAMETERS] ({len(findings['parameters'])} found)\n"
            for url in findings["parameters"][:25]:
                output += f"  - {url}\n"

        if total_interesting == 0:
            output += "Not ada URL menarik yang found dari historical data.\n"

        return output

    except requests.Timeout:
        exec_logger.add_log("Wayback Scraper", "ERROR", "Timeout saat fetch CDX API")
        return f"Timeout: Wayback Machine not merespons dalam 30 detik untuk {domain}."
    except Exception as e:
        exec_logger.add_log("Wayback Scraper", "ERROR", f"Scraping failed: {str(e)}")
        return f"Wayback scraping error: {str(e)}"
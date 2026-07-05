"""
DEEP JS ANALYSIS
==================
Analisa JavaScript lebih dalam dari sekedar regex scan.
Difokuskan ke endpoint extraction dan dependency analysis
yang sering jadi attack vector di modern SPA (React/Vue/Angular).

Extends playwright_tools.browser_extract_js_secrets dengan:
1. Source map detection & extraction
2. webpack chunk analysis (nemuin semua route di SPA)
3. API base URL detection
4. GraphQL schema extraction dari introspection
5. Environment variable leak detection
"""

import json
import re
from urllib.parse import urlparse, urljoin

import requests
import urllib3
from crewai.tools import tool

from cancellation import check_cancelled
from rate_limiter import rate_limiter
from redact import redact

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SESSION = requests.Session()
SESSION.verify = False
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


# ── Patterns ─────────────────────────────────────────────────────────────────

API_URL_PATTERNS = [
    # Base URL patterns
    re.compile(r'(?:baseURL|baseUrl|API_URL|REACT_APP_API|VUE_APP_API|NEXT_PUBLIC_API)["\s:=]+["\']?(https?://[^\s"\'`,]+)', re.I),
    re.compile(r'(?:apiUrl|api_url|endpoint|base_url)["\s:=]+["\']?(https?://[^\s"\'`,]+)', re.I),
    # Relative API paths
    re.compile(r'["\']/(api|v\d+|rest|graphql)/[a-zA-Z0-9_/\-]+["\']'),
    # Axios/fetch base URL
    re.compile(r'axios\.create\(\{[^}]*baseURL[:\s]+["\']([^"\']+)["\']', re.I),
    re.compile(r'fetch\(["\']([^"\']+)["\']', re.I),
]

ENV_LEAK_PATTERNS = {
    "NEXT_PUBLIC vars": re.compile(r'NEXT_PUBLIC_[A-Z_]+["\s:=]+["\']?([^\s"\'`,]{5,})', re.I),
    "REACT_APP vars": re.compile(r'REACT_APP_[A-Z_]+["\s:=]+["\']?([^\s"\'`,]{5,})', re.I),
    "VUE_APP vars": re.compile(r'VUE_APP_[A-Z_]+["\s:=]+["\']?([^\s"\'`,]{5,})', re.I),
    "process.env leak": re.compile(r'process\.env\.([A-Z_]{5,})["\s:=]+["\']?([^\s"\'`,]{5,})'),
    "NODE_ENV": re.compile(r'NODE_ENV["\s:=]+["\']?(development|staging|test)["\']', re.I),
}

GRAPHQL_PATTERNS = [
    re.compile(r'["\']([^"\']*graphql[^"\']*)["\']', re.I),
    re.compile(r'gql`([^`]+)`'),
    re.compile(r'query\s+\w+\s*\{[^}]+\}'),
    re.compile(r'mutation\s+\w+\s*[({][^)}]+[)}]'),
]

WEBPACK_ROUTE_PATTERN = re.compile(
    r'["\']([/][a-zA-Z0-9_\-/]+)["\'],?\s*(?:component|page|lazy)',
    re.I
)

SOURCE_MAP_PATTERN = re.compile(r'//# sourceMappingURL=(.+\.map)')


@tool
def analyze_js_deep(url: str) -> str:
    """
    Analisa JavaScript secara mendalam buat extract:
    - Semua API endpoint dan base URLs
    - Environment variable yang ke-leak
    - GraphQL queries dan schema hints
    - SPA routes (dari webpack chunks)
    - Source maps yang exposed (bisa reveal original source code)
    - Third-party service integrations

    Args:
        url: URL halaman target (bukan JS file langsung)
    Returns:
        JSON berisi semua findings dari JS analysis
    """
    logger = _logger()
    tool_name = "Deep JS Analyzer"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    if logger:
        logger.add_log(tool_name, "START", f"Deep JS analysis untuk {url}")

    # ── 1. Collect JS files dari halaman ─────────────────────────────────────
    rate_limiter.wait(domain)
    try:
        page_resp = SESSION.get(url, headers=HEADERS, timeout=15)
        page_html = page_resp.text
    except Exception as e:
        return json.dumps({"error": f"Gagal load halaman: {str(e)}"})

    # Extract script URLs dari HTML
    script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
    script_urls = []
    for match in script_pattern.finditer(page_html):
        src = match.group(1)
        if src.startswith("http"):
            script_urls.append(src)
        elif src.startswith("/"):
            script_urls.append(f"{base}{src}")
        else:
            script_urls.append(urljoin(url, src))

    # Deduplicate dan filter ke domain yang sama atau CDN
    seen = set()
    filtered_scripts = []
    for s in script_urls:
        s_domain = _domain_of(s)
        if s not in seen and (s_domain == domain or "cdn" in s_domain):
            filtered_scripts.append(s)
            seen.add(s)

    if logger:
        logger.add_log(tool_name, "PROCESSING", f"Found {len(filtered_scripts)} JS files to analyze")

    findings = {
        "api_endpoints": [],
        "env_leaks": [],
        "graphql_hints": [],
        "spa_routes": [],
        "source_maps": [],
        "third_party_services": [],
        "webpack_chunks": [],
    }

    third_party_patterns = {
        "Stripe": re.compile(r'stripe\.com|pk_live_|pk_test_', re.I),
        "Firebase": re.compile(r'firebase|firebaseapp\.com|apiKey.*AIza', re.I),
        "Sentry": re.compile(r'sentry\.io|Sentry\.init', re.I),
        "Segment": re.compile(r'segment\.com|analytics\.load', re.I),
        "Mixpanel": re.compile(r'mixpanel\.com|mixpanel\.init', re.I),
        "Amplitude": re.compile(r'amplitude\.com', re.I),
        "Intercom": re.compile(r'intercom\.io|intercomSettings', re.I),
        "HubSpot": re.compile(r'hubspot\.com|hubspot\.js', re.I),
    }

    # ── 2. Analyze tiap JS file ───────────────────────────────────────────────
    for js_url in filtered_scripts[:15]:  # Max 15 file
        if check_cancelled(logger):
            break

        rate_limiter.wait(_domain_of(js_url))
        try:
            js_resp = SESSION.get(js_url, headers=HEADERS, timeout=15)
            if "javascript" not in js_resp.headers.get("content-type", "") and js_resp.status_code != 200:
                continue

            js_content = js_resp.text
            js_size = len(js_content)

            # Source map check
            sm_match = SOURCE_MAP_PATTERN.search(js_content[-500:])
            if sm_match:
                sm_url = sm_match.group(1)
                if not sm_url.startswith("http"):
                    sm_url = urljoin(js_url, sm_url)
                # Verify source map accessible
                rate_limiter.wait(_domain_of(sm_url))
                try:
                    sm_resp = SESSION.get(sm_url, headers=HEADERS, timeout=5)
                    if sm_resp.status_code == 200 and "sources" in sm_resp.text:
                        findings["source_maps"].append({
                            "js_file": js_url,
                            "source_map": sm_url,
                            "severity": "HIGH",
                            "impact": "Source map exposed — original source code bisa di-recover",
                        })
                except Exception:
                    pass

            # API endpoint extraction
            for pattern in API_URL_PATTERNS:
                for match in pattern.findall(js_content):
                    endpoint = match if isinstance(match, str) else match[0]
                    if endpoint and len(endpoint) > 3 and endpoint not in findings["api_endpoints"]:
                        findings["api_endpoints"].append(endpoint)

            # Environment variable leaks
            for leak_type, pattern in ENV_LEAK_PATTERNS.items():
                matches = pattern.findall(js_content)
                if matches:
                    findings["env_leaks"].append({
                        "type": leak_type,
                        "file": js_url,
                        "count": len(matches),
                        "note": "Nilai actual di-redact. Review manual untuk konfirmasi.",
                    })

            # GraphQL hints
            for gql_pattern in GRAPHQL_PATTERNS:
                gql_matches = gql_pattern.findall(js_content)
                if gql_matches and len(gql_matches) > 2:
                    findings["graphql_hints"].append({
                        "file": js_url,
                        "query_count": len(gql_matches),
                        "sample": str(gql_matches[0])[:100] if gql_matches else "",
                    })
                    break

            # SPA routes (webpack)
            routes = WEBPACK_ROUTE_PATTERN.findall(js_content)
            for route in routes:
                if route not in findings["spa_routes"] and len(route) > 1:
                    findings["spa_routes"].append(route)

            # Third party services
            for service, pattern in third_party_patterns.items():
                if pattern.search(js_content):
                    if service not in findings["third_party_services"]:
                        findings["third_party_services"].append(service)

            # Webpack chunk detection
            chunk_pattern = re.compile(r'chunk[s]?\s*\(["\']([^"\']+)["\']', re.I)
            chunks = chunk_pattern.findall(js_content)
            if chunks:
                findings["webpack_chunks"].extend(chunks[:10])

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "WARNING", f"Error analyze {js_url}: {str(e)[:100]}")
            continue

    # Deduplicate
    findings["api_endpoints"] = list(dict.fromkeys(findings["api_endpoints"]))[:50]
    findings["spa_routes"] = list(dict.fromkeys(findings["spa_routes"]))[:30]
    findings["webpack_chunks"] = list(dict.fromkeys(findings["webpack_chunks"]))[:20]

    # ── 3. Check GraphQL introspection ────────────────────────────────────────
    if findings["graphql_hints"]:
        graphql_endpoints = [e for e in findings["api_endpoints"] if "graphql" in e.lower()]
        if not graphql_endpoints:
            graphql_endpoints = [f"{base}/graphql", f"{base}/api/graphql"]

        for gql_url in graphql_endpoints[:2]:
            if check_cancelled(logger):
                break
            rate_limiter.wait(_domain_of(gql_url))
            try:
                introspection_query = '{"query": "{ __schema { queryType { name } } }"}'
                resp = SESSION.post(
                    gql_url,
                    data=introspection_query,
                    headers={**HEADERS, "Content-Type": "application/json"},
                    timeout=10
                )
                if resp.status_code == 200 and "__schema" in resp.text:
                    findings["graphql_hints"].append({
                        "endpoint": gql_url,
                        "introspection_enabled": True,
                        "severity": "MEDIUM",
                        "impact": "GraphQL introspection enabled — full schema bisa di-dump",
                    })
            except Exception:
                pass

    result = {
        "url": url,
        "js_files_analyzed": len(filtered_scripts),
        "findings": findings,
        "summary": {
            "api_endpoints_found": len(findings["api_endpoints"]),
            "env_leaks_found": len(findings["env_leaks"]),
            "source_maps_exposed": len(findings["source_maps"]),
            "spa_routes_found": len(findings["spa_routes"]),
            "graphql_detected": len(findings["graphql_hints"]) > 0,
            "third_party_services": findings["third_party_services"],
        },
        "status": "success" if not check_cancelled(logger) else "cancelled"
    }

    if logger:
        has_critical = findings["source_maps"] or findings["env_leaks"]
        logger.add_log(
            tool_name,
            "WARNING" if has_critical else "SUCCESS",
            f"Deep JS analysis selesai. {len(findings['api_endpoints'])} endpoints, "
            f"{len(findings['source_maps'])} source maps, {len(findings['env_leaks'])} env leaks."
        )

    return json.dumps(redact(result), indent=2)
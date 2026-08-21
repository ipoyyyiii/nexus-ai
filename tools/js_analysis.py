import json
import re
from urllib.parse import urlparse, urljoin

from core.tool_transport import guarded_requests as requests
import urllib3
from core.tool_decorator import crewai_tool as tool

from core.cancellation import check_cancelled
from core.rate_limiter import rate_limiter
from core.redact import redact
# 1. Taruh import proxy router di paling atas file men
from core.proxy_router import proxy_router
from core.auth_store import inject_into_session

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        from tools.custom_tools import exec_logger
        return exec_logger
    except Exception:
        return None


# ── Patterns ─────────────────────────────────────────────────────────────────

API_URL_PATTERNS = [
    re.compile(r'(?:baseURL|baseUrl|API_URL|REACT_APP_API|VUE_APP_API|NEXT_PUBLIC_API)["\s:=]+["\']?(https?://[^\s"\'`,]+)', re.I),
    re.compile(r'(?:apiUrl|api_url|endpoint|base_url)["\s:=]+["\']?(https?://[^\s"\'`,]+)', re.I),
    re.compile(r'["\']/(api|v\d+|rest|graphql)/[a-zA-Z0-9_/\-]+["\']'),
    re.compile(r'axios\.create\(\{[^}]*baseURL[:\s]+["\']([^"\']+)["\']', re.I),
    re.compile(r'fetch\(["\']([^"\']+)["\']', re.I),
    # ── NEW API PATTERNS ──────────────────────────────────────────────────────
    re.compile(r'["\']https?://[^"\']*api[^"\']*["\']', re.I),
    re.compile(r'["\']https?://[^"\']*/v\d+/[^"\']*["\']', re.I),
    re.compile(r'["\']https?://[^"\']*/graphql["\']', re.I),
    re.compile(r'["\']https?://[^"\']*/rest/[^"\']*["\']', re.I),
    re.compile(r'["\']https?://[^"\']*/webhook[^"\']*["\']', re.I),
    re.compile(r'["\']https?://[^"\']*/callback[^"\']*["\']', re.I),
    re.compile(r'["\']https?://[^"\']*/oauth[^"\']*["\']', re.I),
    re.compile(r'["\']https?://[^"\']*/auth[^"\']*["\']', re.I),
    re.compile(r'["\']https?://[^"\']*/token[^"\']*["\']', re.I),
    re.compile(r'["\']https?://[^"\']*/login[^"\']*["\']', re.I),
]

ENV_LEAK_PATTERNS = {
    "NEXT_PUBLIC vars": re.compile(r'NEXT_PUBLIC_[A-Z_]+["\s:=]+["\']?([^\s"\'`,]{5,})', re.I),
    "REACT_APP vars": re.compile(r'REACT_APP_[A-Z_]+["\s:=]+["\']?([^\s"\'`,]{5,})', re.I),
    "VUE_APP vars": re.compile(r'VUE_APP_[A-Z_]+["\s:=]+["\']?([^\s"\'`,]{5,})', re.I),
    "process.env leak": re.compile(r'process\.env\.([A-Z_]{5,})["\s:=]+["\']?([^\s"\'`,]{5,})'),
    "NODE_ENV": re.compile(r'NODE_ENV["\s:=]+["\']?(development|staging|test)["\']', re.I),
    # ── NEW ENV PATTERNS ──────────────────────────────────────────────────────
    "AWS keys": re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}', re.I),
    "API keys": re.compile(r'(?:api[_-]?key|apikey)["\s:=]+["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
    "Secret keys": re.compile(r'(?:secret|secret[_-]?key)["\s:=]+["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
    "Access tokens": re.compile(r'(?:access[_-]?token|auth[_-]?token)["\s:=]+["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
    "Private keys": re.compile(r'(?:private[_-]?key|priv[_-]?key)["\s:=]+["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
    "Database URLs": re.compile(r'(?:database[_-]?url|db[_-]?url|mysql://|postgres://|mongodb://)', re.I),
    "JWT secrets": re.compile(r'(?:jwt[_-]?secret|token[_-]?secret)["\s:=]+["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
    "OAuth secrets": re.compile(r'(?:client[_-]?secret|oauth[_-]?secret)["\s:=]+["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
    "Stripe keys": re.compile(r'(?:sk_live_|pk_live_|sk_test_|pk_test_)[A-Za-z0-9]+', re.I),
    "GitHub tokens": re.compile(r'(?:ghp_|gho_|github_pat_)[A-Za-z0-9]+', re.I),
    "Slack tokens": re.compile(r'(?:xox[baprs]-)[A-Za-z0-9\-]+', re.I),
    "Heroku API keys": re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
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

# ── NEW: Secrets Detection Patterns ──────────────────────────────────────────
SECRETS_PATTERNS = {
    "AWS Access Key": re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
    "AWS Secret Key": re.compile(r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key["\s:=]+["\']?([A-Za-z0-9/+=]{40})'),
    "GitHub Token": re.compile(r'(?:ghp_|gho_|github_pat_)[A-Za-z0-9]+'),
    "GitLab Token": re.compile(r'glpat-[A-Za-z0-9\-_]{20,}'),
    "Slack Token": re.compile(r'xox[baprs]-[A-Za-z0-9\-]+'),
    "Slack Webhook": re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+'),
    "Stripe Key": re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]+'),
    "Twilio Account SID": re.compile(r'AC[a-f0-9]{32}'),
    "Twilio Auth Token": re.compile(r'[a-f0-9]{32}'),
    "SendGrid API Key": re.compile(r'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}'),
    "Mailgun API Key": re.compile(r'key-[A-Za-z0-9]{32}'),
    "Heroku API Key": re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    "Google API Key": re.compile(r'AIza[A-Za-z0-9_\-]{35}'),
    "Google OAuth ID": re.compile(r'[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com'),
    "Firebase Key": re.compile(r'AIza[A-Za-z0-9_\-]{35}'),
    "Heroku API Key": re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    "JWT Token": re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
    "Bearer Token": re.compile(r'[Bb]earer\s+[A-Za-z0-9\-_\.]+'),
    "Basic Auth": re.compile(r'[Bb]asic\s+[A-Za-z0-9+/=]+'),
    "Password in URL": re.compile(r'(?i)password["\s:=]+["\']([^\s"\']+)["\']'),
    "Connection String": re.compile(r'(?i)(?:mysql|postgres|mongodb|redis)://[^\s"\']+'),
}


@tool
def analyze_js_deep(url: str) -> str:
    """
    Analyze JavaScript in depth for extracting endpoints, env leak, and sensitive info with proxy rotation.
    """
    logger = _logger()
    tool_name = "Deep JS Analyzer"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    SESSION = requests.Session()
    SESSION.verify = True

    domain = _domain_of(url)
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Inject auth session jika ada
    inject_into_session(SESSION, domain)

    if logger:
        logger.add_log(tool_name, "START", f"Deep JS analysis for {url}")

    # ── 1. Collect JS files from page with Proxy ────────────────────────
    rate_limiter.wait(domain)
    current_proxy = proxy_router.get_proxy()
    try:
        page_resp = SESSION.get(url, headers=HEADERS, proxies=current_proxy, timeout=15)
        page_html = page_resp.text
    except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
        if current_proxy:
            proxy_router.remove_dead_proxy(current_proxy)
        return json.dumps({"error": "Failed load halaman karena kendala proxy saat scanning awal."})
    except Exception as e:
        return json.dumps({"error": f"Failed load halaman: {str(e)}"})

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

    # ── 2. Analyze each JS file with Proxy ─────────────────────────────────
    for js_url in filtered_scripts[:15]:
        if check_cancelled(logger):
            break

        rate_limiter.wait(_domain_of(js_url))
        current_proxy = proxy_router.get_proxy()
        try:
            js_resp = SESSION.get(js_url, headers=HEADERS, proxies=current_proxy, timeout=15)
            if "javascript" not in js_resp.headers.get("content-type", "") and js_resp.status_code != 200:
                continue

            js_content = js_resp.text

            # Source map check with new private Proxy
            sm_match = SOURCE_MAP_PATTERN.search(js_content[-500:])
            if sm_match:
                sm_url = sm_match.group(1)
                if not sm_url.startswith("http"):
                    sm_url = urljoin(js_url, sm_url)
                
                rate_limiter.wait(_domain_of(sm_url))
                sm_proxy = proxy_router.get_proxy()
                try:
                    sm_resp = SESSION.get(sm_url, headers=HEADERS, proxies=sm_proxy, timeout=5)
                    if sm_resp.status_code == 200 and "sources" in sm_resp.text:
                        findings["source_maps"].append({
                            "js_file": js_url,
                            "source_map": sm_url,
                            "severity": "HIGH",
                            "impact": "Source map exposed — original source code can be recovered",
                        })
                except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
                    if sm_proxy:
                        proxy_router.remove_dead_proxy(sm_proxy)
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
                        "note": "Actual value di-redact. Manual review untuk konfirmasi.",
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

        except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
            if current_proxy:
                proxy_router.remove_dead_proxy(current_proxy)
            continue
        except Exception as e:
            if logger:
                logger.add_log(tool_name, "WARNING", f"Error analyze {js_url}: {str(e)[:100]}")
            continue

    findings["api_endpoints"] = list(dict.fromkeys(findings["api_endpoints"]))[:50]
    findings["spa_routes"] = list(dict.fromkeys(findings["spa_routes"]))[:30]
    findings["webpack_chunks"] = list(dict.fromkeys(findings["webpack_chunks"]))[:20]

    # ── 3. Check GraphQL introspection dengan Proxy ──────────────────────────
    if findings["graphql_hints"]:
        graphql_endpoints = [e for e in findings["api_endpoints"] if "graphql" in e.lower()]
        if not graphql_endpoints:
            graphql_endpoints = [f"{base}/graphql", f"{base}/api/graphql"]

        for gql_url in graphql_endpoints[:2]:
            if check_cancelled(logger):
                break
            rate_limiter.wait(_domain_of(gql_url))
            gql_proxy = proxy_router.get_proxy()
            try:
                introspection_query = '{"query": "{ __schema { queryType { name } } }"}'
                resp = SESSION.post(
                    gql_url,
                    data=introspection_query,
                    headers={**HEADERS, "Content-Type": "application/json"},
                    proxies=gql_proxy,
                    timeout=10
                )
                if resp.status_code == 200 and "__schema" in resp.text:
                    findings["graphql_hints"].append({
                        "endpoint": gql_url,
                        "introspection_enabled": True,
                        "severity": "MEDIUM",
                        "impact": "GraphQL introspection enabled — full schema bisa di-dump",
                    })
            except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
                if gql_proxy:
                    proxy_router.remove_dead_proxy(gql_proxy)
                continue
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

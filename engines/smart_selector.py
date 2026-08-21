"""
SMART TOOL SELECTOR — Tech Stack Based Tool Selection
======================================================
Pilih tools that paling relevan based on tech stack target.

Usage:
    from engines.smart_selector import smart_selector

    tools = smart_selector.select_tools(
        tech_stack={"language": "php", "framework": "laravel", "database": "mysql"},
        phase="analis"
    )
"""

from typing import Dict, List, Any, Optional
from urllib.parse import urlparse


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


# ============================================================
# TECH STACK → TOOL MAPPING
# ============================================================

# Tools that relevan per tech stack
TECH_TOOL_MAP = {
    "php": {
        "high_priority": [
            "scan_sql_injection", "blind_sqli_scanner",
            "lfi_rfi_scanner", "ssti_tester",
            "file_upload_scanner", "insecure_deserialization_scanner",
        ],
        "medium_priority": [
            "detect_xss_csrf", "stored_xss_scanner",
            "command_injection_scanner", "xxe_tester",
        ],
        "skip": [],
    },
    "laravel": {
        "high_priority": [
            "scan_sql_injection", "blind_sqli_scanner",
            "ssti_tester", "insecure_deserialization_scanner",
            "mass_assignment_scanner",
        ],
        "medium_priority": [
            "detect_xss_csrf", "stored_xss_scanner",
            "command_injection_scanner", "csrf_exploit_scanner",
        ],
        "skip": [],
    },
    "wordpress": {
        "high_priority": [
            "scan_sql_injection", "lfi_rfi_scanner",
            "xss_scanner", "file_upload_scanner",
        ],
        "medium_priority": [
            "misconfiguration_scanner", "run_nuclei_scan",
        ],
        "skip": [],
    },
    "django": {
        "high_priority": [
            "blind_sqli_scanner", "ssti_tester",
            "csrf_exploit_scanner", "mass_assignment_scanner",
        ],
        "medium_priority": [
            "stored_xss_scanner", "command_injection_scanner",
            "path_traversal_scanner",
        ],
        "skip": [],
    },
    "flask": {
        "high_priority": [
            "ssti_tester", "blind_sqli_scanner",
            "csrf_exploit_scanner",
        ],
        "medium_priority": [
            "stored_xss_scanner", "command_injection_scanner",
        ],
        "skip": [],
    },
    "spring": {
        "high_priority": [
            "blind_sqli_scanner", "ssti_tester",
            "mass_assignment_scanner", "xxe_tester",
        ],
        "medium_priority": [
            "command_injection_scanner", "path_traversal_scanner",
        ],
        "skip": [],
    },
    "nodejs": {
        "high_priority": [
            "nosql_injection_scanner", "prototype_pollution_scanner",
            "ssti_tester",
        ],
        "medium_priority": [
            "stored_xss_scanner", "command_injection_scanner",
        ],
        "skip": [],
    },
    "ruby": {
        "high_priority": [
            "ssti_tester", "blind_sqli_scanner",
        ],
        "medium_priority": [
            "csrf_exploit_scanner", "command_injection_scanner",
        ],
        "skip": [],
    },
    "react": {
        "high_priority": [
            "dom_xss_scanner", "prototype_pollution_scanner",
        ],
        "medium_priority": [
            "jsonp_injection_scanner", "cors_tester",
        ],
        "skip": ["ssti_tester"],
    },
    "angular": {
        "high_priority": [
            "dom_xss_scanner", "prototype_pollution_scanner",
        ],
        "medium_priority": [
            "cors_tester",
        ],
        "skip": ["ssti_tester"],
    },
    "vue": {
        "high_priority": [
            "dom_xss_scanner", "prototype_pollution_scanner",
        ],
        "medium_priority": [
            "jsonp_injection_scanner",
        ],
        "skip": ["ssti_tester"],
    },
}

# Database → specific tools
DB_TOOL_MAP = {
    "mysql": ["blind_sqli_scanner", "nosql_injection_scanner"],
    "postgresql": ["blind_sqli_scanner"],
    "mssql": ["blind_sqli_scanner"],
    "mongodb": ["nosql_injection_scanner"],
    "redis": ["command_injection_scanner"],
    "oracle": ["blind_sqli_scanner"],
    "sqlite": ["blind_sqli_scanner"],
}

# Always run regardless of tech stack
ALWAYS_RUN = [
    "recon_target", "enumerate_dns_subdomains", "analyze_ssl_tls",
    "browser_screenshot", "browser_extract_surface",
    "param_discovery_get", "misconfiguration_scanner",
    "cors_tester", "graphql_tester",
    "scan_ssrf", "scan_idor",
    "test_jwt_weakness", "oauth_flow_tester",
    "session_management_scanner", "access_control_scanner",
]


class SmartToolSelector:
    """
    Select tools based on tech stack target.
    """

    def __init__(self):
        pass

    def detect_tech_stack(self, url: str) -> Dict[str, str]:
        """
        Detect tech stack from target URL.
        Return: {"language": "...", "framework": "...", "database": "..."}
        """
        from core.tool_transport import guarded_requests as requests
        try:
            from core.rate_limiter import rate_limiter
            rate_limiter.wait(_domain_of(url))
            r = requests.get(url, timeout=10, verify=False, allow_redirects=True)

            headers_str = str(dict(r.headers)).lower()
            body = r.text.lower()

            detected = {"language": "unknown", "framework": "unknown", "database": "unknown"}

            # Language detection
            lang_signatures = {
                "php": ["php", "PHPSESSID", "laravel", "wordpress", "drupal"],
                "python": ["django", "flask", "fastapi", "python", "csrfmiddlewaretoken"],
                "java": ["spring", "tomcat", "jboss", "java", "JSESSIONID"],
                "nodejs": ["express", "next", "react", "vue", "angular", "node"],
                "ruby": ["rails", "ruby", "sinatra", "puma"],
                "dotnet": ["aspx", "asp.net", "dotnet", ".net"],
            }

            for lang, sigs in lang_signatures.items():
                for sig in sigs:
                    if sig.lower() in headers_str or sig.lower() in body:
                        detected["language"] = lang
                        break
                if detected["language"] != "unknown":
                    break

            # Framework detection
            fw_signatures = {
                "laravel": ["laravel", "csrf_token"],
                "django": ["csrfmiddlewaretoken", "django"],
                "flask": ["flask"],
                "spring": ["spring", "springframework"],
                "wordpress": ["wp-content", "wordpress"],
                "react": ["react", "div id=\"root\""],
                "angular": ["ng-version", "angular"],
                "vue": ["vue", "v-cloak"],
                "next": ["next", "__next"],
                "express": ["x-powered-by: express"],
            }

            for fw, sigs in fw_signatures.items():
                for sig in sigs:
                    if sig.lower() in headers_str or sig.lower() in body:
                        detected["framework"] = fw
                        break
                if detected["framework"] != "unknown":
                    break

            # Database detection (from error messages or headers)
            db_signatures = {
                "mysql": ["mysql", "mysqli", "maria"],
                "postgresql": ["postgresql", "pgsql"],
                "mongodb": ["mongodb", "mongo", "bson"],
                "mssql": ["mssql", "microsoft sql"],
                "oracle": ["oracle", "ora-"],
                "redis": ["redis"],
            }

            for db, sigs in db_signatures.items():
                for sig in sigs:
                    if sig.lower() in body or sig.lower() in headers_str:
                        detected["database"] = db
                        break
                if detected["database"] != "unknown":
                    break

            return detected

        except Exception:
            return {"language": "unknown", "framework": "unknown", "database": "unknown"}

    def select_tools(
        self,
        tech_stack: Dict[str, str],
        phase: str = "analis",
        all_tools: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Select tools based on tech stack dan phase.
        
        Args:
            tech_stack: {"language": "...", "framework": "...", "database": "..."}
            phase: "recon" | "analis" | "eksekutor" | "assessor"
            all_tools: List all available tools (optional)
        
        Returns:
            List of tool names that paling relevan
        """
        language = tech_stack.get("language", "unknown")
        framework = tech_stack.get("framework", "unknown")
        database = tech_stack.get("database", "unknown")

        selected = set(ALWAYS_RUN)

        # Add tools from language
        if language in TECH_TOOL_MAP:
            selected.update(TECH_TOOL_MAP[language].get("high_priority", []))
            selected.update(TECH_TOOL_MAP[language].get("medium_priority", []))

        # Add tools from framework
        if framework in TECH_TOOL_MAP:
            selected.update(TECH_TOOL_MAP[framework].get("high_priority", []))

        # Add tools from database
        if database in DB_TOOL_MAP:
            selected.update(DB_TOOL_MAP[database])

        # Phase-specific tools
        phase_tools = {
            "recon": [
                "recon_target", "enumerate_dns_subdomains", "analyze_ssl_tls",
                "browser_screenshot", "browser_extract_surface",
                "browser_extract_js_secrets", "analyze_js_deep",
                "param_discovery_get", "param_discovery_headers",
                "recon_advanced", "misconfiguration_scanner",
                "client_side_security_scanner", "mixed_content_scanner",
                "shodan_scanner", "censys_scanner",
                "wayback_scraper", "github_dorking",
            ],
            "analis": [
                "scan_sql_injection", "blind_sqli_scanner",
                "detect_xss_csrf", "stored_xss_scanner", "dom_xss_scanner",
                "nosql_injection_scanner", "ssti_tester", "xxe_tester",
                "command_injection_scanner", "graphql_tester", "cors_tester",
                "param_discovery_post", "run_nuclei_scan",
                "access_control_scanner", "csrf_exploit_scanner",
                "mass_assignment_scanner", "http_method_tampering_scanner",
                "web_cache_poisoning_scanner", "cache_deception_scanner",
                "prototype_pollution_scanner",
            ],
            "eksekutor": [
                "scan_ssrf", "scan_idor", "xxe_tester",
                "test_jwt_weakness", "test_auth_rate_limiting",
                "oauth_flow_tester", "session_management_scanner",
                "password_reset_tester", "twofa_bypass_scanner",
                "host_header_injection_scanner", "race_condition_scanner",
                "file_upload_scanner", "http_request_smuggling_scanner",
                "websocket_security_scanner", "insecure_deserialization_scanner",
                "ssrf_advanced_scanner", "tembak_payload",
            ],
            "assessor": [],  # Assessor gak butuh tools
        }

        if phase in phase_tools:
            # Intersect with phase tools
            selected = selected.intersection(set(phase_tools[phase]))
        else:
            # Gak filter by phase
            pass

        return list(selected)

    def get_skip_tools(self, tech_stack: Dict[str, str]) -> List[str]:
        """Return tools that can di-skip based on tech stack."""
        language = tech_stack.get("language", "unknown")
        framework = tech_stack.get("framework", "unknown")

        skip = set()

        if language in TECH_TOOL_MAP:
            skip.update(TECH_TOOL_MAP[language].get("skip", []))
        if framework in TECH_TOOL_MAP:
            skip.update(TECH_TOOL_MAP[framework].get("skip", []))

        return list(skip)


# Global instance
smart_selector = SmartToolSelector()

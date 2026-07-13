"""
API DISCOVERY — Auto-discover Swagger/OpenAPI Endpoints
=======================================================
Auto-detect API documentation endpoints dan extract attack surface.

Usage:
    from engines.api_discovery import api_discovery

    result = api_discovery.discover("https://target.com")
    # result = {"endpoints": [...], "schemas": {...}, "auth_required": [...]}
"""

import json
import re
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin


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


# ============================================================
# COMMON API DOCUMENTATION PATHS
# ============================================================

SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi/v1",
    "/api/swagger.json",
    "/api/docs",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
]

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphiql",
    "/playground",
]


class APIDiscovery:
    """
    Auto-discover API endpoints dari Swagger/OpenAPI documentation.
    """

    def __init__(self):
        self._cache: Dict[str, Dict] = {}

    def discover(self, url: str, exec_logger=None) -> Dict[str, Any]:
        """
        Discover API endpoints dari target.
        
        Return:
            {
                "swagger_found": bool,
                "swagger_url": str,
                "endpoints": [...],
                "schemas": {...},
                "auth_required": [...],
                "attack_surface": [...]
            }
        """
        domain = _domain_of(url)

        # Check cache
        if domain in self._cache:
            return self._cache[domain]

        if exec_logger:
            exec_logger.add_log("API Discovery", "START", f"Discovering APIs for {domain}")

        result = {
            "swagger_found": False,
            "swagger_url": "",
            "swagger_format": "",
            "endpoints": [],
            "schemas": {},
            "auth_required": [],
            "attack_surface": [],
            "graphql_endpoints": [],
        }

        # ── 1. Search for Swagger/OpenAPI documentation ────────────────────────
        from core.rate_limiter import rate_limiter
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in SWAGGER_PATHS:
            try:
                rate_limiter.wait(domain)
                test_url = f"{base}{path}"
                resp = requests.get(test_url, timeout=5, verify=False, allow_redirects=True)

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        # Check if it's valid Swagger/OpenAPI
                        if "swagger" in data or "openapi" in data:
                            result["swagger_found"] = True
                            result["swagger_url"] = test_url
                            result["swagger_format"] = data.get("swagger", data.get("openapi", "unknown"))

                            if exec_logger:
                                exec_logger.add_log("API Discovery", "SUCCESS",
                                    f"Swagger found: {test_url} (format: {result['swagger_format']})")

                            # Parse endpoints
                            self._parse_swagger(data, result)
                            break
                    except json.JSONDecodeError:
                        pass

            except Exception:
                pass

        # ── 2. Search for GraphQL endpoints ────────────────────────────────────
        if exec_logger:
            exec_logger.add_log("API Discovery", "PROCESSING", "Checking GraphQL endpoints")

        for path in GRAPHQL_PATHS:
            try:
                rate_limiter.wait(domain)
                test_url = f"{base}{path}"
                resp = requests.post(
                    test_url,
                    json={"query": "{ __typename }"},
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                    verify=False,
                )

                if resp.status_code in [200, 400]:
                    try:
                        data = resp.json()
                        if "data" in data or "errors" in data:
                            result["graphql_endpoints"].append(test_url)
                            if exec_logger:
                                exec_logger.add_log("API Discovery", "SUCCESS",
                                    f"GraphQL endpoint: {test_url}")
                    except Exception:
                        pass
            except Exception:
                pass

        # ── 3. Analyze attack surface ──────────────────────────────────────────
        self._analyze_attack_surface(result)

        # Cache result
        self._cache[domain] = result

        if exec_logger:
            exec_logger.add_log("API Discovery", "SUCCESS",
                f"Found {len(result['endpoints'])} endpoints, {len(result['graphql_endpoints'])} GraphQL")

        return result

    def _parse_swagger(self, data: Dict, result: Dict):
        """Parse Swagger/OpenAPI spec untuk extract endpoints."""
        # Try paths
        paths = data.get("paths", {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    endpoint = {
                        "path": path,
                        "method": method.upper(),
                        "summary": details.get("summary", ""),
                        "tags": details.get("tags", []),
                        "parameters": [],
                        "auth_required": False,
                    }

                    # Extract parameters
                    for param in details.get("parameters", []):
                        endpoint["parameters"].append({
                            "name": param.get("name", ""),
                            "in": param.get("in", ""),
                            "required": param.get("required", False),
                            "type": param.get("type", ""),
                        })

                    # Check if auth is required
                    security = details.get("security", data.get("security", []))
                    if security:
                        endpoint["auth_required"] = True
                        result["auth_required"].append(f"{method.upper()} {path}")

                    result["endpoints"].append(endpoint)

        # Extract schemas
        definitions = data.get("definitions", data.get("components", {}).get("schemas", {}))
        for schema_name, schema_def in definitions.items():
            result["schemas"][schema_name] = {
                "properties": list(schema_def.get("properties", {}).keys()),
                "required": schema_def.get("required", []),
            }

    def _analyze_attack_surface(self, result: Dict):
        """Analyze endpoints buat identify attack surface."""
        attack_surface = []

        for endpoint in result["endpoints"]:
            path = endpoint["path"]
            method = endpoint["method"]

            # High-risk endpoints
            if any(kw in path.lower() for kw in ["/admin", "/internal", "/debug", "/test"]):
                attack_surface.append({
                    "endpoint": f"{method} {path}",
                    "risk": "high",
                    "reason": "Sensitive path detected",
                })

            # Auth-required endpoints (potential IDOR)
            if endpoint.get("auth_required") and method in ["GET", "POST"]:
                attack_surface.append({
                    "endpoint": f"{method} {path}",
                    "risk": "medium",
                    "reason": "Auth-required endpoint — test for IDOR",
                })

            # File operations
            if any(kw in path.lower() for kw in ["/upload", "/file", "/import", "/export"]):
                attack_surface.append({
                    "endpoint": f"{method} {path}",
                    "risk": "high",
                    "reason": "File operation endpoint — test for file upload/inclusion",
                })

            # User data
            if any(kw in path.lower() for kw in ["/user", "/account", "/profile", "/order"]):
                attack_surface.append({
                    "endpoint": f"{method} {path}",
                    "risk": "medium",
                    "reason": "User data endpoint — test for IDOR/access control",
                })

        result["attack_surface"] = attack_surface


# Global instance
api_discovery = APIDiscovery()

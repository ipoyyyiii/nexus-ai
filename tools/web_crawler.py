"""
WEB CRAWLER
===========
Endpoint discovery using katana web crawler.

Usage:
    from tools.web_crawler import web_crawler
"""

from core.tool_transport import guarded_subprocess as subprocess
import tempfile
import os
import json
from core.tool_decorator import langchain_tool as tool
from core.rate_limiter import rate_limiter
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from core.auth_store import get_auth_kwargs

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


def _domain_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


def _logger():
    from tools.custom_tools import exec_logger
    return exec_logger


@tool("web_crawler")
def web_crawler(url: str, depth: int = 2, scope: str = "subdomain") -> str:
    """
    Discover endpoints using katana web crawler.
    
    Args:
        url: Target URL to crawl
        depth: Crawl depth (1-5, default 2)
        scope: Crawl scope (subdomain, domain, host)
    """
    tool_name = "Web Crawler"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting web crawl on {url}")
    if check_cancelled(logger): return "CANCELLED: job cancelled by user."

    approved = require_approval(
        action=f"Web crawl on {url}",
        context=f"Discovering endpoints with depth={depth}, scope={scope}",
        risk="low",
        exec_logger=logger,
    )
    if not approved:
        return "CANCELLED: approval rejected or timeout."

    domain = _domain_of(url)

    try:
        # Create temp output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = f.name

        # Run katana
        cmd = [
            "katana",
            "-u", url,
            "-d", str(depth),
            "-o", output_file,
            "-silent",
            "-jc",  # JavaScript crawling
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",  # Exclude static files
            "-timeout", "10",
        ]

        # Apply scope
        if scope == "subdomain":
            cmd.extend(["-fs", "subdomain"])
        elif scope == "domain":
            cmd.extend(["-fs", "domain"])
        elif scope == "host":
            cmd.extend(["-fs", "host"])

        # Apply stealth mode
        if os.environ.get("STEALTH_MODE", "0") == "1":
            cmd.extend(["-delay", "1", "-concurrency", "5"])

        logger.add_log(tool_name, "PROCESSING", f"Crawling {url} with depth={depth}")

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        # Parse katana output
        endpoints = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    endpoint = line.strip()
                    if endpoint and endpoint.startswith("http"):
                        endpoints.append(endpoint)
            os.unlink(output_file)

        # Categorize endpoints
        categories = {
            "api": [],
            "auth": [],
            "admin": [],
            "static": [],
            "dynamic": [],
            "other": [],
        }

        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()
            if any(kw in endpoint_lower for kw in ["/api/", "/v1/", "/v2/", "/graphql"]):
                categories["api"].append(endpoint)
            elif any(kw in endpoint_lower for kw in ["/login", "/auth", "/signin", "/register"]):
                categories["auth"].append(endpoint)
            elif any(kw in endpoint_lower for kw in ["/admin", "/panel", "/dashboard"]):
                categories["admin"].append(endpoint)
            elif any(ext in endpoint_lower for ext in [".js", ".css", ".png", ".jpg", ".gif", ".svg"]):
                categories["static"].append(endpoint)
            elif "?" in endpoint or "=" in endpoint:
                categories["dynamic"].append(endpoint)
            else:
                categories["other"].append(endpoint)

        # Build report
        output = f"=== WEB CRAWL RESULTS FOR {url} ===\n"
        output += f"Tool: katana | Depth: {depth} | Scope: {scope}\n"
        output += f"Total endpoints: {len(endpoints)}\n\n"

        for cat_name, cat_endpoints in categories.items():
            if cat_endpoints:
                emoji = {"api": "🔌", "auth": "🔐", "admin": "🔴", "static": "📁", "dynamic": "⚡", "other": "📄"}.get(cat_name, "📄")
                output += f"{emoji} {cat_name.upper()} ({len(cat_endpoints)})\n"
                for ep in cat_endpoints[:15]:  # Limit per category
                    output += f"  - {ep}\n"
                output += "\n"

        if not endpoints:
            output += "[✅] No endpoints discovered.\n"

        logger.add_log(tool_name, "SUCCESS", f"Web crawl complete. Found: {len(endpoints)} endpoints")

        return output

    except subprocess.TimeoutExpired:
        if os.path.exists(output_file):
            os.unlink(output_file)
        return f"ERROR: Web crawl timed out after 5 minutes for {domain}"
    except FileNotFoundError:
        return "ERROR: katana not found. Install: https://github.com/projectdiscovery/katana"
    except Exception as e:
        if os.path.exists(output_file):
            os.unlink(output_file)
        return f"ERROR: Web crawl failed: {str(e)}"

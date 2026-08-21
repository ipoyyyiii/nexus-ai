"""
WORDPRESS SCANNER
=================
WordPress security scanning using wpscan.

Usage:
    from tools.wp_scanner import wp_scanner
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


@tool("wp_scanner")
def wp_scanner(url: str, enumerate_options: str = "vp,vt,u") -> str:
    """
    WordPress security scanning using wpscan.
    Detects plugins, themes, users, and vulnerabilities.
    
    Args:
        url: Target WordPress URL (e.g., https://example.com)
        enumerate_options: WPScan enumerate options (vp=plugins, vt=themes, u=users)
    """
    tool_name = "WordPress Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting WordPress scan on {url}")
    if check_cancelled(logger): return "CANCELLED: job cancelled by user."

    approved = require_approval(
        action=f"WordPress scan on {url}",
        context=f"Running wpscan for plugin/theme/user enumeration and vulnerability detection",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "CANCELLED: approval rejected or timeout."

    domain = _domain_of(url)

    try:
        # Create temp output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name

        # Run wpscan
        cmd = [
            "wpscan",
            "--url", url,
            "--enumerate", enumerate_options,
            "--format", "json",
            "--output", output_file,
            "--no-banner",
            "--random-user-agent",
            "--disable-tls-checks",
        ]

        # Apply stealth mode
        if os.environ.get("STEALTH_MODE", "0") == "1":
            cmd.extend(["--throttle", "1000"])

        logger.add_log(tool_name, "PROCESSING", f"Running wpscan on {domain}")

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,  # 10 minute timeout
        )

        # Parse wpscan JSON output
        findings = {
            "wordpress_version": None,
            "plugins": [],
            "themes": [],
            "users": [],
            "vulnerabilities": [],
            "interesting_findings": [],
        }

        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)

                # Extract WordPress version
                findings["wordpress_version"] = data.get("target", {}).get("wordpress_version")

                # Extract plugins
                for plugin_name, plugin_data in data.get("plugins", {}).items():
                    if plugin_data.get("status") == "active":
                        findings["plugins"].append({
                            "name": plugin_name,
                            "version": plugin_data.get("version", {}).get("number", "unknown"),
                            "vulnerabilities": len(plugin_data.get("vulnerabilities", [])),
                        })

                # Extract themes
                for theme_name, theme_data in data.get("themes", {}).items():
                    if theme_data.get("status") == "active":
                        findings["themes"].append({
                            "name": theme_name,
                            "version": theme_data.get("version", {}).get("number", "unknown"),
                            "vulnerabilities": len(theme_data.get("vulnerabilities", [])),
                        })

                # Extract users
                for user_id, user_data in data.get("users", {}).items():
                    findings["users"].append({
                        "id": user_id,
                        "username": user_data.get("username", "unknown"),
                    })

                # Extract vulnerabilities
                for vuln in data.get("vulnerabilities", []):
                    findings["vulnerabilities"].append({
                        "title": vuln.get("title", ""),
                        "severity": vuln.get("severity", "unknown"),
                        "fix": vuln.get("fix", ""),
                    })

                # Extract interesting findings
                for finding in data.get("interesting_findings", []):
                    findings["interesting_findings"].append({
                        "type": finding.get("type", ""),
                        "url": finding.get("url", ""),
                        "to_serve": finding.get("to_serve", ""),
                    })

            except json.JSONDecodeError:
                logger.add_log(tool_name, "WARNING", "Failed to parse wpscan JSON output")
            finally:
                try:
                    os.unlink(output_file)
                except:
                    pass

        # Build report
        output = f"=== WORDPRESS SCAN RESULTS FOR {domain} ===\n"
        output += f"Tool: wpscan\n\n"

        # WordPress version
        if findings["wordpress_version"]:
            output += f"📋 WordPress Version: {findings['wordpress_version']}\n\n"

        # Plugins
        if findings["plugins"]:
            output += f"🔌 Plugins ({len(findings['plugins'])})\n"
            for plugin in findings["plugins"]:
                vuln_marker = "🔴" if plugin["vulnerabilities"] > 0 else "🟢"
                output += f"  {vuln_marker} {plugin['name']} v{plugin['version']}"
                if plugin["vulnerabilities"] > 0:
                    output += f" ({plugin['vulnerabilities']} vulns)"
                output += "\n"
            output += "\n"

        # Themes
        if findings["themes"]:
            output += f"🎨 Themes ({len(findings['themes'])})\n"
            for theme in findings["themes"]:
                vuln_marker = "🔴" if theme["vulnerabilities"] > 0 else "🟢"
                output += f"  {vuln_marker} {theme['name']} v{theme['version']}"
                if theme["vulnerabilities"] > 0:
                    output += f" ({theme['vulnerabilities']} vulns)"
                output += "\n"
            output += "\n"

        # Users
        if findings["users"]:
            output += f"👤 Users ({len(findings['users'])})\n"
            for user in findings["users"]:
                output += f"  - {user['username']} (ID: {user['id']})\n"
            output += "\n"

        # Vulnerabilities
        if findings["vulnerabilities"]:
            output += f"🔴 VULNERABILITIES ({len(findings['vulnerabilities'])})\n"
            for vuln in findings["vulnerabilities"]:
                output += f"  ▸ [{vuln['severity']}] {vuln['title']}\n"
                if vuln.get("fix"):
                    output += f"    Fix: {vuln['fix'][:200]}\n"
            output += "\n"

        # Interesting findings
        if findings["interesting_findings"]:
            output += f"🔍 Interesting Findings ({len(findings['interesting_findings'])})\n"
            for finding in findings["interesting_findings"][:10]:
                output += f"  - {finding['type']}: {finding['url']}\n"
            output += "\n"

        # Summary
        total_vulns = len(findings["vulnerabilities"])
        total_plugin_vulns = sum(p["vulnerabilities"] for p in findings["plugins"])
        total_theme_vulns = sum(t["vulnerabilities"] for t in findings["themes"])

        output += f"\nSummary: {len(findings['plugins'])} plugins, {len(findings['themes'])} themes, {len(findings['users'])} users\n"
        output += f"Vulnerabilities: {total_vulns} core + {total_plugin_vulns} plugin + {total_theme_vulns} theme\n"

        if not findings["wordpress_version"] and not findings["plugins"]:
            output += "\n[⚠️] Target may not be WordPress or wpscan couldn't detect it.\n"

        logger.add_log(tool_name, "SUCCESS",
            f"WordPress scan complete. Found: {len(findings['vulnerabilities'])} vulns")

        return output

    except subprocess.TimeoutExpired:
        if os.path.exists(output_file):
            os.unlink(output_file)
        return f"ERROR: WordPress scan timed out after 10 minutes for {domain}"
    except FileNotFoundError:
        return "ERROR: wpscan not found. Install: sudo apt install wpscan -y"
    except Exception as e:
        if os.path.exists(output_file):
            os.unlink(output_file)
        return f"ERROR: WordPress scan failed: {str(e)}"

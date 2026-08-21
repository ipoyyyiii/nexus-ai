"""
DIRECTORY BRUTEFORCE SCANNER
============================
Discover hidden directories and files using gobuster/ffuf.

Usage:
    from tools.dir_bruteforce import dir_bruteforce_scanner
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


# ── Common Wordlists ─────────────────────────────────────────────────────────
WORDLISTS = {
    "common": "/usr/share/wordlists/common.txt",
    "big": "/opt/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    "dirs": "/opt/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "files": "/opt/wordlists/SecLists/Discovery/Web-Content/common.txt",
    "api": "/opt/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt",
    "raft": "/opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
    "raft_files": "/opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-files.txt",
}


def _run_gobuster(url: str, wordlist: str, logger, threads: int = 10) -> list:
    """Run gobuster and return findings."""
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = f.name

        cmd = [
            "gobuster",
            "dir",
            "-u", url,
            "-w", wordlist,
            "-o", output_file,
            "-t", str(threads),
            "-q",  # Quiet mode
            "--no-error",
            "--timeout", "10s",
        ]

        # Apply stealth mode
        if os.environ.get("STEALTH_MODE", "0") == "1":
            cmd.extend(["-t", "3", "--delay", "1s"])

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )

        findings = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and "(Status:" in line:
                        # Parse gobuster output
                        parts = line.split("(Status:")
                        if len(parts) == 2:
                            path = parts[0].strip()
                            status = parts[1].split(")")[0].strip()
                            findings.append({
                                "path": path,
                                "status": int(status) if status.isdigit() else 0,
                                "tool": "gobuster",
                            })
            os.unlink(output_file)

        return findings

    except subprocess.TimeoutExpired:
        if os.path.exists(output_file):
            os.unlink(output_file)
        return []
    except FileNotFoundError:
        logger.add_log("Dir Bruteforce", "WARNING", "gobuster not found")
        return []
    except Exception as e:
        logger.add_log("Dir Bruteforce", "WARNING", f"gobuster error: {str(e)[:100]}")
        return []


def _run_ffuf(url: str, wordlist: str, logger, threads: int = 10) -> list:
    """Run ffuf and return findings."""
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name

        # ffuf needs FUZZ keyword in URL
        fuzz_url = url.rstrip('/') + '/FUZZ'

        cmd = [
            "ffuf",
            "-u", fuzz_url,
            "-w", wordlist,
            "-o", output_file,
            "-of", "json",
            "-t", str(threads),
            "-s",  # Silent mode
            "-mc", "200,201,301,302,307,401,403,405",
            "-timeout", "10",
        ]

        # Apply stealth mode
        if os.environ.get("STEALTH_MODE", "0") == "1":
            cmd.extend(["-t", "3", "-p", "1"])

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )

        findings = []
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    for result in data.get("results", []):
                        findings.append({
                            "path": result.get("input", {}).get("FUZZ", ""),
                            "status": result.get("status", 0),
                            "length": result.get("length", 0),
                            "words": result.get("words", 0),
                            "tool": "ffuf",
                        })
            except json.JSONDecodeError:
                pass
            os.unlink(output_file)

        return findings

    except subprocess.TimeoutExpired:
        if os.path.exists(output_file):
            os.unlink(output_file)
        return []
    except FileNotFoundError:
        logger.add_log("Dir Bruteforce", "WARNING", "ffuf not found")
        return []
    except Exception as e:
        logger.add_log("Dir Bruteforce", "WARNING", f"ffuf error: {str(e)[:100]}")
        return []


@tool("dir_bruteforce_scanner")
def dir_bruteforce_scanner(url: str, wordlist: str = "common") -> str:
    """
    Discover hidden directories and files using gobuster/ffuf.
    
    Args:
        url: Target URL
        wordlist: Wordlist to use (common, big, dirs, files, api, raft, raft_files)
    """
    tool_name = "Dir Bruteforce Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting directory bruteforce on {url}")
    if check_cancelled(logger): return "CANCELLED: job cancelled by user."

    approved = require_approval(
        action=f"Directory bruteforce on {url}",
        context=f"Using wordlist: {wordlist}",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "CANCELLED: approval rejected or timeout."

    domain = _domain_of(url)

    # Resolve wordlist
    wordlist_path = WORDLISTS.get(wordlist, WORDLISTS["common"])
    if not os.path.exists(wordlist_path):
        # Fallback to common.txt
        wordlist_path = WORDLISTS["common"]
        logger.add_log(tool_name, "WARNING", f"Wordlist not found: {wordlist_path}, using common.txt")

    logger.add_log(tool_name, "PROCESSING", f"Using wordlist: {wordlist_path}")

    # Try gobuster first, fallback to ffuf
    findings = []
    tool_used = ""

    # Check which tool is available
    gobuster_available = os.path.exists("/usr/local/bin/gobuster")
    ffuf_available = os.path.exists("/usr/local/bin/ffuf")

    if gobuster_available:
        logger.add_log(tool_name, "PROCESSING", "Running gobuster...")
        findings = _run_gobuster(url, wordlist_path, logger, threads=10)
        tool_used = "gobuster"
    elif ffuf_available:
        logger.add_log(tool_name, "PROCESSING", "Running ffuf...")
        findings = _run_ffuf(url, wordlist_path, logger, threads=10)
        tool_used = "ffuf"
    else:
        return "ERROR: Neither gobuster nor ffuf found. Install one of them."

    # Deduplicate findings
    seen_paths = set()
    unique_findings = []
    for f in findings:
        if f["path"] not in seen_paths:
            seen_paths.add(f["path"])
            unique_findings.append(f)

    # Sort by status code
    unique_findings.sort(key=lambda x: x.get("status", 0))

    # Build report
    output = f"=== DIRECTORY BRUTEFORCE RESULTS FOR {url} ===\n"
    output += f"Tool: {tool_used} | Wordlist: {wordlist_path}\n"
    output += f"Total findings: {len(unique_findings)}\n\n"

    # Group by status code
    by_status = {}
    for f in unique_findings:
        status = f.get("status", 0)
        by_status.setdefault(status, []).append(f)

    for status in sorted(by_status.keys()):
        items = by_status[status]
        if status == 200:
            emoji = "🟢"
        elif status in [301, 302, 307]:
            emoji = "🟡"
        elif status in [401, 403]:
            emoji = "🟠"
        elif status == 405:
            emoji = "🔵"
        else:
            emoji = "⚪"

        output += f"\n{emoji} [Status {status}] — {len(items)} path(s)\n"
        for item in items[:20]:  # Limit per status
            output += f"  - {item['path']}\n"

    if not unique_findings:
        output += "\n[✅] No hidden directories/files found.\n"

    logger.add_log(tool_name, "SUCCESS", f"Dir bruteforce complete. Found: {len(unique_findings)} paths")
    return output

"""Hunter pipeline wrappers — 1:1 with serious bug bounty workflow."""

import subprocess
import json
import shlex
from crewai.tools import tool

def _run(cmd: str, timeout: int = 90) -> str:
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (out.stdout + out.stderr)[:8000]
    except Exception as e:
        return f"error: {e}"

@tool("httpx_probe")
def httpx_probe(target: str) -> str:
    """Live host probe via httpx: check if subdomains/hosts are alive."""
    return _run(f"echo {shlex.quote(target)} | httpx -silent -status-code -title -tech-detect -timeout 8 2>&1 | head -30")

@tool("naabu_scan")
def naabu_scan(target: str) -> str:
    """Port scan via naabu (fast, reliable)."""
    host = target.replace("https://","").replace("http://","").split("/")[0]
    return _run(f"naabu -host {shlex.quote(host)} -top-ports 1000 -silent 2>&1 | head -40", timeout=120)

@tool("gowitness_shot")
def gowitness_shot(target: str) -> str:
    """Screenshot via gowitness (Chrome headless with report)."""
    host = target.replace("https://","").replace("http://","").split("/")[0]
    return _run(f"gowitness single {shlex.quote(target)} --disable-db 2>&1 | head -40")

@tool("gau_urls")
def gau_urls(target: str) -> str:
    """URL gathering via gau (GetAllUrls) — historical endpoints."""
    host = target.replace("https://","").replace("http://","").split("/")[0]
    return _run(f"echo {shlex.quote(host)} | gau --threads 5 2>&1 | head -80")

@tool("hakrawler_crawl")
def hakrawler_crawl(target: str) -> str:
    """JS crawling via hakrawler — discovers endpoints/assets in web app."""
    return _run(f"echo {shlex.quote(target)} | hakrawler -depth 2 -plain 2>&1 | head -80")

@tool("amass_enum")
def amass_enum(target: str) -> str:
    """Subdomain enum via amass (OSINT + active)."""
    domain = target.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
    return _run(f"amass enum -passive -d {shlex.quote(domain)} -timeout 2 2>&1 | head -50", timeout=150)

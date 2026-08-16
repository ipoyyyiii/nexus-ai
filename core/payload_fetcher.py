"""Fetch payloads from PayloadsAllTheThings & PayloadBox."""

import os
import re
from pathlib import Path
from typing import Dict, List

REPOS = {
    "payloadsallthethings": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master",
    "payloadbox": "https://raw.githubusercontent.com/payloadbox",
}

CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "payloads"

# Mapping vuln -> raw paths (sample, cover major cats)
PATHS = {
    "sqli": ["SQL Injection/README.md", "SQL Injection/Intruder/SQLi.txt"],
    "xss": ["XSS Injection/README.md", "XSS Injection/XSS-Payloads.txt"],
    "ssrf": ["Server Side Request Forgery/README.md"],
    "lfi": ["Directory Traversal/README.md", "File Inclusion/README.md"],
    "ssti": ["Server Side Template Injection/README.md"],
    "xxe": ["XXE Injection/README.md"],
}


def fetch_all() -> Dict[str, List[str]]:
    """Fetch & cache payloads per vuln. Returns dict vuln -> payloads."""
    import requests
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    result: Dict[str, List[str]] = {}
    for vuln, paths in PATHS.items():
        payloads: List[str] = []
        for p in paths:
            for repo, base in [("payloadsallthethings", REPOS["payloadsallthethings"])]:
                url = f"{base}/{p}"
                try:
                    r = requests.get(url, timeout=15)
                    if r.status_code == 200:
                        # Extract code blocks / lines that look like payloads
                        payloads.extend(re.findall(r"`([^`]{3,80})`", r.text))
                        payloads.extend([l.strip() for l in r.text.splitlines() if l.strip().startswith(("'", '"', "<", "{", ";"))][:30])
                        break
                except Exception:
                    continue
        # Dedupe & cache
        payloads = list(dict.fromkeys(p for p in payloads if len(p) > 2))[:80]
        if payloads:
            (CACHE_DIR / f"{vuln}.txt").write_text("\n".join(payloads))
        result[vuln] = payloads
    return result


def load_cached(vuln: str) -> List[str]:
    f = CACHE_DIR / f"{vuln}.txt"
    if f.exists():
        return [l.strip() for l in f.read_text().splitlines() if l.strip()]
    return []

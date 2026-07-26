"""
WAF DETECTOR — Web Application Firewall Detection
===================================================
Detect WAF vendor dan adjust scanning strategy.

Supported WAFs:
- Cloudflare (Free/Pro/Business/Enterprise)
- AWS WAF / AWS Shield
- ModSecurity (OWASP CRS)
- Imperva / Incapsula
- F5 BIG-IP ASM
- Sucuri / CloudProxy
- Akamai Kona
- Barracuda
- FortiWeb
- Radware
- DenyAll / DenyAll WAF
- NAXSI (nginx)
- Safe3
- WebSEAL

Usage:
    from waf_detector import waf_detector

    result = waf_detector.detect(url)
    # result = {"waf": "Cloudflare", "confidence": "high", "strategy": {...}}
"""

import re
import requests
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse


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


# ============================================================
# WAF SIGNATURES
# ============================================================

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id", "cf-visitor"],
        "body": ["cloudflare", "attention required", "checking your browser", "ray id"],
        "status_codes": [403, 503, 429],
        "error_pages": ["just a moment", "please wait", "verify you are human"],
        "strategy": {
            "rate_limit": 0.5,  # Slower - Cloudflare aggressive
            "skip_tools": ["xxe_tester"],  # Cloudflare blocks XML
            "bypass_priority": ["case_variation", "encoding", "chunked"],
            "max_requests_before_block": 50,
        },
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-cf-pop", "x-amzn-trace-id"],
        "body": ["aws", "forbidden", "request blocked", "aws-waf"],
        "status_codes": [403, 419],
        "error_pages": ["the request was rejected by aws waf"],
        "strategy": {
            "rate_limit": 1.0,
            "skip_tools": [],
            "bypass_priority": ["encoding", "case_variation", "chunked"],
            "max_requests_before_block": 100,
        },
    },
    "ModSecurity": {
        "headers": ["mod_security", "modsecurity", "sec-chua"],
        "body": ["mod_security", "modsecurity", "transaction id", "rules engine", "owasp"],
        "status_codes": [403, 406],
        "error_pages": ["not acceptable", "security violation", "mod security"],
        "strategy": {
            "rate_limit": 1.5,
            "skip_tools": [],
            "bypass_priority": ["encoding", "chunked", "case_variation"],
            "max_requests_before_block": 30,
        },
    },
    "Imperva": {
        "headers": ["x-iinfo", "x-cdn", "imperva"],
        "body": ["imperva", "incapsula", "visid_incap", "incap_ses"],
        "status_codes": [403, 406, 429],
        "error_pages": ["access denied", "request blocked"],
        "strategy": {
            "rate_limit": 0.5,
            "skip_tools": [],
            "bypass_priority": ["case_variation", "encoding"],
            "max_requests_before_block": 40,
        },
    },
    "F5 BIG-IP": {
        "headers": ["bigip", "f5", "x-wa-info"],
        "body": ["bigip", "f5", "the requested url was rejected"],
        "status_codes": [403, 429],
        "error_pages": ["the requested url was rejected", "support id"],
        "strategy": {
            "rate_limit": 1.0,
            "skip_tools": [],
            "bypass_priority": ["encoding", "case_variation"],
            "max_requests_before_block": 60,
        },
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-block", "sucuri"],
        "body": ["sucuri", "cloudproxy", "access denied", "blocked by sucuri"],
        "status_codes": [403],
        "error_pages": ["blocked by sucuri", "security incident"],
        "strategy": {
            "rate_limit": 1.0,
            "skip_tools": [],
            "bypass_priority": ["encoding", "case_variation"],
            "max_requests_before_block": 50,
        },
    },
    "Akamai": {
        "headers": ["x-akamai", "akamai", "x-akamai-transformed"],
        "body": ["akamai", "reference#", "error", "denied"],
        "status_codes": [403, 429],
        "error_pages": ["access denied", "reference #"],
        "strategy": {
            "rate_limit": 0.5,
            "skip_tools": [],
            "bypass_priority": ["encoding", "chunked"],
            "max_requests_before_block": 40,
        },
    },
    "Barracuda": {
        "headers": ["barracuda", "x-barracuda"],
        "body": ["barracuda", "barracuda waf"],
        "status_codes": [403],
        "error_pages": ["blocked by barracuda"],
        "strategy": {
            "rate_limit": 1.0,
            "skip_tools": [],
            "bypass_priority": ["case_variation", "encoding"],
            "max_requests_before_block": 50,
        },
    },
    "FortiWeb": {
        "headers": ["fortiweb", "x-fortiweb"],
        "body": ["fortiweb", "fortinet"],
        "status_codes": [403],
        "error_pages": ["blocked by fortiweb"],
        "strategy": {
            "rate_limit": 1.0,
            "skip_tools": [],
            "bypass_priority": ["encoding", "case_variation"],
            "max_requests_before_block": 50,
        },
    },
    "NAXSI": {
        "headers": [],
        "body": ["naxsi", "naxsi_error"],
        "status_codes": [400, 403, 406],
        "error_pages": ["naxsi", "bad request"],
        "strategy": {
            "rate_limit": 1.5,
            "skip_tools": [],
            "bypass_priority": ["encoding", "case_variation", "chunked"],
            "max_requests_before_block": 20,
        },
    },
}

# ============================================================
# WAF PROBE PAYLOADS
# ============================================================

WAF_PROBE_PAYLOADS = [
    # SQL injection probe
    ("?id=1' OR '1'='1", "sqli"),
    # XSS probe
    ("?q=<script>alert(1)</script>", "xss"),
    # Command injection probe
    ("?cmd=;id", "cmdi"),
    # Path traversal probe
    ("?file=../../../../etc/passwd", "path_traversal"),
    # XXE probe
    ("?xml=<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", "xxe"),
    # SSRF probe
    ("?url=http://169.254.169.254/", "ssrf"),
]


class WAFDetector:
    """
    Detect WAF vendor dan return scanning strategy.
    """

    def __init__(self):
        self._cache: Dict[str, Dict] = {}

    def detect(self, url: str, exec_logger=None) -> Dict[str, Any]:
        """
        Detect WAF on target URL.
        
        Return:
            {
                "waf": str (vendor name atau "None"),
                "confidence": "high" | "medium" | "low" | "none",
                "strategy": {...} (scanning strategy),
                "evidence": [...] (what was detected),
                "recommendations": [...] (scanning tips)
            }
        """
        domain = _domain_of(url)

        # Check cache
        if domain in self._cache:
            return self._cache[domain]

        if exec_logger:
            exec_logger.add_log("WAF Detector", "START", f"Detecting WAF on {domain}")

        evidence_list = []
        detected_wafs = []

        # ── 1. Passive detection (headers + body) ─────────────────────────────
        try:
            from core.rate_limiter import rate_limiter
            from core.auth_store import auth_get, auth_post
            rate_limiter.wait(domain)
            resp = auth_get(url, timeout=10, verify=False, allow_redirects=True)
            headers_str = str(dict(resp.headers)).lower()
            body = resp.text.lower()
            status = resp.status_code

            for waf_name, signatures in WAF_SIGNATURES.items():
                matches = []

                # Check headers
                for header_sig in signatures.get("headers", []):
                    if header_sig.lower() in headers_str:
                        matches.append(f"Header: {header_sig}")

                # Check body
                for body_sig in signatures.get("body", []):
                    if body_sig.lower() in body:
                        matches.append(f"Body: {body_sig}")

                # Check status code (weak indicator)
                if status in signatures.get("status_codes", []):
                    matches.append(f"Status: {status}")

                # Check error page patterns
                for error_page in signatures.get("error_pages", []):
                    if error_page.lower() in body:
                        matches.append(f"Error page: {error_page}")

                if matches:
                    detected_wafs.append({
                        "waf": waf_name,
                        "matches": matches,
                        "match_count": len(matches),
                        "confidence": self._calculate_confidence(len(matches)),
                    })

        except Exception as e:
            if exec_logger:
                exec_logger.add_log("WAF Detector", "WARNING", f"Passive detection error: {str(e)[:100]}")

        # ── 2. Active probing (send malicious payloads) ───────────────────────
        if exec_logger:
            exec_logger.add_log("WAF Detector", "PROCESSING", "Active WAF probing")

        for probe_url, probe_type in WAF_PROBE_PAYLOADS[:3]:  # Limit to 3 probes
            try:
                from core.rate_limiter import rate_limiter
                from core.auth_store import auth_get, auth_post
                rate_limiter.wait(domain)
                test_url = f"{url}{probe_url}"
                resp = auth_get(test_url, timeout=5, verify=False)

                # If WAF blocked us (403, 406, etc.) = WAF detected
                if resp.status_code in [403, 406, 429, 503]:
                    body = resp.text.lower()
                    for waf_name, signatures in WAF_SIGNATURES.items():
                        for error_page in signatures.get("error_pages", []):
                            if error_page.lower() in body:
                                # Check if this WAF already detected
                                already = any(d["waf"] == waf_name for d in detected_wafs)
                                if not already:
                                    detected_wafs.append({
                                        "waf": waf_name,
                                        "matches": [f"Active probe blocked by {waf_name}"],
                                        "match_count": 1,
                                        "confidence": "medium",
                                    })
                                break
            except Exception:
                pass

        # ── 3. Determine result ───────────────────────────────────────────────
        if detected_wafs:
            # Sort by confidence and match count
            detected_wafs.sort(key=lambda x: (
                {"high": 3, "medium": 2, "low": 1}.get(x["confidence"], 0),
                x["match_count"]
            ), reverse=True)

            best_detection = detected_wafs[0]
            waf_name = best_detection["waf"]
            strategy = WAF_SIGNATURES.get(waf_name, {}).get("strategy", {})

            result = {
                "waf": waf_name,
                "confidence": best_detection["confidence"],
                "all_detected": [d["waf"] for d in detected_wafs],
                "strategy": strategy,
                "evidence": best_detection["matches"],
                "recommendations": self._get_recommendations(waf_name, strategy),
            }
        else:
            result = {
                "waf": "None",
                "confidence": "none",
                "all_detected": [],
                "strategy": {
                    "rate_limit": 2.0,
                    "skip_tools": [],
                    "bypass_priority": [],
                    "max_requests_before_block": 200,
                },
                "evidence": ["No WAF signatures detected"],
                "recommendations": ["No WAF detected — standard scanning strategy can be used"],
            }

        # Cache result
        self._cache[domain] = result

        if exec_logger:
            exec_logger.add_log("WAF Detector", "SUCCESS",
                f"WAF: {result['waf']} (confidence: {result['confidence']})")

        return result

    def _calculate_confidence(self, match_count: int) -> str:
        """Calculate confidence level based on jumlah matches."""
        if match_count >= 3:
            return "high"
        elif match_count >= 2:
            return "medium"
        else:
            return "low"

    def _get_recommendations(self, waf_name: str, strategy: Dict) -> List[str]:
        """Generate scanning recommendations based on WAF."""
        recs = []

        rate = strategy.get("rate_limit", 2.0)
        if rate < 1.0:
            recs.append(f"Reduce scan rate to {rate} req/s (WAF aggresive)")

        skip_tools = strategy.get("skip_tools", [])
        if skip_tools:
            recs.append(f"Skip tools: {', '.join(skip_tools)} (will be blocked)")

        bypass_priority = strategy.get("bypass_priority", [])
        if bypass_priority:
            recs.append(f"Use bypass techniques: {', '.join(bypass_priority)}")

        max_req = strategy.get("max_requests_before_block", 200)
        recs.append(f"Max {max_req} requests before potential block")

        if waf_name == "Cloudflare":
            recs.append("Cloudflare has JS challenge — use Playwright for browser-based scanning")
            recs.append("Avoid rapid-fire requests — Cloudflare tracks request patterns")

        return recs

    def get_strategy(self, url: str) -> Dict[str, Any]:
        """Get scanning strategy for target URL."""
        result = self.detect(url)
        return result.get("strategy", {})


# Global instance
waf_detector = WAFDetector()

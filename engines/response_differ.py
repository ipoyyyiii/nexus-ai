"""
RESPONSE DIFFER — Semantic Response Comparison
===============================================
Bandingin baseline vs test response dengan cerdas.
Bukan cuma length diff — tapi semantic diff.

Usage:
    from engines.response_differ import ResponseDiffer

    differ = ResponseDiffer()
    baseline = differ.capture_baseline(url)
    diff = differ.compare(baseline, test_response)
    # diff = {"status_changed": False, "body_changed": True, "vulnerability_score": 0.7, ...}
"""

import re
import hashlib
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse


class ResponseDiffer:
    """
    Smart response differ buat detect vulnerability indicators.
    
    Bandingin baseline vs test response pake multiple signals:
    - Status code changes
    - Response length changes
    - Body content changes (semantic diff)
    - Header changes
    - Error message patterns
    - Reflection detection
    """

    def __init__(self):
        # Error patterns yang sering muncul kalau vulnerability ada
        self.error_patterns = {
            "sql": [
                r"sql\s+syntax", r"mysql", r"postgresql", r"sqlite",
                r"ora-\d{5}", r"unclosed quotation", r"unterminated string",
                r"query\s+failed", r"database\s+error", r"syntax\s+error",
            ],
            "xss": [
                r"<script", r"alert\(", r"onerror=", r"onload=",
                r"javascript:", r"<img[^>]+src=x",
            ],
            "lfi": [
                r"root:x:0:0", r"bin/bash", r"/bin/sh",
                r"\[fonts\]", r"boot\s+loader",
            ],
            "xxe": [
                r"xml", r"entity", r"doctype", r"system\s+entity",
            ],
            "ssti": [
                r"49", r"7777777",  # {{7*7}} results
            ],
            "rce": [
                r"uid=\d+", r"gid=\d+", r"groups=",
                r"www-data", r"apache", r"nginx", r"root",
            ],
            "auth_bypass": [
                r"dashboard", r"welcome", r"logout", r"profile",
                r"admin", r"settings", r"account",
            ],
        }

        # Patterns yang menandakan input di-reflect
        self.reflection_indicators = [
            r"<script[^>]*>.*?</script>",
            r"on\w+\s*=",  # event handlers
            r"javascript:",
        ]

    def capture_baseline(self, url: str, method: str = "GET", **kwargs) -> Dict[str, Any]:
        """
        Capture baseline response dari target URL.
        Return dict yang bisa dipake buat compare.
        """
        import requests
        try:
            resp = requests.request(
                method, url,
                timeout=kwargs.get("timeout", 10),
                verify=False,
                allow_redirects=True,
                **{k: v for k, v in kwargs.items() if k != "timeout"}
            )
            return self._parse_response(resp)
        except Exception as e:
            return {
                "error": str(e),
                "status_code": 0,
                "body": "",
                "body_length": 0,
                "headers": {},
                "body_hash": "",
            }

    def _parse_response(self, resp) -> Dict[str, Any]:
        """Parse response object jadi dict."""
        body = resp.text[:10000]  # Cap body buat performance
        return {
            "status_code": resp.status_code,
            "body": body,
            "body_length": len(body),
            "body_hash": hashlib.md5(body.encode()).hexdigest(),
            "headers": dict(resp.headers),
            "content_type": resp.headers.get("Content-Type", ""),
            "redirect_url": resp.headers.get("Location", ""),
            "response_time": getattr(resp, "elapsed", None),
        }

    def compare(
        self,
        baseline: Dict[str, Any],
        test_response,
        payload: str = "",
        param: str = "",
    ) -> Dict[str, Any]:
        """
        Compare baseline vs test response.
        
        Return:
            {
                "status_changed": bool,
                "body_changed": bool,
                "body_length_diff": int,
                "reflection_detected": bool,
                "error_patterns_found": [str],
                "vulnerability_score": float (0.0 - 1.0),
                "diff_summary": str,
                "severity": str,
            }
        """
        test = self._parse_response(test_response) if not isinstance(test_response, dict) else test_response

        result = {
            "status_changed": False,
            "body_changed": False,
            "body_length_diff": 0,
            "body_length_ratio": 1.0,
            "reflection_detected": False,
            "reflection_type": "",
            "error_patterns_found": [],
            "error_category": "",
            "header_changed": False,
            "redirect_changed": False,
            "vulnerability_score": 0.0,
            "diff_summary": "",
            "severity": "info",
            "indicators": [],
        }

        # ── Status code comparison ─────────────────────────────────────────────
        baseline_status = baseline.get("status_code", 0)
        test_status = test.get("status_code", 0)

        if baseline_status != test_status:
            result["status_changed"] = True
            result["indicators"].append(f"Status changed: {baseline_status} → {test_status}")

            # Status 200 di test vs 4xx di baseline = mungkin bypass
            if baseline_status >= 400 and test_status == 200:
                result["vulnerability_score"] += 0.5
                result["indicators"].append("Possible access control bypass (4xx → 200)")

            # Status 500 di test = mungkin error injection
            if test_status == 500:
                result["vulnerability_score"] += 0.3
                result["indicators"].append("Server error (500) — possible injection")

        # ── Body content comparison ────────────────────────────────────────────
        baseline_body = baseline.get("body", "")
        test_body = test.get("body", "")

        baseline_len = len(baseline_body)
        test_len = len(test_body)

        if baseline_len > 0:
            result["body_length_diff"] = test_len - baseline_len
            result["body_length_ratio"] = test_len / baseline_len if baseline_len > 0 else 1.0

        if baseline_body != test_body:
            result["body_changed"] = True

            # Significant length change
            if baseline_len > 0 and abs(test_len - baseline_len) > 100:
                result["vulnerability_score"] += 0.2
                result["indicators"].append(f"Significant body length change: {baseline_len} → {test_len}")

        # ── Payload reflection detection ───────────────────────────────────────
        if payload:
            # Check if payload reflected in body
            if payload.lower() in test_body.lower():
                result["reflection_detected"] = True
                result["reflection_type"] = "body"
                result["vulnerability_score"] += 0.4
                result["indicators"].append(f"Payload reflected in body: '{payload[:50]}'")

            # Check if payload in headers
            for header_val in test.get("headers", {}).values():
                if payload.lower() in str(header_val).lower():
                    result["reflection_detected"] = True
                    result["reflection_type"] = "header"
                    result["vulnerability_score"] += 0.3
                    result["indicators"].append(f"Payload reflected in header")
                    break

        # ── Error pattern detection ────────────────────────────────────────────
        test_body_lower = test_body.lower()
        for category, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, test_body_lower):
                    if category not in result["error_patterns_found"]:
                        result["error_patterns_found"].append(category)
                        result["error_category"] = category

                        # Map error category ke vulnerability score
                        score_map = {
                            "sql": 0.7, "xss": 0.6, "lfi": 0.8,
                            "xxe": 0.8, "ssti": 0.9, "rce": 0.9,
                            "auth_bypass": 0.6,
                        }
                        result["vulnerability_score"] += score_map.get(category, 0.3)
                        result["indicators"].append(f"Error pattern detected: {category}")
                        break  # Satu match per kategori cukup

        # ── XSS reflection check ───────────────────────────────────────────────
        if payload and any(ind in payload.lower() for ind in ["<script", "<img", "<svg", "onerror"]):
            for pattern in self.reflection_indicators:
                if re.search(pattern, test_body, re.IGNORECASE):
                    result["reflection_detected"] = True
                    result["reflection_type"] = "xss_vector"
                    result["vulnerability_score"] += 0.5
                    result["indicators"].append("XSS vector reflected unescaped")
                    break

        # ── Redirect analysis ──────────────────────────────────────────────────
        if baseline.get("redirect_url") != test.get("redirect_url"):
            result["redirect_changed"] = True
            result["indicators"].append("Redirect behavior changed")

        # ── Header changes ─────────────────────────────────────────────────────
        baseline_headers = baseline.get("headers", {})
        test_headers = test.get("headers", {})
        header_diffs = set(baseline_headers.keys()) - set(test_headers.keys())
        if header_diffs:
            result["header_changed"] = True
            result["indicators"].append(f"Missing headers: {header_diffs}")

        # ── Normalize score ────────────────────────────────────────────────────
        result["vulnerability_score"] = min(result["vulnerability_score"], 1.0)

        # ── Determine severity ─────────────────────────────────────────────────
        score = result["vulnerability_score"]
        if score >= 0.7:
            result["severity"] = "critical"
        elif score >= 0.5:
            result["severity"] = "high"
        elif score >= 0.3:
            result["severity"] = "medium"
        elif score >= 0.1:
            result["severity"] = "low"
        else:
            result["severity"] = "safe"

        # ── Build summary ──────────────────────────────────────────────────────
        summary_parts = []
        if result["status_changed"]:
            summary_parts.append(f"Status {baseline_status}→{test_status}")
        if result["reflection_detected"]:
            summary_parts.append(f"Payload reflected ({result['reflection_type']})")
        if result["error_patterns_found"]:
            summary_parts.append(f"Errors: {', '.join(result['error_patterns_found'])}")
        if result["body_changed"]:
            summary_parts.append(f"Body diff: {result['body_length_diff']:+d} bytes")

        result["diff_summary"] = "; ".join(summary_parts) if summary_parts else "No significant changes"

        return result


# Global instance
differ = ResponseDiffer()


def quick_diff(url: str, payload: str, param: str = "test") -> Dict[str, Any]:
    """
    Quick helper: capture baseline, inject payload, compare.
    Return diff result.
    """
    import requests
    from urllib.parse import quote
    from core.rate_limiter import rate_limiter

    domain = urlparse(url).netloc.split(":")[0].lower()
    
    # Capture baseline
    baseline = differ.capture_baseline(url)
    
    # Inject payload
    test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(payload)}"
    rate_limiter.wait(domain)
    try:
        test_resp = requests.get(test_url, timeout=10, verify=False)
        return differ.compare(baseline, test_resp, payload=payload, param=param)
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "vulnerability_score": 0.0,
            "severity": "info",
        }

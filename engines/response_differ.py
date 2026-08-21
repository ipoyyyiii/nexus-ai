"""
RESPONSE DIFFER — Semantic Response Comparison
===============================================
Bandingin baseline vs test response with cerdas.
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
    Smart response differ for detect vulnerability indicators.
    
    Bandingin baseline vs test response pake multiple signals:
    - Status code changes
    - Response length changes
    - Body content changes (semantic diff)
    - Header changes
    - Error message patterns
    - Reflection detection
    """

    def __init__(self):
        # Error patterns that spesifik — generic patterns deleted for kurangi FP
        self.error_patterns = {
            "sql": [
                r"sql\s+syntax\s+error",  # must spesifik "syntax error"
                r"unquoted\s+string",
                r"mysql_fetch",
                r"pg_query",
                r"sqlite3\.OperationalError",
                r"ora-\d{5}",  # Oracle error codes
                r"microsoft\s+oledb",
                r"unclosed\s+quotation\s+mark",
                r"unterminated\s+string\s+constant",
                r"you\s+have\s+an\s+error\s+in\s+your\s+sql\s+syntax",
            ],
            "xss": [
                r"<script[^>]*>.*?</script>",  # must full tag
                r"alert\(['\"]",  # must ada argument
                r"onerror\s*=",  # event handler
                r"onload\s*=",
                r"javascript\s*:",  # protocol handler
                r"<img[^>]+onerror\s*=",
            ],
            "lfi": [
                r"root:x:0:0:.*:/bin/",  # must full /etc/passwd line
                r"bin/bash\s*$",
                r"\[boot loader\]",  # Windows boot.ini
                r"Warning.*fopen\(",
                r"failed to open stream",
            ],
            "xxe": [
                r"xml\s+parsing\s+error",
                r"entity\s+reference",
                r"doctype\s+not\s+allowed",
                r"lxml\.etree\.XMLSyntaxError",
                r"SimpleXMLElement",
                r"xmlrpc\s+server\s+error",
            ],
            "ssti": [
                r"\{\{7\*7\}\}",  # literal template expression
                r"\b49\b",  # {{7*7}} output (word boundary to avoid false matches)
                r"7777777",  # {{7*7}} output
                r"123456789.*123456789",  # {{9*9}} pattern
                r"Jinja2\.Template",
                r"Twig\\Error",
                r"TemplateSyntaxError",
                r"template.*error",
                r"syntax.*error.*template",
            ],
            "rce": [
                r"uid=\d+\(.*\)\s+gid=\d+",  # must full id output
                r"groups?=.*root",
                r"/bin/sh:\s+\d+:",
                r"sh:\s+\d+:\s+not\s+found",
            ],
            "auth_bypass": [
                r"welcome\s+admin",
                r"admin\s+panel",
                r"dashboard\s+loaded",
                r"logout\s+successful",
                r"session\s+started",
            ],
        }

        # Patterns that menandwill input di-reflect
        self.reflection_indicators = [
            r"<script[^>]*>.*?</script>",
            r"on\w+\s*=",  # event handlers
            r"javascript:",
        ]

        # Baseline patterns — diisi waktu capture_baseline
        self._baseline_patterns = set()

        # Error template fingerprints — auto-detect known error pages
        self.error_templates = {
            "laravel_500": {
                "size_range": (9800, 10100),
                "must_contain": ["whoops", "laravel", "stacktrace", "vendor"],
                "penalty": 0.8,  # kurangi score sebanyak this kalau match
            },
            "laravel_404": {
                "size_range": (9800, 10100),
                "must_contain": ["404", "not found"],
                "penalty": 0.8,
            },
            "django_500": {
                "size_range": (2000, 3000),
                "must_contain": ["django", "traceback"],
                "penalty": 0.7,
            },
            "express_500": {
                "size_range": (200, 500),
                "must_contain": ["internal server error"],
                "penalty": 0.6,
            },
            "spring_500": {
                "size_range": (500, 800),
                "must_contain": ["whitelabel", "error page"],
                "penalty": 0.7,
            },
            "nginx_502": {
                "size_range": (500, 700),
                "must_contain": ["502", "bad gateway"],
                "penalty": 0.9,
            },
            "cloudflare_502": {
                "size_range": (1000, 1500),
                "must_contain": ["cloudflare", "502"],
                "penalty": 0.95,
            },
        }

        # WAF indicators — kalau detect WAF, turunkan confidence
        self.waf_indicators = {
            "cloudflare": [r"cf-ray", r"__cf_bm", r"cf_clearance"],
            "aws_waf": [r"x-amzn-requestid", r"x-amz-cf-id"],
            "akamai": [r"x-akamai", r"akamai"],
            "incapsula": [r"x-iinfo", r"incap_ses"],
            "Sucuri": [r"x-sucuri-id"],
        }

        # Severity adjustment based on endpoint context
        self.endpoint_risk_profiles = {
            "admin": {"multiplier": 1.5, "keywords": ["admin", "dashboard", "manage"]},
            "api": {"multiplier": 0.8, "keywords": ["/api/", "json"]},
            "auth": {"multiplier": 1.3, "keywords": ["login", "auth", "signin", "register"]},
            "public": {"multiplier": 1.0, "keywords": []},
        }

        # ── NEW: Application Framework Fingerprints ───────────────────────────
        self.framework_fingerprints = {
            "laravel": {
                "headers": ["x-powered-by.*laravel", "set-cookie.*laravel_session"],
                "body": ["laravel", "illuminate", "whoops", "ignition"],
                "patterns": ["csrf-token", "csrf_token", "_token"],
            },
            "django": {
                "headers": ["x-frame-options.*DENY", "set-cookie.*csrftoken"],
                "body": ["django", "csrfmiddlewaretoken", "django.contrib"],
                "patterns": ["csrfmiddlewaretoken", "__admin__"],
            },
            "express": {
                "headers": ["x-powered-by.*express"],
                "body": ["express", "jwt", "passport"],
                "patterns": ["express-session", "connect.sid"],
            },
            "spring": {
                "headers": ["x-application-context"],
                "body": ["spring", "whitelabel error", "springframework"],
                "patterns": ["JSESSIONID", "spring-security"],
            },
            "rails": {
                "headers": ["x-runtime", "set-cookie.*_session_id"],
                "body": ["rails", "ruby", "actionpack"],
                "patterns": ["_session_id", "csrf-token"],
            },
            "aspnet": {
                "headers": ["x-aspnet-version", "x-powered-by.*asp\\.net"],
                "body": ["asp\\.net", "viewstate", "__viewstate"],
                "patterns": ["ASP.NET_SessionId", "__VIEWSTATE"],
            },
        }

        # ── NEW: Error Template Fingerprints ──────────────────────────────────
        self.error_templates = {
            "laravel_500": {
                "size_range": (9800, 10100),
                "must_contain": ["whoops", "laravel", "stacktrace"],
                "penalty": 0.8,
            },
            "laravel_404": {
                "size_range": (9800, 10100),
                "must_contain": ["404", "not found"],
                "penalty": 0.8,
            },
            "django_500": {
                "size_range": (2000, 3000),
                "must_contain": ["django", "traceback"],
                "penalty": 0.7,
            },
            "express_500": {
                "size_range": (200, 500),
                "must_contain": ["internal server error"],
                "penalty": 0.6,
            },
            "spring_500": {
                "size_range": (500, 800),
                "must_contain": ["whitelabel", "error page"],
                "penalty": 0.7,
            },
            "nginx_502": {
                "size_range": (500, 700),
                "must_contain": ["502", "bad gateway"],
                "penalty": 0.9,
            },
            "cloudflare_502": {
                "size_range": (1000, 1500),
                "must_contain": ["cloudflare", "502"],
                "penalty": 0.95,
            },
        }

        # ── NEW: Multi-Payload Tracking ───────────────────────────────────────
        self._payload_history: Dict[str, List[Dict]] = {}

        # ── NEW: Baseline Snapshots ───────────────────────────────────────────
        self._baseline_snapshots: List[Dict] = []

    def capture_baseline(self, url: str, method: str = "GET", snapshots: int = 1, **kwargs) -> Dict[str, Any]:
        """
        Capture baseline response from target URL.
        snapshots: jumlah baseline snapshot (for consistency check)
        Return dict that can dipake for compare.
        """
        from core.tool_transport import guarded_requests as requests
        import time

        snapshots_data = []

        for i in range(snapshots):
            try:
                resp = requests.request(
                    method, url,
                    timeout=kwargs.get("timeout", 10),
                    verify=False,
                    allow_redirects=True,
                    **{k: v for k, v in kwargs.items() if k != "timeout"}
                )
                snapshot = self._parse_response(resp)
                snapshots_data.append(snapshot)

                if snapshots > 1 and i < snapshots - 1:
                    time.sleep(0.5)  # Small delay between snapshots
            except Exception:
                pass

        if not snapshots_data:
            self._baseline_patterns = set()
            return {
                "error": "Failed to capture baseline",
                "status_code": 0,
                "body": "",
                "body_length": 0,
                "headers": {},
                "body_hash": "",
                "_url": url,
            }

        # Use first snapshot as primary baseline
        result = snapshots_data[0]
        result["_url"] = url
        result["_snapshots"] = snapshots_data  # Store all snapshots
        self._baseline_snapshots = snapshots_data

        # Scan baseline for detect error patterns that udah ada
        baseline_body = result.get("body", "").lower()
        self._baseline_patterns = set()
        for category, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, baseline_body):
                    self._baseline_patterns.add(category)
                    break

        return result

    def _detect_error_template(self, body: str, status_code: int) -> tuple:
        """
        Deteksi apakah response is error template that dikenal.
        Return (is_error_template: bool, template_name: str, penalty: float)
        """
        body_lower = body.lower()
        body_len = len(body)

        for template_name, template in self.error_templates.items():
            # Cek size range (lebih tolerant)
            min_size, max_size = template["size_range"]
            size_tolerance = (max_size - min_size) * 0.5  # 50% tolerance
            if not ((min_size - size_tolerance) <= body_len <= (max_size + size_tolerance)):
                continue

            # Cek required keywords (lebih flexibel - 2 from 3 must match)
            keywords = template.get("must_contain", [])
            matches = sum(1 for kw in keywords if kw.lower() in body_lower)
            if matches >= max(2, len(keywords) - 1):  # At least 2 or N-1 keywords
                return True, template_name, template["penalty"]

        # Check for generic error patterns
        generic_error_patterns = [
            (r"whoops|laravel|ignition", "laravel_error", 0.7),
            (r"traceback|django", "django_error", 0.6),
            (r"whitelabel.*error|spring", "spring_error", 0.6),
            (r"internal server error|apache|nginx", "generic_500", 0.5),
            (r"502 bad gateway", "bad_gateway", 0.8),
            (r"503 service unavailable", "service_unavailable", 0.7),
        ]

        for pattern, template_name, penalty in generic_error_patterns:
            if re.search(pattern, body_lower):
                return True, template_name, penalty

        return False, "", 0.0

    def _detect_framework(self, headers: dict, body: str) -> str:
        """
        Detect application framework from response headers dan body.
        Return framework name atau "unknown".
        """
        headers_str = str(headers).lower()
        body_lower = body.lower()

        for framework, fingerprints in self.framework_fingerprints.items():
            # Check headers
            header_match = any(
                re.search(pattern, headers_str)
                for pattern in fingerprints.get("headers", [])
            )
            # Check body
            body_match = any(
                pattern.lower() in body_lower
                for pattern in fingerprints.get("body", [])
            )

            if header_match or body_match:
                return framework

        return "unknown"

    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text.
        High entropy = random content (likely payload reflected)
        Low entropy = structured content (likely normal response)
        """
        import math
        from collections import Counter

        if not text:
            return 0.0

        # Count character frequencies
        freq = Counter(text)
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def _semantic_diff(self, baseline_body: str, test_body: str) -> Dict[str, Any]:
        """
        Compare response bodies semantically (HTML structure aware).
        Returns diff metrics including structural changes.
        """
        import re

        # Extract HTML tags from both bodies
        baseline_tags = re.findall(r'<(\w+)[^>]*>', baseline_body)
        test_tags = re.findall(r'<(\w+)[^>]*>', test_body)

        baseline_tag_counts = {}
        test_tag_counts = {}

        for tag in baseline_tags:
            tag_lower = tag.lower()
            baseline_tag_counts[tag_lower] = baseline_tag_counts.get(tag_lower, 0) + 1

        for tag in test_tags:
            tag_lower = tag.lower()
            test_tag_counts[tag_lower] = test_tag_counts.get(tag_lower, 0) + 1

        # Calculate tag differences
        all_tags = set(list(baseline_tag_counts.keys()) + list(test_tag_counts.keys()))
        tags_added = {}
        tags_removed = {}
        tags_modified = {}

        for tag in all_tags:
            baseline_count = baseline_tag_counts.get(tag, 0)
            test_count = test_tag_counts.get(tag, 0)

            if baseline_count == 0 and test_count > 0:
                tags_added[tag] = test_count
            elif baseline_count > 0 and test_count == 0:
                tags_removed[tag] = baseline_count
            elif baseline_count != test_count:
                tags_modified[tag] = {"from": baseline_count, "to": test_count}

        # Check for script/form injection indicators
        baseline_scripts = len(re.findall(r'<script', baseline_body, re.I))
        test_scripts = len(re.findall(r'<script', test_body, re.I))
        baseline_forms = len(re.findall(r'<form', baseline_body, re.I))
        test_forms = len(re.findall(r'<form', test_body, re.I))

        return {
            "tags_added": tags_added,
            "tags_removed": tags_removed,
            "tags_modified": tags_modified,
            "scripts_changed": test_scripts - baseline_scripts,
            "forms_changed": test_forms - baseline_forms,
            "structural_change_score": len(tags_added) + len(tags_removed) + len(tags_modified),
        }

    def _check_temporal_consistency(self, url: str, param: str, payload: str, requests_count: int = 3) -> Dict[str, Any]:
        """
        Check temporal consistency - kirim requests beberapa kali dan cek konsistensi.
        Returns consistency metrics.
        """
        from core.tool_transport import guarded_requests as requests
        import time

        responses = []
        for i in range(requests_count):
            try:
                from urllib.parse import quote
                test_url = f"{url}?{param}={quote(payload)}"
                resp = requests.get(test_url, timeout=5, verify=False)
                responses.append({
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "body_hash": hashlib.md5(resp.text.encode()).hexdigest(),
                })
                time.sleep(0.3)
            except Exception:
                pass

        if len(responses) < 2:
            return {"consistent": False, "reason": "Insufficient responses"}

        # Check consistency
        statuses = [r["status"] for r in responses]
        lengths = [r["length"] for r in responses]
        hashes = [r["body_hash"] for r in responses]

        status_consistent = len(set(statuses)) == 1
        length_consistent = max(lengths) - min(lengths) < 50  # Less than 50 bytes difference
        hash_consistent = len(set(hashes)) == 1

        all_consistent = status_consistent and length_consistent and hash_consistent

        return {
            "consistent": all_consistent,
            "status_consistent": status_consistent,
            "length_consistent": length_consistent,
            "hash_consistent": hash_consistent,
            "requests_made": len(responses),
            "unique_statuses": list(set(statuses)),
            "length_range": max(lengths) - min(lengths) if lengths else 0,
        }

    def _check_baseline_consistency(self, test_body: str, test_status: int) -> Dict[str, Any]:
        """
        Check if test response is consistent with baseline snapshots.
        Returns consistency metrics.
        """
        if not self._baseline_snapshots:
            return {"consistent": True, "reason": "No baseline snapshots"}

        # Compare with each snapshot
        matches = 0
        for snapshot in self._baseline_snapshots:
            if snapshot.get("status_code") == test_status:
                # Check body similarity
                baseline_body = snapshot.get("body", "")
                if len(baseline_body) > 0 and len(test_body) > 0:
                    # Simple similarity check using hash
                    baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()
                    test_hash = hashlib.md5(test_body.encode()).hexdigest()
                    if baseline_hash == test_hash:
                        matches += 1
                elif baseline_body == test_body:
                    matches += 1

        consistency_ratio = matches / len(self._baseline_snapshots) if self._baseline_snapshots else 0

        return {
            "consistent": consistency_ratio > 0.5,
            "consistency_ratio": consistency_ratio,
            "snapshots_checked": len(self._baseline_snapshots),
            "matches": matches,
        }

    def _check_response_entropy(self, baseline_body: str, test_body: str) -> Dict[str, Any]:
        """
        Check response entropy - high entropy difference = likely injection.
        """
        baseline_entropy = self._calculate_entropy(baseline_body)
        test_entropy = self._calculate_entropy(test_body)
        entropy_diff = abs(test_entropy - baseline_entropy)

        # High entropy difference = likely payload reflected
        return {
            "baseline_entropy": baseline_entropy,
            "test_entropy": test_entropy,
            "entropy_diff": entropy_diff,
            "high_entropy_diff": entropy_diff > 1.0,  # Threshold for significant change
        }

    def _detect_waf(self, headers: dict) -> list:
        """
        Deteksi WAF/CDN that aktif.
        Return list nama WAF that terdeteksi.
        """
        detected = []
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        for waf_name, patterns in self.waf_indicators.items():
            for pattern in patterns:
                if any(re.search(pattern, v) for v in headers_lower.values()):
                    detected.append(waf_name)
                    break

        return detected

    def _get_endpoint_risk(self, url: str) -> tuple:
        """
        Determine risk profile based on URL/endpoint.
        Return (profile_name: str, multiplier: float)
        """
        url_lower = url.lower()

        for profile_name, profile in self.endpoint_risk_profiles.items():
            if any(kw in url_lower for kw in profile["keywords"]):
                return profile_name, profile["multiplier"]

        return "public", 1.0

    def _check_content_type_mismatch(
        self, baseline_ct: str, test_ct: str, baseline_status: int, test_status: int
    ) -> tuple:
        """
        Deteksi content-type mismatch that mengindikasikan app broken.
        Return (is_mismatch: bool, penalty: float, reason: str)
        """
        if not baseline_ct or not test_ct:
            return False, 0.0, ""

        # Normalize
        baseline_ct = baseline_ct.split(";")[0].strip().lower()
        test_ct = test_ct.split(";")[0].strip().lower()

        # HTML → JSON = suspicious (app might be returning error JSON)
        if baseline_ct == "text/html" and test_ct == "application/json":
            return True, 0.3, "Content-Type changed from HTML to JSON"

        # HTML → empty/unknown = suspicious
        if baseline_ct == "text/html" and test_ct in ("", "text/plain", "application/octet-stream"):
            return True, 0.4, "Content-Type changed to non-HTML"

        # 200 → 500 with CT change = error page
        if baseline_status == 200 and test_status == 500 and baseline_ct != test_ct:
            return True, 0.5, "Status 500 with Content-Type change = error page"

        return False, 0.0, ""

    def _parse_response(self, resp) -> Dict[str, Any]:
        """Parse response object jadi dict."""
        body = resp.text[:10000]  # Cap body for performance
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
        # Hanya hitung pattern that BUKAN udah ada di baseline
        test_body_lower = test_body.lower()
        for category, patterns in self.error_patterns.items():
            # Skip kalau pattern this udah ada di baseline
            if category in self._baseline_patterns:
                continue

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

        # ── Error Template Fingerprinting ─────────────────────────────────────
        is_error_template, template_name, template_penalty = self._detect_error_template(
            test.get("body", ""), test_status
        )
        if is_error_template:
            result["vulnerability_score"] = max(0, result["vulnerability_score"] - template_penalty)
            result["indicators"].append(
                f"Error template detected: {template_name} (penalty: -{template_penalty})"
            )

        # ── Content-Type Mismatch Detection ──────────────────────────────────
        baseline_ct = baseline.get("content_type", "")
        test_ct = test.get("content_type", "")
        ct_mismatch, ct_penalty, ct_reason = self._check_content_type_mismatch(
            baseline_ct, test_ct, baseline_status, test_status
        )
        if ct_mismatch:
            result["vulnerability_score"] = max(0, result["vulnerability_score"] - ct_penalty)
            result["indicators"].append(f"CT mismatch: {ct_reason} (penalty: -{ct_penalty})")

        # ── Body change gate: high/critical butuh body berubah ────────────────
        # Kalau body IDENTIK sama baseline, score dibatasi max 0.3 (medium)
        # Kecuali ada payload reflection atau status bypass that jelas
        if not result["body_changed"]:
            has_clear_bypass = (
                (result["status_changed"] and baseline_status >= 400 and test_status == 200)
                or result["reflection_detected"]
            )
            if not has_clear_bypass and result["vulnerability_score"] > 0.3:
                result["indicators"].append(
                    f"Score capped: body unchanged ({result['vulnerability_score']:.2f} → 0.3)"
                )
                result["vulnerability_score"] = 0.3

        # ── WAF-Aware Scoring ────────────────────────────────────────────────
        waf_detected = self._detect_waf(test.get("headers", {}))
        if waf_detected:
            waf_penalty = 0.15 * len(waf_detected)  # 15% per WAF
            result["vulnerability_score"] = max(0, result["vulnerability_score"] - waf_penalty)
            result["indicators"].append(f"WAF detected: {', '.join(waf_detected)} (penalty: -{waf_penalty:.2f})")

        # ── Context-Aware Severity ───────────────────────────────────────────
        # Get URL from baseline (assume same URL)
        endpoint_url = baseline.get("_url", "")
        if endpoint_url:
            risk_profile, risk_multiplier = self._get_endpoint_risk(endpoint_url)
            if risk_multiplier != 1.0:
                result["vulnerability_score"] = min(1.0, result["vulnerability_score"] * risk_multiplier)
                result["indicators"].append(
                    f"Endpoint risk: {risk_profile} (multiplier: {risk_multiplier}x)"
                )

        # ── NEW: Framework Detection ──────────────────────────────────────────
        framework = self._detect_framework(test.get("headers", {}), test.get("body", ""))
        if framework != "unknown":
            result["indicators"].append(f"Framework detected: {framework}")

        # ── NEW: Semantic Diff ─────────────────────────────────────────────────
        if result["body_changed"]:
            semantic = self._semantic_diff(baseline_body, test_body)
            if semantic["structural_change_score"] > 3:
                result["vulnerability_score"] += 0.1
                result["indicators"].append(f"Structural changes: {semantic['structural_change_score']} tags modified")

        # ── NEW: Entropy Analysis ─────────────────────────────────────────────
        entropy = self._check_response_entropy(baseline_body, test_body)
        if entropy["high_entropy_diff"]:
            result["vulnerability_score"] += 0.1
            result["indicators"].append(f"High entropy diff: {entropy['entropy_diff']:.2f}")

        # ── NEW: Baseline Consistency Check ───────────────────────────────────
        if self._baseline_snapshots:
            consistency = self._check_baseline_consistency(test_body, test_status)
            if not consistency["consistent"]:
                # Response not konsisten = mungkin FP
                result["vulnerability_score"] = max(0, result["vulnerability_score"] - 0.1)
                result["indicators"].append(
                    f"Baseline inconsistency: {consistency['matches']}/{consistency['snapshots_checked']} snapshots matched"
                )

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

    def confirm_detection(
        self,
        url: str,
        param: str,
        original_diff: Dict[str, Any],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Konfirmasi deteksi with kirim known-safe payload.
        Kalau safe payload juga trigger vulnerability → false positive.
        
        Return:
            {
                "confirmed": bool,
                "original_score": float,
                "confirmation_score": float,
                "is_false_positive": bool,
                "reason": str,
            }
        """
        from core.tool_transport import guarded_requests as requests
        import string
        import random

        # Generate random safe payload (bukan SQL/XSS/SSRF)
        safe_payload = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))

        try:
            # Kirim safe payload
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={safe_payload}"
            resp = requests.get(
                test_url,
                timeout=kwargs.get("timeout", 10),
                verify=False,
                allow_redirects=True,
            )

            # Compare with baseline that sama
            baseline = original_diff.get("_baseline", {})
            if not baseline:
                # Fallback: capture baru
                baseline = self.capture_baseline(url, **kwargs)

            confirm_diff = self.compare(baseline, resp, payload=safe_payload, param=param)

            is_fp = False
            reason = ""

            # Kalau safe payload juga dapet score tinggi → FP
            if confirm_diff["vulnerability_score"] >= 0.5:
                is_fp = True
                reason = (
                    f"Safe payload juga trigger score {confirm_diff['vulnerability_score']:.2f} "
                    f"(patterns: {confirm_diff['error_patterns_found']}). "
                    f"Kemungkinan false positive."
                )
            # Kalau error pattern that sama muncul di safe payload → FP
            elif set(confirm_diff["error_patterns_found"]) & set(original_diff.get("error_patterns_found", [])):
                is_fp = True
                overlapping = set(confirm_diff["error_patterns_found"]) & set(original_diff.get("error_patterns_found", []))
                reason = (
                    f"Error patterns {overlapping} muncul di both payload → "
                    f"pattern that memang bagian from aplikasi, bukan from injection."
                )
            else:
                reason = "Detection confirmed — safe payload not trigger vulnerability."

            return {
                "confirmed": not is_fp,
                "original_score": original_diff.get("vulnerability_score", 0),
                "confirmation_score": confirm_diff["vulnerability_score"],
                "is_false_positive": is_fp,
                "reason": reason,
            }

        except Exception as e:
            return {
                "confirmed": False,
                "original_score": original_diff.get("vulnerability_score", 0),
                "confirmation_score": 0,
                "is_false_positive": True,
                "reason": f"Confirmation failed ({e}) — treating as FP for safety.",
            }


# Global instance
differ = ResponseDiffer()


def quick_diff(url: str, payload: str, param: str = "test") -> Dict[str, Any]:
    """
    Quick helper: capture baseline, inject payload, compare.
    Return diff result.
    """
    from core.tool_transport import guarded_requests as requests
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

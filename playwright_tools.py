import asyncio
import base64
import json
import re
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

from crewai.tools import tool

from cancellation import check_cancelled
from rate_limiter import rate_limiter
from redact import redact

try:
    from playwright.async_api import async_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ── Shared browser context (lazy init) ────────────────────────────────────────

_browser = None
_playwright = None


async def _get_browser():
    global _browser, _playwright
    if not PLAYWRIGHT_AVAILABLE:
        raise RuntimeError(
            "Playwright belum diinstall. Jalankan:\n"
            "  pip install playwright --break-system-packages\n"
            "  playwright install chromium"
        )
    if _browser is None or not _browser.is_connected():
        _playwright = await async_playwright().start()
        _browser = await _playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ]
        )
    return _browser


async def _new_page(browser, timeout_ms: int = 15000):
    """Buat page baru dengan stealth settings dasar."""
    ctx = await browser.new_context(
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        viewport={"width": 1280, "height": 800},
        ignore_https_errors=True,
    )
    page = await ctx.new_page()
    page.set_default_timeout(timeout_ms)

    # Basic anti-detection: hapus webdriver fingerprint
    await page.add_init_script(
        "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
    )
    return page, ctx


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


def _run_async(coro):
    """Run async coroutine dari sync tool context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=60)
        else:
            return loop.run_until_complete(coro)
    except Exception:
        return asyncio.run(coro)


# ── Exec logger accessor (sama kayak custom_tools.py) ─────────────────────────

def _logger():
    try:
        from custom_tools import exec_logger
        return exec_logger
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — Screenshot + visual analysis
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_screenshot(url: str) -> str:
    """
    Buka URL di headless browser, ambil screenshot full-page, dan extract
    informasi dasar (title, meta, visible text snippet).
    Berguna buat: verify target accessible, detect login wall, lihat struktur
    halaman, nemuin error message atau debug info yang exposed.

    Args:
        url: URL target yang mau di-screenshot
    Returns:
        JSON string berisi title, meta description, visible text (500 char),
        dan screenshot base64 (untuk analisis visual oleh LLM).
    """
    logger = _logger()
    tool_name = "Browser Screenshot"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        try:
            await page.goto(url, wait_until="domcontentloaded")
            await page.wait_for_timeout(2000)  # Tunggu JS render

            title = await page.title()
            meta_desc = await page.evaluate(
                "() => document.querySelector('meta[name=\"description\"]')?.content ?? ''"
            )
            visible_text = await page.evaluate(
                "() => document.body?.innerText?.slice(0, 500) ?? ''"
            )
            screenshot_bytes = await page.screenshot(full_page=True)
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode()

            result = {
                "url": url,
                "title": title,
                "meta_description": meta_desc,
                "visible_text_preview": visible_text,
                "screenshot_base64": screenshot_b64[:200] + "...[truncated for log]",
                "status": "success"
            }
            if logger:
                logger.add_log(tool_name, "SUCCESS", f"Screenshot berhasil: {title}")
            return json.dumps(redact(result), indent=2)
        except PWTimeout:
            return json.dumps({"error": f"Timeout saat load {url}"})
        except Exception as e:
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — Extract attack surface
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_extract_surface(url: str) -> str:
    """
    Buka halaman di headless browser dan extract semua attack surface:
    - Semua link (internal & eksternal)
    - Semua form (action URL, method, input fields)
    - Semua input element dengan name/id/type
    - Script src URLs (JS files)
    - API-like URLs yang kedeteksi dari href/action
    Berguna buat: mapping attack surface sebelum scanning, nemuin endpoint
    tersembunyi yang cuma muncul setelah browser render JS.

    Args:
        url: URL halaman yang mau di-extract
    Returns:
        JSON berisi links, forms, inputs, scripts, dan api_endpoints
    """
    logger = _logger()
    tool_name = "Browser Extract Surface"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        try:
            await page.goto(url, wait_until="networkidle")
            await page.wait_for_timeout(1500)

            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

            # Extract links
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter((v, i, arr) => arr.indexOf(v) === i)
                    .slice(0, 100)
            """)

            # Extract forms
            forms = await page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action || '',
                    method: f.method || 'get',
                    inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                        .map(i => ({name: i.name, id: i.id, type: i.type}))
                }))
            """)

            # Extract all inputs (termasuk yang di luar form)
            inputs = await page.evaluate("""
                () => Array.from(document.querySelectorAll('input,select,textarea'))
                    .map(i => ({name: i.name, id: i.id, type: i.type, placeholder: i.placeholder}))
                    .filter(i => i.name || i.id)
                    .slice(0, 50)
            """)

            # Extract script sources
            scripts = await page.evaluate("""
                () => Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter((v, i, arr) => arr.indexOf(v) === i)
            """)

            # Filter API-looking endpoints
            api_patterns = re.compile(r'/api/|/v\d+/|/graphql|/rest/|/json|/data/', re.I)
            api_endpoints = [l for l in links if api_patterns.search(l)]

            result = {
                "url": url,
                "base_url": base,
                "total_links": len(links),
                "internal_links": [l for l in links if base in l][:30],
                "external_links": [l for l in links if base not in l][:20],
                "api_endpoints_detected": api_endpoints,
                "forms": forms,
                "all_inputs": inputs,
                "script_sources": scripts,
                "status": "success"
            }

            if logger:
                logger.add_log(
                    tool_name, "SUCCESS",
                    f"Extracted {len(links)} links, {len(forms)} forms, {len(api_endpoints)} API endpoints"
                )
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — Intercept network requests
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_intercept_requests(url: str) -> str:
    """
    Load halaman di browser sambil intercept SEMUA network request yang dibuat
    — termasuk XHR, fetch, WebSocket handshake, dan asset requests.
    Ini cara terbaik nemuin hidden API endpoints yang cuma dipanggil pas
    JS jalan di browser, bukan dari HTML source.

    Args:
        url: URL halaman yang mau dimonitor request-nya
    Returns:
        JSON berisi semua request yang tertangkap (URL, method, headers, type)
    """
    logger = _logger()
    tool_name = "Browser Intercept Requests"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        captured = []

        async def on_request(request):
            captured.append({
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type,
                "headers": dict(list(request.headers.items())[:5]),  # Ambil 5 header pertama
            })

        page.on("request", on_request)

        try:
            await page.goto(url, wait_until="networkidle")
            await page.wait_for_timeout(3000)  # Extra wait buat lazy-loaded requests

            # Scroll ke bawah buat trigger lazy load
            await page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(1000)

            # Filter yang interesting (exclude assets statis)
            interesting_types = {"xhr", "fetch", "websocket", "document"}
            api_requests = [r for r in captured if r["resource_type"] in interesting_types]

            # Juga flag request yang URL-nya API-looking
            api_pattern = re.compile(r'/api/|/v\d+/|/graphql|/rest/|\.json|/data/', re.I)
            flagged = [r for r in captured if api_pattern.search(r["url"])]

            result = {
                "url": url,
                "total_requests_captured": len(captured),
                "xhr_and_fetch_requests": api_requests[:40],
                "api_flagged_requests": flagged[:20],
                "unique_domains_contacted": list(set(
                    urlparse(r["url"]).netloc for r in captured
                )),
                "status": "success"
            }

            if logger:
                logger.add_log(
                    tool_name, "SUCCESS",
                    f"Captured {len(captured)} requests, {len(api_requests)} XHR/fetch, {len(flagged)} API-flagged"
                )
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 4 — Extract JS secrets & hidden endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_extract_js_secrets(url: str) -> str:
    """
    Download dan scan semua file JavaScript dari halaman target.
    Nyari: API keys yang hardcoded, endpoint tersembunyi, token, config values,
    internal URL, dan credential yang sering nyangkut di JS bundle.

    Args:
        url: URL halaman awal (bukan JS file langsung)
    Returns:
        JSON berisi findings per JS file
    """
    logger = _logger()
    tool_name = "Browser JS Secret Scanner"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    # Pattern buat deteksi secrets & endpoints di JS
    SECRET_PATTERNS = {
        "api_key": re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
        "token": re.compile(r'(?:token|secret|password)\s*[:=]\s*["\']([A-Za-z0-9_\-]{10,})["\']', re.I),
        "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "internal_url": re.compile(r'https?://(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)[^\s"\']+'),
        "hidden_endpoint": re.compile(r'["\'](/(?:api|admin|internal|v\d+|debug|test|dev)/[^"\']+)["\']'),
        "graphql": re.compile(r'["\']([^"\']*graphql[^"\']*)["\']', re.I),
        "firebase": re.compile(r'firebaseConfig\s*=\s*\{[^}]+\}', re.I),
    }

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)

        try:
            # Ambil daftar JS files dari halaman
            await page.goto(url, wait_until="domcontentloaded")
            script_urls = await page.evaluate("""
                () => Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(s => s.startsWith('http'))
            """)

            findings = {}
            base_domain = _domain_of(url)

            for js_url in script_urls[:10]:  # Max 10 JS files biar gak lama
                if check_cancelled(logger):
                    break

                # Cuma scan JS dari domain yang sama (atau CDN-nya)
                js_domain = _domain_of(js_url)
                rate_limiter.wait(js_domain)

                try:
                    js_response = await page.request.get(js_url)
                    js_content = await js_response.text()

                    file_findings = {}
                    for pattern_name, pattern in SECRET_PATTERNS.items():
                        matches = pattern.findall(js_content)
                        if matches:
                            # Redact actual values — cukup tau ada, jangan log nilainya
                            file_findings[pattern_name] = {
                                "found": True,
                                "count": len(matches),
                                "sample": "[REDACTED — ada di file JS, perlu review manual]"
                            }

                    if file_findings:
                        findings[js_url] = file_findings

                except Exception:
                    continue

            result = {
                "url": url,
                "js_files_scanned": len(script_urls[:10]),
                "js_files_with_findings": len(findings),
                "findings": findings,
                "note": "Nilai actual di-redact. Review file JS secara manual untuk konfirmasi.",
                "status": "success" if not check_cancelled(logger) else "cancelled"
            }

            if logger:
                logger.add_log(
                    tool_name, "SUCCESS" if findings else "INFO",
                    f"Scanned {len(script_urls[:10])} JS files. Findings di {len(findings)} file."
                )
            return json.dumps(result, indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 5 — Security headers analysis
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_check_security_headers(url: str) -> str:
    """
    Load halaman dan analisa security headers yang ada/tidak ada.
    Cek: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy, CORS headers, cookies security flags.

    Args:
        url: URL target
    Returns:
        JSON berisi header analysis dengan severity per missing/misconfigured header
    """
    logger = _logger()
    tool_name = "Browser Security Headers"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    REQUIRED_HEADERS = {
        "content-security-policy": {
            "severity": "HIGH",
            "description": "Mencegah XSS dan injection attacks"
        },
        "strict-transport-security": {
            "severity": "HIGH",
            "description": "Enforce HTTPS, mencegah SSL stripping"
        },
        "x-frame-options": {
            "severity": "MEDIUM",
            "description": "Mencegah clickjacking via iframe"
        },
        "x-content-type-options": {
            "severity": "LOW",
            "description": "Mencegah MIME type sniffing"
        },
        "referrer-policy": {
            "severity": "LOW",
            "description": "Kontrol informasi di Referer header"
        },
        "permissions-policy": {
            "severity": "LOW",
            "description": "Restrict browser features (camera, mic, dll)"
        },
    }

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        try:
            response = await page.goto(url, wait_until="domcontentloaded")
            headers = dict(response.headers) if response else {}

            # Analisa per header
            analysis = {}
            missing_high = []
            missing_medium = []

            for header_name, meta in REQUIRED_HEADERS.items():
                value = headers.get(header_name)
                if value:
                    analysis[header_name] = {
                        "status": "PRESENT",
                        "value": value,
                        "severity": "OK"
                    }
                else:
                    analysis[header_name] = {
                        "status": "MISSING",
                        "severity": meta["severity"],
                        "description": meta["description"]
                    }
                    if meta["severity"] == "HIGH":
                        missing_high.append(header_name)
                    elif meta["severity"] == "MEDIUM":
                        missing_medium.append(header_name)

            # Cek cookies security flags
            cookies = await page.context.cookies()
            cookie_issues = []
            for cookie in cookies:
                issues = []
                if not cookie.get("secure"):
                    issues.append("missing Secure flag")
                if not cookie.get("httpOnly"):
                    issues.append("missing HttpOnly flag")
                if not cookie.get("sameSite") or cookie.get("sameSite") == "None":
                    issues.append("SameSite=None (potential CSRF risk)")
                if issues:
                    cookie_issues.append({
                        "name": cookie["name"],
                        "issues": issues
                    })

            result = {
                "url": url,
                "headers_analysis": analysis,
                "missing_critical": missing_high,
                "missing_medium": missing_medium,
                "cookie_issues": cookie_issues,
                "overall_score": (
                    "POOR" if missing_high else
                    "FAIR" if missing_medium else
                    "GOOD"
                ),
                "status": "success"
            }

            if logger:
                logger.add_log(
                    tool_name,
                    "WARNING" if missing_high else "SUCCESS",
                    f"Headers analysis done. Missing critical: {missing_high or 'none'}"
                )
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 6 — Simulate form interaction
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_simulate_form(url: str, form_data: str) -> str:
    """
    Isi dan submit form di halaman target menggunakan headless browser.
    Berguna buat: test login form, test search input dengan XSS payload,
    test upload form, atau interact dengan form multi-step.

    CATATAN: Tool ini butuh HITL approval karena mengirim data ke target.

    Args:
        url: URL halaman yang berisi form
        form_data: JSON string berisi {selector: value} pairs.
                   Contoh: '{"#username": "test", "#password": "test123"}'
                   Bisa juga: '{"input[name=q]": "<script>alert(1)</script>"}'
    Returns:
        JSON berisi: response URL setelah submit, title, visible text, dan
        apakah payload ter-reflect di response
    """
    logger = _logger()
    tool_name = "Browser Form Simulator"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    # HITL approval sebelum interact dengan form
    from checkpoint import require_approval
    approved = require_approval(
        action=f"Simulate form interaction di {url}",
        context=f"Form data: {form_data[:200]}",
        risk="medium",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval ditolak atau timeout."

    rate_limiter.wait(_domain_of(url))

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        try:
            await page.goto(url, wait_until="domcontentloaded")
            await page.wait_for_timeout(1000)

            try:
                fields = json.loads(form_data)
            except Exception:
                return json.dumps({"error": "form_data harus berupa JSON string valid"})

            # Isi tiap field
            for selector, value in fields.items():
                try:
                    await page.fill(selector, str(value))
                except Exception as e:
                    if logger:
                        logger.add_log(tool_name, "WARNING", f"Gagal isi field {selector}: {e}")

            # Submit — coba beberapa cara
            submitted = False
            for submit_selector in ['button[type=submit]', 'input[type=submit]', 'button:has-text("Login")', 'button:has-text("Submit")', 'button:has-text("Search")']:
                try:
                    await page.click(submit_selector)
                    submitted = True
                    break
                except Exception:
                    continue

            if not submitted:
                # Fallback: tekan Enter di field terakhir
                try:
                    last_selector = list(fields.keys())[-1]
                    await page.press(last_selector, "Enter")
                    submitted = True
                except Exception:
                    pass

            await page.wait_for_timeout(2000)

            final_url = page.url
            title = await page.title()
            body_text = await page.evaluate("() => document.body?.innerText?.slice(0, 1000) ?? ''")

            # Cek apakah payload ter-reflect (basic XSS indicator)
            xss_reflected = any(
                str(v) in body_text
                for v in fields.values()
                if "<" in str(v) or "'" in str(v)
            )

            result = {
                "original_url": url,
                "final_url": final_url,
                "redirected": url != final_url,
                "page_title": title,
                "visible_text_preview": body_text[:500],
                "form_submitted": submitted,
                "xss_payload_reflected": xss_reflected,
                "status": "success"
            }

            if logger:
                logger.add_log(
                    tool_name,
                    "WARNING" if xss_reflected else "SUCCESS",
                    f"Form submitted. Final URL: {final_url}. XSS reflected: {xss_reflected}"
                )
            return json.dumps(redact(result), indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 7 — Open redirect finder
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def browser_find_open_redirect(url: str) -> str:
    """
    Test semua link dan parameter di halaman target untuk open redirect vulnerability.
    Open redirect sering valid di H1 karena bisa dipake buat phishing dan
    bypass referrer-based access control.

    Args:
        url: URL halaman yang mau dites
    Returns:
        JSON berisi list parameter/URL yang vulnerable terhadap open redirect
    """
    logger = _logger()
    tool_name = "Browser Open Redirect Finder"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    rate_limiter.wait(_domain_of(url))

    # Canary domain yang lo kontrol — ganti ini ke domain/burp collaborator lo
    CANARY = "your-canary-domain.example"
    REDIRECT_PAYLOADS = [
        f"https://{CANARY}",
        f"//{CANARY}",
        f"https://{CANARY}%2F%2F",
        f"https://example.com@{CANARY}",
    ]

    # Parameter name yang sering dipake buat redirect
    REDIRECT_PARAMS = [
        "next", "redirect", "redirect_to", "redirect_url", "url",
        "return", "return_url", "returnTo", "goto", "go", "target",
        "destination", "redir", "r", "u", "link", "callback",
    ]

    async def _run():
        browser = await _get_browser()
        page, ctx = await _new_page(browser)
        findings = []

        try:
            await page.goto(url, wait_until="domcontentloaded")
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            for param in REDIRECT_PARAMS:
                if check_cancelled(logger):
                    break

                for payload in REDIRECT_PAYLOADS[:2]:  # Test 2 payload per param biar gak lama
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                    rate_limiter.wait(_domain_of(test_url))

                    try:
                        response = await page.goto(test_url, wait_until="domcontentloaded")
                        final_url = page.url

                        # Cek apakah ter-redirect ke canary domain
                        if CANARY in final_url or CANARY in (response.url if response else ""):
                            findings.append({
                                "parameter": param,
                                "test_url": test_url,
                                "redirected_to": final_url,
                                "severity": "MEDIUM",
                                "type": "Open Redirect"
                            })
                    except Exception:
                        continue

            result = {
                "url": url,
                "parameters_tested": REDIRECT_PARAMS,
                "payloads_used": REDIRECT_PAYLOADS[:2],
                "findings": findings,
                "vulnerable": len(findings) > 0,
                "note": f"Ganti CANARY_DOMAIN di playwright_tools.py ke domain yang lo kontrol buat hasil akurat.",
                "status": "success" if not check_cancelled(logger) else "cancelled"
            }

            if logger:
                logger.add_log(
                    tool_name,
                    "WARNING" if findings else "SUCCESS",
                    f"Open redirect test selesai. Findings: {len(findings)}"
                )
            return json.dumps(result, indent=2)

        except Exception as e:
            if logger:
                logger.add_log(tool_name, "ERROR", str(e))
            return json.dumps({"error": str(e)})
        finally:
            await ctx.close()

    return _run_async(_run())
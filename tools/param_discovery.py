import json
import time
from typing import Optional
from urllib.parse import urlparse, urlencode

from core.tool_transport import guarded_requests as requests
import urllib3
from core.tool_decorator import crewai_tool as tool

from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from core.rate_limiter import rate_limiter
from core.redact import redact
# 1. Taruh import proxy router di sthis men
from core.proxy_router import proxy_router
from core.auth_store import inject_into_session
from core.safety_kernel import SafetyViolation
from core.structured_contract import ToolErrorV1, ToolResultV1

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
}

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


def _auth_session(url: str):
    """Create a context-bound session and attach any operator auth state."""
    session = requests.Session()
    session.verify = True
    inject_into_session(session, _domain_of(url))
    return session


def _proxy_kwargs(proxy: Optional[dict]) -> dict:
    """Pass a proxy only when one was explicitly configured.

    Passing ``proxies=None`` through compatibility layers used to re-enable
    ambient HTTP(S)_PROXY handling in requests.  Direct local-lab traffic
    must remain direct and operator-configured proxy traffic must remain
    explicit.
    """
    return {"proxies": proxy} if proxy else {}


def _request_error(tool_name: str, url: str, exc: BaseException, *, phase: str) -> ToolErrorV1:
    if isinstance(exc, SafetyViolation):
        code = str(exc.reason_code or "tool_transport_error")
        retryable = code in {"tool_timeout", "tool_transport_error"}
    elif isinstance(exc, requests.exceptions.Timeout):
        code, retryable = "tool_timeout", True
    elif isinstance(exc, requests.exceptions.ProxyError):
        code, retryable = "tool_transport_error", True
    elif isinstance(exc, requests.exceptions.ConnectionError):
        code, retryable = "tool_transport_error", True
    elif isinstance(exc, requests.exceptions.RequestException):
        code, retryable = "tool_request_error", True
    else:
        code, retryable = "tool_execution_error", False
    return ToolErrorV1(
        code=code,
        message=f"{tool_name} {phase} failed: {type(exc).__name__}: {str(exc)[:500]}",
        retryable=retryable,
        details={
            "phase": phase,
            "target_url": url,
            "tool_name": tool_name,
            "error_type": type(exc).__name__,
        },
    )


def _failed_request_result(tool_name: str, url: str, error: ToolErrorV1) -> ToolResultV1:
    return ToolResultV1(
        tool_name=tool_name,
        category="recon",
        target=url,
        status="failed",
        summary=f"{tool_name} could not establish its baseline request.",
        errors=[error],
        metrics={
            "request_failures": 1,
            "baseline_request_failed": True,
            "transport_diagnostic": error.model_dump(mode="json"),
        },
    )


# ── Wordlists ─────────────────────────────────────────────────────────────────

COMMON_GET_PARAMS = [
    "token", "key", "api_key", "apikey", "secret", "password", "pass",
    "auth", "access_token", "refresh_token", "session", "csrf", "nonce",
    "id", "user_id", "uid", "user", "username", "email", "account",
    "profile_id", "member_id", "customer_id", "admin", "role",
    "next", "redirect", "return", "url", "goto", "target", "page",
    "ref", "referrer", "callback", "continue", "forward",
    "q", "query", "search", "s", "keyword", "term", "filter",
    "sort", "order", "limit", "offset", "page_size", "per_page",
    "format", "type", "category", "tag", "lang", "locale",
    "debug", "test", "dev", "mode", "verbose", "trace", "log",
    "preview", "draft", "version", "v", "env", "config",
    "file", "path", "dir", "folder", "document", "doc", "pdf",
    "image", "img", "src", "source", "load", "include",
    "fields", "expand", "include", "exclude", "embed", "select",
    "scope", "grant_type", "response_type", "client_id",
    "p", "post", "article", "slug", "feed", "attachment_id",
    "cat", "tag_id", "author", "m", "year", "month",
    "action", "module", "controller", "view", "template",
    "cmd", "exec", "command", "op", "do", "func",
    "data", "value", "input", "output", "name", "title",
    "content", "body", "message", "text", "info", "detail",
    "status", "state", "code", "error", "success",
]

COMMON_POST_PARAMS = [
    "username", "password", "email", "user", "pass", "login",
    "name", "first_name", "last_name", "phone", "address",
    "message", "content", "body", "text", "comment",
    "title", "subject", "description", "notes",
    "token", "csrf_token", "nonce", "auth_token",
    "file", "upload", "attachment", "image",
    "action", "type", "method", "format",
    "id", "user_id", "account_id", "record_id",
    "data", "payload", "json", "xml",
    "redirect_url", "return_url", "next",
    "code", "otp", "pin", "verification_code",
    "old_password", "new_password", "confirm_password",
    "search", "query", "q", "filter",
    "page", "limit", "offset", "sort",
]

TECH_SPECIFIC = {
    "php": ["phpMyAdmin", "PHPSESSID", "php_errormsg"],
    "wordpress": ["p", "page_id", "cat", "m", "paged", "attachment_id"],
    "django": ["csrfmiddlewaretoken", "next", "format"],
    "laravel": ["_token", "_method", "remember"],
    "spring": ["_csrf", "redirect", "spring_security_remember_me_cookie"],
    "graphql": ["query", "mutation", "variables", "operationName"],
    "rest_api": ["fields", "expand", "include", "filter", "sort", "page", "per_page"],
}


def _run_arjun_discovery(url: str, logger) -> list:
    """Run arjun for parameter discovery."""
    from core.tool_transport import guarded_subprocess as subprocess
    import tempfile
    import os

    tool_name = "Arjun Parameter Discovery"
    output_file = ""

    try:
        # Create temp output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name

        # Run arjun
        cmd = [
            "arjun",
            "-u", url,
            "-o", output_file,
            "-q",  # Quiet mode
            "--timeout", "10",
            "--threads", "5",
        ]

        # Apply stealth mode
        if os.environ.get("STEALTH_MODE", "0") == "1":
            cmd.extend(["--delay", "1"])

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,  # 3 minute timeout
        )

        # Parse arjun output
        params = []
        if output_file and os.path.exists(output_file):
            try:
                import json
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        params = data
                    elif isinstance(data, dict) and "params" in data:
                        params = data["params"]
            except Exception:
                pass
            finally:
                try:
                    os.unlink(output_file)
                except:
                    pass

        if params:
            if logger:
                logger.add_log(tool_name, "SUCCESS", f"Arjun found {len(params)} parameters")
        
        return params

    except subprocess.TimeoutExpired:
        if output_file and os.path.exists(output_file):
            os.unlink(output_file)
        if logger:
            logger.add_log(tool_name, "WARNING", "Arjun timed out")
        return []
    except FileNotFoundError:
        if logger:
            logger.add_log(tool_name, "WARNING", "Arjun not found")
        return []
    except Exception as e:
        if logger:
            logger.add_log(tool_name, "WARNING", f"Arjun error: {str(e)[:100]}")
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — GET Parameter Discovery
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def param_discovery_get(url: str, tech_stack: str = "") -> str:
    """
    Discover hidden GET parameters di endpoint target using wordlist bruteforce dan rotasi proxy.
    """
    logger = _logger()
    tool_name = "GET Parameter Discovery"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"GET parameter discovery on {url}",
        context=f"Bruteforce {len(COMMON_GET_PARAMS)} common parameters. Tech stack: {tech_stack or 'unknown'}",
        risk="read_only",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval rejected atau timeout."

    SESSION = _auth_session(url)
    domain = _domain_of(url)

    wordlist = list(COMMON_GET_PARAMS)
    if tech_stack and tech_stack.lower() in TECH_SPECIFIC:
        tech_params = TECH_SPECIFIC[tech_stack.lower()]
        wordlist = tech_params + [p for p in wordlist if p not in tech_params]

    request_errors: list[ToolErrorV1] = []
    failed_requests = 0

    # ── Baseline request through the guarded transport ───────────────────────
    rate_limiter.wait(domain)
    current_proxy = proxy_router.get_proxy()
    try:
        baseline = SESSION.get(url, headers=HEADERS, **_proxy_kwargs(current_proxy), timeout=5)
        baseline_length = len(baseline.text)
        baseline_status = baseline.status_code
    except Exception as exc:
        if current_proxy:
            proxy_router.remove_dead_proxy(current_proxy)
        return _failed_request_result(
            tool_name,
            url,
            _request_error(tool_name, url, exc, phase="baseline"),
        )

    if logger:
        logger.add_log(tool_name, "PROCESSING", f"Baseline: status={baseline_status}, length={baseline_length}. Testing {len(wordlist)} params...")

    discovered = []
    tested = 0
    batch_size = 5
    interesting_batches = []

    # ── Bruteforce in batches with Proxy ─────────────────────────────────────
    for i in range(0, len(wordlist), batch_size):
        if check_cancelled(logger):
            break

        batch = wordlist[i:i+batch_size]
        batch_params = {p: f"nexus_test_{p}_1337" for p in batch}
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{urlencode(batch_params)}"

        rate_limiter.wait(domain)
        current_proxy = proxy_router.get_proxy()
        try:
            resp = SESSION.get(test_url, headers=HEADERS, **_proxy_kwargs(current_proxy), timeout=4)
            tested += 1

            length_diff = abs(len(resp.text) - baseline_length)
            status_diff = resp.status_code != baseline_status

            if length_diff > 100 or status_diff:
                interesting_batches.append(batch)

        except Exception as exc:
            if current_proxy:
                proxy_router.remove_dead_proxy(current_proxy)
            failed_requests += 1
            if len(request_errors) < 10:
                request_errors.append(_request_error(tool_name, test_url, exc, phase="batch"))
            continue

    # ── Individual test for batch that interesting with Proxy ───────────────
    for batch in interesting_batches:
        for param in batch:
            if check_cancelled(logger):
                break

            test_value = f"nexus_test_1337"
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={test_value}"

            rate_limiter.wait(domain)
            current_proxy = proxy_router.get_proxy()
            try:
                resp = SESSION.get(test_url, headers=HEADERS, **_proxy_kwargs(current_proxy), timeout=4)
                tested += 1

                resp_length = len(resp.text)
                length_diff = abs(resp_length - baseline_length)
                status_diff = resp.status_code != baseline_status

                evidence = []

                if length_diff > 150:
                    evidence.append(f"Response length berbeda: {baseline_length} → {resp_length} (diff: {length_diff})")
                if status_diff:
                    evidence.append(f"Status code berbeda: {baseline_status} → {resp.status_code}")
                if param.lower() in resp.text.lower() and param.lower() not in baseline.text.lower():
                    evidence.append(f"Parameter name '{param}' ter-reflect di response")
                if resp.status_code in (400, 422):
                    evidence.append(f"Status {resp.status_code} = server recognizes parameter ini")

                if evidence:
                    discovered.append({
                        "parameter": param,
                        "evidence": evidence,
                        "baseline_status": baseline_status,
                        "found_status": resp.status_code,
                        "baseline_length": baseline_length,
                        "found_length": resp_length,
                        "test_url": test_url,
                    })

            except Exception as exc:
                if current_proxy:
                    proxy_router.remove_dead_proxy(current_proxy)
                failed_requests += 1
                if len(request_errors) < 10:
                    request_errors.append(_request_error(tool_name, test_url, exc, phase="individual"))
                continue

    result = {
        "url": url,
        "tech_stack": tech_stack or "unknown",
        "total_params_tested": tested,
        "discovered_params": discovered,
        "total_discovered": len(discovered),
        "wordlist_size": len(wordlist),
        "status": (
            "cancelled" if check_cancelled(logger)
            else "partial" if request_errors
            else "succeeded"
        ),
        "request_failures": failed_requests,
        "request_error_samples": [item.model_dump(mode="json") for item in request_errors],
    }

    if logger:
        logger.add_log(
            tool_name,
            "WARNING" if request_errors else "SUCCESS" if discovered else "INFO",
            f"Discovery selesai. {tested} params tested, {len(discovered)} discovered, {failed_requests} request failures.",
        )

    # ── ARJUN CONFIRMATION STEP ───────────────────────────────────────────────
    if logger:
        logger.add_log(tool_name, "PROCESSING", "Running arjun for additional parameter discovery")
    
    arjun_result = _run_arjun_discovery(url, logger)
    if arjun_result:
        # Merge arjun findings
        existing_params = {d["parameter"] for d in discovered}
        for param in arjun_result:
            if param not in existing_params:
                discovered.append({
                    "parameter": param,
                    "evidence": ["Discovered by arjun"],
                    "source": "arjun",
                })
        
        result["discovered_params"] = discovered
        result["total_discovered"] = len(discovered)
        result["arjun_discovered"] = len(arjun_result)

    return ToolResultV1(
        tool_name=tool_name,
        category="recon",
        target=url,
        status=result["status"],
        summary=f"GET parameter discovery completed with {tested} tested requests and {failed_requests} failures.",
        metrics=redact(result),
        errors=request_errors,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — POST Parameter Discovery
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def param_discovery_post(url: str, content_type: str = "application/x-www-form-urlencoded") -> str:
    """
    Discover hidden POST body parameters di endpoint target with perlindungan proxy.
    """
    logger = _logger()
    tool_name = "POST Parameter Discovery"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"POST parameter discovery on {url}",
        context=f"Test {len(COMMON_POST_PARAMS)} common POST params with content-type: {content_type}",
        risk="low",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval rejected atau timeout."

    SESSION = _auth_session(url)
    domain = _domain_of(url)
    use_json = "json" in content_type.lower()
    request_errors: list[ToolErrorV1] = []
    failed_requests = 0

    # Baseline POST request through the guarded transport
    rate_limiter.wait(domain)
    current_proxy = proxy_router.get_proxy()
    try:
        if use_json:
            baseline = SESSION.post(url, json={}, headers={**HEADERS, "Content-Type": "application/json"}, **_proxy_kwargs(current_proxy), timeout=5)
        else:
            baseline = SESSION.post(url, data={}, headers=HEADERS, **_proxy_kwargs(current_proxy), timeout=5)
        baseline_length = len(baseline.text)
        baseline_status = baseline.status_code
    except Exception as exc:
        if current_proxy:
            proxy_router.remove_dead_proxy(current_proxy)
        return _failed_request_result(
            tool_name,
            url,
            _request_error(tool_name, url, exc, phase="baseline"),
        )

    discovered = []
    tested = 0

    for param in COMMON_POST_PARAMS:
        if check_cancelled(logger):
            break

        rate_limiter.wait(domain)
        current_proxy = proxy_router.get_proxy()
        try:
            test_value = "nexus_test_1337"
            if use_json:
                resp = SESSION.post(
                    url,
                    json={param: test_value},
                    headers={**HEADERS, "Content-Type": "application/json"},
                    **_proxy_kwargs(current_proxy),
                    timeout=4
                )
            else:
                resp = SESSION.post(
                    url,
                    data={param: test_value},
                    headers=HEADERS,
                    **_proxy_kwargs(current_proxy),
                    timeout=4
                )
            tested += 1

            resp_length = len(resp.text)
            length_diff = abs(resp_length - baseline_length)
            evidence = []

            if length_diff > 150:
                evidence.append(f"Response length berbeda: {baseline_length} → {resp_length}")
            if resp.status_code != baseline_status:
                evidence.append(f"Status berbeda: {baseline_status} → {resp.status_code}")
            if param.lower() in resp.text.lower() and param.lower() not in baseline.text.lower():
                evidence.append(f"Parameter '{param}' ter-reflect di response")
            if resp.status_code in (400, 422):
                evidence.append(f"Status {resp.status_code} = server recognizes parameter ini")

            if evidence:
                discovered.append({
                    "parameter": param,
                    "content_type": "json" if use_json else "form",
                    "evidence": evidence,
                    "baseline_status": baseline_status,
                    "found_status": resp.status_code,
                })

        except Exception as exc:
            if current_proxy:
                proxy_router.remove_dead_proxy(current_proxy)
            failed_requests += 1
            if len(request_errors) < 10:
                request_errors.append(_request_error(tool_name, url, exc, phase="parameter"))
            continue

    result = {
        "url": url,
        "method": "POST",
        "content_type": "json" if use_json else "form",
        "total_tested": tested,
        "discovered_params": discovered,
        "total_discovered": len(discovered),
        "status": (
            "cancelled" if check_cancelled(logger)
            else "partial" if request_errors
            else "succeeded"
        ),
        "request_failures": failed_requests,
        "request_error_samples": [item.model_dump(mode="json") for item in request_errors],
    }

    if logger:
        logger.add_log(
            tool_name,
            "WARNING" if request_errors else "SUCCESS" if discovered else "INFO",
            f"POST discovery selesai. {tested} tested, {len(discovered)} discovered, {failed_requests} request failures.",
        )
    return ToolResultV1(
        tool_name=tool_name,
        category="recon",
        target=url,
        status=result["status"],
        summary=f"POST parameter discovery completed with {tested} tested requests and {failed_requests} failures.",
        metrics=redact(result),
        errors=request_errors,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — Header Parameter Discovery
# ═══════════════════════════════════════════════════════════════════════════════

@tool
def param_discovery_headers(url: str) -> str:
    """
    Discover custom HTTP headers that received server with rotasi proxy acak.
    """
    logger = _logger()
    tool_name = "Header Parameter Discovery"

    if check_cancelled(logger):
        return "DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"Header parameter discovery on {url}",
        context="Test read-only diagnostic headers against the target baseline.",
        risk="read_only",
        exec_logger=logger,
    )
    if not approved:
        return "DIBATALKAN: approval rejected atau timeout."

    INTERESTING_HEADERS = [
        "X-Debug", "X-Debug-Mode", "X-Dev-Mode", "X-Internal",
        "X-Test", "X-Admin", "X-Forwarded-User",
        "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
        "X-Forwarded-For", "X-Real-IP", "X-Remote-IP",
        "X-Originating-IP", "X-Remote-Addr",
        "X-Auth-Token", "X-API-Key", "Authorization",
        "X-User-ID", "X-User-Role", "X-Admin-Token",
        "X-Bypass-Auth", "X-Internal-Auth",
        "X-Forwarded-Host", "X-Host", "X-Custom-Host",
        "X-Override-URL", "X-Forwarded-Path",
        "X-Feature-Flag", "X-Beta", "X-Preview",
        "X-Version", "X-API-Version",
        "X-CSRF-Token", "X-Requested-With",
        "X-HTTP-Method-Override", "X-Method-Override",
    ]

    SESSION = _auth_session(url)
    domain = _domain_of(url)
    request_errors: list[ToolErrorV1] = []
    failed_requests = 0

    # Baseline through the guarded transport
    rate_limiter.wait(domain)
    current_proxy = proxy_router.get_proxy()
    try:
        baseline = SESSION.get(url, headers=HEADERS, **_proxy_kwargs(current_proxy), timeout=5)
        baseline_length = len(baseline.text)
        baseline_status = baseline.status_code
    except Exception as exc:
        if current_proxy:
            proxy_router.remove_dead_proxy(current_proxy)
        return _failed_request_result(
            tool_name,
            url,
            _request_error(tool_name, url, exc, phase="baseline"),
        )

    interesting_headers = []
    tested = 0

    for header in INTERESTING_HEADERS:
        if check_cancelled(logger):
            break

        rate_limiter.wait(domain)
        current_proxy = proxy_router.get_proxy()
        try:
            test_headers = {**HEADERS, header: "nexus-test-1337"}
            resp = SESSION.get(url, headers=test_headers, **_proxy_kwargs(current_proxy), timeout=4)
            tested += 1

            length_diff = abs(len(resp.text) - baseline_length)
            status_diff = resp.status_code != baseline_status

            if length_diff > 100 or status_diff:
                interesting_headers.append({
                    "header": header,
                    "test_value": "nexus-test-1337",
                    "baseline_status": baseline_status,
                    "found_status": resp.status_code,
                    "length_diff": length_diff,
                    "evidence": f"Response berbeda: status {baseline_status}→{resp.status_code}, length diff {length_diff}",
                })

        except Exception as exc:
            if current_proxy:
                proxy_router.remove_dead_proxy(current_proxy)
            failed_requests += 1
            if len(request_errors) < 10:
                request_errors.append(_request_error(tool_name, url, exc, phase="header"))
            continue

    result = {
        "url": url,
        "total_tested": tested,
        "interesting_headers": interesting_headers,
        "total_found": len(interesting_headers),
        "status": (
            "cancelled" if check_cancelled(logger)
            else "partial" if request_errors
            else "succeeded"
        ),
        "request_failures": failed_requests,
        "request_error_samples": [item.model_dump(mode="json") for item in request_errors],
    }

    if logger:
        logger.add_log(
            tool_name,
            "WARNING" if request_errors or interesting_headers else "INFO",
            f"Header discovery selesai. {tested} tested, {len(interesting_headers)} interesting, {failed_requests} request failures.",
        )
    return ToolResultV1(
        tool_name=tool_name,
        category="recon",
        target=url,
        status=result["status"],
        summary=f"Header parameter discovery completed with {tested} tested requests and {failed_requests} failures.",
        metrics=redact(result),
        errors=request_errors,
    )

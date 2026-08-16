"""Mitmproxy addon: passive scan like Burp — capture + analyze headers/cookies."""

from mitmproxy import http
import json

FINDINGS = []

def response(flow: http.HTTPFlow):
    req, resp = flow.request, flow.response
    url = req.pretty_url
    issues = []
    # Passive checks
    headers = {k.lower(): v for k, v in resp.headers.items()}
    if "content-security-policy" not in headers:
        issues.append("Missing CSP")
    if "strict-transport-security" not in headers:
        issues.append("Missing HSTS")
    if "x-frame-options" not in headers:
        issues.append("Missing X-Frame-Options")
    cookies = resp.headers.get("set-cookie", "")
    if cookies and "httponly" not in cookies.lower():
        issues.append("Cookie missing HttpOnly")
    if "token=" in req.url.lower() or "key=" in req.url.lower():
        issues.append("Sensitive param in URL")
    if issues:
        FINDINGS.append({"url": url, "issues": issues, "status": resp.status_code})

def done():
    open("/tmp/mitm_findings.json", "w").write(json.dumps(FINDINGS[:100], indent=2))

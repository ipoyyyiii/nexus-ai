import requests
import json
import time
from langchain.tools import tool
from cancellation import check_cancelled
from checkpoint import require_approval
from custom_tools import exec_logger
from rate_limiter import rate_limiter
from auth_store import get_auth_kwargs

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

            # Coba POST dengan query kosong dulu
            resp = requests.post(
                url,
                json={"query": "{ __typename }"},
                headers={"Content-Type": "application/json"},
                **auth_kw,
                timeout=5,
                verify=False,
            )

            # GraphQL endpoint biasanya return JSON dengan key "data" atau "errors"
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
        resp = requests.post(
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

            # Cari field yang suspicious
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
    """Test batch query buat bypass rate limiting."""
    try:
        rate_limiter.wait(_domain_of(endpoint))

        # Kirim 10 query sekaligus dalam satu request
        batch = [{"query": "{ __typename }"}] * 10

        resp = requests.post(
            endpoint,
            json=batch,
            headers={"Content-Type": "application/json"},
            timeout=10,
            verify=False,
        )

        if resp.status_code == 200:
            try:
                data = resp.json()
                # Kalau response-nya array = batch query diterima
                if isinstance(data, list) and len(data) > 1:
                    return {
                        "vulnerable": True,
                        "severity": "Medium",
                        "detail": f"Server menerima {len(data)} query sekaligus dalam 1 request — bisa dieksploitasi buat bypass rate limiting pada mutation login/register"
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
        resp = requests.post(
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
                "detail": f"Server memproses nested query dalam {duration:.1f}s — tidak ada query depth limiting, rentan DoS"
            }
        elif resp.status_code == 200:
            try:
                data = resp.json()
                # Kalau gak ada error soal depth = depth limit gak ada
                if "errors" not in data:
                    return {
                        "vulnerable": True,
                        "severity": "Low",
                        "detail": "Tidak ada query depth limiting terdeteksi — nested query diterima tanpa pembatasan"
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

        # Query field yang salah sengaja
        resp = requests.post(
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
                "detail": f"Server memberikan field suggestion pada error — bisa dieksploitasi buat enumerate schema tanpa introspection",
                "error_sample": str(data.get("errors", ""))[:300]
            }

    except Exception:
        pass

    return {"vulnerable": False}


def _test_idor(endpoint: str, query_type: str = "Query") -> dict:
    """Test basic IDOR via GraphQL ID manipulation."""
    findings = []

    # Common query patterns yang sering ada
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
            resp = requests.post(
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
                        "detail": "Query berhasil return data tanpa autentikasi — perlu manual verify apakah data milik user lain bisa diakses"
                    })
                    exec_logger.add_log("GraphQL Tester", "WARNING", f"Potential IDOR: {query[:50]}")
                    break  # Cukup satu finding, sisanya manual

        except Exception:
            pass

    return findings


@tool("graphql_tester")
def graphql_tester(target_url: str) -> str:
    """
    Menguji implementasi GraphQL pada target untuk menemukan kerentanan:
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
        action=f"GraphQL security testing pada {target_url}",
        context="Test: introspection, batch query, nested DoS, field suggestion, IDOR",
        risk="medium",
        exec_logger=exec_logger,
    )
    if not approved:
        return "TEST DIBATALKAN: human-in-the-loop approval ditolak atau timeout."

    exec_logger.add_log("GraphQL Tester", "START", f"Memulai GraphQL testing pada {target_url}")

    # Inject auth session jika ada
    from urllib.parse import urlparse
    domain = urlparse(target_url).netloc.split(":")[0].lower()
    auth_kwargs = get_auth_kwargs(domain)

    # Step 1: Detect endpoint
    exec_logger.add_log("GraphQL Tester", "PROCESSING", "Detecting GraphQL endpoints")
    endpoints = _detect_graphql(target_url)

    if not endpoints:
        return f"[+] Tidak ditemukan GraphQL endpoint pada {target_url}. Target kemungkinan pake REST API."

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
        output += "\n[+] Tidak ditemukan kerentanan GraphQL yang obvious. GraphQL implementation tampak cukup hardened.\n"

    output += "\n⚠️  Manual verification tetap diperlukan untuk konfirmasi semua findings.\n"

    return output
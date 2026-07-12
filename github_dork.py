import requests
import os
import time
from langchain.tools import tool
from cancellation import check_cancelled
from custom_tools import exec_logger
from redact import redact
from auth_store import get_auth_kwargs

DORK_QUERIES = [
    'password',
    'secret',
    'api_key',
    'DB_PASSWORD',
    'private_key',
    'access_token',
    'client_secret',
    'SMTP_PASSWORD',
    'database_url',
    'AWS_SECRET',
]

@tool("github_dorking")
def github_dorking(target_org: str) -> str:
    """
    Melakukan GitHub dorking untuk menemukan secret, credential, API key,
    atau konfigurasi sensitif yang tidak sengaja ter-push ke repo publik
    milik organisasi/developer target.
    
    Args:
        target_org: nama organisasi atau username GitHub target (contoh: 'google' atau 'john-dev')
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        return "[-] GITHUB_TOKEN belum di-set di .env. Tambahkan personal access token GitHub (scope: public_repo) untuk menggunakan tool ini."

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }

    org = target_org.strip().lstrip("@")
    exec_logger.add_log("GitHub Dorking", "START", f"Memulai dorking untuk org/user: {org}")

    all_findings = []

    for query_keyword in DORK_QUERIES:
        if check_cancelled(exec_logger):
            break

        search_query = f"{query_keyword} org:{org}"

        try:
            exec_logger.add_log("GitHub Dorking", "PROCESSING", f"Searching: {search_query}")

            resp = requests.get(
                "https://api.github.com/search/code",
                headers=headers,
                params={
                    "q": search_query,
                    "per_page": 5,  # Batasi biar gak kena secondary rate limit
                },
                timeout=10,
            )

            # GitHub rate limit — tunggu kalau kena
            if resp.status_code == 403:
                reset_time = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset_time - int(time.time()), 10)
                exec_logger.add_log("GitHub Dorking", "WARNING", f"Rate limited, tunggu {wait}s")
                time.sleep(min(wait, 30))  # Max tunggu 30 detik
                continue

            if resp.status_code != 200:
                exec_logger.add_log("GitHub Dorking", "WARNING", f"Query '{query_keyword}' gagal: {resp.status_code}")
                continue

            data = resp.json()
            items = data.get("items", [])

            for item in items:
                finding = {
                    "keyword": query_keyword,
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "file": item.get("path", ""),
                    "url": item.get("html_url", ""),
                    "visibility": item.get("repository", {}).get("visibility", "public"),
                }
                all_findings.append(finding)
                exec_logger.add_log(
                    "GitHub Dorking", "WARNING",
                    redact(f"Potential secret found: {finding['keyword']} in {finding['repo']}/{finding['file']}")
                )

            # Jeda antar query biar gak kena secondary rate limit GitHub
            time.sleep(2)

        except requests.Timeout:
            exec_logger.add_log("GitHub Dorking", "WARNING", f"Timeout untuk query: {query_keyword}")
            continue
        except Exception as e:
            exec_logger.add_log("GitHub Dorking", "ERROR", f"Query error: {str(e)}")
            continue

    # Build output
    if not all_findings:
        exec_logger.add_log("GitHub Dorking", "SUCCESS", "Tidak ada secret yang ditemukan")
        return f"[+] GitHub dorking selesai untuk {org}. Tidak ada credential/secret yang ter-expose di repo publik."

    exec_logger.add_log("GitHub Dorking", "SUCCESS", f"Total findings: {len(all_findings)}")

    output = f"=== GITHUB DORKING RESULTS FOR {org} ===\n"
    output += f"Total potential findings: {len(all_findings)}\n\n"
    output += "⚠️  MANUAL VERIFICATION REQUIRED — ini hasil search, bukan confirmed vuln.\n\n"

    # Group by keyword
    by_keyword = {}
    for f in all_findings:
        by_keyword.setdefault(f["keyword"], []).append(f)

    for keyword, items in by_keyword.items():
        output += f"[{keyword.upper()}] — {len(items)} file\n"
        for item in items:
            output += f"  - {item['repo']}/{item['file']}\n"
            output += f"    🔗 {item['url']}\n"

    return output
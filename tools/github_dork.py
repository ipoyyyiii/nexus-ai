import requests
import os
import time
from langchain.tools import tool
from core.cancellation import check_cancelled
from tools.custom_tools import exec_logger
from core.redact import redact
from core.auth_store import get_auth_kwargs

DORK_QUERIES = [
    # ── CREDENTIALS ───────────────────────────────────────────────────────────
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
    'AWS_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'GITHUB_TOKEN',
    'GITLAB_TOKEN',
    'HEROKU_API_KEY',
    'STRIPE_SECRET_KEY',
    'TWILIO_AUTH_TOKEN',
    'SENDGRID_API_KEY',
    'MAILGUN_API_KEY',
    'SLACK_TOKEN',
    'SLACK_WEBHOOK',
    'DISCORD_TOKEN',
    'TELEGRAM_TOKEN',

    # ── CLOUD CREDENTIALS ─────────────────────────────────────────────────────
    'GOOGLE_API_KEY',
    'GOOGLE_CLIENT_SECRET',
    'AZURE_CLIENT_SECRET',
    'AZURE_STORAGE_KEY',
    'DIGITALOCEAN_TOKEN',
    'LINODE_API_KEY',
    'VULTR_API_KEY',
    'CLOUDFLARE_API_KEY',
    'CLOUDFLARE_ZONE_TOKEN',

    # ── DATABASE ──────────────────────────────────────────────────────────────
    'DATABASE_URL',
    'DB_HOST',
    'DB_USER',
    'DB_PASS',
    'MYSQL_PWD',
    'POSTGRES_PASSWORD',
    'REDIS_PASSWORD',
    'MONGO_PASSWORD',
    'MONGODB_URI',

    # ── JWT / TOKENS ──────────────────────────────────────────────────────────
    'JWT_SECRET',
    'jwt_secret',
    'SESSION_SECRET',
    'ENCRYPTION_KEY',
    'SIGNING_KEY',
    'TOKEN_SECRET',

    # ── CONFIG FILES ──────────────────────────────────────────────────────────
    'filename:.env',
    'filename:.env.local',
    'filename:.env.production',
    'filename:config.json',
    'filename:config.yml',
    'filename:config.yaml',
    'filename:credentials.json',
    'filename:service-account.json',
    'filename:.htpasswd',
    'filename:.htaccess',
    'filename:wp-config.php',
    'filename:database.yml',
    'filename:secrets.yml',

    # ── PRIVATE KEYS ──────────────────────────────────────────────────────────
    'BEGIN RSA PRIVATE KEY',
    'BEGIN DSA PRIVATE KEY',
    'BEGIN EC PRIVATE KEY',
    'BEGIN OPENSSH PRIVATE KEY',
    'BEGIN PGP PRIVATE KEY BLOCK',

    # ── INTERNAL URLs ─────────────────────────────────────────────────────────
    'hostname:localhost',
    'hostname:127.0.0.1',
    'hostname:192.168.',
    'hostname:10.0.',
    'hostname:172.16.',
    'url:staging.',
    'url:dev.',
    'url:test.',
    'url:internal.',
    'url:admin.',

    # ── HARDCODED SECRETS ─────────────────────────────────────────────────────
    'AKIA',
    'SG.',
    'sk_live_',
    'pk_live_',
    'sk_test_',
    'ghp_',
    'glpat-',
    'xox[baprs]-',
    'eyJ',
]

@tool("github_dorking")
def github_dorking(target_org: str) -> str:
    """
    Melakukan GitHub dorking untuk menemukan secret, credential, API key,
    atau konfigurasi sensitif yang not sengaja ter-push ke repo publik
    milik organisasi/developer target.
    
    Args:
        target_org: nama organisasi atau username GitHub target (contoh: 'google' atau 'john-dev')
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        return "[-] GITHUB_TOKEN not yet di-set di .env. Tambahkan personal access token GitHub (scope: public_repo) untuk using tool ini."

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }

    org = target_org.strip().lstrip("@")
    exec_logger.add_log("GitHub Dorking", "START", f"Starting dorking untuk org/user: {org}")

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
                exec_logger.add_log("GitHub Dorking", "WARNING", f"Query '{query_keyword}' failed: {resp.status_code}")
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
        exec_logger.add_log("GitHub Dorking", "SUCCESS", "Not ada secret yang found")
        return f"[+] GitHub dorking selesai untuk {org}. Not ada credential/secret yang ter-expose di repo publik."

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
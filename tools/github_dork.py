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

def _domain_to_org_candidates(domain_or_org: str) -> list:
    """Derive GitHub org candidates from domain or direct org input."""
    raw = domain_or_org.strip().lower()
    # Strip URL parts if given full url
    raw = raw.replace("https://", "").replace("http://", "").split("/")[0]
    candidates = []
    # Direct org/user as-is
    candidates.append(raw)
    # Domain-derived: example.co.id -> example, example-co-id, exampleid
    base = raw.split(".")[0]
    if "." in raw:
        candidates.append(base)
        candidates.append(raw.replace(".", "-"))
        candidates.append(raw.replace(".", ""))
        # Second-level for co.id style: example.co.id -> example
        parts = raw.split(".")
        if len(parts) >= 3:
            candidates.append(parts[0])
    # Dedupe preserve order
    seen = set()
    out = []
    for c in candidates:
        if c and c not in seen and len(c) >= 2:
            seen.add(c)
            out.append(c)
    return out[:4]

@tool("github_dorking")
def github_dorking(target_org: str) -> str:
    """
    Perform GitHub dorking to find secret, credential, API key,
    or sensitive configuration that was accidentally pushed to public repo
    milik organisasi/developer target.
    
    Args:
        target_org: domain (example.com) atau nama organisasi/username GitHub target (contoh: 'google' atau 'john-dev')
                    Akan auto-map domain -> org candidates dan dual query.
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        return "[-] GITHUB_TOKEN not yet set di .env. add a personal access token GitHub (scope: public_repo) to use this tool."

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }

    candidates = _domain_to_org_candidates(target_org)
    org = candidates[0]
    exec_logger.add_log("GitHub Dorking", "START", f"Starting dorking for candidates: {candidates}")

    all_findings = []
    seen_urls = set()

    for query_keyword in DORK_QUERIES:
        if check_cancelled(exec_logger):
            break

        # Dual query: org:candidate + fallback freetext domain
        queries = [f"{query_keyword} org:{c}" for c in candidates[:2]]
        if "." in target_org:
            queries.append(f'"{target_org.strip().lower()}" {query_keyword}')
        for search_query in queries:
            if search_query in seen_urls:
                continue
            seen_urls.add(search_query)

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
            exec_logger.add_log("GitHub Dorking", "WARNING", f"Timeout for query: {query_keyword}")
            continue
        except Exception as e:
            exec_logger.add_log("GitHub Dorking", "ERROR", f"Query error: {str(e)}")
            continue

    # Build output
    if not all_findings:
        exec_logger.add_log("GitHub Dorking", "SUCCESS", "No secrets found")
        return f"[+] GitHub dorking completed for {org}. No credentials/secrets exposed in public repo."

    exec_logger.add_log("GitHub Dorking", "SUCCESS", f"Total findings: {len(all_findings)}")

    output = f"=== GITHUB DORKING RESULTS FOR {org} ===\n"
    output += f"Total potential findings: {len(all_findings)}\n\n"
    output += "⚠️  MANUAL VERIFICATION REQUIRED — this is search, not a confirmed vulnerability.\n\n"

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
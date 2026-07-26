import fnmatch
from urllib.parse import urlparse
from typing import Tuple
from supabase import Client


def extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc.split(":")[0].lower()


def validate_target(url: str, supabase: Client) -> Tuple[bool, str]:
    """
    Return (allowed: bool, reason: str)

    Logic:
    - Domain must match at least one rule 'allow'
    - Kalau match rule 'deny' manapun -> langsung rejected, deny menang atas allow
    - Kalau scope_rules kosong sama sekali -> rejected (fail-safe, bukan fail-open)
    """
    domain = extract_domain(url)
    if not domain:
        return False, f"Failed extract domain from URL: {url}"

    try:
        res = supabase.table("scope_rules").select("*").execute()
        rules = res.data or []
    except Exception as e:
        return False, f"Failed akses tabel scope_rules: {e}"

    if not rules:
        return False, (
            "Scope rules table is empty. Add at least one allow-rule "
            "dulu senot yet can jalanin pentest (lihat docstring scope.py)."
        )

    matched_allow = None
    matched_deny = None

    for rule in rules:
        pattern = (rule.get("pattern") or "").lower().strip()
        rtype = rule.get("rule_type")
        if not pattern:
            continue
        if fnmatch.fnmatch(domain, pattern):
            if rtype == "deny":
                matched_deny = rule
            elif rtype == "allow":
                matched_allow = rule

    if matched_deny:
        return False, (
            f"Domain '{domain}' match DENY rule '{matched_deny['pattern']}' "
            f"({matched_deny.get('notes') or 'tanpa catatan'}). Deny selalu menang atas allow."
        )

    if matched_allow:
        return True, f"Domain '{domain}' diizinkan via rule '{matched_allow['pattern']}' (program: {matched_allow.get('program_name')})"

    return False, f"Domain '{domain}' not match rule allow manapun di scope_rules. Tolak by default."
import os
from dotenv import load_dotenv
from crewai import Agent, Task, Crew
from custom_tools import (
    baca_log_burp, tembak_payload, recon_target,
    scan_sql_injection, detect_xss_csrf, analyze_ssl_tls,
    enumerate_dns_subdomains, analyze_password_strength,
    test_api_security, scan_lfi_rfi, test_header_injection,
    get_execution_logs, clear_execution_logs
)
from playwright_tools import (
    browser_screenshot, browser_extract_surface,
    browser_intercept_requests, browser_extract_js_secrets,
    browser_check_security_headers, browser_simulate_form,
    browser_find_open_redirect,
)
from ssrf_idor_tools import scan_ssrf, scan_idor
from param_discovery import param_discovery_get, param_discovery_post, param_discovery_headers
from js_analysis import analyze_js_deep
from model_registry import build_llm, chain_summary
from scope import validate_target

# ==========================================
# 1. LOAD ENV
# ==========================================
load_dotenv()

# ==========================================
# 2. SCOPE VALIDATION (CLI mode)
# Buat CLI kita pakai simple input validation —
# scope_rules Supabase tetap bisa dicek kalau
# SUPABASE_URL & SUPABASE_KEY di-set di .env,
# kalau gak ada skip warning aja.
# ==========================================
def check_scope_cli(url: str) -> bool:
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_KEY")
    if not supabase_url or not supabase_key:
        print("⚠️  SUPABASE tidak di-set. Scope validation dilewati (CLI mode).")
        print("   Pastikan lo punya izin untuk test target ini!\n")
        return True
    try:
        from supabase import create_client
        sb = create_client(supabase_url, supabase_key)
        allowed, reason = validate_target(url, sb)
        if not allowed:
            print(f"\n❌ TARGET DITOLAK SCOPE: {reason}")
            print("   Tambah scope rule dulu via frontend atau Supabase SQL editor.")
        return allowed
    except Exception as e:
        print(f"⚠️  Gagal cek scope: {e}. Lanjut tanpa validasi.")
        return True


# ==========================================
# 3. INTERACTIVE CLI
# ==========================================
if __name__ == "__main__":
    print("==============================================")
    print("🔥 NEXUS AI - PENTEST AGENT v6.1 (CLI Mode) 🔥")
    print("==============================================")
    print("Tools   : 11 Advanced Scanners")
    print("Vectors : SQLi, XSS, CSRF, LFI, RFI, Header Injection,")
    print("          API Security, SSL/TLS, DNS Enumeration")
    print("==============================================\n")

    input_target = input("🎯 Target URL (contoh: https://target.com): ").strip()
    input_goal   = input("🎯 Goal      (contoh: Cari celah SQLi / Bypass login): ").strip()

    # ── Scope check ──────────────────────────────────────────────────────────────
    if not check_scope_cli(input_target):
        exit(1)

    # ── Model selection ───────────────────────────────────────────────────────────
    print("\n📋 Model yang tersedia:")
    from model_registry import list_available_models, MODEL_REGISTRY
    available = list_available_models()
    if not available:
        print("❌ Tidak ada model tersedia. Pastikan OPENROUTER_API_KEY di-set di .env")
        exit(1)

    for i, m in enumerate(available):
        tier_badge = "💰" if m["tier"] == "paid" else "🆓"
        print(f"  [{i+1}] {tier_badge} {m['label']} ({m['provider']})")

    print("\nPilih model per agent (tekan Enter untuk auto fallback chain):")

    def pick_model(agent_name: str) -> str | None:
        raw = input(f"  Model untuk {agent_name} [1-{len(available)}, Enter=auto]: ").strip()
        if not raw:
            return None
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(available):
                chosen = available[idx]["id"]
                print(f"    → {available[idx]['label']}")
                return chosen
        except ValueError:
            pass
        print("    → Input tidak valid, pakai auto.")
        return None

    model_recon     = pick_model("Recon")
    model_analis    = pick_model("Analis")
    model_eksekutor = pick_model("Eksekutor")
    model_assessor  = pick_model("Assessor")

    print("\n⛓️  Fallback chain:")
    print(f"  Recon     : {' → '.join(chain_summary(model_recon)[:3])}")
    print(f"  Analis    : {' → '.join(chain_summary(model_analis)[:3])}")
    print(f"  Eksekutor : {' → '.join(chain_summary(model_eksekutor)[:3])}")
    print(f"  Assessor  : {' → '.join(chain_summary(model_assessor)[:3])}")

    # ── Build LLMs ────────────────────────────────────────────────────────────────
    llm_recon     = build_llm(model_recon)
    llm_analis    = build_llm(model_analis)
    llm_eksekutor = build_llm(model_eksekutor)
    llm_assessor  = build_llm(model_assessor)

    # ── Agents ───────────────────────────────────────────────────────────────────
    tim_recon = Agent(
        role='Advanced Reconnaissance & Intel Gatherer',
        goal='Deep recon: infrastruktur, tech-stack, WAF, DNS, SSL, browser-based surface mapping.',
        backstory='Intel Red Team level elit. Ngebedah server pakai fingerprinting tingkat tinggi, dan bisa liat web app kayak user beneran pakai headless browser.',
        llm=llm_recon,
        tools=[
            recon_target, enumerate_dns_subdomains, analyze_ssl_tls,
            browser_screenshot, browser_extract_surface,
            browser_intercept_requests, browser_check_security_headers,
            browser_extract_js_secrets, analyze_js_deep,
            param_discovery_get, param_discovery_headers,
        ],
        verbose=True
    )

    tim_analis = Agent(
        role='Senior Vulnerability Strategist & Exploit Designer',
        goal='Analisis intel recon, rancang payload presisi, discover hidden parameters.',
        backstory='Mastermind eksploitasi. Payload surgical, WAF-aware. Expert di parameter discovery dan attack vector analysis.',
        llm=llm_analis,
        tools=[
            baca_log_burp, scan_sql_injection, detect_xss_csrf,
            scan_lfi_rfi, test_header_injection,
            browser_simulate_form, browser_find_open_redirect,
            param_discovery_post,
        ],
        verbose=True
    )

    tim_eksekutor = Agent(
        role='Active Exploit Executor & API Security Tester',
        goal='Eksekusi payload, test SSRF, IDOR, API security, dan password analysis.',
        backstory='Eksekutor berdarah dingin. Expert di SSRF dan IDOR yang sering jadi goldmine di H1.',
        llm=llm_eksekutor,
        tools=[
            tembak_payload, test_api_security, analyze_password_strength,
            scan_ssrf, scan_idor,
        ],
        verbose=True
    )

    tim_assessor = Agent(
        role='Chief Information Security Officer (CISO)',
        goal='Menilai dampak bisnis dari semua hasil eksploitasi dan menyusun laporan eksekutif profesional.',
        backstory='Ahli CIA Triad + CVSS scoring. Terjemahkan celah teknis jadi laporan eksekutif yang actionable.',
        llm=llm_assessor,
        verbose=True
    )

    # ── Clear logs ────────────────────────────────────────────────────────────────
    clear_execution_logs()

    # ── Tasks ─────────────────────────────────────────────────────────────────────
    tugas_recon = Task(
        description=f"Lakukan Active Recon ke: {input_target}. Petakan ports, tech-stack, WAF, DNS, SSL/TLS.",
        expected_output="Laporan intelijen infrastruktur lengkap.",
        agent=tim_recon
    )

    tugas_analis = Task(
        description=(
            f"Target: {input_target} | Goal: {input_goal}\n"
            "Berdasarkan recon, rancang serangan: SQLi, XSS, LFI, Header Injection.\n"
            "Sesuaikan payload dengan tech-stack dan hindari WAF triggers."
        ),
        expected_output="Instruksi eksekusi detail + hasil vulnerability scanners.",
        agent=tim_analis,
        human_input=True   # HITL: pause buat review sebelum eksekusi
    )

    tugas_eksekusi = Task(
        description="Eksekusi payload dari Analis. Test API endpoints. Laporkan semua HTTP response.",
        expected_output="Log HTTP response + API security findings.",
        agent=tim_eksekutor
    )

    tugas_assessment = Task(
        description=(
            "Analisis semua findings. Buat laporan:\n"
            "1. Nama & deskripsi kerentanan\n"
            "2. Dampak CIA Triad\n"
            "3. CVSS score\n"
            "4. Saran mitigasi\n"
            "5. PoC jika ada"
        ),
        expected_output="Laporan eksekutif risk assessment lengkap.",
        agent=tim_assessor
    )

    # ── Run ───────────────────────────────────────────────────────────────────────
    crew = Crew(
        agents=[tim_recon, tim_analis, tim_eksekutor, tim_assessor],
        tasks=[tugas_recon, tugas_analis, tugas_eksekusi, tugas_assessment],
        memory=True,
        verbose=True
    )

    print("\n🚀 Memulai Eksekusi Red Team...\n")
    hasil_akhir = crew.kickoff()

    logs_data = get_execution_logs()

    print("\n==============================================")
    print("🎯 FINAL REPORT - CISO DESK:")
    print("==============================================")
    print(hasil_akhir)

    print("\n==============================================")
    print("📊 EXECUTION LOGS SUMMARY:")
    print("==============================================")
    print(f"Total Log Entries : {logs_data['summary']['total_logs']}")
    print(f"Tools Executed    : {', '.join(logs_data['summary']['tools_executed'])}")
    print(f"Errors            : {logs_data['summary']['error_count']}")
    print(f"Duration          : {logs_data['summary']['duration_seconds']:.2f}s")

    print("\n[D] Detail Logs (First 10):")
    for log in logs_data['logs'][:10]:
        print(f"  [{log['timestamp']}] {log['tool']} - {log['status']}: {log['message']}")
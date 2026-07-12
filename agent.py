import os
from dotenv import load_dotenv
from crewai import Agent, Task, Crew
from langchain_openai import ChatOpenAI
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
from nuclei_tool import run_nuclei_scan
from subdomain_takeover import detect_subdomain_takeover
from auth_testing import test_jwt_weakness, test_auth_rate_limiting
from custom_tools import report_new_endpoint
from wayback_tool import wayback_scraper
from github_dork import github_dorking
from oauth_tester import oauth_flow_tester
from graphql_tester import graphql_tester
from cors_tester import cors_tester
from ssti_tester import ssti_tester
from xxe_tester import xxe_tester

# ── New tools (Phase 2-4) ─────────────────────────────────────────────────────
from misconfiguration_scanner import misconfiguration_scanner
from command_injection import command_injection_scanner, log_injection_scanner, csv_injection_scanner
from xss_advanced import stored_xss_scanner, dom_xss_scanner, jsonp_injection_scanner
from auth_session_advanced import session_management_scanner, password_reset_tester
from injection_advanced import (
    blind_sqli_scanner, nosql_injection_scanner,
    ldap_injection_scanner, xpath_injection_scanner
)
from access_control_advanced import access_control_scanner
from client_side_advanced import client_side_security_scanner, prototype_pollution_scanner
from advanced_web_attacks import (
    host_header_injection_scanner, race_condition_scanner,
    file_upload_scanner, http_request_smuggling_scanner,
    websocket_security_scanner
)
from recon_advanced import recon_advanced, email_header_injection_scanner
from deserialization_cache_tools import (
    insecure_deserialization_scanner, web_cache_poisoning_scanner,
    cache_deception_scanner, ssrf_advanced_scanner
)
from auth_recon_tools import (
    twofa_bypass_scanner, credential_stuffing_scanner,
    mixed_content_scanner, idor_uuid_scanner,
    postmessage_vulnerability_scanner, asn_ip_mapper
)
from shodan_censys_tools import shodan_scanner, censys_scanner

# ==========================================
# 1. LOAD ENV
# ==========================================
load_dotenv()

# ==========================================
# 2. SCOPE VALIDATION (CLI mode)
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
    print("🔥 NEXUS AI - PENTEST AGENT v7.0 (CLI Mode) 🔥")
    print("==============================================")
    print("Tools   : 70 Advanced Scanners")
    print("Vectors : SQLi (error + blind), XSS (reflected/stored/DOM),")
    print("          LFI/RFI, SSTI, XXE, SSRF, IDOR, CORS, OAuth, JWT,")
    print("          GraphQL, Command Injection, NoSQL, LDAP, XPath,")
    print("          File Upload, Deserialization, Cache Poisoning,")
    print("          Host Header, Race Condition, HTTP Smuggling,")
    print("          WebSocket, 2FA Bypass, Session Management,")
    print("          Misconfiguration, Access Control, Client-Side,")
    print("          Recon (CT logs, ASN, Cloud Assets)")
    print("==============================================\n")

    input_target = input("🎯 Target URL (contoh: https://target.com): ").strip()
    input_goal   = input("🎯 Goal      (contoh: Cari celah SQLi / Bypass login): ").strip()

    # ── Scope check ──────────────────────────────────────────────────────────
    if not check_scope_cli(input_target):
        exit(1)

    # ── Model selection ───────────────────────────────────────────────────────
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

    # ── Helper: LangChain → CrewAI BaseTool ──────────────────────────────────
    def langchain_to_crewai(lc_tool):
        from crewai.tools import BaseTool
        from pydantic import create_model
        import inspect

        if hasattr(lc_tool, 'args_schema') and lc_tool.args_schema:
            schema = lc_tool.args_schema
        else:
            sig = inspect.signature(lc_tool.func)
            fields = {k: (str, ...) for k, v in sig.parameters.items() if k != 'self'}
            schema = create_model(f"{lc_tool.name}Input", **fields) if fields else None

        class CrewAIWrappedTool(BaseTool):
            name: str = lc_tool.name
            description: str = lc_tool.description
            args_schema: type = schema if schema else type('EmptySchema', (), {})

            def _run(self, **kwargs) -> str:
                return lc_tool.invoke(kwargs)

        return CrewAIWrappedTool()

    # ── Build LLMs ────────────────────────────────────────────────────────────
    llm_recon     = build_llm(model_recon)
    llm_analis    = build_llm(model_analis)
    llm_eksekutor = build_llm(model_eksekutor)
    llm_assessor  = build_llm(model_assessor)

    # ── Agents ───────────────────────────────────────────────────────────────
    tim_recon = Agent(
        role='Advanced Reconnaissance & Intel Gatherer',
        goal='Deep recon: infrastruktur, tech-stack, WAF, DNS, SSL, browser-based surface mapping, cloud assets.',
        backstory=(
            'Intel Red Team level elit. Ngebedah server pakai fingerprinting tingkat tinggi, '
            'dan bisa liat web app kayak user beneran pakai headless browser. '
            'Jago temuin exposed cloud buckets, subdomain takeover, dan leaked secrets di JS.'
        ),
        llm=llm_recon,
        tools=[langchain_to_crewai(t) for t in [
            # Core recon
            recon_target, enumerate_dns_subdomains, analyze_ssl_tls,
            # Browser-based
            browser_screenshot, browser_extract_surface,
            browser_intercept_requests, browser_check_security_headers,
            browser_extract_js_secrets, analyze_js_deep,
            # Parameter & endpoint discovery
            param_discovery_get, param_discovery_headers,
            detect_subdomain_takeover, report_new_endpoint,
            wayback_scraper, github_dorking,
            # Advanced recon
            recon_advanced, misconfiguration_scanner,
            asn_ip_mapper, mixed_content_scanner,
            client_side_security_scanner, postmessage_vulnerability_scanner,
            shodan_scanner, censys_scanner,
        ]],
        verbose=True
    )

    tim_analis = Agent(
        role='Senior Vulnerability Strategist & Exploit Designer',
        goal='Analisis intel recon, rancang payload presisi, discover hidden parameters, test injection vectors.',
        backstory=(
            'Mastermind eksploitasi. Payload surgical, WAF-aware. '
            'Expert di injection attacks (SQL, NoSQL, LDAP, XPath, Command), '
            'XSS variants (reflected, stored, DOM), dan access control bypass.'
        ),
        llm=llm_analis,
        tools=[langchain_to_crewai(t) for t in [
            # Core scanners
            baca_log_burp, scan_sql_injection, detect_xss_csrf,
            scan_lfi_rfi, test_header_injection,
            # Browser
            browser_simulate_form, browser_find_open_redirect,
            param_discovery_post,
            # Vuln scanners
            run_nuclei_scan, graphql_tester, cors_tester, ssti_tester,
            report_new_endpoint,
            # Injection advanced
            blind_sqli_scanner, nosql_injection_scanner,
            ldap_injection_scanner, xpath_injection_scanner,
            command_injection_scanner, log_injection_scanner, csv_injection_scanner,
            # XSS advanced
            stored_xss_scanner, dom_xss_scanner, jsonp_injection_scanner,
            # Access control
            access_control_scanner,
            # Client-side
            prototype_pollution_scanner,
            # Cache attacks
            web_cache_poisoning_scanner, cache_deception_scanner,
            idor_uuid_scanner,
        ]],
        verbose=True
    )

    tim_eksekutor = Agent(
        role='Active Exploit Executor & API Security Tester',
        goal='Eksekusi payload, test auth flows, session management, file upload, advanced web attacks.',
        backstory=(
            'Eksekutor berdarah dingin. Expert di auth bypass (JWT, OAuth, 2FA, session), '
            'file upload RCE, deserialization, race conditions, dan HTTP-level attacks. '
            'Selalu cari goldmine di endpoint yang tampak innocuous.'
        ),
        llm=llm_eksekutor,
        tools=[langchain_to_crewai(t) for t in [
            # Core
            tembak_payload, test_api_security, analyze_password_strength,
            scan_ssrf, scan_idor,
            # Auth
            test_jwt_weakness, test_auth_rate_limiting,
            oauth_flow_tester, report_new_endpoint,
            # Vuln scanners
            xxe_tester,
            # Auth advanced
            session_management_scanner, password_reset_tester,
            twofa_bypass_scanner, credential_stuffing_scanner,
            # Advanced web attacks
            host_header_injection_scanner, race_condition_scanner,
            file_upload_scanner, http_request_smuggling_scanner,
            websocket_security_scanner, email_header_injection_scanner,
            # Deserialization & SSRF
            insecure_deserialization_scanner, ssrf_advanced_scanner,
        ]],
        verbose=True
    )

    tim_assessor = Agent(
        role='Chief Information Security Officer (CISO)',
        goal='Menilai dampak bisnis dari semua hasil eksploitasi dan menyusun laporan eksekutif profesional.',
        backstory=(
            'Ahli CIA Triad + CVSS scoring. Terjemahkan celah teknis jadi laporan eksekutif '
            'yang actionable untuk C-level dan dev team. Prioritas berdasarkan business impact.'
        ),
        llm=llm_assessor,
        verbose=True
    )

    # ── Clear logs ────────────────────────────────────────────────────────────
    clear_execution_logs()

    # ── Tasks ─────────────────────────────────────────────────────────────────
    tugas_recon = Task(
        description=(
            f"Lakukan Active Recon ke: {input_target}\n"
            "Petakan: ports, tech-stack, WAF, DNS, SSL/TLS, subdomain, "
            "cloud assets, JS secrets, exposed files (.git, .env, backup), "
            "certificate transparency logs, ASN/IP ranges."
        ),
        expected_output="Laporan intelijen infrastruktur lengkap beserta semua attack surface yang ditemukan.",
        agent=tim_recon
    )

    tugas_analis = Task(
        description=(
            f"Target: {input_target} | Goal: {input_goal}\n"
            "Berdasarkan hasil recon, test semua injection vectors yang relevan:\n"
            "- SQL Injection (error-based dan blind)\n"
            "- XSS (reflected, stored, DOM)\n"
            "- Command/OS Injection\n"
            "- NoSQL, LDAP, XPath Injection\n"
            "- Access Control (forced browsing, mass assignment, path traversal)\n"
            "- Cache attacks (poisoning, deception)\n"
            "Sesuaikan payload dengan tech-stack yang ditemukan recon."
        ),
        expected_output="Daftar vulnerabilities yang ditemukan beserta payload, parameter, dan evidence.",
        agent=tim_analis,
        human_input=True   # HITL: pause untuk review sebelum eksekusi
    )

    tugas_eksekusi = Task(
        description=(
            f"Target: {input_target}\n"
            "Eksekusi attack vectors dari Analis. Focus pada:\n"
            "- Auth bypass (JWT, session, 2FA, OAuth)\n"
            "- File upload bypass dan RCE verification\n"
            "- SSRF via berbagai vectors (URL param, file upload, PDF generator)\n"
            "- Deserialization detection\n"
            "- Race conditions pada critical endpoints\n"
            "- HTTP Request Smuggling\n"
            "- WebSocket security\n"
            "Laporkan semua HTTP response dan evidence."
        ),
        expected_output="Log eksekusi lengkap: HTTP responses, confirmed vulnerabilities, PoC evidence.",
        agent=tim_eksekutor
    )

    tugas_assessment = Task(
        description=(
            "Analisis semua findings dari Recon, Analis, dan Eksekutor.\n"
            "Buat laporan komprehensif:\n"
            "1. Nama & deskripsi kerentanan\n"
            "2. Dampak CIA Triad (Confidentiality, Integrity, Availability)\n"
            "3. CVSS v3.1 score & vector\n"
            "4. Risk rating (Critical/High/Medium/Low/Info)\n"
            "5. Saran mitigasi yang actionable\n"
            "6. PoC atau evidence jika ada\n"
            "7. Prioritas remediation"
        ),
        expected_output="Laporan eksekutif risk assessment lengkap siap untuk C-level dan dev team.",
        agent=tim_assessor
    )

    # ── Run ───────────────────────────────────────────────────────────────────
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
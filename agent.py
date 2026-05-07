import os
from dotenv import load_dotenv
from crewai import Agent, Task, Crew
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from custom_tools import (
    baca_log_burp, tembak_payload, recon_target,
    scan_sql_injection, detect_xss_csrf, analyze_ssl_tls,
    enumerate_dns_subdomains, analyze_password_strength,
    test_api_security, scan_lfi_rfi, test_header_injection,
    get_execution_logs, clear_execution_logs
)

# ==========================================
# 1. LOAD API KEYS SECARA AMAN
# ==========================================
load_dotenv()

# ==========================================
# 2. SETUP OTAK AI (LLM)
# ==========================================
llm_sonnet = ChatAnthropic(
    model="claude-3-5-sonnet-20240620", 
    temperature=0.2
)

llm_llama = ChatOpenAI(
    openai_api_base="https://openrouter.ai/api/v1",
    openai_api_key=os.environ.get("OPENROUTER_API_KEY"),
    model_name="meta-llama/llama-3-70b-instruct",
    temperature=0.5 
)

# ==========================================
# 3. BENTUK TIM (4 Divisi Red Team - Holy Agent Version)
# ==========================================
tim_recon = Agent(
    role='Advanced Reconnaissance & Intel Gatherer',
    goal='Melakukan Deep Recon untuk memetakan infrastruktur, Tech-Stack, Port, WAF, DNS records, dan SSL/TLS posture target.',
    backstory='Lo adalah intel Red Team level elit. Lo nggak cuma ngecek web nyala atau mati, tapi lo ngebedah jeroan servernya pakai teknik fingerprinting tingkat tinggi, DNS enumeration, dan SSL analysis sebelum tim lain bergerak.',
    llm=llm_sonnet,
    tools=[
        recon_target,
        enumerate_dns_subdomains,
        analyze_ssl_tls
    ],
    verbose=True
)

tim_analis = Agent(
    role='Senior Vulnerability Strategist & Exploit Designer',
    goal='Menganalisis data intelijen dan meracik payload yang 100% akurat dengan arsitektur target. Test untuk SQLi, XSS, LFI, Header Injection, API security issues.',
    backstory='Lo adalah mastermind eksploitasi tingkat dewa. Kalau tim Recon bilang target pakai PHP, lo nggak bakal buang waktu ngirim payload Node.js. Lo sangat memperhitungkan WAF dan merancang teknik stealth. Lo bisa design SQLi, XSS, LFI, dan header injection yang surgical.',
    llm=llm_sonnet,
    tools=[
        baca_log_burp,
        scan_sql_injection,
        detect_xss_csrf,
        scan_lfi_rfi,
        test_header_injection
    ],
    verbose=True
)

tim_eksekutor = Agent(
    role='Active Exploit Executor & API Security Tester',
    goal='Menembakkan HTTP Request berdasarkan instruksi presisi dari Analis. Test API endpoints dan analyze password strength.',
    backstory='Eksekutor berdarah dingin. Lo mengeksekusi payload tanpa ragu menggunakan tool "Tembak Request HTTP" dan melaporkan respons server apa adanya. Lo juga expert dalam API security testing dan password analysis.',
    llm=llm_llama,
    tools=[
        tembak_payload,
        test_api_security,
        analyze_password_strength
    ], 
    verbose=True
)

tim_assessor = Agent(
    role='Chief Information Security Officer (CISO)',
    goal='Menilai dampak bisnis dari semua hasil eksploitasi dan menyusun laporan eksekutif profesional.',
    backstory='Ahli Risk Management dengan understanding mendalam tentang semua vector attack modern (SQLi, XSS, LFI, RFI, Header Injection, API vulnerabilities, SSL/TLS weaknesses). Mampu menerjemahkan celah teknis menjadi laporan dampak CIA Triad dan kalkulasi skor CVSS akurat.',
    llm=llm_sonnet,
    verbose=True
)

# ==========================================
# 4. JALANKAN OPERASI (Interactive CLI - UPGRADED)
# ==========================================
if __name__ == "__main__":
    print("==============================================")
    print("🔥 AI PENTEST AGENT - HOLY VERSION 5.0 🔥")
    print("==============================================")
    print("Tools: 11 Advanced Scanners + Execution Logging")
    print("Vectors: SQLi, XSS, CSRF, LFI, RFI, Header Injection, API Security, SSL/TLS, DNS")
    print("==============================================\n")
    
    input_target = input("🎯 Masukkan URL Target (contoh: https://target.com/api): ")
    input_goal = input("🎯 Masukkan Goal (contoh: Bypass login / Cari celah RCE): ")
    
    # Clear logs untuk fresh start
    clear_execution_logs()
    
    # TASKS PIPELINE (Rantai Komando - UPGRADED)
    tugas_recon = Task(
        description=f"Lakukan Active Recon Target ke URL: {input_target}. Petakan semua Open Ports, Tech-Stack, WAF, dan DNS records. Analyze SSL/TLS certificates untuk weakness detection.",
        expected_output="Laporan intelijen infrastruktur, postur keamanan target, DNS enumeration results, dan SSL/TLS analysis.",
        agent=tim_recon
    )

    tugas_analis = Task(
        description=f"Berdasarkan URL {input_target}, Goal '{input_goal}', dan laporan intelijen dari Recon, rancang strategi serangan komprehensif. Test untuk:\n1. SQL Injection pada semua parameters\n2. XSS dan CSRF vulnerabilities\n3. Local/Remote File Inclusion (LFI/RFI)\n4. HTTP Header Injection\nSesuaikan payload dengan Tech-Stack target dan hindari WAF triggers.",
        expected_output="Instruksi eksekusi detail (URL, method, headers, body payload) + hasil dari semua vulnerability scanners.",
        agent=tim_analis
    )

    tugas_eksekusi = Task(
        description="Gunakan tool Tembak Request HTTP untuk mengeksekusi instruksi Analis secara live. Test API endpoints untuk security issues. Analyze password strength jika diperlukan. Laporkan semua response details.",
        expected_output="Log HTTP Response mentah + API security findings + password strength analysis.",
        agent=tim_eksekutor
    )

    tugas_assessment = Task(
        description="Analisis semua bukti dari Eksekutor dan vulnerability scanners. Buat laporan profesional berisi:\n1. Nama & Deskripsi Kerentanan (SQLi, XSS, CSRF, LFI, RFI, Header Injection, API issues, SSL/TLS weaknesses)\n2. Dampak terhadap CIA Triad (Confidentiality, Integrity, Availability)\n3. Estimasi Skor CVSS (Low/Medium/High/Critical)\n4. Saran Mitigasi Taktis\n5. Proof of Concept (jika ada)",
        expected_output="Laporan eksekutif risk assessment lengkap dan actionable.",
        agent=tim_assessor
    )
    
    pentest_crew = Crew(
        agents=[tim_recon, tim_analis, tim_eksekutor, tim_assessor],
        tasks=[tugas_recon, tugas_analis, tugas_eksekusi, tugas_assessment],
        memory=True,
        verbose=True
    )

    print("\n🚀 Memulai Eksekusi Red Team (Holy Agent Mode)...\n")
    hasil_akhir = pentest_crew.kickoff()
    
    # Get execution logs
    logs_data = get_execution_logs()
    
    print("\n==============================================")
    print("🎯 FINAL REPORT - CISO DESK:")
    print("==============================================")
    print(hasil_akhir)
    
    print("\n==============================================")
    print("📊 EXECUTION LOGS SUMMARY:")
    print("==============================================")
    print(f"Total Log Entries: {logs_data['summary']['total_logs']}")
    print(f"Tools Executed: {', '.join(logs_data['summary']['tools_executed'])}")
    print(f"Errors Encountered: {logs_data['summary']['error_count']}")
    print(f"Total Duration: {logs_data['summary']['duration_seconds']:.2f} seconds")
    
    print("\n[D] Detail Logs (First 10):")
    for log in logs_data['logs'][:10]:
        print(f"  [{log['timestamp']}] {log['tool']} - {log['status']}: {log['message']}")
import os
from dotenv import load_dotenv
from crewai import Agent, Task, Crew
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from custom_tools import baca_log_burp, tembak_payload

# ==========================================
# 1. LOAD API KEYS SECARA AMAN
# ==========================================
load_dotenv()

# ==========================================
# 2. SETUP OTAK AI (LLM)
# ==========================================
llm_analis = ChatAnthropic(
    model="claude-3-5-sonnet-20240620", 
    temperature=0.2
)

llm_eksekutor = ChatOpenAI(
    openai_api_base="https://openrouter.ai/api/v1",
    openai_api_key=os.environ.get("OPENROUTER_API_KEY"),
    model_name="meta-llama/llama-3-70b-instruct",
    temperature=0.5 
)

# ==========================================
# 3. BENTUK TIM (Define Agents)
# ==========================================
tim_analis = Agent(
    role='Senior Web Traffic Analyzer',
    goal='Menganalisis request HTTP untuk menemukan parameter rentan IDOR atau Logic Bug.',
    backstory='Lo adalah bug bounty hunter spesialis logic flaw. Lo teliti banget menganalisis struktur parameter JSON dan HTTP headers.',
    llm=llm_analis,
    tools=[baca_log_burp],
    verbose=True
)

tim_eksekutor = Agent(
    role='Exploit Crafter & Active Executor',
    goal='Membuat payload eksploitasi dan MENGEKSEKUSINYA langsung ke target.',
    backstory='Lo adalah pembuat exploit yang barbar. Lo nggak cuma bikin PoC di atas kertas, tapi lo tes langsung ke server target menggunakan tool "Tembak Request HTTP" buat ngebuktiin payload lo valid.',
    llm=llm_eksekutor,
    tools=[tembak_payload], 
    verbose=True
)

# ==========================================
# 4. KASIH KERJAAN (Dinamic Tasks)
# ==========================================
tugas_analisis = Task(
    description='''
    Analisis target berikut: {target_url}. 
    Goal spesifik dari user: {goal_khusus}.
    Gunakan tool yang tersedia untuk membaca file log dari path: {file_log}. 
    Identifikasi celah Business Logic atau cara manipulasi parameter untuk mencapai goal tersebut.
    ''',
    expected_output='Penjelasan singkat tentang celah keamanan dan parameter mana yang menjadi titik lemah.',
    agent=tim_analis
)

tugas_eksekusi = Task(
    description='''
    Berdasarkan hasil analisis untuk mencapai goal "{goal_khusus}", racik payload (XSS/SQLi/IDOR).
    Setelah diracik, lo WAJIB memanggil tool "Tembak Request HTTP" untuk menguji payload tersebut secara live ke {target_url}.
    Jika payload pertama gagal, coba racik payload alternatif dan tembak lagi.
    ''',
    expected_output='Laporan akhir berisi payload mana yang berhasil tembus, beserta bukti status code dan response dari server target.',
    agent=tim_eksekutor
)

# ==========================================
# 5. JALANKAN OPERASI (Interactive CLI)
# ==========================================
if __name__ == "__main__":
    print("==============================================")
    print("🔥 CUSTOM PENTEST AGENT - SNIPER MODE 🔥")
    print("==============================================\n")
    
    input_target = input("🎯 Masukkan URL Target (contoh: target.com/api): ")
    input_goal = input("🎯 Masukkan Goal (contoh: Ubah alpha jadi hadir): ")
    input_file = input("📁 Masukkan Path File Log (contoh: /Users/nama/export.json): ")
    
    data_dinamis = {
        'target_url': input_target,
        'goal_khusus': input_goal,
        'file_log': input_file
    }
    
    pentest_crew = Crew(
        agents=[tim_analis, tim_eksekutor],
        tasks=[tugas_analisis, tugas_eksekusi],
        memory=True,
        verbose=True
    )

    print("\n🚀 Memulai Red Team AI Agent...\n")
    hasil_akhir = pentest_crew.kickoff(inputs=data_dinamis)
    
    print("\n==============================================")
    print("🎯 HASIL AKHIR DARI TIM EKSEKUTOR:")
    print("==============================================")
    print(hasil_akhir)
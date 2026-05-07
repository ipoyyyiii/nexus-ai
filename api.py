import os
import uuid
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from supabase import create_client, Client

from crewai import Agent, Task, Crew
from custom_tools import (
    baca_log_burp, tembak_payload, recon_target,
    scan_sql_injection, detect_xss_csrf, analyze_ssl_tls,
    enumerate_dns_subdomains, analyze_password_strength,
    test_api_security, scan_lfi_rfi, test_header_injection,
    get_execution_logs, clear_execution_logs
)
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from typing import Optional
from langchain_core.messages import HumanMessage

load_dotenv()

# --- INISIALISASI SUPABASE ---
url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

app = FastAPI(title="AI Pentest OS API", version="5.0 - Advanced Logging Edition")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PentestRequest(BaseModel):
    target: str
    goal: str
    session_id: Optional[str] = None

class ImageRequest(BaseModel): 
    image_data: str 
    session_id: Optional[str] = None

# --- HELPER: SIMPAN PERCAKAPAN KE SUPABASE ---
def save_message_to_cloud(session_id, role, content):
    supabase.table("chat_messages").insert({
        "session_id": session_id,
        "role": role,
        "content": content
    }).execute()

# --- ENDPOINT: AMBIL DAFTAR SESSION (SIDEBAR) ---
@app.get("/sessions")
async def get_all_sessions():
    try:
        res = supabase.table("sessions").select("*").order("created_at", desc=True).execute()
        return res.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- ENDPOINT BARU: GET EXECUTION LOGS (Real-Time) ---
@app.get("/logs")
async def get_logs():
    """
    Endpoint ini dipangin secara periodik dari frontend.
    Return semua execution logs dari tools yang sedang/udah jalan.
    """
    try:
        logs_data = get_execution_logs()
        return {
            "status": "success",
            "logs": logs_data["logs"],
            "summary": logs_data["summary"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- ENDPOINT BARU: CLEAR EXECUTION LOGS ---
@app.post("/logs/clear")
async def clear_logs():
    """Clear semua execution logs untuk fresh start."""
    try:
        clear_execution_logs()
        return {"status": "success", "message": "Logs cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==========================================
# ENDPOINT UTAMA: PENTEST EXECUTION (UPGRADED)
# ==========================================
@app.post("/pentest")
async def execute_pentest(req: PentestRequest):
    # 1. Tentukan Session ID (Bikin baru kalau tidak ada)
    current_session_id = req.session_id
    if not current_session_id:
        new_session = supabase.table("sessions").insert({
            "title": f"Scan: {req.target}" 
        }).execute()
        current_session_id = new_session.data[0]['id']

    # 2. Simpan input user ke memori cloud
    save_message_to_cloud(current_session_id, "user", req.goal)
    
    # 3. Clear logs untuk execution baru
    clear_execution_logs()

    def log_step(step):
        try:
            from custom_tools import exec_logger
            exec_logger.add_log("AI_THOUGHT", "PROCESSING", str(step.thought))
        except:
            pass

    try:
        # --- LLM CONFIG ---
        llm_sonnet = ChatAnthropic(
            model_name="claude-3-5-sonnet-20240620", 
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY"),
            temperature=0.2
        )
        llm_llama = ChatOpenAI(
            model="meta-llama/llama-3-70b-instruct", 
            base_url="https://openrouter.ai/api/v1", 
            api_key=os.environ.get("OPENROUTER_API_KEY"),
            temperature=0.5
        )

        # --- AGEN-AGEN ELIT (UPGRADED DENGAN 11 TOOLS) ---
        recon = Agent(
            role='Advanced Reconnaissance & Intel Gatherer',
            goal='Melakukan Deep Recon untuk memetakan infrastruktur, Tech-Stack, Port, dan WAF target.',
            backstory='Lo adalah intel Red Team level elit. Lo nggak cuma ngecek web nyala atau mati, tapi lo ngebedah jeroan servernya pakai teknik fingerprinting tingkat tinggi sebelum tim lain bergerak.',
            llm=llm_sonnet, 
            tools=[
                recon_target, 
                enumerate_dns_subdomains,
                analyze_ssl_tls
            ], 
            verbose=True
        )
        
        analis = Agent(
            role='Senior Vulnerability Strategist',
            goal='Menganalisis data intelijen (Tech-Stack, Ports, WAF) dan meracik payload yang 100% akurat dengan arsitektur target.',
            backstory='Lo adalah mastermind eksploitasi. Kalau tim Recon bilang target pakai PHP, lo nggak bakal buang waktu ngirim payload Node.js. Lo sangat memperhitungkan WAF dan merancang teknik stealth.',
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
        
        eksekutor = Agent(
            role='Active Exploit Executor',
            goal='Menembakkan HTTP Request berdasarkan instruksi presisi dari Analis.',
            backstory='Eksekutor berdarah dingin. Lo mengeksekusi payload tanpa ragu menggunakan tool "Tembak Request HTTP" dan melaporkan respons server apa adanya.',
            llm=llm_llama, 
            tools=[
                tembak_payload,
                test_api_security,
                analyze_password_strength
            ], 
            verbose=True
        )
        
        assessor = Agent(
            role='Chief Information Security Officer (CISO)',
            goal='Menilai dampak bisnis dari hasil eksploitasi dan menyusun laporan eksekutif.',
            backstory='Ahli Risk Management. Mampu menerjemahkan celah teknis (dari response body/status code) menjadi laporan dampak CIA Triad dan kalkulasi skor CVSS.',
            llm=llm_sonnet, 
            verbose=True
        )

        # --- TASKS (TETAP SAMA TAPI LEBIH POWERFUL) ---
        task_recon = Task(
            description=f"Lakukan Active Recon Target ke URL: {req.target}. Petakan semua Open Ports, Tech-Stack, dan status WAF. Gunakan DNS enumeration, SSL analysis untuk insight maksimal.",
            expected_output="Laporan intelijen infrastruktur, postur keamanan, DNS records, dan SSL certificate analysis.", 
            agent=recon
        )
        
        task_analis = Task(
            description=f"Berdasarkan URL {req.target}, Goal '{req.goal}', dan laporan intelijen dari Recon, rancang strategi serangan komprehensif. Test SQLi, XSS/CSRF, LFI/RFI, Header Injection. Sesuaikan payload spesifik dengan Tech-Stack target dan hindari WAF.",
            expected_output="Instruksi eksekusi detail (URL, method, headers, body payload) + hasil vulnerability assessment dari multiple vectors.", 
            agent=analis
        )
        
        task_eksekusi = Task(
            description="Gunakan tool Tembak Request HTTP untuk mengeksekusi instruksi Analis secara live. Laporkan status code dan response body seakurat mungkin. Test API security dan analyze response patterns.",
            expected_output="Log HTTP Response mentah dari server target setelah dieksploitasi + API security findings.", 
            agent=eksekutor
        )
        
        task_assessor = Task(
            description="Analisis bukti HTTP Response dari Eksekutor + semua findings dari vulnerability scanners. Buat laporan profesional berisi:\n1. Nama & Deskripsi Kerentanan (SQLi, XSS, LFI, Header Injection, API issues, SSL/TLS weaknesses)\n2. Dampak terhadap CIA Triad (Confidentiality, Integrity, Availability)\n3. Estimasi Skor CVSS (Low/Medium/High/Critical)\n4. Saran Mitigasi Taktis",
            expected_output="Laporan eksekutif risk assessment komprehensif dengan semua findings.", 
            agent=assessor
        )

        crew = Crew(
            agents=[recon, analis, eksekutor, assessor], 
            tasks=[task_recon, task_analis, task_eksekusi, task_assessor], 
            step_callback=log_step,
            verbose=True
        )
        
        hasil = crew.kickoff()
        report_text = str(hasil)

        # 4. Simpan balasan AI ke cloud
        save_message_to_cloud(current_session_id, "agent", report_text)

        return {
            "status": "success",
            "session_id": current_session_id,
            "target": req.target,
            "report": report_text
        }

    except Exception as e:
        error_msg = str(e)
        save_message_to_cloud(current_session_id, "agent", f"CRITICAL ERROR: {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)

@app.post("/analyze-image")
async def analyze_image(req: ImageRequest):
    # Tentukan session (pake yang ada atau bikin baru)
    current_session_id = req.session_id or str(uuid.uuid4())
    
    try:
        # Bersihin data base64 (buang header "data:image/jpeg;base64,")
        base64_image = req.image_data.split(",")[1] if "," in req.image_data else req.image_data
        
        # Pake Sonnet 3.5 karena dia jago baca gambar (Multimodal)
        llm_vision = ChatAnthropic(model="claude-3-5-sonnet-20240620", anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY"))
        
        # Rakit perintah buat si AI
        message = HumanMessage(
            content=[
                {"type": "text", "text": "Analyze this image technically. If it's a security dashboard, find vulnerabilities. If it's hardware, identify parts and issues."},
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"},
                },
            ]
        )
        
        response = llm_vision.invoke([message])
        analysis_result = str(response.content)

        # Simpan ke cloud biar log-nya sinkron
        save_message_to_cloud(current_session_id, "agent", f"[VISION_ANALYSIS]: {analysis_result}")

        return {"status": "success", "analysis": analysis_result}
        
    except Exception as e:
        print(f"Vision Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# ENDPOINT: DOWNLOAD EXECUTION REPORT AS JSON
# ==========================================
@app.get("/export/logs.json")
async def export_logs_json():
    """Export semua execution logs dalam format JSON untuk archiving."""
    try:
        logs_data = get_execution_logs()
        return logs_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
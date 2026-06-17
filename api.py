import os
import uuid
import asyncio
import json
from datetime import datetime
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from supabase import create_client, Client
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from crewai import Agent, Task, Crew

from custom_tools import (
    baca_log_burp, tembak_payload, recon_target,
    scan_sql_injection, detect_xss_csrf, analyze_ssl_tls,
    enumerate_dns_subdomains, analyze_password_strength,
    test_api_security, scan_lfi_rfi, test_header_injection,
    get_execution_logs, clear_execution_logs
)

load_dotenv()

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

app = FastAPI(title="Nexus AI Pentest API", version="6.0 - Async Edition")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# IN-MEMORY JOB STORE
# Menyimpan status setiap pentest job secara thread-safe.
# Di production ganti dengan Redis.
# ============================================================
jobs: Dict[str, Dict[str, Any]] = {}

# ============================================================
# HUMAN-IN-THE-LOOP CHECKPOINT STORE
# ============================================================
pending_checkpoints: Dict[str, asyncio.Future] = {}


# ============================================================
# MODELS
# ============================================================
class PentestRequest(BaseModel):
    target: str           # URL eksplisit, sudah divalidasi di frontend
    goal: str
    session_id: Optional[str] = None

class ImageRequest(BaseModel):
    image_data: str
    session_id: Optional[str] = None

class CheckpointResponse(BaseModel):
    job_id: str
    approved: bool


# ============================================================
# HELPERS
# ============================================================
def save_message(session_id: str, role: str, content: str):
    try:
        supabase.table("chat_messages").insert({
            "session_id": session_id,
            "role": role,
            "content": content
        }).execute()
    except Exception as e:
        print(f"[WARN] Supabase save failed: {e}")

def update_job(job_id: str, **kwargs):
    if job_id in jobs:
        jobs[job_id].update(kwargs)
        jobs[job_id]["updated_at"] = datetime.now().isoformat()


# ============================================================
# BACKGROUND PENTEST RUNNER
# Ini yang dulu blocking sekarang jalan di background thread.
# ============================================================
def run_pentest_job(job_id: str, target: str, goal: str, session_id: str):
    """
    Dijalankan di background thread oleh FastAPI BackgroundTasks.
    Update jobs[job_id] secara berkala agar bisa di-poll dari frontend.
    """
    try:
        update_job(job_id, status="running", message="Inisialisasi agents...")
        clear_execution_logs()

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

        # --- AGENTS ---
        recon = Agent(
            role="Advanced Reconnaissance & Intel Gatherer",
            goal="Deep recon: infrastruktur, tech-stack, WAF, DNS, SSL.",
            backstory="Intel Red Team level elit. Ngebedah server pakai fingerprinting tingkat tinggi.",
            llm=llm_sonnet,
            tools=[recon_target, enumerate_dns_subdomains, analyze_ssl_tls],
            verbose=True
        )

        analis = Agent(
            role="Senior Vulnerability Strategist",
            goal="Rancang payload presisi berdasarkan intel recon.",
            backstory="Mastermind eksploitasi. Payload-nya surgical, WAF-aware.",
            llm=llm_sonnet,
            tools=[baca_log_burp, scan_sql_injection, detect_xss_csrf, scan_lfi_rfi, test_header_injection],
            verbose=True
        )

        eksekutor = Agent(
            role="Active Exploit Executor",
            goal="Eksekusi payload, test API, analisis password.",
            backstory="Eksekutor berdarah dingin. Laporkan response apa adanya.",
            llm=llm_llama,
            tools=[tembak_payload, test_api_security, analyze_password_strength],
            verbose=True
        )

        assessor = Agent(
            role="Chief Information Security Officer (CISO)",
            goal="Risk assessment dan laporan eksekutif.",
            backstory="Ahli CIA Triad + CVSS scoring.",
            llm=llm_sonnet,
            verbose=True
        )

        # --- TASKS ---
        update_job(job_id, message="Phase 1: Reconnaissance...")

        task_recon = Task(
            description=f"Active Recon target: {target}. Petakan ports, tech-stack, WAF, DNS, SSL.",
            expected_output="Laporan intelijen infrastruktur lengkap.",
            agent=recon
        )

        task_analis = Task(
            description=f"Target: {target} | Goal: {goal}\nBerdasarkan recon, rancang serangan: SQLi, XSS, LFI, Header Injection.",
            expected_output="Instruksi eksekusi detail + vulnerability assessment.",
            agent=analis
        )

        task_eksekusi = Task(
            description="Eksekusi payload dari Analis. Test API endpoints. Report response mentah.",
            expected_output="Log HTTP response + API security findings.",
            agent=eksekutor
        )

        task_assessor = Task(
            description=(
                "Analisis semua findings. Buat laporan:\n"
                "1. Kerentanan + deskripsi\n"
                "2. Dampak CIA Triad\n"
                "3. CVSS score\n"
                "4. Mitigasi\n"
                "5. PoC jika ada"
            ),
            expected_output="Laporan eksekutif risk assessment.",
            agent=assessor
        )

        def on_step(step):
            try:
                msg = str(getattr(step, "thought", step))[:200]
                update_job(job_id, message=msg)
            except Exception:
                pass

        crew = Crew(
            agents=[recon, analis, eksekutor, assessor],
            tasks=[task_recon, task_analis, task_eksekusi, task_assessor],
            step_callback=on_step,
            verbose=True
        )

        update_job(job_id, message="Phase 2: Scanning vulnerabilities...")
        result = crew.kickoff()
        report = str(result)

        logs_data = get_execution_logs()
        save_message(session_id, "agent", report)

        update_job(
            job_id,
            status="done",
            message="Selesai.",
            report=report,
            logs=logs_data["logs"],
            summary=logs_data["summary"]
        )

    except Exception as e:
        err = str(e)
        save_message(session_id, "agent", f"ERROR: {err}")
        update_job(job_id, status="error", message=err, report=None)


# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/sessions")
async def get_sessions():
    try:
        res = supabase.table("sessions").select("*").order("created_at", desc=True).execute()
        return res.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/pentest")
async def start_pentest(req: PentestRequest, background_tasks: BackgroundTasks):
    """
    Langsung return job_id. Pentest jalan di background.
    Frontend poll /job/{job_id} atau stream dari /job/{job_id}/stream.
    """
    # Buat atau ambil session
    session_id = req.session_id
    if not session_id:
        res = supabase.table("sessions").insert({
            "title": f"Scan: {req.target}"
        }).execute()
        session_id = res.data[0]["id"]

    save_message(session_id, "user", f"[TARGET] {req.target}\n[GOAL] {req.goal}")

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id": job_id,
        "session_id": session_id,
        "target": req.target,
        "goal": req.goal,
        "status": "queued",          # queued | running | waiting_hitl | done | error
        "message": "Mengantre...",
        "report": None,
        "logs": [],
        "summary": {},
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }

    background_tasks.add_task(
        run_pentest_job, job_id, req.target, req.goal, session_id
    )

    return {"job_id": job_id, "session_id": session_id, "status": "queued"}


@app.get("/job/{job_id}")
async def get_job(job_id: str):
    """Poll status job."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan")
    return jobs[job_id]


@app.get("/job/{job_id}/stream")
async def stream_job(job_id: str):
    """
    SSE endpoint — frontend subscribe ke sini untuk dapat update real-time
    tanpa perlu polling manual.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan")

    async def event_generator():
        last_message = ""
        last_status = ""
        while True:
            job = jobs.get(job_id, {})
            status = job.get("status", "")
            message = job.get("message", "")

            # Kirim event kalau ada perubahan
            if message != last_message or status != last_status:
                payload = {
                    "status": status,
                    "message": message,
                    "logs": job.get("logs", []),
                    "summary": job.get("summary", {}),
                }
                if status in ("done", "error"):
                    payload["report"] = job.get("report")

                yield f"data: {json.dumps(payload)}\n\n"
                last_message = message
                last_status = status

            if status in ("done", "error"):
                yield "data: {\"event\": \"close\"}\n\n"
                break

            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


# ============================================================
# HUMAN-IN-THE-LOOP CHECKPOINTS
# ============================================================

@app.post("/checkpoint/request")
async def request_checkpoint(job_id: str, action: str, context: str):
    """
    Agent memanggil ini saat akan melakukan tindakan berbahaya.
    Endpoint ini BLOCKING sampai user respond atau timeout 5 menit.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan")

    loop = asyncio.get_event_loop()
    future = loop.create_future()
    pending_checkpoints[job_id] = future

    update_job(
        job_id,
        status="waiting_hitl",
        message=f"Menunggu persetujuan: {action}",
        checkpoint={
            "action": action,
            "context": context,
            "requested_at": datetime.now().isoformat()
        }
    )

    try:
        approved = await asyncio.wait_for(future, timeout=300)
        update_job(job_id, status="running", checkpoint=None)
        return {"approved": approved}
    except asyncio.TimeoutError:
        update_job(job_id, status="running", checkpoint=None)
        pending_checkpoints.pop(job_id, None)
        return {"approved": False, "reason": "timeout"}


@app.post("/checkpoint/respond")
async def respond_checkpoint(data: CheckpointResponse):
    """Frontend kirim approved=True/False ke sini."""
    future = pending_checkpoints.pop(data.job_id, None)
    if not future or future.done():
        raise HTTPException(status_code=404, detail="Tidak ada checkpoint aktif")
    future.set_result(data.approved)
    return {"ok": True}


# ============================================================
# LOGS
# ============================================================

@app.get("/logs")
async def get_logs():
    data = get_execution_logs()
    return {"status": "success", "logs": data["logs"], "summary": data["summary"]}

@app.post("/logs/clear")
async def clear_logs():
    clear_execution_logs()
    return {"status": "success"}

@app.get("/export/logs.json")
async def export_logs():
    return get_execution_logs()


# ============================================================
# IMAGE ANALYSIS
# ============================================================

@app.post("/analyze-image")
async def analyze_image(req: ImageRequest):
    session_id = req.session_id or str(uuid.uuid4())
    try:
        b64 = req.image_data.split(",")[1] if "," in req.image_data else req.image_data
        llm = ChatAnthropic(
            model="claude-3-5-sonnet-20240620",
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY")
        )
        message = HumanMessage(content=[
            {"type": "text", "text": "Analyze this image for security vulnerabilities, misconfigurations, or interesting attack surface. Be specific and technical."},
            {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}}
        ])
        response = llm.invoke([message])
        analysis = str(response.content)
        save_message(session_id, "agent", f"[VISION]: {analysis}")
        return {"status": "success", "analysis": analysis}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
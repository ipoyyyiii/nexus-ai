import os
import uuid
import asyncio
import json
import secrets
import asyncio
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from supabase import create_client, Client
from langchain_core.messages import HumanMessage
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
from session_memory import SessionMemory, MEMORY_TABLE_SQL
from scope import validate_target
from checkpoint import checkpoint_store, current_job_id
from model_registry import build_llm, list_available_models, chain_summary
from cancellation import cancellation_store, current_job_id as cancel_job_id
from model_registry import build_llm, list_available_models, chain_summary
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

load_dotenv()

import litellm
litellm._turn_on_debug()

if os.environ.get("OPENROUTER_API_KEY"):
    os.environ["OPENAI_API_KEY"] = os.environ.get("OPENROUTER_API_KEY")
    os.environ["OPENAI_API_BASE"] = "https://openrouter.ai/api/v1"
    os.environ["OPENAI_BASE_URL"] = "https://openrouter.ai/api/v1"

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)
memory = SessionMemory(supabase)

app = FastAPI(title="Nexus AI Pentest API", version="6.1 - Hardened Edition")

def langchain_to_crewai(lc_tool):
    from crewai.tools import BaseTool
    from pydantic import create_model
    import inspect

    # Bangun schema dari args_schema tool asli
    if hasattr(lc_tool, 'args_schema') and lc_tool.args_schema:
        schema = lc_tool.args_schema
    else:
        # Fallback: bikin schema dinamis dari signature fungsi
        sig = inspect.signature(lc_tool.func)
        fields = {
            k: (str, ...) 
            for k, v in sig.parameters.items() 
            if k != 'self'
        }
        schema = create_model(f"{lc_tool.name}Input", **fields) if fields else None

    class CrewAIWrappedTool(BaseTool):
        name: str = lc_tool.name
        description: str = lc_tool.description
        args_schema: type = schema if schema else type('EmptySchema', (), {})

        def _run(self, **kwargs) -> str:
            return lc_tool.invoke(kwargs)

    return CrewAIWrappedTool()

# ============================================================
# API KEY AUTH
# Set NEXUS_API_KEY di .env. Semua endpoint sensitif butuh header
# `X-API-Key`. Kalau NEXUS_API_KEY gak di-set sama sekali, server
# REFUSE TO START dengan auth kosong (biar gak ke-deploy tanpa sadar
# tanpa proteksi apapun) — kecuali eksplisit di-allow lewat
# NEXUS_ALLOW_NO_AUTH=true (cuma buat dev lokal).
# ============================================================
NEXUS_API_KEY = os.environ.get("NEXUS_API_KEY")
ALLOW_NO_AUTH = os.environ.get("NEXUS_ALLOW_NO_AUTH", "false").lower() == "true"

if not NEXUS_API_KEY and not ALLOW_NO_AUTH:
    raise RuntimeError(
        "NEXUS_API_KEY belum di-set di .env. Generate satu (mis. python -c "
        "\"import secrets; print(secrets.token_hex(32))\") lalu set NEXUS_API_KEY=<hasilnya>. "
        "Kalau ini cuma dev lokal dan sengaja mau tanpa auth, set NEXUS_ALLOW_NO_AUTH=true."
    )

async def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if ALLOW_NO_AUTH and not NEXUS_API_KEY:
        return True
    if not x_api_key or not secrets.compare_digest(x_api_key, NEXUS_API_KEY or ""):
        raise HTTPException(status_code=401, detail="API key tidak valid. Kirim header X-API-Key.")
    return True


# ============================================================
# CORS
# Gak ada lagi wildcard "*". Set NEXUS_ALLOWED_ORIGINS di .env
# ============================================================
allowed_origins_env = os.environ.get("NEXUS_ALLOWED_ORIGINS", "http://48.193.45.254:3000")
allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Content-Type", "X-API-Key"],
)

# ============================================================
# IN-MEMORY JOB STORE
# Menyimpan status setiap pentest job secara thread-safe.
# Di production ganti dengan Redis.
# ============================================================
jobs: Dict[str, Dict[str, Any]] = {}

class JobQueueState:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.visited_targets = set()
        self.max_depth = 3
        self.is_running = False

ACTIVE_QUEUE_SESSIONS: Dict[str, JobQueueState] = {}
# ============================================================
# HUMAN-IN-THE-LOOP: hubungkan checkpoint_store (dipanggil dari
# dalam tool di worker thread) ke jobs dict supaya status job
# ke-update real-time dan kelihatan di SSE stream.
# ============================================================
def _on_checkpoint_wait_start(job_id: str, action: str, context: str):
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

def _on_checkpoint_wait_end(job_id: str):
    update_job(job_id, status="running", checkpoint=None)

checkpoint_store.on_wait_start = _on_checkpoint_wait_start
checkpoint_store.on_wait_end = _on_checkpoint_wait_end


# ============================================================
# MODELS
# ============================================================
class PentestRequest(BaseModel):
    target: str           # URL eksplisit, sudah divalidasi di frontend
    goal: str
    session_id: Optional[str] = None
    # Per-agent model override dari frontend. Key: "recon" | "analis" | "eksekutor" | "assessor"
    # Value: model_id dari model_registry.py (mis. "claude-sonnet", "glm-4.5-air-free"), atau
    # None/gak diisi -> default fallback chain (paid dulu, baru free kalau gagal).
    agent_models: Optional[Dict[str, Optional[str]]] = None

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
def run_pentest_job(job_id: str, target: str, goal: str, session_id: str, agent_models: Optional[Dict[str, Optional[str]]] = None):
    """
    Dijalankan di background thread oleh FastAPI BackgroundTasks.
    Kini mendukung multi-target paralel (Async Worker Pool) tanpa merusak WAF.
    """
    agent_models = agent_models or {}
    try:
        current_job_id.set(job_id)
        cancel_job_id.set(job_id)
        cancellation_store.register(job_id)

        update_job(job_id, status="running", message="Validasi scope target...")
        allowed, reason = validate_target(target, supabase)
        if not allowed:
            update_job(job_id, status="error", message=f"DITOLAK SCOPE: {reason}", report=None)
            save_message(session_id, "agent", f"SCOPE REJECTED: {reason}")
            return

        update_job(job_id, status="running", message="Inisialisasi agents & model chain...")
        clear_execution_logs()

        # Load intelligence lama dari target utama
        memory_context = memory.build_context(target)
        if memory_context:
            update_job(job_id, message="📚 Loading previous intelligence from memory...")

        # Bangun engine LLM per agent
        llm_recon = build_llm(agent_models.get("recon"))
        llm_analis = build_llm(agent_models.get("analis"))
        llm_eksekutor = build_llm(agent_models.get("eksekutor"))
        llm_assessor = build_llm(agent_models.get("assessor"))

        # ============================================================
        # BIKIN EVENT LOOP ASYNC DI DALAM BACKGROUND THREAD INI
        # ============================================================
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        state = JobQueueState()
        state.is_running = True
        
        # Masukkan target utama/pertama dari user ke antrean
        loop.run_until_complete(state.queue.put(target))
        ACTIVE_QUEUE_SESSIONS[job_id] = state

        all_reports = []  # Tempat nampung laporan dari tiap target yang kena scan

        # Fungsi worker asinkron yang bakal jalan barengan
        async def worker(worker_id: int):
            print(f"[Worker-{worker_id}] Aktif dan memantau antrean...")
            while state.is_running:
                try:
                    # Ambil target baru dari antrean (tunggu maks 10 detik kalau kosong)
                    current_target = await asyncio.wait_for(state.queue.get(), timeout=10.0)
                except asyncio.TimeoutError:
                    if state.queue.empty():
                        break
                    continue

                if current_target in state.visited_targets:
                    state.queue.task_done()
                    continue

                state.visited_targets.add(current_target)
                update_job(job_id, message=f"🚀 [Worker-{worker_id}] Mulai menyisir target: {current_target}")

                try:
                    # --------------------------------------------------------
                    # AGENTS (Konfigurasi dinamis menggunakan current_target)
                    # --------------------------------------------------------
                    recon = Agent(
                        role="Advanced Reconnaissance & Intel Gatherer",
                        goal="Deep recon: infrastruktur, tech-stack, WAF, DNS, SSL, browser-based surface mapping.",
                        backstory=(
                            "Intel Red Team level elit. Ngebedah server pakai fingerprinting tingkat tinggi, "
                            "dan bisa 'liat' web app kayak user beneran pakai headless browser."
                            + (f"\n{memory_context}" if memory_context else "")
                        ),
                        llm=llm_recon,
                        tools=[langchain_to_crewai(t) for t in [
                            recon_target, enumerate_dns_subdomains, analyze_ssl_tls,
                            browser_screenshot, browser_extract_surface,
                            browser_intercept_requests, browser_check_security_headers,
                            browser_extract_js_secrets, analyze_js_deep,
                            param_discovery_get, param_discovery_headers,
                            detect_subdomain_takeover,
                            report_new_endpoint, wayback_scraper,github_dorking,
                        ]],
                        verbose=True
                    )

                    analis = Agent(
                        role="Senior Vulnerability Strategist",
                        goal="Rancang payload presisi berdasarkan intel recon. Manfaatkan hasil browser-based recon buat temuin attack vector yang lebih dalam.",
                        backstory="Mastermind eksploitasi. Payload-nya surgical, WAF-aware. Bisa analisa JS bundle, form behavior, dan hidden API endpoint.",
                        llm=llm_analis,
                        tools=[langchain_to_crewai(t) for t in [
                            baca_log_burp, scan_sql_injection, detect_xss_csrf,
                            scan_lfi_rfi, test_header_injection,
                            browser_simulate_form, browser_find_open_redirect,
                            param_discovery_post,
                            run_nuclei_scan,
                            report_new_endpoint,graphql_tester,cors_tester,
                            ssti_tester,
                        ]],
                        verbose=True
                    )

                    eksekutor = Agent(
                        role="Active Exploit Executor",
                        goal="Eksekusi payload, test API, SSRF, IDOR, analisis password.",
                        backstory="Eksekutor berdarah dingin. Expert di SSRF dan IDOR yang sering jadi goldmine di H1.",
                        llm=llm_eksekutor,
                        tools=[langchain_to_crewai(t) for t in [
                            tembak_payload, test_api_security, analyze_password_strength,
                            scan_ssrf, scan_idor,
                            test_jwt_weakness,
                            test_auth_rate_limiting,
                            report_new_endpoint,oauth_flow_tester,
                            xxe_tester,
                        ]],
                        verbose=True
                    )

                    assessor = Agent(
                        role="Chief Information Security Officer (CISO)",
                        goal="Risk assessment dan laporan eksekutif.",
                        backstory="Ahli CIA Triad + CVSS scoring.",
                        llm=llm_assessor,
                        verbose=True
                    )

                    # --------------------------------------------------------
                    # TASKS
                    # --------------------------------------------------------
                    task_recon = Task(
                        description=f"Active Recon target: {current_target}. Petakan ports, tech-stack, WAF, DNS, SSL.",
                        expected_output="Laporan intelijen infrastruktur lengkap.",
                        agent=recon
                    )

                    task_analis = Task(
                        description=f"Target: {current_target} | Goal: {goal}\nBerdasarkan recon, rancang serangan: SQLi, XSS, LFI, Header Injection.",
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
                            msg = str(getattr(step, "thought", step))[:150]
                            update_job(job_id, message=f"[Worker-{worker_id}] {msg}")
                        except Exception:
                            pass

                    # Bangun Crew untuk current_target
                    crew = Crew(
                        agents=[recon, analis, eksekutor, assessor],
                        tasks=[task_recon, task_analis, task_eksekusi, task_assessor],
                        step_callback=on_step,
                        verbose=True
                    )

                    # Kickoff berjalan secara blocking di dalam thread worker ini
                    result = crew.kickoff()
                    all_reports.append(f"## 🎯 Target Scan Result: {current_target}\n\n{str(result)}\n\n")

                except Exception as worker_err:
                    print(f"[Worker-{worker_id}] Gagal memproses {current_target}: {str(worker_err)}")
                finally:
                    state.queue.task_done()

        # Buka 2 worker paralel (Bisa disesuaikan spek MacBook lo)
        async def start_pool():
            workers = [worker(i+1) for i in range(2)]
            await asyncio.gather(*workers)

        # Jalankan loop pool worker sampai antrean bener-benar kosong
        loop.run_until_complete(start_pool())
        state.is_running = False

        # Gabungkan seluruh laporan target jadi satu string besar
        report = "\n".join(all_reports) if all_reports else "Tidak ada target yang berhasil dianalisis."

        # ============================================================
        # BAGIAN AKHIR (Sama seperti kode lama lo, update status & log)
        # ============================================================
        logs_data = get_execution_logs()

        if cancellation_store.is_cancelled(job_id):
            save_message(session_id, "agent", "JOB DIBATALKAN oleh user.")
            update_job(
                job_id,
                status="cancelled",
                message="Dibatalkan oleh user.",
                logs=logs_data["logs"],
                summary=logs_data["summary"]
            )
        else:
            save_message(session_id, "agent", report)
            update_job(
                job_id,
                status="done",
                message="Selesai.",
                report=report,
                logs=logs_data["logs"],
                summary=logs_data["summary"]
            )
            try:
                memory.save_findings_from_report(target, report, session_id)
            except Exception as mem_err:
                print(f"[MEMORY] Auto-save failed (non-critical): {mem_err}")

    except Exception as e:
        err = str(e)
        save_message(session_id, "agent", f"ERROR: {err}")
        update_job(job_id, status="error", message=err, report=None)

    finally:
        cancellation_store.cleanup(job_id)
        if job_id in ACTIVE_QUEUE_SESSIONS:
            del ACTIVE_QUEUE_SESSIONS[job_id]


# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/sessions")
async def get_sessions(_: bool = Depends(require_api_key)):
    try:
        res = supabase.table("sessions").select("*").order("created_at", desc=True).execute()
        return res.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sessions/{session_id}/messages")
async def get_session_messages(session_id: str, _: bool = Depends(require_api_key)):
    """
    Ambil semua chat messages dari session tertentu, diurutkan dari yang paling lama.
    Frontend pakai ini buat restore chat history waktu klik session di sidebar.
    """
    try:
        res = (
            supabase.table("chat_messages")
            .select("*")
            .eq("session_id", session_id)
            .order("created_at", desc=False)
            .execute()
        )
        return res.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/models")
async def get_models(_: bool = Depends(require_api_key)):
    """Return daftar model yang available buat dipilih di frontend."""
    return list_available_models()


# ============================================================
# SCOPE RULES CRUD
# ============================================================

class ScopeRuleRequest(BaseModel):
    program_name: str
    pattern: str
    rule_type: str  # "allow" | "deny"
    notes: Optional[str] = None


@app.get("/scope-rules")
async def get_scope_rules(_: bool = Depends(require_api_key)):
    try:
        res = supabase.table("scope_rules").select("*").order("created_at", desc=True).execute()
        return res.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scope-rules")
async def create_scope_rule(req: ScopeRuleRequest, _: bool = Depends(require_api_key)):
    if req.rule_type not in ("allow", "deny"):
        raise HTTPException(status_code=400, detail="rule_type harus 'allow' atau 'deny'.")
    if not req.pattern.strip():
        raise HTTPException(status_code=400, detail="Pattern tidak boleh kosong.")
    if not req.program_name.strip():
        raise HTTPException(status_code=400, detail="Program name tidak boleh kosong.")
    try:
        res = supabase.table("scope_rules").insert({
            "program_name": req.program_name.strip(),
            "pattern": req.pattern.strip().lower(),
            "rule_type": req.rule_type,
            "notes": req.notes or None,
        }).execute()
        return res.data[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/scope-rules/{rule_id}")
async def delete_scope_rule(rule_id: str, _: bool = Depends(require_api_key)):
    try:
        supabase.table("scope_rules").delete().eq("id", rule_id).execute()
        return {"ok": True, "deleted": rule_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/pentest")
async def start_pentest(req: PentestRequest, background_tasks: BackgroundTasks, _: bool = Depends(require_api_key)):
    """
    Langsung return job_id. Pentest jalan di background.
    Frontend poll /job/{job_id} atau stream dari /job/{job_id}/stream.
    """
    # Cek scope DULU sebelum bikin session/job apapun — fail fast, jangan
    # nunggu sampai background job jalan baru ketauan ditolak.
    allowed, reason = validate_target(req.target, supabase)
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Target di luar scope: {reason}")

    # Buat atau ambil session
    session_id = req.session_id
    if not session_id:
        res = supabase.table("sessions").insert({
            "title": f"Scan: {req.target}"
        }).execute()
        session_id = res.data[0]["id"]

    save_message(session_id, "user", f"[TARGET] {req.target}\n[GOAL] {req.goal}")

    job_id = str(uuid.uuid4())
    stream_token = secrets.token_urlsafe(32)
    jobs[job_id] = {
        "job_id": job_id,
        "session_id": session_id,
        "target": req.target,
        "goal": req.goal,
        "status": "queued",
        "message": "Mengantre...",
        "report": None,
        "logs": [],
        "summary": {},
        "stream_token": stream_token,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }

    background_tasks.add_task(
        run_pentest_job, job_id, req.target, req.goal, session_id, req.agent_models
    )

    return {"job_id": job_id, "session_id": session_id, "status": "queued", "stream_token": stream_token}


@app.get("/job/{job_id}")
async def get_job(job_id: str, _: bool = Depends(require_api_key)):
    """Poll status job."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan")
    return jobs[job_id]


@app.post("/job/{job_id}/cancel")
async def cancel_job(job_id: str, _: bool = Depends(require_api_key)):
    """
    Cancel job yang lagi jalan. Set cancellation token yang dicek oleh setiap
    tool sebelum eksekusi — tool yang belum jalan akan berhenti, tool yang
    sedang berjalan akan selesai dulu baru berhenti di tool berikutnya.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan")

    job = jobs[job_id]
    if job.get("status") not in ("queued", "running", "waiting_hitl"):
        raise HTTPException(
            status_code=400,
            detail=f"Job tidak bisa di-cancel, status saat ini: {job.get('status')}"
        )

    # Kalau lagi nunggu HITL, auto-reject dulu biar thread gak stuck
    checkpoint_store.respond(job_id, False)

    cancelled = cancellation_store.cancel(job_id)
    if cancelled:
        update_job(job_id, status="cancelling", message="Menunggu tool selesai lalu berhenti...")

    return {"ok": cancelled, "job_id": job_id}


@app.get("/job/{job_id}/stream")
async def stream_job(job_id: str, token: Optional[str] = None):
    """
    SSE endpoint. Diprotect pakai query param `?token=` karena EventSource
    browser gak bisa kirim custom header. Token di-generate waktu POST /pentest
    dan dikirim balik ke frontend di response body.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan")

    job = jobs[job_id]
    stored_token = job.get("stream_token")
    if stored_token and (not token or not secrets.compare_digest(token, stored_token)):
        raise HTTPException(status_code=401, detail="Stream token tidak valid.")

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

@app.get("/checkpoint/{job_id}")
async def get_checkpoint(job_id: str, _: bool = Depends(require_api_key)):
    """
    Frontend poll/baca ini buat tau apakah job lagi nunggu approval, dan
    detail aksi apa yang mau dijalankan.
    """
    pending = checkpoint_store.get_pending(job_id)
    if not pending:
        return {"waiting": False}
    return {"waiting": True, **pending}


@app.post("/checkpoint/respond")
async def respond_checkpoint(data: CheckpointResponse, _: bool = Depends(require_api_key)):
    """
    Frontend kirim approved=True/False ke sini. Ini langsung set threading.Event
    yang lagi di-`wait()` oleh worker thread tempat tool eksekusi nungguin.
    """
    ok = checkpoint_store.respond(data.job_id, data.approved)
    if not ok:
        raise HTTPException(status_code=404, detail="Tidak ada checkpoint aktif untuk job_id ini")
    return {"ok": True, "approved": data.approved}


# ============================================================
# LOGS
# ============================================================

@app.get("/job/{job_id}/report.md")
async def export_report_markdown(job_id: str, _: bool = Depends(require_api_key)):
    """
    Export laporan dalam format Markdown siap paste ke HackerOne.
    Return plain text dengan Content-Disposition biar browser auto-download.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan")

    job = jobs[job_id]
    if job.get("status") != "done" or not job.get("report"):
        raise HTTPException(status_code=400, detail="Report belum tersedia. Tunggu job selesai.")

    target = job.get("target", "Unknown")
    goal = job.get("goal", "Unknown")
    created_at = job.get("created_at", "")[:10]
    raw_report = job.get("report", "")
    logs = job.get("logs", [])
    summary = job.get("summary", {})

    # Ringkasan tools yang dieksekusi
    tools_list = ", ".join(summary.get("tools_executed", [])) or "N/A"
    duration = f"{summary.get('duration_seconds', 0):.1f}s"
    error_count = summary.get("error_count", 0)

    md = f"""# Penetration Test Report
**Target:** {target}
**Goal:** {goal}
**Date:** {created_at}
**Job ID:** {job_id}

---

## Executive Summary

{raw_report}

---

## Scan Coverage

| Field | Value |
|---|---|
| Tools Executed | {tools_list} |
| Total Log Entries | {summary.get('total_logs', 0)} |
| Errors Encountered | {error_count} |
| Duration | {duration} |

---

## Execution Log (Summary)

"""
    # Tambah log entries yang punya status WARNING/ERROR/SUCCESS (skip PROCESSING/START buat brevity)
    notable_logs = [l for l in logs if l.get("status") in ("WARNING", "ERROR", "SUCCESS")]
    if notable_logs:
        for log in notable_logs[:30]:  # Max 30 biar gak kebanjiran
            md += f"- `[{log['status']}]` **{log['tool']}** — {log['message']}\n"
    else:
        md += "_No notable findings in execution log._\n"

    md += f"""
---

## Methodology

This assessment was conducted using Nexus AI, an autonomous penetration testing agent.
The following attack vectors were evaluated:

- SQL Injection (all accessible parameters)
- Cross-Site Scripting (XSS) & CSRF
- Local/Remote File Inclusion (LFI/RFI)
- HTTP Header Injection
- API Security Testing
- SSL/TLS Configuration Analysis
- DNS Enumeration
- WAF Detection & Fingerprinting

---

## Disclaimer

This test was conducted with explicit authorization under the applicable bug bounty program.
All findings are reported in good faith for responsible disclosure purposes.

_Generated by Nexus AI — {created_at}_
"""

    from fastapi.responses import Response
    filename = f"nexus-report-{job_id[:8]}-{created_at}.md"
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.get("/logs")
async def get_logs(_: bool = Depends(require_api_key)):
    data = get_execution_logs()
    return {"status": "success", "logs": data["logs"], "summary": data["summary"]}

@app.post("/logs/clear")
async def clear_logs(_: bool = Depends(require_api_key)):
    clear_execution_logs()
    return {"status": "success"}

@app.get("/export/logs.json")
async def export_logs(_: bool = Depends(require_api_key)):
    return get_execution_logs()


# ============================================================
# IMAGE ANALYSIS
# ============================================================

@app.post("/analyze-image")
async def analyze_image(req: ImageRequest, _: bool = Depends(require_api_key)):
    session_id = req.session_id or str(uuid.uuid4())
    try:
        b64 = req.image_data.split(",")[1] if "," in req.image_data else req.image_data
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model="anthropic/claude-opus-4-8",
            api_key=os.environ.get("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            default_headers={
                "HTTP-Referer": "http://localhost:3000",
                "X-Title": "Nexus Pentest AI",
            },
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

class InjectTargetRequest(BaseModel):
    url: str
    source: str

@app.post("/api/v1/job/{job_id}/inject-target")
@app.post("/api/v1/session/{session_id}/inject-target")
async def inject_new_target(
    req: InjectTargetRequest,
    job_id: str = None,
    session_id: str = None,
    _: bool = Depends(require_api_key)
):
    # Resolve job_id dari session_id kalau agent cuma tau session_id
    if not job_id and session_id:
        job_id = next(
            (jid for jid, j in jobs.items() if j.get("session_id") == session_id),
            None
        )

    if not job_id or job_id not in ACTIVE_QUEUE_SESSIONS:
        raise HTTPException(status_code=404, detail="Job queue tidak aktif atau sudah selesai.")

    state = ACTIVE_QUEUE_SESSIONS[job_id]
    new_url = req.url.strip()

    if new_url in state.visited_targets:
        return {"status": "ignored", "message": "Target sudah masuk antrean atau sudah discan."}

    asyncio.run_coroutine_threadsafe(state.queue.put(new_url), asyncio.get_event_loop())
    update_job(job_id, message=f"Menambahkan target baru dari {req.source}: {new_url}")

    return {"status": "success", "message": f"Target {new_url} berhasil ditambahkan ke antrean pool."}
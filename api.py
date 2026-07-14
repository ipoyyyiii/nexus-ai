import os
import uuid
import asyncio
import json
import secrets
import threading
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from supabase import create_client, Client
from langchain_core.messages import HumanMessage
from crewai import Agent, Task, Crew

from tools.custom_tools import (
    baca_log_burp, tembak_payload, recon_target,
    scan_sql_injection, detect_xss_csrf, analyze_ssl_tls,
    enumerate_dns_subdomains, analyze_password_strength,
    test_api_security, scan_lfi_rfi, test_header_injection,
    get_execution_logs, clear_execution_logs
)
from tools.playwright_tools import (
    browser_screenshot, browser_extract_surface,
    browser_intercept_requests, browser_extract_js_secrets,
    browser_check_security_headers, browser_simulate_form,
    browser_find_open_redirect,
)
from tools.ssrf_idor_tools import scan_ssrf, scan_idor
from tools.param_discovery import param_discovery_get, param_discovery_post, param_discovery_headers
from tools.js_analysis import analyze_js_deep
from core.session_memory import SessionMemory, MEMORY_TABLE_SQL
from core.scope import validate_target
from core.checkpoint import checkpoint_store, current_job_id
from core.model_registry import build_llm, list_available_models, chain_summary
from core.cancellation import cancellation_store, current_job_id as cancel_job_id
from tools.nuclei_tool import run_nuclei_scan
from tools.subdomain_takeover import detect_subdomain_takeover
from tools.auth_testing import test_jwt_weakness, test_auth_rate_limiting
from tools.custom_tools import report_new_endpoint
from tools.wayback_tool import wayback_scraper
from tools.github_dork import github_dorking
from tools.oauth_tester import oauth_flow_tester
from tools.graphql_tester import graphql_tester
from tools.cors_tester import cors_tester
from tools.ssti_tester import ssti_tester
from tools.xxe_tester import xxe_tester
from tools.misconfiguration_scanner import misconfiguration_scanner
from tools.command_injection import command_injection_scanner, log_injection_scanner, csv_injection_scanner
from tools.xss_advanced import stored_xss_scanner, dom_xss_scanner, jsonp_injection_scanner
from tools.auth_session_advanced import session_management_scanner, password_reset_tester
from tools.injection_advanced import blind_sqli_scanner, nosql_injection_scanner, ldap_injection_scanner, xpath_injection_scanner
from tools.access_control_advanced import access_control_scanner
from tools.client_side_advanced import client_side_security_scanner, prototype_pollution_scanner
from tools.advanced_web_attacks import host_header_injection_scanner, race_condition_scanner, file_upload_scanner, http_request_smuggling_scanner, websocket_security_scanner
from tools.recon_advanced import recon_advanced, email_header_injection_scanner
from tools.deserialization_cache_tools import insecure_deserialization_scanner, web_cache_poisoning_scanner, cache_deception_scanner, ssrf_advanced_scanner
from tools.auth_recon_tools import twofa_bypass_scanner, credential_stuffing_scanner, mixed_content_scanner, idor_uuid_scanner, postmessage_vulnerability_scanner, asn_ip_mapper
from tools.shodan_censys_tools import shodan_scanner, censys_scanner
from tools.playwright_tools import login_automator, inject_session
from tools.access_control_scanners import csrf_exploit_scanner, mass_assignment_scanner, http_method_tampering_scanner
from tools.report_generator import report_generator
from tools.waf_detector import waf_detector
from tools.html_injection_scanner import html_injection_scanner
from tools.ssi_injection_scanner import ssi_injection_scanner
from tools.hpp_scanner import hpp_scanner
from tools.password_storage_analyzer import password_storage_analyzer
from tools.credential_reuse_scanner import credential_reuse_scanner
from tools.open_redirect_scanner import open_redirect_scanner
from tools.dir_bruteforce import dir_bruteforce_scanner
from tools.ssl_scanner import ssl_scanner
from tools.wp_scanner import wp_scanner
from tools.web_crawler import web_crawler
from core.scan_history import scan_history
from core.auth_store import auth_store, AuthSession
from core.auth_detection import detect_login_wall, needs_auth
from core.auth_checkpoint import auth_checkpoint_store, current_job_id as auth_job_id

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
        "NEXUS_API_KEY not yet di-set di .env. Generate satu (mis. python -c "
        "\"import secrets; print(secrets.token_hex(32))\") lalu set NEXUS_API_KEY=<hasilnya>. "
        "Kalau ini cuma dev lokal dan sengaja mau tanpa auth, set NEXUS_ALLOW_NO_AUTH=true."
    )

async def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if ALLOW_NO_AUTH and not NEXUS_API_KEY:
        return True
    if not x_api_key or not secrets.compare_digest(x_api_key, NEXUS_API_KEY or ""):
        raise HTTPException(status_code=401, detail="API key not valid. Kirim header X-API-Key.")
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
# Saving status setiap pentest job secara thread-safe.
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
        message=f"Waiting persetujuan: {action}",
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
# HUMAN-IN-THE-LOOP: AUTH CHECKPOINT
# ============================================================
def _on_auth_request(job_id: str, url: str, domain: str):
    update_job(
        job_id,
        status="waiting_auth",
        message=f"Login wall terdeteksi di {domain}. Waiting credentials/session dari user.",
        auth_request={
            "url": url,
            "domain": domain,
            "requested_at": datetime.now().isoformat()
        }
    )

def _on_auth_response(job_id: str):
    update_job(job_id, status="running", auth_request=None)

auth_checkpoint_store.on_auth_request = _on_auth_request
auth_checkpoint_store.on_auth_response = _on_auth_response


# ============================================================
# CONTINUE STORE — buat phase-by-phase execution
# ============================================================
class ContinueStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._pending: Dict[str, threading.Event] = {}
        self._approved: Dict[str, bool] = {}

    def request_continue(self, job_id: str) -> bool:
        """Block sampai user klik continue atau timeout."""
        event = threading.Event()
        with self._lock:
            self._pending[job_id] = event
            self._approved[job_id] = False

        got_response = event.wait(timeout=600)  # 10 menit timeout

        with self._lock:
            self._pending.pop(job_id, None)
            approved = self._approved.pop(job_id, False)

        return approved

    def respond(self, job_id: str, approved: bool) -> bool:
        with self._lock:
            event = self._pending.get(job_id)
            if not event:
                return False
            self._approved[job_id] = approved
            event.set()
        return True

continue_store = ContinueStore()


# ============================================================
# MODELS
# ============================================================
class PentestRequest(BaseModel):
    target: str           # URL eksplisit, already validated di frontend
    goal: str
    session_id: Optional[str] = None
    # Per-agent model override dari frontend. Key: "recon" | "analis" | "eksekutor" | "assessor"
    # Value: model_id dari model_registry.py (mis. "claude-sonnet", "glm-4.5-air-free"), atau
    # None/gak diisi -> default fallback chain (paid dulu, baru free kalau failed).
    agent_models: Optional[Dict[str, Optional[str]]] = None
    # Auth credentials (opsional). Kalau diisi, auto-login senot yet scan dimulai.
    credentials: Optional[Dict[str, Any]] = None
    # Scan configuration — phases mana yang mau running
    scan_config: Optional[Dict[str, Any]] = None

class ImageRequest(BaseModel):
    image_data: str
    session_id: Optional[str] = None

class CheckpointResponse(BaseModel):
    job_id: str
    approved: bool


class AuthResponse(BaseModel):
    job_id: str
    # Mode: "credentials" atau "session"
    mode: str
    # Untuk mode "credentials"
    username: Optional[str] = None
    password: Optional[str] = None
    login_url: Optional[str] = None
    # Untuk mode "session"
    cookies: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


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
def run_pentest_job(job_id: str, target: str, goal: str, session_id: str, agent_models: Optional[Dict[str, Optional[str]]] = None, credentials: Optional[Dict[str, Any]] = None, scan_config: Optional[Dict[str, Any]] = None):
    """
    Phase-by-phase execution: Recon -> Analis -> Eksekutor -> Assessor.
    Setelah setiap phase, pause dan tunggu user klik "Continue".
    Auto-Pilot mode: skip manual approval, auto-continue.
    """
    agent_models = agent_models or {}
    scan_config = scan_config or {}
    auto_pilot = scan_config.get("auto_pilot", False)
    stealth_mode = scan_config.get("stealth_mode", False)
    
    # Apply stealth mode globally if enabled
    if stealth_mode:
        os.environ["STEALTH_MODE"] = "1"
    else:
        os.environ["STEALTH_MODE"] = "0"
    
    try:
        current_job_id.set(job_id)
        cancel_job_id.set(job_id)
        auth_job_id.set(job_id)
        cancellation_store.register(job_id)

        update_job(job_id, status="running", message="Validasi scope target...")
        allowed, reason = validate_target(target, supabase)
        if not allowed:
            update_job(job_id, status="error", message=f"DITOLAK SCOPE: {reason}", report=None)
            save_message(session_id, "agent", f"SCOPE REJECTED: {reason}")
            return

        update_job(job_id, status="running", message="Inisialisasi agents & model chain...")
        clear_execution_logs()

        # ── WAF Detection ─────────────────────────────────────────────────────
        try:
            waf_result = waf_detector.detect(target)
            waf_name = waf_result.get("waf", "None")
            waf_confidence = waf_result.get("confidence", "none")
            waf_strategy = waf_result.get("strategy", {})
            update_job(job_id, message=f"WAF detected: {waf_name} (confidence: {waf_confidence})")

            # Apply WAF strategy
            if waf_strategy.get("rate_limit"):
                from core.rate_limiter import rate_limiter
                rate_limiter.set_domain_rate(_domain_of(target), waf_strategy["rate_limit"])

            if _logger():
                _logger().add_log("Scan", "SUCCESS",
                    f"WAF: {waf_name} | Rate: {waf_strategy.get('rate_limit', 2.0)} req/s")
        except Exception as waf_err:
            update_job(job_id, message=f"WAF detection skipped: {waf_err}")
            waf_result = {"waf": "Unknown", "confidence": "none", "strategy": {}}

        # ── Scan History — compare with previous scan ─────────────────────────
        try:
            comparison = scan_history.compare(target, [])
            if comparison.get("has_previous_scan"):
                update_job(job_id, message=f"Previous scan found: {comparison.get('previous_total', 0)} findings. Trend: {comparison.get('severity_trend', 'unknown')}")
        except Exception:
            pass

        # ── Pre-provided credentials ───────────────────────────────────────────
        if credentials:
            domain = _domain_of(target)
            mode = credentials.get("mode", "")
            if mode == "credentials":
                update_job(job_id, status="running", message=f"Auto-login ke {domain}...")
                try:
                    from tools.playwright_tools import login_automator
                    login_result = login_automator.invoke({
                        "url": credentials.get("login_url", target),
                        "username": credentials.get("username", ""),
                        "password": credentials.get("password", ""),
                    })
                    update_job(job_id, message=f"Login result: {login_result[:200]}")
                except Exception as login_err:
                    update_job(job_id, message=f"Auto-login failed: {login_err}. Lanjut tanpa auth.")
            elif mode == "session":
                update_job(job_id, status="running", message=f"Injecting session untuk {domain}...")
                try:
                    from tools.playwright_tools import inject_session
                    inject_result = inject_session.invoke({
                        "url": target,
                        "cookies": credentials.get("cookies", ""),
                        "headers": json.dumps(credentials.get("headers", {})),
                    })
                    update_job(job_id, message=f"Session injected: {inject_result[:200]}")
                except Exception as inject_err:
                    update_job(job_id, message=f"Session injection failed: {inject_err}. Lanjut tanpa auth.")

        # Load intelligence lama
        memory_context = memory.build_context(target)

        # Build LLMs
        llm_recon = build_llm(agent_models.get("recon"))
        llm_analis = build_llm(agent_models.get("analis"))
        llm_eksekutor = build_llm(agent_models.get("eksekutor"))
        llm_assessor = build_llm(agent_models.get("assessor"))

        # Determine which phases to run
        phases = []
        if scan_config.get("recon", True):
            phases.append("recon")
        if scan_config.get("exploitation", True):
            phases.extend(["analis", "eksekutor"])
        if scan_config.get("assessor", True):
            phases.append("assessor")
        if not phases:
            phases = ["recon", "analis", "eksekutor", "assessor"]

        # ── Phase-by-phase execution ──────────────────────────────────────────
        all_results = {}
        all_reports = []
        phase_names = {"recon": "Reconnaissance", "analis": "Vulnerability Analysis", "eksekutor": "Exploitation", "assessor": "Risk Assessment"}

        for phase_idx, phase in enumerate(phases):
            if cancellation_store.is_cancelled(job_id):
                break

            is_last_phase = (phase_idx == len(phases) - 1)
            update_job(job_id, status="running", message=f"Phase {phase_idx+1}/{len(phases)}: {phase_names.get(phase, phase)}...")

            if phase == "recon":
                agent = Agent(
                    role="Advanced Reconnaissance & Intel Gatherer",
                    goal="Deep recon: infrastruktur, tech-stack, WAF, DNS, SSL, browser-based surface mapping.",
                    backstory="Intel Red Team level elit." + (f"\n{memory_context}" if memory_context else ""),
                    llm=llm_recon,
                    tools=[langchain_to_crewai(t) for t in [
                        recon_target, enumerate_dns_subdomains, analyze_ssl_tls,
                        browser_screenshot, browser_extract_surface,
                        browser_intercept_requests, browser_check_security_headers,
                        browser_extract_js_secrets, analyze_js_deep,
                        param_discovery_get, param_discovery_headers,
                        detect_subdomain_takeover, report_new_endpoint, wayback_scraper, github_dorking,
                        recon_advanced, misconfiguration_scanner,
                        client_side_security_scanner, mixed_content_scanner, asn_ip_mapper,
                        postmessage_vulnerability_scanner, shodan_scanner, censys_scanner,
                    ]],
                    verbose=True
                )
                task = Task(
                    description=f"Active Recon target: {target}. Petakan ports, tech-stack, WAF, DNS, SSL, cloud assets, JS secrets.",
                    expected_output="Laporan intelijen infrastruktur lengkap dalam format GFM markdown.",
                    agent=agent
                )
            elif phase == "analis":
                agent = Agent(
                    role="Senior Vulnerability Strategist",
                    goal="Rancang payload presisi berdasarkan intel recon.",
                    backstory="Mastermind eksploitasi. Payload-nya surgical, WAF-aware.",
                    llm=llm_analis,
                    tools=[langchain_to_crewai(t) for t in [
                        baca_log_burp, scan_sql_injection, detect_xss_csrf,
                        scan_lfi_rfi, test_header_injection,
                        browser_simulate_form, browser_find_open_redirect,
                        param_discovery_post, run_nuclei_scan,
                        report_new_endpoint, graphql_tester, cors_tester, ssti_tester,
                        blind_sqli_scanner, nosql_injection_scanner,
                        ldap_injection_scanner, xpath_injection_scanner,
                        stored_xss_scanner, dom_xss_scanner, jsonp_injection_scanner,
                        access_control_scanner,
                        csrf_exploit_scanner, mass_assignment_scanner, http_method_tampering_scanner,
                        command_injection_scanner, log_injection_scanner, csv_injection_scanner,
                        prototype_pollution_scanner,
                        web_cache_poisoning_scanner, cache_deception_scanner, idor_uuid_scanner,
                        # New scanners (2026 Benchmark)
                        html_injection_scanner, ssi_injection_scanner, hpp_scanner,
                    ]],
                    verbose=True
                )
                recon_ctx = all_results.get("recon", "")[:1000]
                task = Task(
                    description=f"Target: {target} | Goal: {goal}\nBerdasarkan recon:\n{recon_ctx}\n\nTest semua injection vectors: SQLi, XSS, LFI, Header Injection.",
                    expected_output="Daftar vulnerabilities dalam format GFM markdown.",
                    agent=agent
                )
            elif phase == "eksekutor":
                agent = Agent(
                    role="Active Exploit Executor",
                    goal="Eksekusi payload, test API, SSRF, IDOR.",
                    backstory="Eksekutor berdarah dingin. Expert di SSRF dan IDOR.",
                    llm=llm_eksekutor,
                    tools=[langchain_to_crewai(t) for t in [
                        tembak_payload, test_api_security, analyze_password_strength,
                        scan_ssrf, scan_idor, test_jwt_weakness, test_auth_rate_limiting,
                        report_new_endpoint, oauth_flow_tester, xxe_tester,
                        session_management_scanner, password_reset_tester,
                        host_header_injection_scanner, race_condition_scanner,
                        file_upload_scanner, http_request_smuggling_scanner,
                        websocket_security_scanner, email_header_injection_scanner,
                        insecure_deserialization_scanner, ssrf_advanced_scanner,
                        twofa_bypass_scanner, credential_stuffing_scanner,
                        # New scanners (2026 Benchmark)
                        password_storage_analyzer, credential_reuse_scanner,
                    ]],
                    verbose=True
                )
                analis_ctx = all_results.get("analis", "")[:1000]
                task = Task(
                    description=f"Target: {target}\nEksekusi attack vectors dari Analis:\n{analis_ctx}\n\nTest API endpoints, SSRF, IDOR, auth bypass.",
                    expected_output="Log eksekusi dalam format GFM markdown.",
                    agent=agent
                )
            elif phase == "assessor":
                agent = Agent(
                    role="Chief Information Security Officer (CISO)",
                    goal="Risk assessment dan laporan eksekutif.",
                    backstory="Ahli CIA Triad + CVSS scoring.",
                    llm=llm_assessor,
                    verbose=True
                )
                prev_ctx = "\n\n".join([
                    f"### Recon:\n{all_results.get('recon', 'N/A')[:500]}",
                    f"### Analysis:\n{all_results.get('analis', 'N/A')[:500]}",
                    f"### Exploitation:\n{all_results.get('eksekutor', 'N/A')[:500]}",
                ])
                task = Task(
                    description=f"Analisis semua findings untuk {target}:\n{prev_ctx}\n\nBuat laporan GFM markdown. Jangan gunakan ASCII art. Setiap vulnerability harus punya section terpisah dengan metadata lengkap (CWE-ID, CVSS vector, severity, steps to reproduce, PoC). Gunakan tabel markdown, bullet points, dan blockquote (>).",
                    expected_output="Laporan eksekutif risk assessment dalam format GFM markdown.",
                    agent=agent
                )

            # Run single agent
            try:
                crew = Crew(agents=[agent], tasks=[task], verbose=True)
                result = crew.kickoff()
                result_str = str(result)
                all_results[phase] = result_str
                all_reports.append(f"## Phase: {phase_names.get(phase, phase)}\n\n{result_str}")
                save_message(session_id, "agent", f"[Phase {phase_idx+1}/{len(phases)} - {phase_names.get(phase, phase)} Selesai]\n\n{result_str[:2000]}")
                update_job(job_id, message=f"Phase {phase_idx+1}/{len(phases)} selesai: {phase_names.get(phase, phase)}")
            except Exception as phase_err:
                update_job(job_id, message=f"Error di phase {phase}: {phase_err}")
                all_results[phase] = f"Error: {phase_err}"

            # Pause between phases (skip if auto_pilot)
            if not is_last_phase and not cancellation_store.is_cancelled(job_id):
                if auto_pilot:
                    update_job(job_id, status="running", message=f"Phase {phase_names.get(phase, phase)} selesai. Auto-Pilot: continuing...")
                    # Auto-approve, no pause
                else:
                    update_job(job_id, status="waiting_continue", message=f"Phase {phase_names.get(phase, phase)} selesai. Klik 'Continue' untuk lanjut.")
                    approved = continue_store.request_continue(job_id)
                    if not approved:
                        update_job(job_id, status="cancelled", message="Cancelled oleh user.")
                        save_message(session_id, "agent", "JOB DIBATALKAN oleh user.")
                        return

        # ── Finalize ──────────────────────────────────────────────────────────
        raw_report = "\n\n---\n\n".join(all_reports) if all_reports else "Not ada results."

        # Post-process: generate full professional report dari phase results
        try:
            from tools.report_generator import ReportGenerator
            gen = ReportGenerator()
            report = gen.generate_from_phase_results(
                phase_results=all_results,
                target=target,
            )
        except Exception as report_err:
            print(f"[REPORT] Generate failed (non-critical): {report_err}")
            report = raw_report

        logs_data = get_execution_logs()

        if cancellation_store.is_cancelled(job_id):
            save_message(session_id, "agent", "JOB DIBATALKAN oleh user.")
            update_job(job_id, status="cancelled", message="Cancelled oleh user.", logs=logs_data["logs"], summary=logs_data["summary"])
        else:
            save_message(session_id, "agent", report)
            update_job(job_id, status="done", message="Selesai.", report=report, logs=logs_data["logs"], summary=logs_data["summary"])

            # ── Save scan history ─────────────────────────────────────────────
            try:
                scan_history.save(
                    target=target,
                    findings=[],  # Findings dari phase results
                    session_id=session_id,
                    summary={"waf": waf_result.get("waf", "Unknown"), "phases": list(all_results.keys())},
                )
            except Exception as hist_err:
                print(f"[HISTORY] Save failed (non-critical): {hist_err}")

            # ── Save to memory ────────────────────────────────────────────────
            try:
                memory.save_findings_from_report(target, report, session_id)
            except Exception as mem_err:
                print(f"[MEMORY] Auto-save failed (non-critical): {mem_err}")

            # ── Save report to persistent file storage ──────────────────────────
            try:
                report_dir = "/app/reports"
                os.makedirs(report_dir, exist_ok=True)
                report_file = os.path.join(report_dir, f"{session_id}_{job_id[:8]}.md")
                with open(report_file, "w", encoding="utf-8") as f:
                    f.write(report)
                print(f"[REPORT] Saved to {report_file}")
            except Exception as file_err:
                print(f"[REPORT] File save failed (non-critical): {file_err}")

    except Exception as e:
        err = str(e)
        save_message(session_id, "agent", f"ERROR: {err}")
        update_job(job_id, status="error", message=err, report=None)
    finally:
        cancellation_store.cleanup(job_id)
        auth_store.clear_all()
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
        raise HTTPException(status_code=400, detail="Pattern not boleh kosong.")
    if not req.program_name.strip():
        raise HTTPException(status_code=400, detail="Program name not boleh kosong.")
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


@app.delete("/sessions/{session_id}")
async def delete_session(session_id: str, _: bool = Depends(require_api_key)):
    """Hapus session dan semua chat messages terkait."""
    try:
        # Hapus chat messages dulu
        supabase.table("chat_messages").delete().eq("session_id", session_id).execute()
        # Hapus session
        supabase.table("sessions").delete().eq("id", session_id).execute()
        return {"ok": True, "deleted": session_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/pentest")
async def start_pentest(req: PentestRequest, background_tasks: BackgroundTasks, _: bool = Depends(require_api_key)):
    """
    Langsung return job_id. Pentest jalan di background.
    Frontend poll /job/{job_id} atau stream dari /job/{job_id}/stream.
    """
    # Cek scope DULU senot yet bikin session/job apapun — fail fast, jangan
    # nunggu sampai background job jalan baru ketauan rejected.
    allowed, reason = validate_target(req.target, supabase)
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Target out of scope: {reason}")

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
        run_pentest_job, job_id, req.target, req.goal, session_id, req.agent_models, req.credentials, req.scan_config
    )

    return {"job_id": job_id, "session_id": session_id, "status": "queued", "stream_token": stream_token}


@app.get("/job/{job_id}")
async def get_job(job_id: str, _: bool = Depends(require_api_key)):
    """Poll status job."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.post("/job/{job_id}/cancel")
async def cancel_job(job_id: str, _: bool = Depends(require_api_key)):
    """
    Cancel job yang lagi jalan. Set cancellation token yang dicek oleh setiap
    tool senot yet eksekusi — tool yang not yet jalan akan berhenti, tool yang
    currently berjalan akan selesai dulu baru berhenti di tool berikutnya.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]
    if job.get("status") not in ("queued", "running", "waiting_hitl", "waiting_continue"):
        raise HTTPException(
            status_code=400,
            detail=f"Job not bisa di-cancel, status saat ini: {job.get('status')}"
        )

    # Kalau lagi nunggu HITL/continue, auto-reject dulu biar thread gak stuck
    checkpoint_store.respond(job_id, False)
    continue_store.respond(job_id, False)

    cancelled = cancellation_store.cancel(job_id)
    if cancelled:
        update_job(job_id, status="cancelling", message="Waiting tool selesai lalu berhenti...")

    return {"ok": cancelled, "job_id": job_id}


@app.post("/job/{job_id}/continue")
async def continue_job(job_id: str, _: bool = Depends(require_api_key)):
    """
    Continue job setelah phase selesai. User klik 'Continue' di frontend.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]
    if job.get("status") != "waiting_continue":
        raise HTTPException(
            status_code=400,
            detail=f"Job not dalam status waiting_continue. Status: {job.get('status')}"
        )

    ok = continue_store.respond(job_id, True)
    if ok:
        update_job(job_id, status="running", message="Continuing ke phase berikutnya...")

    return {"ok": ok, "job_id": job_id}


@app.get("/job/{job_id}/stream")
async def stream_job(job_id: str, token: Optional[str] = None):
    """
    SSE endpoint. Diprotect pakai query param `?token=` karena EventSource
    browser gak bisa kirim custom header. Token di-generate waktu POST /pentest
    dan sent balik ke frontend di response body.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]
    stored_token = job.get("stream_token")
    if stored_token and (not token or not secrets.compare_digest(token, stored_token)):
        raise HTTPException(status_code=401, detail="Stream token not valid.")

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

                # Include checkpoint dan auth_request kalau ada
                if job.get("checkpoint"):
                    payload["checkpoint"] = job["checkpoint"]
                if job.get("auth_request"):
                    payload["auth_request"] = job["auth_request"]

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
    detail aksi apa yang mau running.
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
        raise HTTPException(status_code=404, detail="Not ada checkpoint aktif untuk job_id ini")
    return {"ok": True, "approved": data.approved}


@app.post("/auth/respond")
async def respond_auth(data: AuthResponse, _: bool = Depends(require_api_key)):
    """
    Frontend kirim credentials atau session cookies ke sini.
    Ini langsung set threading.Event yang lagi di-`wait()` oleh worker thread.
    """
    # Build auth_data dict
    auth_data = {
        "mode": data.mode,
    }

    if data.mode == "credentials":
        auth_data["username"] = data.username
        auth_data["password"] = data.password
        auth_data["login_url"] = data.login_url
    elif data.mode == "session":
        auth_data["cookies"] = data.cookies
        auth_data["headers"] = data.headers or {}
    else:
        raise HTTPException(status_code=400, detail="mode harus 'credentials' atau 'session'")

    ok = auth_checkpoint_store.respond(data.job_id, auth_data)
    if not ok:
        raise HTTPException(status_code=404, detail="Not ada auth request aktif untuk job_id ini")
    return {"ok": True, "mode": data.mode}


@app.get("/auth/pending/{job_id}")
async def get_pending_auth(job_id: str, _: bool = Depends(require_api_key)):
    """Frontend poll ini buat cek apakah ada auth request yang pending."""
    pending = auth_checkpoint_store.get_pending(job_id)
    if not pending:
        return {"waiting": False}
    return {"waiting": True, **{k: v for k, v in pending.items() if k != "event"}}


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
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]
    if job.get("status") != "done" or not job.get("report"):
        raise HTTPException(status_code=400, detail="Report not yet tersedia. Tunggu job selesai.")

    target = job.get("target", "Unknown")
    goal = job.get("goal", "Unknown")
    created_at = job.get("created_at", "")[:10]
    raw_report = job.get("report", "")
    logs = job.get("logs", [])
    summary = job.get("summary", {})

    # Ringkasan tools yang executed
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


@app.get("/job/{job_id}/export")
async def export_report(job_id: str, format: str = "md", _: bool = Depends(require_api_key)):
    """
    Export report in multiple formats: md, pdf, docx.
    Query param: ?format=md|pdf|docx
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]
    if job.get("status") != "done" or not job.get("report"):
        raise HTTPException(status_code=400, detail="Report not yet available.")

    from tools.report_export import ReportExporter
    from fastapi.responses import Response as FastAPIResponse

    exporter = ReportExporter()
    report_data = {
        "target": job.get("target", "Unknown"),
        "findings": [],
        "phases": {"recon": job.get("report", "")[:2000]},
    }

    try:
        if format == "pdf":
            pdf_bytes = exporter.to_pdf(report_data)
            return FastAPIResponse(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="nexus-report-{job_id[:8]}.pdf"'},
            )
        elif format == "docx":
            docx_bytes = exporter.to_docx(report_data)
            return FastAPIResponse(
                content=docx_bytes,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": f'attachment; filename="nexus-report-{job_id[:8]}.docx"'},
            )
        else:
            md = exporter.to_markdown(report_data)
            return FastAPIResponse(
                content=md,
                media_type="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="nexus-report-{job_id[:8]}.md"'},
            )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

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
        raise HTTPException(status_code=404, detail="Job queue not aktif atau already selesai.")

    state = ACTIVE_QUEUE_SESSIONS[job_id]
    new_url = req.url.strip()

    if new_url in state.visited_targets:
        return {"status": "ignored", "message": "Target already masuk antrean atau already discan."}

    asyncio.run_coroutine_threadsafe(state.queue.put(new_url), asyncio.get_event_loop())
    update_job(job_id, message=f"Adding target baru dari {req.source}: {new_url}")

    return {"status": "success", "message": f"Target {new_url} success added ke antrean pool."}
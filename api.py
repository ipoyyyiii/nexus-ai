import os
from dotenv import load_dotenv

load_dotenv()

import uuid
import asyncio
import json
from core.target_state import set_target_state
from core.interactive_flow import run_phase1, run_phase2_interactive, run_phase3
import secrets
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
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
from core.model_registry import build_llm, build_chat_llm, list_available_models, chain_summary
from core.session_store import SessionStore, SESSION_CONTEXT_SQL
from core.chat_orchestrator import ChatOrchestrator
from core.workflow_planner import WorkflowPlanner
from core.workflow_models import ActionProposal
from core.execution_guard import ExecutionGuard
from core.evidence_service import EvidenceService
from core.lifecycle_service import LifecycleService
from core.workflow_dispatch import WorkflowDispatcher
from core.tool_adapter import ToolOutputAdapter
from core.structured_contract import ObservationV1, ToolResultV1
from core.structured_repository import StructuredRepository
from core.authorization_contract import (
    AuthContextV1,
    AuthorizationExpectationV1,
    AuthorizationReplayRunV1,
    IdentityV1,
    RequestTemplateV1,
    ResourceInstanceV1,
)
from core.authorization_repository import AuthorizationRepository
from core.redact import redact
from core.authorization_engine import AuthorizationReplayEngine
from core.authorization_discovery import capture_to_contracts
from core.secret_vault import SecretVault
from core.validation_engine import validation_engine
from core.detection_validation_api import register_detection_validation_routes
from core.identity_context import ToolExecutionContext, set_execution_context, reset_execution_context
from core.chain_planner import ChainPlanner
from core.impact_service import ImpactService
from core.cleanup_registry import cleanup_registry
from core.retest_service import RetestService
from core.workflow_report import WorkflowReport
from core.artifact_store import ArtifactStore
from core.browser_workflow_contract import (
    BrowserRunV1, BrowserStepV1, BrowserWorkflowV1, BusinessInvariantV1,
)
from core.browser_workflow_repository import BrowserWorkflowRepository
from core.browser_workflow_runner import StatefulBrowserRunner
from core.business_logic_engine import RULE_REGISTRY, business_invariant_compiler, business_invariant_engine
from core.workflow_discovery import workflow_discovery_service
from core.config_loader import get_setting, get_config
from core.execution_contract import ExecutionJobV1, ResourceBudgetV1, stable_digest
from core.durable_execution import DurableExecutionRepository
from core.evaluation_engine import EvaluationEngine
from core.evaluation_repository import EvaluationRepository
from core.evaluation_api import register_evaluation_routes
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

import litellm
litellm._turn_on_debug()

# Suppress LiteLLM cost calculation warnings for unmapped models
import logging
litellm_logger = logging.getLogger("litellm")
litellm_logger.setLevel(logging.ERROR)  # Only show errors, not warnings

if os.environ.get("OPENROUTER_API_KEY"):
    os.environ["OPENAI_API_KEY"] = os.environ.get("OPENROUTER_API_KEY")
    os.environ["OPENAI_API_BASE"] = "https://openrouter.ai/api/v1"
    os.environ["OPENAI_BASE_URL"] = "https://openrouter.ai/api/v1"

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)
durable_execution_repository = DurableExecutionRepository(supabase)
evaluation_engine = EvaluationEngine()
evaluation_repository = EvaluationRepository(supabase)
memory = SessionMemory(supabase)
session_store = SessionStore(supabase)
chat_orchestrator = ChatOrchestrator(session_store, supabase)
workflow_planner = WorkflowPlanner(session_store)
execution_guard = ExecutionGuard(session_store)
evidence_service = EvidenceService(session_store)
lifecycle_service = LifecycleService(session_store)
tool_adapter = ToolOutputAdapter()
structured_repository = StructuredRepository(session_store)
authorization_repository = AuthorizationRepository(session_store)
browser_workflow_repository = BrowserWorkflowRepository(supabase)
browser_artifact_store = ArtifactStore(supabase)
stateful_browser_runner = StatefulBrowserRunner(
    session_store, browser_workflow_repository, browser_artifact_store
)
secret_vault = SecretVault(supabase, int(get_setting("auth_secret_ttl_minutes", 240)))
chain_planner = ChainPlanner(session_store)
impact_service = ImpactService(session_store, chain_planner)
retest_service = RetestService(session_store, evidence_service)
workflow_report = WorkflowReport(session_store)

app = FastAPI(title="Nexus AI Pentest API", version="6.1 - Hardened Edition")

def langchain_to_crewai(lc_tool):
    """Compatibility wrapper; interactive flows use the session-bound runner."""
    from core.structured_runner import structured_crewai_tool
    return structured_crewai_tool(lc_tool, target="", category="api")

# ============================================================
# API KEY AUTH
# Set NEXUS_API_KEY di .env. Semua endpoint sensitif butuh header
# `X-API-Key`. Kalau NEXUS_API_KEY gak set sama sekali, server
# REFUSE TO START with auth kosong (biar gak ke-deploy tanpa sadar
# tanpa proteksi apapun) — kecuali eksplisit di-allow lewat
# NEXUS_ALLOW_NO_AUTH=true (cuma for dev lokal).
# ============================================================
NEXUS_API_KEY = os.environ.get("NEXUS_API_KEY")
ALLOW_NO_AUTH = os.environ.get("NEXUS_ALLOW_NO_AUTH", "false").lower() == "true"

if not NEXUS_API_KEY and not ALLOW_NO_AUTH:
    raise RuntimeError(
        "NEXUS_API_KEY not yet set di .env. Generate satu (mis. python -c "
        "\"import secrets; print(secrets.token_hex(32))\") lalu set NEXUS_API_KEY=<hasilnya>. "
        "Kalau this cuma dev lokal dan sengaja mau tanpa auth, set NEXUS_ALLOW_NO_AUTH=true."
    )

async def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if ALLOW_NO_AUTH and not NEXUS_API_KEY:
        return True
    if not x_api_key or not secrets.compare_digest(x_api_key, NEXUS_API_KEY or ""):
        raise HTTPException(status_code=401, detail="API key not valid. Kirim header X-API-Key.")
    return True


# Stage 6 evaluation routes are registered after API-key auth exists, but
# before the legacy endpoint block.
evaluation_route_memory = register_evaluation_routes(
    app, require_api_key, evaluation_engine, evaluation_repository,
    durable_execution_repository, get_setting,
)

detection_validation_route_memory = register_detection_validation_routes(
    app, require_api_key, structured_repository, session_store, supabase,
)

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
# Di production ganti with Redis.
# ============================================================
jobs: Dict[str, Dict[str, Any]] = {}
workflow_dispatcher = WorkflowDispatcher(session_store, execution_guard, jobs)

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
        message=f"Login wall terdeteksi di {domain}. Waiting credentials/session from user.",
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
# CONTINUE STORE — for phase-by-phase execution
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
    # Per-agent model override from frontend. Key: "recon" | "analis" | "eksekutor" | "assessor"
    # Value: model_id from model_registry.py (mis. "claude-sonnet", "glm-4.5-air-free"), atau
    # None/gak diisi -> default fallback chain (paid dulu, baru free kalau failed).
    agent_models: Optional[Dict[str, Optional[str]]] = None
    # Auth credentials (opsional). Kalau diisi, auto-login senot yet scan dimulai.
    credentials: Optional[Dict[str, Any]] = None
    # Scan configuration — phases mana that mau running
    scan_config: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None

class SessionSetupRequest(BaseModel):
    target: str
    goal: str
    scope_rules: list[Dict[str, Any]]
    authorization_confirmed: bool
    model_id: Optional[str] = None
    scan_preset: Optional[str] = None
    vuln_types: Optional[List[str]] = None


class ChatMessageRequest(BaseModel):
    content: str
    model_id: Optional[str] = None
    message_id: Optional[str] = None
    parent_message_id: Optional[str] = None


class ChatCancelRequest(BaseModel):
    message_id: str


class WorkflowPlanRequest(BaseModel):
    request: str = ""


class WorkflowTransitionRequest(BaseModel):
    phase: str


class WorkflowDecisionRequest(BaseModel):
    reviewer_note: str = ""
    dispatch: bool = True


class CleanupRequest(BaseModel):
    description: str
    action: str
    source_action_id: str = ""


class CleanupCompleteRequest(BaseModel):
    result: str
    success: bool


class RetestStartRequest(BaseModel):
    finding_id: str


class ChainPlanRequest(BaseModel):
    objective: str = ""


class EvidenceReviewRequest(BaseModel):
    confirmed: bool


class ImpactResultRequest(BaseModel):
    action_id: str
    before: str
    after: str
    success: bool


class CleanupExecuteRequest(BaseModel):
    handler_name: str
    context: Dict[str, Any] = {}


class RetestRecordRequest(BaseModel):
    status: str
    comparison: str
    evidence: Dict[str, Any] = {}


class EvidenceRequest(BaseModel):
    source: str
    summary: str
    target_url: str = ""
    method: str = "GET"
    request: str = ""
    response: str = ""
    confidence: str = "medium"
    tool_run_id: str = ""


class CandidateReviewRequest(BaseModel):
    decision: str
    reason: str
    reviewer: str = "api"


class BrowserWorkflowCreateRequest(BaseModel):
    name: str
    origin: str
    goal: str = ""
    identity_requirements: List[str] = Field(default_factory=list)
    input_schema: Dict[str, Any] = Field(default_factory=dict)
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    preconditions: List[Dict[str, Any]] = Field(default_factory=list)
    postconditions: List[Dict[str, Any]] = Field(default_factory=list)
    cleanup_step_ids: List[str] = Field(default_factory=list)
    source_observation_ids: List[str] = Field(default_factory=list)


class BrowserDiscoveryRequest(BaseModel):
    origin: str
    goal: str = ""
    captures: List[Dict[str, Any]] = Field(default_factory=list)
    identity_ids: List[str] = Field(default_factory=list)


class BrowserRunRequest(BaseModel):
    workflow_id: str
    identity_id: str = ""
    auth_context_id: str = ""
    role: str = "baseline"
    bindings: Dict[str, Any] = Field(default_factory=dict)
    approval_action_id: str = ""
    approved: bool = False
    approval_digest: str = ""
    parent_run_id: str = ""


class BrowserResumeRequest(BaseModel):
    approval_action_id: str = ""
    bindings: Dict[str, Any] = Field(default_factory=dict)
    approved: bool = False
    approval_digest: str = ""


class BusinessInvariantCreateRequest(BaseModel):
    name: str
    rule_type: str = ""
    rule_version: str = "1.0"
    source: str = "operator"
    rule: Dict[str, Any] = Field(default_factory=dict)
    required_workflow_ids: List[str] = Field(default_factory=list)
    required_identity_ids: List[str] = Field(default_factory=list)
    source_observation_ids: List[str] = Field(default_factory=list)


class BusinessInvariantEvaluateRequest(BaseModel):
    transitions: List[Dict[str, Any]] = Field(default_factory=list)
    runs: List[Dict[str, Any]] = Field(default_factory=list)
    observations: List[Dict[str, Any]] = Field(default_factory=list)


class IdentityCreateRequest(BaseModel):
    label: str
    kind: str = "user"
    source: str = "user_session"
    role_label: str = ""
    tenant_label: str = ""
    metadata: Dict[str, Any] = {}


class AuthContextCreateRequest(BaseModel):
    origin: str
    auth_type: str = "cookie"
    # Write-only secret payload. It is never returned after this request.
    secret: Dict[str, Any] = {}
    ttl_minutes: Optional[int] = None


class AuthorizationExpectationRequest(BaseModel):
    subject_identity_id: str
    resource_fingerprint: str
    action: str
    expected: str = "deny"
    source: str = "user_asserted"
    reason: str = ""


class RequestTemplateRequest(BaseModel):
    origin: str
    method: str = "GET"
    path_template: str
    query_template: Dict[str, Any] = {}
    body_template: Any = None
    header_template: Dict[str, str] = {}
    variable_bindings: Dict[str, Dict[str, Any]] = {}
    operation_name: str = ""
    protocol: str = "http"
    side_effect_class: str = "unknown"
    source_observation_ids: List[str] = []


class AuthorizationDiscoveryRequest(BaseModel):
    identity_id: str
    captures: List[Dict[str, Any]] = []
    source_observation_ids: List[str] = []


class ResourceInstanceRequest(BaseModel):
    resource_type: str
    origin: str
    locator_redacted: Any = None
    locator_ref: str = ""
    owner_identity_id: str = ""
    tenant_label: str = ""
    private_canary: bool = False
    source_observation_ids: List[str] = []
    metadata: Dict[str, Any] = {}


class AuthorizationReplayRequest(BaseModel):
    template_id: str
    resource_fingerprint: str
    owner_identity_id: str
    test_identity_ids: List[str]
    bindings: Dict[str, Any] = {}
    approved: bool = False


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
        try:
            session_store.save_job(jobs[job_id])
        except Exception as persist_err:
            print(f"[WORKFLOW] Job persistence warning: {persist_err}")


def _execution_mode() -> str:
    return str(get_setting("execution_platform_mode", "shadow")).lower()


def _execution_budget() -> ResourceBudgetV1:
    safety = get_setting("safety", {}) or {}
    race = get_setting("race_engine", {}) or {}
    return ResourceBudgetV1(
        max_requests=int(safety.get("max_requests_per_job", 20000)),
        max_download_bytes=int(safety.get("max_download_bytes", 512 * 1024 * 1024)),
        max_response_bytes=int(safety.get("max_response_bytes", 2 * 1024 * 1024)),
        max_upload_bytes=int(safety.get("max_upload_bytes", 10 * 1024 * 1024)),
        max_credential_attempts=int(safety.get("max_credential_attempts", 10)),
        requests_per_second=float(safety.get("requests_per_second", 2.0)),
        burst=int(safety.get("burst", 4)),
        browser_concurrency=1,
        cli_concurrency=1,
        race_concurrency=min(8, int(race.get("max_concurrency", 8))),
    )


def _enqueue_execution_job(
    job_id: str,
    session_id: str,
    target: str,
    goal: str,
    job_type: str,
    payload: Optional[Dict[str, Any]] = None,
    risk: str = "read_only",
    approval_ref: str = "",
    idempotency_key: str = "",
) -> ExecutionJobV1:
    execution = get_setting("execution", {}) or {}
    attempt_key = "max_attempts_mutation" if risk != "read_only" else "max_attempts_read_only"
    max_attempts = max(1, int(execution.get(attempt_key, 1 if risk != "read_only" else 3)))
    job = ExecutionJobV1(
        job_id=job_id,
        session_id=session_id,
        job_type=job_type,
        target=target,
        goal=goal,
        payload_redacted=payload or {},
        config_snapshot=get_config(),
        idempotency_key=idempotency_key or stable_digest({
            "session_id": session_id, "job_type": job_type, "target": target,
            "goal": goal, "payload": payload or {},
        }, 40),
        risk=risk,
        approval_ref=approval_ref,
        budget=_execution_budget(),
        max_attempts=max_attempts,
    )
    try:
        durable_execution_repository.enqueue(job)
    except Exception as exc:
        if _execution_mode() == "strict":
            raise RuntimeError(f"Durable execution queue unavailable: {exc}") from exc
        print(f"[DURABLE] shadow enqueue skipped: {type(exc).__name__}: {exc}")
    return job


def _legacy_job_view(job: Dict[str, Any]) -> Dict[str, Any]:
    view = dict(job)
    view["status"] = {"succeeded": "done", "failed": "error", "dead_lettered": "error"}.get(
        str(view.get("status", "")), view.get("status")
    )
    view.setdefault("message", view.get("error_message", ""))
    return view


def _ingest_phase_result(session_id: str, target: str, phase: str, output: str, run_id: str):
    """Persist phase narrative as observation only.

    Final LLM phase text is not authoritative evidence and can no longer
    create findings through severity regex parsing.
    """
    try:
        observation = ObservationV1(
            role="external",
            kind="phase_narrative",
            summary=f"Phase {phase} completed; structured tool runs contain authoritative evidence.",
            target_url=target,
            response_excerpt=output[:8000],
            metadata={"phase": phase, "narrative_only": True},
        )
        result = ToolResultV1(
            tool_run_id=f"phase_{phase}_{run_id}",
            tool_name=f"phase:{phase}",
            category="phase_narrative",
            target=target,
            summary=output[:4000],
            observations=[observation],
        )
        structured_repository.persist(session_id, result, [])
        return {"tool_run_id": result.tool_run_id, "observation_id": observation.observation_id}
    except Exception as exc:
        print(f"[WORKFLOW] Phase narrative ingestion skipped: {exc}")
        return None


# ============================================================
# BACKGROUND PENTEST RUNNER
# Ini that dulu blocking sekarang jalan di background thread.
# ============================================================
def run_pentest_job(job_id: str, target: str, goal: str, session_id: str, agent_models: Optional[Dict[str, Optional[str]]] = None, credentials: Optional[Dict[str, Any]] = None, scan_config: Optional[Dict[str, Any]] = None, attempt_id: str = "", budget: Optional[Dict[str, Any]] = None, worker_capabilities: tuple[str, ...] = (), execution_repository: Any = None):
    """
    Phase-by-phase execution: Recon -> Analis -> Eksekutor -> Assessor.
    Sealready setiap phase, pause dan tunggu user klik "Continue".
    Auto-Pilot mode: skip manual approval, auto-continue.
    """
    agent_models = agent_models or {}
    scan_config = scan_config or {}
    auto_pilot = scan_config.get("auto_pilot", False)
    stealth_mode = scan_config.get("stealth_mode", False)
    
    # Modes and budgets are immutable per-job context, never process-global state.
    from core.safety_kernel import SafetyKernel
    budget_contract = ResourceBudgetV1(**(budget or {}))
    safety_repository = execution_repository or durable_execution_repository
    execution_token = set_execution_context(ToolExecutionContext(
        session_id=session_id, job_id=job_id, identity_id="primary", target_origin=target,
        attempt_id=attempt_id, tool_name="pentest_job",
        auto_pilot=bool(auto_pilot), stealth_mode=bool(stealth_mode),
        budget=budget_contract, config_snapshot=dict(scan_config),
        safety_kernel=SafetyKernel(session_store=session_store, repository=safety_repository),
        repository=structured_repository,
        secret_vault=secret_vault,
        worker_capabilities=tuple(worker_capabilities),
    ))
    try:
        authorization_repository.create_identity(session_id, IdentityV1(
            session_id=session_id, label="primary", kind="user", source="user_session", status="pending",
        ))
    except Exception:
        # Existing deployments can finish the additive migration separately;
        # the runtime context remains safe and isolated even while persistence
        # is unavailable.
        pass
    
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
                    login_summary = login_result.llm_summary() if hasattr(login_result, "llm_summary") else str(login_result)
                    update_job(job_id, message=f"Login result: {login_summary[:200]}")
                except Exception as login_err:
                    update_job(job_id, message=f"Auto-login failed: {login_err}. Lanjut tanpa auth.")
            elif mode == "session":
                update_job(job_id, status="running", message=f"Injecting session for {domain}...")
                try:
                    from tools.playwright_tools import inject_session
                    inject_result = inject_session.invoke({
                        "url": target,
                        "cookies": credentials.get("cookies", ""),
                        "headers": json.dumps(credentials.get("headers", {})),
                    })
                    inject_summary = inject_result.llm_summary() if hasattr(inject_result, "llm_summary") else str(inject_result)
                    update_job(job_id, message=f"Session injected: {inject_summary[:200]}")
                except Exception as inject_err:
                    update_job(job_id, message=f"Session injection failed: {inject_err}. Lanjut tanpa auth.")

        # Load intelligence lama
        memory_context = memory.build_context(target)

        # Build LLMs
        llm_recon = build_llm(agent_models.get("recon"))
        llm_analis = build_llm(agent_models.get("analis"))
        llm_eksekutor = build_llm(agent_models.get("eksekutor"))
        llm_assessor = build_llm(agent_models.get("assessor"))

        # ── Initialize Target State ────────────────────────────────────────────
        target_state = session_store.load_state(session_id)
        target_state.url = target
        target_state.goal = goal
        set_target_state(target_state)
        target_state.scan_start = datetime.now().isoformat()

        # ── Phase 1: Automated Data Gathering (Recon & Vuln) ─────────────────
        all_results = {}
        all_reports = []
        
        preset = scan_config.get("scan_preset") or session_store.get(session_id, {}).get("scan_preset", "full")
        phase1_success = run_phase1(
            job_id=job_id,
            session_id=session_id,
            target=target,
            goal=goal,
            memory_context=memory_context,
            llm_recon=llm_recon,
            llm_analis=llm_analis,
            all_results=all_results,
            all_reports=all_reports,
            auto_pilot=auto_pilot,
            cancellation_store=cancellation_store,
            continue_store=continue_store,
            update_job=update_job,
            save_message=save_message,
            phase_filter=scan_config.get("phase_filter"),
            result_handler=lambda phase, output, run_id: _ingest_phase_result(session_id, target, phase, output, run_id),
            scan_preset=preset,
            recommended_tools=scan_config.get("recommended_tools"),
            planner_context=scan_config.get("planner_context"),
        )
        
        if not phase1_success:
            update_job(job_id, status="cancelled", message="Phase 1 cancelled by user.")
            save_message(session_id, "agent", "JOB CANCELLED by user during Phase 1.")
            return

        # ── Phase 2: Interactive Consultation (Co-Pilot Chat) ─────────────────
        phase2_success = run_phase2_interactive(
            job_id=job_id,
            session_id=session_id,
            target=target,
            auto_pilot=auto_pilot,
            cancellation_store=cancellation_store,
            continue_store=continue_store,
            update_job=update_job,
            save_message=save_message,
            jobs=jobs
        )
        
        if not phase2_success:
            update_job(job_id, status="cancelled", message="Phase 2 cancelled by user.")
            save_message(session_id, "agent", "JOB CANCELLED by user during Phase 2.")
            return

        # ── Phase 3: Automated Synthesis & Reporting ─────────────────────────
        if scan_config.get("assessor", True):
            run_phase3(
                job_id=job_id,
                session_id=session_id,
                target=target,
                all_results=all_results,
                all_reports=all_reports,
                llm_assessor=llm_assessor,
                cancellation_store=cancellation_store,
                update_job=update_job,
                save_message=save_message
            )

        # ── Finalize ──────────────────────────────────────────────────────────
        target_state.scan_end = datetime.now().isoformat()
        raw_report = "\n\n---\n\n".join(all_reports) if all_reports else "No results."

        # Structured evidence is authoritative in strict mode. The old LLM
        # report remains available only as a migration/shadow comparison.
        structured_mode = str(get_setting("structured_evidence_mode", "strict")).lower()
        if structured_mode == "shadow":
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
        else:
            try:
                report = workflow_report.generate(session_id)["markdown"]
            except Exception as report_err:
                print(f"[REPORT] Structured report failed: {report_err}")
                report = "# Structured report unavailable\n\nEvidence persistence or schema migration is not ready. No unvalidated LLM findings were promoted."

        logs_data = get_execution_logs()

        if cancellation_store.is_cancelled(job_id):
            save_message(session_id, "agent", "JOB CANCELLED by user.")
            update_job(job_id, status="cancelled", message="Cancelled by user.", logs=logs_data["logs"], summary=logs_data["summary"])
        else:
            save_message(session_id, "agent", report)
            update_job(job_id, status="done", message="Complete.", report=report, logs=logs_data["logs"], summary=logs_data["summary"])

            # ── Save scan history ─────────────────────────────────────────────
            try:
                scan_history.save(
                    target=target,
                    findings=[{**item.__dict__, "fingerprint": getattr(item, "fingerprint", "")} for item in session_store.load_state(session_id).workflow.findings if getattr(item, "status", "") in ("validated","impact_proven")],
                    session_id=session_id,
                    summary={"waf": waf_result.get("waf", "Unknown"), "phases": list(all_results.keys())},
                )
            except Exception as hist_err:
                print(f"[HISTORY] Save failed (non-critical): {hist_err}")

            # ── Save to memory ────────────────────────────────────────────────
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
        job_record = jobs.get(job_id, {})
        action_id = str(job_record.get("workflow_action_id") or "")
        terminal_status = str(job_record.get("status") or "")
        if action_id and terminal_status in {"done", "error", "cancelled"}:
            try:
                succeeded = terminal_status == "done"
                reason = "Approved action completed." if succeeded else str(job_record.get("message") or terminal_status)
                workflow_dispatcher.complete(
                    session_id, action_id, succeeded=succeeded, reason=reason,
                )
                plan = workflow_planner.propose(session_id, "Automatic replan after new execution evidence.")
                update_job(
                    job_id, next_proposals=plan.get("proposals", []),
                    next_hypotheses=plan.get("hypotheses", []), planner_finalized=True,
                )
            except Exception as planner_err:
                print(f"[PLANNER] Completion/replan warning: {planner_err}")
                update_job(job_id, planner_finalized=True, planner_error=str(redact(str(planner_err)))[:500])
        cancellation_store.cleanup(job_id)
        auth_store.clear_for_job(job_id)
        auth_store.clear_for_session(session_id)
        try:
            secret_vault.delete_for_session(session_id)
        except Exception:
            pass
        if job_id in ACTIVE_QUEUE_SESSIONS:
            del ACTIVE_QUEUE_SESSIONS[job_id]
        reset_execution_context(execution_token)


# ============================================================
# ENDPOINTS
# ============================================================

@app.post("/sessions")
async def create_interactive_session(req: SessionSetupRequest, _: bool = Depends(require_api_key)):
    try:
        preset = (req.scan_preset or "full").lower()
        if preset not in ("recon-only", "full"):
            preset = "full"
        vuln_types = getattr(req, "vuln_types", None) or []
        session = session_store.create(
            target_url=req.target,
            goal=req.goal,
            scope_rules=req.scope_rules,
            authorization_confirmed=req.authorization_confirmed,
            model_id=req.model_id,
        )
        try:
            authorization_repository.create_identity(session["session_id"], IdentityV1(
                session_id=session["session_id"], label="anonymous", kind="anonymous", source="system", status="active",
            ))
        except Exception:
            # The core session remains usable if the optional Stage 2
            # migration has not been applied yet.
            pass
        # Persist preset + vuln_types
        updates: dict = {}
        if preset != "full":
            updates["scan_preset"] = preset
        if vuln_types:
            updates["scan_vuln_types"] = vuln_types
        if updates:
            session_store.sb.table("session_context").update(updates).eq("session_id", session["session_id"]).execute()
            session.update(updates)
        return session
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/sessions/{session_id}/context")
async def get_session_context(session_id: str, _: bool = Depends(require_api_key)):
    context = session_store.get(session_id)
    if not context:
        raise HTTPException(status_code=404, detail="Session setup not found.")
    return context


@app.get("/sessions/{session_id}/jobs/latest")
async def get_latest_session_job(session_id: str, _: bool = Depends(require_api_key)):
    try:
        session_store.require(session_id)
        return {"job": jobs.get(next((job_id for job_id, item in jobs.items() if item.get("session_id") == session_id), "")) or session_store.latest_job(session_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/workflow")
async def get_session_workflow(session_id: str, _: bool = Depends(require_api_key)):
    try:
        context = session_store.require(session_id)
        state = session_store.load_state(session_id)
        return {"session_id": session_id, "phase": context.get("phase", state.workflow.phase), "workflow": state.workflow.to_dict()}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/workflow/hypotheses")
async def list_workflow_hypotheses(
    session_id: str,
    status: Optional[str] = None,
    _: bool = Depends(require_api_key),
):
    try:
        state = session_store.load_state(session_id)
        hypotheses = state.workflow.hypotheses
        if status:
            hypotheses = [item for item in hypotheses if item.status == status]
        return {"session_id": session_id, "hypotheses": [item.__dict__ for item in hypotheses]}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/workflow/planner-decisions")
async def list_workflow_planner_decisions(
    session_id: str,
    limit: int = 25,
    _: bool = Depends(require_api_key),
):
    try:
        state = session_store.load_state(session_id)
        bounded = max(1, min(limit, 100))
        decisions = state.workflow.planner_decisions[-bounded:]
        return {"session_id": session_id, "decisions": [item.__dict__ for item in reversed(decisions)]}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/plan")
async def create_workflow_plan(session_id: str, req: WorkflowPlanRequest, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, **workflow_planner.propose(session_id, req.request)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/transition")
async def transition_workflow(session_id: str, req: WorkflowTransitionRequest, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, **workflow_planner.transition(session_id, req.phase)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/chain")
async def propose_workflow_chain(session_id: str, req: ChainPlanRequest, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, **chain_planner.propose_next(session_id, req.objective)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/evidence/{evidence_id}/review")
async def review_workflow_evidence(session_id: str, evidence_id: str, req: EvidenceReviewRequest, _: bool = Depends(require_api_key)):
    try:
        state = session_store.load_state(session_id)
        if evidence_id not in {item.evidence_id for item in state.workflow.evidence}:
            raise ValueError("Evidence not found.")
        matched = [item for item in state.workflow.findings if evidence_id in item.evidence_ids]
        for finding in matched:
            finding.status = "validated" if req.confirmed else "disproven"
        state.workflow.record_event("evidence_reviewed", evidence_id=evidence_id, confirmed=req.confirmed)
        session_store.save_state(session_id, state)
        return {"ok": True, "findings": [item.__dict__ for item in matched]}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/workflow/progress")
async def workflow_progress(session_id: str, _: bool = Depends(require_api_key)):
    try:
        return evidence_service.objective_progress(session_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/actions/{action_id}/approve")
async def approve_workflow_action(
    session_id: str,
    action_id: str,
    req: WorkflowDecisionRequest,
    background_tasks: BackgroundTasks,
    _: bool = Depends(require_api_key),
):
    try:
        proposal = execution_guard.approve(session_id, action_id, req.reviewer_note)
        result = {"ok": True, "proposal": proposal.__dict__}
        if req.dispatch and proposal.action != "browser_workflow_mutation":
            dispatch = workflow_dispatcher.dispatch(session_id, action_id)
            context = session_store.require(session_id)
            background_tasks.add_task(
                run_pentest_job,
                dispatch["job_id"],
                context["target_url"],
                context["attack_goal"],
                session_id,
                {},
                None,
                dispatch["scan_config"],
            )
            result.update({"job_id": dispatch["job_id"], "stream_token": dispatch["stream_token"]})
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/actions/{action_id}/reject")
async def reject_workflow_action(session_id: str, action_id: str, req: WorkflowDecisionRequest, _: bool = Depends(require_api_key)):
    try:
        proposal = execution_guard.reject(session_id, action_id, req.reviewer_note)
        return {"ok": True, "proposal": proposal.__dict__}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/evidence")
async def add_workflow_evidence(session_id: str, req: EvidenceRequest, _: bool = Depends(require_api_key)):
    try:
        evidence = evidence_service.add(
            session_id=session_id,
            source=req.source,
            summary=req.summary,
            target_url=req.target_url,
            method=req.method,
            request=req.request,
            response=req.response,
            confidence=req.confidence,
            tool_run_id=req.tool_run_id,
        )
        return {"ok": True, "evidence": evidence.__dict__}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/impact-proof")
async def propose_impact_proof(session_id: str, req: ChainPlanRequest, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, **impact_service.propose(session_id, req.objective)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/impact-proof/result")
async def record_impact_proof(session_id: str, req: ImpactResultRequest, _: bool = Depends(require_api_key)):
    try:
        return impact_service.record_result(session_id, req.action_id, req.before, req.after, req.success)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/workflow/cleanup-handlers")
async def list_cleanup_handlers(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"handlers": cleanup_registry.available()}


@app.post("/sessions/{session_id}/workflow/cleanup/{cleanup_id}/execute")
async def execute_workflow_cleanup(session_id: str, cleanup_id: str, req: CleanupExecuteRequest, _: bool = Depends(require_api_key)):
    try:
        item = lifecycle_service.execute_cleanup(session_id, cleanup_id, req.handler_name, req.context)
        return {"ok": True, "cleanup": item.__dict__}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _browser_mutation_proposal(session_id: str, workflow: BrowserWorkflowV1, run: BrowserRunV1, bindings: Dict[str, Any]) -> ActionProposal:
    state = session_store.load_state(session_id)
    mutation_steps = [step for step in workflow.steps if step.is_mutation()]
    proposal = ActionProposal(
        action="browser_workflow_mutation",
        target_url=workflow.origin,
        rationale=f"Run published browser workflow {workflow.workflow_id} version {workflow.version}.",
        expected_evidence="Before/after snapshots, network fingerprints, and cleanup verification.",
        risk="high" if any(step.risk in {"high", "critical"} for step in mutation_steps) else "medium",
        requires_approval=True,
        side_effects=[step.description or step.action for step in mutation_steps],
        cleanup_required=True,
        recommended_tool="stateful_browser_workflow",
        input_bindings={
            "browser_run_id": run.run_id,
            "workflow_id": workflow.workflow_id,
            "workflow_version": workflow.version,
            "approval_digest": run.approval_digest,
            "identity_id": run.identity_id,
            "bindings": redact(bindings),
        },
        fingerprint=run.approval_digest,
    )
    state.workflow.add_proposal(proposal)
    state.workflow.record_event("browser_mutation_approval_requested", action_id=proposal.action_id, run_id=run.run_id, workflow_id=workflow.workflow_id, workflow_version=workflow.version)
    session_store.save_state(session_id, state)
    return proposal


def _approved_browser_proposal(session_id: str, action_id: str, run_id: str) -> ActionProposal:
    state = session_store.load_state(session_id)
    proposal = next((item for item in state.workflow.proposals if item.action_id == action_id), None)
    if not proposal or proposal.action != "browser_workflow_mutation":
        raise ValueError("Browser mutation approval proposal not found.")
    if proposal.status != "approved":
        raise ValueError("Browser mutation approval is not approved yet.")
    if proposal.input_bindings.get("browser_run_id") != run_id:
        raise ValueError("Approval is bound to a different browser run.")
    return proposal


@app.post("/sessions/{session_id}/browser/workflows/discover")
async def discover_browser_workflow(session_id: str, req: BrowserDiscoveryRequest, _: bool = Depends(require_api_key)):
    try:
        session_store.require(session_id)
        allowed, reason = session_store.validate_active_scope(session_id, req.origin)
        if not allowed:
            raise ValueError(f"Scope rejected: {reason}")
        workflow = workflow_discovery_service.discover(session_id, req.origin, req.goal, req.captures, req.identity_ids)
        browser_workflow_repository.save_workflow(workflow)
        return {"workflow": workflow.model_dump(mode="json"), "mode": "shadow", "requires_review": True}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/browser/workflows")
async def list_browser_workflows(session_id: str, status: Optional[str] = None, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "workflows": browser_workflow_repository.list_workflows(session_id, status)}


@app.post("/sessions/{session_id}/browser/workflows")
async def create_browser_workflow(session_id: str, req: BrowserWorkflowCreateRequest, _: bool = Depends(require_api_key)):
    try:
        session_store.require(session_id)
        allowed, reason = session_store.validate_active_scope(session_id, req.origin)
        if not allowed:
            raise ValueError(f"Scope rejected: {reason}")
        workflow = BrowserWorkflowV1(session_id=session_id, **req.model_dump()).ensure_fingerprint()
        browser_workflow_repository.save_workflow(workflow)
        return {"workflow": workflow.model_dump(mode="json")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.put("/sessions/{session_id}/browser/workflows/{workflow_id}")
async def edit_browser_workflow(session_id: str, workflow_id: str, req: BrowserWorkflowCreateRequest, _: bool = Depends(require_api_key)):
    try:
        old = browser_workflow_repository.get_workflow(session_id, workflow_id)
        allowed, reason = session_store.validate_active_scope(session_id, req.origin)
        if not allowed:
            raise ValueError(f"Scope rejected: {reason}")
        steps = [BrowserStepV1(**{key: value for key, value in item.items() if key not in {"step_id", "ordinal"}}, ordinal=index) for index, item in enumerate(req.steps)]
        workflow = BrowserWorkflowV1(workflow_id=old.workflow_id, session_id=session_id, name=req.name, origin=req.origin, goal=req.goal, version=old.version + 1, steps=steps, identity_requirements=req.identity_requirements, input_schema=req.input_schema, preconditions=req.preconditions, postconditions=req.postconditions, cleanup_step_ids=req.cleanup_step_ids, source_observation_ids=req.source_observation_ids).ensure_fingerprint()
        browser_workflow_repository.save_workflow(workflow)
        return {"workflow": workflow.model_dump(mode="json"), "version_created": workflow.version}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/browser/workflows/{workflow_id}")
async def get_browser_workflow(session_id: str, workflow_id: str, _: bool = Depends(require_api_key)):
    try:
        return {"workflow": browser_workflow_repository.get_workflow(session_id, workflow_id).model_dump(mode="json")}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/browser/workflows/{workflow_id}/publish")
async def publish_browser_workflow(session_id: str, workflow_id: str, _: bool = Depends(require_api_key)):
    try:
        return {"workflow": browser_workflow_repository.publish(session_id, workflow_id)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/browser/runs")
async def create_browser_run(session_id: str, req: BrowserRunRequest, _: bool = Depends(require_api_key)):
    try:
        context = session_store.require(session_id)
        workflow = browser_workflow_repository.get_workflow(session_id, req.workflow_id)
        if workflow.status != "published":
            raise ValueError("Only a published workflow version may run.")
        if _execution_mode() != "strict" and workflow.has_mutations() and (req.approved or req.approval_action_id):
            raise ValueError("Mutating runs must be approved through the existing workflow proposal endpoint, then resumed.")
        if _execution_mode() == "strict":
            approval_ref = ""
            if workflow.has_mutations():
                if not req.approval_action_id:
                    raise ValueError("Mutating durable browser runs require an approved workflow proposal.")
                proposal = _approved_browser_proposal(session_id, req.approval_action_id, req.parent_run_id or "")
                approval_ref = proposal.action_id
            run = BrowserRunV1(
                session_id=session_id, workflow_id=workflow.workflow_id, workflow_version=workflow.version,
                identity_id=req.identity_id, auth_context_id=req.auth_context_id, role=req.role,
                total_steps=len(workflow.steps), status="planned",
            )
            browser_workflow_repository.save_run(run)
            durable = _enqueue_execution_job(
                job_id=str(uuid.uuid4()), session_id=session_id, target=context["target_url"],
                goal=workflow.goal, job_type="browser_workflow",
                payload={
                    "workflow_id": workflow.workflow_id, "identity_id": req.identity_id,
                    "auth_context_id": req.auth_context_id, "role": req.role,
                    "bindings": req.bindings, "browser_run_id": run.run_id,
                    "approval_digest": req.approval_digest,
                }, risk="medium" if workflow.has_mutations() else "read_only", approval_ref=approval_ref,
            )
            return {"run": run.model_dump(mode="json"), "job_id": durable.job_id, "approval_proposal": None}
        run = await stateful_browser_runner.run(workflow, session_id=session_id, target=context["target_url"], identity_id=req.identity_id, auth_context_id=req.auth_context_id, role=req.role, bindings=req.bindings, parent_run_id=req.parent_run_id)
        proposal = _browser_mutation_proposal(session_id, workflow, run, req.bindings) if run.status == "approval_required" else None
        return {"run": run.model_dump(mode="json"), "approval_proposal": proposal.__dict__ if proposal else None}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/browser/runs")
async def list_browser_runs(session_id: str, workflow_id: Optional[str] = None, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "runs": browser_workflow_repository.list_runs(session_id, workflow_id)}


@app.get("/sessions/{session_id}/browser/runs/{run_id}")
async def get_browser_run(session_id: str, run_id: str, _: bool = Depends(require_api_key)):
    try:
        return {"run": browser_workflow_repository.get_run(session_id, run_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/browser/runs/{run_id}/resume")
async def resume_browser_run(session_id: str, run_id: str, req: BrowserResumeRequest, _: bool = Depends(require_api_key)):
    try:
        context = session_store.require(session_id)
        row = browser_workflow_repository.get_run(session_id, run_id)
        workflow = browser_workflow_repository.get_workflow(session_id, row["workflow_id"])
        if workflow.has_mutations():
            if not req.approval_action_id:
                raise ValueError("approval_action_id is required for a mutating resume.")
            proposal = _approved_browser_proposal(session_id, req.approval_action_id, run_id)
            digest = req.approval_digest or proposal.input_bindings.get("approval_digest", "")
            approved = True
        else:
            digest, approved = "", False
        run = await stateful_browser_runner.run(workflow, session_id=session_id, target=context["target_url"], identity_id=row.get("identity_id", ""), auth_context_id=row.get("auth_context_id", ""), role=row.get("role", "baseline"), bindings=req.bindings, approved=approved, approval_digest=digest, resume_from=BrowserRunV1(**row))
        return {"run": run.model_dump(mode="json")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/browser/runs/{run_id}/snapshots")
async def list_browser_snapshots(session_id: str, run_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "run_id": run_id, "snapshots": browser_workflow_repository.list_snapshots(session_id, run_id)}


@app.get("/sessions/{session_id}/business-invariants")
async def list_business_invariants(session_id: str, status: Optional[str] = None, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "invariants": browser_workflow_repository.list_invariants(session_id, status)}


@app.post("/sessions/{session_id}/business-invariants")
async def create_business_invariant(session_id: str, req: BusinessInvariantCreateRequest, _: bool = Depends(require_api_key)):
    try:
        session_store.require(session_id)
        if req.rule_type:
            if req.rule_type not in RULE_REGISTRY:
                raise ValueError("Unsupported invariant rule.")
            invariant = BusinessInvariantV1(session_id=session_id, name=req.name, rule_type=req.rule_type, rule_version=req.rule_version, source=req.source, rule=req.rule, required_workflow_ids=req.required_workflow_ids, required_identity_ids=req.required_identity_ids, source_observation_ids=req.source_observation_ids)
        else:
            invariant = business_invariant_compiler.compile(req.name, session_id, req.source)
            invariant.required_workflow_ids = req.required_workflow_ids
            invariant.required_identity_ids = req.required_identity_ids
            invariant.source_observation_ids = req.source_observation_ids
        browser_workflow_repository.save_invariant(invariant)
        return {"invariant": invariant.model_dump(mode="json"), "mode": "shadow"}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.put("/sessions/{session_id}/business-invariants/{invariant_id}")
async def edit_business_invariant(session_id: str, invariant_id: str, req: BusinessInvariantCreateRequest, _: bool = Depends(require_api_key)):
    try:
        rows = browser_workflow_repository.list_invariants(session_id)
        row = next((item for item in rows if item.get("invariant_id") == invariant_id), None)
        if not row:
            raise ValueError("Business invariant not found.")
        if req.rule_type and req.rule_type not in RULE_REGISTRY:
            raise ValueError("Unsupported invariant rule.")
        invariant = BusinessInvariantV1(**row)
        invariant.name = req.name
        invariant.rule_type = req.rule_type or invariant.rule_type
        invariant.rule_version = req.rule_version
        invariant.source = req.source
        invariant.rule = req.rule
        invariant.required_workflow_ids = req.required_workflow_ids
        invariant.required_identity_ids = req.required_identity_ids
        invariant.source_observation_ids = req.source_observation_ids
        invariant.status = "draft"
        invariant.revision += 1
        browser_workflow_repository.save_invariant(invariant)
        return {"invariant": invariant.model_dump(mode="json")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/business-invariants/{invariant_id}/activate")
@app.post("/sessions/{session_id}/business-invariants/{invariant_id}/activate")
async def activate_business_invariant(session_id: str, invariant_id: str, _: bool = Depends(require_api_key)):
    try:
        rows = browser_workflow_repository.list_invariants(session_id)
        row = next((item for item in rows if item.get("invariant_id") == invariant_id), None)
        if not row:
            raise ValueError("Business invariant not found.")
        invariant = BusinessInvariantV1(**row)
        if invariant.rule_type not in RULE_REGISTRY:
            raise ValueError("Invariant has no supported typed rule.")
        invariant.status = "active"
        browser_workflow_repository.save_invariant(invariant)
        return {"invariant": invariant.model_dump(mode="json")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/business-invariants/{invariant_id}/evaluate")
async def evaluate_business_invariant(session_id: str, invariant_id: str, req: BusinessInvariantEvaluateRequest, _: bool = Depends(require_api_key)):
    try:
        rows = browser_workflow_repository.list_invariants(session_id)
        row = next((item for item in rows if item.get("invariant_id") == invariant_id), None)
        if not row:
            raise ValueError("Business invariant not found.")
        invariant = BusinessInvariantV1(**row)
        evaluation, candidate = business_invariant_engine.evaluate(invariant, req.transitions, req.runs, req.observations)
        browser_workflow_repository.save_evaluation(evaluation)
        if candidate:
            observations = [ObservationV1(**item) for item in req.observations]
            result = ToolResultV1(tool_name="business_invariant_engine", category="validation", target=invariant.rule.get("target_url", ""), observations=observations, candidate_findings=[candidate])
            validation_decisions = validation_engine.validate(result)
            structured_repository.persist(session_id, result, validation_decisions)
        return {"evaluation": evaluation.model_dump(mode="json"), "candidate": candidate.model_dump(mode="json") if candidate else None, "mode": "shadow"}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/business-invariants/{invariant_id}/evaluations")
async def list_business_invariant_evaluations(session_id: str, invariant_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"evaluations": browser_workflow_repository.list_evaluations(session_id, invariant_id)}


@app.get("/sessions/{session_id}/artifacts/{artifact_id}")
async def get_browser_artifact(session_id: str, artifact_id: str, _: bool = Depends(require_api_key)):
    try:
        return {"artifact": browser_workflow_repository.artifact(session_id, artifact_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/artifacts/{artifact_id}/signed-url")
async def get_browser_artifact_url(session_id: str, artifact_id: str, _: bool = Depends(require_api_key)):
    try:
        artifact = browser_workflow_repository.artifact(session_id, artifact_id)
        url = browser_artifact_store.signed_url(artifact.get("storage_uri", ""))
        if not url:
            raise ValueError("Artifact does not have a signed storage URL.")
        return {"artifact_id": artifact_id, "signed_url": url, "expires_in": browser_artifact_store.signed_url_ttl}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
@app.get("/sessions/{session_id}/tool-runs")
async def list_structured_tool_runs(session_id: str, limit: int = 100, _: bool = Depends(require_api_key)):
    try:
        session_store.require(session_id)
        return {"session_id": session_id, "tool_runs": structured_repository.list_runs(session_id, min(limit, 500))}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/candidates")
async def list_candidate_findings(session_id: str, status: Optional[str] = None, limit: int = 100, _: bool = Depends(require_api_key)):
    try:
        session_store.require(session_id)
        return {"session_id": session_id, "candidates": structured_repository.list_candidates(session_id, status, min(limit, 500))}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/candidates/{candidate_id}/validation")
async def get_candidate_validation(session_id: str, candidate_id: str, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "candidate": structured_repository.get_candidate(session_id, candidate_id), "validations": structured_repository.validations(session_id, candidate_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/candidates/{candidate_id}/revalidate")
async def revalidate_candidate(session_id: str, candidate_id: str, _: bool = Depends(require_api_key)):
    try:
        return {"ok": True, **structured_repository.revalidate(session_id, candidate_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/candidates/{candidate_id}/review")
async def review_candidate(session_id: str, candidate_id: str, req: CandidateReviewRequest, _: bool = Depends(require_api_key)):
    try:
        result = structured_repository.review(session_id, candidate_id, req.decision, req.reason, req.reviewer)
        return {"ok": True, "candidate": result}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ============================================================
# DYNAMIC AUTHORIZATION GRAPH
# ============================================================

def _identity_or_404(session_id: str, identity_id: str) -> Dict[str, Any]:
    try:
        return authorization_repository.get_identity(session_id, identity_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/identities")
async def list_authorization_identities(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    identities = authorization_repository.list_identities(session_id)
    if not identities:
        anonymous = IdentityV1(session_id=session_id, label="anonymous", kind="anonymous", source="system", status="active")
        authorization_repository.create_identity(session_id, anonymous)
        identities = authorization_repository.list_identities(session_id)
    return {"session_id": session_id, "identities": identities}


@app.post("/sessions/{session_id}/identities")
async def create_authorization_identity(session_id: str, req: IdentityCreateRequest, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    if req.kind == "anonymous":
        identity = IdentityV1(session_id=session_id, label=req.label, kind="anonymous", source="system", status="active", metadata=req.metadata)
    else:
        identity = IdentityV1(
            session_id=session_id, label=req.label, kind=req.kind, source=req.source,
            role_label=req.role_label, tenant_label=req.tenant_label, metadata=req.metadata,
        )
    try:
        return {"identity": authorization_repository.create_identity(session_id, identity)}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/identities/{identity_id}/auth-context")
async def create_authorization_auth_context(session_id: str, identity_id: str, req: AuthContextCreateRequest, _: bool = Depends(require_api_key)):
    identity_row = _identity_or_404(session_id, identity_id)
    if identity_row.get("kind") == "anonymous":
        raise HTTPException(status_code=400, detail="Anonymous identity cannot receive credentials.")
    if not req.secret:
        raise HTTPException(status_code=400, detail="A write-only credential/session payload is required.")
    try:
        secret_meta = secret_vault.put(session_id, identity_id, "auth_context", req.secret, req.ttl_minutes)
        context = AuthContextV1(
            identity_id=identity_id, origin=req.origin, auth_type=req.auth_type,
            secret_ref=secret_meta["secret_ref"], secret_fingerprint=secret_meta["secret_fingerprint"],
            status="active" if req.auth_type in {"cookie", "bearer", "basic", "storage_state", "mixed"} else "pending",
            expires_at=secret_meta["expires_at"],
        )
        row = authorization_repository.create_auth_context(session_id, context)
        if context.status == "active":
            authorization_repository.update_identity(session_id, identity_id, {"status": "active"})

        # Keep a request-scoped runtime copy for HTTP tools. It is never put in
        # the response or structured evidence.
        domain = urlparse(req.origin).netloc.split(":")[0].lower()
        secret = req.secret
        cookies = secret.get("cookies", {})
        if isinstance(cookies, str):
            parsed = {}
            for part in cookies.split(";"):
                if "=" in part:
                    key, value = part.strip().split("=", 1)
                    parsed[key.strip()] = value.strip()
            cookies = parsed
        headers = secret.get("headers", {}) if isinstance(secret.get("headers", {}), dict) else {}
        auth_store.save_session(
            domain,
            AuthSession(
                domain=domain, cookies=cookies if isinstance(cookies, dict) else {},
                headers=headers, auth_type=req.auth_type, source="user",
                identity_id=identity_id, session_id=session_id,
                auth_context_id=context.auth_context_id, secret_ref=context.secret_ref,
                storage_state=secret.get("storage_state") if isinstance(secret.get("storage_state"), dict) else None,
            ),
            session_id=session_id, identity_id=identity_id,
        )
        return {"auth_context": row, "secret_stored": True}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/identities/{identity_id}/auth-contexts")
async def list_authorization_auth_contexts(session_id: str, identity_id: str, _: bool = Depends(require_api_key)):
    _identity_or_404(session_id, identity_id)
    return {"auth_contexts": authorization_repository.list_auth_contexts(session_id, identity_id)}


@app.post("/sessions/{session_id}/authorization/expectations")
async def create_authorization_expectation(session_id: str, req: AuthorizationExpectationRequest, _: bool = Depends(require_api_key)):
    _identity_or_404(session_id, req.subject_identity_id)
    if req.expected not in {"allow", "deny"}:
        raise HTTPException(status_code=400, detail="expected must be allow or deny")
    expectation = AuthorizationExpectationV1(
        session_id=session_id, subject_identity_id=req.subject_identity_id,
        resource_fingerprint=req.resource_fingerprint, action=req.action,
        expected=req.expected, source=req.source, reason=req.reason,
    )
    return {"expectation": authorization_repository.create_expectation(session_id, expectation)}


@app.get("/sessions/{session_id}/authorization/expectations")
async def list_authorization_expectations(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"expectations": authorization_repository.list_expectations(session_id)}


@app.post("/sessions/{session_id}/authorization/templates")
async def create_authorization_template(session_id: str, req: RequestTemplateRequest, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    allowed, reason = session_store.validate_active_scope(session_id, req.origin)
    if not allowed:
        raise HTTPException(status_code=403, detail=reason)
    template = RequestTemplateV1(session_id=session_id, **req.model_dump()).ensure_fingerprint()
    try:
        return {"template": authorization_repository.save_template(session_id, template)}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/authorization/templates")
async def list_authorization_templates(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"templates": authorization_repository.list_templates(session_id)}


@app.post("/sessions/{session_id}/authorization/discover")
async def discover_authorization_surface(session_id: str, req: AuthorizationDiscoveryRequest, _: bool = Depends(require_api_key)):
    _identity_or_404(session_id, req.identity_id)
    templates, resources = capture_to_contracts(req.captures, session_id, req.identity_id, req.source_observation_ids)
    stored_templates = [authorization_repository.save_template(session_id, item) for item in templates]
    stored_resources = [authorization_repository.save_resource(session_id, item) for item in resources]
    return {
        "templates": stored_templates,
        "resources": stored_resources,
        "discovered_template_count": len(stored_templates),
        "discovered_resource_count": len(stored_resources),
    }


@app.post("/sessions/{session_id}/authorization/resources")
async def create_authorization_resource(session_id: str, req: ResourceInstanceRequest, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    if req.owner_identity_id:
        _identity_or_404(session_id, req.owner_identity_id)
    resource = ResourceInstanceV1(session_id=session_id, **req.model_dump()).ensure_fingerprint()
    try:
        return {"resource": authorization_repository.save_resource(session_id, resource)}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/authorization/resources")
async def list_authorization_resources(session_id: str, owner_identity_id: Optional[str] = None, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    if owner_identity_id:
        _identity_or_404(session_id, owner_identity_id)
    return {"resources": authorization_repository.list_resources(session_id, owner_identity_id)}


@app.post("/sessions/{session_id}/authorization/replays")
async def run_authorization_replay(session_id: str, req: AuthorizationReplayRequest, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    template = authorization_repository.get_template(session_id, req.template_id)
    resources = [item for item in authorization_repository.list_resources(session_id) if item.get("fingerprint") == req.resource_fingerprint]
    if not resources:
        raise HTTPException(status_code=404, detail="Resource fingerprint not found.")
    resource = ResourceInstanceV1(**resources[0])
    _identity_or_404(session_id, req.owner_identity_id)
    for identity_id in req.test_identity_ids:
        _identity_or_404(session_id, identity_id)
    if template.side_effect_class in {"mutation", "unknown"} and not req.approved:
        raise HTTPException(status_code=409, detail="This replay requires explicit approval because it may mutate state.")
    allowed, reason = session_store.validate_active_scope(session_id, template.origin)
    if not allowed:
        raise HTTPException(status_code=403, detail=reason)
    expectations = [AuthorizationExpectationV1(**item) for item in authorization_repository.list_expectations(session_id)]
    run = AuthorizationReplayRunV1(
        session_id=session_id, template_id=template.template_id,
        resource_fingerprint=resource.fingerprint, owner_identity_id=req.owner_identity_id,
        test_identity_ids=req.test_identity_ids, mutation_approved=req.approved,
    )
    engine = AuthorizationReplayEngine(target=template.origin)
    result = engine.run_differential(
        session_id, template, resource, req.owner_identity_id,
        req.test_identity_ids, expectations, req.bindings, req.approved, run,
    )
    validations = validation_engine.validate(result) if result.candidate_findings else []
    structured_repository.persist(session_id, result, validations)
    if engine.last_run:
        authorization_repository.create_replay_run(session_id, engine.last_run)
        for attempt in engine.last_run.attempts:
            authorization_repository.save_attempt(session_id, attempt)
    return {"result": result.model_dump(), "replay": engine.last_run.model_dump() if engine.last_run else {}}


@app.get("/sessions/{session_id}/authorization/replays")
async def list_authorization_replays(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"replays": authorization_repository.list_replay_runs(session_id)}


@app.get("/sessions/{session_id}/authorization/replays/{replay_run_id}")
async def get_authorization_replay(session_id: str, replay_run_id: str, _: bool = Depends(require_api_key)):
    try:
        return authorization_repository.replay_detail(session_id, replay_run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/workflow/report")
async def get_workflow_report(session_id: str, _: bool = Depends(require_api_key)):
    try:
        return workflow_report.generate(session_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/workflow/lifecycle")
async def workflow_lifecycle(session_id: str, _: bool = Depends(require_api_key)):
    try:
        return lifecycle_service.summary(session_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/cleanup")
async def register_workflow_cleanup(session_id: str, req: CleanupRequest, _: bool = Depends(require_api_key)):
    try:
        item = lifecycle_service.register_cleanup(session_id, req.description, req.action, req.source_action_id)
        return {"ok": True, "cleanup": item.__dict__}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/cleanup/{cleanup_id}")
async def complete_workflow_cleanup(session_id: str, cleanup_id: str, req: CleanupCompleteRequest, _: bool = Depends(require_api_key)):
    try:
        item = lifecycle_service.complete_cleanup(session_id, cleanup_id, req.result, req.success)
        return {"ok": True, "cleanup": item.__dict__}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/retest")
async def start_workflow_retest(session_id: str, req: RetestStartRequest, _: bool = Depends(require_api_key)):
    try:
        retest = lifecycle_service.start_retest(session_id, req.finding_id)
        return {"ok": True, "retest": retest.__dict__, "procedure": retest_service.prepare(session_id, req.finding_id)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/workflow/retest/result")
async def record_workflow_retest(session_id: str, req: RetestRecordRequest, _: bool = Depends(require_api_key)):
    try:
        finding_id = req.evidence.get("finding_id", "")
        if not finding_id:
            raise ValueError("evidence.finding_id is required.")
        return retest_service.record(session_id, finding_id, req.status, req.comparison, req.evidence)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sessions/{session_id}/messages/stream")
async def stream_session_message(session_id: str, req: ChatMessageRequest, _: bool = Depends(require_api_key)):
    from core.chat_runtime import new_message_id

    content = req.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")
    message_id = req.message_id or new_message_id()
    session_store.require(session_id)
    session_store.save_chat_message(session_id, {
        "role": "user",
        "content": content,
        "message_id": message_id,
        "status": "complete",
        "parent_message_id": req.parent_message_id,
        "metadata": {"model": req.model_id},
    })

    async def event_generator():
        assistant_parts: list[str] = []
        intent = chat_orchestrator.classify_intent(content)
        if intent in {"plan", "proposal"}:
            plan = workflow_planner.propose(session_id, content)
            reply = "I prepared a workflow proposal for your review. No active job has started."
            proposal_event = {
                "event": "tool_proposal",
                "message_id": message_id,
                "session_id": session_id,
                "status": "proposal_pending",
                "content": reply,
                "metadata": {
                    "proposals": plan["proposals"], "hypotheses": plan.get("hypotheses", []),
                    "planner_decision": plan.get("planner_decision"),
                    "workflow": plan["workflow"], "phase": plan["phase"],
                },
            }
            yield f"data: {json.dumps(proposal_event)}\\n\\n"
            session_store.save_chat_message(session_id, {
                "role": "agent", "content": reply, "message_id": message_id,
                "status": "complete", "metadata": {"decision": "tool_proposal"},
            })
            yield f"data: {json.dumps({**proposal_event, 'event': 'done', 'status': 'complete'})}\\n\\n"
            return
        for event in chat_orchestrator.stream(session_id, content, message_id, req.model_id):
            if event.get("event") == "delta":
                assistant_parts.append(event.get("delta", ""))
            if event.get("event") == "done":
                answer = event.get("content", "".join(assistant_parts))
                session_store.save_chat_message(session_id, {
                    "role": "agent",
                    "content": answer,
                    "message_id": message_id,
                    "status": "complete",
                    "parent_message_id": message_id,
                    "metadata": event.get("metadata", {}),
                })
                chat_orchestrator.update_summary(session_id)
            yield f"data: {json.dumps(event)}\\n\\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


@app.post("/sessions/{session_id}/messages/{message_id}/cancel")
async def cancel_session_message(session_id: str, message_id: str, _: bool = Depends(require_api_key)):
    try:
        session_store.require(session_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    from core.chat_runtime import chat_cancellation
    return {"ok": chat_cancellation.cancel(message_id), "message_id": message_id}


@app.post("/sessions/{session_id}/messages")
async def send_session_message(
    session_id: str,
    req: ChatMessageRequest,
    background_tasks: BackgroundTasks,
    _: bool = Depends(require_api_key),
):
    content = req.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")
    try:
        context = session_store.require(session_id)
        save_message(session_id, "user", content)
        intent = chat_orchestrator.classify_intent(content)

        if intent == "plan":
            plan = workflow_planner.propose(session_id, content)
            reply = "I prepared an evidence-driven next-step plan for review. No scanner has started yet."
            save_message(session_id, "agent", reply)
            return {
                "session_id": session_id,
                "role": "agent",
                "content": reply,
                "phase": plan["phase"],
                "workflow": plan["workflow"],
                "proposals": plan["proposals"],
            }

        if intent == "proposal":
            plan = workflow_planner.propose(session_id, content)
            reply = "I understand this as a request to inspect the target. I prepared a proposal for your review; no job has started."
            session_store.save_chat_message(session_id, {
                "role": "agent",
                "content": reply,
                "message_id": req.message_id or str(uuid.uuid4()),
                "status": "complete",
                "metadata": {"decision": "tool_proposal", "proposal_count": len(plan["proposals"])},
            })
            return {
                "session_id": session_id,
                "role": "agent",
                "content": reply,
                "phase": plan["phase"],
                "workflow": plan["workflow"],
                "proposals": plan["proposals"],
            }

        if intent in {"recon", "analysis"}:
            valid, reason = session_store.validate_active_scope(session_id, context["target_url"])
            if not valid:
                reply = f"I can't start that job because the session scope is invalid: {reason}"
                save_message(session_id, "agent", reply)
                return {"session_id": session_id, "role": "agent", "content": reply, "phase": context.get("phase", "SETUP")}

            job_id = str(uuid.uuid4())
            stream_token = secrets.token_urlsafe(32)
            scan_config = {
                "recon": intent == "recon",
                "exploitation": intent == "analysis",
                "assessor": False,
                "auto_pilot": False,
                "stealth_mode": False,
            }
            jobs[job_id] = {
                "job_id": job_id,
                "session_id": session_id,
                "target": context["target_url"],
                "goal": context["attack_goal"],
                "status": "queued",
                "message": "Queued from interactive chat.",
                "report": None,
                "logs": [],
                "summary": {},
                "stream_token": stream_token,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
            }
            try:
                session_store.save_job(jobs[job_id])
            except Exception as persist_err:
                print(f"[WORKFLOW] Job persistence warning: {persist_err}")
            queued_reply = (
                f"I queued {intent} for `{context['target_domain']}`. "
                "The job will stay within this session's scope; I'll show progress in the execution stream."
            )
            save_message(session_id, "agent", queued_reply)
            background_tasks.add_task(
                run_pentest_job,
                job_id,
                context["target_url"],
                context["attack_goal"],
                session_id,
                {"recon": req.model_id, "analis": req.model_id},
                None,
                scan_config,
            )
            return {
                "session_id": session_id,
                "role": "agent",
                "content": queued_reply,
                "phase": "RECON" if intent == "recon" else "ANALYSIS",
                "job_id": job_id,
                "stream_token": stream_token,
            }

        reply = chat_orchestrator.reply(session_id, content, req.model_id)
        save_message(session_id, "agent", reply)
        return {
            "session_id": session_id,
            "role": "agent",
            "content": reply,
            "phase": context.get("phase", "SETUP"),
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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
    Ambil all chat messages from session tertentu, diurutkan from that paling lama.
    Frontend pakai this for restore chat history waktu klik session di sidebar.
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
    """Return daftar model that available for selected di frontend."""
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
        raise HTTPException(status_code=400, detail="rule_type must 'allow' atau 'deny'.")
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
    """Delete session dan all chat messages terkait."""
    try:
        # Delete chat messages dulu
        supabase.table("chat_messages").delete().eq("session_id", session_id).execute()
        # Delete session
        supabase.table("sessions").delete().eq("id", session_id).execute()
        return {"ok": True, "deleted": session_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/pentest")
async def start_pentest(req: PentestRequest, background_tasks: BackgroundTasks, _: bool = Depends(require_api_key)):
    """
    Langsung return job_id. Pentest jalan di background.
    Frontend poll /job/{job_id} atau stream from /job/{job_id}/stream.
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

    risk = "medium" if req.credentials else "read_only"
    try:
        _enqueue_execution_job(
            job_id=job_id,
            session_id=session_id,
            target=req.target,
            goal=req.goal,
            job_type="pentest",
            payload={
                "agent_models": req.agent_models,
                "credentials": req.credentials,
                "scan_config": req.scan_config,
            },
            risk=risk, idempotency_key=req.idempotency_key or "",
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    if _execution_mode() == "strict":
        return {"job_id": job_id, "session_id": session_id, "status": "queued", "stream_token": stream_token}

    background_tasks.add_task(
        run_pentest_job, job_id, req.target, req.goal, session_id, req.agent_models, req.credentials, req.scan_config
    )

    return {"job_id": job_id, "session_id": session_id, "status": "queued", "stream_token": stream_token}


@app.get("/sessions/{session_id}/execution/jobs")
async def list_execution_jobs(session_id: str, limit: int = 100, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    try:
        return {"session_id": session_id, "jobs": durable_execution_repository.list_jobs(session_id, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Durable execution unavailable: {exc}")


@app.get("/sessions/{session_id}/execution/jobs/{job_id}/events")
async def list_execution_events(session_id: str, job_id: str, after_sequence: int = 0, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    try:
        return {"job_id": job_id, "events": durable_execution_repository.list_events(job_id, after_sequence)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Durable event stream unavailable: {exc}")


@app.get("/job/{job_id}")
async def get_job(job_id: str, _: bool = Depends(require_api_key)):
    """Poll status job."""
    if job_id not in jobs:
        try:
            durable = durable_execution_repository.get_job(job_id)
        except Exception:
            durable = None
        if durable:
            return _legacy_job_view(durable)
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.post("/job/{job_id}/cancel")
async def cancel_job(job_id: str, _: bool = Depends(require_api_key)):
    """
    Cancel job that lagi jalan. Set cancellation token that checked oleh setiap
    tool senot yet eksekusi — tool that not yet jalan will berhenti, tool yang
    currently berjalan will completed dulu baru berhenti di tool berikutnya.
    """
    if job_id not in jobs:
        try:
            durable = durable_execution_repository.get_job(job_id)
        except Exception:
            durable = None
        if durable:
            ok = durable_execution_repository.request_cancel(job_id)
            return {"ok": ok, "job_id": job_id, "source": "durable"}
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]
    durable_cancel_requested = False
    try:
        durable_cancel_requested = durable_execution_repository.request_cancel(job_id)
    except Exception:
        pass
    if job.get("status") not in ("queued", "running", "waiting_hitl", "waiting_continue"):
        raise HTTPException(
            status_code=400,
            detail=f"Job not can di-cancel, status saat ini: {job.get('status')}"
        )

    # Kalau lagi nunggu HITL/continue, auto-reject dulu biar thread gak stuck
    checkpoint_store.respond(job_id, False)
    continue_store.respond(job_id, False)

    cancelled = cancellation_store.cancel(job_id)
    if cancelled:
        update_job(job_id, status="cancelling", message="Waiting tool completed lalu berhenti...")

    return {"ok": cancelled or durable_cancel_requested, "job_id": job_id}


@app.post("/job/{job_id}/continue")
async def continue_job(job_id: str, _: bool = Depends(require_api_key)):
    """
    Continue job sealready phase selesai. User klik 'Continue' di frontend.
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
    browser gak can kirim custom header. Token di-generate waktu POST /pentest
    dan sent balik ke frontend di response body.
    """
    if job_id not in jobs:
        try:
            durable = durable_execution_repository.get_job(job_id)
        except Exception:
            durable = None
        if durable:
            jobs[job_id] = _legacy_job_view(durable)
        else:
            raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]
    stored_token = job.get("stream_token")
    if stored_token and (not token or not secrets.compare_digest(token, stored_token)):
        raise HTTPException(status_code=401, detail="Stream token not valid.")

    async def event_generator():
        last_message = ""
        last_status = ""
        last_updated = ""
        terminal_waits = 0
        while True:
            job = jobs.get(job_id, {})
            status = job.get("status", "")
            message = job.get("message", "")
            updated_at = job.get("updated_at", "")

            # Send every terminal-finalization update, even when status/message
            # remain unchanged.
            if message != last_message or status != last_status or updated_at != last_updated:
                payload = {
                    "status": status,
                    "message": message,
                    "logs": job.get("logs", []),
                    "summary": job.get("summary", {}),
                }
                if "next_proposals" in job:
                    payload["next_proposals"] = job.get("next_proposals", [])
                if "next_hypotheses" in job:
                    payload["next_hypotheses"] = job.get("next_hypotheses", [])
                if job.get("planner_finalized"):
                    payload["planner_finalized"] = True
                if status in ("done", "error") and status != last_status:
                    payload["report"] = job.get("report")

                if job.get("checkpoint"):
                    payload["checkpoint"] = job["checkpoint"]
                if job.get("auth_request"):
                    payload["auth_request"] = job["auth_request"]

                yield f"data: {json.dumps(payload)}\n\n"
                last_message = message
                last_status = status
                last_updated = updated_at

            if status in ("done", "error", "cancelled"):
                planner_pending = bool(job.get("workflow_action_id")) and not bool(job.get("planner_finalized"))
                if not planner_pending or terminal_waits >= 20:
                    yield "data: {\"event\": \"close\"}\n\n"
                    break
                terminal_waits += 1
                await asyncio.sleep(0.25)
                continue

            terminal_waits = 0
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
    Frontend poll/baca this for tau apakah job lagi nunggu approval, dan
    detail aksi apa that mau running.
    """
    pending = checkpoint_store.get_pending(job_id)
    if not pending:
        return {"waiting": False}
    return {"waiting": True, **pending}


@app.post("/checkpoint/respond")
async def respond_checkpoint(data: CheckpointResponse, _: bool = Depends(require_api_key)):
    """
    Frontend kirim approved=True/False ke sini. Ini langsung set threading.Event
    that lagi di-`wait()` oleh worker thread tempat tool eksekusi nungguin.
    """
    ok = checkpoint_store.respond(data.job_id, data.approved)
    if not ok:
        raise HTTPException(status_code=404, detail="Not ada checkpoint aktif for job_id ini")
    return {"ok": True, "approved": data.approved}


@app.post("/auth/respond")
async def respond_auth(data: AuthResponse, _: bool = Depends(require_api_key)):
    """
    Frontend kirim credentials atau session cookies ke sini.
    Ini langsung set threading.Event that lagi di-`wait()` oleh worker thread.
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
        raise HTTPException(status_code=400, detail="mode must 'credentials' atau 'session'")

    ok = auth_checkpoint_store.respond(data.job_id, auth_data)
    if not ok:
        raise HTTPException(status_code=404, detail="Not ada auth request aktif for job_id ini")
    return {"ok": True, "mode": data.mode}


@app.get("/auth/pending/{job_id}")
async def get_pending_auth(job_id: str, _: bool = Depends(require_api_key)):
    """Frontend poll this for cek apakah ada auth request that pending."""
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
    Return plain text with Content-Disposition biar browser auto-download.
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

    # Ringkasan tools that executed
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
    # Tambah log entries that punya status WARNING/ERROR/SUCCESS (skip PROCESSING/START for brevity)
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
        # Fallback: coba ambil dari workflow_jobs (durable) biar gak 404 setelah restart
        try:
            res = supabase.table("workflow_jobs").select("*").eq("job_id", job_id).execute()
            db_job = (res.data or [None])[0]
            if db_job:
                payload = db_job.pop("payload", {}) or {}
                db_job.update(payload)
                jobs[job_id] = db_job
        except Exception:
            pass
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
    # Resolve job_id from session_id kalau agent cuma tau session_id
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
    update_job(job_id, message=f"Adding target baru from {req.source}: {new_url}")

    return {"status": "success", "message": f"Target {new_url} success added ke antrean pool."}

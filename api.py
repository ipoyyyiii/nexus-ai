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
    AuthSurfaceObservationV1,
    AuthorizationExpectationV1,
    AuthorizationReplayRunV1,
    IdentityGraphV1,
    IdentityV1,
    RequestTemplateV1,
    ResourceInstanceV1,
    SessionTransitionV1,
    WorkflowPrerequisiteV1,
)
from core.authorization_repository import AuthorizationRepository
from core.redact import redact
from core.authorization_engine import AuthorizationReplayEngine
from core.authorization_engine import build_identity_graph, plan_identity_coverage
from core.authorization_discovery import capture_to_contracts
from core.secret_vault import SecretVault
from core.validation_engine import validation_engine
from core.detection_validation_api import register_detection_validation_routes
from core.detection_validation_v2 import validation_engine_v2
from core.identity_context import ToolExecutionContext, set_execution_context, reset_execution_context
from core.chain_planner import ChainPlanner
from core.mission_contract import MissionV1
from core.mission_graph import MissionGraphEngine, MissionGraphError
from core.mission_repository import MissionRepository
from core.knowledge_graph_contract import KnowledgeProposalV1, TargetMemoryRecordV1
from core.knowledge_graph_engine import KnowledgeGraphError, TargetKnowledgeGraphEngine
from core.knowledge_graph_repository import KnowledgeGraphRepository
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
from core.recon_orchestrator import ReconOrchestrator
from core.identity_workflow_matrix import identity_workflow_matrix
from core.config_loader import get_setting, get_config
from core.execution_contract import ExecutionJobV1, ResourceBudgetV1, stable_digest
from core.production_contract import (
    ArtifactSweepV1, CutoverDecisionV1, OperatorIncidentV1,
    ProductionReadinessV1, ReadinessCheckV1, RecoveryVerificationV1,
    SLOSnapshotV1, SoakEventV1, SoakRunV1,
)
from core.durable_execution import DurableExecutionRepository
from core.production_repository import ProductionReadinessRepository
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
from tools.modern_protocol_tools import compare_protocol_captures, normalize_protocol_capture, operation_dicts
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


def _domain_of(url: str) -> str:
    """Return the hostname used by the per-origin WAF/rate-limit policy."""
    parsed = urlparse(str(url or ""))
    return (parsed.hostname or parsed.netloc or "").lower()

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
production_readiness_repository = ProductionReadinessRepository(supabase)
evaluation_engine = EvaluationEngine()
evaluation_repository = EvaluationRepository(supabase)
knowledge_graph_repository = KnowledgeGraphRepository(supabase)
memory = SessionMemory(supabase, knowledge_graph_repository)
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
chain_planner = ChainPlanner(session_store, structured_repository, knowledge_graph_repository)
mission_repository = MissionRepository(supabase)
mission_graph_engine = MissionGraphEngine(max_paths=int((get_setting("mission_graph", {}) or {}).get("max_paths", 8)))
knowledge_graph_engine = TargetKnowledgeGraphEngine(
    max_nodes=int((get_setting("target_knowledge", {}) or {}).get("max_nodes", 10000)),
    max_edges=int((get_setting("target_knowledge", {}) or {}).get("max_edges", 20000)),
    observation_ttl_hours=int((get_setting("target_knowledge", {}) or {}).get("observation_ttl_hours", 24)),
)
impact_service = ImpactService(session_store, chain_planner)
retest_service = RetestService(session_store, evidence_service)
workflow_report = WorkflowReport(session_store)

app = FastAPI(title="Nexus AI Pentest API", version="6.1 - Hardened Edition")


class SoakStartRequest(BaseModel):
    duration_minutes: int = Field(default=120, ge=1, le=1440)
    session_id: str = ""
    worker_count: int = Field(default=1, ge=1, le=8)
    simulated_worker_count: int = Field(default=2, ge=0, le=32)
    readiness_run_id: str = ""
    dry_run: bool = True


class CutoverDecisionRequest(BaseModel):
    readiness_run_id: str = Field(min_length=1, max_length=200)
    decision: str = Field(pattern="^(approved|rejected|rollback)$")
    reviewer_id: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=2000)
    config_digest: str = ""
    schema_digest: str = ""
    image_digest: str = ""
    soak_run_id: str = ""
    slo_snapshot_id: str = ""
    rollback_ref: str = "config/pentest_config.yaml:execution_platform_mode"


class RecoveryVerificationRequest(BaseModel):
    attempt_id: str = ""
    recovery_id: str = ""
    decision: str = Field(pattern="^(verified|failed|inconclusive)$")
    checkpoint_valid: bool = False
    side_effects_verified: bool = False
    mutation_replayed: bool = False
    cleanup_verified: bool = False
    evidence_ids: List[str] = Field(default_factory=list)
    reason: str = Field(default="", max_length=2000)


@app.get("/health/live")
async def health_live():
    """Liveness must not depend on Supabase or an LLM."""
    return {"status": "alive", "service": "nexus-api"}


@app.get("/health/ready")
async def health_ready():
    """Readiness proves the control plane can see the durable schema."""
    checks: Dict[str, str] = {"config": "ok", "supabase": "unknown", "durable_schema": "unknown"}
    try:
        supabase.table("sessions").select("id").limit(1).execute()
        checks["supabase"] = "ok"
        supabase.table("workflow_jobs").select("job_id").limit(1).execute()
        supabase.table("workflow_job_attempts").select("attempt_id").limit(1).execute()
        if _execution_mode() == "strict":
            supabase.table("workflow_events").select("sequence").limit(1).execute()
            supabase.table("worker_nodes").select("worker_id").limit(1).execute()
            supabase.table("production_cutover_decisions").select("decision_id").limit(1).execute()
        checks["durable_schema"] = "ok"
    except Exception as exc:
        checks["supabase"] = "error"
        checks["durable_schema"] = "error"
        if _execution_mode() == "strict":
            raise HTTPException(status_code=503, detail={"status": "not_ready", "checks": checks, "error": redact(str(exc))[:300]})
    status = "ready" if all(value == "ok" for value in checks.values()) else "degraded"
    return {"status": status, "mode": _execution_mode(), "checks": checks}


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


@app.get("/ops/metrics")
async def operational_metrics(_: bool = Depends(require_api_key)):
    """Small persisted metrics surface; no Prometheus dependency required."""
    metrics: Dict[str, Any] = {"mode": _execution_mode(), "worker_count": 0, "active_jobs": 0, "recovery_required": 0, "cleanup_failed": 0}
    try:
        workers = supabase.table("worker_nodes").select("worker_id,status,last_heartbeat_at").execute().data or []
        metrics["worker_count"] = len(workers)
        jobs = supabase.table("workflow_jobs").select("status").in_("status", ["leased", "running", "waiting_approval", "waiting_auth", "waiting_continue"]).execute().data or []
        metrics["active_jobs"] = len(jobs)
        metrics["recovery_required"] = len(supabase.table("workflow_jobs").select("job_id").eq("status", "recovery_required").execute().data or [])
        metrics["cleanup_failed"] = len(supabase.table("cleanup_attempts").select("cleanup_attempt_id").eq("status", "cleanup_failed").execute().data or [])
    except Exception as exc:
        metrics["persistence_error"] = redact(type(exc).__name__)
    return metrics


@app.get("/ops/workers")
async def operational_workers(_: bool = Depends(require_api_key)):
    try:
        result = supabase.table("worker_nodes").select("worker_id,capabilities,status,last_heartbeat_at,metadata").order("last_heartbeat_at", desc=True).execute()
        return {"workers": [redact(row) for row in (result.data or [])]}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Worker telemetry unavailable: {redact(str(exc))[:300]}")


@app.get("/ops/readiness/runs")
async def readiness_runs(limit: int = 50, _: bool = Depends(require_api_key)):
    try:
        return {"runs": [redact(row) for row in production_readiness_repository.list(limit)]}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Readiness persistence unavailable.") from exc


@app.get("/ops/readiness/runs/{run_id}")
async def readiness_run_detail(run_id: str, _: bool = Depends(require_api_key)):
    try:
        run = production_readiness_repository.get(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Readiness run not found.")
        return {"run": redact(run), "checks": [redact(row) for row in production_readiness_repository.checks(run_id)]}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Readiness persistence unavailable.") from exc


def _ensure_soak_session(requested_session_id: str, soak_run_id: str) -> str:
    """Return an existing session or create an isolated operational session.

    workflow_jobs require a valid session FK; a soak is not allowed to borrow
    an unrelated target session implicitly.
    """
    if requested_session_id:
        result = supabase.table("sessions").select("id").eq("id", requested_session_id).limit(1).execute()
        if not result.data:
            raise HTTPException(status_code=404, detail="Soak session not found.")
        return requested_session_id
    result = supabase.table("sessions").insert({"title": f"Nexus operational soak · {soak_run_id}"}).execute()
    if not result.data:
        raise HTTPException(status_code=503, detail="Could not create isolated soak session.")
    return str(result.data[0]["id"])


@app.post("/ops/readiness/soak")
async def start_readiness_soak(req: SoakStartRequest, _: bool = Depends(require_api_key)):
    """Persist a soak plan and enqueue its durable worker execution."""
    soak = SoakRunV1(
        readiness_run_id=req.readiness_run_id,
        mode="diagnostic" if req.dry_run else "deterministic",
        duration_seconds=req.duration_minutes * 60,
        worker_count=req.worker_count,
        simulated_worker_count=req.simulated_worker_count,
        expected_jobs=max(1, req.simulated_worker_count or req.worker_count),
        status="queued",
        config_digest=stable_digest({"duration_minutes": req.duration_minutes, "workers": req.worker_count, "simulated": req.simulated_worker_count, "dry_run": req.dry_run}),
        metadata={"dry_run": req.dry_run, "raw_network_worker": "disabled"},
    )
    session_id = _ensure_soak_session(req.session_id, soak.soak_run_id)
    payload = {
        "soak_run_id": soak.soak_run_id,
        "readiness_run_id": req.readiness_run_id,
        "duration_seconds": soak.duration_seconds,
        "sample_interval_seconds": soak.sample_interval_seconds,
        "worker_count": req.worker_count,
        "simulated_worker_count": req.simulated_worker_count,
        "dry_run": req.dry_run,
    }
    # workflow_jobs.job_id is a PostgreSQL UUID; keep the public soak ID separate.
    job_id = str(uuid.uuid4())
    try:
        production_readiness_repository.save_soak(soak)
        # Persist the queued event before enqueueing. If this fails (for
        # example migration 020 is missing), no orphan workflow job is made.
        production_readiness_repository.save_soak_event(SoakEventV1(
            soak_run_id=soak.soak_run_id, job_id=job_id, status="queued",
            payload={"job_id": job_id, "expected_jobs": soak.expected_jobs},
        ))
        job = _enqueue_execution_job(
            job_id=job_id, session_id=session_id,
            target="internal://readiness-soak", goal="Run durable production readiness soak",
            job_type="readiness_soak", payload=payload, risk="read_only",
            idempotency_key=f"soak:{soak.soak_run_id}", require_queue=True,
        )
    except HTTPException:
        raise
    except Exception as exc:
        print(f"[SOAK] durable enqueue failed: {type(exc).__name__}: {redact(str(exc))[:500]}")
        try:
            production_readiness_repository.save_soak_event(SoakEventV1(
                soak_run_id=soak.soak_run_id, status="failed",
                payload={"error_code": type(exc).__name__},
            ))
        except Exception:
            pass
        raise HTTPException(status_code=503, detail="Soak durable enqueue unavailable.") from exc
    return {
        "soak": soak.model_dump(mode="json"), "status": "queued",
        "job_id": job.job_id, "session_id": session_id,
        "note": "Worker execution must persist samples and terminal evidence before success is reported.",
    }


@app.get("/ops/readiness/soaks")
async def readiness_soaks(limit: int = 50, _: bool = Depends(require_api_key)):
    try:
        return {"soaks": [redact(row) for row in production_readiness_repository.list_soaks(limit)]}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Soak persistence unavailable.") from exc


@app.get("/ops/readiness/soaks/{soak_run_id}")
async def readiness_soak_detail(soak_run_id: str, _: bool = Depends(require_api_key)):
    try:
        rows = [row for row in production_readiness_repository.list_soaks(200) if row.get("soak_run_id") == soak_run_id]
        if not rows:
            raise HTTPException(status_code=404, detail="Soak run not found.")
        return {
            "soak": redact(rows[0]),
            "samples": [redact(row) for row in production_readiness_repository.soak_samples(soak_run_id)],
            "events": [redact(row) for row in production_readiness_repository.soak_events(soak_run_id)],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Soak persistence unavailable.") from exc


@app.get("/ops/slo")
async def operational_slo(limit: int = 50, _: bool = Depends(require_api_key)):
    try:
        return {"snapshots": [redact(row) for row in production_readiness_repository.list_slo(limit)]}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="SLO persistence unavailable.") from exc


@app.post("/ops/cutover/preview")
async def cutover_preview(readiness_run_id: str, _: bool = Depends(require_api_key)):
    run = production_readiness_repository.get(readiness_run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Readiness run not found.")
    blockers = []
    if run.get("release_decision") != "ready":
        blockers.append("readiness_gate_not_ready")
    if not bool(run.get("cutover_candidate", False)):
        blockers.append("run_not_marked_cutover_candidate")
    if _execution_mode() == "strict":
        blockers.append("already_in_strict_mode")
    recovery = supabase.table("workflow_jobs").select("job_id").eq("status", "recovery_required").limit(1).execute().data or []
    if recovery:
        blockers.append("mutation_recovery_required")
    return {"readiness_run_id": readiness_run_id, "from_mode": _execution_mode(), "to_mode": "strict", "eligible": not blockers, "blockers": blockers, "rollback_ref": "config/pentest_config.yaml:execution_platform_mode"}


@app.post("/ops/cutover/decision")
async def record_cutover_decision(req: CutoverDecisionRequest, _: bool = Depends(require_api_key)):
    preview = await cutover_preview(req.readiness_run_id, True)
    if req.decision == "approved" and not preview["eligible"]:
        raise HTTPException(status_code=409, detail={"message": "Cutover prerequisites are not met.", "blockers": preview["blockers"]})
    decision = CutoverDecisionV1(
        readiness_run_id=req.readiness_run_id, decision=req.decision,
        reviewer_id=req.reviewer_id, reason=req.reason,
        config_digest=req.config_digest, schema_digest=req.schema_digest,
        image_digest=req.image_digest, soak_run_id=req.soak_run_id,
        slo_snapshot_id=req.slo_snapshot_id, rollback_ref=req.rollback_ref,
    )
    try:
        production_readiness_repository.save_cutover(decision)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Cutover audit persistence unavailable.") from exc
    # This endpoint records approval only. YAML/config change and restart are
    # intentionally separate operator actions, preventing an API bypass.
    return {"decision": decision.model_dump(mode="json"), "config_change_required": decision.decision == "approved"}


@app.get("/ops/recovery/{job_id}/verifications")
async def recovery_verifications(job_id: str, limit: int = 50, _: bool = Depends(require_api_key)):
    try:
        return {"job_id": job_id, "verifications": [redact(row) for row in production_readiness_repository.list_recovery_verifications(job_id, limit)]}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Recovery verification persistence unavailable.") from exc


@app.post("/ops/recovery/{job_id}/verify")
async def verify_recovery(job_id: str, req: RecoveryVerificationRequest, _: bool = Depends(require_api_key)):
    verification = RecoveryVerificationV1(job_id=job_id, **req.model_dump())
    try:
        production_readiness_repository.save_recovery_verification(verification)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Recovery verification persistence unavailable.") from exc
    return {"verification": verification.model_dump(mode="json")}


@app.get("/ops/incidents")
async def operational_incidents(limit: int = 100, _: bool = Depends(require_api_key)):
    try:
        return {"incidents": [redact(row) for row in production_readiness_repository.list_incidents(limit)]}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Incident persistence unavailable.") from exc


@app.post("/ops/artifacts/sweep")
async def sweep_artifacts(dry_run: bool = True, _: bool = Depends(require_api_key)):
    if not bool(get_setting("artifact_storage", {}).get("sweep_enabled", True)):
        raise HTTPException(status_code=409, detail="Artifact sweep is disabled by configuration.")
    sweep = browser_artifact_store.sweep_expired(dry_run=dry_run)
    try:
        supabase.table("artifact_sweeps").insert(sweep.model_dump(mode="json")).execute()
    except Exception as exc:
        if _execution_mode() == "strict":
            raise HTTPException(status_code=503, detail="Artifact sweep audit persistence unavailable.") from exc
    return sweep.model_dump(mode="json")


# Stage 6 evaluation routes are registered after API-key auth exists, but
# before the legacy endpoint block.
evaluation_route_memory = register_evaluation_routes(
    app, require_api_key, evaluation_engine, evaluation_repository,
    durable_execution_repository, get_setting, production_readiness_repository,
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


class ReasoningCycleRequest(BaseModel):
    request: str = ""
    model_id: str = ""
    mode: str = Field(default="shadow", pattern="^(shadow|strict)$")
    model_actions: List[Dict[str, Any]] = Field(default_factory=list)


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


class ChainBuildRequest(BaseModel):
    objective: str = ""
    protocol_operations: List[Dict[str, Any]] = Field(default_factory=list)


class ChainEvaluateRequest(BaseModel):
    graph: Dict[str, Any] = Field(default_factory=dict)


class ImpactGraphCompileRequest(BaseModel):
    objective: str = ""
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    identity_graph_digest: str = ""
    knowledge_graph_digest: str = ""
    workflow_matrix_id: str = ""


class ImpactChainEvaluateRequest(BaseModel):
    graph: Dict[str, Any] = Field(default_factory=dict)
    evidence_roles: Dict[str, List[str]] = Field(default_factory=dict)
    identity_contexts: List[Dict[str, Any]] = Field(default_factory=list)
    impact: Dict[str, Any] = Field(default_factory=dict)
    approval_present: bool = False
    mutation: bool = False


class MissionCreateRequest(BaseModel):
    objective: str = Field(min_length=1, max_length=4000)
    target: str = ""
    risk_profile: str = "bounded_autonomy"
    budget: Dict[str, Any] = Field(default_factory=dict)
    deadline_at: Optional[str] = None


class MissionPlanRequest(BaseModel):
    objective: str = ""
    sources: Dict[str, Any] = Field(default_factory=dict)


class MissionDispatchCheckRequest(BaseModel):
    approved: bool = False
    approval_ref: str = ""
    approval_digest: str = ""


class KnowledgeIngestRequest(BaseModel):
    sources: Dict[str, Any] = Field(default_factory=dict)
    scope: Dict[str, Any] = Field(default_factory=dict)
    version: Optional[int] = Field(default=None, ge=1, le=100000)
    parent_graph_id: str = ""


class KnowledgeRebuildRequest(BaseModel):
    sources: Dict[str, Any] = Field(default_factory=dict)
    scope: Dict[str, Any] = Field(default_factory=dict)
    include_historical_memory: bool = True


class ReconClosureRequest(BaseModel):
    """Read-only request for deterministic Stage 27 recon synthesis."""

    sources: Dict[str, Any] = Field(default_factory=dict)
    scope: Dict[str, Any] = Field(default_factory=dict)
    freshness_boundary: str = Field(default="live-observations-24h", min_length=1, max_length=200)
    max_actions: int = Field(default=50, ge=1, le=200)


class ContradictionReviewRequest(BaseModel):
    status: str = Field(pattern="^(reviewed|resolved|stale)$")
    reviewer_id: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=2000)


class ImpactPlanRequest(BaseModel):
    objective: str = ""
    identity_id: str = ""
    auth_context_id: str = ""
    exact_steps: List[Dict[str, Any]] = Field(default_factory=list)
    payload_ids: List[str] = Field(default_factory=list)
    bindings: Dict[str, Any] = Field(default_factory=dict)


class ProtocolCaptureRequest(BaseModel):
    target: str
    captures: List[Dict[str, Any]] = Field(default_factory=list)


class ProtocolComparisonRequest(BaseModel):
    protocol: str = "http"
    operation_id: str = ""
    baseline: Dict[str, Any] = Field(default_factory=dict)
    test: Dict[str, Any] = Field(default_factory=dict)
    control: Dict[str, Any] = Field(default_factory=dict)
    evidence_ids: List[str] = Field(default_factory=list)
    tool_run_id: str = ""
    job_id: Optional[str] = None
    attempt_id: str = ""


class PayloadProposalRequest(BaseModel):
    target_url: str
    input_ref: str
    family: str
    risk: str = "harmless"
    redacted_excerpt: str = ""
    encoding_variants: List[str] = Field(default_factory=list)
    expected_signal: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    cleanup_ref: str = ""
    value_hash: str = ""
    parser_context: str = "unknown"
    parameter_location: str = ""
    mutation_operator: str = ""
    schema_digest: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


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
    graph_id: str = ""
    matrix_id: str = ""
    entity_fingerprints: List[str] = Field(default_factory=list)
    clean_context: bool = False


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
    graph_id: str = ""
    workflow_matrix_id: str = ""
    required_role_labels: List[str] = Field(default_factory=list)
    required_tenant_labels: List[str] = Field(default_factory=list)
    required_entity_fingerprints: List[str] = Field(default_factory=list)


class BusinessInvariantEvaluateRequest(BaseModel):
    transitions: List[Dict[str, Any]] = Field(default_factory=list)
    runs: List[Dict[str, Any]] = Field(default_factory=list)
    observations: List[Dict[str, Any]] = Field(default_factory=list)


class IdentityGraphBuildRequest(BaseModel):
    claim_identity_ids: List[str] = Field(default_factory=list)


class IdentityCoverageRequest(BaseModel):
    graph_id: str
    required_identity_ids: List[str] = Field(default_factory=list)
    required_resource_fingerprints: List[str] = Field(default_factory=list)


class WorkflowMatrixRequest(BaseModel):
    workflow_id: str
    graph_id: str
    identity_ids: List[str] = Field(default_factory=list)
    entity_fingerprint: str = ""
    run_roles: Dict[str, str] = Field(default_factory=dict)
    cleanup_required: Optional[bool] = None


class IdentityAccessEvaluationRequest(BaseModel):
    attempts: List[Dict[str, Any]] = Field(default_factory=list)
    owner_identity_id: str
    resource_fingerprint: str
    require_clean_reproduction: bool = True
    require_cleanup: bool = False


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


class IdentityWorkflowDiscoveryRequest(BaseModel):
    origin: str
    captures: List[Dict[str, Any]] = []
    identity_id: str = ""
    identity_ids: List[str] = []
    goal: str = "map identity, session, and workflow prerequisites"
    persist: bool = True


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


def _agent_models_for_context(context: Dict[str, Any]) -> Dict[str, str]:
    """Propagate the immutable session model choice to every phase agent."""
    selected_model_id = str((context or {}).get("model_id") or "")
    if not selected_model_id:
        return {}
    return {
        role: selected_model_id
        for role in ("recon", "analis", "eksekutor", "assessor")
    }


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
    require_queue: bool = False,
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
    # In shadow mode, pentest jobs are executed by the API background task.
    # Enqueuing the same job for the general worker creates two independent
    # executions (duplicate requests, browser sessions, and findings).  Keep
    # durable enqueue for worker-owned job types such as evaluations and
    # readiness soaks; a pentest becomes worker-owned only in strict mode.
    if job_type == "pentest" and _execution_mode() != "strict":
        print("[DURABLE] shadow pentest stays API-background-owned")
        return job
    try:
        durable_execution_repository.enqueue(job)
    except Exception as exc:
        if require_queue or _execution_mode() == "strict":
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


def _execution_integrity_failure(
    all_results: Dict[str, Any],
    logs_data: Dict[str, Any],
    structured_runs: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Return a fail-closed reason when a phase only produced narrative.

    LLM phase text is an observation, not proof that a registered tool ran.
    A successful-looking job with zero authoritative tool executions is a
    false success and must never reach reporting as ``done``.
    """
    phase_errors: List[str] = []
    for phase, result in (all_results or {}).items():
        if isinstance(result, str) and result.lstrip().lower().startswith("error:"):
            phase_errors.append(str(phase))
        elif isinstance(result, dict) and str(result.get("status", "")).lower() in {
            "error", "failed", "failure",
        }:
            phase_errors.append(str(phase))

    if phase_errors:
        return f"phase execution failed: {', '.join(sorted(phase_errors))}"

    summary = (logs_data or {}).get("summary") or {}
    tools_executed = summary.get("tools_executed") or []
    authoritative_runs = [
        row for row in (structured_runs or [])
        if str(row.get("category", "")) != "phase_narrative"
        and not str(row.get("tool_name", "")).startswith("phase:")
    ]
    failed_runs = [
        row for row in authoritative_runs
        if str(row.get("status", "")).lower() in {"failed", "error", "partial"}
    ]
    if failed_runs:
        names = sorted({str(row.get("tool_name", "unknown")) for row in failed_runs})
        return f"authoritative tool execution failed: {', '.join(names)}"
    if not any(str(tool).strip() for tool in tools_executed) and not authoritative_runs:
        return "no authoritative tool execution was recorded"

    return ""


def _merge_structured_execution_summary(
    logs_data: Dict[str, Any],
    structured_runs: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Expose durable tool execution in the compatibility report summary.

    The in-memory execution logger is intentionally not the source of truth
    for worker/tool execution.  A worker can complete a structured run while
    that process-local logger remains empty, so report metadata must merge the
    persisted authoritative runs without turning narrative phase records into
    tool executions.
    """
    merged = dict(logs_data or {})
    summary = dict(merged.get("summary") or {})
    authoritative = [
        row for row in (structured_runs or [])
        if str(row.get("category", "")) != "phase_narrative"
        and not str(row.get("tool_name", "")).startswith("phase:")
    ]

    names = list(summary.get("tools_executed") or [])
    for row in authoritative:
        name = str(row.get("tool_name") or "").strip()
        if name and name not in names:
            names.append(name)
    summary["tools_executed"] = names
    summary["structured_tool_runs"] = len(authoritative)
    summary["error_count"] = int(summary.get("error_count") or 0) + sum(
        1 for row in authoritative
        if str(row.get("status", "")).lower() in {"failed", "error", "partial"}
    )
    merged["summary"] = summary
    return merged


def _persist_report_file(
    report_dir: str,
    session_id: str,
    job_id: str,
    report: str,
) -> str:
    """Persist a report and return its path; callers must handle failure."""
    os.makedirs(report_dir, exist_ok=True)
    report_file = os.path.join(report_dir, f"{session_id}_{job_id[:8]}.md")
    with open(report_file, "w", encoding="utf-8") as report_handle:
        report_handle.write(report)
    return report_file


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

            # ``update_job`` is the durable/canonical execution log here.
            # The old process-global logger was removed with the durable
            # execution migration; calling it made a successful WAF probe
            # look like a skipped probe because ``_logger`` no longer exists.
            update_job(
                job_id,
                message=(
                    f"WAF strategy applied: {waf_name} | "
                    f"Rate: {waf_strategy.get('rate_limit', 2.0)} req/s"
                ),
            )
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
        try:
            structured_run_ids_before = {
                str(row.get("tool_run_id"))
                for row in structured_repository.list_runs(session_id)
                if row.get("tool_run_id")
            }
        except Exception:
            structured_run_ids_before = set()
        
        session_context = session_store.get(session_id) or {}
        preset = scan_config.get("scan_preset") or session_context.get("scan_preset", "full")
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

        # Do not let an LLM-generated report turn a provider/tool-contract
        # failure into a successful pentest. The phase narrative is persisted
        # as observation only; an actual registered tool run is mandatory.
        phase1_logs = get_execution_logs()
        try:
            structured_runs_after = [
                row for row in structured_repository.list_runs(session_id)
                if str(row.get("tool_run_id")) not in structured_run_ids_before
            ]
        except Exception as persistence_err:
            structured_runs_after = []
            integrity_error = f"structured tool persistence unavailable: {type(persistence_err).__name__}"
        else:
            integrity_error = _execution_integrity_failure(
                all_results, phase1_logs, structured_runs_after,
            )
        if integrity_error:
            message = f"Execution integrity failure: {integrity_error}."
            save_message(session_id, "agent", f"JOB FAILED: {message}")
            update_job(
                job_id,
                status="error",
                message=message,
                report=None,
                logs=phase1_logs["logs"],
                summary=phase1_logs["summary"],
            )
            return

        # A recon-only request is a complete bounded workflow.  Do not enter
        # the legacy interactive consultation or assessor phases: they are
        # intended for full pentest jobs and would otherwise leave a finished
        # reconnaissance run waiting on an unrelated HITL continue event.
        if preset == "recon-only":
            logs_data = _merge_structured_execution_summary(
                get_execution_logs(), structured_runs_after,
            )
            # The structured repository and knowledge graph are authoritative
            # for bounded recon.  Do not push the complete legacy log bundle
            # (which can be very large for a local lab) through the workflow
            # job payload during terminalization.  Keeping a compact status
            # marker makes the durable job finish reliably while callers can
            # retrieve full detail from /tool-runs and /knowledge.
            compact_summary = {
                "tools_executed": logs_data.get("summary", {}).get("tools_executed", []),
                "structured_tool_runs": len(structured_runs_after),
                "log_count": len(logs_data.get("logs", [])),
                "recon_source": "structured_tool_runs_and_knowledge_graph",
            }
            update_job(
                job_id,
                status="done",
                message="Reconnaissance complete.",
                report=None,
                logs=[],
                summary=compact_summary,
            )
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

        logs_data = _merge_structured_execution_summary(
            get_execution_logs(), structured_runs_after,
        )

        if cancellation_store.is_cancelled(job_id):
            save_message(session_id, "agent", "JOB CANCELLED by user.")
            update_job(job_id, status="cancelled", message="Cancelled by user.", logs=logs_data["logs"], summary=logs_data["summary"])
        else:
            # A report is not complete until its durable file artifact exists.
            # In particular, do not report ``done`` when a bind-mounted
            # reports directory is unwritable inside the non-root container.
            try:
                report_file = _persist_report_file(
                    "/app/reports", session_id, job_id, report,
                )
                print(f"[REPORT] Saved to {report_file}")
            except Exception as file_err:
                message = f"Report persistence failed: {type(file_err).__name__}."
                print(f"[REPORT] {message}")
                save_message(session_id, "agent", f"JOB FAILED: {message}")
                update_job(
                    job_id,
                    status="error",
                    message=message,
                    report=None,
                    logs=logs_data["logs"],
                    summary=logs_data["summary"],
                )
                return

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


@app.post("/sessions/{session_id}/workflow/reasoning/cycles")
async def create_reasoning_cycle(session_id: str, req: ReasoningCycleRequest, _: bool = Depends(require_api_key)):
    try:
        result = workflow_planner.reasoning_cycle(
            session_id, req.request, model_actions=req.model_actions,
            model_id=req.model_id, mode=req.mode,
        )
        persistence = "memory"
        try:
            structured_repository.save_reasoning_result(session_id, result)
            persistence = "supabase"
        except Exception as exc:
            if req.mode == "strict":
                raise HTTPException(status_code=503, detail=f"Reasoning persistence unavailable: {type(exc).__name__}") from exc
        return {**result, "persistence": persistence}
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Reasoning cycle failed: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/workflow/reasoning/cycles")
async def list_reasoning_cycles(session_id: str, limit: int = 50, _: bool = Depends(require_api_key)):
    try:
        bounded = max(1, min(limit, 200))
        return {"session_id": session_id, "cycles": structured_repository.list_reasoning_cycles(session_id, bounded)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Reasoning persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/workflow/reasoning/cycles/{cycle_id}")
async def get_reasoning_cycle(session_id: str, cycle_id: str, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, **structured_repository.get_reasoning_cycle(session_id, cycle_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Reasoning persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/workflow/reasoning/evidence-gaps")
async def list_reasoning_evidence_gaps(session_id: str, limit: int = 200, _: bool = Depends(require_api_key)):
    try:
        rows = structured_repository.sb.table("reasoning_evidence_gaps").select("*").eq("session_id", session_id).order("created_at", desc=True).limit(max(1, min(limit, 500))).execute().data or []
        return {"session_id": session_id, "evidence_gaps": rows}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Reasoning persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/workflow/reasoning/branches")
async def list_reasoning_branches(session_id: str, cycle_id: Optional[str] = None, limit: int = 200, _: bool = Depends(require_api_key)):
    """Return durable search branches without exposing raw model prompts/output."""
    try:
        bounded = max(1, min(limit, 500))
        return {
            "session_id": session_id,
            "cycle_id": cycle_id or "",
            "branches": structured_repository.list_reasoning_branches(session_id, cycle_id, bounded),
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Reasoning branch persistence unavailable: {redact(str(exc))[:500]}")


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


def _knowledge_session_target(session_id: str) -> str:
    context = session_store.require(session_id)
    target = str(context.get("target_url") or "").strip()
    if not target:
        raise ValueError("Active session has no target URL.")
    return target


def _knowledge_graph_sources(session_id: str, supplied: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Collect structured session-local sources for the canonical graph."""
    sources: Dict[str, Any] = {}
    for key, values in (supplied or {}).items():
        if isinstance(values, list):
            sources[key] = [redact(item) for item in values if isinstance(item, (dict, str))]
    try:
        current = knowledge_graph_repository.current(session_id)
        if current:
            detail = knowledge_graph_repository.graph(session_id, current["graph_id"])
            node_by_id = {
                str(row.get("node_id")): row
                for row in detail.get("nodes", [])
                if row.get("node_id")
            }
            for key, rows in (("nodes", detail.get("nodes", [])), ("edges", detail.get("edges", [])), ("coverage", detail.get("coverage", []))):
                if key == "nodes":
                    source_type_by_node_type = {
                        "asset": "assets", "origin": "origins", "service": "services",
                        "endpoint": "endpoints", "operation": "operations", "parameter": "parameters",
                        "input": "inputs", "schema": "schemas", "identity": "identities",
                        "role": "roles", "tenant": "tenants", "auth_context": "auth_contexts",
                        "entity": "entities", "resource": "resources", "workflow": "workflows",
                        "state": "states", "protocol": "protocols", "trust_boundary": "trust_boundaries",
                        "observation": "observations", "candidate": "candidates", "finding": "findings",
                        "capability": "capabilities", "cleanup": "cleanups",
                        "ip_address": "ip_addresses", "certificate": "certificates",
                        "dns_record": "dns_records", "redirect": "redirects",
                        "technology": "technology_fingerprints", "waf_profile": "waf_profiles",
                        "provider_observation": "provider_observations",
                        "auth_surface": "auth_surfaces", "session_transition": "session_transitions",
                        "prerequisite": "workflow_prerequisites",
                    }
                    for row in rows:
                        reference_id = str(row.get("reference_id", "")).strip().lower().rstrip("/")
                        canonical_locator = str(row.get("canonical_locator", "")).strip().lower().rstrip("/")
                        synthetic_locator = canonical_locator in {reference_id, "/" + reference_id.lstrip("/")}
                        if row.get("graph_id") and synthetic_locator and not row.get("source_ids") and not row.get("evidence_ids"):
                            # Do not promote an old fallback locator from a
                            # symbolic reference ID into a canonical rebuild.
                            continue
                        source_type = source_type_by_node_type.get(str(row.get("node_type", "")), "observations")
                        sources.setdefault(source_type, []).append(row)
                elif key == "edges":
                    for row in rows:
                        source = node_by_id.get(str(row.get("source_node_id")))
                        target = node_by_id.get(str(row.get("target_node_id")))
                        if not source or not target:
                            continue
                        sources.setdefault("edges", []).append({
                            "source_reference_id": source.get("reference_id", ""),
                            "target_reference_id": target.get("reference_id", ""),
                            "relation": row.get("relation", "derived_from"),
                            "status": row.get("status", "hypothesized"),
                            "evidence_ids": row.get("evidence_ids", []),
                            "source_ids": row.get("source_ids", []),
                            "metadata": row.get("metadata", {}),
                        })
                else:
                    sources.setdefault("coverage", []).extend(rows)
    except Exception:
        pass
    # Existing structured repositories are joined here, not through raw text.
    try:
        for row in structured_repository.list_candidates(session_id, limit=500):
            metadata = row.get("metadata") or {}
            sources.setdefault("candidates", []).append({
                "reference_id": row.get("candidate_id", ""), "label": row.get("title", "candidate"),
                "status": row.get("status", "hypothesized"),
                "evidence_ids": metadata.get("evidence_ids") or row.get("observation_ids") or [],
                "identity_id": metadata.get("identity_id", ""), "tenant_label": metadata.get("tenant_label", ""),
            })
    except Exception:
        pass
    try:
        for row in authorization_repository.list_identities(session_id):
            sources.setdefault("identities", []).append({
                "reference_id": row.get("identity_id", ""), "label": row.get("label") or row.get("identity_id", ""),
                "identity_id": row.get("identity_id", ""), "evidence_ids": row.get("evidence_ids") or [],
                "metadata": {"kind": row.get("kind", ""), "role_label": row.get("role_label", ""), "tenant_label": row.get("tenant_label", "")},
            })
    except Exception:
        pass
    try:
        for row in browser_workflow_repository.list_workflows(session_id):
            sources.setdefault("workflows", []).append({
                "reference_id": row.get("workflow_id", ""), "label": row.get("name") or row.get("workflow_id", ""),
                "status": row.get("status", "observed"), "evidence_ids": row.get("source_observation_ids") or [],
            })
        for row in browser_workflow_repository.list_entities(session_id):
            sources.setdefault("entities", []).append({
                "reference_id": row.get("entity_id") or row.get("fingerprint", ""),
                "label": row.get("fingerprint", "entity"), "entity_fingerprint": row.get("fingerprint", ""),
                "evidence_ids": row.get("source_snapshot_ids") or [],
                "metadata": {"state_digest": row.get("state_digest", "")},
            })
    except Exception:
        pass
    return redact(sources)


@app.post("/sessions/{session_id}/knowledge/ingest")
async def ingest_target_knowledge(session_id: str, req: KnowledgeIngestRequest, _: bool = Depends(require_api_key)):
    try:
        target = _knowledge_session_target(session_id)
        current = knowledge_graph_repository.current(session_id)
        version = req.version or (int(current.get("version", 0)) + 1 if current else 1)
        parent = req.parent_graph_id or (str(current.get("graph_id", "")) if current else "")
        sources = _knowledge_graph_sources(session_id, req.sources)
        compiled = knowledge_graph_engine.compile(session_id, target, sources, scope=req.scope, version=version, parent_graph_id=parent)
        saved = knowledge_graph_repository.save_compiled(compiled)
        return {"mode": get_setting("target_knowledge_mode", "shadow"), "compiled": compiled, "saved": saved}
    except KnowledgeGraphError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Target knowledge persistence unavailable.") from exc


@app.post("/sessions/{session_id}/knowledge/rebuild")
async def rebuild_target_knowledge(session_id: str, req: KnowledgeRebuildRequest, _: bool = Depends(require_api_key)):
    return await ingest_target_knowledge(session_id, KnowledgeIngestRequest(sources=req.sources, scope=req.scope), _)


def _closure_plan_from_graph(session_id: str, graph_id: str, *, freshness_boundary: str, max_actions: int) -> Dict[str, Any]:
    detail = knowledge_graph_repository.graph(session_id, graph_id)
    detail["gaps"] = knowledge_graph_repository.gaps(session_id, graph_id, limit=2000)
    sources = _knowledge_graph_sources(session_id)
    plan = knowledge_graph_engine.synthesize_recon_closure(
        detail, sources, freshness_boundary=freshness_boundary, max_actions=max_actions,
    )
    return {"session_id": session_id, "mode": get_setting("target_knowledge_mode", "shadow"), "plan": plan}


@app.get("/sessions/{session_id}/knowledge/closure-plan")
async def get_target_recon_closure_plan(
    session_id: str,
    graph_id: Optional[str] = None,
    freshness_boundary: str = "live-observations-24h",
    max_actions: int = 50,
    _: bool = Depends(require_api_key),
):
    try:
        current = knowledge_graph_repository.current(session_id)
        selected = graph_id or str((current or {}).get("graph_id", ""))
        if not selected:
            return {"session_id": session_id, "mode": get_setting("target_knowledge_mode", "shadow"), "plan": None}
        return _closure_plan_from_graph(session_id, selected, freshness_boundary=freshness_boundary, max_actions=max_actions)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Recon closure persistence unavailable.") from exc


@app.post("/sessions/{session_id}/knowledge/closure-plan")
async def create_target_recon_closure_plan(
    session_id: str,
    req: ReconClosureRequest,
    _: bool = Depends(require_api_key),
):
    """Compile and synthesize a plan without persisting a new graph version."""
    try:
        target = _knowledge_session_target(session_id)
        current = knowledge_graph_repository.current(session_id)
        version = int((current or {}).get("version", 0)) + 1
        parent = str((current or {}).get("graph_id", ""))
        sources = _knowledge_graph_sources(session_id, req.sources)
        compiled = knowledge_graph_engine.compile(
            session_id, target, sources, scope=req.scope, version=version, parent_graph_id=parent,
        )
        plan = knowledge_graph_engine.synthesize_recon_closure(
            compiled, sources, freshness_boundary=req.freshness_boundary, max_actions=req.max_actions,
        )
        return {
            "session_id": session_id,
            "mode": get_setting("target_knowledge_mode", "shadow"),
            "persisted": False,
            "plan": plan,
        }
    except KnowledgeGraphError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Recon closure synthesis unavailable.") from exc


@app.get("/sessions/{session_id}/knowledge")
async def get_target_knowledge(session_id: str, graph_id: Optional[str] = None, _: bool = Depends(require_api_key)):
    try:
        graph_id = graph_id or str((knowledge_graph_repository.current(session_id) or {}).get("graph_id", ""))
        if not graph_id:
            return {"session_id": session_id, "graph": None, "nodes": [], "edges": [], "coverage": [], "contradictions": [], "source_links": []}
        return knowledge_graph_repository.graph(session_id, graph_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Target knowledge persistence unavailable.") from exc


@app.get("/sessions/{session_id}/knowledge/versions")
async def list_target_knowledge_versions(session_id: str, limit: int = 100, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "graphs": knowledge_graph_repository.list_graphs(session_id, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Target knowledge persistence unavailable.") from exc


@app.get("/sessions/{session_id}/knowledge/nodes")
async def list_target_knowledge_nodes(session_id: str, graph_id: Optional[str] = None, node_type: Optional[str] = None, limit: int = 500, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "nodes": knowledge_graph_repository.nodes(session_id, graph_id, node_type, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Target knowledge persistence unavailable.") from exc


@app.get("/sessions/{session_id}/knowledge/edges")
async def list_target_knowledge_edges(session_id: str, graph_id: Optional[str] = None, relation: Optional[str] = None, limit: int = 500, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "edges": knowledge_graph_repository.edges(session_id, graph_id, relation, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Target knowledge persistence unavailable.") from exc


@app.get("/sessions/{session_id}/knowledge/contradictions")
async def list_target_knowledge_contradictions(session_id: str, graph_id: Optional[str] = None, status: Optional[str] = None, limit: int = 200, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "contradictions": knowledge_graph_repository.contradictions(session_id, graph_id, status, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Target knowledge persistence unavailable.") from exc


@app.post("/sessions/{session_id}/knowledge/contradictions/{contradiction_id}/review")
async def review_target_knowledge_contradiction(session_id: str, contradiction_id: str, req: ContradictionReviewRequest, _: bool = Depends(require_api_key)):
    try:
        return {"review": knowledge_graph_repository.review_contradiction(session_id, contradiction_id, req.status, req.reviewer_id, req.reason)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Contradiction review persistence unavailable.") from exc


@app.get("/sessions/{session_id}/coverage")
async def list_target_coverage(session_id: str, graph_id: Optional[str] = None, status: Optional[str] = None, limit: int = 1000, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "coverage": knowledge_graph_repository.coverage(session_id, graph_id, status, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Coverage persistence unavailable.") from exc


@app.get("/sessions/{session_id}/coverage/gaps")
async def list_target_coverage_gaps(session_id: str, graph_id: Optional[str] = None, limit: int = 500, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "gaps": knowledge_graph_repository.gaps(session_id, graph_id, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Coverage persistence unavailable.") from exc


@app.post("/sessions/{session_id}/coverage/recompute")
async def recompute_target_coverage(session_id: str, req: KnowledgeIngestRequest, _: bool = Depends(require_api_key)):
    return await ingest_target_knowledge(session_id, req, _)


def _mission_sources(session_id: str, supplied: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Collect only session-local structured material for mission planning."""
    sources: Dict[str, Any] = _knowledge_graph_sources(session_id, supplied)
    try:
        for row in structured_repository.list_candidates(session_id, limit=500):
            metadata = row.get("metadata") or {}
            sources.setdefault("candidates", []).append({
                "node_type": "candidate", "reference_id": row.get("candidate_id", ""),
                "label": row.get("title", "candidate"),
                "status": row.get("status", "hypothesized"),
                "evidence_ids": metadata.get("evidence_ids") or row.get("observation_ids") or [],
                "identity_id": metadata.get("identity_id", ""),
                "tenant_label": metadata.get("tenant_label", ""),
            })
    except Exception:
        pass
    try:
        for row in authorization_repository.list_identities(session_id):
            sources.setdefault("identities", []).append({
                "node_type": "identity", "reference_id": row.get("identity_id", ""),
                "label": row.get("label") or row.get("name") or row.get("identity_id", ""),
                "evidence_ids": row.get("evidence_ids") or [],
                "metadata": {"kind": row.get("kind", "")},
            })
    except Exception:
        pass
    try:
        for row in browser_workflow_repository.list_workflows(session_id):
            sources.setdefault("workflows", []).append({
                "node_type": "workflow", "reference_id": row.get("workflow_id", ""),
                "label": row.get("name") or row.get("workflow_id", ""),
                "status": row.get("status", "observed"), "evidence_ids": row.get("evidence_ids") or [],
            })
    except Exception:
        pass
    try:
        for row in browser_workflow_repository.list_entities(session_id):
            sources.setdefault("entities", []).append({
                "node_type": "entity", "reference_id": row.get("entity_id") or row.get("fingerprint", ""),
                "label": row.get("fingerprint", "entity"), "evidence_ids": row.get("source_snapshot_ids") or [],
                "metadata": {"state_digest": row.get("state_digest", "")},
            })
    except Exception:
        pass
    # Remove empty or duplicate references before the graph compiler sees them.
    for key, values in list(sources.items()):
        if not isinstance(values, list):
            sources.pop(key, None)
            continue
        seen = set()
        cleaned = []
        for value in values:
            if isinstance(value, dict):
                reference = str(value.get("reference_id") or value.get("id") or value.get("candidate_id") or "")
                if key == "edges":
                    reference = str(value.get("edge_id") or value.get("source_reference_id") or value.get("source_ref") or "") + ":" + str(value.get("target_reference_id") or value.get("target_ref") or "")
                if not reference or reference in seen:
                    continue
                seen.add(reference)
            cleaned.append(value)
        sources[key] = cleaned
    return redact(sources)


@app.post("/sessions/{session_id}/missions")
async def create_mission(session_id: str, req: MissionCreateRequest, _: bool = Depends(require_api_key)):
    try:
        context = session_store.require(session_id)
        target = req.target or str(context.get("target_url", ""))
        if not target:
            raise ValueError("Mission target is missing from the active session.")
        mission = MissionV1(
            session_id=session_id, target=target, objective=req.objective,
            risk_profile=req.risk_profile or str((get_setting("mission_graph", {}) or {}).get("risk_profile", "bounded_autonomy")),
            budget=req.budget or _execution_budget().model_dump(mode="json"), deadline_at=req.deadline_at,
            config_digest=stable_digest(get_config()), policy_version="14.0",
        )
        row = mission_repository.create(mission)
        return {"mission": row, "mode": get_setting("mission_graph_mode", "shadow")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mission persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/missions")
async def list_missions(session_id: str, limit: int = 100, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "missions": mission_repository.list(session_id, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mission persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/missions/{mission_id}")
async def get_mission(session_id: str, mission_id: str, _: bool = Depends(require_api_key)):
    try:
        row = mission_repository.get(session_id, mission_id)
        if not row:
            raise HTTPException(status_code=404, detail="Mission not found.")
        return {"mission": row, "mode": get_setting("mission_graph_mode", "shadow")}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mission persistence unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/missions/{mission_id}/plan")
async def plan_mission(session_id: str, mission_id: str, req: MissionPlanRequest, _: bool = Depends(require_api_key)):
    try:
        row = mission_repository.get(session_id, mission_id)
        if not row:
            raise ValueError("Mission not found.")
        mission = MissionV1(**row)
        mission.graph_version = max(1, int(mission.graph_version or 0))
        sources = _mission_sources(session_id, req.sources)
        graph = mission_graph_engine.seed(mission, sources)
        mission_repository.save_graph(session_id, graph)
        planned = mission_graph_engine.plan(graph, req.objective or mission.objective)
        mission_repository.save_paths(session_id, planned)
        mission_repository.save_decision(session_id, planned["decision"])
        mission_repository.save_event(session_id, planned["event"])
        selected = (planned.get("paths") or [None])[0]
        status = "waiting_approval" if selected and selected.get("status") == "waiting_approval" else "planning"
        mission_repository.update_status(session_id, mission_id, status)
        return {"session_id": session_id, **planned, "mode": get_setting("mission_graph_mode", "shadow")}
    except MissionGraphError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mission graph persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/missions/{mission_id}/graph")
async def get_mission_graph(session_id: str, mission_id: str, version: Optional[int] = None, _: bool = Depends(require_api_key)):
    try:
        return mission_repository.get_graph(session_id, mission_id, version)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mission graph persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/missions/{mission_id}/paths")
async def list_mission_paths(session_id: str, mission_id: str, limit: int = 100, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "mission_id": mission_id, "paths": mission_repository.paths(session_id, mission_id, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mission path persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/missions/{mission_id}/decisions")
async def list_mission_decisions(session_id: str, mission_id: str, limit: int = 100, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "mission_id": mission_id, "decisions": mission_repository.decisions(session_id, mission_id, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mission decision persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/missions/{mission_id}/events")
async def list_mission_events(session_id: str, mission_id: str, limit: int = 200, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "mission_id": mission_id, "events": mission_repository.events(session_id, mission_id, limit)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mission event persistence unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/missions/{mission_id}/paths/{path_id}/dispatch-check")
async def check_mission_dispatch(session_id: str, mission_id: str, path_id: str, req: MissionDispatchCheckRequest, _: bool = Depends(require_api_key)):
    try:
        path = mission_repository.get_path(session_id, mission_id, path_id)
        if not path:
            raise HTTPException(status_code=404, detail="Mission path not found.")
        decision = mission_graph_engine.validate_dispatch(
            path, approved=req.approved, approval_ref=req.approval_ref,
            approval_digest=req.approval_digest,
        )
        return {"mission_id": mission_id, "path_id": path_id, "decision": decision, "mode": get_setting("mission_graph_mode", "shadow")}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mission dispatch check unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/missions/{mission_id}/replan")
async def replan_mission(session_id: str, mission_id: str, req: MissionPlanRequest, _: bool = Depends(require_api_key)):
    try:
        row = mission_repository.get(session_id, mission_id)
        if not row:
            raise ValueError("Mission not found.")
        mission = MissionV1(**row)
        mission.graph_version = max(1, int(mission.graph_version or 0) + 1)
        mission.status = "replanning"
        graph = mission_graph_engine.seed(mission, _mission_sources(session_id, req.sources))
        mission_repository.save_graph(session_id, graph)
        planned = mission_graph_engine.plan(graph, req.objective or mission.objective)
        mission_repository.save_paths(session_id, planned)
        mission_repository.save_decision(session_id, planned["decision"])
        mission_repository.save_event(session_id, planned["event"])
        return {"session_id": session_id, **planned, "mode": get_setting("mission_graph_mode", "shadow")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mission replan persistence unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/workflow/chains/build")
async def build_workflow_chain(session_id: str, req: ChainBuildRequest, _: bool = Depends(require_api_key)):
    try:
        graph = chain_planner.build_graph(session_id, req.objective, req.protocol_operations)
        if graph.get("status") == "proposed":
            structured_repository.save_chain_graph(session_id, graph)
        return {"session_id": session_id, **graph, "mode": get_setting("exploit_chain_mode", "shadow")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Chain persistence unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/workflow/chains/impact-graph/compile")
async def compile_impact_graph(session_id: str, req: ImpactGraphCompileRequest, _: bool = Depends(require_api_key)):
    """Compile an explicit identity/business impact DAG.

    Nodes and edges are supplied by discovery/workflow services; the planner
    drops anything without evidence or deterministic endpoints. This endpoint
    only creates a proposed graph and never executes a mutation.
    """
    try:
        graph = chain_planner.build_impact_graph(
            session_id,
            req.objective,
            nodes=req.nodes,
            edges=req.edges,
            identity_graph_digest=req.identity_graph_digest,
            knowledge_graph_digest=req.knowledge_graph_digest,
            workflow_matrix_id=req.workflow_matrix_id,
        )
        if graph.get("status") == "proposed":
            structured_repository.save_chain_graph(session_id, graph)
        return {"session_id": session_id, **graph, "mode": get_setting("identity_business_impact_mode", "shadow")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Impact graph persistence unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/workflow/chains/impact-graph/evaluate")
async def evaluate_impact_graph(session_id: str, req: ImpactChainEvaluateRequest, _: bool = Depends(require_api_key)):
    """Run chain-level deterministic checks; Stage 1 owns finding promotion."""
    try:
        evaluation = chain_planner.evaluate_impact_chain(
            session_id,
            req.graph,
            evidence_roles=req.evidence_roles,
            identity_contexts=req.identity_contexts,
            impact=req.impact,
            approval_present=req.approval_present,
            mutation=req.mutation,
        )
        saved = structured_repository.save_chain_evaluation(session_id, evaluation)
        return {"session_id": session_id, "evaluation": saved, "mode": get_setting("identity_business_impact_mode", "shadow")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Impact graph evaluation persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/workflow/chains")
async def list_workflow_chains(session_id: str, status: Optional[str] = None, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "chains": structured_repository.list_chains(session_id, status)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Chain persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/workflow/chains/{chain_id}")
async def get_workflow_chain(session_id: str, chain_id: str, _: bool = Depends(require_api_key)):
    try:
        return structured_repository.get_chain(session_id, chain_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Chain persistence unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/workflow/chains/{chain_id}/evaluate")
async def evaluate_workflow_chain(session_id: str, chain_id: str, req: ChainEvaluateRequest, _: bool = Depends(require_api_key)):
    try:
        graph = req.graph or structured_repository.get_chain(session_id, chain_id)
        if str((graph.get("chain") or {}).get("chain_id", chain_id)) != chain_id:
            raise ValueError("Chain ID does not match the supplied graph.")
        evaluation = chain_planner.evaluate_graph(session_id, graph)
        saved = structured_repository.save_chain_evaluation(session_id, evaluation)
        return {"session_id": session_id, "evaluation": saved}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Chain evaluation persistence unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/workflow/chains/impact-plan")
async def create_chain_impact_plan(session_id: str, req: ImpactPlanRequest, _: bool = Depends(require_api_key)):
    try:
        result = impact_service.build_plan(
            session_id, req.objective, identity_id=req.identity_id,
            auth_context_id=req.auth_context_id, exact_steps=req.exact_steps or None,
            payload_ids=req.payload_ids, bindings=req.bindings,
        )
        plan_row = dict(result["plan"])
        plan_row["exact_steps"] = plan_row.pop("exact_steps", [])
        structured_repository.save_impact_plan(session_id, plan_row)
        return {"session_id": session_id, **result, "mode": get_setting("exploit_chain_mode", "shadow")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Impact plan persistence unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/workflow/protocol-surface")
async def record_protocol_surface(session_id: str, req: ProtocolCaptureRequest, _: bool = Depends(require_api_key)):
    try:
        result = normalize_protocol_capture(session_id, req.target, req.captures)
        operations = operation_dicts(result)
        structured_repository.save_protocol_operations(session_id, operations)
        return {"session_id": session_id, "result": result.model_dump(mode="json"), "operations": operations}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Protocol persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/workflow/protocol-surface")
async def list_protocol_surface(session_id: str, protocol: Optional[str] = None, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "operations": structured_repository.list_protocol_operations(session_id, protocol)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Protocol persistence unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/workflow/protocol-comparisons")
async def create_protocol_comparison(session_id: str, req: ProtocolComparisonRequest, _: bool = Depends(require_api_key)):
    try:
        comparison = compare_protocol_captures(
            req.baseline, req.test, req.control or None,
            protocol=req.protocol, operation_id=req.operation_id,
            evidence_ids=req.evidence_ids,
        )
        saved = structured_repository.save_protocol_comparison(
            session_id, comparison, tool_run_id=req.tool_run_id,
            job_id=req.job_id or "", attempt_id=req.attempt_id,
        )
        return {"session_id": session_id, "comparison": saved}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Protocol comparison persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/workflow/protocol-comparisons")
async def list_protocol_comparisons(session_id: str, protocol: Optional[str] = None, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "comparisons": structured_repository.list_protocol_comparisons(session_id, protocol)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Protocol comparison persistence unavailable: {redact(str(exc))[:500]}")


@app.post("/sessions/{session_id}/workflow/payload-proposals")
async def create_payload_proposal(session_id: str, req: PayloadProposalRequest, _: bool = Depends(require_api_key)):
    try:
        result = impact_service.build_payload_proposal(
            session_id, target_url=req.target_url, input_ref=req.input_ref, family=req.family,
            risk=req.risk, redacted_excerpt=req.redacted_excerpt,
            encoding_variants=req.encoding_variants, expected_signal=req.expected_signal,
            evidence_ids=req.evidence_ids, cleanup_ref=req.cleanup_ref,
            value_hash=req.value_hash, parser_context=req.parser_context,
            parameter_location=req.parameter_location, mutation_operator=req.mutation_operator,
            schema_digest=req.schema_digest, metadata=req.metadata,
        )
        saved = structured_repository.save_payload_proposal(session_id, result["proposal"])
        return {"session_id": session_id, "proposal": saved, "execution_policy": result["execution_policy"]}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Payload persistence unavailable: {redact(str(exc))[:500]}")


@app.get("/sessions/{session_id}/workflow/payload-proposals")
async def list_payload_proposals(session_id: str, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "proposals": structured_repository.list_payload_proposals(session_id)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Payload persistence unavailable: {redact(str(exc))[:500]}")


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
            agent_models = _agent_models_for_context(context)
            if _execution_mode() == "strict":
                _enqueue_execution_job(
                    job_id=dispatch["job_id"], session_id=session_id,
                    target=context["target_url"], goal=context["attack_goal"], job_type="pentest",
                    payload={
                        "scan_config": dispatch["scan_config"],
                        "workflow_action_id": action_id,
                        "agent_models": agent_models,
                    },
                    risk="read_only", idempotency_key=dispatch["job_id"],
                )
            else:
                background_tasks.add_task(
                    run_pentest_job,
                    dispatch["job_id"], context["target_url"], context["attack_goal"], session_id,
                    agent_models, None, dispatch["scan_config"],
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
                graph_id=req.graph_id, matrix_id=req.matrix_id,
                entity_fingerprints=req.entity_fingerprints, clean_context=req.clean_context,
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
                    "graph_id": req.graph_id, "matrix_id": req.matrix_id,
                    "entity_fingerprints": req.entity_fingerprints, "clean_context": req.clean_context,
                }, risk="medium" if workflow.has_mutations() else "read_only", approval_ref=approval_ref,
            )
            return {"run": run.model_dump(mode="json"), "job_id": durable.job_id, "approval_proposal": None}
        run = await stateful_browser_runner.run(workflow, session_id=session_id, target=context["target_url"], identity_id=req.identity_id, auth_context_id=req.auth_context_id, role=req.role, bindings=req.bindings, parent_run_id=req.parent_run_id, graph_id=req.graph_id, matrix_id=req.matrix_id, entity_fingerprints=req.entity_fingerprints, clean_context=req.clean_context)
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
        run = await stateful_browser_runner.run(workflow, session_id=session_id, target=context["target_url"], identity_id=row.get("identity_id", ""), auth_context_id=row.get("auth_context_id", ""), role=row.get("role", "baseline"), bindings=req.bindings, approved=approved, approval_digest=digest, resume_from=BrowserRunV1(**row), graph_id=row.get("graph_id", ""), matrix_id=row.get("matrix_id", ""), entity_fingerprints=row.get("entity_fingerprints", []), clean_context=bool(row.get("clean_context", False)))
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
            invariant = BusinessInvariantV1(session_id=session_id, name=req.name, rule_type=req.rule_type, rule_version=req.rule_version, source=req.source, rule=req.rule, required_workflow_ids=req.required_workflow_ids, required_identity_ids=req.required_identity_ids, required_role_labels=req.required_role_labels, required_tenant_labels=req.required_tenant_labels, required_entity_fingerprints=req.required_entity_fingerprints, source_observation_ids=req.source_observation_ids, graph_id=req.graph_id, workflow_matrix_id=req.workflow_matrix_id)
            invariant.compiled = not bool(business_invariant_compiler.validate_typed(invariant))
        else:
            invariant = business_invariant_compiler.compile(req.name, session_id, req.source)
            invariant.required_workflow_ids = req.required_workflow_ids
            invariant.required_identity_ids = req.required_identity_ids
            invariant.required_role_labels = req.required_role_labels
            invariant.required_tenant_labels = req.required_tenant_labels
            invariant.required_entity_fingerprints = req.required_entity_fingerprints
            invariant.graph_id = req.graph_id
            invariant.workflow_matrix_id = req.workflow_matrix_id
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
        invariant.required_role_labels = req.required_role_labels
        invariant.required_tenant_labels = req.required_tenant_labels
        invariant.required_entity_fingerprints = req.required_entity_fingerprints
        invariant.graph_id = req.graph_id
        invariant.workflow_matrix_id = req.workflow_matrix_id
        invariant.source_observation_ids = req.source_observation_ids
        invariant.status = "draft"
        invariant.compiled = not bool(business_invariant_compiler.validate_typed(invariant))
        invariant.revision += 1
        browser_workflow_repository.save_invariant(invariant)
        return {"invariant": invariant.model_dump(mode="json")}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


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
        missing = business_invariant_compiler.validate_typed(invariant)
        if missing:
            raise ValueError("Invariant is missing typed fields: " + ", ".join(missing))
        invariant.status = "active"
        invariant.compiled = True
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
            v2_decisions = validation_engine_v2.validate(
                result,
                mode=get_setting("detection_depth_mode", "shadow"),
                apply_status=False,
            )
            structured_repository.persist(session_id, result, validation_decisions)
        return {"evaluation": evaluation.model_dump(mode="json"), "candidate": candidate.model_dump(mode="json") if candidate else None, "validation_v2": [item.model_dump(mode="json") for item in v2_decisions] if candidate else [], "mode": get_setting("detection_depth_mode", "shadow")}
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


@app.post("/sessions/{session_id}/identity-graph/build")
async def build_session_identity_graph(session_id: str, req: IdentityGraphBuildRequest, _: bool = Depends(require_api_key)):
    """Create an immutable graph snapshot from explicit session records."""
    session_store.require(session_id)
    identities = authorization_repository.list_identities(session_id)
    claims: List[Dict[str, Any]] = []
    contexts: List[Dict[str, Any]] = []
    for identity in identities:
        identity_id = str(identity.get("identity_id", ""))
        if req.claim_identity_ids and identity_id not in req.claim_identity_ids:
            continue
        claims.extend(authorization_repository.list_claims(session_id, identity_id))
        contexts.extend(authorization_repository.list_auth_contexts(session_id, identity_id))
    previous = authorization_repository.list_identity_graphs(session_id, limit=1)
    previous_version = int(previous[0].get("version", 0)) if previous else 0
    graph = build_identity_graph(session_id, identities, claims, contexts, previous_version)
    row = authorization_repository.save_identity_graph(session_id, graph)
    return {"graph": row, "relations": [item.model_dump(mode="json") for item in graph.relations], "mode": "shadow"}


@app.get("/sessions/{session_id}/identity-graph")
async def list_session_identity_graphs(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "graphs": authorization_repository.list_identity_graphs(session_id)}


@app.get("/sessions/{session_id}/identity-graph/{graph_id}")
async def get_session_identity_graph(session_id: str, graph_id: str, _: bool = Depends(require_api_key)):
    try:
        return authorization_repository.identity_graph_detail(session_id, graph_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/identity-graph/coverage")
async def create_identity_coverage_plan(session_id: str, req: IdentityCoverageRequest, _: bool = Depends(require_api_key)):
    try:
        detail = authorization_repository.identity_graph_detail(session_id, req.graph_id)
        graph = IdentityGraphV1(**detail["graph"], relations=detail.get("relations", []))
        plan = plan_identity_coverage(session_id, graph, req.required_identity_ids, req.required_resource_fingerprints)
        return {"plan": authorization_repository.save_identity_coverage_plan(plan)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/identity-coverage-plans")
async def list_identity_coverage_plans(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "plans": authorization_repository.list_identity_coverage_plans(session_id)}


@app.post("/sessions/{session_id}/browser/workflow-matrices")
async def create_identity_workflow_matrix(session_id: str, req: WorkflowMatrixRequest, _: bool = Depends(require_api_key)):
    try:
        workflow = browser_workflow_repository.get_workflow(session_id, req.workflow_id)
        detail = authorization_repository.identity_graph_detail(session_id, req.graph_id)
        graph = IdentityGraphV1(**detail["graph"], relations=detail.get("relations", []))
        matrix = identity_workflow_matrix.plan(
            workflow, graph, req.identity_ids,
            entity_fingerprint=req.entity_fingerprint,
            run_roles=req.run_roles,
            cleanup_required=req.cleanup_required,
        )
        saved = browser_workflow_repository.save_run_matrix(matrix)
        return {"matrix": saved, "dispatch": identity_workflow_matrix.can_dispatch(matrix, mutation=workflow.has_mutations())}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/sessions/{session_id}/browser/workflow-matrices")
async def list_identity_workflow_matrices(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "matrices": browser_workflow_repository.list_run_matrices(session_id)}


@app.get("/sessions/{session_id}/browser/workflow-matrices/{matrix_id}")
async def get_identity_workflow_matrix(session_id: str, matrix_id: str, _: bool = Depends(require_api_key)):
    try:
        return {"matrix": browser_workflow_repository.get_run_matrix(session_id, matrix_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/sessions/{session_id}/authorization/access-matrix/evaluate")
async def evaluate_identity_access_matrix(session_id: str, req: IdentityAccessEvaluationRequest, _: bool = Depends(require_api_key)):
    """Compare owner/non-owner access using redacted semantic state evidence."""
    session_store.require(session_id)
    return {
        "session_id": session_id,
        "evaluation": identity_workflow_matrix.evaluate_access_matrix(
            req.attempts,
            owner_identity_id=req.owner_identity_id,
            resource_fingerprint=req.resource_fingerprint,
            require_clean_reproduction=req.require_clean_reproduction,
            require_cleanup=req.require_cleanup,
        ),
        "mode": get_setting("identity_business_impact_mode", "shadow"),
    }


@app.get("/sessions/{session_id}/business-entities")
async def list_business_entities(session_id: str, fingerprint: Optional[str] = None, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "entities": browser_workflow_repository.list_entities(session_id, fingerprint)}


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


@app.post("/sessions/{session_id}/identity-workflow/discover")
async def discover_identity_workflow_intelligence(
    session_id: str,
    req: IdentityWorkflowDiscoveryRequest,
    _: bool = Depends(require_api_key),
):
    """Compile passive auth/session/workflow intelligence for one session.

    Captures are treated as untrusted observations. This endpoint never logs
    in, submits a form, follows a redirect, or promotes a vulnerability. Raw
    credentials and tokens are redacted before they reach persistence or the
    response.
    """
    session_store.require(session_id)
    allowed, reason = session_store.validate_active_scope(session_id, req.origin)
    if not allowed:
        raise HTTPException(status_code=403, detail=reason)
    selected_identity_ids = list(dict.fromkeys([item for item in req.identity_ids if item] + ([req.identity_id] if req.identity_id else [])))
    for identity_id in selected_identity_ids:
        _identity_or_404(session_id, identity_id)
    capture_result = ToolResultV1(
        tool_name="identity_workflow_discovery",
        category="recon",
        target=req.origin,
        summary=json.dumps({"captures": redact(req.captures)}, sort_keys=True),
    )
    compiled = ReconOrchestrator.identity_workflow_sources(
        req.origin,
        [capture_result],
        session_id=session_id,
        identity_id=req.identity_id,
        identity_ids=selected_identity_ids,
        goal=req.goal,
    )
    if req.persist:
        inventory = compiled.get("identity_workflow_inventory") or {}
        for raw in inventory.get("auth_surfaces") or []:
            authorization_repository.save_auth_surface(AuthSurfaceObservationV1(**raw))
        for raw in inventory.get("session_transitions") or []:
            authorization_repository.save_session_transition(SessionTransitionV1(**raw))
        workflow_raw = inventory.get("workflow") or {}
        if workflow_raw:
            workflow = BrowserWorkflowV1(**workflow_raw)
            workflow.auth_surface_ids = [str(item.get("observation_id")) for item in inventory.get("auth_surfaces") or []]
            workflow.prerequisite_ids = [str(item.get("prerequisite_id")) for item in inventory.get("prerequisites") or []]
            workflow.ensure_fingerprint()
            browser_workflow_repository.save_workflow(workflow)
        for raw in inventory.get("prerequisites") or []:
            authorization_repository.save_workflow_prerequisite(WorkflowPrerequisiteV1(**raw))
    return {
        "session_id": session_id,
        "mode": get_setting("identity_workflow_mode", "shadow"),
        "persisted": bool(req.persist),
        "inventory": redact(compiled.get("identity_workflow_inventory") or {}),
        "workflows": redact(compiled.get("workflows") or []),
        "gaps": redact(compiled.get("identity_workflow_gaps") or []),
    }


@app.get("/sessions/{session_id}/identity-workflow/auth-surfaces")
async def list_identity_workflow_auth_surfaces(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "auth_surfaces": authorization_repository.list_auth_surfaces(session_id)}


@app.get("/sessions/{session_id}/identity-workflow/session-transitions")
async def list_identity_workflow_session_transitions(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "session_transitions": authorization_repository.list_session_transitions(session_id)}


@app.get("/sessions/{session_id}/identity-workflow/prerequisites")
async def list_identity_workflow_prerequisites(session_id: str, _: bool = Depends(require_api_key)):
    session_store.require(session_id)
    return {"session_id": session_id, "prerequisites": authorization_repository.list_workflow_prerequisites(session_id)}


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
        report = workflow_report.generate(session_id)
        persistence = "memory"
        try:
            structured_repository.save_report_narrative(session_id, report["narrative"], report["claims"])
            persistence = "supabase"
        except Exception:
            pass
        return {**report, "persistence": persistence}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/sessions/{session_id}/workflow/report/claims")
async def list_workflow_report_claims(session_id: str, report_id: Optional[str] = None, limit: int = 500, _: bool = Depends(require_api_key)):
    try:
        return {"session_id": session_id, "claims": structured_repository.list_report_claims(session_id, report_id, max(1, min(limit, 1000)))}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Report persistence unavailable: {redact(str(exc))[:500]}")


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
            if _execution_mode() == "strict":
                _enqueue_execution_job(
                    job_id=job_id, session_id=session_id, target=context["target_url"],
                    goal=context["attack_goal"], job_type="pentest",
                    payload={"agent_models": {"recon": req.model_id, "analis": req.model_id}, "scan_config": scan_config},
                    risk="read_only", idempotency_key=job_id,
                )
            else:
                background_tasks.add_task(
                    run_pentest_job, job_id, context["target_url"], context["attack_goal"], session_id,
                    {"recon": req.model_id, "analis": req.model_id}, None, scan_config,
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
    if _execution_mode() == "strict":
        try:
            durable = durable_execution_repository.get_job(job_id)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Durable job state unavailable.") from exc
        if durable:
            return _legacy_job_view(durable)
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
    if _execution_mode() == "strict":
        try:
            durable = durable_execution_repository.get_job(job_id)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Durable job state unavailable.") from exc
        if not durable:
            raise HTTPException(status_code=404, detail="Job not found")
        return {"ok": durable_execution_repository.request_cancel(job_id), "job_id": job_id, "source": "durable"}
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
| Structured Tool Runs | {summary.get('structured_tool_runs', 0)} |
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

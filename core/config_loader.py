"""Load editable YAML config with safe fallback."""

from pathlib import Path
import os

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "pentest_config.yaml"
DEFAULTS = {
    "structured_evidence_mode": "strict",
    "authorization_graph_mode": "shadow",
    "auth_secret_ttl_minutes": 240,
    "browser_workflow_mode": "shadow",
    "execution_platform_mode": "shadow",
    "tool_boundary_mode": "shadow",
    "detection_depth_mode": "shadow",
    "identity_browser_business_mode": "shadow",
    "exploit_chain_mode": "shadow",
    "reasoning_mode": "shadow",
    "reasoning_adaptation_mode": "shadow",
    "report_intelligence_mode": "shadow",
    "production_readiness_mode": "shadow",
    "mission_graph_mode": "shadow",
    "target_knowledge_mode": "shadow",
    "identity_workflow_mode": "shadow",
    "exploration_mode": "assisted",
    "exploration": {
        "read_only_auto_run": True,
        "max_payload_variants": 10,
        "max_action_seconds": 120,
        "mutation_requires_approval": True,
    },
    "evaluation": {
        "enabled": True,
        "mode": "shadow",
        "core_suite_path": "benchmarks/stage6/core_suite.yaml",
        "stage8_suite_path": "benchmarks/stage8/foundation_suite.yaml",
        "stage9_suite_path": "benchmarks/stage9/detection_suite.yaml",
        "stage10_suite_path": "benchmarks/stage10/identity_business_suite.yaml",
        "stage11_suite_path": "benchmarks/stage11/modern_chain_suite.yaml",
        "deterministic_trial_count": 3,
        "model_trial_count": 3,
        "benchmark_matrix_size": 48,
        "stage9_benchmark_matrix_size": 72,
        "stage10_benchmark_matrix_size": 60,
        "stage11_benchmark_matrix_size": 96,
        "stage12_benchmark_matrix_size": 96,
        "stage12_suite_path": "benchmarks/stage12/reasoning_report_suite.yaml",
        "stage13_benchmark_matrix_size": 96,
        "stage13_suite_path": "benchmarks/stage13/production_readiness_suite.yaml",
        "stage22_suite_path": "benchmarks/stage22/perimeter_asset_waf_suite.yaml",
        "stage22_benchmark_matrix_size": 48,
        "stage23_suite_path": "benchmarks/stage23/surface_endpoint_discovery_suite.yaml",
        "stage23_benchmark_matrix_size": 72,
        "stage24_suite_path": "benchmarks/stage24/technology_fingerprinting_suite.yaml",
        "stage24_benchmark_matrix_size": 72,
        "stage25_suite_path": "benchmarks/stage25/application_contract_suite.yaml",
        "stage25_benchmark_matrix_size": 72,
        "stage26_suite_path": "benchmarks/stage26/identity_workflow_suite.yaml",
        "stage27_suite_path": "benchmarks/stage27/recon_closure_suite.yaml",
        "stage26_benchmark_matrix_size": 72,
        "stage15_suite_path": "benchmarks/stage15/target_knowledge_coverage_suite.yaml",
        "stage15_benchmark_matrix_size": 72,
        "stage16_suite_path": "benchmarks/stage16/autonomous_reasoning_search_suite.yaml",
        "stage16_benchmark_matrix_size": 96,
        "primary_model_trials": 3,
        "max_performance_regression": 0.20,
        "require_zero_registry_violations": True,
        "require_zero_redaction_leaks": True,
        "public_lab_profile": "benchmark-labs",
    },
    "execution": {
        "poll_interval_seconds": 2,
        "lease_seconds": 60,
        "heartbeat_seconds": 15,
        "worker_concurrency": 1,
        "max_attempts_read_only": 3,
        "max_attempts_mutation": 1,
        "job_timeout_minutes": 120,
        "strict_rpc_required": True,
        "worker_health_interval_seconds": 15,
        "stale_worker_after_seconds": 90,
        "checkpoint_interval_seconds": 30,
        "readiness_soak_minutes": 120,
        "memory_limit_mb": 2048,
        "cpu_limit": 1.0,
    },
    "safety": {
        "policy_version": "1.0",
        "allow_private_network": False,
        "tls_verify": True,
        "random_proxy_enabled": False,
        "egress_providers": {},
        "max_requests_per_job": 20000,
        "max_download_bytes": 536870912,
        "max_response_bytes": 2097152,
        "max_upload_bytes": 10485760,
        "max_credential_attempts": 10,
        "requests_per_second": 2.0,
        "burst": 4,
    },
    "race_engine": {
        "enabled": True,
        "max_concurrency": 8,
        "ramp": [2, 4, 8],
    },
    "browser_workflow": {
        "max_steps": 30,
        "step_timeout_ms": 15000,
        "max_retries": 1,
        "max_mutations_per_run": 3,
        "approval_ttl_minutes": 30,
        "require_cleanup": True,
        "read_only_auto_run": True,
        "artifact_bucket": "nexus-evidence",
        "identity_matrix_max_runs": 12,
        "require_identity_graph": True,
        "require_entity_fingerprint": True,
    },
    "artifact_storage": {
        "bucket": "nexus-evidence",
        "retention_days": 30,
        "signed_url_ttl_seconds": 300,
        "sweep_enabled": True,
        "sweep_interval_minutes": 60,
        "orphan_grace_days": 2,
    },
    "adaptive_planner": {
        "max_proposals": 3,
        "max_hypotheses": 80,
        "max_attempts_per_hypothesis": 3,
        "scoring": {
            "information_gain": 0.38,
            "objective_relevance": 0.22,
            "evidence_strength": 0.18,
            "novelty": 0.12,
            "technology_fit": 0.10,
            "cost_penalty": 0.16,
            "risk_penalty": 0.22,
            "failure_penalty": 0.10,
        },
    },
    "reasoning": {
        "max_cycles": 10,
        "max_actions_per_cycle": 3,
        "max_model_actions": 20,
        "min_information_gain": 0.10,
        "search_strategy": "best_first",
        "max_branch_factor": 4,
        "max_backtracks": 3,
        "repetition_penalty": 0.20,
        "stale_evidence_reject": True,
        "memory_isolation_required": True,
        "invalid_action_retry_limit": 1,
        "stop_on_contradiction": True,
        "require_evidence_grounding": True,
    },
    "mission_graph": {
        "max_paths": 8,
        "max_replans": 10,
        "read_only_auto_run": True,
        "require_evidence": True,
        "risk_profile": "bounded_autonomy",
        "mutation_requires_approval": True,
        "cleanup_required_for_mutation": True,
    },
    "target_knowledge": {
        "max_nodes": 10000,
        "max_edges": 20000,
        "observation_ttl_hours": 24,
        "require_evidence": True,
        "historical_import_requires_revalidation": True,
        "max_coverage_items": 10000,
    },
    "recon": {
        "asset_intelligence_mode": "shadow",
        "perimeter_graph_enabled": True,
        "dns_record_types": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV"],
        "wildcard_detection_enabled": True,
        "dns_drift_detection_enabled": True,
        "historical_requires_revalidation": True,
        "max_assets": 500,
        "surface_inventory_mode": "shadow",
        "max_surface_endpoints": 500,
        "max_surface_parameters": 2000,
        "parse_api_schema_hints": True,
        "surface_dedupe_by_method": True,
        "historical_surface_requires_revalidation": True,
        "technology_fingerprinting_mode": "shadow",
        "technology_signal_correlation": True,
        "technology_require_independent_version_signal": True,
        "technology_max_signals": 2000,
        "technology_max_fingerprints": 500,
        "technology_conflict_is_inconclusive": True,
        "application_contract_mode": "shadow",
        "application_contract_max_operations": 1000,
        "application_contract_max_inputs": 3000,
        "application_contract_require_provenance": True,
        "application_contract_conflict_is_inconclusive": True,
        "application_contract_mutations_require_approval": True,
        "provider_queries_enabled": False,
        "r1_active_enabled": True,
        "r2_active_enabled": False,
        "raw_network_enabled": False,
        "max_tools": 64,
        "max_runs": 128,
        "max_endpoints": 100,
        "max_depth": 2,
        "max_followups_per_endpoint": 8,
        "incremental_graph_updates": True,
        "followup_tools": [
            "browser_extract_surface",
            "browser_intercept_requests",
            "browser_check_security_headers",
            "analyze_js_deep",
            "param_discovery_get",
            "client_side_security_scanner",
            "mixed_content_scanner",
            "postmessage_vulnerability_scanner",
        ],
        "stop_on_error_rate": 0.50,
    },
    "waf_testing": {
        "enabled": True,
        "authorized": False,
        "mode": "passive",
        "max_requests": 50,
        "cache_ttl_seconds": 300,
        "active_requires_exact_approval": True,
        "strategy_application": True,
        "stop_on_429": True,
        "stop_on_error_spike": True,
    },
    "human_recon": {
        "max_pages": 60,
        "max_depth": 3,
        "max_clicks_per_page": 12,
        "fallback_priority": {"form": 10, "api_link": 8, "button": 5, "link": 3},
    }
}

def load_config() -> dict:
    if yaml and CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                data = yaml.safe_load(f) or {}
            # shallow merge with defaults
            merged = dict(DEFAULTS)
            for k, v in data.items():
                if isinstance(v, dict) and isinstance(merged.get(k), dict):
                    merged[k] = {**merged[k], **v}
                else:
                    merged[k] = v
            return merged
        except Exception:
            pass
    return DEFAULTS

_config = None

def get_config() -> dict:
    global _config
    if _config is None:
        _config = load_config()
    return _config

def reload_config() -> dict:
    global _config
    _config = load_config()
    return _config


def get_setting(name: str, default=None):
    """Return a scalar application setting from the editable YAML config."""
    return get_config().get(name, default)

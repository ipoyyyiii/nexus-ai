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
    "evaluation": {
        "enabled": True,
        "mode": "shadow",
        "core_suite_path": "benchmarks/stage6/core_suite.yaml",
        "stage8_suite_path": "benchmarks/stage8/foundation_suite.yaml",
        "stage9_suite_path": "benchmarks/stage9/detection_suite.yaml",
        "deterministic_trial_count": 3,
        "model_trial_count": 3,
        "benchmark_matrix_size": 48,
        "stage9_benchmark_matrix_size": 72,
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
    },
    "artifact_storage": {
        "bucket": "nexus-evidence",
        "retention_days": 30,
        "signed_url_ttl_seconds": 300,
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

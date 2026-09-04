from pathlib import Path

import pytest


def test_invalid_security_config_fails_closed(monkeypatch, tmp_path: Path):
    import core.config_loader as config_loader

    invalid = tmp_path / "pentest_config.yaml"
    invalid.write_text("execution_platform_mode: [", encoding="utf-8")
    monkeypatch.setattr(config_loader, "CONFIG_PATH", invalid)

    with pytest.raises(RuntimeError, match="Unable to load security configuration"):
        config_loader.load_config()


def test_default_assessment_mode_is_autonomous():
    from core.config_loader import DEFAULTS

    assert DEFAULTS["assessment_mode"] == "autonomous"


def test_default_recon_mission_has_wall_clock_budget():
    from core.config_loader import DEFAULTS

    assert DEFAULTS["recon"]["mission_timeout_seconds"] == 1800
    assert DEFAULTS["recon"]["incremental_graph_updates"] is False
    assert DEFAULTS["recon"]["local_lab_bounds"] == {
        "max_endpoints": 8,
        "max_depth": 1,
        "max_followups_per_endpoint": 2,
        "mission_timeout_seconds": 600,
        "human_recon_max_pages": 4,
        "human_recon_max_depth": 1,
        "human_recon_max_clicks_per_page": 6,
    }


def test_autonomous_web_loop_uses_timeout_budget_without_fixed_action_cap():
    from core.config_loader import DEFAULTS

    config = DEFAULTS["autonomous_web_pentest"]
    assert config["enabled"] is True
    assert config["read_only_auto_run"] is True
    assert config.get("max_actions_total") is None
    assert config.get("max_cycles") is None
    assert config["max_actions_per_cycle"] == "auto"
    assert config["mutation_requires_approval"] is True

    reasoning = DEFAULTS["reasoning"]
    assert reasoning["max_model_actions"] == "auto"
    assert reasoning["provider_retry_attempts"] == 1
    assert reasoning["provider_retry_backoff_seconds"] == 0.5
    assert reasoning["max_actions_per_cycle"] == "auto"


def test_config_loader_preserves_nested_policy_defaults(monkeypatch, tmp_path: Path):
    import core.config_loader as config_loader

    config_path = tmp_path / "pentest_config.yaml"
    config_path.write_text(
        "recon:\n  local_lab_bounds:\n    max_endpoints: 12\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config_loader, "CONFIG_PATH", config_path)

    loaded = config_loader.load_config()
    assert loaded["recon"]["local_lab_bounds"]["max_endpoints"] == 12
    assert loaded["recon"]["local_lab_bounds"]["max_depth"] == 1
    assert loaded["recon"]["local_lab_bounds"]["mission_timeout_seconds"] == 600


def test_merged_config_snapshot_preserves_defaults_and_is_isolated(monkeypatch):
    import core.config_loader as config_loader

    monkeypatch.setattr(config_loader, "get_config", lambda: config_loader.DEFAULTS)
    snapshot = config_loader.merged_config_snapshot({
        "recon": {"local_lab_bounds": {"max_endpoints": 12}},
    })

    assert snapshot["recon"]["local_lab_bounds"]["max_endpoints"] == 12
    assert snapshot["recon"]["local_lab_bounds"]["max_depth"] == 1
    snapshot["recon"]["local_lab_bounds"]["max_endpoints"] = 99
    assert config_loader.DEFAULTS["recon"]["local_lab_bounds"]["max_endpoints"] == 8

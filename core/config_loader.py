"""Load editable YAML config with safe fallback."""

from pathlib import Path
import os

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "pentest_config.yaml"
DEFAULTS = {
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

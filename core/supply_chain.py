"""Local supply-chain checks for the shipped Docker/toolchain boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from core.config_loader import get_config


ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "config" / "toolchain_manifest.yaml"


def load_toolchain_manifest() -> dict[str, Any]:
    with MANIFEST_PATH.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def supply_chain_report() -> dict[str, Any]:
    manifest = load_toolchain_manifest()
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    violations: list[str] = []
    clone_count = dockerfile.count("git clone")
    checkout_count = dockerfile.count("git -C")
    if checkout_count < clone_count:
        violations.append("unpinned_git_clone")
    if ":latest" in dockerfile:
        violations.append("latest_image_or_binary")
    if "|| echo" in dockerfile and "install skipped" in dockerfile:
        violations.append("fake_success_on_missing_binary")
    source_pins = manifest.get("source_pins", {})
    missing_pins = sorted(name for name, value in source_pins.items() if not str(value).strip())
    if missing_pins:
        violations.append("missing_source_pin")
    versions = manifest.get("release_binaries", {})
    missing_versions = sorted(name for name, value in versions.items() if not str(value).strip())
    if missing_versions:
        violations.append("missing_binary_version")
    base_images = manifest.get("base_images", {})
    if any("@sha256:" not in str(value) for value in base_images.values()):
        violations.append("mutable_base_image")
    if "FROM python:3.11-slim@sha256:" not in dockerfile or "FROM node:20-alpine@sha256:" not in (ROOT / "frontend-pentest" / "Dockerfile").read_text(encoding="utf-8"):
        violations.append("dockerfile_base_not_digest_pinned")
    return {
        "ready": not violations,
        "manifest_version": str(manifest.get("schema_version", "")),
        "source_pin_count": len(source_pins),
        "binary_version_count": len(versions),
        "violations": sorted(set(violations)),
        "base_images": base_images,
    }

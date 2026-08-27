"""Small local operational CLI for Stage 13 diagnostics."""

from __future__ import annotations

import argparse
import json
import os

from dotenv import load_dotenv

from core.config_loader import get_config
from core.execution_contract import stable_digest
from core.redact import redact
from core.supply_chain import supply_chain_report


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Nexus production-readiness diagnostics")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("supply-chain", help="validate pinned local toolchain metadata")
    sub.add_parser("config", help="print non-secret config digest")
    args = parser.parse_args(argv)
    if args.command == "supply-chain":
        result = supply_chain_report()
        print(json.dumps(redact(result), sort_keys=True, indent=2))
        return 0 if result.get("ready") else 1
    config = get_config()
    result = {
        "config_digest": stable_digest(config),
        "execution_platform_mode": config.get("execution_platform_mode"),
        "tool_boundary_mode": config.get("tool_boundary_mode"),
        "production_readiness_mode": config.get("production_readiness_mode"),
        "worker_concurrency": config.get("execution", {}).get("worker_concurrency"),
        "supabase_configured": bool(os.environ.get("SUPABASE_URL") and os.environ.get("SUPABASE_KEY")),
    }
    print(json.dumps(redact(result), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

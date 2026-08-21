"""Offline command line entrypoint for versioned evaluation suites."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from core.evaluation_contract import content_digest
from core.evaluation_engine import EvaluationEngine
from core.stage8_benchmark import STAGE8_SUITE_ID, Stage8BenchmarkEngine, load_stage8_suite, run_model_shadow_trial
from core.stage9_benchmark import STAGE9_SUITE_ID, Stage9BenchmarkEngine, load_stage9_suite, run_stage9_model_shadow_trial
from core.redact import redact


def _stage8(args: argparse.Namespace) -> int:
    engine = Stage8BenchmarkEngine()
    suite, scenarios, matrix = load_stage8_suite()
    runs = []
    canonical = None
    model_actions = []
    for number in range(1, max(1, args.trials) + 1):
        run, results, snapshots, gate, matrix, coverage, trials = engine.run_suite(
            suite, trial_number=number, trial_count=max(1, args.trials), seed=args.seed, model_id=args.model_id
        )
        outcome_digest = content_digest([(item.case_id, item.status, item.actual_outcome) for item in results])
        runs.append({"trial_number": number, "run_id": run.run_id, "outcome_digest": outcome_digest, "status": run.status, "gate": gate.decision})
        if canonical is None:
            canonical = (run, results, snapshots, gate, matrix, coverage, trials)
        if args.mode in {"model", "hybrid"}:
            for scenario in scenarios:
                for model_number in range(1, max(3, args.trials) + 1):
                    model_trial, actions = run_model_shadow_trial(
                        run.run_id, scenario, trial_number=model_number, trial_count=max(3, args.trials), model_id=args.model_id or "offline-stub"
                    )
                    model_actions.extend([action.model_dump(mode="json") for action in actions])
    assert canonical is not None
    run, results, snapshots, gate, matrix, coverage, trials = canonical
    stable = len({item["outcome_digest"] for item in runs}) == 1
    run.metrics["deterministic_replay_stability"] = 1.0 if stable else 0.0
    gate = gate.model_copy(update={
        "decision": "ready" if stable and gate.decision == "ready" else "not_ready",
        "metrics": run.metrics,
    })
    summary: dict[str, Any] = {
        "suite": suite.model_dump(mode="json"),
        "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"),
        "release_gate": gate.model_dump(mode="json"),
        "trial_replays": runs,
        "coverage": {
            "samples": len(coverage),
            "required": matrix.required_count,
            "diagnostic": matrix.diagnostic_count,
            "unsupported_capabilities": matrix.unsupported_capabilities,
            "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})},
        },
        "model": {"mode": args.mode, "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage6(args: argparse.Namespace) -> int:
    engine = EvaluationEngine()
    suite = engine.load_suite()
    run, results, snapshots, gate = engine.run_suite(suite)
    print(json.dumps(redact({"suite": suite.model_dump(mode="json"), "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json")}), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage9(args: argparse.Namespace) -> int:
    engine = Stage9BenchmarkEngine()
    suite, scenarios, matrix = load_stage9_suite()
    replays = []
    model_actions = []
    canonical = None
    trial_count = max(1, args.trials)
    for number in range(1, trial_count + 1):
        run, results, snapshots, gate, matrix, coverage, trials = engine.run_suite(
            suite, trial_number=number, trial_count=trial_count, seed=args.seed, mode=args.mode,
        )
        digest = content_digest([(item.case_id, item.status, item.actual_outcome) for item in results])
        replays.append({"trial_number": number, "run_id": run.run_id, "outcome_digest": digest, "status": run.status, "gate": gate.decision})
        if args.mode in {"model", "hybrid"}:
            for scenario in scenarios:
                for model_number in range(1, max(3, args.trials) + 1):
                    model_trial, actions = run_stage9_model_shadow_trial(
                        run.run_id, scenario, trial_number=model_number,
                        trial_count=max(3, args.trials), model_id=args.model_id or "offline-stub",
                    )
                    model_actions.extend([action.model_dump(mode="json") for action in actions])
        if canonical is None:
            canonical = (run, results, snapshots, gate, matrix, coverage, trials)
    assert canonical is not None
    run, results, snapshots, gate, matrix, coverage, trials = canonical
    stable = len({item["outcome_digest"] for item in replays}) == 1
    run.metrics["deterministic_replay_stability"] = 1.0 if stable else 0.0
    gate = gate.model_copy(update={"decision": "ready" if stable and gate.decision == "ready" else "not_ready", "metrics": run.metrics})
    summary = {
        "suite": suite.model_dump(mode="json"),
        "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"),
        "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Nexus local deterministic/model-shadow evaluation")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run a local benchmark suite")
    run.add_argument("--suite", default=STAGE8_SUITE_ID, choices=[STAGE8_SUITE_ID, STAGE9_SUITE_ID, "stage6-core"])
    run.add_argument("--mode", default="deterministic", choices=["deterministic", "model", "hybrid"])
    run.add_argument("--trials", type=int, default=3, choices=range(1, 101))
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--model-id", default="")
    args = parser.parse_args(argv)
    if args.suite == "stage6-core":
        return _stage6(args)
    if args.suite == STAGE9_SUITE_ID:
        return _stage9(args)
    return _stage8(args)


if __name__ == "__main__":
    sys.exit(main())

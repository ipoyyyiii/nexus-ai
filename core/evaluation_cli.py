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
from core.stage10_benchmark import STAGE10_SUITE_ID, Stage10BenchmarkEngine, load_stage10_suite, run_stage10_model_shadow_trial
from core.stage11_benchmark import STAGE11_SUITE_ID, Stage11BenchmarkEngine, load_stage11_suite, run_stage11_model_shadow_trial
from core.stage12_benchmark import STAGE12_SUITE_ID, Stage12BenchmarkEngine, load_stage12_suite, run_stage12_model_shadow_trial
from core.stage13_benchmark import STAGE13_SUITE_ID, Stage13BenchmarkEngine, load_stage13_suite
from core.stage14_benchmark import STAGE14_SUITE_ID, Stage14BenchmarkEngine, load_stage14_suite, run_stage14_model_shadow_trial
from core.stage15_benchmark import STAGE15_SUITE_ID, Stage15BenchmarkEngine, load_stage15_suite, run_stage15_model_shadow_trial
from core.stage16_benchmark import STAGE16_SUITE_ID, Stage16BenchmarkEngine, load_stage16_suite, run_stage16_model_shadow_trial
from core.stage17_benchmark import STAGE17_SUITE_ID, Stage17BenchmarkEngine, load_stage17_suite, run_stage17_model_shadow_trial
from core.stage18_benchmark import STAGE18_SUITE_ID, Stage18BenchmarkEngine, load_stage18_suite, run_stage18_model_shadow_trial
from core.stage19_benchmark import STAGE19_SUITE_ID, Stage19BenchmarkEngine, load_stage19_suite, run_stage19_model_shadow_trial
from core.stage22_benchmark import STAGE22_SUITE_ID, Stage22BenchmarkEngine, load_stage22_suite, run_stage22_model_shadow_trial
from core.stage23_benchmark import STAGE23_SUITE_ID, Stage23BenchmarkEngine, load_stage23_suite, run_stage23_model_shadow_trial
from core.stage24_benchmark import STAGE24_SUITE_ID, Stage24BenchmarkEngine, load_stage24_suite, run_stage24_model_shadow_trial
from core.stage25_benchmark import STAGE25_SUITE_ID, Stage25BenchmarkEngine, load_stage25_suite, run_stage25_model_shadow_trial
from core.stage26_benchmark import STAGE26_SUITE_ID, Stage26BenchmarkEngine, load_stage26_suite, run_stage26_model_shadow_trial
from core.stage27_benchmark import STAGE27_SUITE_ID, Stage27BenchmarkEngine, load_stage27_suite, run_stage27_model_shadow_trial
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


def _stage10(args: argparse.Namespace) -> int:
    engine = Stage10BenchmarkEngine()
    suite, scenarios, matrix = load_stage10_suite()
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
                    _, actions = run_stage10_model_shadow_trial(
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
        "coverage": {
            "samples": len(coverage),
            "required": matrix.required_count,
            "diagnostic": matrix.diagnostic_count,
            "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})},
        },
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage11(args: argparse.Namespace) -> int:
    engine = Stage11BenchmarkEngine()
    suite, scenarios, matrix = load_stage11_suite()
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
                    _, actions = run_stage11_model_shadow_trial(
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage12(args: argparse.Namespace) -> int:
    engine = Stage12BenchmarkEngine()
    suite, scenarios, matrix = load_stage12_suite()
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
                    _, actions = run_stage12_model_shadow_trial(
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage13(args: argparse.Namespace) -> int:
    engine = Stage13BenchmarkEngine()
    suite, scenarios, matrix = load_stage13_suite()
    replays = []
    canonical = None
    trial_count = max(1, args.trials)
    for number in range(1, trial_count + 1):
        run, results, snapshots, gate, matrix, coverage, trials = engine.run_suite(
            suite, trial_number=number, trial_count=trial_count, seed=args.seed, mode=args.mode,
        )
        digest = content_digest([(item.case_id, item.status, item.actual_outcome) for item in results])
        replays.append({"trial_number": number, "run_id": run.run_id, "outcome_digest": digest, "status": run.status, "gate": gate.decision})
        if canonical is None:
            canonical = (run, results, snapshots, gate, matrix, coverage, trials)
    assert canonical is not None
    run, results, snapshots, gate, matrix, coverage, trials = canonical
    stable = len({item["outcome_digest"] for item in replays}) == 1
    run.metrics["deterministic_replay_stability"] = 1.0 if stable else 0.0
    gate = gate.model_copy(update={"decision": "ready" if stable and gate.decision == "ready" else "not_ready", "metrics": run.metrics})
    summary = {
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "operational_note": "Crash/soak and external dependency checks are local deterministic simulations; run the operational drill before strict cutover.",
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage14(args: argparse.Namespace) -> int:
    engine = Stage14BenchmarkEngine()
    suite, scenarios, matrix = load_stage14_suite()
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
                    _, actions = run_stage14_model_shadow_trial(run.run_id, scenario, trial_number=model_number, trial_count=max(3, args.trials), model_id=args.model_id or "offline-stub")
                    model_actions.extend([action.model_dump(mode="json") for action in actions])
        if canonical is None:
            canonical = (run, results, snapshots, gate, matrix, coverage, trials)
    assert canonical is not None
    run, results, snapshots, gate, matrix, coverage, trials = canonical
    stable = len({item["outcome_digest"] for item in replays}) == 1
    run.metrics["deterministic_replay_stability"] = 1.0 if stable else 0.0
    gate = gate.model_copy(update={"decision": "ready" if stable and gate.decision == "ready" else "not_ready", "metrics": run.metrics})
    summary = {
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage15(args: argparse.Namespace) -> int:
    engine = Stage15BenchmarkEngine()
    suite, scenarios, matrix = load_stage15_suite()
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
                    _, actions = run_stage15_model_shadow_trial(run.run_id, scenario, trial_number=model_number, trial_count=max(3, args.trials), model_id=args.model_id or "offline-stub")
                    model_actions.extend([action.model_dump(mode="json") for action in actions])
        if canonical is None:
            canonical = (run, results, snapshots, gate, matrix, coverage, trials)
    assert canonical is not None
    run, results, snapshots, gate, matrix, coverage, trials = canonical
    stable = len({item["outcome_digest"] for item in replays}) == 1
    run.metrics["deterministic_replay_stability"] = 1.0 if stable else 0.0
    gate = gate.model_copy(update={"decision": "ready" if stable and gate.decision == "ready" else "not_ready", "metrics": run.metrics})
    summary = {
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage if item.failure_taxonomy == key) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage16(args: argparse.Namespace) -> int:
    engine = Stage16BenchmarkEngine()
    suite, scenarios, matrix = load_stage16_suite()
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
                    _, actions = run_stage16_model_shadow_trial(
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage if item.failure_taxonomy == key) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage17(args: argparse.Namespace) -> int:
    engine = Stage17BenchmarkEngine()
    suite, scenarios, matrix = load_stage17_suite()
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
                    _, actions = run_stage17_model_shadow_trial(
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage18(args: argparse.Namespace) -> int:
    engine = Stage18BenchmarkEngine()
    suite, scenarios, matrix = load_stage18_suite()
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
                    _, actions = run_stage18_model_shadow_trial(
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {
            "samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count,
            "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})},
        },
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage19(args: argparse.Namespace) -> int:
    engine = Stage19BenchmarkEngine()
    suite, scenarios, matrix = load_stage19_suite()
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
                    _, actions = run_stage19_model_shadow_trial(
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {
            "samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count,
            "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})},
        },
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage22(args: argparse.Namespace) -> int:
    """Run the local Stage 22 perimeter/asset/WAF benchmark."""
    engine = Stage22BenchmarkEngine()
    suite, scenarios, matrix = load_stage22_suite()
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
                    _, actions = run_stage22_model_shadow_trial(
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
    gate = gate.model_copy(update={
        "decision": "ready" if stable and gate.decision == "ready" else "not_ready",
        "metrics": run.metrics,
    })
    summary = {
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {
            "samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count,
            "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})},
        },
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage23(args: argparse.Namespace) -> int:
    """Run the local Stage 23 surface and endpoint discovery benchmark."""
    engine = Stage23BenchmarkEngine()
    suite, scenarios, matrix = load_stage23_suite()
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
                    _, actions = run_stage23_model_shadow_trial(
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage24(args: argparse.Namespace) -> int:
    """Run the local Stage 24 technology fingerprint benchmark."""
    engine = Stage24BenchmarkEngine()
    suite, scenarios, matrix = load_stage24_suite()
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
                    _, actions = run_stage24_model_shadow_trial(
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage25(args: argparse.Namespace) -> int:
    """Run the local Stage 25 application contract benchmark."""
    engine = Stage25BenchmarkEngine()
    suite, scenarios, matrix = load_stage25_suite()
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
                    _, actions = run_stage25_model_shadow_trial(
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage26(args: argparse.Namespace) -> int:
    """Run the local Stage 26 identity/workflow intelligence benchmark."""
    engine = Stage26BenchmarkEngine()
    suite, scenarios, matrix = load_stage26_suite()
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
            model_trials = max(3, trial_count)
            for scenario in scenarios:
                for model_number in range(1, model_trials + 1):
                    _, actions = run_stage26_model_shadow_trial(
                        run.run_id, scenario, trial_number=model_number,
                        trial_count=model_trials, model_id=args.model_id or "offline-stub",
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
        "trial_replays": replays,
        "coverage": {"samples": len(coverage), "required": matrix.required_count, "diagnostic": matrix.diagnostic_count, "failure_taxonomy": {key: sum(item.failure_taxonomy == key for item in coverage) for key in sorted({item.failure_taxonomy for item in coverage if item.failure_taxonomy})}},
        "model": {"mode": args.mode, "provider": "offline_stub" if args.mode in {"model", "hybrid"} else "none", "status": "diagnostic_only", "actions": len(model_actions), "valid_actions": sum(bool(item["valid"]) for item in model_actions)},
    }
    print(json.dumps(redact(summary), sort_keys=True, indent=2))
    return 0 if gate.decision == "ready" else 1


def _stage27(args: argparse.Namespace) -> int:
    """Run the local Stage 27 recon closure benchmark."""
    engine = Stage27BenchmarkEngine()
    suite, scenarios, matrix = load_stage27_suite()
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
                for model_number in range(1, max(3, trial_count) + 1):
                    _, actions = run_stage27_model_shadow_trial(
                        run.run_id, scenario, trial_number=model_number,
                        trial_count=max(3, trial_count), model_id=args.model_id or "offline-stub",
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
        "suite": suite.model_dump(mode="json"), "matrix": matrix.model_dump(mode="json"),
        "run": run.model_dump(mode="json"), "release_gate": gate.model_dump(mode="json"),
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
    run.add_argument("--suite", default=STAGE8_SUITE_ID, choices=[STAGE8_SUITE_ID, STAGE9_SUITE_ID, STAGE10_SUITE_ID, STAGE11_SUITE_ID, STAGE12_SUITE_ID, STAGE13_SUITE_ID, STAGE14_SUITE_ID, STAGE15_SUITE_ID, STAGE16_SUITE_ID, STAGE17_SUITE_ID, STAGE18_SUITE_ID, STAGE19_SUITE_ID, STAGE22_SUITE_ID, STAGE23_SUITE_ID, STAGE24_SUITE_ID, STAGE25_SUITE_ID, STAGE26_SUITE_ID, STAGE27_SUITE_ID, "stage6-core"])
    run.add_argument("--mode", default="deterministic", choices=["deterministic", "model", "hybrid"])
    run.add_argument("--trials", type=int, default=3, choices=range(1, 101))
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--model-id", default="")
    args = parser.parse_args(argv)
    if args.suite == "stage6-core":
        return _stage6(args)
    if args.suite == STAGE9_SUITE_ID:
        return _stage9(args)
    if args.suite == STAGE10_SUITE_ID:
        return _stage10(args)
    if args.suite == STAGE11_SUITE_ID:
        return _stage11(args)
    if args.suite == STAGE12_SUITE_ID:
        return _stage12(args)
    if args.suite == STAGE13_SUITE_ID:
        return _stage13(args)
    if args.suite == STAGE14_SUITE_ID:
        return _stage14(args)
    if args.suite == STAGE15_SUITE_ID:
        return _stage15(args)
    if args.suite == STAGE16_SUITE_ID:
        return _stage16(args)
    if args.suite == STAGE17_SUITE_ID:
        return _stage17(args)
    if args.suite == STAGE18_SUITE_ID:
        return _stage18(args)
    if args.suite == STAGE19_SUITE_ID:
        return _stage19(args)
    if args.suite == STAGE22_SUITE_ID:
        return _stage22(args)
    if args.suite == STAGE23_SUITE_ID:
        return _stage23(args)
    if args.suite == STAGE24_SUITE_ID:
        return _stage24(args)
    if args.suite == STAGE25_SUITE_ID:
        return _stage25(args)
    if args.suite == STAGE26_SUITE_ID:
        return _stage26(args)
    if args.suite == STAGE27_SUITE_ID:
        return _stage27(args)
    return _stage8(args)


if __name__ == "__main__":
    sys.exit(main())

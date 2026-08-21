"""HTTP surface for Stage 6 regression and Stage 8 benchmark runs."""
from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

from core.evaluation_contract import EvaluationBaselineV1, EvaluationRunV1, ReleaseGateDecisionV1
from core.evaluation_engine import EvaluationEngine, compare_to_baseline
from core.evaluation_repository import EvaluationRepository
from core.execution_contract import ExecutionJobV1, ResourceBudgetV1, stable_digest
from core.stage8_benchmark import (
    STAGE8_SUITE_ID,
    Stage8BenchmarkEngine,
    load_stage8_suite,
    run_model_shadow_trial,
)
from core.stage9_benchmark import STAGE9_SUITE_ID, Stage9BenchmarkEngine, load_stage9_suite, run_stage9_model_shadow_trial


class EvaluationRunRequest(BaseModel):
    suite_id: str = "stage6-core"
    session_id: Optional[str] = None
    mode: str = Field(default="deterministic", pattern="^(deterministic|model|hybrid)$")
    model_id: str = ""
    seed: int = 0
    trial_number: int = Field(default=1, ge=1, le=100)
    trial_count: int = Field(default=1, ge=1, le=100)
    enqueue: bool = True


class ReleaseReviewRequest(BaseModel):
    reviewer_id: str = Field(min_length=1, max_length=200)
    decision: str = Field(pattern="^(approve|reject)$")
    reason: str = Field(min_length=1, max_length=2000)


class BaselineAcceptRequest(BaseModel):
    reviewer_id: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=2000)


def register_evaluation_routes(
    app: Any,
    require_api_key: Callable[..., Any],
    engine: EvaluationEngine,
    repository: EvaluationRepository,
    durable_repository: Any,
    config_getter: Callable[[str, Any], Any],
) -> Dict[str, Any]:
    stage8_engine = Stage8BenchmarkEngine()
    stage9_engine = Stage9BenchmarkEngine()
    memory: Dict[str, Any] = {
        "runs": {},
        "cases": {},
        "metrics": {},
        "gates": {},
        "stage8": {"matrices": {}, "coverage": {}, "trials": {}, "actions": {}},
        "stage9": {"matrices": {}, "coverage": {}, "trials": {}, "actions": {}},
    }

    def configured_path(key: str, fallback: str) -> Path:
        evaluation_config = config_getter("evaluation", {}) or {}
        configured = Path(str(evaluation_config.get(key, fallback)))
        return configured if configured.is_absolute() else Path(__file__).resolve().parent.parent / configured

    def load_suite(suite_id: str = "stage6-core"):
        if suite_id == STAGE8_SUITE_ID:
            return stage8_engine.load_suite(configured_path("stage8_suite_path", "benchmarks/stage8/foundation_suite.yaml"))
        if suite_id == STAGE9_SUITE_ID:
            return stage9_engine.load_suite(configured_path("stage9_suite_path", "benchmarks/stage9/detection_suite.yaml"))
        if suite_id == "stage6-core":
            return engine.load_suite(configured_path("core_suite_path", "benchmarks/stage6/core_suite.yaml"))
        raise HTTPException(status_code=404, detail="Evaluation suite not found.")

    def stage8_bundle():
        return load_stage8_suite(configured_path("stage8_suite_path", "benchmarks/stage8/foundation_suite.yaml"))

    def stage9_bundle():
        return load_stage9_suite(configured_path("stage9_suite_path", "benchmarks/stage9/detection_suite.yaml"))

    def execute_suite(
        suite_id: str,
        *,
        run_id: str,
        mode: str = "deterministic",
        model_id: str = "",
        trial_number: int = 1,
        trial_count: int = 1,
        seed: int = 0,
    ) -> Tuple[EvaluationRunV1, list, list, ReleaseGateDecisionV1, Dict[str, Any]]:
        suite = load_suite(suite_id)
        if suite_id == STAGE9_SUITE_ID:
            _, scenarios, _ = stage9_bundle()
            run, results, snapshots, gate, matrix, coverage, trials = stage9_engine.run_suite(
                suite, run_id=run_id, trial_number=trial_number, trial_count=max(1, trial_count), seed=seed, mode=mode,
            )
            run.mode = mode
            actions = []
            if mode in {"model", "hybrid"}:
                model_trials = max(3, trial_count)
                for scenario in scenarios:
                    for number in range(1, model_trials + 1):
                        model_trial, model_actions = run_stage9_model_shadow_trial(
                            run.run_id, scenario, trial_number=number,
                            trial_count=model_trials, model_id=model_id or "offline-stub",
                        )
                        model_trial = model_trial.model_copy(update={"seed": seed})
                        trials.append(model_trial)
                        actions.extend(model_actions)
                valid = sum(item.valid for item in actions)
                run.metrics["model_action_validity"] = valid / max(1, len(actions))
                run.metrics["model_invalid_action_count"] = float(len(actions) - valid)
                run.totals["model_trials"] = len([item for item in trials if item.mode != "deterministic"])
            return run, results, snapshots, gate, {"matrix": matrix, "scenarios": scenarios, "coverage": coverage, "trials": trials, "actions": actions, "benchmark_group": "stage9"}
        if suite_id == STAGE8_SUITE_ID:
            _, scenarios, _ = stage8_bundle()
            run, results, snapshots, gate, matrix, coverage, trials = stage8_engine.run_suite(
                suite,
                run_id=run_id,
                model_id=model_id,
                trial_number=trial_number,
                trial_count=trial_count,
                seed=seed,
                path=configured_path("stage8_suite_path", "benchmarks/stage8/foundation_suite.yaml"),
            )
            run.mode = mode
            actions = []
            if mode in {"model", "hybrid"}:
                model_trials = max(3, trial_count)
                for scenario in scenarios:
                    for number in range(1, model_trials + 1):
                        model_trial, model_actions = run_model_shadow_trial(
                            run.run_id,
                            scenario,
                            trial_number=number,
                            trial_count=model_trials,
                            model_id=model_id or "offline-stub",
                        )
                        model_trial = model_trial.model_copy(update={"seed": seed})
                        trials.append(model_trial)
                        actions.extend(model_actions)
                valid = sum(item.valid for item in actions)
                run.metrics["model_action_validity"] = valid / max(1, len(actions))
                run.metrics["model_invalid_action_count"] = float(len(actions) - valid)
                run.totals["model_trials"] = len([item for item in trials if item.mode != "deterministic"])
            extra = {
                "matrix": matrix,
                "scenarios": scenarios,
                "coverage": coverage,
                "trials": trials,
                "actions": actions,
            }
            return run, results, snapshots, gate, extra
        run, results, snapshots, gate = engine.run_suite(
            suite,
            run_id=run_id,
            model_id=model_id,
            trial_number=trial_number,
            trial_count=trial_count,
        )
        run.mode = mode
        return run, results, snapshots, gate, {}

    def persist(run: EvaluationRunV1, results: list, snapshots: list, gate: ReleaseGateDecisionV1, extra: Dict[str, Any]) -> None:
        memory["runs"][run.run_id] = run.model_dump(mode="json")
        memory["cases"][run.run_id] = [item.model_dump(mode="json") for item in results]
        memory["metrics"][run.run_id] = [item.model_dump(mode="json") for item in snapshots]
        memory["gates"][run.run_id] = gate.model_dump(mode="json")
        if extra.get("matrix"):
            group = str(extra.get("benchmark_group", "stage8"))
            memory[group]["matrices"][run.run_id] = extra["matrix"].model_dump(mode="json")
            memory[group]["coverage"][run.run_id] = [item.model_dump(mode="json") for item in extra.get("coverage", [])]
            memory[group]["trials"][run.run_id] = [item.model_dump(mode="json") for item in extra.get("trials", [])]
            memory[group]["actions"][run.run_id] = [item.model_dump(mode="json") for item in extra.get("actions", [])]
        try:
            suite = load_suite(run.suite_id)
            repository.save_suite(suite)
            repository.save_run(run)
            repository.save_case_results(results)
            repository.save_metrics(snapshots)
            repository.save_gate(gate)
            if extra.get("matrix"):
                repository.save_stage8_records(
                    extra["matrix"], extra.get("scenarios", []), extra.get("trials", []),
                    extra.get("coverage", []), extra.get("actions", []),
                )
        except Exception:
            # Shadow mode remains queryable in memory when migrations are not
            # installed. Production cutover still requires persistence success.
            pass

    def run_for_worker(payload: Dict[str, Any], session_id: str, job_id: str) -> Dict[str, Any]:
        run, results, snapshots, gate, extra = execute_suite(
            str(payload.get("suite_id", "stage6-core")),
            run_id=str(payload.get("run_id") or f"eval_{uuid.uuid4().hex}"),
            mode=str(payload.get("mode", "deterministic")),
            model_id=str(payload.get("model_id") or ""),
            trial_number=int(payload.get("trial_number", 1)),
            trial_count=int(payload.get("trial_count", 1)),
            seed=int(payload.get("seed", 0)),
        )
        run.session_id = session_id
        run.job_id = job_id
        persist(run, results, snapshots, gate, extra)
        return {"run": run, "results": results, "snapshots": snapshots, "gate": gate, "extra": extra}

    memory["load_suite"] = load_suite
    memory["execute"] = run_for_worker

    @app.get("/evaluations/suites")
    async def list_evaluation_suites(_: bool = Depends(require_api_key)):
        return {"suites": [load_suite("stage6-core").model_dump(mode="json"), load_suite(STAGE8_SUITE_ID).model_dump(mode="json"), load_suite(STAGE9_SUITE_ID).model_dump(mode="json")]}

    @app.post("/evaluations/runs")
    async def start_evaluation_run(req: EvaluationRunRequest, _: bool = Depends(require_api_key)):
        suite = load_suite(req.suite_id)
        run_id = f"eval_{uuid.uuid4().hex}"
        fixture_digest = suite.manifest_digest
        if req.suite_id == STAGE8_SUITE_ID:
            fixture_digest = stage8_bundle()[2].fixture_digest
        elif req.suite_id == STAGE9_SUITE_ID:
            fixture_digest = stage9_bundle()[2].fixture_digest
        if req.enqueue:
            if not req.session_id:
                raise HTTPException(status_code=400, detail="session_id is required for queued evaluation.")
            job_id = str(uuid.uuid4())
            run = EvaluationRunV1(
                run_id=run_id, suite_id=suite.suite_id, suite_version=suite.version,
                mode=req.mode, session_id=req.session_id, job_id=job_id,
                model_id=req.model_id, random_seed=req.seed,
                trial_number=req.trial_number, trial_count=req.trial_count,
                fixture_digest=fixture_digest,
            )
            memory["runs"][run_id] = run.model_dump(mode="json")
            try:
                repository.save_suite(suite)
                repository.save_run(run)
            except Exception:
                pass
            job = ExecutionJobV1(
                job_id=job_id, session_id=req.session_id, job_type="evaluation_suite",
                queue_name="general", target=f"{req.suite_id}://local",
                goal=f"Run versioned {req.suite_id} evaluation suite",
                payload_redacted={
                    "run_id": run_id, "suite_id": req.suite_id, "mode": req.mode,
                    "model_id": req.model_id, "seed": req.seed,
                    "trial_number": req.trial_number, "trial_count": req.trial_count,
                }, risk="read_only", budget=ResourceBudgetV1(max_requests=1, max_wall_seconds=120 * 60),
                idempotency_key=stable_digest({"run_id": run_id, "suite": suite.manifest_digest}, 40),
            )
            try:
                durable_repository.enqueue(job)
            except Exception as exc:
                raise HTTPException(status_code=503, detail=f"Evaluation queue unavailable: {type(exc).__name__}") from exc
            return {"run": run.model_dump(mode="json"), "job_id": job_id, "status": "queued"}
        run, results, snapshots, gate, extra = execute_suite(
            req.suite_id, run_id=run_id, mode=req.mode, model_id=req.model_id,
            trial_number=req.trial_number, trial_count=req.trial_count, seed=req.seed,
        )
        run.session_id = req.session_id or ""
        persist(run, results, snapshots, gate, extra)
        response = {
            "run": run.model_dump(mode="json"),
            "cases": [item.model_dump(mode="json") for item in results],
            "metrics": [item.model_dump(mode="json") for item in snapshots],
            "release_gate": gate.model_dump(mode="json"),
        }
        if extra.get("matrix"):
            response.update({
                "matrix": extra["matrix"].model_dump(mode="json"),
                "coverage": [item.model_dump(mode="json") for item in extra.get("coverage", [])],
                "trials": [item.model_dump(mode="json") for item in extra.get("trials", [])],
                "model_actions": [item.model_dump(mode="json") for item in extra.get("actions", [])],
            })
        return response

    @app.get("/evaluations/runs")
    async def list_evaluation_runs(suite_id: Optional[str] = None, limit: int = 100, _: bool = Depends(require_api_key)):
        rows = list(memory["runs"].values())
        if suite_id:
            rows = [row for row in rows if row.get("suite_id") == suite_id]
        try:
            persisted = repository.list_runs(suite_id, limit)
            if persisted:
                rows = persisted + [row for row in rows if row.get("run_id") not in {item.get("run_id") for item in persisted}]
        except Exception:
            pass
        return {"runs": rows[: max(1, min(limit, 500))]}

    @app.get("/evaluations/runs/{run_id}")
    async def get_evaluation_run(run_id: str, _: bool = Depends(require_api_key)):
        run = None
        try:
            run = repository.get_run(run_id)
        except Exception:
            pass
        run = run or memory["runs"].get(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Evaluation run not found.")
        cases = memory["cases"].get(run_id)
        metrics = memory["metrics"].get(run_id)
        if cases is None:
            try: cases = repository.list_case_results(run_id)
            except Exception: cases = []
        if metrics is None:
            try: metrics = repository.list_metrics(run_id)
            except Exception: metrics = []
        response = {"run": run, "cases": cases, "metrics": metrics, "release_gate": memory["gates"].get(run_id) or _latest_gate(run_id)}
        if run.get("suite_id") in {STAGE8_SUITE_ID, STAGE9_SUITE_ID}:
            group = "stage9" if run.get("suite_id") == STAGE9_SUITE_ID else "stage8"
            response.update({
                "matrix": memory[group]["matrices"].get(run_id),
                "coverage": memory[group]["coverage"].get(run_id),
                "trials": memory[group]["trials"].get(run_id),
                "model_actions": memory[group]["actions"].get(run_id),
            })
            if response["coverage"] is None:
                try: response["coverage"] = repository.list_stage8_coverage(run_id)
                except Exception: response["coverage"] = []
            if response["trials"] is None:
                try: response["trials"] = repository.list_stage8_trials(run_id)
                except Exception: response["trials"] = []
            if response["model_actions"] is None:
                try: response["model_actions"] = repository.list_stage8_actions(run_id)
                except Exception: response["model_actions"] = []
        return response

    @app.post("/evaluations/runs/{run_id}/release-review")
    async def review_evaluation_run(run_id: str, req: ReleaseReviewRequest, _: bool = Depends(require_api_key)):
        gate_data = memory["gates"].get(run_id) or _latest_gate(run_id)
        if not gate_data:
            raise HTTPException(status_code=404, detail="Evaluation release gate not found.")
        if req.decision == "approve" and gate_data.get("decision") != "ready":
            raise HTTPException(status_code=409, detail="Hard release gates are not ready.")
        gate = ReleaseGateDecisionV1(**gate_data)
        signature_key = os.environ.get("NEXUS_RELEASE_SIGNING_KEY", "")
        signed_payload = f"{gate.run_id}:{gate.suite_id}:{gate.suite_version}:{req.decision}:{req.reviewer_id}:{req.reason}"
        signature = hmac.new(signature_key.encode(), signed_payload.encode(), hashlib.sha256).hexdigest() if signature_key else ""
        reviewed = gate.model_copy(update={"reviewer_id": req.reviewer_id, "review_reason": req.reason, "signature": signature})
        memory["gates"][run_id] = reviewed.model_dump(mode="json")
        try: repository.save_gate(reviewed)
        except Exception: pass
        return {"release_gate": reviewed.model_dump(mode="json")}

    def _latest_gate(run_id: str) -> Optional[Dict[str, Any]]:
        try: return repository.get_latest_gate(run_id)
        except Exception: return None

    @app.get("/evaluations/runs/{run_id}/cases")
    async def list_evaluation_cases(run_id: str, _: bool = Depends(require_api_key)):
        if run_id in memory["cases"]: return {"run_id": run_id, "cases": memory["cases"][run_id]}
        return {"run_id": run_id, "cases": repository.list_case_results(run_id)}

    @app.get("/evaluations/runs/{run_id}/metrics")
    async def list_evaluation_metrics(run_id: str, _: bool = Depends(require_api_key)):
        if run_id in memory["metrics"]: return {"run_id": run_id, "metrics": memory["metrics"][run_id]}
        return {"run_id": run_id, "metrics": repository.list_metrics(run_id)}

    @app.get("/evaluations/runs/{run_id}/coverage")
    async def list_evaluation_coverage(run_id: str, _: bool = Depends(require_api_key)):
        rows = memory["stage8"]["coverage"].get(run_id) or memory["stage9"]["coverage"].get(run_id)
        if rows is None:
            try: rows = repository.list_stage8_coverage(run_id)
            except Exception: rows = []
        return {"run_id": run_id, "coverage": rows}

    @app.get("/evaluations/runs/{run_id}/trials")
    async def list_evaluation_trials(run_id: str, _: bool = Depends(require_api_key)):
        rows = memory["stage8"]["trials"].get(run_id) or memory["stage9"]["trials"].get(run_id)
        if rows is None:
            try: rows = repository.list_stage8_trials(run_id)
            except Exception: rows = []
        return {"run_id": run_id, "trials": rows}

    @app.get("/evaluations/runs/{run_id}/matrix")
    async def get_evaluation_matrix(run_id: str, _: bool = Depends(require_api_key)):
        row = memory["stage8"]["matrices"].get(run_id) or memory["stage9"]["matrices"].get(run_id)
        if row is None:
            run = repository.get_run(run_id) or memory["runs"].get(run_id)
            if run and run.get("suite_id") in {STAGE8_SUITE_ID, STAGE9_SUITE_ID}:
                try: row = repository.get_stage8_matrix(run["suite_id"], run.get("suite_version"))
                except Exception: row = None
        if row is None: raise HTTPException(status_code=404, detail="Benchmark matrix not found.")
        return {"run_id": run_id, "matrix": row}

    @app.get("/evaluations/runs/{run_id}/model-actions")
    async def list_model_actions(run_id: str, _: bool = Depends(require_api_key)):
        rows = memory["stage8"]["actions"].get(run_id)
        if rows is None:
            try: rows = repository.list_stage8_actions(run_id)
            except Exception: rows = []
        return {"run_id": run_id, "model_actions": rows}

    @app.get("/evaluations/runs/{run_id}/coverage-gaps")
    async def evaluation_coverage_gaps(run_id: str, _: bool = Depends(require_api_key)):
        run = repository.get_run(run_id) or memory["runs"].get(run_id)
        if not run or run.get("suite_id") not in {STAGE8_SUITE_ID, STAGE9_SUITE_ID}:
            raise HTTPException(status_code=404, detail="Benchmark run not found.")
        coverage = memory["stage8"]["coverage"].get(run_id) or memory["stage9"]["coverage"].get(run_id)
        if coverage is None:
            try: coverage = repository.list_stage8_coverage(run_id)
            except Exception: coverage = []
        by_family: Dict[str, Dict[str, Any]] = {}
        for item in coverage:
            family = str(item.get("vulnerability_family", "unknown"))
            row = by_family.setdefault(family, {"scenario_count": 0, "diagnostic_count": 0, "unsupported": False, "failure_taxonomies": []})
            row["scenario_count"] += 1
            if item.get("capability_tier") != "required": row["diagnostic_count"] += 1
            if item.get("failure_taxonomy") == "unsupported_capability": row["unsupported"] = True
            if item.get("failure_taxonomy") and item.get("failure_taxonomy") not in row["failure_taxonomies"]:
                row["failure_taxonomies"].append(item["failure_taxonomy"])
        return {"run_id": run_id, "unsupported_capabilities": sorted([key for key, value in by_family.items() if value["unsupported"]]), "by_family": by_family}

    @app.post("/evaluations/runs/{run_id}/baseline")
    async def accept_evaluation_baseline(run_id: str, req: BaselineAcceptRequest, _: bool = Depends(require_api_key)):
        run_data = repository.get_run(run_id) or memory["runs"].get(run_id)
        gate_data = memory["gates"].get(run_id) or _latest_gate(run_id)
        if not run_data or not gate_data:
            raise HTTPException(status_code=404, detail="Evaluation run or release gate not found.")
        if gate_data.get("decision") != "ready":
            raise HTTPException(status_code=409, detail="Only a ready deterministic gate can become a baseline.")
        baseline = EvaluationBaselineV1(
            suite_id=run_data["suite_id"], suite_version=run_data["suite_version"], run_id=run_id,
            commit_sha=run_data.get("commit_sha", ""), config_digest=run_data.get("config_digest", ""),
            metrics=run_data.get("metrics", {}),
        )
        suite = load_suite(baseline.suite_id)
        fixture_digest = run_data.get("fixture_digest", "")
        try:
            repository.save_baseline(baseline)
            repository.save_baseline_acceptance(baseline.baseline_id, req.reviewer_id, req.reason, suite.manifest_digest, fixture_digest, baseline.metrics)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Baseline persistence unavailable: {type(exc).__name__}") from exc
        return {"baseline": baseline.model_dump(mode="json"), "reviewer_id": req.reviewer_id, "reason": req.reason}

    @app.get("/evaluations/runs/{run_id}/diff")
    async def diff_evaluation_run(run_id: str, _: bool = Depends(require_api_key)):
        current = repository.get_run(run_id) or memory["runs"].get(run_id)
        if not current: raise HTTPException(status_code=404, detail="Evaluation run not found.")
        previous = [item for item in repository.list_runs(current.get("suite_id"), 20) if item.get("run_id") != run_id]
        baseline = previous[0].get("metrics", {}) if previous else {}
        return {"run_id": run_id, "baseline_run_id": previous[0].get("run_id") if previous else None, "diff": [item.model_dump(mode="json") for item in compare_to_baseline(current.get("metrics", {}), baseline)]}

    @app.post("/evaluations/runs/{run_id}/cancel")
    async def cancel_evaluation_run(run_id: str, _: bool = Depends(require_api_key)):
        run = repository.get_run(run_id) or memory["runs"].get(run_id)
        if not run: raise HTTPException(status_code=404, detail="Evaluation run not found.")
        if not run.get("job_id"): raise HTTPException(status_code=409, detail="Evaluation run has no durable job.")
        accepted = durable_repository.request_cancel(run["job_id"])
        run["status"] = "cancelled"
        memory["runs"][run_id] = run
        return {"run_id": run_id, "job_id": run["job_id"], "cancel_requested": bool(accepted)}

    @app.get("/release-gates/current")
    async def current_release_gate(suite_id: Optional[str] = None, _: bool = Depends(require_api_key)):
        gates = [item for item in memory["gates"].values() if not suite_id or item.get("suite_id") == suite_id]
        try: gates.extend(item for item in repository.list_gates(None, 20) if not suite_id or item.get("suite_id") == suite_id)
        except Exception: pass
        return {"release_gate": gates[0] if gates else None}

    return memory

"""Bounded deterministic race experiment runner.

The engine measures server-side effects and repeatability. Response status or
body length alone can never produce a finding.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from core.execution_contract import RaceExperimentV1, stable_digest


@dataclass
class RaceSample:
    role: str
    sample_number: int
    concurrency: int
    status_code: Optional[int] = None
    response_fingerprint: str = ""
    effect_key: str = ""
    elapsed_ms: float = 0.0
    error: str = ""
    observation_ids: List[str] = field(default_factory=list)


@dataclass
class RaceEvaluation:
    decision: str
    reason: str
    baseline: List[RaceSample]
    control: List[RaceSample]
    test: List[RaceSample]
    reproduction: List[RaceSample]
    cleanup_verified: bool
    candidate: Optional[Dict[str, Any]] = None


class RaceExperimentError(RuntimeError):
    pass


class DeterministicRaceEngine:
    def __init__(self, max_concurrency: int = 8, schedule: Iterable[int] = (2, 4, 8)):
        self.max_concurrency = max(1, min(8, int(max_concurrency)))
        self.schedule = sorted({max(1, min(self.max_concurrency, int(value))) for value in schedule})

    @staticmethod
    def approval_digest(experiment: RaceExperimentV1) -> str:
        return stable_digest({
            "experiment_id": experiment.experiment_id,
            "target": experiment.target,
            "method": experiment.method,
            "template": experiment.request_template_id,
            "workflow": experiment.workflow_id,
            "identity": experiment.identity_id,
            "invariant": experiment.invariant_id,
            "mutation_digest": experiment.mutation_digest,
            "schedule": experiment.schedule,
            "cleanup_refs": experiment.cleanup_refs,
        }, 40)

    def run(
        self,
        experiment: RaceExperimentV1,
        *,
        approved_digest: str,
        baseline_fn: Callable[[int], Dict[str, Any]],
        control_fn: Callable[[int], Dict[str, Any]],
        mutation_fn: Callable[[int, threading.Barrier], Dict[str, Any]],
        reproduction_fn: Callable[[int], Dict[str, Any]],
        cleanup_fn: Callable[[], bool],
    ) -> RaceEvaluation:
        if approved_digest != self.approval_digest(experiment):
            raise RaceExperimentError("Exact race experiment approval is required.")
        if not experiment.cleanup_refs:
            raise RaceExperimentError("Race experiment requires a registered cleanup plan.")
        baseline = self._sequential("baseline", experiment.baseline_samples, 1, baseline_fn)
        control = self._sequential("negative_control", experiment.control_samples, 1, control_fn)
        if not baseline or not control:
            return RaceEvaluation("inconclusive", "Baseline and negative control are required.", baseline, control, [], [], False)

        test: List[RaceSample] = []
        for concurrency in self.schedule:
            test.extend(self._burst("test", concurrency, mutation_fn))
            if self._effect_count(test) > self._effect_count(control) + 1:
                break

        reproduction = self._sequential("reproduction", 1, 1, reproduction_fn)
        cleanup_verified = bool(cleanup_fn())
        expected = self._effect_count(control)
        observed = self._effect_count(test)
        control_keys = {sample.effect_key for sample in control if sample.effect_key}
        reproduced = bool(reproduction) and any(sample.effect_key and sample.effect_key not in control_keys for sample in reproduction)
        violated = observed > expected and reproduced and cleanup_verified
        if violated:
            candidate = {
                "title": "Concurrent operation produced more server-side effects than the control",
                "vuln_type": "race_condition",
                "status": "suspected",
                "metadata": {
                    "policy_id": "race_condition.v1",
                    "baseline_samples": len(baseline),
                    "control_samples": len(control),
                    "test_samples": len(test),
                    "reproduction_samples": len(reproduction),
                    "control_effects": expected,
                    "test_effects": observed,
                    "cleanup_verified": cleanup_verified,
                },
            }
            return RaceEvaluation("violated", "Concurrent server-side effect was reproduced and cleanup verified.", baseline, control, test, reproduction, cleanup_verified, candidate)
        reason = "Race signal was not reproduced, control was missing, or cleanup failed."
        return RaceEvaluation("satisfied" if cleanup_verified else "inconclusive", reason, baseline, control, test, reproduction, cleanup_verified)

    @staticmethod
    def _sequential(role: str, count: int, concurrency: int, fn: Callable[[int], Dict[str, Any]]) -> List[RaceSample]:
        samples: List[RaceSample] = []
        for index in range(max(0, count)):
            samples.append(DeterministicRaceEngine._sample(role, index, concurrency, fn, index))
        return samples

    @staticmethod
    def _burst(role: str, concurrency: int, fn: Callable[[int, threading.Barrier], Dict[str, Any]]) -> List[RaceSample]:
        barrier = threading.Barrier(concurrency)
        samples: List[RaceSample] = []
        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="nexus-race") as pool:
            futures = [pool.submit(fn, index, barrier) for index in range(concurrency)]
            for index, future in enumerate(as_completed(futures)):
                try:
                    data = future.result() or {}
                    samples.append(DeterministicRaceEngine._from_data(role, index, concurrency, data))
                except Exception as exc:
                    samples.append(RaceSample(role, index, concurrency, error=type(exc).__name__))
        return samples

    @staticmethod
    def _sample(role: str, index: int, concurrency: int, fn: Callable[[int], Dict[str, Any]], arg: int) -> RaceSample:
        started = time.monotonic()
        try:
            return DeterministicRaceEngine._from_data(role, index, concurrency, fn(arg), elapsed_ms=(time.monotonic() - started) * 1000)
        except Exception as exc:
            return RaceSample(role, index, concurrency, elapsed_ms=(time.monotonic() - started) * 1000, error=type(exc).__name__)

    @staticmethod
    def _from_data(role: str, index: int, concurrency: int, data: Optional[Dict[str, Any]], elapsed_ms: float = 0.0) -> RaceSample:
        data = data or {}
        return RaceSample(
            role=role, sample_number=index, concurrency=concurrency,
            status_code=data.get("status_code"),
            response_fingerprint=str(data.get("response_fingerprint", "")),
            effect_key=str(data.get("effect_key", "")),
            elapsed_ms=float(data.get("elapsed_ms", elapsed_ms) or 0),
            observation_ids=list(data.get("observation_ids", []) or []),
        )

    @staticmethod
    def _effect_count(samples: List[RaceSample]) -> int:
        return len({sample.effect_key for sample in samples if sample.effect_key})


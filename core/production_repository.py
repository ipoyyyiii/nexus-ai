"""Supabase repository for Stage 13 readiness records."""

from __future__ import annotations

from typing import Any, Optional

from core.production_contract import (
    CutoverDecisionV1, OperatorIncidentV1, ProductionReadinessV1,
    RecoveryVerificationV1, ReadinessCheckV1, SLOSnapshotV1,
    SoakEventV1, SoakRunV1, SoakSampleV1,
)


class ProductionReadinessRepository:
    def __init__(self, supabase: Any):
        self.sb = supabase

    @staticmethod
    def _run_row(run: ProductionReadinessV1) -> dict:
        row = run.model_dump(mode="json")
        row.pop("schema_version", None)
        row.pop("hard_gates", None)
        return row

    @staticmethod
    def _check_row(check: ReadinessCheckV1) -> dict:
        row = check.model_dump(mode="json")
        row.pop("schema_version", None)
        return row

    def save(self, run: ProductionReadinessV1, checks: list[ReadinessCheckV1]) -> None:
        self.sb.table("production_readiness_runs").insert(self._run_row(run)).execute()
        if checks:
            self.sb.table("readiness_checks").insert([self._check_row(item) for item in checks]).execute()

    def get(self, run_id: str) -> Optional[dict]:
        result = self.sb.table("production_readiness_runs").select("*").eq("run_id", run_id).limit(1).execute()
        return result.data[0] if result.data else None

    def list(self, limit: int = 50) -> list[dict]:
        result = self.sb.table("production_readiness_runs").select("*").order("created_at", desc=True).limit(max(1, min(int(limit), 200))).execute()
        return result.data or []

    def checks(self, run_id: str) -> list[dict]:
        result = self.sb.table("readiness_checks").select("*").eq("run_id", run_id).order("created_at").execute()
        return result.data or []


    @staticmethod
    def _row(model: Any) -> dict:
        row = model.model_dump(mode="json")
        row.pop("schema_version", None)
        return row

    def save_soak(self, run: SoakRunV1, samples: list[SoakSampleV1] | None = None) -> None:
        self.sb.table("production_soak_runs").insert(self._row(run)).execute()
        if samples:
            self.sb.table("production_soak_samples").insert([self._row(item) for item in samples]).execute()

    def save_soak_sample(self, sample: SoakSampleV1) -> None:
        self.sb.table("production_soak_samples").upsert(
            self._row(sample), on_conflict="sample_id"
        ).execute()

    def save_soak_event(self, event: SoakEventV1) -> None:
        self.sb.table("production_soak_events").insert(self._row(event)).execute()

    def soak_events(self, soak_run_id: str, limit: int = 100) -> list[dict]:
        result = (self.sb.table("production_soak_events").select("*")
                  .eq("soak_run_id", soak_run_id).order("created_at")
                  .limit(max(1, min(int(limit), 500))).execute())
        return result.data or []

    def _effective_soak(self, row: dict) -> dict:
        effective = dict(row)
        events = self.soak_events(str(row.get("soak_run_id", "")))
        if events:
            latest = events[-1]
            effective["status"] = latest.get("status", effective.get("status"))
            payload = latest.get("payload") or {}
            for key in (
                "expected_jobs", "completed_jobs", "failed_jobs", "recovery_events",
                "stale_write_rejections", "duplicate_suppression_count",
                "cleanup_failures", "redaction_leaks", "finished_at",
                "slo_snapshot_id", "job_id",
            ):
                if key in payload:
                    effective[key] = payload[key]
            effective["last_event_id"] = latest.get("event_id", "")
        return effective

    def list_soaks(self, limit: int = 50) -> list[dict]:
        result = self.sb.table("production_soak_runs").select("*").order("started_at", desc=True).limit(max(1, min(int(limit), 200))).execute()
        return [self._effective_soak(row) for row in (result.data or [])]

    def soak_samples(self, soak_run_id: str) -> list[dict]:
        result = self.sb.table("production_soak_samples").select("*").eq("soak_run_id", soak_run_id).order("sample_number").execute()
        return result.data or []

    def save_slo(self, snapshot: SLOSnapshotV1) -> None:
        self.sb.table("production_slo_snapshots").insert(self._row(snapshot)).execute()

    def list_slo(self, limit: int = 50) -> list[dict]:
        result = self.sb.table("production_slo_snapshots").select("*").order("created_at", desc=True).limit(max(1, min(int(limit), 200))).execute()
        return result.data or []

    def save_cutover(self, decision: CutoverDecisionV1) -> None:
        self.sb.table("production_cutover_decisions").insert(self._row(decision)).execute()

    def list_cutovers(self, limit: int = 50) -> list[dict]:
        result = self.sb.table("production_cutover_decisions").select("*").order("created_at", desc=True).limit(max(1, min(int(limit), 200))).execute()
        return result.data or []

    def save_recovery_verification(self, verification: RecoveryVerificationV1) -> None:
        self.sb.table("recovery_verifications").insert(self._row(verification)).execute()

    def list_recovery_verifications(self, job_id: str, limit: int = 50) -> list[dict]:
        result = self.sb.table("recovery_verifications").select("*").eq("job_id", job_id).order("created_at", desc=True).limit(max(1, min(int(limit), 200))).execute()
        return result.data or []

    def save_incident(self, incident: OperatorIncidentV1) -> None:
        self.sb.table("operator_incidents").insert(self._row(incident)).execute()

    def list_incidents(self, limit: int = 100) -> list[dict]:
        result = self.sb.table("operator_incidents").select("*").order("created_at", desc=True).limit(max(1, min(int(limit), 200))).execute()
        return result.data or []

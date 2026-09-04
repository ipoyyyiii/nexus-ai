"""Supabase persistence for structured tool results."""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from core.detection_validation_repository import (
    DetectionValidationRepository,
    ValidationPersistenceError,
    ValidationStatusIntegrityError,
)
from core.detection_validation_v2 import validation_engine_v2
from core.structured_contract import CandidateFindingV1, ModelCallTraceV1, ObservationV1, ReportClaimV1, ReportNarrativeV1, SemanticComparisonV1, ToolResultV1
from core.validation_engine import validation_engine


class ReasoningPersistenceError(RuntimeError):
    """Typed failure for an incomplete durable AI reasoning cycle."""

    code = "reasoning_persistence_error"

    def __init__(self, table: str, cause: Exception):
        self.table = table
        self.cause_type = type(cause).__name__
        super().__init__(f"reasoning persistence failed at {table}: {self.cause_type}: {cause}")


class ToolRunReconciliationError(RuntimeError):
    """Raised when a failed tool run cannot be durably reconciled exactly once."""

    code = "tool_run_reconciliation_error"


STRUCTURED_SCHEMA_SQL = r'''
create table if not exists tool_runs (
    tool_run_id text primary key, session_id uuid not null, job_id text,
    tool_name text not null, tool_version text not null default '1',
    category text not null default 'unknown', target text not null,
    status text not null, started_at timestamptz not null, finished_at timestamptz,
    inputs_redacted jsonb not null default '{}'::jsonb, summary text not null default '',
    metrics jsonb not null default '{}'::jsonb, errors jsonb not null default '[]'::jsonb,
    side_effects jsonb not null default '[]'::jsonb, cleanup_refs jsonb not null default '[]'::jsonb,
    legacy_source boolean not null default false, created_at timestamptz not null default now()
);
create table if not exists evidence_artifacts (
    artifact_id text primary key, session_id uuid not null, tool_run_id text,
    kind text not null, mime_type text not null default 'text/plain', sha256 text not null default '',
    size_bytes integer not null default 0, excerpt text not null default '', storage_uri text not null default '',
    redacted boolean not null default true, retention_until timestamptz,
    metadata jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);
create table if not exists observations (
    observation_id text primary key, session_id uuid not null, tool_run_id text not null,
    role text not null, kind text not null, summary text not null default '', target_url text not null default '',
    method text not null default 'GET', request_excerpt text not null default '', response_excerpt text not null default '',
    status_code integer, response_time_ms numeric, payload_hash text not null default '',
    artifact_ids jsonb not null default '[]'::jsonb, metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);
create table if not exists candidate_findings (
    candidate_id text primary key, session_id uuid not null, tool_run_id text,
    title text not null, vuln_type text not null, severity text not null default 'INFO', target_url text not null default '',
    method text not null default 'GET', parameter text not null default '', injection_point text not null default '',
    fingerprint text not null, status text not null default 'suspected', confidence_score numeric not null default 0.5,
    confidence_reasons jsonb not null default '[]'::jsonb, remediation text not null default '',
    metadata jsonb not null default '{}'::jsonb, created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(), unique(session_id, fingerprint)
);
create table if not exists candidate_evidence (
    candidate_id text not null references candidate_findings(candidate_id) on delete cascade,
    observation_id text not null references observations(observation_id) on delete cascade,
    primary key(candidate_id, observation_id)
);
create table if not exists validation_runs (
    validation_run_id text primary key, candidate_id text not null references candidate_findings(candidate_id) on delete cascade, policy_id text not null,
    policy_version text not null, decision text not null, score numeric not null default 0,
    reason text not null default '', created_at timestamptz not null default now()
);
create table if not exists validation_checks (
    validation_run_id text not null references validation_runs(validation_run_id) on delete cascade, check_name text not null, passed boolean not null,
    details jsonb not null default '{}'::jsonb, primary key(validation_run_id, check_name)
);
create table if not exists finding_reviews (
    review_id uuid primary key default gen_random_uuid(), candidate_id text not null references candidate_findings(candidate_id) on delete cascade,
    decision text not null, reason text not null, reviewer text not null default 'api',
    created_at timestamptz not null default now()
);
create index if not exists idx_structured_runs_session on tool_runs(session_id, created_at desc);
create index if not exists idx_structured_candidates_session on candidate_findings(session_id, status, updated_at desc);
'''


class StructuredRepository:
    def __init__(self, session_store: Any):
        self.store = session_store
        self.sb = session_store.sb
        # V2 validation is invoked by StructuredToolRunner before this
        # repository receives the ToolResult.  Defer only that batch until the
        # candidate rows have crossed the durable persistence boundary.
        # A repository instance is shared by API requests. Pending V2 batches
        # therefore must be partitioned by session; a global list could flush
        # a failed batch into the next user's run. The empty key is retained
        # only for old in-process callers that did not provide session_id.
        self._pending_v2_validations: Dict[str, list[tuple[list, list]]] = {}

    def persist(self, session_id: str, result: ToolResultV1, validations: Optional[list] = None, *, job_id: str = "") -> None:
        self.sb.table("tool_runs").upsert({
            "tool_run_id": result.tool_run_id, "session_id": session_id,
            "job_id": job_id or result.tool_run_id, "tool_name": result.tool_name,
            "tool_version": result.tool_version, "category": result.category,
            "target": result.target, "status": result.status,
            "started_at": result.started_at, "finished_at": result.finished_at,
            "inputs_redacted": result.inputs_redacted, "summary": result.summary,
            "metrics": result.metrics, "errors": [e.model_dump() for e in result.errors],
            "side_effects": result.side_effects, "cleanup_refs": result.cleanup_refs,
            "legacy_source": result.legacy_source,
        }).execute()
        for item in result.artifacts:
            self.sb.table("evidence_artifacts").upsert({"session_id": session_id, "tool_run_id": result.tool_run_id, **item.model_dump()}).execute()
        for item in result.observations:
            self.sb.table("observations").upsert({"session_id": session_id, "tool_run_id": result.tool_run_id, **item.model_dump()}).execute()
        candidate_id_map = {}
        candidate_statuses = {}
        for item in result.candidate_findings:
            source_candidate_id = item.candidate_id
            # Candidate IDs are globally unique, while fingerprints are
            # session-scoped.  Reject a caller trying to reuse another
            # session's candidate ID instead of allowing a primary-key error
            # or accidental cross-session update to obscure the cause.
            owner_rows = (
                self.sb.table("candidate_findings")
                .select("candidate_id,session_id")
                .eq("candidate_id", source_candidate_id)
                .limit(1)
                .execute()
                .data
                or []
            )
            if owner_rows and str(owner_rows[0].get("session_id") or "") != str(session_id):
                raise ValidationPersistenceError(
                    "Candidate ID belongs to a different session.",
                    candidate_id=source_candidate_id,
                    details={"operation": "candidate_session_ownership", "session_id": session_id},
                )
            existing = self.sb.table("candidate_findings").select("candidate_id").eq("session_id", session_id).eq("fingerprint", item.fingerprint).limit(1).execute().data or []
            stored_id = existing[0]["candidate_id"] if existing else item.candidate_id
            candidate_id_map[source_candidate_id] = stored_id
            candidate_statuses[stored_id] = item.status
            item.candidate_id = stored_id
            # ``observation_ids`` is a contract-level convenience field.  It
            # is not a column in ``candidate_findings``; the normalized link
            # belongs in ``candidate_evidence`` below.  Passing the complete
            # model dump to Supabase made every legacy candidate fail after
            # its tool run and observation had already been written.
            observation_ids = list(item.observation_ids)
            item.metadata = {**(item.metadata or {}), "evidence_ids": observation_ids}
            candidate_payload = item.model_dump(exclude={"observation_ids"})
            # A validator mutates the in-memory contract before persistence.
            # Stage a validated candidate as inconclusive; promotion happens
            # only after a complete durable validation run and its checks.
            if candidate_payload.get("status") == "validated":
                candidate_payload["status"] = "inconclusive"
            row = {"session_id": session_id, "tool_run_id": result.tool_run_id, **candidate_payload}
            self.sb.table("candidate_findings").upsert(row, on_conflict="session_id,fingerprint").execute()
            self._require_durable_candidate(session_id, stored_id)
            for observation_id in observation_ids:
                self.sb.table("candidate_evidence").upsert({"candidate_id": stored_id, "observation_id": observation_id}).execute()

        # V2 validation is authoritative for the runner path.  It is flushed
        # only after every candidate in this result is durable, so its FK can
        # never race candidate insertion.
        self._flush_pending_v2_validations(candidate_id_map, session_id=session_id)

        for validation in validations or []:
            validation_candidate_id = candidate_id_map.get(validation.candidate_id, validation.candidate_id)
            validation_id = f"val_{uuid.uuid4().hex}"
            DetectionValidationRepository(self.sb).save_legacy_decision(
                validation_run_id=validation_id,
                candidate_id=validation_candidate_id,
                policy_id=validation.policy_id,
                policy_version=validation.policy_version,
                decision=validation.decision,
                score=validation.score,
                reason=validation.reason,
                checks=validation.checks,
            )

        for candidate_id, original_status in candidate_statuses.items():
            if original_status != "validated":
                continue
            # If the authoritative V2 trace failed before this persistence
            # boundary, legacy validation rows are not enough to claim a
            # complete finding.  Leave the staged candidate inconclusive and
            # let the runner surface the typed trace error as partial.
            if any(
                getattr(error, "code", "") == "validation_trace_persistence_error"
                for error in (result.errors or [])
            ):
                continue
            validator = DetectionValidationRepository(self.sb)
            if not validator.has_successful_canonical_validation(candidate_id):
                raise ValidationStatusIntegrityError(
                    "Candidate promotion was requested without a complete canonical V2 validation run.",
                    candidate_id=candidate_id,
                    details={"operation": "candidate_status_promotion"},
                )
            self._promote_candidate(session_id, candidate_id)

    def reconcile_tool_run_failure(self, session_id: str, result: ToolResultV1) -> None:
        """Repair the root tool row after a child persistence failure.

        ``persist`` writes the root row before observations, artifacts, and
        candidate validation rows.  If a later write fails, the caller must
        not leave a durable ``succeeded`` row behind while returning
        ``partial`` in memory.  The reconciliation update is deliberately
        narrow and carries the complete structured error list. The update must
        affect exactly one session/tool-run row and the repaired values are
        read back before this method returns; otherwise the caller must surface
        reconciliation as a second persistence failure.
        """
        if not session_id or not result.tool_run_id:
            raise ToolRunReconciliationError(
                "Cannot reconcile a tool run without an exact session_id and tool_run_id."
            )
        payload = {
            "status": result.status if result.status != "succeeded" else "partial",
            "errors": [item.model_dump(mode="json") for item in result.errors],
            "metrics": result.metrics,
            "finished_at": result.finished_at,
        }
        query = (
            self.sb.table("tool_runs")
            .update(payload)
            .eq("tool_run_id", result.tool_run_id)
            .eq("session_id", session_id)
            .select("tool_run_id,session_id,status,errors,metrics,finished_at")
        )
        try:
            response = query.execute()
            affected_rows = list(getattr(response, "data", None) or [])
        except Exception as exc:
            raise ToolRunReconciliationError(
                f"Tool-run reconciliation update failed: {type(exc).__name__}: {exc}"
            ) from exc
        if len(affected_rows) != 1:
            raise ToolRunReconciliationError(
                "Tool-run reconciliation must affect exactly one row; "
                f"affected={len(affected_rows)} session_id={session_id} "
                f"tool_run_id={result.tool_run_id}"
            )

        expected = {
            "tool_run_id": result.tool_run_id,
            "session_id": session_id,
            **payload,
        }
        try:
            readback_rows = list(
                self.sb.table("tool_runs")
                .select("tool_run_id,session_id,status,errors,metrics,finished_at")
                .eq("tool_run_id", result.tool_run_id)
                .eq("session_id", session_id)
                .limit(2)
                .execute()
                .data
                or []
            )
        except Exception as exc:
            raise ToolRunReconciliationError(
                f"Tool-run reconciliation readback failed: {type(exc).__name__}: {exc}"
            ) from exc
        if len(readback_rows) != 1:
            raise ToolRunReconciliationError(
                "Tool-run reconciliation readback must return exactly one row; "
                f"rows={len(readback_rows)} session_id={session_id} "
                f"tool_run_id={result.tool_run_id}"
            )
        repaired = readback_rows[0]
        mismatches = {
            field: {"expected": value, "actual": repaired.get(field)}
            for field, value in expected.items()
            if repaired.get(field) != value
        }
        if mismatches:
            raise ToolRunReconciliationError(
                "Tool-run reconciliation readback mismatch: "
                f"session_id={session_id} tool_run_id={result.tool_run_id} "
                f"mismatches={mismatches}"
            )

    def _require_durable_candidate(self, session_id: str, candidate_id: str) -> None:
        try:
            rows = (
                self.sb.table("candidate_findings")
                .select("candidate_id")
                .eq("session_id", session_id)
                .eq("candidate_id", candidate_id)
                .limit(1)
                .execute()
                .data
                or []
            )
        except Exception as exc:
            raise ValidationPersistenceError(
                f"Unable to verify candidate persistence: {type(exc).__name__}",
                candidate_id=candidate_id,
                details={"operation": "candidate_verify", "session_id": session_id},
            ) from exc
        if not rows:
            raise ValidationPersistenceError(
                "Candidate upsert completed without a durable candidate row.",
                candidate_id=candidate_id,
                details={"operation": "candidate_verify", "session_id": session_id},
            )

    def _promote_candidate(self, session_id: str, candidate_id: str) -> None:
        try:
            (
                self.sb.table("candidate_findings")
                .update({"status": "validated"})
                .eq("session_id", session_id)
                .eq("candidate_id", candidate_id)
                .execute()
            )
            rows = (
                self.sb.table("candidate_findings")
                .select("candidate_id,status")
                .eq("session_id", session_id)
                .eq("candidate_id", candidate_id)
                .limit(1)
                .execute()
                .data
                or []
            )
            if not rows or rows[0].get("status") != "validated":
                raise ValidationStatusIntegrityError(
                    "Candidate status promotion was not durably confirmed.",
                    candidate_id=candidate_id,
                    details={"operation": "candidate_status_verify"},
                )
        except ValidationStatusIntegrityError:
            raise
        except Exception as exc:
            raise ValidationPersistenceError(
                f"Unable to promote candidate after validation: {type(exc).__name__}",
                candidate_id=candidate_id,
                details={"operation": "candidate_status_update", "session_id": session_id},
            ) from exc

    def _flush_pending_v2_validations(
        self,
        candidate_id_map: Dict[str, str],
        *,
        session_id: str = "",
    ) -> None:
        scopes = [session_id]
        if "" not in scopes:
            # Backward-compatible unscoped batches can only be flushed after
            # the current persist call has made their candidate durable.
            scopes.append("")
        repository = DetectionValidationRepository(self.sb)
        for scope in scopes:
            pending = self._pending_v2_validations.pop(scope, [])
            still_pending: list[tuple[list, list]] = []
            for traces, decisions in pending:
                remapped_traces = []
                remapped_decisions = []
                for trace, decision in zip(traces, decisions):
                    stored_id = candidate_id_map.get(decision.candidate_id, decision.candidate_id)
                    if stored_id == decision.candidate_id:
                        remapped_traces.append(trace)
                        remapped_decisions.append(decision)
                        continue
                    remapped_decisions.append(decision.model_copy(update={"candidate_id": stored_id}))
                    remapped_traces.append(
                        trace.model_copy(
                            update={
                                "candidate_id": stored_id,
                                "context": trace.context.model_copy(update={"candidate_id": stored_id}),
                            }
                        )
                    )
                # Do not attempt the batch merely because another candidate
                # was persisted. Every candidate FK must be durable and,
                # where known, owned by the same session.
                candidate_ready = True
                for decision in remapped_decisions:
                    query = (
                        self.sb.table("candidate_findings")
                        .select("candidate_id,session_id")
                        .eq("candidate_id", decision.candidate_id)
                        .limit(1)
                    )
                    rows = query.execute().data or []
                    if not rows:
                        candidate_ready = False
                        break
                    if scope and str(rows[0].get("session_id") or "") != str(scope):
                        candidate_ready = False
                        break
                if not candidate_ready:
                    still_pending.append((traces, decisions))
                    continue
                repository.save_traces(remapped_traces, remapped_decisions)
            if still_pending:
                self._pending_v2_validations[scope] = still_pending

    def persist_v2_validation_traces(
        self,
        traces: list,
        decisions: list,
        *,
        session_id: str = "",
    ) -> None:
        """Persist the authoritative V2 validation trace for live tool runs.

        The legacy validation rows remain for compatibility, but they are not
        sufficient to audit the current validator.  Keeping this write behind
        an explicit method lets callers fail closed when the V2 migration is
        unavailable instead of silently reporting an untraceable decision.
        """
        traces = list(traces)
        decisions = list(decisions)
        if len(traces) != len(decisions):
            raise ValidationPersistenceError(
                "Validation trace and decision batches must have equal length.",
                details={"trace_count": len(traces), "decision_count": len(decisions)},
            )
        if not traces:
            return
        # If the caller is revalidating an already-persisted candidate, write
        # immediately.  The normal tool-run path has new candidates and is
        # deferred until persist() has written them.
        try:
            candidate_rows = []
            for decision in decisions:
                query = (
                    self.sb.table("candidate_findings")
                    .select("candidate_id,session_id")
                    .eq("candidate_id", decision.candidate_id)
                    .limit(1)
                )
                rows = query.execute().data or []
                if rows and session_id and str(rows[0].get("session_id") or "") != str(session_id):
                    raise ValidationPersistenceError(
                        "Validation candidate belongs to a different session.",
                        candidate_id=decision.candidate_id,
                        details={"operation": "validation_candidate_session_ownership", "session_id": session_id},
                    )
                candidate_rows.append(rows)
        except Exception as exc:
            if isinstance(exc, ValidationPersistenceError):
                raise
            raise ValidationPersistenceError(
                f"Unable to determine candidate persistence state: {type(exc).__name__}",
                details={"operation": "candidate_preflight"},
            ) from exc
        if all(candidate_rows):
            DetectionValidationRepository(self.sb).save_traces(traces, decisions)
            return
        self._pending_v2_validations.setdefault(session_id, []).append((traces, decisions))

    def list_runs(self, session_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        return self.sb.table("tool_runs").select("*").eq("session_id", session_id).order("created_at", desc=True).limit(limit).execute().data or []

    def list_candidates(self, session_id: str, status: Optional[str] = None, limit: int = 100) -> list[Dict[str, Any]]:
        query = self.sb.table("candidate_findings").select("*").eq("session_id", session_id)
        if status:
            query = query.eq("status", status)
        return query.order("updated_at", desc=True).limit(limit).execute().data or []

    def has_durable_candidate_evidence(
        self,
        session_id: str,
        candidate_id: str,
        evidence_ids: list[str],
    ) -> bool:
        """Require candidate evidence to exist and belong to this session."""
        ids = {str(item) for item in evidence_ids if str(item)}
        if not candidate_id or not ids:
            return False
        candidate_rows = (
            self.sb.table("candidate_findings")
            .select("candidate_id,session_id")
            .eq("candidate_id", candidate_id)
            .limit(1)
            .execute()
            .data
            or []
        )
        if not candidate_rows or str(candidate_rows[0].get("session_id") or "") != str(session_id):
            return False
        links = (
            self.sb.table("candidate_evidence")
            .select("candidate_id,observation_id")
            .eq("candidate_id", candidate_id)
            .execute()
            .data
            or []
        )
        linked_ids = {str(row.get("observation_id") or "") for row in links}
        if not ids.issubset(linked_ids):
            return False
        observations = (
            self.sb.table("observations")
            .select("observation_id,session_id")
            .in_("observation_id", sorted(ids))
            .execute()
            .data
            or []
        )
        by_id = {str(row.get("observation_id") or ""): row for row in observations}
        return all(
            evidence_id in by_id
            and str(by_id[evidence_id].get("session_id") or "") == str(session_id)
            for evidence_id in ids
        )

    def get_candidate(self, session_id: str, candidate_id: str) -> Dict[str, Any]:
        rows = self.sb.table("candidate_findings").select("*").eq("session_id", session_id).eq("candidate_id", candidate_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Candidate finding not found.")
        return rows[0]

    def validations(self, session_id: str, candidate_id: str) -> list[Dict[str, Any]]:
        self.get_candidate(session_id, candidate_id)
        return self.sb.table("validation_runs").select("*, validation_checks(*)").eq("candidate_id", candidate_id).order("created_at", desc=True).execute().data or []

    def revalidate(self, session_id: str, candidate_id: str) -> Dict[str, Any]:
        candidate_row = self.get_candidate(session_id, candidate_id)
        links = self.sb.table("candidate_evidence").select("observation_id").eq("candidate_id", candidate_id).execute().data or []
        observations = []
        for link in links:
            rows = self.sb.table("observations").select("*").eq("observation_id", link["observation_id"]).limit(1).execute().data or []
            if rows:
                observations.append(ObservationV1(**rows[0]))
        candidate = CandidateFindingV1(**candidate_row)
        result = ToolResultV1(tool_name="revalidation", category="validation", target=candidate.target_url, observations=observations, candidate_findings=[candidate])
        decisions = validation_engine.validate(result)
        decision = decisions[0]
        # Revalidation must refresh the authoritative v2 trace as well as the
        # compatibility row. Without this, the report gate could accept an
        # old v2 validation after a fresh revalidation changed the evidence.
        v2_decisions = validation_engine_v2.validate(
            result,
            mode="autonomous",
            apply_status=True,
        )
        self.persist_v2_validation_traces(
            validation_engine_v2.last_traces,
            v2_decisions,
            session_id=session_id,
        )
        validation_id = f"val_{uuid.uuid4().hex}"
        DetectionValidationRepository(self.sb).save_legacy_decision(
            validation_run_id=validation_id,
            candidate_id=candidate_id,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            decision=decision.decision,
            score=decision.score,
            reason=decision.reason,
            checks=decision.checks,
        )
        if candidate.status == "validated":
            if not DetectionValidationRepository(self.sb).has_successful_canonical_validation(candidate_id):
                raise ValidationStatusIntegrityError(
                    "Revalidation produced no complete canonical v2 validation.",
                    candidate_id=candidate_id,
                    validation_run_id=validation_id,
                    details={"operation": "revalidation_promotion"},
                )
        updated = self.sb.table("candidate_findings").update({"status": candidate.status, "confidence_score": candidate.confidence_score, "confidence_reasons": candidate.confidence_reasons}).eq("session_id", session_id).eq("candidate_id", candidate_id).execute().data or []
        return {"candidate": updated[0] if updated else candidate.model_dump(), "validation": {"validation_run_id": validation_id, **decision.__dict__}}

    def review(self, session_id: str, candidate_id: str, decision: str, reason: str, reviewer: str = "api") -> Dict[str, Any]:
        if not reason.strip():
            raise ValueError("A review reason is required.")
        self.get_candidate(session_id, candidate_id)
        statuses = {"override_validate": "validated_override", "reject": "disproven", "return_to_validation": "validating"}
        if decision not in statuses:
            raise ValueError("Invalid review decision.")
        self.sb.table("finding_reviews").insert({"candidate_id": candidate_id, "decision": decision, "reason": reason[:4000], "reviewer": reviewer[:200]}).execute()
        rows = self.sb.table("candidate_findings").update({"status": statuses[decision]}).eq("session_id", session_id).eq("candidate_id", candidate_id).execute().data or []
        return rows[0] if rows else self.get_candidate(session_id, candidate_id)

    # Stage 11 durable chain/protocol persistence. These methods are additive
    # and deliberately kept in the structured repository so chain evidence and
    # candidate evidence share one persistence boundary.
    def save_chain_graph(self, session_id: str, graph: Dict[str, Any]) -> Dict[str, Any]:
        chain = dict(graph.get("chain") or {})
        if not chain.get("chain_id"):
            raise ValueError("Chain graph is missing chain_id.")
        chain_row = {
            "chain_id": chain["chain_id"], "session_id": session_id,
            "name": chain.get("name", "attack chain"), "current_version": chain.get("chain_version", 1),
            "status": chain.get("status", "proposed"), "validation_status": chain.get("validation_status", "inconclusive"),
            "validation_source": chain.get("validation_source", "machine"), "graph_digest": graph.get("graph_digest", chain.get("graph_digest", "")),
            "objective": chain.get("impact_objective", ""), "evidence_ids": chain.get("evidence_ids", []),
            "prerequisite_ids": chain.get("prerequisite_ids", []),
            "identity_ids": chain.get("identity_ids", []), "protocol_operation_ids": chain.get("protocol_operation_ids", []),
        }
        self.sb.table("attack_chains").upsert(chain_row, on_conflict="chain_id").execute()
        version = int(chain.get("chain_version", 1))
        self.sb.table("attack_chain_versions").upsert({
            "chain_version_id": f"{chain['chain_id']}_v{version}", "chain_id": chain["chain_id"],
            "session_id": session_id, "version": version, "graph_digest": chain.get("graph_digest", ""),
            "objective": chain.get("impact_objective", ""), "prerequisite_ids": chain.get("prerequisite_ids", []),
            "node_ids": chain.get("node_ids", []), "edge_ids": chain.get("edge_ids", []),
            "evidence_ids": chain.get("evidence_ids", []), "policy_version": "1.0",
        }, on_conflict="chain_version_id").execute()
        for node in graph.get("nodes", []):
            self.sb.table("attack_chain_nodes").upsert({"chain_id": chain["chain_id"], "chain_version": version, "session_id": session_id, **node}, on_conflict="node_id").execute()
        for edge in graph.get("edges", []):
            self.sb.table("attack_chain_edges").upsert({"chain_id": chain["chain_id"], "chain_version": version, "session_id": session_id, **edge}, on_conflict="edge_id").execute()
        for evidence_id in chain.get("evidence_ids", []):
            self.sb.table("chain_evidence_links").upsert({"chain_id": chain["chain_id"], "chain_version": version, "evidence_id": evidence_id, "role": "supporting"}, on_conflict="chain_id,chain_version,evidence_id,role").execute()
        return chain_row

    def list_chains(self, session_id: str, status: Optional[str] = None, limit: int = 100) -> list[Dict[str, Any]]:
        query = self.sb.table("attack_chains").select("*").eq("session_id", session_id)
        if status:
            query = query.eq("status", status)
        return query.order("updated_at", desc=True).limit(min(max(limit, 1), 200)).execute().data or []

    def get_chain(self, session_id: str, chain_id: str) -> Dict[str, Any]:
        rows = self.sb.table("attack_chains").select("*").eq("session_id", session_id).eq("chain_id", chain_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Attack chain not found.")
        chain = rows[0]
        version = int(chain.get("current_version", 1))
        version_rows = self.sb.table("attack_chain_versions").select("prerequisite_ids,node_ids,edge_ids,evidence_ids").eq("chain_id", chain_id).eq("version", version).limit(1).execute().data or []
        if version_rows:
            chain.update(version_rows[0])
        nodes = self.sb.table("attack_chain_nodes").select("*").eq("chain_id", chain_id).eq("chain_version", version).execute().data or []
        edges = self.sb.table("attack_chain_edges").select("*").eq("chain_id", chain_id).eq("chain_version", version).execute().data or []
        evaluations = self.sb.table("chain_evaluations").select("*").eq("chain_id", chain_id).order("created_at", desc=True).limit(20).execute().data or []
        return {"chain": chain, "nodes": nodes, "edges": edges, "evaluations": evaluations}

    def save_protocol_operations(self, session_id: str, operations: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        saved = []
        for operation in operations:
            row = {"session_id": session_id, **operation}
            result = self.sb.table("protocol_operations").upsert(row, on_conflict="operation_id").execute().data or []
            saved.append(result[0] if result else row)
        return saved

    def save_payload_proposal(self, session_id: str, proposal: Dict[str, Any]) -> Dict[str, Any]:
        row = {"session_id": session_id, **proposal}
        result = self.sb.table("payload_proposals").upsert(row, on_conflict="payload_id").execute().data or []
        return result[0] if result else row

    def list_payload_proposals(self, session_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        return (self.sb.table("payload_proposals").select("*").eq("session_id", session_id)
                .order("created_at", desc=True).limit(min(max(limit, 1), 200)).execute().data or [])

    def list_protocol_operations(self, session_id: str, protocol: Optional[str] = None, limit: int = 200) -> list[Dict[str, Any]]:
        query = self.sb.table("protocol_operations").select("*").eq("session_id", session_id)
        if protocol:
            query = query.eq("protocol", protocol)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute().data or []

    def save_protocol_comparison(self, session_id: str, comparison: SemanticComparisonV1 | Dict[str, Any], *, tool_run_id: str = "", job_id: str = "", attempt_id: str = "") -> Dict[str, Any]:
        payload = comparison.model_dump(mode="json") if isinstance(comparison, SemanticComparisonV1) else dict(comparison)
        payload.pop("schema_version", None)
        normalized_job_id = None
        if job_id:
            try:
                normalized_job_id = str(uuid.UUID(str(job_id)))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError("job_id must be a UUID when supplied.") from exc
        # Empty operation IDs are intentionally stored as NULL: the column is
        # an optional FK to a discovered operation, and an empty string would
        # turn a diagnostic-only comparison into a referential-integrity error.
        payload["operation_id"] = payload.get("operation_id") or None
        row = {"session_id": session_id, "tool_run_id": tool_run_id, "job_id": normalized_job_id, "attempt_id": attempt_id, **payload}
        result = self.sb.table("protocol_comparisons").insert(row).execute().data or []
        return result[0] if result else row

    def list_protocol_comparisons(self, session_id: str, protocol: Optional[str] = None, limit: int = 200) -> list[Dict[str, Any]]:
        query = self.sb.table("protocol_comparisons").select("*").eq("session_id", session_id)
        if protocol:
            query = query.eq("protocol", protocol)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute().data or []

    def save_chain_evaluation(self, session_id: str, evaluation: Dict[str, Any]) -> Dict[str, Any]:
        row = {"session_id": session_id, **evaluation}
        result = self.sb.table("chain_evaluations").insert(row).execute().data or []
        return result[0] if result else row

    def save_impact_plan(self, session_id: str, plan: Dict[str, Any]) -> Dict[str, Any]:
        row = {"session_id": session_id, **plan}
        result = self.sb.table("impact_proof_plans").upsert(row, on_conflict="plan_id").execute().data or []
        return result[0] if result else row

    # Stage 12 reasoning/report records. Trace tables are append-only; cycle
    # lifecycle itself is the only mutable record.
    def save_reasoning_result(self, session_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Persist one reasoning cycle as one auditable transaction boundary.

        Reasoning telemetry is acceptance-critical.  In particular, a model
        call that disappears because a migration is missing must not look like
        a successful deterministic cycle.  Every write therefore fails loud;
        the autonomous loop turns that exception into a partial job and
        exposes the exact table/code in its telemetry status.

        The writes remain idempotent (all records have stable conflict keys),
        so retrying a failed cycle is safe and does not duplicate traces.
        """
        def upsert(table: str, row: Dict[str, Any], **kwargs: Any) -> None:
            try:
                self.sb.table(table).upsert(row, **kwargs).execute()
            except Exception as exc:
                raise ReasoningPersistenceError(table, exc) from exc

        cycle_columns = {
            "cycle_id", "session_id", "job_id", "objective", "mode", "status",
            "snapshot_digest", "config_digest", "model_id", "prompt_version",
            "action_budget", "cycle_number", "max_cycles", "selected_action_ids",
            "hypothesis_ids", "evidence_gap_ids", "stop_condition_ids", "stop_reason",
            "input_digest", "output_digest", "created_at", "finished_at", "branch_ids",
            "current_branch_id", "search_strategy", "search_depth", "replan_count",
            "budget_snapshot",
        }
        cycle = {
            key: value
            for key, value in dict(result.get("cycle") or {}).items()
            if key in cycle_columns
        }
        cycle["session_id"] = session_id
        if not cycle.get("cycle_id"):
            raise ReasoningPersistenceError("reasoning_cycles", ValueError("missing cycle_id"))
        cycle["job_id"] = self._normalise_reasoning_job_id(cycle.get("job_id"), "reasoning_cycles")
        budget_snapshot = dict(cycle.get("budget_snapshot") or {})
        if cycle.get("action_budget") is None:
            cycle["action_budget"] = 0
            budget_snapshot.setdefault("action_budget_mode", "auto")
        if cycle.get("max_cycles") is None:
            cycle["max_cycles"] = 0
            budget_snapshot.setdefault("max_cycles_mode", "auto")
        cycle["budget_snapshot"] = budget_snapshot
        upsert("reasoning_cycles", cycle, on_conflict="cycle_id")
        self._verify_reasoning_row(
            "reasoning_cycles", "cycle_id", cycle.get("cycle_id"),
            expected={
                key: cycle.get(key)
                for key in ("session_id", "job_id", "status", "model_id", "action_budget", "max_cycles")
                if cycle.get(key) is not None
            },
        )
        counts = {"reasoning_cycles": 1}
        hypothesis_columns = {
            "hypothesis_id", "cycle_id", "session_id", "claim", "null_hypothesis",
            "status", "category", "target_url", "method", "parameter",
            "supporting_evidence_ids", "contradicting_evidence_ids",
            "required_evidence_roles", "evidence_gap_ids", "priority_score",
            "expected_information_gain", "confidence_score", "source", "fingerprint",
            "metadata",
            "parent_hypothesis_id", "branch_id", "assumptions", "expected_outcomes",
            "contradiction_ids", "alternative_strategy_ids", "search_depth", "freshness_boundary",
        }
        for item in result.get("hypotheses", []):
            row = {"session_id": session_id, **{key: value for key, value in dict(item).items() if key in hypothesis_columns}}
            upsert("reasoning_hypotheses", row, on_conflict="hypothesis_id,cycle_id", ignore_duplicates=True)
        counts["reasoning_hypotheses"] = len(result.get("hypotheses", []))
        action_columns = {
            "action_id", "cycle_id", "session_id", "action_type", "tool_name", "endpoint_ref",
            "hypothesis_id", "risk", "side_effect_class", "evidence_ids", "expected_evidence_roles",
            "requires_approval", "cleanup_ref", "expected_information_gain", "rationale", "status",
            "rejection_reason", "input_digest", "source", "metadata",
            "capability_id", "branch_id", "parent_action_id", "target_digest", "input_bindings",
            "expected_observation_kinds", "mutation_operator", "approval_digest", "budget_snapshot",
        }
        for item in result.get("actions", []):
            row = {"session_id": session_id, **{key: value for key, value in dict(item).items() if key in action_columns}}
            upsert("reasoning_actions", row, on_conflict="action_id", ignore_duplicates=True)
        counts["reasoning_actions"] = len(result.get("actions", []))
        gap_columns = {"gap_id", "cycle_id", "session_id", "hypothesis_id", "gap_type", "description", "required_role", "blocking", "status", "evidence_ids", "metadata"}
        for item in result.get("evidence_gaps", []):
            row = {"session_id": session_id, **{key: value for key, value in dict(item).items() if key in gap_columns}}
            upsert("reasoning_evidence_gaps", row, on_conflict="gap_id", ignore_duplicates=True)
        counts["reasoning_evidence_gaps"] = len(result.get("evidence_gaps", []))
        stop_columns = {"stop_condition_id", "cycle_id", "session_id", "kind", "triggered", "reason", "evidence_ids"}
        for item in result.get("stop_conditions", []):
            row = {"session_id": session_id, **{key: value for key, value in dict(item).items() if key in stop_columns}}
            upsert("reasoning_stop_conditions", row, on_conflict="stop_condition_id", ignore_duplicates=True)
        counts["reasoning_stop_conditions"] = len(result.get("stop_conditions", []))
        decision_columns = {"decision_id", "cycle_id", "session_id", "snapshot_digest", "selected_action_ids", "rejected_action_ids", "evidence_gap_ids", "stop_condition_ids", "rationale", "deterministic", "input_digest", "selected_branch_id", "score_breakdown", "rejected_alternatives", "replan_reason"}
        decision = dict(result.get("decision") or {})
        if decision:
            decision = {"session_id": session_id, **{key: value for key, value in decision.items() if key in decision_columns}}
            upsert("reasoning_decisions", decision, on_conflict="decision_id", ignore_duplicates=True)
        counts["reasoning_decisions"] = 1 if decision else 0
        trace_columns = {"trace_id", "cycle_id", "session_id", "model_id", "provider", "prompt_version", "raw_output_digest", "action", "valid", "rejection_reason", "hallucinated_reference", "unsafe_mutation", "invented_evidence", "unknown_tool", "unsupported_capability", "stale_context"}
        for item in result.get("model_traces", []):
            row = {"session_id": session_id, **{key: value for key, value in dict(item).items() if key in trace_columns}}
            upsert("model_action_traces", row, on_conflict="trace_id", ignore_duplicates=True)
            self._verify_reasoning_row(
                "model_action_traces", "trace_id", row.get("trace_id"),
                expected={
                    key: row.get(key)
                    for key in ("session_id", "cycle_id", "valid", "raw_output_digest", "rejection_reason")
                    if row.get(key) is not None
                },
            )
        counts["model_action_traces"] = len(result.get("model_traces", []))
        # Provider-call telemetry is part of the AI-native acceptance
        # contract, not an optional decoration.  A missing migration must be
        # visible as a failed/partial run rather than silently becoming zero
        # model calls in the scorecard.
        for item in result.get("model_calls", []):
            payload = item.model_dump(mode="json") if isinstance(item, ModelCallTraceV1) else dict(item)
            payload.pop("schema_version", None)
            row = {"session_id": session_id, **payload}
            row["job_id"] = self._normalise_reasoning_job_id(row.get("job_id"), "reasoning_model_calls")
            upsert("reasoning_model_calls", row, on_conflict="call_id", ignore_duplicates=True)
            self._verify_reasoning_row(
                "reasoning_model_calls", "call_id", row.get("call_id"),
                expected={
                    key: row.get(key)
                    for key in ("session_id", "cycle_id", "job_id", "status", "model_id", "provider", "attempt_number", "input_digest", "output_digest")
                    if row.get(key) is not None
                },
            )
        counts["reasoning_model_calls"] = len(result.get("model_calls", []))
        for item in result.get("branches", []):
            row = {"session_id": session_id, **dict(item)}
            row.pop("schema_version", None)
            upsert("reasoning_branches", row, on_conflict="branch_id", ignore_duplicates=True)
        counts["reasoning_branches"] = len(result.get("branches", []))
        for item in result.get("branch_transitions", []):
            row = {"session_id": session_id, **dict(item)}
            row.pop("schema_version", None)
            upsert("reasoning_branch_transitions", row, on_conflict="transition_id", ignore_duplicates=True)
        counts["reasoning_branch_transitions"] = len(result.get("branch_transitions", []))
        adaptation = dict(result.get("adaptation") or {})
        if adaptation:
            adaptation = {"session_id": session_id, **adaptation}
            adaptation.pop("schema_version", None)
            upsert("reasoning_adaptations", adaptation, on_conflict="adaptation_id", ignore_duplicates=True)
        counts["reasoning_adaptations"] = 1 if adaptation else 0
        child_specs = (
            ("reasoning_hypotheses", "hypothesis_id", result.get("hypotheses", [])),
            ("reasoning_actions", "action_id", result.get("actions", [])),
            ("reasoning_evidence_gaps", "gap_id", result.get("evidence_gaps", [])),
            ("reasoning_stop_conditions", "stop_condition_id", result.get("stop_conditions", [])),
            ("reasoning_decisions", "decision_id", [decision] if decision else []),
            ("reasoning_branches", "branch_id", result.get("branches", [])),
            ("reasoning_branch_transitions", "transition_id", result.get("branch_transitions", [])),
            ("reasoning_adaptations", "adaptation_id", [adaptation] if adaptation else []),
        )
        for table, key, expected_rows in child_specs:
            if expected_rows:
                self._verify_reasoning_children(
                    table,
                    key,
                    str(cycle.get("cycle_id") or ""),
                    expected_rows,
                )
        if result.get("actions"):
            self._verify_reasoning_action_children(
                session_id=session_id,
                cycle_id=str(cycle.get("cycle_id") or ""),
                expected_rows=result.get("actions", []),
            )
        return {**cycle, "_persistence": {"attempted": counts, "strict": True}}

    def _verify_reasoning_children(
        self,
        table: str,
        key: str,
        cycle_id: str,
        expected_rows: list,
    ) -> None:
        """Confirm every child trace for a cycle is queryable after write."""
        expected_ids = {
            str((item.model_dump(mode="json") if hasattr(item, "model_dump") else item).get(key) or "")
            for item in expected_rows
        }
        expected_ids.discard("")
        if not expected_ids:
            raise ReasoningPersistenceError(table, ValueError(f"missing {key}"))
        try:
            rows = (
                self.sb.table(table)
                .select(f"{key},cycle_id")
                .eq("cycle_id", cycle_id)
                .execute()
                .data
                or []
            )
        except Exception as exc:
            raise ReasoningPersistenceError(table, exc) from exc
        actual_ids = {str(row.get(key) or "") for row in rows}
        missing = sorted(expected_ids - actual_ids)
        if missing:
            raise ReasoningPersistenceError(
                table,
                RuntimeError(f"durable child read-back missing {key}: {', '.join(missing[:8])}"),
            )

    def _verify_reasoning_action_children(
        self,
        *,
        session_id: str,
        cycle_id: str,
        expected_rows: list,
    ) -> None:
        """Verify model-action state and tool-dispatch linkage after write."""
        expected_by_id = {}
        for item in expected_rows:
            value = item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item)
            action_id = str(value.get("action_id") or "")
            if action_id:
                expected_by_id[action_id] = value
        if not expected_by_id:
            raise ReasoningPersistenceError("reasoning_actions", ValueError("missing action_id"))
        try:
            rows = (
                self.sb.table("reasoning_actions")
                .select("action_id,cycle_id,session_id,action_type,status,metadata")
                .eq("cycle_id", cycle_id)
                .execute()
                .data
                or []
            )
        except Exception as exc:
            raise ReasoningPersistenceError("reasoning_actions", exc) from exc
        actual_by_id = {
            str(row.get("action_id") or ""): row
            for row in rows
            if row.get("action_id")
        }
        missing = sorted(set(expected_by_id) - set(actual_by_id))
        if missing:
            raise ReasoningPersistenceError(
                "reasoning_actions",
                RuntimeError(f"durable action read-back missing action_id: {', '.join(missing[:8])}"),
            )
        for action_id, expected in expected_by_id.items():
            actual = actual_by_id[action_id]
            if actual.get("session_id") != session_id or actual.get("cycle_id") != cycle_id:
                raise ReasoningPersistenceError(
                    "reasoning_actions",
                    RuntimeError("durable action read-back session/cycle mismatch"),
                )
            if actual.get("status") != expected.get("status"):
                raise ReasoningPersistenceError(
                    "reasoning_actions",
                    RuntimeError("durable action read-back status mismatch"),
                )
            expected_metadata = dict(expected.get("metadata") or {})
            actual_metadata = dict(actual.get("metadata") or {})
            expected_outcome = expected_metadata.get("dispatch_outcome")
            actual_outcome = actual_metadata.get("dispatch_outcome")
            if expected_outcome is not None and actual_outcome != expected_outcome:
                raise ReasoningPersistenceError(
                    "reasoning_actions",
                    RuntimeError("durable action read-back dispatch outcome mismatch"),
                )
            if (
                bool(expected_metadata.get("ai_dispatch_expected"))
                and not isinstance(actual_outcome, dict)
            ):
                raise ReasoningPersistenceError(
                    "reasoning_actions",
                    RuntimeError("dispatchable model action has no durable dispatch outcome"),
                )

    @staticmethod
    def _normalise_reasoning_job_id(value: Any, table: str) -> Optional[str]:
        """Normalize public job identifiers for UUID-backed audit columns."""
        if value in (None, ""):
            return None
        text = str(value)
        candidate = text[4:] if text.startswith("job_") else text
        try:
            return str(uuid.UUID(candidate))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ReasoningPersistenceError(
                table,
                ValueError("job_id must be a UUID or job_<uuid>"),
            ) from exc

    def _verify_reasoning_row(
        self,
        table: str,
        key: str,
        value: Any,
        *,
        expected: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Confirm an acceptance-critical reasoning write is queryable now."""
        if not value:
            raise ReasoningPersistenceError(table, ValueError(f"missing {key}"))
        try:
            selected_columns = list(dict.fromkeys([key, *(expected or {}).keys()]))
            rows = (
                self.sb.table(table)
                .select(",".join(selected_columns))
                .eq(key, value)
                .limit(1)
                .execute()
                .data
                or []
            )
        except Exception as exc:
            raise ReasoningPersistenceError(table, exc) from exc
        if not rows:
            raise ReasoningPersistenceError(
                table,
                RuntimeError(f"durable read-back returned no {key}={value}"),
            )
        row = rows[0]
        for field, expected_value in (expected or {}).items():
            if field not in row or row.get(field) != expected_value:
                raise ReasoningPersistenceError(
                    table,
                    RuntimeError(
                        f"durable read-back mismatch for {field}: "
                        f"expected={expected_value!r} actual={row.get(field)!r}"
                    ),
                )

    def list_reasoning_cycles(self, session_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        return (self.sb.table("reasoning_cycles").select("*").eq("session_id", session_id)
                .order("created_at", desc=True).limit(min(max(limit, 1), 200)).execute().data or [])

    def get_reasoning_cycle(self, session_id: str, cycle_id: str) -> Dict[str, Any]:
        rows = self.sb.table("reasoning_cycles").select("*").eq("session_id", session_id).eq("cycle_id", cycle_id).limit(1).execute().data or []
        if not rows:
            raise ValueError("Reasoning cycle not found.")
        cycle = rows[0]
        return {
            "cycle": cycle,
            "hypotheses": self.sb.table("reasoning_hypotheses").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "actions": self.sb.table("reasoning_actions").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "evidence_gaps": self.sb.table("reasoning_evidence_gaps").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "stop_conditions": self.sb.table("reasoning_stop_conditions").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "decisions": self.sb.table("reasoning_decisions").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "model_traces": self.sb.table("model_action_traces").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "model_calls": self._list_reasoning_model_calls(cycle_id),
            "branches": self.sb.table("reasoning_branches").select("*").eq("cycle_id", cycle_id).execute().data or [],
            "branch_transitions": self.sb.table("reasoning_branch_transitions").select("*").eq("cycle_id", cycle_id).order("created_at").execute().data or [],
            "adaptations": self.sb.table("reasoning_adaptations").select("*").eq("cycle_id", cycle_id).execute().data or [],
        }

    def _list_reasoning_model_calls(self, cycle_id: str) -> list[Dict[str, Any]]:
        try:
            return self.sb.table("reasoning_model_calls").select("*").eq("cycle_id", cycle_id).order("created_at").execute().data or []
        except Exception as exc:
            raise RuntimeError(
                f"reasoning retrieval failed at reasoning_model_calls: {type(exc).__name__}: {exc}"
            ) from exc

    def list_reasoning_branches(self, session_id: str, cycle_id: Optional[str] = None, limit: int = 200) -> list[Dict[str, Any]]:
        query = self.sb.table("reasoning_branches").select("*").eq("session_id", session_id)
        if cycle_id:
            query = query.eq("cycle_id", cycle_id)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 500)).execute().data or []

    def save_report_narrative(self, session_id: str, narrative: Dict[str, Any], claims: list[Dict[str, Any]]) -> Dict[str, Any]:
        row = {"session_id": session_id, **dict(narrative)}
        row.pop("schema_version", None)
        self.sb.table("report_narratives").upsert(row, on_conflict="report_id", ignore_duplicates=True).execute()
        stored_narratives = (
            self.sb.table("report_narratives")
            .select("report_id,session_id,target,objective,status,finding_ids,claim_ids,markdown,grounding_complete,redaction_leaks,source_digest")
            .eq("report_id", row["report_id"])
            .eq("session_id", session_id)
            .limit(2)
            .execute()
            .data
            or []
        )
        if len(stored_narratives) != 1:
            raise ReasoningPersistenceError(
                "report_narratives",
                RuntimeError("report narrative upsert was not durably confirmed"),
            )
        stored_narrative = stored_narratives[0]
        narrative_fields = (
            "report_id", "session_id", "target", "objective", "status",
            "finding_ids", "claim_ids", "markdown", "grounding_complete",
            "redaction_leaks", "source_digest",
        )
        if any(stored_narrative.get(field) != row.get(field) for field in narrative_fields):
            raise ReasoningPersistenceError(
                "report_narratives",
                RuntimeError("report narrative readback mismatch"),
            )
        for claim in claims:
            claim_row = {"session_id": session_id, **dict(claim)}
            claim_row.pop("schema_version", None)
            self.sb.table("report_claims").upsert(claim_row, on_conflict="claim_id", ignore_duplicates=True).execute()
            for evidence_id in claim.get("evidence_ids", []):
                self.sb.table("report_claim_evidence").upsert({"claim_id": claim["claim_id"], "evidence_id": evidence_id, "role": "supporting"}, on_conflict="claim_id,evidence_id,role", ignore_duplicates=True).execute()
            stored_claims = (
                self.sb.table("report_claims")
                .select("claim_id,report_id,session_id,claim_type,text,source_candidate_ids,evidence_ids,policy_versions,validated,override,grounded,metadata")
                .eq("claim_id", claim_row["claim_id"])
                .eq("session_id", session_id)
                .limit(2)
                .execute()
                .data
                or []
            )
            if len(stored_claims) != 1:
                raise ReasoningPersistenceError(
                    "report_claims",
                    RuntimeError("report claim upsert was not durably confirmed"),
                )
            stored_claim = stored_claims[0]
            claim_fields = (
                "claim_id", "report_id", "session_id", "claim_type", "text",
                "source_candidate_ids", "evidence_ids", "policy_versions",
                "validated", "override", "grounded", "metadata",
            )
            if any(stored_claim.get(field) != claim_row.get(field) for field in claim_fields):
                raise ReasoningPersistenceError(
                    "report_claims",
                    RuntimeError("report claim readback mismatch"),
                )
            expected_links = {
                (str(claim["claim_id"]), str(evidence_id), "supporting")
                for evidence_id in claim.get("evidence_ids", [])
            }
            stored_links = (
                self.sb.table("report_claim_evidence")
                .select("claim_id,evidence_id,role")
                .eq("claim_id", claim["claim_id"])
                .execute()
                .data
                or []
            )
            actual_links = {
                (str(item.get("claim_id") or ""), str(item.get("evidence_id") or ""), str(item.get("role") or ""))
                for item in stored_links
            }
            if actual_links != expected_links:
                raise ReasoningPersistenceError(
                    "report_claim_evidence",
                    RuntimeError("report claim evidence readback mismatch"),
                )
        return row

    def list_report_claims(self, session_id: str, report_id: Optional[str] = None, limit: int = 500) -> list[Dict[str, Any]]:
        query = self.sb.table("report_claims").select("*").eq("session_id", session_id)
        if report_id:
            query = query.eq("report_id", report_id)
        return query.order("created_at", desc=True).limit(min(max(limit, 1), 1000)).execute().data or []

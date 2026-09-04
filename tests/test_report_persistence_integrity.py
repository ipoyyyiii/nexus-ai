from __future__ import annotations

import pytest

from core.structured_repository import ReasoningPersistenceError, StructuredRepository


class _Response:
    def __init__(self, data=None):
        self.data = data or []


class _Query:
    CONFLICT_KEYS = {
        "report_narratives": ("report_id",),
        "report_claims": ("claim_id",),
        "report_claim_evidence": ("claim_id", "evidence_id", "role"),
    }

    def __init__(self, database, table_name):
        self.database = database
        self.table_name = table_name
        self.operation = "select"
        self.payload = None
        self.filters = {}
        self.row_limit = None

    def select(self, *_args, **_kwargs):
        self.operation = "select"
        return self

    def eq(self, key, value):
        self.filters[key] = value
        return self

    def limit(self, value):
        self.row_limit = value
        return self

    def upsert(self, row, **kwargs):
        self.operation = "upsert"
        self.payload = dict(row)
        self.ignore_duplicates = bool(kwargs.get("ignore_duplicates"))
        return self

    def execute(self):
        rows = self.database.setdefault(self.table_name, [])
        if self.operation == "select":
            selected = [
                dict(row)
                for row in rows
                if all(row.get(key) == value for key, value in self.filters.items())
            ]
            if self.row_limit is not None:
                selected = selected[: self.row_limit]
            return _Response(selected)

        payload = dict(self.payload or {})
        keys = self.CONFLICT_KEYS.get(self.table_name, ())
        existing = next(
            (
                row for row in rows
                if keys and all(row.get(key) == payload.get(key) for key in keys)
            ),
            None,
        )
        if existing is None:
            rows.append(payload)
        elif not getattr(self, "ignore_duplicates", False):
            existing.update(payload)
        return _Response([payload])


class _Supabase:
    def __init__(self):
        self.records = {}

    def table(self, table_name):
        return _Query(self.records, table_name)


class _Store:
    def __init__(self):
        self.sb = _Supabase()


def _report_rows():
    narrative = {
        "report_id": "report-1",
        "session_id": "session-1",
        "target": "http://fixture.local",
        "objective": "evaluate fixture",
        "status": "ready",
        "finding_ids": ["candidate-1"],
        "claim_ids": ["claim-1"],
        "markdown": "# Report",
        "grounding_complete": True,
        "redaction_leaks": 0,
        "source_digest": "source-digest",
    }
    claim = {
        "claim_id": "claim-1",
        "report_id": "report-1",
        "session_id": "session-1",
        "claim_type": "finding",
        "text": "The fixture exposes a validated issue.",
        "source_candidate_ids": ["candidate-1"],
        "evidence_ids": ["observation-1"],
        "policy_versions": {"validator": "2.0"},
        "validated": True,
        "override": False,
        "grounded": True,
        "metadata": {},
    }
    return narrative, claim


def test_report_persistence_requires_exact_narrative_claim_and_evidence_readback():
    store = _Store()
    narrative, claim = _report_rows()

    persisted = StructuredRepository(store).save_report_narrative(
        "session-1",
        narrative,
        [claim],
    )

    assert persisted["report_id"] == "report-1"
    assert store.sb.records["report_claim_evidence"] == [{
        "claim_id": "claim-1",
        "evidence_id": "observation-1",
        "role": "supporting",
    }]


def test_report_persistence_rejects_stale_append_only_narrative():
    store = _Store()
    narrative, claim = _report_rows()
    store.sb.records["report_narratives"] = [{**narrative, "markdown": "# stale"}]

    with pytest.raises(ReasoningPersistenceError, match="report narrative readback mismatch"):
        StructuredRepository(store).save_report_narrative(
            "session-1",
            narrative,
            [claim],
        )

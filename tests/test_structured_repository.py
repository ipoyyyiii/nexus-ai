from __future__ import annotations

from core.structured_contract import CandidateFindingV1, ObservationV1, ToolResultV1
from core.structured_repository import StructuredRepository


class _Response:
    def __init__(self, data=None):
        self.data = data or []


class _Query:
    def __init__(self, database, table_name):
        self.database = database
        self.table_name = table_name
        self.operation = ""
        self.row = None
        self.filters = {}

    def select(self, *_args, **_kwargs):
        self.operation = "select"
        return self

    def eq(self, *_args, **_kwargs):
        if len(_args) >= 2:
            self.filters[_args[0]] = _args[1]
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def upsert(self, row, **_kwargs):
        self.operation = "upsert"
        self.row = dict(row)
        self.database.setdefault(self.table_name, []).append(self.row)
        return self

    def insert(self, row, **_kwargs):
        self.operation = "insert"
        self.row = dict(row)
        self.database.setdefault(self.table_name, []).append(self.row)
        return self

    def update(self, row, **_kwargs):
        self.operation = "update"
        self.row = dict(row)
        return self

    def execute(self):
        if self.operation == "select":
            rows = self.database.get(self.table_name, [])
            rows = [
                row for row in rows
                if all(row.get(key) == value for key, value in self.filters.items())
            ]
            return _Response(rows[:1])
        if self.operation == "update":
            for row in self.database.get(self.table_name, []):
                if all(row.get(key) == value for key, value in self.filters.items()):
                    row.update(self.row or {})
            return _Response(self.database.get(self.table_name, []))
        return _Response([])


class _Supabase:
    def __init__(self):
        self.records = {}

    def table(self, table_name):
        return _Query(self.records, table_name)


class _Store:
    def __init__(self):
        self.sb = _Supabase()


def test_candidate_persistence_normalizes_observation_links():
    store = _Store()
    result = ToolResultV1(
        tool_name="legacy_detector",
        target="http://fixture.local/login",
        observations=[
            ObservationV1(
                observation_id="obs-test",
                role="test",
                target_url="http://fixture.local/login",
            )
        ],
        candidate_findings=[
            CandidateFindingV1(
                candidate_id="cand-test",
                title="Open redirect candidate",
                vuln_type="open_redirect",
                target_url="http://fixture.local/login",
                observation_ids=["obs-test"],
            )
        ],
    )

    StructuredRepository(store).persist("session-test", result)

    candidate_row = store.sb.records["candidate_findings"][0]
    assert "observation_ids" not in candidate_row
    assert candidate_row["metadata"]["evidence_ids"] == ["obs-test"]
    assert store.sb.records["candidate_evidence"] == [
        {"candidate_id": "cand-test", "observation_id": "obs-test"}
    ]

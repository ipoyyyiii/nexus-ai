from pathlib import Path

import pytest

from core.schema_readiness import Phase1SchemaNotReadyError, verify_phase1_acceptance_schema


ROOT = Path(__file__).resolve().parents[1]


def test_phase1_schema_marker_requires_both_integrity_migrations():
    sql = (ROOT / "migrations" / "025_phase1_acceptance_schema_marker.sql").read_text(encoding="utf-8")
    assert "reasoning_model_calls" in sql
    assert "candidate_validation_integrity" in sql
    assert "validation_run_integrity" in sql
    assert "nexus_schema_migrations" in sql
    assert "pg_get_functiondef" in sql
    assert "pg_get_triggerdef" in sql
    assert "tgenabled" in sql
    assert "md5(" in sql


def test_readiness_requires_marker_checks_in_api():
    source = (ROOT / "api.py").read_text(encoding="utf-8")
    assert '"phase1_acceptance_schema"' in source
    assert "verify_phase1_acceptance_schema" in source


class _Response:
    def __init__(self, data):
        self.data = data


class _Query:
    def __init__(self, table, rows):
        self.table = table
        self.rows = rows

    def select(self, *_args, **_kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def in_(self, *_args, **_kwargs):
        return self

    def execute(self):
        return _Response(self.rows.get(self.table, []))


class _Supabase:
    def __init__(self, rows):
        self.rows = rows

    def table(self, name):
        return _Query(name, self.rows)

    def rpc(self, name, _params):
        return _Query(name, self.rows)


def test_phase1_schema_readiness_accepts_verified_marker_set():
    rows = {
        "nexus_schema_migrations": [
            {"migration_id": "023_reasoning_model_calls", "checksum": "md5-023"},
            {"migration_id": "024_candidate_validation_integrity", "checksum": "md5-024"},
        ],
        "nexus_phase1_acceptance_status": [{"ready": True, "missing": []}],
    }
    result = verify_phase1_acceptance_schema(_Supabase(rows))
    assert result["markers"]["024_candidate_validation_integrity"] == "md5-024"


def test_phase1_schema_readiness_rejects_missing_marker():
    with pytest.raises(Phase1SchemaNotReadyError, match="marker"):
        verify_phase1_acceptance_schema(_Supabase({
            "nexus_schema_migrations": [
                {"migration_id": "023_reasoning_model_calls", "checksum": "md5-023"},
            ]
        }))

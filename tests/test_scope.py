from types import SimpleNamespace

from core.scope import validate_target


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def select(self, _columns):
        return self

    def eq(self, _column, value):
        self.rows = [row for row in self.rows if row.get("session_id") == value]
        return self

    def limit(self, _count):
        return self

    def execute(self):
        return SimpleNamespace(data=self.rows)


class _Supabase:
    def __init__(self):
        self.tables = {
            "scope_rules": [],
            "session_context": [
                {
                    "session_id": "session-a",
                    "scope_rules": [{
                        "pattern": "10.1.2.3",
                        "rule_type": "allow",
                        "allow_private": True,
                    }],
                },
                {
                    "session_id": "session-b",
                    "scope_rules": [{
                        "pattern": "10.9.8.7",
                        "rule_type": "allow",
                        "allow_private": True,
                    }],
                },
            ],
        }

    def table(self, name):
        return _Query(list(self.tables[name]))


def test_scope_validation_isolated_to_requested_session():
    supabase = _Supabase()

    allowed, _ = validate_target(
        "http://10.1.2.3:8080/", supabase, session_id="session-a",
    )
    assert allowed is True

    leaked, reason = validate_target(
        "http://10.9.8.7:8080/", supabase, session_id="session-a",
    )
    assert leaked is False
    assert "not match" in reason

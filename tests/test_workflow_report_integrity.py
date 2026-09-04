from core.workflow_models import WorkflowState
from core.workflow_models import FindingRecord
from core.workflow_report import WorkflowReport


class _Sessions:
    def __init__(self, state=None):
        self._state = state or WorkflowState()

    def require(self, _session_id):
        return {"target_url": "http://fixture.local", "attack_goal": "find issues"}

    def load_state(self, _session_id):
        return type("State", (), {"workflow": self._state})()


class _Structured:
    sb = object()

    def __init__(self, candidates=None):
        self._candidates = candidates or []

    def list_candidates(self, _session_id):
        return list(self._candidates)

    def has_durable_candidate_evidence(self, _session_id, _candidate_id, evidence_ids):
        return bool(evidence_ids)

    def has_successful_canonical_validation(self, _candidate_id):
        return True


class _FakeAppendOnlyReportRepository:
    """Minimal report-claim repository with the production conflict behavior."""

    def __init__(self):
        self.claims = []

    def save_report_narrative(self, _session_id, _narrative, claims):
        for claim in claims:
            if not any(row["claim_id"] == claim["claim_id"] for row in self.claims):
                self.claims.append(dict(claim))


def test_report_never_promotes_status_only_historical_candidate(monkeypatch):
    monkeypatch.setattr(
        "core.workflow_report.StructuredRepository",
        lambda _sessions: _Structured([{
            "candidate_id": "candidate-historical",
            "status": "validated",
            "title": "Historical status-only row",
            "vuln_type": "xss",
            "severity": "high",
            "metadata": {"evidence_ids": ["obs-1"]},
        }]),
    )
    monkeypatch.setattr(
        "core.workflow_report.DetectionValidationRepository.has_successful_validation",
        lambda _self, _candidate_id: False,
    )

    report = WorkflowReport(_Sessions()).generate("session-1")

    assert "No validated findings recorded." in report["markdown"]
    assert report["claims"] == []
    assert report["report_quality"]["status"] == "review_required"
    assert report["narrative"]["status"] == "blocked"


def test_repeated_generation_keeps_candidate_and_legacy_claim_ids(monkeypatch):
    candidate = {
        "candidate_id": "candidate-1",
        "status": "validated_override",
        "title": "Header disclosure",
        "vuln_type": "information_disclosure",
        "severity": "low",
        "metadata": {"evidence_ids": ["obs-candidate"]},
    }
    legacy = FindingRecord(
        finding_id="legacy-finding-1",
        title="Legacy finding",
        vuln_type="xss",
        severity="medium",
        status="validated",
        evidence_ids=["obs-legacy"],
    )
    state = WorkflowState(findings=[legacy])
    structured = _Structured([candidate])
    monkeypatch.setattr(
        "core.workflow_report.StructuredRepository",
        lambda _sessions: structured,
    )
    monkeypatch.setattr(
        "core.workflow_report.DetectionValidationRepository.has_successful_canonical_validation",
        lambda _self, _candidate_id: True,
    )

    generator = WorkflowReport(_Sessions(state))
    first = generator.generate("session-1")
    second = generator.generate("session-1")

    first_claim_ids = [claim["claim_id"] for claim in first["claims"]]
    second_claim_ids = [claim["claim_id"] for claim in second["claims"]]
    assert first["narrative"]["report_id"] == second["narrative"]["report_id"]
    assert first_claim_ids == second_claim_ids
    assert len(first_claim_ids) == 2
    assert len(set(first_claim_ids)) == 2


def test_repeated_generation_does_not_duplicate_logical_claims_in_append_only_repository(monkeypatch):
    candidate = {
        "candidate_id": "candidate-1",
        "status": "validated_override",
        "title": "Header disclosure",
        "vuln_type": "information_disclosure",
        "severity": "low",
        "metadata": {"evidence_ids": ["obs-candidate"]},
    }
    legacy = FindingRecord(
        finding_id="legacy-finding-1",
        title="Legacy finding",
        vuln_type="xss",
        severity="medium",
        status="validated",
        evidence_ids=["obs-legacy"],
    )
    structured = _Structured([candidate])
    monkeypatch.setattr(
        "core.workflow_report.StructuredRepository",
        lambda _sessions: structured,
    )
    monkeypatch.setattr(
        "core.workflow_report.DetectionValidationRepository.has_successful_canonical_validation",
        lambda _self, _candidate_id: True,
    )

    generator = WorkflowReport(_Sessions(WorkflowState(findings=[legacy])))
    repository = _FakeAppendOnlyReportRepository()
    for _ in range(3):
        report = generator.generate("session-1")
        repository.save_report_narrative(
            "session-1",
            report["narrative"],
            report["claims"],
        )

    assert len(repository.claims) == 2
    logical_claims = {
        (row["report_id"], row["claim_id"])
        for row in repository.claims
    }
    assert len(logical_claims) == len(repository.claims)

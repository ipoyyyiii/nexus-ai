from pathlib import Path

import pytest

from core.live_lab_matrix import LiveLabMatrixRunner


def test_manifest_has_the_five_authorized_lab_profiles(monkeypatch):
    monkeypatch.delenv("NEXUS_LAB_OWASP_BENCHMARK_URL", raising=False)
    profiles = LiveLabMatrixRunner().profiles()
    assert [item.profile_id for item in profiles] == [
        "juice-shop", "crapi", "webgoat", "dvwa", "owasp-benchmark",
    ]
    assert profiles[-1].configured is False
    assert profiles[2].probe_url == "http://host.docker.internal:8080/WebGoat/login"
    assert profiles[3].probe_url == "http://host.docker.internal:8081/login.php"


def test_live_matrix_uses_probe_results_and_does_not_claim_findings():
    def probe(profile):
        return {
            "profile_id": profile.profile_id,
            "name": profile.name,
            "status": "available",
            "http_status": 200,
            "surface_signals": ["forms", "api"],
            "finding_assertion": "none",
        }

    result = LiveLabMatrixRunner(probe=probe).run(["juice-shop", "dvwa"])
    assert result["release_gate"] == "ready"
    assert result["totals"] == {
        "profiles": 2,
        "configured": 2,
        "available": 2,
        "unavailable": 0,
        "blocked": 0,
        "not_configured": 0,
        "surface_signal_ready": 2,
    }
    assert all(item["finding_assertion"] == "none" for item in result["results"])


def test_external_target_is_blocked_before_probe(monkeypatch):
    monkeypatch.setenv("NEXUS_LAB_JUICE_SHOP_URL", "https://example.com")
    called = False

    def probe(_profile):
        nonlocal called
        called = True
        return {"status": "available"}

    result = LiveLabMatrixRunner(probe=probe).run(["juice-shop"])
    assert called is False
    assert result["results"][0]["status"] == "blocked"
    assert result["results"][0]["reason"] == "non_local_target"


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError, match="Unknown live-lab profile"):
        LiveLabMatrixRunner().profiles(["does-not-exist"])

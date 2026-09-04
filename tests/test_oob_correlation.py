from datetime import datetime, timedelta, timezone

from core.oob_correlation import correlate_interactions


def test_oob_correlation_requires_an_exact_token_and_expected_domain():
    result = correlate_interactions(
        "ssrf-ab12",
        [
            {"protocol": "http", "raw": "GET /ssrf-ab123.whoopbhapzham.my.id HTTP/1.1"},
            {"protocol": "http", "raw": "GET /ssrf-ab12.whoopbhapzham.my.id HTTP/1.1"},
        ],
        expected_domain="ssrf-ab12.whoopbhapzham.my.id",
    )

    assert result.status == "correlated"
    assert result.matched_count == 1
    assert result.target_attributed is True


def test_oob_correlation_rejects_stale_callbacks():
    issued = datetime.now(timezone.utc)
    result = correlate_interactions(
        "xxe-ab12",
        [{
            "timestamp": (issued - timedelta(minutes=5)).isoformat(),
            "q": "xxe-ab12.whoopbhapzham.my.id",
        }],
        expected_domain="xxe-ab12.whoopbhapzham.my.id",
        issued_at=issued,
    )

    assert result.status == "stale"
    assert result.stale_callback is True
    assert result.matched_count == 0


def test_oob_correlation_does_not_promote_an_unattributed_match():
    result = correlate_interactions(
        "ssrf-ab12",
        [{"q": "ssrf-ab12.other-domain.invalid"}],
        expected_domain="ssrf-ab12.whoopbhapzham.my.id",
    )

    assert result.status == "ambiguous"
    assert result.target_attributed is False

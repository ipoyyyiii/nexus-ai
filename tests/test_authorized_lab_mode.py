from core.authorized_lab_mode import allows_action, issue_preapproval


CONFIG = {
    "authorized_local_lab_mode": {
        "enabled": True,
        "allowed_origins": ["http://host.docker.internal:3001"],
        "allowed_risks": ["medium", "high"],
    }
}


def _approval(target="http://host.docker.internal:3001/"):
    return issue_preapproval(
        session_id="session-1",
        target=target,
        session_context={"authorization_confirmed": True},
        scan_config={"authorized_local_lab_mode": True},
        config=CONFIG,
    )


def test_preapproval_requires_authorized_exact_lab_origin():
    approved = _approval("http://host.docker.internal:3001/#/login")
    assert approved.approved is True
    assert approved.source == "session_authorization"
    assert approved.preapproval_id.startswith("labpre_")

    wrong_port = _approval("http://host.docker.internal:3002/")
    assert wrong_port.approved is False

    not_confirmed = issue_preapproval(
        session_id="session-1",
        target="http://host.docker.internal:3001/",
        session_context={"authorization_confirmed": False},
        scan_config={"authorized_local_lab_mode": True},
        config=CONFIG,
    )
    assert not_confirmed.approved is False


def test_preapproval_allows_bounded_action_and_blocks_destructive_action():
    approval = _approval()
    assert allows_action(
        target="http://host.docker.internal:3001/",
        action="SQL injection scan on http://host.docker.internal:3001/rest/products",
        context_text="Harmless differential payloads",
        risk="high",
        preapproval=approval,
        config=CONFIG,
    )
    assert not allows_action(
        target="http://host.docker.internal:3001/",
        action="Delete test account at http://host.docker.internal:3001/admin",
        context_text="Cleanup",
        risk="high",
        preapproval=approval,
        config=CONFIG,
    )
    assert not allows_action(
        target="http://host.docker.internal:3001/",
        action="Run high-impact check on http://host.docker.internal:3001/",
        context_text="Critical operation",
        risk="critical",
        preapproval=approval,
        config=CONFIG,
    )

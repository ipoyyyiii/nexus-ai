"""Offline benchmark for the autonomous web-pentest control loop.

It exercises the real planner, registry admission, input binder, cycle
controller, and evidence hand-off with a fake runner. It never contacts a
target, but catches unsafe dispatch and unroutable planner proposals.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from core.adaptive_planner import PlanningSnapshot
from core.autonomous_web_pentest import AutonomousWebPentestLoop
from core.structured_contract import ObservationV1, ToolResultV1
from core.target_state import EndpointInfo, TargetState
from core.tool_registry import get_tool_capability


SUITE_PATH = Path(__file__).resolve().parent.parent / "benchmarks" / "stage28" / "autonomous_web_control_suite.yaml"


@dataclass(frozen=True)
class ControlCase:
    name: str
    target: str
    expected_category: str
    expected_tool: str
    expect_blocked: bool = False


CASES = (
    ControlCase("query_surface", "http://fixture.local/search?q=alpha", "sql_injection", "scan_sql_injection", True),
    ControlCase("navigation_surface", "http://fixture.local/login?return=/home", "open_redirect", "browser_find_open_redirect"),
    ControlCase("graphql_surface", "http://fixture.local/graphql", "graphql", "graphql_tester", True),
    ControlCase("external_fetch_surface", "http://fixture.local/proxy?url=https://example.invalid", "ssrf", "scan_ssrf", True),
    ControlCase("upload_surface", "http://fixture.local/upload", "file_upload", "file_upload_scanner", True),
    ControlCase("session_surface", "http://fixture.local/login", "session_security", "session_management_scanner"),
)


def _authorization_contract_snapshot() -> PlanningSnapshot:
    return PlanningSnapshot(
        identities=[
            {"identity_id": "owner", "status": "active"},
            {"identity_id": "other", "status": "active"},
        ],
        auth_contexts=[
            {"identity_id": "owner", "auth_context_id": "ctx-owner", "status": "active"},
            {"identity_id": "other", "auth_context_id": "ctx-other", "status": "active"},
        ],
        identity_graphs=[{"graph_id": "graph-1", "node_ids": ["owner", "other"], "digest": "graph-digest"}],
        identity_coverage_plans=[{
            "plan_id": "plan-1", "status": "ready",
            "required_identity_ids": ["owner", "other"],
            "required_resource_fingerprints": ["resource-fp"],
        }],
        request_templates=[{
            "template_id": "template-1", "origin": "http://fixture.local",
            "path_template": "/api/items/{resource_id}", "method": "GET",
            "side_effect_class": "read", "fingerprint": "template-fp",
        }],
        resource_instances=[{
            "resource_id": "resource-1", "origin": "http://fixture.local",
            "fingerprint": "resource-fp", "owner_identity_id": "owner",
            "resource_type": "item", "locator_redacted": "item-1",
        }],
        authorization_expectations=[{
            "expectation_id": "expect-1", "subject_identity_id": "other",
            "resource_fingerprint": "resource-fp", "action": "GET", "expected": "deny",
        }],
    )


def _run_contract_gate_cases() -> List[Dict[str, Any]]:
    incomplete = PlanningSnapshot(
        identities=[
            {"identity_id": "owner", "status": "active"},
            {"identity_id": "other", "status": "active"},
        ],
    )
    loop = AutonomousWebPentestLoop(_MemoryStore(TargetState(url="http://fixture.local")), config={"read_only_auto_run": True})
    blocked_reason = loop._precondition_block(
        "authorization",
        get_tool_capability("authorization_differential_replay"),
        incomplete,
    )
    ready = _authorization_contract_snapshot()
    bindings, binding_reason = loop._authorization_bindings(
        object(), ready, target="http://fixture.local/api/items/opaque-id",
    )
    mutation_admitted, _, mutation_reason = loop._admit(
        type("Proposal", (), {"recommended_tool": "stateful_browser_workflow"})(),
        "business_logic_mutation",
    )
    return [
        {
            "name": "authorization_readiness_gate",
            "status": "passed" if "two_isolated_active_auth_contexts_required" in blocked_reason else "failed",
            "checks": {"fail_closed": "two_isolated_active_auth_contexts_required" in blocked_reason},
            "detail": blocked_reason,
        },
        {
            "name": "observed_authorization_binding",
            "status": "passed" if not binding_reason and bindings.get("owner_identity_id") == "owner" and '"other": "ctx-other"' in bindings.get("auth_contexts_json", "") else "failed",
            "checks": {"exact_contract_binding": not binding_reason, "identity_context_binding": '"other": "ctx-other"' in bindings.get("auth_contexts_json", "")},
            "detail": binding_reason or "template/resource/identity/auth-context binding is deterministic",
        },
        {
            "name": "business_mutation_gate",
            "status": "passed" if not mutation_admitted and "explicit approval" in mutation_reason else "failed",
            "checks": {"approval_required": not mutation_admitted, "cleanup_required": "cleanup" in mutation_reason},
            "detail": mutation_reason,
        },
    ]


class _MemoryStore:
    def __init__(self, state: TargetState):
        self.context = {
            "session_id": "00000000-0000-0000-0000-000000000028",
            "target_url": "http://fixture.local",
            "target_domain": "fixture.local",
            "attack_goal": "map and validate the fixture surface",
            "scope_rules": [{"pattern": "fixture.local", "rule_type": "allow"}],
        }
        self.state = state

    def require(self, session_id: str) -> Dict[str, Any]:
        return self.context

    def load_state(self, session_id: str) -> TargetState:
        return self.state

    def save_state(self, session_id: str, state: TargetState, phase: str = "") -> None:
        self.state = state

    def validate_active_scope(self, session_id: str, target: str) -> tuple[bool, str]:
        return True, "scope accepted"


class _FakeTool:
    def __init__(self, name: str):
        self.name = name

    def __call__(self, **kwargs: Any) -> None:
        return None


class _FakeRunner:
    def __init__(self):
        self.calls: List[Dict[str, Any]] = []

    def execute(self, tool: Any, kwargs: Dict[str, Any], **context: Any) -> ToolResultV1:
        self.calls.append({"tool": tool.name, "kwargs": dict(kwargs), **context})
        return ToolResultV1(
            tool_run_id=f"run:{len(self.calls)}",
            tool_name=tool.name,
            category=context["category"],
            target=context["target"],
            summary="fixture observation recorded",
            observations=[ObservationV1(
                observation_id=f"obs:{len(self.calls)}",
                role="test",
                target_url=context["target"],
                metadata={"fixture": True},
            )],
        )


class _OfflineReasoningGateway:
    """Explicitly disable configured providers for the hermetic control suite.

    The stage-28 benchmark measures routing, safety, evidence hand-off, and
    repeatability of the controller.  It must not change behavior based on a
    developer's active Colab/Kaggle/remote model or spend time on network
    inference.  Raising here exercises the controller's typed provider-failure
    fallback while keeping every case deterministic and offline.
    """

    primary_model_id = "offline-benchmark"

    def reason(self, **_: Any) -> Any:
        raise RuntimeError("offline benchmark provider disabled")


def _fixture(case: ControlCase) -> tuple[_MemoryStore, PlanningSnapshot]:
    state = TargetState(url="http://fixture.local", goal="map fixture")
    state.endpoints = [EndpointInfo(url=case.target, method="GET")]
    store = _MemoryStore(state)
    snapshot = PlanningSnapshot(observations=[{
        "observation_id": f"baseline:{case.name}",
        "role": "baseline",
        "target_url": case.target,
        "method": "GET",
    }])
    return store, snapshot


def _run_case(case: ControlCase) -> Dict[str, Any]:
    def run_once() -> tuple[Dict[str, Any], _FakeRunner]:
        store, snapshot = _fixture(case)
        runner = _FakeRunner()
        loop = AutonomousWebPentestLoop(
            store,
            runner=runner,
            snapshot_loader=lambda _: snapshot,
            tool_resolver=lambda capability: _FakeTool(capability.public_name),
            reasoning_gateway=_OfflineReasoningGateway(),
            config={"max_cycles": 1, "max_actions_per_cycle": 2, "max_actions_total": 2, "read_only_auto_run": True},
        )
        return loop.execute(
            store.context["session_id"],
            target=case.target,
            goal="validate the fixture surface",
            max_cycles=1,
            max_actions=2,
        ), runner

    first, first_runner = run_once()
    second, _ = run_once()
    def selection(result: Dict[str, Any]) -> List[tuple[Any, ...]]:
        return [
            (item.get("category"), item.get("tool"), item.get("status"), item.get("target_url"))
            for item in result.get("actions", []) + result.get("blocked", [])
        ]

    selected = first.get("actions", []) + first.get("blocked", [])
    category_match = any(item.get("category") == case.expected_category for item in selected)
    tool_match = any(item.get("tool") == case.expected_tool for item in selected)
    blocked_safely = case.expect_blocked and not first.get("actions") and any(
        item.get("category") == case.expected_category and item.get("status") == "blocked"
        for item in first.get("blocked", [])
    )
    checks = {
        "routing": blocked_safely if case.expect_blocked else category_match and tool_match,
        "safety": (not first.get("actions")) if case.expect_blocked else all(
            item.get("status") not in {"blocked", "failed"} for item in first.get("actions", [])
        ),
        "evidence_handoff": all(bool(item.get("tool_run_id") or item.get("evidence_ids")) for item in first.get("actions", [])),
        "repeatability": selection(first) == selection(second),
    }
    return {
        "name": case.name,
        "expected_category": case.expected_category,
        "expected_tool": case.expected_tool,
        "expected_blocked": case.expect_blocked,
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "selected": selected,
        "runner_calls": len(first_runner.calls),
        "loop_status": first.get("status"),
    }


def run_benchmark() -> Dict[str, Any]:
    control_results = [_run_case(case) for case in CASES]
    contract_results = _run_contract_gate_cases()
    results = control_results + contract_results
    metrics = {
        "routing_recall": sum(item["checks"]["routing"] for item in control_results) / len(control_results),
        "safety_pass_rate": sum(item["checks"]["safety"] for item in control_results) / len(control_results),
        "evidence_handoff_rate": sum(item["checks"]["evidence_handoff"] for item in control_results) / len(control_results),
        "repeatability": sum(item["checks"]["repeatability"] for item in control_results) / len(control_results),
        "contract_gate_pass_rate": sum(item["status"] == "passed" for item in contract_results) / len(contract_results),
    }
    metrics["overall"] = sum(metrics.values()) / len(metrics)
    return {
        "suite": "stage28-autonomous-web-control",
        "cases": len(results),
        "passed": sum(item["status"] == "passed" for item in results),
        "failed": sum(item["status"] == "failed" for item in results),
        "metrics": metrics,
        "release_gate": "ready" if all(item["status"] == "passed" for item in results) else "not_ready",
        "results": results,
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), indent=2, sort_keys=True))

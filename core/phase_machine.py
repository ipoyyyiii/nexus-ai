"""Validated phase transitions for the engagement workflow."""

from typing import Dict, Set

from core.workflow_models import WorkflowPhase, WorkflowState


_ALLOWED: Dict[str, Set[str]] = {
    WorkflowPhase.SETUP.value: {WorkflowPhase.RECON.value},
    WorkflowPhase.RECON.value: {WorkflowPhase.MAPPING.value, WorkflowPhase.CLEANUP.value},
    WorkflowPhase.MAPPING.value: {WorkflowPhase.THREAT_MODEL.value, WorkflowPhase.HYPOTHESIS.value},
    WorkflowPhase.THREAT_MODEL.value: {WorkflowPhase.HYPOTHESIS.value},
    WorkflowPhase.HYPOTHESIS.value: {WorkflowPhase.VALIDATION.value, WorkflowPhase.RECON.value},
    WorkflowPhase.VALIDATION.value: {WorkflowPhase.CHAINING.value, WorkflowPhase.HYPOTHESIS.value, WorkflowPhase.CLEANUP.value},
    WorkflowPhase.CHAINING.value: {WorkflowPhase.IMPACT_PROOF.value, WorkflowPhase.VALIDATION.value, WorkflowPhase.CLEANUP.value},
    WorkflowPhase.IMPACT_PROOF.value: {WorkflowPhase.CLEANUP.value},
    WorkflowPhase.CLEANUP.value: {WorkflowPhase.REPORT.value, WorkflowPhase.VALIDATION.value},
    WorkflowPhase.REPORT.value: {WorkflowPhase.RETEST.value, WorkflowPhase.COMPLETE.value},
    WorkflowPhase.RETEST.value: {WorkflowPhase.REPORT.value, WorkflowPhase.COMPLETE.value},
    WorkflowPhase.COMPLETE.value: {WorkflowPhase.RETEST.value},
}


def can_transition(current: str, target: str) -> bool:
    return target in _ALLOWED.get(current, set())


def transition(state: WorkflowState, target: str) -> None:
    if not can_transition(state.phase, target):
        raise ValueError(f"Invalid workflow transition: {state.phase} -> {target}")
    previous = state.phase
    state.phase = target
    state.record_event("phase_changed", previous=previous, current=target)


def allowed_transitions(current: str) -> list[str]:
    return sorted(_ALLOWED.get(current, set()))

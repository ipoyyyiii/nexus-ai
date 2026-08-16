"""Persistent setup and TargetState storage for interactive sessions."""

import fnmatch
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.target_state import TargetState


SESSION_CONTEXT_SQL = """
create table if not exists session_context (
    session_id uuid primary key references sessions(id) on delete cascade,
    target_url text not null,
    target_domain text not null,
    attack_goal text not null,
    scope_rules jsonb not null default '[]'::jsonb,
    authorization_confirmed boolean not null default false,
    phase text not null default 'SETUP',
    status text not null default 'active',
    model_id text,
    target_state jsonb not null default '{}'::jsonb,
    workflow_state jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now()
);

alter table session_context add column if not exists workflow_state jsonb not null default '{}'::jsonb;
alter table session_context add column if not exists conversation_summary text not null default '';
alter table session_context add column if not exists conversation_summary_version integer not null default 0;

create table if not exists workflow_jobs (
    job_id uuid primary key,
    session_id uuid not null references sessions(id) on delete cascade,
    status text not null,
    target text not null,
    goal text not null,
    payload jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists workflow_events (
    id uuid primary key default gen_random_uuid(),
    session_id uuid not null references sessions(id) on delete cascade,
    job_id uuid,
    event_type text not null,
    payload jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);
"""


def normalize_target(value: str) -> tuple[str, str]:
    target = value.strip()
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be a valid HTTP or HTTPS URL.")
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized.rstrip("/"), parsed.hostname.lower()


def validate_session_scope(domain: str, rules: List[Dict[str, Any]]) -> tuple[bool, str]:
    if not rules:
        return False, "At least one allow scope rule is required."
    allowed = False
    for rule in rules:
        pattern = str(rule.get("pattern", "")).strip().lower()
        rule_type = rule.get("rule_type")
        if not pattern or rule_type not in {"allow", "deny"}:
            return False, "Each scope rule needs a pattern and allow/deny type."
        if fnmatch.fnmatch(domain, pattern):
            if rule_type == "deny":
                return False, f"Target domain matches deny rule '{pattern}'."
            allowed = True
    if not allowed:
        return False, "Target domain does not match an allow scope rule."
    return True, "Scope accepted."


class SessionStore:
    def __init__(self, supabase_client):
        self.sb = supabase_client

    def create(
        self,
        target_url: str,
        goal: str,
        scope_rules: List[Dict[str, Any]],
        authorization_confirmed: bool,
        model_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        normalized, domain = normalize_target(target_url)
        if not goal.strip():
            raise ValueError("Attack goal is required.")
        if not authorization_confirmed:
            raise ValueError("Explicit authorization confirmation is required.")
        valid, reason = validate_session_scope(domain, scope_rules)
        if not valid:
            raise ValueError(reason)

        session = self.sb.table("sessions").insert({
            "title": f"{domain} · {goal.strip()[:80]}"
        }).execute().data[0]
        state = TargetState(url=normalized, goal=goal.strip())
        context = {
            "session_id": session["id"],
            "target_url": normalized,
            "target_domain": domain,
            "attack_goal": goal.strip(),
            "scope_rules": scope_rules,
            "authorization_confirmed": True,
            "phase": "SETUP",
            "status": "active",
            "model_id": model_id,
            "target_state": state.to_dict(),
            "workflow_state": state.workflow.to_dict(),
        }
        try:
            self.sb.table("session_context").insert(context).execute()
        except Exception:
            self.sb.table("sessions").delete().eq("id", session["id"]).execute()
            raise
        return context

    def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        try:
            uuid.UUID(session_id)
        except ValueError:
            return None
        try:
            result = self.sb.table("session_context").select("*").eq("session_id", session_id).limit(1).execute()
        except Exception as exc:
            if "invalid input syntax for type uuid" in str(exc).lower():
                return None
            raise
        return result.data[0] if result.data else None

    def require(self, session_id: str) -> Dict[str, Any]:
        context = self.get(session_id)
        if not context:
            raise ValueError("Session setup not found. Create a new session first.")
        return context

    def load_state(self, session_id: str) -> TargetState:
        context = self.require(session_id)
        state_data = context.get("target_state") or {}
        return TargetState.from_dict(state_data) if state_data.get("url") else TargetState(
            url=context["target_url"], goal=context["attack_goal"]
        )

    def save_state(self, session_id: str, state: TargetState, phase: Optional[str] = None, expected_version: Optional[int] = None) -> None:
        # Optimistic locking: check conversation_summary_version if provided
        if expected_version is not None:
            current = self.get(session_id)
            cur_ver = current.get("conversation_summary_version", 0) if current else 0
            if cur_ver != expected_version:
                raise ValueError(f"Version conflict: expected {expected_version}, got {cur_ver}")
        values: Dict[str, Any] = {
            "target_state": state.to_dict(),
            "workflow_state": state.workflow.to_dict(),
        }
        if phase:
            values["phase"] = phase
        self.sb.table("session_context").update(values).eq("session_id", session_id).execute()

    def save_job(self, job: Dict[str, Any]) -> None:
        payload = {key: value for key, value in job.items() if key not in {"job_id", "session_id", "status", "target", "goal", "created_at", "updated_at"}}
        self.sb.table("workflow_jobs").upsert({
            "job_id": job["job_id"],
            "session_id": job["session_id"],
            "status": job.get("status", "queued"),
            "target": job.get("target", ""),
            "goal": job.get("goal", ""),
            "payload": payload,
            "created_at": job.get("created_at"),
            "updated_at": job.get("updated_at"),
        }).execute()

    def latest_job(self, session_id: str) -> Optional[Dict[str, Any]]:
        result = (
            self.sb.table("workflow_jobs")
            .select("*")
            .eq("session_id", session_id)
            .order("updated_at", desc=True)
            .limit(1)
            .execute()
        )
        if not result.data:
            return None
        item = result.data[0]
        item.update(item.pop("payload", {}) or {})
        return item

    def save_conversation_summary(self, session_id: str, summary: str, version: int) -> None:
        self.sb.table("session_context").update({
            "conversation_summary": summary[:12000],
            "conversation_summary_version": version,
        }).eq("session_id", session_id).execute()

    def conversation_summary(self, session_id: str) -> Dict[str, Any]:
        context = self.require(session_id)
        return {
            "text": context.get("conversation_summary", ""),
            "version": context.get("conversation_summary_version", 0),
        }

    def save_chat_message(self, session_id: str, message: Dict[str, Any]) -> None:
        payload = {
            "session_id": session_id,
            "role": message["role"],
            "content": message.get("content", ""),
        }
        optional = {key: message[key] for key in (
            "message_id", "status", "model", "parent_message_id", "metadata"
        ) if key in message}
        try:
            self.sb.table("chat_messages").insert({**payload, **optional}).execute()
        except Exception:
            self.sb.table("chat_messages").insert(payload).execute()

    def validate_active_scope(self, session_id: str, target: Optional[str] = None) -> tuple[bool, str]:
        context = self.require(session_id)
        domain = context["target_domain"]
        if target:
            _, domain = normalize_target(target)
        return validate_session_scope(domain, context.get("scope_rules") or [])

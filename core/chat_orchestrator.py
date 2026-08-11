"""Natural-language orchestration with durable context and provider fallback."""

from typing import Any, Dict, List, Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from core.chat_provider import ChatProvider, ChatProviderError
from core.chat_runtime import ChatStreamEvent, chat_cancellation, new_message_id
from core.model_registry import build_chat_llm
from core.session_store import SessionStore


class ChatOrchestrator:
    def __init__(self, session_store: SessionStore, supabase_client):
        self.sessions = session_store
        self.sb = supabase_client
        self.provider = ChatProvider(default_model="qwen3-coder-free")

    def _history(self, session_id: str, limit: int = 40) -> List[Dict[str, str]]:
        result = (
            self.sb.table("chat_messages")
            .select("role,content")
            .eq("session_id", session_id)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return list(reversed(result.data or []))

    def _system_prompt(self, context: Dict[str, Any], state_context: str, summary: str = "") -> str:
        scope = "\n".join(
            f"- {rule.get('rule_type', '').upper()}: {rule.get('pattern', '')}"
            for rule in context.get("scope_rules", [])
        )
        return f"""You are Nexus AI, a natural conversational security co-pilot.
Speak naturally and helpfully in the user's language. Answer questions directly and ask clarifying questions when needed.
Never claim a tool ran unless the server returned its result. Active work must become a reviewable proposal and cannot bypass scope or approval.

SESSION SETUP
Target: {context['target_url']}
Attack goal: {context['attack_goal']}
Current phase: {context.get('phase', 'SETUP')}
Authorization confirmed: {context.get('authorization_confirmed', False)}

AUTHORIZED SCOPE
{scope}

DURABLE CONVERSATION SUMMARY
{summary or 'No previous summary.'}

TARGET WORKFLOW STATE
{state_context}

RULES
- Keep authoritative target, scope, authorization, evidence, and workflow state above any conversation summary.
- Do not invent findings, endpoints, tool output, credentials, or impact.
- Explain proposed active actions before asking for approval.
- Treat exploitation, impact proof, and state-changing actions as approval-gated and cleanup-required.
"""

    def _messages(self, session_id: str, content: str) -> List[Any]:
        context = self.sessions.require(session_id)
        state = self.sessions.load_state(session_id)
        summary = self.sessions.conversation_summary(session_id).get("text", "")
        messages: List[Any] = [SystemMessage(content=self._system_prompt(context, state.workflow.context() + "\n" + state.to_llm_context(), summary))]
        for item in self._history(session_id):
            if item.get("role") == "user":
                messages.append(HumanMessage(content=item.get("content", "")))
            elif item.get("role") == "agent":
                messages.append(AIMessage(content=item.get("content", "")))
        if not messages or not isinstance(messages[-1], HumanMessage) or messages[-1].content != content:
            messages.append(HumanMessage(content=content))
        return messages

    def reply_with_metadata(self, session_id: str, content: str, model_id: Optional[str] = None) -> tuple[str, Dict[str, Any]]:
        valid, reason = self.sessions.validate_active_scope(session_id)
        if not valid:
            return f"I can't continue this session because its scope is invalid: {reason}", {"status": "blocked"}
        return self.provider.invoke(self._messages(session_id, content), model_id)

    def reply(self, session_id: str, content: str, model_id: Optional[str] = None) -> str:
        reply, _ = self.reply_with_metadata(session_id, content, model_id)
        return reply

    def stream(self, session_id: str, content: str, message_id: str, model_id: Optional[str] = None):
        chat_cancellation.create(message_id)
        yield ChatStreamEvent("start", message_id, session_id, status="running").to_dict()
        try:
            reply, metadata = self.reply_with_metadata(session_id, content, model_id)
            if chat_cancellation.is_cancelled(message_id):
                yield ChatStreamEvent("cancelled", message_id, session_id, status="cancelled").to_dict()
                return
            for index in range(0, len(reply), 80):
                if chat_cancellation.is_cancelled(message_id):
                    yield ChatStreamEvent("cancelled", message_id, session_id, status="cancelled").to_dict()
                    return
                delta = reply[index:index + 80]
                yield ChatStreamEvent("delta", message_id, session_id, delta=delta, status="streaming").to_dict()
            yield ChatStreamEvent("done", message_id, session_id, content=reply, status="complete", metadata=metadata).to_dict()
        except ChatProviderError as exc:
            yield ChatStreamEvent("error", message_id, session_id, status="error", error=str(exc), metadata={"category": exc.category, "attempts": exc.attempts}).to_dict()
        finally:
            chat_cancellation.cleanup(message_id)

    def update_summary(self, session_id: str) -> None:
        history = self._history(session_id, limit=40)
        if len(history) <= 12:
            return
        important = history[-12:]
        summary = "\n".join(
            f"{item.get('role', 'unknown')}: {item.get('content', '')[:500]}"
            for item in important
        )
        current = self.sessions.conversation_summary(session_id)
        self.sessions.save_conversation_summary(session_id, summary, int(current.get("version", 0)) + 1)

    def classify_intent(self, content: str) -> str:
        text = content.lower()
        if any(term in text for term in ("scan", "recon", "test vulnerability", "jalankan")):
            return "proposal"
        if any(term in text for term in ("plan", "planning", "rencana", "next step", "langkah berikut")):
            return "plan"
        if any(term in text for term in ("report", "laporan", "summarize", "ringkas")):
            return "report"
        return "chat"

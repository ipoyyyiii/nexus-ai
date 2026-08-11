"""Resilient conversational provider with free-first fallback."""

import time
from typing import Any, Dict, Iterable, Optional

from core.chat_runtime import classify_provider_error
from core.model_registry import build_chat_llm


class ChatProviderError(RuntimeError):
    def __init__(self, category: str, message: str, attempts: list[str]):
        super().__init__(message)
        self.category = category
        self.attempts = attempts


class ChatProvider:
    def __init__(self, default_model: Optional[str] = None):
        self.default_model = default_model

    def _models(self, preferred: Optional[str]) -> list[Optional[str]]:
        if preferred:
            return [preferred, self.default_model] if self.default_model != preferred else [preferred]
        return [self.default_model]

    def invoke(self, messages: list[Any], preferred_model: Optional[str] = None) -> tuple[str, Dict[str, Any]]:
        attempts: list[str] = []
        last_category = "provider_unavailable"
        for model_id in self._models(preferred_model):
            label = model_id or "default-free"
            attempts.append(label)
            for retry in range(2):
                try:
                    response = build_chat_llm(model_id).invoke(messages)
                    return str(response.content), {"model": label, "attempts": attempts, "retry": retry}
                except Exception as exc:
                    last_category = classify_provider_error(exc)
                    if last_category not in {"rate_limited", "timeout", "provider_unavailable"} or retry == 1:
                        break
                    time.sleep(0.25 * (2 ** retry))
        raise ChatProviderError(last_category, self._message(last_category), attempts)

    @staticmethod
    def _message(category: str) -> str:
        return {
            "insufficient_credit": "The selected model has insufficient credit. Choose a free model or another provider.",
            "rate_limited": "The model provider is rate-limited. Please retry or choose another model.",
            "timeout": "The model provider timed out. Please retry.",
            "invalid_model": "The selected model is unavailable or invalid.",
            "provider_unavailable": "The model provider is temporarily unavailable.",
        }.get(category, "The chat provider failed.")

"""Typed decorators for legacy LangChain/CrewAI public tools."""

from __future__ import annotations

import functools
import json
from typing import Any, Callable

from core.structured_contract import ToolResultV1, result_from_legacy


def _target(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    for key in ("url", "target", "target_url", "login_url"):
        value = kwargs.get(key)
        if isinstance(value, str) and value:
            return value
    for value in args:
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            return value
    return ""


def _typed_function(fn: Callable[..., Any], public_name: str) -> Callable[..., ToolResultV1]:
    @functools.wraps(fn)
    def invoke(*args: Any, **kwargs: Any) -> ToolResultV1:
        output = fn(*args, **kwargs)
        if isinstance(output, ToolResultV1):
            return output
        return result_from_legacy(public_name, _target(args, kwargs), output)

    return invoke


def langchain_tool(*args: Any, **kwargs: Any):
    from langchain.tools import tool as native_tool

    def decorate(fn: Callable[..., Any]):
        name = args[0] if args and isinstance(args[0], str) else kwargs.get("name") or fn.__name__
        typed = _typed_function(fn, str(name))
        if args or kwargs:
            return native_tool(*args, **kwargs)(typed)
        return native_tool(typed)

    if args and callable(args[0]) and not isinstance(args[0], str):
        fn = args[0]
        typed = _typed_function(fn, fn.__name__)
        return native_tool(typed)
    return decorate


def crewai_tool(*args: Any, **kwargs: Any):
    from crewai.tools import tool as native_tool

    def decorate(fn: Callable[..., Any]):
        name = args[0] if args and isinstance(args[0], str) else kwargs.get("name") or fn.__name__
        typed = _typed_function(fn, str(name))
        if args or kwargs:
            return native_tool(*args, **kwargs)(typed)
        return native_tool(typed)

    if args and callable(args[0]) and not isinstance(args[0], str):
        fn = args[0]
        typed = _typed_function(fn, fn.__name__)
        return native_tool(typed)
    return decorate

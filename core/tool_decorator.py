"""Typed decorators for legacy LangChain/CrewAI public tools."""

from __future__ import annotations

import functools
import json
from typing import Any, Callable

from core.structured_contract import ToolResultV1, result_from_legacy


_MODERN_PROTOCOL_METADATA = {
    "graphql_tester": {"protocol": "graphql", "parser_context": "graphql"},
    "oauth_flow_tester": {"protocol": "oauth", "parser_context": "form"},
}


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
        result = result_from_legacy(public_name, _target(args, kwargs), output)
        protocol_metadata = _MODERN_PROTOCOL_METADATA.get(public_name)
        if protocol_metadata:
            observations = [
                item.model_copy(update={"metadata": {**item.metadata, **protocol_metadata}})
                for item in result.observations
            ]
            candidates = [
                item.model_copy(update={"metadata": {**item.metadata, **protocol_metadata}})
                for item in result.candidate_findings
            ]
            result = result.model_copy(
                update={
                    "category": "protocol_surface",
                    "observations": observations,
                    "candidate_findings": candidates,
                }
            )
        return result

    return invoke


def invoke_tool_compat(tool_obj: Any, kwargs: dict[str, Any]) -> Any:
    """Invoke LangChain and CrewAI tools through their actual public shape.

    LangChain tools commonly expose ``invoke`` while CrewAI's ``Tool``
    exposes the wrapped callable as ``func`` (and may expose ``run``).  The
    application has call sites outside the structured runner, so keep the
    compatibility rule in one place instead of assuming one framework API.
    """
    if hasattr(tool_obj, "invoke"):
        return tool_obj.invoke(kwargs)
    func = getattr(tool_obj, "func", None)
    if callable(func):
        return func(**kwargs)
    run = getattr(tool_obj, "run", None)
    if callable(run):
        return run(kwargs)
    if callable(tool_obj):
        return tool_obj(**kwargs)
    raise TypeError(f"Unsupported tool wrapper: {type(tool_obj).__name__}")


class _LazyNativeTool:
    """Framework-compatible tool facade with deferred native imports.

    The canonical runner only needs a stable name, description, callable
    implementation, and ``invoke`` boundary.  Importing LangChain/CrewAI while
    the modules in ``tools/`` are being discovered caused the API process to
    spend minutes importing LiteLLM and its dependency graph before it could
    even answer ``/health``.  Keep the legacy native conversion available for
    the compatibility path, but defer it until explicitly requested.
    """

    def __init__(
        self,
        fn: Callable[..., Any],
        framework: str,
        decorator_args: tuple[Any, ...],
        decorator_kwargs: dict[str, Any],
    ) -> None:
        public_name = (
            decorator_args[0]
            if decorator_args and isinstance(decorator_args[0], str)
            else decorator_kwargs.get("name") or fn.__name__
        )
        self.name = str(public_name)
        self.description = str(fn.__doc__ or "").strip()
        self.func = _typed_function(fn, self.name)
        self._framework = framework
        self._decorator_args = decorator_args
        self._decorator_kwargs = dict(decorator_kwargs)
        self._native = None
        self.__name__ = getattr(fn, "__name__", self.name)
        self.__qualname__ = getattr(fn, "__qualname__", self.name)
        self.__doc__ = fn.__doc__
        self.__wrapped__ = fn

    def invoke(self, input: Any = None, **kwargs: Any) -> ToolResultV1:
        """Invoke the typed function using LangChain/CrewAI input semantics."""
        if isinstance(input, dict) and not kwargs:
            return self.func(**input)
        if input is not None and not kwargs:
            return self.func(input)
        return self.func(**kwargs)

    def run(self, tool_input: Any = None, **kwargs: Any) -> ToolResultV1:
        """Compatibility alias used by older CrewAI call sites."""
        return self.invoke(tool_input, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> ToolResultV1:
        return self.func(*args, **kwargs)

    def as_native_tool(self) -> Any:
        """Materialize the requested framework wrapper on the legacy path."""
        if self._native is not None:
            return self._native

        if self._framework == "langchain":
            from langchain.tools import tool as native_tool
        elif self._framework == "crewai":
            from crewai.tools import tool as native_tool
        else:  # pragma: no cover - constructor is private and closed over
            raise ValueError(f"Unsupported native tool framework: {self._framework}")

        if self._decorator_args or self._decorator_kwargs:
            self._native = native_tool(
                *self._decorator_args,
                **self._decorator_kwargs,
            )(self.func)
        else:
            self._native = native_tool(self.func)
        return self._native


def _lazy_tool_decorator(framework: str, *args: Any, **kwargs: Any):
    if args and callable(args[0]) and not isinstance(args[0], str):
        fn = args[0]
        return _LazyNativeTool(fn, framework, (), {})

    def decorate(fn: Callable[..., Any]):
        return _LazyNativeTool(fn, framework, tuple(args), dict(kwargs))

    return decorate


def langchain_tool(*args: Any, **kwargs: Any):
    """Decorate a legacy tool without importing LangChain at module import."""
    return _lazy_tool_decorator("langchain", *args, **kwargs)



def crewai_tool(*args: Any, **kwargs: Any):
    """Decorate a legacy tool without importing CrewAI at module import."""
    return _lazy_tool_decorator("crewai", *args, **kwargs)

"""Regression checks for the canonical AI-native import boundary."""

import subprocess
import sys


def _run_isolated(code: str) -> str:
    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def test_core_package_does_not_eagerly_import_model_registry():
    result = _run_isolated(
        "import sys; import core; print('core.model_registry' in sys.modules)"
    )
    assert result == "False"


def test_chat_provider_does_not_eagerly_import_model_registry():
    result = _run_isolated(
        "import sys; import core.chat_provider; print('core.model_registry' in sys.modules)"
    )
    assert result == "False"


def test_tools_namespace_does_not_eagerly_import_scanners():
    result = _run_isolated(
        "import sys; import tools; print('tools.playwright_tools' in sys.modules, 'mitmproxy' in sys.modules)"
    )
    assert result == "False False"


def test_tool_modules_do_not_eagerly_import_crewai_or_langchain():
    result = _run_isolated(
        "import sys; import tools.playwright_tools; print('crewai' in sys.modules, 'langchain' in sys.modules)"
    )
    assert result == "False False"


def test_lazy_crewai_facade_preserves_structured_runner_shape():
    code = """
import sys
from core.tool_decorator import crewai_tool

@crewai_tool('fixture_tool')
def fixture_tool(target_url: str):
    return {'target': target_url, 'status': 'ok'}

assert fixture_tool.name == 'fixture_tool'
assert fixture_tool.description == ''
assert fixture_tool.invoke({'target_url': 'http://fixture.local'}).status == 'succeeded'
assert 'crewai' not in sys.modules
"""
    _run_isolated(code)

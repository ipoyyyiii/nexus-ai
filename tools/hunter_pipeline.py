"""Allowlisted hunter pipeline wrappers using the Stage 5 sandbox boundary."""

from core.tool_decorator import crewai_tool as tool

from core.sandbox_runner import SandboxedCommandRunner

_runner = SandboxedCommandRunner()


def _run(command_id: str, args=(), *, stdin: str = "", timeout: int = 90, lines: int = 80) -> str:
    try:
        result = _runner.run(command_id, args, stdin=stdin, timeout_seconds=timeout)
        output = "\n".join((result.stdout + result.stderr).splitlines()[:lines])
        return output or f"exit_code: {result.run.exit_code}"
    except Exception as exc:
        return f"error: {type(exc).__name__}: {exc}"


def _host(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0]


@tool("httpx_probe")
def httpx_probe(target: str) -> str:
    """Live host probe via allowlisted httpx."""
    return _run("httpx_probe", stdin=target, lines=30)


@tool("naabu_scan")
def naabu_scan(target: str) -> str:
    """Port scan via allowlisted naabu."""
    return _run("naabu_scan", ["-host", _host(target)], timeout=120, lines=40)


@tool("gowitness_shot")
def gowitness_shot(target: str) -> str:
    """Screenshot via allowlisted gowitness."""
    return _run("gowitness_shot", [target], timeout=120, lines=40)


@tool("gau_urls")
def gau_urls(target: str) -> str:
    """Historical URL gathering via allowlisted gau."""
    return _run("gau_urls", stdin=_host(target), lines=80)


@tool("hakrawler_crawl")
def hakrawler_crawl(target: str) -> str:
    """Endpoint crawling via allowlisted hakrawler."""
    return _run("hakrawler_crawl", stdin=target, lines=80)


@tool("amass_enum")
def amass_enum(target: str) -> str:
    """Passive subdomain enumeration via allowlisted amass."""
    domain = _host(target).split(":")[0]
    return _run("amass_enum", ["-d", domain], timeout=150, lines=50)

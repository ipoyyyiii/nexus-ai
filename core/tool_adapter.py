"""Normalize scanner output into redacted workflow evidence and findings."""

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Dict, List, Optional

from core.evidence_service import redact


@dataclass
class AdapterResult:
    tool: str
    target_url: str
    summary: str
    confidence: str = "medium"
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)


def fingerprint(vuln_type: str, target_url: str, parameter: str = "") -> str:
    value = "|".join((vuln_type.lower().strip(), target_url.lower().strip(), parameter.lower().strip()))
    return hashlib.sha256(value.encode()).hexdigest()[:24]


class ToolOutputAdapter:
    _severity = re.compile(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+)", re.IGNORECASE)
    _url = re.compile(r"https?://[^\s<>'\"{}|\\^`\[\]]+")

    def adapt(self, tool: str, target_url: str, output: str, tool_run_id: str = "", historical: bool = False) -> AdapterResult:
        safe_output = redact(output)
        urls = sorted({url.rstrip(".,);]") for url in self._url.findall(output)})
        result = AdapterResult(
            tool=tool,
            target_url=target_url,
            summary=safe_output[:1000],
            evidence=[{
                "source": tool,
                "summary": f"{tool} returned structured output for the authorized target.",
                "target_url": target_url,
                "response": safe_output,
                "confidence": "medium",
                "tool_run_id": tool_run_id,
            }],
            endpoints=urls,
        )
        # Regex severity parsing is historical-only. New execution paths use
        # typed ToolResultV1 and deterministic validators.
        if historical:
            for match in self._severity.finditer(output):
                severity = match.group(1).upper()
                title = redact(match.group(2).strip(), 500)
                vuln_type = self._vuln_type(title)
                result.findings.append({
                    "title": title,
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "fingerprint": fingerprint(vuln_type, target_url),
                    "confidence": "medium",
                    "evidence_summary": title,
                })
        return result

    @staticmethod
    def _vuln_type(value: str) -> str:
        text = value.lower()
        for terms, name in (
            (("sql", "sqli", "injection"), "SQL Injection"),
            (("xss", "cross-site scripting"), "XSS"),
            (("ssrf", "server-side request"), "SSRF"),
            (("idor", "insecure direct object"), "IDOR"),
            (("lfi", "file inclusion", "path traversal"), "LFI/Path Traversal"),
            (("ssti", "template injection"), "SSTI"),
            (("csrf", "cross-site request"), "CSRF"),
            (("xxe", "xml external"), "XXE"),
        ):
            if any(term in text for term in terms):
                return name
        return "Other"

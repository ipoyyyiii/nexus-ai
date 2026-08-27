"""
REPORT GENERATOR — Professional Bug Bounty Report Engine
=========================================================
Generate enterprise-grade penetration testing reports dalam format Markdown.

Usage:
    from report_generator import ReportGenerator

    gen = ReportGenerator()
    report = gen.generate(finding)
    gen.save_to_file(report, "report.md")
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime

from core.redact import redact


# ============================================================
# CWE DATABASE (Common)
# ============================================================
CWE_MAP = {
    "sql_injection": {"cwe": "CWE-89", "owasp": "A03:2021 - Injection"},
    "blind_sqli": {"cwe": "CWE-89", "owasp": "A03:2021 - Injection"},
    "nosql_injection": {"cwe": "CWE-943", "owasp": "A03:2021 - Injection"},
    "xss_reflected": {"cwe": "CWE-79", "owasp": "A03:2021 - Injection"},
    "xss_stored": {"cwe": "CWE-79", "owasp": "A03:2021 - Injection"},
    "xss_dom": {"cwe": "CWE-79", "owasp": "A03:2021 - Injection"},
    "ssrf": {"cwe": "CWE-918", "owasp": "A10:2021 - Server-Side Request Forgery"},
    "blind_ssrf": {"cwe": "CWE-918", "owasp": "A10:2021 - Server-Side Request Forgery"},
    "xxe": {"cwe": "CWE-611", "owasp": "A05:2021 - Security Misconfiguration"},
    "blind_xxe": {"cwe": "CWE-611", "owasp": "A05:2021 - Security Misconfiguration"},
    "command_injection": {"cwe": "CWE-78", "owasp": "A03:2021 - Injection"},
    "lfi": {"cwe": "CWE-98", "owasp": "A01:2021 - Broken Access Control"},
    "rfi": {"cwe": "CWE-98", "owasp": "A01:2021 - Broken Access Control"},
    "ssti": {"cwe": "CWE-94", "owasp": "A03:2021 - Injection"},
    "idor": {"cwe": "CWE-639", "owasp": "A01:2021 - Broken Access Control"},
    "idor_uuid": {"cwe": "CWE-639", "owasp": "A01:2021 - Broken Access Control"},
    "csrf": {"cwe": "CWE-352", "owasp": "A01:2021 - Broken Access Control"},
    "open_redirect": {"cwe": "CWE-601", "owasp": "A01:2021 - Broken Access Control"},
    "cors_misconfiguration": {"cwe": "CWE-942", "owasp": "A05:2021 - Security Misconfiguration"},
    "clickjacking": {"cwe": "CWE-1021", "owasp": "A05:2021 - Security Misconfiguration"},
    "csp_missing": {"cwe": "CWE-693", "owasp": "A05:2021 - Security Misconfiguration"},
    "host_header_injection": {"cwe": "CWE-644", "owasp": "A05:2021 - Security Misconfiguration"},
    "race_condition": {"cwe": "CWE-362", "owasp": "A04:2021 - Insecure Design"},
    "file_upload": {"cwe": "CWE-434", "owasp": "A04:2021 - Insecure Design"},
    "request_smuggling": {"cwe": "CWE-444", "owasp": "A05:2021 - Security Misconfiguration"},
    "mass_assignment": {"cwe": "CWE-915", "owasp": "A04:2021 - Insecure Design"},
    "deserialization": {"cwe": "CWE-502", "owasp": "A08:2021 - Software and Data Integrity Failures"},
    "jwt_weakness": {"cwe": "CWE-327", "owasp": "A02:2021 - Cryptographic Failures"},
    "session_fixation": {"cwe": "CWE-384", "owasp": "A07:2021 - Identification and Authentication Failures"},
    "session_fixation": {"cwe": "CWE-384", "owasp": "A07:2021 - Identification and Authentication Failures"},
    "2fa_bypass": {"cwe": "CWE-308", "owasp": "A07:2021 - Identification and Authentication Failures"},
    "password_reset_poisoning": {"cwe": "CWE-644", "owasp": "A05:2021 - Security Misconfiguration"},
    "log4j": {"cwe": "CWE-502", "owasp": "A08:2021 - Software and Data Integrity Failures"},
    "prototype_pollution": {"cwe": "CWE-1321", "owasp": "A08:2021 - Software and Data Integrity Failures"},
    "http_method_tampering": {"cwe": "CWE-749", "owasp": "A05:2021 - Security Misconfiguration"},
    "path_traversal": {"cwe": "CWE-22", "owasp": "A01:2021 - Broken Access Control"},
    "graphql_introspection": {"cwe": "CWE-200", "owasp": "A01:2021 - Broken Access Control"},
    "subdomain_takeover": {"cwe": "CWE-250", "owasp": "A05:2021 - Security Misconfiguration"},
    "cache_poisoning": {"cwe": "CWE-346", "owasp": "A07:2021 - Identification and Authentication Failures"},
    "cache_deception": {"cwe": "CWE-346", "owasp": "A07:2021 - Identification and Authentication Failures"},
    "email_header_injection": {"cwe": "CWE-74", "owasp": "A03:2021 - Injection"},
    "credential_stuffing": {"cwe": "CWE-307", "owasp": "A07:2021 - Identification and Authentication Failures"},
    "web_socket_hijacking": {"cwe": "CWE-346", "owasp": "A01:2021 - Broken Access Control"},
    "mixed_content": {"cwe": "CWE-319", "owasp": "A02:2021 - Cryptographic Failures"},
    "ldap_injection": {"cwe": "CWE-90", "owasp": "A03:2021 - Injection"},
    "xpath_injection": {"cwe": "CWE-91", "owasp": "A03:2021 - Injection"},
    "csv_injection": {"cwe": "CWE-1236", "owasp": "A03:2021 - Injection"},
    "log_injection": {"cwe": "CWE-117", "owasp": "A09:2021 - Security Logging and Monitoring Failures"},
    "postmessage_vulnerability": {"cwe": "CWE-345", "owasp": "A08:2021 - Software and Data Integrity Failures"},
    "jsonp_injection": {"cwe": "CWE-79", "owasp": "A03:2021 - Injection"},
    "reverse_tabnapping": {"cwe": "CWE-1022", "owasp": "A05:2021 - Security Misconfiguration"},
}

# CVSS v3.1 severity thresholds
CVSS_THRESHOLDS = {
    "Critical": 9.0,
    "High": 7.0,
    "Medium": 4.0,
    "Low": 0.1,
    "Info": 0.0,
}


class ReportGenerator:
    """
    Generate professional penetration testing reports from vulnerability findings.
    """

    def __init__(self, author: str = "Nexus AI Pentest Agent"):
        self.author = author
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    def generate(self, finding: Dict[str, Any]) -> str:
        """
        Generate single vulnerability report from finding dict.
        
        Expected finding keys:
        - vuln_type: str (e.g., "sql_injection", "xss_reflected")
        - name: str (human-readable name)
        - url: str (vulnerable URL)
        - parameter: str (vulnerable parameter)
        - description: str (detailed explanation)
        - severity: str (Critical/High/Medium/Low)
        - cvss_score: float (optional)
        - cvss_vector: str (optional)
        - cve: str (optional)
        - steps_to_reproduce: list[str]
        - poc: str (proof of concept)
        - mitigation: list[str]
        - references: list[str]
        - oob_correlation_id: str (optional)
        - oob_callback_url: str (optional)
        """
        evidence_ids = finding.get("evidence_ids") or finding.get("observation_ids") or (finding.get("metadata") or {}).get("evidence_ids")
        if finding.get("status") not in {"validated", "validated_override"} or not evidence_ids:
            return (
                "# Finding report unavailable\n\n"
                "This item is not a deterministic, evidence-linked validated finding. "
                "It remains in the candidate/diagnostic view and cannot enter the main report."
            )

        vuln_type = finding.get("vuln_type", "unknown")
        cwe_info = CWE_MAP.get(vuln_type, {"cwe": "N/A", "owasp": "A05:2021 - Security Misconfiguration"})

        # Build report
        report = []

        # Title
        report.append(f"# {finding.get('name', 'Vulnerability')}")
        report.append("---")

        # Metadata
        report.append(f"**Vulnerable URL/Area:** `{finding.get('url', 'N/A')}`")
        report.append(f"**Vulnerable Form/Parameter:** `{finding.get('parameter', 'N/A')}`")
        report.append(f"**Vulnerability Description:** {finding.get('description', 'N/A')}")
        report.append(f"**Severity:** `{finding.get('severity', 'N/A')}`")
        report.append(f"**Risk Rating:** `{self._risk_rating(finding.get('severity', 'N/A'))}`")
        report.append(f"**CVE:** `{finding.get('cve', 'N/A')}`")
        report.append(f"**CWE-ID:** `{cwe_info['cwe']}`")
        report.append(f"**CVSS Score:** {finding.get('cvss_score', 'N/A')} `{finding.get('cvss_vector', 'N/A')}`")
        report.append(f"**Vulnerability Class:** `{cwe_info['owasp']}`")
        report.append(f"**Impact of Vulnerability:** {finding.get('impact', 'See description above.')}")
        report.append("")

        # Steps to reproduce
        steps = finding.get("steps_to_reproduce", [])
        if steps:
            report.append("**Steps to reproduce:**")
            report.append("```")
            for i, step in enumerate(steps, 1):
                report.append(f"{i}. {step}")
            report.append("```")
            report.append("")

        # Proof of Concept
        poc = finding.get("poc", "")
        if poc:
            report.append("**Proof of Concept (PoC):**")
            report.append("```text")
            report.append(poc)
            report.append("```")
            report.append("")

        # OOB Callback Evidence
        oob_id = finding.get("oob_correlation_id", "")
        oob_url = finding.get("oob_callback_url", "")
        if oob_id:
            report.append("**OOB Callback Evidence:**")
            report.append("```text")
            report.append(f"Correlation ID: {oob_id}")
            report.append(f"Callback Domain: {oob_url or '[configured OOB domain redacted]'}")
            report.append("OOB server details and authentication are intentionally redacted from reports.")
            report.append("")
            report.append(f"# Poll command:")
            report.append("Poll the configured OOB service using its private credentials.")
            report.append("```")
            report.append("")

        # Mitigation
        mitigation = finding.get("mitigation", [])
        if mitigation:
            report.append(f"**Mitigation Steps for {finding.get('name', 'Vulnerability')}:**")
            report.append("```")
            for i, step in enumerate(mitigation, 1):
                report.append(f"{i}. {step}")
            report.append("```")
            report.append("")

        # References
        refs = finding.get("references", [])
        if refs:
            report.append("**References:**")
            report.append("```")
            for ref in refs:
                report.append(ref)
            report.append("```")

        return "\n".join(report)

    def generate_summary(
        self,
        findings: List[Dict[str, Any]],
        target: str = "",
    ) -> str:
        """
        Generate executive summary + all findings.
        """
        # Candidate/suspected findings are intentionally excluded from the
        # main report and severity summary. They belong in the evidence
        # appendix/UI until deterministic validation or a labeled override.
        findings = [
            item for item in findings
            if item.get("status") in {"validated", "validated_override"}
            and bool(item.get("evidence_ids") or item.get("observation_ids") or (item.get("metadata") or {}).get("evidence_ids"))
        ]
        report = []

        # Header
        report.append(f"# Penetration Test Report")
        report.append("---")
        report.append("")
        report.append(f"**Target:** `{target}`")
        report.append(f"**Date:** {self.generated_at}")
        report.append(f"**Assessor:** {self.author}")
        report.append(f"**Total Findings:** {len(findings)}")
        report.append("")

        # Severity summary
        severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            severity_count[sev] = severity_count.get(sev, 0) + 1

        report.append("## Executive Summary")
        report.append("")
        report.append("| Severity | Count | Impact |")
        report.append("|----------|-------|--------|")
        for sev, count in severity_count.items():
            if count > 0:
                impact = {
                    "Critical": "Immediate action required — system compromise likely",
                    "High": "High impact — significant security risk",
                    "Medium": "Moderate impact — should be addressed soon",
                    "Low": "Limited impact — address when convenient",
                    "Info": "Informational — no immediate risk"
                }.get(sev, "")
                report.append(f"| {sev} | {count} | {impact} |")
        report.append("")

        # Risk assessment
        max_sev = "Info"
        for sev in ["Critical", "High", "Medium", "Low"]:
            if severity_count.get(sev, 0) > 0:
                max_sev = sev
                break

        risk_rating = {
            "Critical": "CRITICAL — Immediate remediation required. System is at high risk of compromise.",
            "High": "HIGH — Significant vulnerabilities found. Remediation should be prioritized.",
            "Medium": "MEDIUM — Moderate security issues. Plan remediation within sprint.",
            "Low": "LOW — Minor issues found. Address during regular maintenance.",
            "Info": "INFO — No significant vulnerabilities found. Good security posture."
        }.get(max_sev, "UNKNOWN")

        report.append(f"**Overall Risk Rating:** {max_sev}")
        report.append(f"**Risk Assessment:** {risk_rating}")
        report.append("")

        # Statistics
        report.append("## Statistics")
        report.append("")
        report.append(f"- **Total Findings:** {len(findings)}")
        report.append(f"- **Critical:** {severity_count.get('Critical', 0)}")
        report.append(f"- **High:** {severity_count.get('High', 0)}")
        report.append(f"- **Medium:** {severity_count.get('Medium', 0)}")
        report.append(f"- **Low:** {severity_count.get('Low', 0)}")
        report.append(f"- **Informational:** {severity_count.get('Info', 0)}")
        report.append("")

        # CWE/OWASP breakdown
        cwe_count = {}
        owasp_count = {}
        for f in findings:
            vuln_type = f.get("vuln_type", "")
            if vuln_type in VULN_REFERENCES:
                cwe = VULN_REFERENCES[vuln_type].get("cwe", "")
                owasp = VULN_REFERENCES[vuln_type].get("owasp", "")
                if cwe:
                    cwe_count[cwe] = cwe_count.get(cwe, 0) + 1
                if owasp:
                    owasp_count[owasp] = owasp_count.get(owasp, 0) + 1

        if cwe_count:
            report.append("### CWE Breakdown")
            report.append("")
            for cwe, count in sorted(cwe_count.items(), key=lambda x: -x[1])[:10]:
                report.append(f"- **{cwe}:** {count} finding(s)")
            report.append("")

        if owasp_count:
            report.append("### OWASP Top 10 Breakdown")
            report.append("")
            for owasp, count in sorted(owasp_count.items(), key=lambda x: -x[1])[:10]:
                report.append(f"- **{owasp}:** {count} finding(s)")
            report.append("")

        # Detailed findings
        report.append("## Detailed Findings")
        report.append("")

        # Sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "Info"), 5))

        for i, finding in enumerate(sorted_findings, 1):
            report.append(f"### Finding {i}: {finding.get('name', 'Unknown')}")
            report.append("")
            report.append(self.generate(finding))
            report.append("")
            report.append("---")
            report.append("")

        # Footer
        report.append("## Disclaimer")
        report.append("")
        report.append("This report was generated by Nexus AI Pentest Agent. All testing was performed")
        report.append("with authorization from the target organization. The findings and recommendations")
        report.append("in this report are provided as-is and should be verified by qualified security")
        report.append("professionals before remediation.")
        report.append("")
        report.append(f"*Report generated on {self.generated_at}*")

        return "\n".join(report)

    def generate_from_phase_results(
        self,
        phase_results: Dict[str, str],
        target: str = "",
    ) -> str:
        """
        Generate full report from phase-by-phase results.
        phase_results = {"recon": "...", "analis": "...", "eksekutor": "...", "assessor": "..."}
        """
        # Legacy phase text is retained only as a redacted diagnostic appendix.
        # It must never be presented as a finding/report authority because it
        # has no candidate, policy, or evidence linkage.
        report = [
            "# Diagnostic Phase Narrative (Shadow Only)",
            "---",
            "",
            f"**Target:** `{redact(target)}`",
            "",
            "This legacy narrative is informational only. It cannot create findings, severity, status, or evidence. The authoritative report is the structured evidence-linked workflow report.",
            "",
        ]
        phase_names = {
            "recon": "Reconnaissance",
            "analis": "Vulnerability Analysis",
            "eksekutor": "Exploitation Narrative",
            "assessor": "Risk Assessment Narrative",
        }
        for phase_key, phase_name in phase_names.items():
            value = phase_results.get(phase_key)
            if value:
                report.extend([f"## {phase_name} (diagnostic)", "", redact(str(value))[:12000], "", "---", ""])
        report.extend(["## Authority", "", "No validated finding is emitted by this legacy adapter.", ""])
        return "\n".join(report)

    def _risk_rating(self, severity: str) -> str:
        """Map severity ke risk rating."""
        mapping = {
            "Critical": "High",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Info": "Low",
        }
        return mapping.get(severity, "Medium")

    def save_to_file(self, report: str, filepath: str):
        """Simpan report ke file."""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report)

    def to_json(self, findings: List[Dict[str, Any]]) -> str:
        """Export findings ke JSON format."""
        return json.dumps(findings, indent=2, default=str)


# Global instance
report_generator = ReportGenerator()

"""
TARGET STATE PROFILER
=====================
Centralized data store that tracks all information about a target.

This module provides:
- TargetState class: Central data store for target information
- Parser methods: Extract structured data from recon/vuln tool outputs
- State persistence: Save/load target state across sessions
- Context generation: Build LLM-ready context from target state

Usage:
    from core.target_state import TargetState, parse_recon_output, parse_vuln_output
    
    state = TargetState(url="https://target.com")
    state.update_from_recon(recon_output)
    state.update_from_vuln(vuln_output)
    context = state.to_llm_context()
"""

import json
import hashlib
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse


@dataclass
class PortInfo:
    """Information about an open port."""
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    version: str = ""
    banner: str = ""


@dataclass
class EndpointInfo:
    """Information about a discovered endpoint."""
    url: str
    method: str = "GET"
    status_code: int = 0
    parameters: List[str] = field(default_factory=list)
    auth_required: bool = False
    content_type: str = ""
    response_length: int = 0


@dataclass
class TechStack:
    """Detected technology stack."""
    language: str = ""
    framework: str = ""
    cms: str = ""
    server: str = ""
    database: str = ""
    cdn: str = ""
    waf: str = ""
    waf_confidence: str = ""
    other: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityInfo:
    """Information about a detected vulnerability."""
    vuln_type: str
    severity: str
    endpoint: str
    parameter: str = ""
    evidence: str = ""
    cvss: float = 0.0
    cwe: str = ""
    confirmed: bool = False
    external_tool: str = ""


@dataclass
class AuthInfo:
    """Authentication information about the target."""
    login_url: str = ""
    auth_type: str = ""  # "cookie", "bearer", "basic", "oauth"
    has_mfa: bool = False
    session_cookies: str = ""
    auth_bypass_possible: bool = False


class TargetState:
    """
    Centralized state store for target information.
    
    Aggregates outputs from Recon, Vulnerability Analysis, and Exploitation
    phases into a structured format that can be injected into LLM prompts.
    """
    
    def __init__(self, url: str = "", goal: str = ""):
        self.url = url
        self.goal = goal
        self.domain = self._extract_domain(url)
        
        # Core state
        self.ports: List[PortInfo] = []
        self.tech_stack = TechStack()
        self.endpoints: List[EndpointInfo] = []
        self.vulnerabilities: List[VulnerabilityInfo] = []
        self.auth_info = AuthInfo()
        
        # Recon data
        self.subdomains: List[str] = []
        self.dns_records: Dict[str, Any] = {}
        self.ssl_info: Dict[str, Any] = {}
        self.cloud_assets: List[Dict] = []
        self.emails: List[str] = []
        
        # Security controls
        self.waf_detected: str = ""
        self.waf_confidence: str = ""
        self.security_headers: Dict[str, str] = {}
        self.rate_limiting: bool = False
        
        # Scan metadata
        self.scan_start: str = ""
        self.scan_end: str = ""
        self.phases_completed: List[str] = []
        self.external_tools_used: List[str] = []
        
        # Raw outputs for debugging
        self.raw_recon: str = ""
        self.raw_vuln: str = ""
        self.raw_exploit: str = ""

        from core.workflow_models import WorkflowState
        self.workflow = WorkflowState()
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            return urlparse(url).netloc.split(":")[0].lower()
        except:
            return url
    
    def update_from_recon(self, recon_output: str):
        """
        Parse recon output and update target state.
        Handles output from: nmap, subfinder, shodan, censys, etc.
        """
        self.raw_recon = recon_output
        self.phases_completed.append("recon")
        
        # Parse nmap output
        self._parse_nmap_output(recon_output)
        
        # Parse tech stack
        self._parse_tech_stack(recon_output)
        
        # Parse SSL info
        self._parse_ssl_info(recon_output)
        
        # Parse subdomains
        self._parse_subdomains(recon_output)
        
        # Parse WAF detection
        self._parse_waf_detection(recon_output)
        
        # Parse cloud assets
        self._parse_cloud_assets(recon_output)
    
    def update_from_vuln(self, vuln_output: str):
        """
        Parse vulnerability analysis output and update target state.
        Handles output from: nuclei, custom scanners, etc.
        """
        self.raw_vuln = vuln_output
        self.phases_completed.append("vuln_analysis")
        
        # Parse vulnerabilities
        self._parse_vulnerabilities(vuln_output)
        
        # Parse endpoints
        self._parse_endpoints(vuln_output)
        
        # Parse security headers
        self._parse_security_headers(vuln_output)
    
    def update_from_exploit(self, exploit_output: str):
        """
        Parse exploitation output and update target state.
        """
        self.raw_exploit = exploit_output
        self.phases_completed.append("exploitation")
        
        # Parse exploitation results
        self._parse_exploitation_results(exploit_output)
    
    def _parse_nmap_output(self, output: str):
        """Parse nmap scan results."""
        import re
        
        # Parse open ports
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)'
        for match in re.finditer(port_pattern, output):
            port_num = int(match.group(1))
            service = match.group(2)
            version = match.group(3).strip()
            
            self.ports.append(PortInfo(
                port=port_num,
                service=service,
                version=version
            ))
        
        # Parse OS detection
        os_pattern = r'OS details?:\s*(.+)'
        os_match = re.search(os_pattern, output)
        if os_match:
            self.tech_stack.other.append(f"OS: {os_match.group(1)}")
    
    def _parse_tech_stack(self, output: str):
        """Parse technology stack from recon output."""
        output_lower = output.lower()
        
        # Server detection
        if "nginx" in output_lower:
            self.tech_stack.server = "nginx"
        elif "apache" in output_lower:
            self.tech_stack.server = "apache"
        elif "iis" in output_lower:
            self.tech_stack.server = "IIS"
        
        # Language detection
        if "php" in output_lower:
            self.tech_stack.language = "PHP"
        elif "python" in output_lower:
            self.tech_stack.language = "Python"
        elif "node" in output_lower or "javascript" in output_lower:
            self.tech_stack.language = "Node.js"
        elif "java" in output_lower:
            self.tech_stack.language = "Java"
        
        # Framework detection
        if "laravel" in output_lower:
            self.tech_stack.framework = "Laravel"
        elif "django" in output_lower:
            self.tech_stack.framework = "Django"
        elif "express" in output_lower:
            self.tech_stack.framework = "Express"
        elif "spring" in output_lower:
            self.tech_stack.framework = "Spring"
        elif "rails" in output_lower:
            self.tech_stack.framework = "Ruby on Rails"
        
        # CMS detection
        if "wordpress" in output_lower:
            self.tech_stack.cms = "WordPress"
        elif "drupal" in output_lower:
            self.tech_stack.cms = "Drupal"
        elif "joomla" in output_lower:
            self.tech_stack.cms = "Joomla"
        
        # CDN detection
        if "cloudflare" in output_lower:
            self.tech_stack.cdn = "Cloudflare"
        elif "cloudfront" in output_lower:
            self.tech_stack.cdn = "CloudFront"
        elif "akamai" in output_lower:
            self.tech_stack.cdn = "Akamai"
    
    def _parse_ssl_info(self, output: str):
        """Parse SSL/TLS information."""
        import re
        
        # Extract SSL version
        ssl_pattern = r'SSL/TLS Version:\s*(.+)'
        ssl_match = re.search(ssl_pattern, output)
        if ssl_match:
            self.ssl_info["version"] = ssl_match.group(1)
        
        # Extract certificate info
        cert_pattern = r'Issuer:\s*(.+)'
        cert_match = re.search(cert_pattern, output)
        if cert_match:
            self.ssl_info["issuer"] = cert_match.group(1)
    
    def _parse_subdomains(self, output: str):
        """Parse subdomain list from recon output."""
        import re
        
        # Look for subdomain patterns
        subdomain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+' + re.escape(self.domain)
        found = re.findall(subdomain_pattern, output)
        
        for sub in found:
            if sub not in self.subdomains and sub != self.domain:
                self.subdomains.append(sub)
    
    def _parse_waf_detection(self, output: str):
        """Parse WAF detection results."""
        output_lower = output.lower()
        
        wafs = {
            "cloudflare": ["cloudflare", "cf-ray"],
            "aws waf": ["aws waf", "amazon waf"],
            "akamai": ["akamai"],
            "incapsula": ["incapsula", "imperva"],
            "modsecurity": ["modsecurity", "mod_security"],
            "sucuri": ["sucuri"],
            "f5 bigip": ["bigip", "f5"],
        }
        
        for waf_name, indicators in wafs.items():
            for indicator in indicators:
                if indicator in output_lower:
                    self.waf_detected = waf_name
                    self.waf_confidence = "high"
                    self.tech_stack.waf = waf_name
                    break
    
    def _parse_cloud_assets(self, output: str):
        """Parse cloud asset information."""
        import re
        
        # S3 buckets
        s3_pattern = r's3\.amazonaws\.com/([a-zA-Z0-9._-]+)'
        s3_matches = re.findall(s3_pattern, output)
        for bucket in s3_matches:
            self.cloud_assets.append({"type": "S3", "name": bucket})
        
        # Azure blobs
        azure_pattern = r'blob\.core\.windows\.net/([a-zA-Z0-9._-]+)'
        azure_matches = re.findall(azure_pattern, output)
        for blob in azure_matches:
            self.cloud_assets.append({"type": "Azure Blob", "name": blob})
    
    def _parse_vulnerabilities(self, output: str):
        """Parse vulnerability findings from scan output."""
        import re
        
        # Parse severity-based findings
        severity_pattern = r'\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+)'
        for match in re.finditer(severity_pattern, output, re.IGNORECASE):
            severity = match.group(1).upper()
            finding = match.group(2).strip()
            
            self.vulnerabilities.append(VulnerabilityInfo(
                vuln_type=self._guess_vuln_type(finding),
                severity=severity,
                endpoint=self.url,
                evidence=finding[:200]
            ))
    
    def _parse_endpoints(self, output: str):
        """Parse endpoint information from scan output."""
        import re
        
        # Look for URL patterns
        url_pattern = r'(https?://[^\s<>"{}|\\^`\[\]]+)'
        found_urls = re.findall(url_pattern, output)
        
        for url in found_urls:
            if self.domain in url and url not in [e.url for e in self.endpoints]:
                self.endpoints.append(EndpointInfo(url=url))
    
    def _parse_security_headers(self, output: str):
        """Parse security header information."""
        import re
        
        headers_to_check = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy"
        ]
        
        for header in headers_to_check:
            if header.lower() in output.lower():
                if "missing" in output.lower() or "not present" in output.lower():
                    self.security_headers[header] = "MISSING"
                else:
                    self.security_headers[header] = "PRESENT"
    
    def _parse_exploitation_results(self, output: str):
        """Parse exploitation results."""
        # Extract confirmed vulnerabilities
        confirmed_pattern = r'(CONFIRMED|VERIFIED|EXPLOITED)[:\s]*(.+)'
        for match in re.finditer(confirmed_pattern, output, re.IGNORECASE):
            self.vulnerabilities.append(VulnerabilityInfo(
                vuln_type="exploited",
                severity="Critical",
                endpoint=self.url,
                evidence=match.group(2).strip()[:200],
                confirmed=True
            ))
    
    def _guess_vuln_type(self, finding: str) -> str:
        """Guess vulnerability type from finding description."""
        finding_lower = finding.lower()
        
        if any(x in finding_lower for x in ["sql", "injection", "sqli"]):
            return "SQL Injection"
        elif any(x in finding_lower for x in ["xss", "cross-site scripting"]):
            return "XSS"
        elif any(x in finding_lower for x in ["ssrf", "server-side request"]):
            return "SSRF"
        elif any(x in finding_lower for x in ["xxe", "xml external"]):
            return "XXE"
        elif any(x in finding_lower for x in ["ssti", "template injection"]):
            return "SSTI"
        elif any(x in finding_lower for x in ["lfi", "file inclusion", "path traversal"]):
            return "LFI/Path Traversal"
        elif any(x in finding_lower for x in ["idor", "insecure direct"]):
            return "IDOR"
        elif any(x in finding_lower for x in ["csrf", "cross-site request"]):
            return "CSRF"
        elif any(x in finding_lower for x in ["cors"]):
            return "CORS Misconfiguration"
        elif any(x in finding_lower for x in ["header", "security"]):
            return "Security Header Issue"
        else:
            return "Other"
    
    def to_llm_context(self) -> str:
        """
        Generate LLM-ready context string from target state.
        This gets injected into the system prompt before user queries.
        """
        context_parts = []
        
        # Header
        context_parts.append(f"=== TARGET STATE PROFILE ===")
        context_parts.append(f"Target: {self.url}")
        context_parts.append(f"Domain: {self.domain}")
        context_parts.append(f"Goal: {self.goal}")
        context_parts.append("")
        
        # Tech Stack
        context_parts.append("=== TECHNOLOGY STACK ===")
        if self.tech_stack.server:
            context_parts.append(f"Server: {self.tech_stack.server}")
        if self.tech_stack.language:
            context_parts.append(f"Language: {self.tech_stack.language}")
        if self.tech_stack.framework:
            context_parts.append(f"Framework: {self.tech_stack.framework}")
        if self.tech_stack.cms:
            context_parts.append(f"CMS: {self.tech_stack.cms}")
        if self.tech_stack.cdn:
            context_parts.append(f"CDN: {self.tech_stack.cdn}")
        if self.tech_stack.waf:
            context_parts.append(f"WAF: {self.tech_stack.waf} (confidence: {self.waf_confidence})")
        context_parts.append("")
        
        # Open Ports
        if self.ports:
            context_parts.append("=== OPEN PORTS ===")
            for port in self.ports:
                context_parts.append(f"  {port.port}/{port.protocol} - {port.service} {port.version}")
            context_parts.append("")
        
        # Endpoints
        if self.endpoints:
            context_parts.append("=== DISCOVERED ENDPOINTS ===")
            for ep in self.endpoints[:20]:  # Limit to 20
                params = ", ".join(ep.parameters) if ep.parameters else "none"
                context_parts.append(f"  {ep.method} {ep.url} (params: {params})")
            context_parts.append("")
        
        # Vulnerabilities
        if self.vulnerabilities:
            context_parts.append("=== VULNERABILITIES FOUND ===")
            for vuln in self.vulnerabilities[:15]:  # Limit to 15
                confirmed = " [CONFIRMED]" if vuln.confirmed else ""
                context_parts.append(f"  [{vuln.severity}] {vuln.vuln_type}{confirmed}")
                if vuln.evidence:
                    context_parts.append(f"    Evidence: {vuln.evidence[:100]}")
            context_parts.append("")
        
        # Security Headers
        if self.security_headers:
            context_parts.append("=== SECURITY HEADERS ===")
            for header, status in self.security_headers.items():
                context_parts.append(f"  {header}: {status}")
            context_parts.append("")
        
        # Auth Info
        if self.auth_info.login_url:
            context_parts.append("=== AUTHENTICATION ===")
            context_parts.append(f"Login URL: {self.auth_info.login_url}")
            context_parts.append(f"Auth Type: {self.auth_info.auth_type}")
            context_parts.append(f"MFA: {'Yes' if self.auth_info.has_mfa else 'No'}")
            context_parts.append("")
        
        # Scan Summary
        context_parts.append("=== SCAN SUMMARY ===")
        context_parts.append(f"Phases completed: {', '.join(self.phases_completed)}")
        context_parts.append(f"External tools used: {', '.join(self.external_tools_used)}")
        context_parts.append(f"Total endpoints: {len(self.endpoints)}")
        context_parts.append(f"Total vulnerabilities: {len(self.vulnerabilities)}")
        
        return "\n".join(context_parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "url": self.url,
            "domain": self.domain,
            "goal": self.goal,
            "ports": [asdict(p) for p in self.ports],
            "tech_stack": asdict(self.tech_stack),
            "endpoints": [asdict(e) for e in self.endpoints],
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "auth_info": asdict(self.auth_info),
            "subdomains": self.subdomains,
            "dns_records": self.dns_records,
            "ssl_info": self.ssl_info,
            "cloud_assets": self.cloud_assets,
            "emails": self.emails,
            "waf_detected": self.waf_detected,
            "waf_confidence": self.waf_confidence,
            "security_headers": self.security_headers,
            "rate_limiting": self.rate_limiting,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "phases_completed": self.phases_completed,
            "external_tools_used": self.external_tools_used,
            "raw_recon": self.raw_recon,
            "raw_vuln": self.raw_vuln,
            "raw_exploit": self.raw_exploit,
            "workflow": self.workflow.to_dict(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TargetState':
        """Create TargetState from dictionary."""
        state = cls(url=data.get("url", ""), goal=data.get("goal", ""))
        
        state.ports = [PortInfo(**p) for p in data.get("ports", [])]
        state.tech_stack = TechStack(**data.get("tech_stack", {}))
        state.endpoints = [EndpointInfo(**e) for e in data.get("endpoints", [])]
        state.vulnerabilities = [VulnerabilityInfo(**v) for v in data.get("vulnerabilities", [])]
        state.auth_info = AuthInfo(**data.get("auth_info", {}))
        state.subdomains = data.get("subdomains", [])
        state.dns_records = data.get("dns_records", {})
        state.ssl_info = data.get("ssl_info", {})
        state.cloud_assets = data.get("cloud_assets", [])
        state.emails = data.get("emails", [])
        state.waf_detected = data.get("waf_detected", "")
        state.waf_confidence = data.get("waf_confidence", "")
        state.security_headers = data.get("security_headers", {})
        state.rate_limiting = data.get("rate_limiting", False)
        state.scan_start = data.get("scan_start", "")
        state.scan_end = data.get("scan_end", "")
        state.phases_completed = data.get("phases_completed", [])
        state.external_tools_used = data.get("external_tools_used", [])
        state.raw_recon = data.get("raw_recon", "")
        state.raw_vuln = data.get("raw_vuln", "")
        state.raw_exploit = data.get("raw_exploit", "")
        from core.workflow_models import WorkflowState
        state.workflow = WorkflowState.from_dict(data.get("workflow"))
        
        return state
    
    def get_summary(self) -> str:
        """Get a concise summary of the target state."""
        vuln_counts = {}
        for v in self.vulnerabilities:
            vuln_counts[v.severity] = vuln_counts.get(v.severity, 0) + 1
        
        summary = f"Target: {self.domain}\n"
        summary += f"Tech: {self.tech_stack.server or 'Unknown'} / {self.tech_stack.language or 'Unknown'} / {self.tech_stack.framework or 'Unknown'}\n"
        summary += f"WAF: {self.waf_detected or 'None'}\n"
        summary += f"Ports: {len(self.ports)} open\n"
        summary += f"Endpoints: {len(self.endpoints)} discovered\n"
        summary += f"Vulnerabilities: {len(self.vulnerabilities)} total"
        
        if vuln_counts:
            summary += " ("
            summary += ", ".join(f"{k}: {v}" for k, v in vuln_counts.items())
            summary += ")"
        
        return summary


# Global target state instance
_current_target_state: Optional[TargetState] = None


def get_target_state() -> Optional[TargetState]:
    """Get the current target state."""
    return _current_target_state


def set_target_state(state: TargetState):
    """Set the current target state."""
    global _current_target_state
    _current_target_state = state


def create_target_state(url: str, goal: str = "") -> TargetState:
    """Create and set a new target state."""
    state = TargetState(url=url, goal=goal)
    set_target_state(state)
    return state


def parse_recon_output(output: str) -> Dict[str, Any]:
    """
    Parse recon output and return structured data.
    Used by agents to extract information from tool outputs.
    """
    state = TargetState()
    state.update_from_recon(output)
    return state.to_dict()


def parse_vuln_output(output: str) -> Dict[str, Any]:
    """
    Parse vulnerability analysis output and return structured data.
    Used by agents to extract vulnerability information.
    """
    state = TargetState()
    state.update_from_vuln(output)
    return state.to_dict()

import subprocess
import json
import os
from langchain.tools import tool
from core.cancellation import check_cancelled
from tools.custom_tools import exec_logger

@tool("run_nuclei_scan")
def run_nuclei_scan(url: str, templates: str = "", severity: str = "", stealth: bool = False) -> str:
    """
    Melakukan vulnerability scanning using Nuclei dengan template pilihan 
    (cve, misconfig, exposure, takeover). Sangat efektif untuk mendeteksi CVE terbaru 
    dan kesalahan konfigurasi server secara cepat.
    
    Args:
        url: Target URL
        templates: Comma-separated template tags (e.g., "cve,xss,sqli") - optional
        severity: Comma-separated severity levels (e.g., "high,critical") - optional
        stealth: Enable stealth mode (slower but less detectable) - optional
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    target = url.strip()
    output_file = f"nuclei_res_{os.getpid()}.json"
    
    # ── Build command ─────────────────────────────────────────────────────────
    cmd = [
        "nuclei",
        "-u", target,
        "-jsonl",
        "-o", output_file,
        "-silent",
    ]
    
    # Template selection
    if templates:
        template_list = [t.strip() for t in templates.split(",")]
        cmd.extend(["-tags", ",".join(template_list)])
    else:
        # Default comprehensive scan
        cmd.extend(["-tags", "cve,misconfig,exposure,takeover,default-login,panel,tech"])
    
    # Severity filter
    if severity:
        cmd.extend(["-severity", severity])
    else:
        cmd.extend(["-severity", "low,medium,high,critical"])
    
    # Stealth mode
    if stealth or os.environ.get("STEALTH_MODE", "0") == "1":
        cmd.extend(["-rl", "10", "-bs", "3", "-delay", "1s"])
        exec_logger.add_log("Nuclei Scanner", "INFO", "Stealth mode enabled: slower scan, less detectable")
    else:
        cmd.extend(["-rl", "20", "-bs", "5"])
    
    # ── Additional options ────────────────────────────────────────────────────
    cmd.extend([
        "-timeout", "10",
        "-retries", "2",
        "-retry-interval", "2",
        "-bulk-size", "25",
        "-concurrency", "10",
    ])
    
    exec_logger.add_log("Nuclei Scanner", "START", f"Starting nuclei scan pada {target}")
    exec_logger.add_log("Nuclei Scanner", "PROCESSING", f"Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)
        
        if not os.path.exists(output_file):
            return f"Nuclei scan selesai untuk {target}, namun not found kerentanan yang cocok."
            
        findings = []
        with open(output_file, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        data = json.loads(line)
                        info = data.get("info", {})
                        findings.append({
                            "template_id": data.get("template-id"),
                            "name": info.get("name"),
                            "severity": info.get("severity"),
                            "type": data.get("type"),
                            "matched_at": data.get("matched-at"),
                            "description": info.get("description", ""),
                            "extracted_results": data.get("extracted-results", []),
                            "curl_command": data.get("curl-command", ""),
                            "matcher_name": data.get("matcher-name", ""),
                        })
                    except json.JSONDecodeError:
                        continue
                    
        os.remove(output_file)
        
        if not findings:
            return f"Nuclei scan selesai. Target {target} bersih dari signature template yang ditesting."
        
        # ── Sort by severity ──────────────────────────────────────────────────
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 5))
        
        # ── Build output ──────────────────────────────────────────────────────
        output = f"=== NUCLEI SCAN RESULTS FOR {target} ===\n"
        output += f"Total findings: {len(findings)}\n\n"
        
        # Group by severity
        by_severity = {}
        for f in findings:
            sev = f.get("severity", "info")
            by_severity.setdefault(sev, []).append(f)
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev not in by_severity:
                continue
            items = by_severity[sev]
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(sev, "❓")
            output += f"\n{emoji} [{sev.upper()}] — {len(items)} finding(s)\n"
            for f in items:
                output += f"  ▸ {f['name']} ({f['template_id']})\n"
                output += f"    Type: {f['type']} | Matched: {f['matched_at']}\n"
                if f['description']:
                    output += f"    Description: {f['description'][:200]}\n"
                if f['extracted_results']:
                    output += f"    Extracted: {', '.join(f['extracted_results'][:5])}\n"
                if f['curl_command']:
                    output += f"    Curl: {f['curl_command'][:150]}\n"
                
        return output

    except subprocess.TimeoutExpired:
        if os.path.exists(output_file):
            os.remove(output_file)
        return f"Error: Scan Nuclei ke {target} stopped karena timeout (lebih dari 10 menit)."
    except Exception as e:
        if os.path.exists(output_file):
            os.remove(output_file)
        return f"Error saat menjalankan Nuclei scan: {str(e)}"
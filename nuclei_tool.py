import subprocess
import json
import os
from langchain.tools import tool
from cancellation import check_cancelled
from custom_tools import exec_logger

@tool("run_nuclei_scan")
def run_nuclei_scan(url: str) -> str:
    """
    Melakukan vulnerability scanning menggunakan Nuclei dengan template pilihan 
    (cve, misconfig, exposure, takeover). Sangat efektif untuk mendeteksi CVE terbaru 
    dan kesalahan konfigurasi server secara cepat.
    """
    if check_cancelled(exec_logger): return "EKSEKUSI DIBATALKAN: job di-cancel oleh user."

    target = url.strip()
    output_file = f"nuclei_res_{os.getpid()}.json"
    
    cmd = [
        "nuclei",
        "-u", target,
        "-tags", "cve,misconfig,exposure,takeover",
        "-severity", "low,medium,high,critical",
        "-jsonl",
        "-o", output_file,
        "-rl", "20",
        "-bs", "5",
        "-silent"
    ]
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)
        
        if not os.path.exists(output_file):
            return f"Nuclei scan selesai untuk {target}, namun tidak ditemukan kerentanan yang cocok."
            
        findings = []
        with open(output_file, "r") as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    info = data.get("info", {})
                    findings.append({
                        "template_id": data.get("template-id"),
                        "name": info.get("name"),
                        "severity": info.get("severity"),
                        "type": data.get("type"),
                        "matched_at": data.get("matched-at"),
                        "description": info.get("description", ""),
                        "extracted_results": data.get("extracted-results", [])
                    })
                    
        os.remove(output_file)
        
        if not findings:
            return f"Nuclei scan selesai. Target {target} bersih dari signature template yang ditesting."
            
        output = f"=== NUCLEI SCAN RESULTS FOR {target} ===\n"
        for f in findings:
            output += f"\n[-] [{f['severity'].upper()}] {f['name']} ({f['template_id']})\n"
            output += f"    Type: {f['type']} | Matched: {f['matched_at']}\n"
            if f['description']:
                output += f"    Description: {f['description']}\n"
            if f['extracted_results']:
                output += f"    Extracted: {', '.join(f['extracted_results'])}\n"
                
        return output

    except subprocess.TimeoutExpired:
        if os.path.exists(output_file):
            os.remove(output_file)
        return f"Error: Scan Nuclei ke {target} dihentikan karena timeout (lebih dari 10 menit)."
    except Exception as e:
        if os.path.exists(output_file):
            os.remove(output_file)
        return f"Error saat menjalankan Nuclei scan: {str(e)}"
"""
TRANSLATE SCRIPT — Indonesian → English Bulk Translation
==========================================================
Translate Indonesian strings dalam Python files ke English.

Usage:
    python translate_to_english.py
"""

import re
import os

# Translation dictionary: Indonesian → English
TRANSLATIONS = {
    # Common verbs
    "Starting": "Starting",
    "Menganalisis": "Analyzing",
    "Menguji": "Testing",
    "Mengirim": "Sending",
    "Mengambil": "Fetching",
    "Mengecek": "Checking",
    "Membuka": "Opening",
    "Menjalankan": "Running",
    "Menunggu": "Waiting",
    "Menyimpan": "Saving",
    "Menghapus": "Deleting",
    "Memperbarui": "Updating",
    "Membuat": "Creating",
    "Mendeteksi": "Detecting",
    "Mencari": "Searching",
    "Membaca": "Reading",
    "Menulis": "Writing",
    "Memproses": "Processing",
    "Mengirim": "Sending",
    "Menerima": "Receiving",
    "Mengunduh": "Downloading",
    "Mengunggah": "Uploading",
    "Menampilkan": "Displaying",
    "Mengubah": "Changing",
    "Mengganti": "Replacing",
    "Menambahkan": "Adding",
    "Mengurangi": "Reducing",
    "Menghitung": "Calculating",
    "Membandingkan": "Comparing",
    "Mengelompokkan": "Grouping",
    "Memfilter": "Filtering",
    "Mencari": "Searching",
    "Menemukan": "Finding",
    "Menghasilkan": "Generating",
    "Mengirim": "Sending",
    "Menerima": "Receiving",
    "Memvalidasi": "Validating",
    "Mengeksekusi": "Executing",
    "Menginisialisasi": "Initializing",
    "Mengakhiri": "Finishing",
    "Menghentikan": "Stopping",
    "Membatalkan": "Cancelling",
    "Mecontinue": "Continuing",
    "Mengulang": "Retrying",
    "Mengabaikan": "Skipping",
    "Using": "Using",
    "Menangani": "Handling",
    "Mengirim": "Sending",
    "Mengambil": "Fetching",
    "Menyimpan": "Saving",
    "Memuat": "Loading",
    "Mengirim": "Sending",
    "Membaca": "Reading",
    "Menulis": "Writing",
    "Menghapus": "Deleting",
    "Memperbarui": "Updating",
    "Membuat": "Creating",
    "Menghapus": "Deleting",
    "Starting": "Starting",
    "Menghentikan": "Stopping",
    "Menjalankan": "Running",
    "Mengirim": "Sending",
    "Menerima": "Receiving",
    "Memproses": "Processing",
    "Menyimpan": "Saving",
    "Memuat": "Loading",
    "Mengambil": "Fetching",
    "Mengirim": "Sending",
    "Menerima": "Receiving",
    "Memvalidasi": "Validating",
    "Mengeksekusi": "Executing",
    "Menginisialisasi": "Initializing",
    "Mengakhiri": "Finishing",
    "Menghentikan": "Stopping",
    "Membatalkan": "Cancelling",
    "Mecontinue": "Continuing",
    "Mengulang": "Retrying",
    "Mengabaikan": "Skipping",
    "Using": "Using",
    "Menangani": "Handling",
    
    # Common nouns
    "Target": "Target",
    "URL": "URL",
    "Endpoint": "Endpoint",
    "Parameter": "Parameter",
    "Header": "Header",
    "Response": "Response",
    "Request": "Request",
    "Payload": "Payload",
    "Vulnerability": "Vulnerability",
    "Findings": "Findings",
    "Results": "Results",
    "Report": "Report",
    "Session": "Session",
    "Token": "Token",
    "Cookie": "Cookie",
    "Cache": "Cache",
    "Proxy": "Proxy",
    "Payload": "Payload",
    "Scan": "Scan",
    "Tool": "Tool",
    "Phase": "Phase",
    "Step": "Step",
    "Log": "Log",
    "Error": "Error",
    "Warning": "Warning",
    "Success": "Success",
    "Failed": "Failed",
    "Timeout": "Timeout",
    "Connection": "Connection",
    "Authentication": "Authentication",
    "Authorization": "Authorization",
    "Permission": "Permission",
    "Access": "Access",
    "Control": "Control",
    "Security": "Security",
    "Configuration": "Configuration",
    "Configuration": "Configuration",
    "Setting": "Setting",
    "Option": "Option",
    "Mode": "Mode",
    "Type": "Type",
    "Status": "Status",
    "State": "State",
    "Level": "Level",
    "Severity": "Severity",
    "Risk": "Risk",
    "Impact": "Impact",
    "Evidence": "Evidence",
    "Detail": "Detail",
    "Description": "Description",
    "Summary": "Summary",
    "Conclusion": "Conclusion",
    "Recommendation": "Recommendation",
    "Mitigation": "Mitigation",
    "Remediation": "Remediation",
    
    # Common phrases
    "Cancelled": "Cancelled",
    "Rejected": "Rejected",
    "Approved": "Approved",
    "Success": "Success",
    "Failed": "Failed",
    "Error": "Error",
    "Warning": "Warning",
    "Info": "Info",
    "Processing": "Processing",
    "Starting": "Starting",
    "Finished": "Finished",
    "Complete": "Complete",
    "Incomplete": "Incomplete",
    "Pending": "Pending",
    "Running": "Running",
    "Stopped": "Stopped",
    "Paused": "Paused",
    "Resumed": "Resumed",
    "Retry": "Retry",
    "Skip": "Skip",
    "Ignore": "Ignore",
    "Continue": "Continue",
    "Break": "Break",
    "Return": "Return",
    "Exit": "Exit",
    "Quit": "Quit",
    
    # Technical terms
    "Parameter found": "Parameter found",
    "Parameter not found": "Parameter not found",
    "Endpoint found": "Endpoint found",
    "Endpoint not found": "Endpoint not found",
    "Vulnerability found": "Vulnerability found",
    "Vulnerability not found": "Vulnerability not found",
    "Request success": "Request successful",
    "Request failed": "Request failed",
    "Response received": "Response received",
    "Response timeout": "Response timeout",
    "Connection timeout": "Connection timeout",
    "Connection refused": "Connection refused",
    "SSL error": "SSL error",
    "DNS error": "DNS error",
    "Proxy error": "Proxy error",
    "Rate limit exceeded": "Rate limit exceeded",
    "Authentication required": "Authentication required",
    "Authorization denied": "Authorization denied",
    "Permission denied": "Permission denied",
    "File not found": "File not found",
    "Directory not found": "Directory not found",
    "Invalid input": "Invalid input",
    "Invalid format": "Invalid format",
    "Invalid URL": "Invalid URL",
    "Invalid parameter": "Invalid parameter",
    "Missing parameter": "Missing parameter",
    "Required parameter": "Required parameter",
    "Optional parameter": "Optional parameter",
    "Default value": "Default value",
    "Custom value": "Custom value",
    
    # UI strings
    "Menunggu persetujuan": "Waiting for approval",
    "Meminta persetujuan": "Requesting approval",
    "Persetujuan required": "Approval required",
    "Persetujuan granted": "Approval granted",
    "Persetujuan rejected": "Approval denied",
    "Timeout - default rejected": "Timeout - default rejected",
    "Job di-cancel oleh user": "Job cancelled by user",
    "Job selesai": "Job completed",
    "Job error": "Job error",
    "Job running": "Job running",
    "Job queued": "Job queued",
    "Job cancelled": "Job cancelled",
    "Scope target rejected": "Target scope rejected",
    "Scope target received": "Target scope accepted",
    "Scope not yet configured": "Scope not configured",
    "Target di luar scope": "Target out of scope",
    "Target dalam scope": "Target in scope",
    
    # Log messages
    "Starting scan": "Starting scan",
    "Scan selesai": "Scan completed",
    "Scan cancelled": "Scan cancelled",
    "Scan error": "Scan error",
    "Scan timeout": "Scan timeout",
    "Testing": "Testing",
    "Scanning": "Scanning",
    "Analyzing": "Analyzing",
    "Exploiting": "Exploiting",
    "Assessing": "Assessing",
    "Reporting": "Reporting",
    
    # Common patterns in docstrings
    "Tool ini": "This tool",
    "Fungsi ini": "This function",
    "Method ini": "This method",
    "Class ini": "This class",
    "Module ini": "This module",
    "File ini": "This file",
    "Variabel ini": "This variable",
    "Parameter ini": "This parameter",
    "Return value": "Return value",
    "Raises": "Raises",
    "Example": "Example",
    "Usage": "Usage",
    "Note": "Note",
    "Warning": "Warning",
    "See also": "See also",
    "Since": "Since",
    "Version": "Version",
    "Author": "Author",
    "Date": "Date",
    "License": "License",
    "Copyright": "Copyright",
}

def translate_file(filepath):
    """Translate Indonesian strings dalam file ke English."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    changes = 0
    
    # Apply translations
    for indo, english in TRANSLATIONS.items():
        # Case-insensitive replacement dalam string literals
        pattern = re.compile(r'f?"[^"]*' + re.escape(indo) + r'[^"]*"', re.IGNORECASE)
        if pattern.search(content):
            content = pattern.sub(lambda m: m.group(0).replace(indo, english), content)
            changes += 1
    
    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return changes
    return 0

def main():
    """Main function."""
    print("=== Indonesian → English Translation Script ===\n")
    
    total_changes = 0
    files_changed = 0
    
    for py_file in sorted(os.listdir('.')):
        if not py_file.endswith('.py') or '__pycache__' in py_file:
            continue
        if py_file == 'translate_to_english.py':
            continue
            
        changes = translate_file(py_file)
        if changes > 0:
            print(f"  {py_file}: {changes} translations")
            total_changes += changes
            files_changed += 1
    
    print(f"\nTotal: {total_changes} translations across {files_changed} files")
    print("Done! Review changes manually for accuracy.")

if __name__ == "__main__":
    main()

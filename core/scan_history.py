"""
SCAN HISTORY — Scan History Tracking & Comparison
===================================================
Track semua scan results dan bandingin antar scan.

Usage:
    from scan_history import scan_history

    # Save scan result
    scan_history.save(target, findings, session_id)

    # Compare with previous scan
    comparison = scan_history.compare(target, current_findings)

    # Get history
    history = scan_history.get_history(target, limit=10)
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


def _logger():
    try:
        from custom_tools import exec_logger
        return exec_logger
    except Exception:
        return None


class ScanHistory:
    """
    Track scan results dan bandingin antar scan.
    Uses Supabase untuk persistence.
    """

    def __init__(self):
        self._supabase = None

    def _get_supabase(self):
        """Lazy init Supabase client."""
        if self._supabase is None:
            try:
                import os
                from supabase import create_client
                url = os.environ.get("SUPABASE_URL")
                key = os.environ.get("SUPABASE_KEY")
                if url and key:
                    self._supabase = create_client(url, key)
            except Exception:
                pass
        return self._supabase

    def save(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        session_id: Optional[str] = None,
        summary: Optional[Dict] = None,
    ) -> bool:
        """
        Save scan result ke Supabase.
        """
        sb = self._get_supabase()
        if not sb:
            if _logger():
                _logger().add_log("Scan History", "WARNING", "Supabase not available")
            return False

        domain = _domain_of(target)

        # Build scan record
        scan_record = {
            "target": target,
            "domain": domain,
            "scan_date": datetime.now().isoformat(),
            "session_id": session_id,
            "total_findings": len(findings),
            "critical_count": len([f for f in findings if f.get("severity") == "Critical"]),
            "high_count": len([f for f in findings if f.get("severity") == "High"]),
            "medium_count": len([f for f in findings if f.get("severity") == "Medium"]),
            "low_count": len([f for f in findings if f.get("severity") == "Low"]),
            "findings_summary": [
                {
                    "name": f.get("name", "Unknown"),
                    "severity": f.get("severity", "Info"),
                    "vuln_type": f.get("vuln_type", "unknown"),
                    "url": f.get("url", ""),
                    "parameter": f.get("parameter", ""),
                }
                for f in findings
            ],
            "raw_findings": json.dumps(findings, default=str),
            "summary": summary or {},
        }

        try:
            sb.table("scan_history").insert(scan_record).execute()
            if _logger():
                _logger().add_log("Scan History", "SUCCESS",
                    f"Saved scan result: {len(findings)} findings for {domain}")
            return True
        except Exception as e:
            if _logger():
                _logger().add_log("Scan History", "ERROR", f"Save failed: {str(e)[:100]}")
            return False

    def get_history(
        self,
        target: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Get scan history untuk target.
        """
        sb = self._get_supabase()
        if not sb:
            return []

        domain = _domain_of(target)

        try:
            res = (
                sb.table("scan_history")
                .select("*")
                .eq("domain", domain)
                .order("scan_date", desc=True)
                .limit(limit)
                .execute()
            )
            return res.data or []
        except Exception as e:
            if _logger():
                _logger().add_log("Scan History", "ERROR", f"Load failed: {str(e)[:100]}")
            return []

    def get_latest(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Get scan result terakhir untuk target.
        """
        history = self.get_history(target, limit=1)
        return history[0] if history else None

    def compare(
        self,
        target: str,
        current_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Bandingin current findings dengan scan senot yetnya.
        
        Return:
            {
                "has_previous_scan": bool,
                "previous_scan_date": str,
                "changes": {
                    "new_findings": [...],
                    "fixed_findings": [...],
                    "unchanged_findings": [...]
                },
                "severity_trend": "improving" | "worsening" | "stable",
                "summary": str
            }
        """
        previous = self.get_latest(target)

        if not previous:
            return {
                "has_previous_scan": False,
                "changes": {
                    "new_findings": current_findings,
                    "fixed_findings": [],
                    "unchanged_findings": [],
                },
                "severity_trend": "new",
                "summary": "First scan — no previous data to compare.",
            }

        # Parse previous findings
        try:
            prev_findings = json.loads(previous.get("raw_findings", "[]"))
        except Exception:
            prev_findings = []

        # Build fingerprints for comparison
        prev_fingerprints = set()
        for f in prev_findings:
            fp = self._fingerprint(f)
            prev_fingerprints.add(fp)

        curr_fingerprints = set()
        curr_by_fp = {}
        for f in current_findings:
            fp = self._fingerprint(f)
            curr_fingerprints.add(fp)
            curr_by_fp[fp] = f

        prev_by_fp = {}
        for f in prev_findings:
            fp = self._fingerprint(f)
            prev_by_fp[fp] = f

        # Find changes
        new_fps = curr_fingerprints - prev_fingerprints
        fixed_fps = prev_fingerprints - curr_fingerprints
        unchanged_fps = curr_fingerprints & prev_fingerprints

        new_findings = [curr_by_fp[fp] for fp in new_fps]
        fixed_findings = [prev_by_fp[fp] for fp in fixed_fps]
        unchanged_findings = [curr_by_fp[fp] for fp in unchanged_fps]

        # Severity trend
        prev_severity = self._severity_score(previous)
        curr_severity = self._severity_score({"critical_count": len([f for f in current_findings if f.get("severity") == "Critical"]), "high_count": len([f for f in current_findings if f.get("severity") == "High"]), "medium_count": len([f for f in current_findings if f.get("severity") == "Medium"])})

        if curr_severity > prev_severity:
            trend = "worsening"
        elif curr_severity < prev_severity:
            trend = "improving"
        else:
            trend = "stable"

        # Build summary
        summary_parts = []
        if new_findings:
            summary_parts.append(f"{len(new_findings)} new findings")
        if fixed_findings:
            summary_parts.append(f"{len(fixed_findings)} fixed")
        if unchanged_findings:
            summary_parts.append(f"{len(unchanged_findings)} unchanged")

        return {
            "has_previous_scan": True,
            "previous_scan_date": previous.get("scan_date", "Unknown"),
            "previous_total": previous.get("total_findings", 0),
            "current_total": len(current_findings),
            "changes": {
                "new_findings": new_findings,
                "fixed_findings": fixed_findings,
                "unchanged_findings": unchanged_findings,
            },
            "severity_trend": trend,
            "summary": "; ".join(summary_parts) if summary_parts else "No changes detected.",
        }

    def _fingerprint(self, finding: Dict) -> str:
        """Generate fingerprint buat comparison."""
        # Gabungkan vuln_type + url + parameter sebagai unique ID
        vuln_type = finding.get("vuln_type", finding.get("type", "unknown"))
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        return f"{vuln_type}:{url}:{param}"

    def _severity_score(self, data: Dict) -> int:
        """Calculate severity score buat trend comparison."""
        return (
            data.get("critical_count", 0) * 4 +
            data.get("high_count", 0) * 3 +
            data.get("medium_count", 0) * 2 +
            data.get("low_count", 0) * 1
        )

    def format_comparison(self, comparison: Dict) -> str:
        """
        Format comparison result jadi readable string.
        """
        if not comparison.get("has_previous_scan"):
            return "This is the first scan for this target. No previous data to compare."

        parts = []
        parts.append(f"**Previous scan:** {comparison.get('previous_scan_date', 'Unknown')}")
        parts.append(f"**Previous total:** {comparison.get('previous_total', 0)} findings")
        parts.append(f"**Current total:** {comparison.get('current_total', 0)} findings")
        parts.append(f"**Trend:** {comparison.get('severity_trend', 'stable').upper()}")
        parts.append("")

        changes = comparison.get("changes", {})

        new = changes.get("new_findings", [])
        if new:
            parts.append(f"**NEW findings ({len(new)}):**")
            for f in new:
                parts.append(f"  - [{f.get('severity', '?')}] {f.get('name', 'Unknown')}")

        fixed = changes.get("fixed_findings", [])
        if fixed:
            parts.append(f"**FIXED ({len(fixed)}):**")
            for f in fixed:
                parts.append(f"  - [{f.get('severity', '?')}] {f.get('name', 'Unknown')}")

        unchanged = changes.get("unchanged_findings", [])
        if unchanged:
            parts.append(f"**UNCHANGED ({len(unchanged)}):**")
            for f in unchanged[:5]:  # Limit
                parts.append(f"  - [{f.get('severity', '?')}] {f.get('name', 'Unknown')}")

        return "\n".join(parts)


# Global instance
scan_history = ScanHistory()

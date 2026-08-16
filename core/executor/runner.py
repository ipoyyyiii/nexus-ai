"""Stateful executor: runs exploit plan steps with differ scoring + re-plan loop."""

from typing import Any, Dict, List
from core.cancellation import check_cancelled
from engines.response_differ import ResponseDiffer

differ = ResponseDiffer()
_differ_baseline = None

def _ensure_baseline(target: str):
    global _differ_baseline
    if _differ_baseline is None:
        try:
            _differ_baseline = differ.capture_baseline(target)
        except Exception:
            _differ_baseline = {}
    return _differ_baseline

def run_chain(chain: List[str], target: str, tool_map: Dict[str, Any], goal: str = "") -> List[Dict[str, Any]]:
    results = []
    baseline = _ensure_baseline(target)
    max_chains = 3
    chains_tried = 0
    for step in chain[:5]:
        if check_cancelled(None):
            break
        if chains_tried >= max_chains:
            break
        tool = tool_map.get(step)
        if not tool:
            results.append({"step": step, "error": "tool not found", "score": 0})
            continue
        try:
            out = tool.invoke({"url": target}) if hasattr(tool, "invoke") else tool(target)
            text = str(out)
            # Differ scoring
            score = 0.0
            try:
                fake_resp = {"body": text, "status_code": 200, "headers": {}, "body_hash": ""}
                cmp = differ.compare(baseline, fake_resp, payload=step)
                score = cmp.get("vulnerability_score", 0)
            except Exception:
                pass
            results.append({"step": step, "output": text[:2000], "score": score})
            # Re-plan if low score: propose alternative chain
            if score < 0.3 and goal:
                try:
                    from core.exploit_planner import propose_plans
                    from core.target_state import get_target_state
                    ts = get_target_state()
                    surf = getattr(ts, "attack_surface", {}) if ts else {}
                    if isinstance(surf, dict):
                        surf["_last_response"] = {"step": step, "score": score, "body": text[:500]}
                        # WAF hint from waf_bypass
                        try:
                            from engines.waf_bypass import waf_bypass
                            surf["_waf_hint"] = ", ".join([p[0][:40] for p in waf_bypass.get_sqli_payloads()[:2]])
                        except Exception:
                            pass
                    alt = propose_plans(goal, surf, {})
                    if alt and alt[0].get("chain"):
                        chains_tried += 1
                        results.append({"step": "re-plan", "pivot_chain": alt[0]["chain"][:3], "reason": f"score {score} low, pivoting {chains_tried}/{max_chains}"})
                        if chains_tried >= max_chains:
                            break
                except Exception:
                    pass
        except Exception as e:
            results.append({"step": step, "error": str(e)[:500], "score": 0})
    return results

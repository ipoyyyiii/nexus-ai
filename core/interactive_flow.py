"""
INTERACTIVE CO-PILOT FLOW
=========================
Refactored CrewAI flow for Interactive Pentest Co-Pilot.

Architecture:
- Phase 1: Automated Data Gathering (Recon & Vuln Scanner Agents)
- Phase 2: Interactive Consultation (Co-Pilot Chat Loop)
- Phase 3: Automated Synthesis & Reporting (Risk Assessment Agent)
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from crewai import Agent, Task, Crew
from core.target_state import TargetState, create_target_state, get_target_state


def build_phase1_agents(target: str, goal: str, memory_context: str,
                         llm_recon, llm_analis, all_results: dict,
                         scan_preset: str = "full", session_id: str = "",
                         recommended_tools: Optional[List[str]] = None,
                         planner_context: Optional[Dict[str, Any]] = None):
    """
    Build Phase 1 agents for automated data gathering.
    Returns list of (agent, task, phase_name) tuples.
    """
    from tools.human_recon_crawl import human_recon_crawl
    from tools import (
        recon_target, enumerate_dns_subdomains, analyze_ssl_tls,
        browser_screenshot, browser_extract_surface,
        browser_intercept_requests, browser_check_security_headers,
        browser_extract_js_secrets, analyze_js_deep,
        param_discovery_get, param_discovery_headers,
        detect_subdomain_takeover, report_new_endpoint, wayback_scraper, github_dorking,
        recon_advanced, misconfiguration_scanner,
        client_side_security_scanner, mixed_content_scanner, asn_ip_mapper,
        postmessage_vulnerability_scanner, shodan_scanner, censys_scanner,
        baca_log_burp, scan_sql_injection, detect_xss_csrf,
        scan_lfi_rfi, test_header_injection,
        browser_simulate_form, browser_find_open_redirect,
        param_discovery_post, run_nuclei_scan,
        graphql_tester, cors_tester, ssti_tester,
        blind_sqli_scanner, nosql_injection_scanner,
        ldap_injection_scanner, xpath_injection_scanner,
        stored_xss_scanner, dom_xss_scanner, jsonp_injection_scanner,
        access_control_scanner,
        authorization_differential_replay,
        csrf_exploit_scanner, mass_assignment_scanner, http_method_tampering_scanner,
        command_injection_scanner, log_injection_scanner, csv_injection_scanner,
        prototype_pollution_scanner,
        web_cache_poisoning_scanner, cache_deception_scanner, idor_uuid_scanner,
        html_injection_scanner, ssi_injection_scanner, hpp_scanner,
        scan_ssrf, ssrf_advanced_scanner, xxe_tester,
        file_upload_scanner, session_management_scanner, test_jwt_weakness,
        websocket_security_scanner,
        browser_workflow_discovery, stateful_browser_workflow,
        business_invariant_evaluator,
    )
    
    from core.structured_runner import structured_crewai_tool

    def langchain_to_crewai(lc_tool):
        category = "recon" if lc_tool is human_recon_crawl else "scanner"
        try:
            from api import session_store
        except Exception:
            session_store = None
        return structured_crewai_tool(
            lc_tool, session_id=session_id, target=target,
            category=category, session_store=session_store,
        )

    phases = []
    
    # ── Recon Agent ────────────────────────────────────────────────────────────
    recon_agent = Agent(
        role="Advanced Reconnaissance & Intel Gatherer",
        goal="Deep recon: infrastructure, tech-stack, WAF, DNS, SSL, browser-based surface mapping.",
        backstory="Elite Intel Red Team level." + (f"\n{memory_context}" if memory_context else ""),
        llm=llm_recon,
        tools=[langchain_to_crewai(t) for t in [human_recon_crawl]],

        verbose=True
    )
    recon_task = Task(
        description=f"Active Recon target: {target}. Use human_recon_crawl with url={target}, goal={goal} and session context. It will click one-by-one and capture XHR/JS.",
        expected_output="Complete infrastructure intelligence report in GFM markdown format.",
        agent=recon_agent
    )
    phases.append(("recon", recon_agent, recon_task, "Reconnaissance"))
    
    # Respect scan preset: recon-only skips vuln agent entirely
    if scan_preset == "recon-only":
        return phases

    # ── Vulnerability Analysis Agent ──────────────────────────────────────────
    vuln_tool_map = {
        "scan_sql_injection": scan_sql_injection,
        "blind_sqli_scanner": blind_sqli_scanner,
        "detect_xss_csrf": detect_xss_csrf,
        "dom_xss_scanner": dom_xss_scanner,
        "stored_xss_scanner": stored_xss_scanner,
        "scan_ssrf": scan_ssrf,
        "ssrf_advanced_scanner": ssrf_advanced_scanner,
        "xxe_tester": xxe_tester,
        "ssti_tester": ssti_tester,
        "command_injection_scanner": command_injection_scanner,
        "scan_lfi_rfi": scan_lfi_rfi,
        "authorization_differential_replay": authorization_differential_replay,
        "access_control_scanner": access_control_scanner,
        "browser_find_open_redirect": browser_find_open_redirect,
        "cors_tester": cors_tester,
        "graphql_tester": graphql_tester,
        "csrf_exploit_scanner": csrf_exploit_scanner,
        "mass_assignment_scanner": mass_assignment_scanner,
        "file_upload_scanner": file_upload_scanner,
        "session_management_scanner": session_management_scanner,
        "test_jwt_weakness": test_jwt_weakness,
        "websocket_security_scanner": websocket_security_scanner,
        "param_discovery_post": param_discovery_post,
        "run_nuclei_scan": run_nuclei_scan,
        "browser_workflow_discovery": browser_workflow_discovery,
        "stateful_browser_workflow": stateful_browser_workflow,
        "business_invariant_evaluator": business_invariant_evaluator,
    }
    default_vuln_tools = [
        baca_log_burp, scan_sql_injection, detect_xss_csrf,
        scan_lfi_rfi, test_header_injection,
        browser_simulate_form, browser_find_open_redirect,
        param_discovery_post, run_nuclei_scan,
        report_new_endpoint, graphql_tester, cors_tester, ssti_tester,
        blind_sqli_scanner, nosql_injection_scanner,
        ldap_injection_scanner, xpath_injection_scanner,
        stored_xss_scanner, dom_xss_scanner, jsonp_injection_scanner,
        access_control_scanner,
        authorization_differential_replay,
        csrf_exploit_scanner, mass_assignment_scanner, http_method_tampering_scanner,
        command_injection_scanner, log_injection_scanner, csv_injection_scanner,
        prototype_pollution_scanner,
        web_cache_poisoning_scanner, cache_deception_scanner, idor_uuid_scanner,
        html_injection_scanner, ssi_injection_scanner, hpp_scanner,
    ]
    planner_requested = list(recommended_tools or [])
    unknown_planner_tools = [
        name for name in planner_requested
        if name not in vuln_tool_map and name != "human_recon_crawl"
    ]
    if unknown_planner_tools:
        raise ValueError(f"Planner selected unavailable tool(s): {unknown_planner_tools}")
    planner_selected = [
        vuln_tool_map[name] for name in planner_requested if name in vuln_tool_map
    ]
    initial_vuln_tools = planner_selected or default_vuln_tools

    vuln_agent = Agent(
        role="Senior Vulnerability Strategist",
        goal="Design precise payloads based on intel recon.",
        backstory="Exploitation mastermind. Surgical, WAF-aware payloads.",
        llm=llm_analis,
        tools=[langchain_to_crewai(t) for t in initial_vuln_tools],
        verbose=True
    )
    # Wire attack surface + dynamic smart selector (filter 34 -> 5-8 kontekstual)
    vuln_tools_filtered = None
    try:
        from dataclasses import asdict as _asdict
        from core.attack_surface import build_graph
        from core.target_state import get_target_state
        from engines.smart_selector import smart_selector
        ts = get_target_state()
        if ts:
            ts.attack_surface = build_graph(ts).to_dict()
            tech = _asdict(ts.tech_stack) if hasattr(ts.tech_stack, "__dict__") else {}
            selected = smart_selector.select_tools(tech, phase='analis')
            # Dynamic: inject only top 8 relevant tools into agent (keep full power breadth via planner chains)
            import tools as _tools
            name_to_tool = {t.name: t for t in [
                _tools.baca_log_burp, _tools.scan_sql_injection, _tools.detect_xss_csrf,
                _tools.scan_lfi_rfi, _tools.test_header_injection, _tools.run_nuclei_scan,
            ] if hasattr(t, 'name')}
            # For now keep vuln_agent tools as configured but add advisor note with dynamic selection
            advisor_note = f"Dynamic advisor (tech {tech.get('language')}/{tech.get('framework')}): prioritize {selected[:6]}"
            # Rebuild vuln_agent with filtered subset if advisor suggests subset
            if len(selected) >= 3 and len(selected) < 15:
                filtered = [t for t in [baca_log_burp, scan_sql_injection, detect_xss_csrf, scan_lfi_rfi, test_header_injection, run_nuclei_scan, blind_sqli_scanner, nosql_injection_scanner] if t.name in selected]
                if filtered:
                    vuln_tools_filtered = filtered
        else:
            advisor_note = ""
    except Exception:
        advisor_note = ""
    recon_ctx = all_results.get("recon", "")[:4000]
    # If filtered, update agent tools dynamically
    if vuln_tools_filtered and not planner_selected:
        vuln_agent.tools = [langchain_to_crewai(t) for t in vuln_tools_filtered + [report_new_endpoint]]
    # Respect user-selected vuln_types (empty = all via advisor)
    selected_vulns = []
    try:
        from api import session_store as _ss
        # Try session preset first (from api create), fallback to global
        sess = _ss.get(all_results.get("_session_id")) if "_session_id" in all_results else None
        if sess and sess.get("scan_vuln_types"):
            selected_vulns = sess["scan_vuln_types"]
    except Exception:
        pass
    vuln_scope = f" Focus only on: {', '.join(selected_vulns)}." if selected_vulns else ""
    planner_note = ""
    if planner_selected:
        planner_note = (
            f"\nDeterministic planner selected only: {recommended_tools}. "
            f"Planner context: {str(planner_context or {})[:3000]}. "
            "Do not claim validation yourself; return observations and candidates through the structured runner."
        )
    vuln_task = Task(
        description=f"Target: {target} | Goal: {goal}\nBased on recon:\n{recon_ctx}\n{advisor_note}{vuln_scope}{planner_note}\n\nRun the bounded evidence-producing test and stop when its configured stop condition is reached.",
        expected_output="List of vulnerabilities in GFM markdown format.",
        agent=vuln_agent
    )
    phases.append(("analis", vuln_agent, vuln_task, "Vulnerability Analysis"))
    
    return phases


def build_phase3_agent(target: str, all_results: dict, target_state: TargetState, llm_assessor, session_id: str = ""):
    """
    Build Phase 3 agent for risk assessment and reporting.
    """
    from tools import report_new_endpoint
    
    from core.structured_runner import structured_crewai_tool
    from api import session_store

    def langchain_to_crewai(lc_tool):
        return structured_crewai_tool(
            lc_tool, session_id=session_id, target=target,
            category="reporting", session_store=session_store,
        )

    agent = Agent(
        role="Chief Information Security Officer (CISO)",
        goal="Risk assessment and executive report.",
        backstory="CIA Triad + CVSS scoring expert.",
        llm=llm_assessor,
        tools=[langchain_to_crewai(t) for t in [report_new_endpoint]],
        verbose=True
    )
    
    # Build comprehensive context
    target_context = target_state.to_llm_context()
    # Also inject exploit plans if available
    try:
        from core.exploit_planner import propose_plans
        plans = propose_plans(target_state.goal, getattr(target_state, "attack_surface", {}), target_state.tech_stack.__dict__ if hasattr(target_state.tech_stack, "__dict__") else {})
        target_context += "\n=== EXPLOIT PLANS (goal-conditioned) ===\n" + "\n".join(p.get("title","") + ": " + ",".join(p.get("chain",[])) for p in plans)
        target_state.exploit_plans = plans
    except Exception:
        pass
    prev_ctx = "\n\n".join([
        f"### Recon:\n{all_results.get('recon', 'N/A')[:4000]}",
        f"### Analysis:\n{all_results.get('analis', 'N/A')[:4000]}",
        f"### Exploitation:\n{all_results.get('eksekutor', 'N/A')[:4000]}",
    ])
    
    full_context = f"=== TARGET STATE ===\n{target_context}\n\n=== PHASE RESULTS ===\n{prev_ctx}"
    
    task = Task(
        description=f"Analyze all findings for {target}:\n{full_context}\n\nCreate GFM markdown report. No ASCII art. Each vulnerability must have separate section with complete metadata (CWE-ID, CVSS vector, severity, steps to reproduce, PoC). Use markdown tables, bullet points, and blockquotes (>).",
        expected_output="Executive risk assessment report in GFM markdown format.",
        agent=agent
    )
    
    return agent, task, "Risk Assessment"


def run_phase1(job_id: str, session_id: str, target: str, goal: str,
                 memory_context: str, llm_recon, llm_analis, 
                 all_results: dict, all_reports: list,
                 auto_pilot: bool, cancellation_store, continue_store,
                 update_job, save_message, phase_filter: Optional[List[str]] = None,
                 result_handler=None, scan_preset: str = "full",
                 recommended_tools: Optional[List[str]] = None,
                 planner_context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Run Phase 1: Automated Data Gathering.
    Returns True if completed successfully, False if cancelled.
    """
    from core.target_state import get_target_state
    
    target_state = get_target_state()
    phase_names = {"recon": "Reconnaissance", "analis": "Vulnerability Analysis"}
    
    phases = build_phase1_agents(
        target, goal, memory_context, llm_recon, llm_analis, all_results,
        scan_preset=scan_preset, session_id=session_id,
        recommended_tools=recommended_tools, planner_context=planner_context,
    )
    if phase_filter:
        phases = [phase for phase in phases if phase[0] in phase_filter]
    
    for phase_idx, (phase_name, agent, task, display_name) in enumerate(phases):
        if cancellation_store.is_cancelled(job_id):
            return False
        
        update_job(job_id, status="running", message=f"Phase 1 - Data Gathering: {display_name}...")
        
        try:
            crew = Crew(agents=[agent], tasks=[task], verbose=True)
            result = crew.kickoff()
            result_str = str(result)
            all_results[phase_name] = result_str
            if result_handler:
                result_handler(phase_name, result_str, job_id)
            all_reports.append(f"## Phase: {display_name}\n\n{result_str}")
            save_message(session_id, "agent", f"[Phase 1 - {display_name} Complete]\n\n{result_str[:8000]}")
            update_job(job_id, message=f"Phase 1 - {display_name} complete")
            
            # Update Target State
            if phase_name == "recon":
                target_state.update_from_recon(result_str)
            elif phase_name == "analis":
                target_state.update_from_vuln(result_str)

            workflow_phase = "RECON" if phase_name == "recon" else "VALIDATION"
            target_state.workflow.phase = workflow_phase
            target_state.workflow.record_event("phase_result", phase=workflow_phase, job_id=job_id)
            try:
                from api import session_store
                session_store.save_state(session_id, target_state, phase=workflow_phase)
            except Exception as persist_err:
                update_job(job_id, message=f"Workflow state persistence warning: {persist_err}")
                
        except Exception as phase_err:
            update_job(job_id, message=f"Error in phase {phase_name}: {phase_err}")
            all_results[phase_name] = f"Error: {phase_err}"
        
        # Pause between sub-phases
        if phase_idx < len(phases) - 1 and not cancellation_store.is_cancelled(job_id):
            if auto_pilot:
                update_job(job_id, status="running", message=f"Phase 1 - {display_name} complete. Auto-Pilot: continuing...")
            else:
                update_job(job_id, status="waiting_continue", message=f"Phase 1 - {display_name} complete. Click 'Continue' to proceed.")
                approved = continue_store.request_continue(job_id)
                if not approved:
                    return False
    
    return True


def run_phase2_interactive(job_id: str, session_id: str, target: str,
                            auto_pilot: bool, cancellation_store, continue_store,
                            update_job, save_message, jobs: dict):
    """
    Run Phase 2: Interactive Consultation.
    Pauses execution and waits for user to finish consultation.
    """
    from core.target_state import get_target_state
    
    target_state = get_target_state()
    target_context = target_state.to_llm_context()
    
    # Save target state to session
    save_message(session_id, "system", f"[Target State Profile Updated]\n\n{target_state.get_summary()}")
    
    # Switch to interactive chat mode
    update_job(job_id, status="waiting_continue", 
               message="Phase 1 complete. Entering Interactive Co-Pilot mode. Ask me anything about the target!")
    
    # Store target context for chat queries
    job_data = jobs.get(job_id, {})
    job_data["target_state"] = target_state.to_dict()
    job_data["target_context"] = target_context
    jobs[job_id] = job_data
    
    # Wait for user to finish consultation
    try:
        from core.identity_context import get_execution_context
        context = get_execution_context()
        auto_pilot = bool(context.auto_pilot) if context else os.environ.get("AUTO_PILOT", "0") == "1"
    except Exception:
        auto_pilot = os.environ.get("AUTO_PILOT", "0") == "1"
    if not auto_pilot:
        approved = continue_store.request_continue(job_id)
        if not approved:
            return False
    
    return True


def run_phase3(job_id: str, session_id: str, target: str,
                all_results: dict, all_reports: list,
                llm_assessor, cancellation_store,
                update_job, save_message):
    """
    Run Phase 3: Automated Synthesis & Reporting.
    """
    from core.target_state import get_target_state
    
    target_state = get_target_state()
    
    update_job(job_id, status="running", message="Phase 3 - Risk Assessment & Final Report...")
    
    agent, task, display_name = build_phase3_agent(target, all_results, target_state, llm_assessor)
    
    try:
        crew = Crew(agents=[agent], tasks=[task], verbose=True)
        result = crew.kickoff()
        result_str = str(result)
        all_results["assessor"] = result_str
        all_reports.append(f"## Phase: {display_name}\n\n{result_str}")
        save_message(session_id, "agent", f"[Phase 3 - {display_name} Complete]\n\n{result_str[:2000]}")
        update_job(job_id, message=f"Phase 3 - {display_name} complete")
        
        # Update target state with final findings
        target_state.update_from_exploit(result_str)
        
    except Exception as phase_err:
        update_job(job_id, message=f"Error in Risk Assessment: {phase_err}")
        all_results["assessor"] = f"Error: {phase_err}"


import os

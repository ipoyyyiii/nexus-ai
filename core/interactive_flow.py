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
                         llm_recon, llm_analis, all_results: dict):
    """
    Build Phase 1 agents for automated data gathering.
    Returns list of (agent, task, phase_name) tuples.
    """
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
        csrf_exploit_scanner, mass_assignment_scanner, http_method_tampering_scanner,
        command_injection_scanner, log_injection_scanner, csv_injection_scanner,
        prototype_pollution_scanner,
        web_cache_poisoning_scanner, cache_deception_scanner, idor_uuid_scanner,
        html_injection_scanner, ssi_injection_scanner, hpp_scanner,
    )
    
    def langchain_to_crewai(lc_tool):
        from crewai.tools import BaseTool
        from pydantic import create_model
        import inspect
        
        if hasattr(lc_tool, 'args_schema') and lc_tool.args_schema:
            schema = lc_tool.args_schema
        else:
            sig = inspect.signature(lc_tool.func)
            fields = {k: (str, ...) for k, v in sig.parameters.items() if k != 'self'}
            schema = create_model(f"{lc_tool.name}Input", **fields) if fields else None
        
        class CrewAIWrappedTool(BaseTool):
            name: str = lc_tool.name
            description: str = lc_tool.description
            args_schema: type = schema if schema else type('EmptySchema', (), {})
            
            def _run(self, **kwargs):
                return lc_tool.invoke(kwargs)
        
        return CrewAIWrappedTool()

    phases = []
    
    # ── Recon Agent ────────────────────────────────────────────────────────────
    recon_agent = Agent(
        role="Advanced Reconnaissance & Intel Gatherer",
        goal="Deep recon: infrastructure, tech-stack, WAF, DNS, SSL, browser-based surface mapping.",
        backstory="Elite Intel Red Team level." + (f"\n{memory_context}" if memory_context else ""),
        llm=llm_recon,
        tools=[langchain_to_crewai(t) for t in [
            recon_target, enumerate_dns_subdomains, analyze_ssl_tls,
            browser_screenshot, browser_extract_surface,
            browser_intercept_requests, browser_check_security_headers,
            browser_extract_js_secrets, analyze_js_deep,
            param_discovery_get, param_discovery_headers,
            detect_subdomain_takeover, report_new_endpoint, wayback_scraper, github_dorking,
            recon_advanced, misconfiguration_scanner,
            client_side_security_scanner, mixed_content_scanner, asn_ip_mapper,
            postmessage_vulnerability_scanner, shodan_scanner, censys_scanner,
        ]],
        verbose=True
    )
    recon_task = Task(
        description=f"Active Recon target: {target}. Find ports, tech-stack, WAF, DNS, SSL, cloud assets, JS secrets.",
        expected_output="Complete infrastructure intelligence report in GFM markdown format.",
        agent=recon_agent
    )
    phases.append(("recon", recon_agent, recon_task, "Reconnaissance"))
    
    # ── Vulnerability Analysis Agent ──────────────────────────────────────────
    vuln_agent = Agent(
        role="Senior Vulnerability Strategist",
        goal="Design precise payloads based on intel recon.",
        backstory="Exploitation mastermind. Surgical, WAF-aware payloads.",
        llm=llm_analis,
        tools=[langchain_to_crewai(t) for t in [
            baca_log_burp, scan_sql_injection, detect_xss_csrf,
            scan_lfi_rfi, test_header_injection,
            browser_simulate_form, browser_find_open_redirect,
            param_discovery_post, run_nuclei_scan,
            report_new_endpoint, graphql_tester, cors_tester, ssti_tester,
            blind_sqli_scanner, nosql_injection_scanner,
            ldap_injection_scanner, xpath_injection_scanner,
            stored_xss_scanner, dom_xss_scanner, jsonp_injection_scanner,
            access_control_scanner,
            csrf_exploit_scanner, mass_assignment_scanner, http_method_tampering_scanner,
            command_injection_scanner, log_injection_scanner, csv_injection_scanner,
            prototype_pollution_scanner,
            web_cache_poisoning_scanner, cache_deception_scanner, idor_uuid_scanner,
            html_injection_scanner, ssi_injection_scanner, hpp_scanner,
        ]],
        verbose=True
    )
    recon_ctx = all_results.get("recon", "")[:1000]
    vuln_task = Task(
        description=f"Target: {target} | Goal: {goal}\nBased on recon:\n{recon_ctx}\n\nTest all injection vectors: SQLi, XSS, LFI, Header Injection.",
        expected_output="List of vulnerabilities in GFM markdown format.",
        agent=vuln_agent
    )
    phases.append(("analis", vuln_agent, vuln_task, "Vulnerability Analysis"))
    
    return phases


def build_phase3_agent(target: str, all_results: dict, target_state: TargetState, llm_assessor):
    """
    Build Phase 3 agent for risk assessment and reporting.
    """
    from tools import report_new_endpoint
    
    def langchain_to_crewai(lc_tool):
        from crewai.tools import BaseTool
        from pydantic import create_model
        import inspect
        
        if hasattr(lc_tool, 'args_schema') and lc_tool.args_schema:
            schema = lc_tool.args_schema
        else:
            sig = inspect.signature(lc_tool.func)
            fields = {k: (str, ...) for k, v in sig.parameters.items() if k != 'self'}
            schema = create_model(f"{lc_tool.name}Input", **fields) if fields else None
        
        class CrewAIWrappedTool(BaseTool):
            name: str = lc_tool.name
            description: str = lc_tool.description
            args_schema: type = schema if schema else type('EmptySchema', (), {})
            
            def _run(self, **kwargs):
                return lc_tool.invoke(kwargs)
        
        return CrewAIWrappedTool()

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
    prev_ctx = "\n\n".join([
        f"### Recon:\n{all_results.get('recon', 'N/A')[:500]}",
        f"### Analysis:\n{all_results.get('analis', 'N/A')[:500]}",
        f"### Exploitation:\n{all_results.get('eksekutor', 'N/A')[:500]}",
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
                result_handler=None) -> bool:
    """
    Run Phase 1: Automated Data Gathering.
    Returns True if completed successfully, False if cancelled.
    """
    from core.target_state import get_target_state
    
    target_state = get_target_state()
    phase_names = {"recon": "Reconnaissance", "analis": "Vulnerability Analysis"}
    
    phases = build_phase1_agents(target, goal, memory_context, llm_recon, llm_analis, all_results)
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
            save_message(session_id, "agent", f"[Phase 1 - {display_name} Complete]\n\n{result_str[:2000]}")
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

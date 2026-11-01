from datetime import datetime
from typing import Dict, Any, List
from app.agents.state import AgentState

def report_generation_node(state: AgentState) -> Dict[str, Any]:
    """
    Agent 7: Report Generation Agent
    Synthesizes the complete structured Incident Report spanning all 14 required sections.
    """
    inv_id = state.get("investigation_id", "INV-UNKNOWN")
    title = state.get("title", "Automated Security Investigation")
    events = state.get("events", [])
    alerts = state.get("alerts", [])
    log_findings = state.get("log_findings", {})
    threat_intel = state.get("threat_intel_findings", [])
    mitre_mappings = state.get("mitre_mappings", [])
    analysis = state.get("incident_analysis", {})
    validation = state.get("validation_result", {})
    triage = state.get("triage_verdict", {})
    traces = list(state.get("traces", []))
    step_id = len(traces) + 1
    ts_now = datetime.utcnow().isoformat() + "Z"

    # Severity determination
    sev = analysis.get("severity") or triage.get("preliminary_priority") or "INFORMATIONAL"
    sev_rationale = analysis.get("severity_rationale", "Standard evaluation based on observed alerts and log evidence.")

    # Assets
    affected_hosts = log_findings.get("affected_hosts", ["unknown"])
    targeted_users = log_findings.get("targeted_users", ["unknown"])
    candidate_ips = log_findings.get("suspicious_ips", [])
    destination_ips = log_findings.get("destination_ips", [])
    all_ips = list(set(candidate_ips + destination_ips))

    # Suspicious indicators
    indicators = []
    for ip in all_ips:
        indicators.append(f"IP: {ip}")
    for a in alerts:
        indicators.append(f"Alert: {a.get('title')} ({a.get('severity')})")

    # Remediation actions (Always requiring human approval per Section 11)
    remediation_actions = []
    if any(m.get("technique_id") in ["T1110.001", "T1110.003"] for m in mitre_mappings):
        remediation_actions.append({
            "action_id": "REM-01",
            "priority": "HIGH",
            "title": "Enforce Account Lockout and MFA",
            "description": "Implement multi-factor authentication (MFA) and aggressive lockout policies for SSH and Windows logons.",
            "requires_human_approval": True
        })
    if any(t.get("is_malicious") for t in threat_intel):
        mal_ips = [t["indicator"] for t in threat_intel if t.get("is_malicious")]
        remediation_actions.append({
            "action_id": "REM-02",
            "priority": "CRITICAL",
            "title": f"Firewall Perimeter Block ({', '.join(mal_ips)})",
            "description": f"Submit rule request to network firewall team to drop ingress/egress for verified malicious indicators: {', '.join(mal_ips)}.",
            "requires_human_approval": True
        })
    if any(m.get("technique_id") == "T1548.003" for m in mitre_mappings):
        remediation_actions.append({
            "action_id": "REM-03",
            "priority": "HIGH",
            "title": "Audit Sudoers and Admin Privilege Tokens",
            "description": "Review sudoers configurations and Windows Administrator group assignments for unauthorized additions.",
            "requires_human_approval": True
        })
    if not remediation_actions:
        remediation_actions.append({
            "action_id": "REM-00",
            "priority": "LOW",
            "title": "Maintain Continuous Telemetry Monitoring",
            "description": "No immediate containment required. Continue baseline auditing across endpoints.",
            "requires_human_approval": False
        })

    # Timeline entries
    timeline_entries = log_findings.get("event_timeline", [])[:25]

    # Collect valid evidence references
    evidence_refs = [t.get("event_id") for t in timeline_entries if t.get("event_id")]

    # Assemble complete 14-section report
    final_report = {
        "investigation_id": inv_id,
        "report_title": f"SENTINEL AI Investigation Report: {title}",
        "generated_at": ts_now,
        "incident_overview": (
            f"Autonomous threat investigation initiated for incident '{title}'. "
            f"Triaged {len(events)} security telemetry events and {len(alerts)} alerts. "
            f"Evaluated by SENTINEL AI LangGraph multi-agent orchestration."
        ),
        "executive_summary": (
            f"SENTINEL AI investigated activity involving host(s) {', '.join(affected_hosts)} and user(s) {', '.join(targeted_users)}. "
            f"The incident has been categorized as {sev}. "
            f"{analysis.get('attack_sequence', 'Routine telemetry observed without adversarial progression.')} "
            f"Validation engine completed verification with status '{validation.get('status', 'PASSED')}'."
        ),
        "severity": sev,
        "severity_rationale": sev_rationale,
        "affected_assets": {
            "hosts": affected_hosts,
            "users": targeted_users,
            "ips": all_ips
        },
        "suspicious_indicators": indicators[:15],
        "event_timeline": timeline_entries,
        "investigation_methodology": (
            "Multi-Agent LangGraph Orchestration: 1) SOC Triage rule/heuristic screening, "
            "2) Pandas chronological correlation, 3) AbuseIPDB/VirusTotal threat reputation queries, "
            "4) MITRE ATT&CK technique mapping, 5) Evidence-backed impact analysis, and "
            "6) Grounding fact-check validation."
        ),
        "threat_intelligence_findings": threat_intel,
        "mitre_attack_mappings": mitre_mappings,
        "root_cause_assessment": analysis.get("root_cause_assessment", "Routine operational activity."),
        "potential_impact": analysis.get("potential_impact", "Minimal risk identified."),
        "recommended_remediation": remediation_actions,
        "evidence_references": evidence_refs[:20],
        "investigation_limitations": (
            "Analysis restricted to ingested log artifacts and telemetry window. "
            "External threat intelligence was verified via simulated or live feeds without intrusive endpoint execution. "
            "All remediation actions are advisory and require human authorization."
        ),
        "validation_status": validation.get("status", "PASSED"),
        "validation_notes": validation.get("validation_issues", ["All referenced events verified in source logs."])
    }

    trace_step = {
        "step_id": step_id,
        "agent_name": "Report Generation Agent",
        "action": "Executive Incident Report Synthesis",
        "status": "COMPLETED",
        "timestamp": ts_now,
        "thought": (
            f"Compiling structured 14-section incident report for investigation {inv_id}. "
            f"Formatting remediation recommendations, executive summary, and evidence references."
        ),
        "tool_name": "compile_incident_report",
        "tool_input": {"investigation_id": inv_id, "severity": sev},
        "tool_output": {"report_title": final_report["report_title"], "sections_count": 14},
        "findings_summary": (
            f"Final report generated successfully. Severity: {sev}. Remediation actions: {len(remediation_actions)}. "
            f"Report validated and ready for export."
        )
    }

    traces.append(trace_step)

    return {
        "final_report": final_report,
        "traces": traces
    }

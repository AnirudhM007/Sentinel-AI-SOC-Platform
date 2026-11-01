from datetime import datetime
from typing import Dict, Any, List
from app.agents.state import AgentState

def incident_analysis_node(state: AgentState) -> Dict[str, Any]:
    """
    Agent 5: Incident Analysis Agent
    Synthesizes multi-agent telemetry, reconstructs attack narrative, assesses scope, and assigns evidence-backed severity.
    """
    log_findings = state.get("log_findings", {})
    threat_intel = state.get("threat_intel_findings", [])
    mitre_mappings = state.get("mitre_mappings", [])
    alerts = state.get("alerts", [])
    traces = list(state.get("traces", []))
    step_id = len(traces) + 1
    ts_now = datetime.utcnow().isoformat() + "Z"

    # Evaluate factors
    has_compromise_alert = any(a.get("rule_id") == "RULE-SUSP-AUTH-SUCCESS" for a in alerts)
    has_malicious_ip = any(t.get("is_malicious") for t in threat_intel)
    has_priv_escalation = any(m.get("technique_id") == "T1548.003" for m in mitre_mappings)
    has_brute_force = any(m.get("technique_id") in ["T1110.001", "T1110.003"] for m in mitre_mappings)
    is_anomaly = any(a.get("detection_type") == "ML_ANOMALY" for a in alerts)

    # Determine severity based on objective evidence
    if has_compromise_alert or (has_malicious_ip and has_priv_escalation):
        severity = "CRITICAL"
        rationale = "Interactive authentication succeeded following brute-force attempts from an external or suspicious entity, accompanied by privilege activity."
    elif has_brute_force or has_priv_escalation or (has_malicious_ip and len(log_findings.get("event_timeline", [])) > 5):
        severity = "HIGH"
        rationale = "Active adversarial technique observed (e.g. brute force, password spray, or unauthorized privilege elevation attempt)."
    elif is_anomaly or len(alerts) > 0:
        severity = "MEDIUM"
        rationale = "Statistical telemetry anomaly or anomalous account activity detected exceeding baseline thresholds."
    elif len(alerts) > 0:
        severity = "LOW"
        rationale = "Low-confidence indicators or sporadic authentication errors."
    else:
        severity = "INFORMATIONAL"
        rationale = "Standard routine system telemetry; no indicators of compromise observed."

    # Attack sequence reconstruction
    attack_phases = []
    if any(m.get("tactic") == "Discovery" for m in mitre_mappings):
        attack_phases.append("Reconnaissance / Discovery")
    if has_brute_force:
        attack_phases.append("Credential Access (Brute Force / Password Spray)")
    if any(m.get("technique_id") == "T1078" for m in mitre_mappings) or has_compromise_alert:
        attack_phases.append("Initial Access / Valid Accounts")
    if has_priv_escalation:
        attack_phases.append("Privilege Escalation (Sudo / Admin Elevation)")
    if any(m.get("technique_id") == "T1136.001" for m in mitre_mappings):
        attack_phases.append("Persistence (Account Creation)")
    if any(m.get("technique_id") == "T1071.001" for m in mitre_mappings):
        attack_phases.append("Command & Control (Outbound Beaconing)")

    narrative = " -> ".join(attack_phases) if attack_phases else "No structured attack sequence detected (Benign activity)."

    root_cause = (
        "Weak credentials or exposed remote authentication interface without multi-factor authentication (MFA)"
        if has_brute_force else (
            "Misconfigured administrative permissions or unmonitored privilege delegation"
            if has_priv_escalation else "Normal business operations and user activities"
        )
    )

    potential_impact = (
        "Potential unauthorized access to host data, lateral movement across the enterprise network, and credential harvesting."
        if severity in ["CRITICAL", "HIGH"] else (
            "Moderate operational disruption or unverified anomalous behavior requiring monitoring."
            if severity == "MEDIUM" else "Minimal to none."
        )
    )

    incident_analysis = {
        "severity": severity,
        "severity_rationale": rationale,
        "attack_sequence": narrative,
        "root_cause_assessment": root_cause,
        "potential_impact": potential_impact,
        "affected_hosts": log_findings.get("affected_hosts", []),
        "affected_users": log_findings.get("targeted_users", []),
        "observed_phases": attack_phases
    }

    trace_step = {
        "step_id": step_id,
        "agent_name": "Incident Analysis Agent",
        "action": "Correlative Synthesis and Impact Assessment",
        "status": "COMPLETED",
        "timestamp": ts_now,
        "thought": (
            f"Synthesizing findings across log timeline, {len(threat_intel)} threat intel records, and {len(mitre_mappings)} MITRE techniques. "
            f"Computing objective severity score and mapping attack phase progression."
        ),
        "tool_name": "correlate_incident_scope",
        "tool_input": {"mitre_count": len(mitre_mappings), "alerts_count": len(alerts)},
        "tool_output": {
            "assigned_severity": severity,
            "attack_sequence": narrative,
            "root_cause": root_cause
        },
        "findings_summary": (
            f"Assigned Severity: {severity}. Attack Narrative: {narrative}. Root Cause: {root_cause}."
        )
    }

    traces.append(trace_step)

    return {
        "incident_analysis": incident_analysis,
        "traces": traces
    }

from datetime import datetime
from typing import Dict, Any
from app.agents.state import AgentState

def soc_triage_node(state: AgentState) -> Dict[str, Any]:
    """
    Agent 1: SOC Triage Agent
    Examines incoming alerts & events, categorizes severity, and decides if full investigation is warranted.
    """
    events = state.get("events", [])
    alerts = state.get("alerts", [])
    traces = list(state.get("traces", []))
    step_id = len(traces) + 1
    ts_now = datetime.utcnow().isoformat() + "Z"

    # Evaluation logic
    has_critical_alert = any(a.get("severity") in ["CRITICAL", "HIGH"] for a in alerts)
    has_ml_anomaly = any(a.get("detection_type") == "ML_ANOMALY" for a in alerts)
    auth_fails = [e for e in events if e.get("event_type") == "AUTH_FAILURE"]
    has_priv_escalation = any(e.get("event_type") == "PRIVILEGE_ESCALATION" for e in events)

    # Determine suspicion
    is_suspicious = bool(has_critical_alert or has_ml_anomaly or len(auth_fails) >= 3 or has_priv_escalation)
    
    if any(a.get("severity") == "CRITICAL" for a in alerts):
        priority = "CRITICAL"
    elif has_critical_alert:
        priority = "HIGH"
    elif is_suspicious:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    category = "Credential Access / Brute Force" if len(auth_fails) >= 3 else (
        "Privilege Escalation" if has_priv_escalation else (
            "Statistical Anomaly" if has_ml_anomaly else "Benign System Telemetry"
        )
    )

    justification = (
        f"Detected {len(alerts)} alerts ({len(auth_fails)} auth failures, "
        f"{'privilege escalation present' if has_priv_escalation else 'no privilege escalation'}). "
        f"{'Investigation mandatory due to elevated risk indicators.' if is_suspicious else 'Activity consistent with benign routine baseline.'}"
    )

    triage_verdict = {
        "is_suspicious": is_suspicious,
        "preliminary_priority": priority,
        "category": category,
        "total_events_triaged": len(events),
        "total_alerts_evaluated": len(alerts),
        "justification": justification
    }

    # Record trace
    trace_step = {
        "step_id": step_id,
        "agent_name": "SOC Triage Agent",
        "action": "Triage and Prioritization",
        "status": "COMPLETED",
        "timestamp": ts_now,
        "thought": (
            f"Analyzing {len(events)} normalized events and {len(alerts)} pre-computed alerts. "
            f"Checking threshold for failed authentications, privilege assignment, and anomalous behaviors."
        ),
        "tool_name": "evaluate_risk_criteria",
        "tool_input": {"events_count": len(events), "alerts_count": len(alerts)},
        "tool_output": triage_verdict,
        "findings_summary": (
            f"Verdict: {'Suspicious Activity Identified' if is_suspicious else 'Benign Pattern'}. "
            f"Assigned preliminary priority {priority}. Category: {category}."
        )
    }

    traces.append(trace_step)

    return {
        "triage_verdict": triage_verdict,
        "traces": traces
    }

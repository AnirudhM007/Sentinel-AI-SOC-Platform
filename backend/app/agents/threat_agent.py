from datetime import datetime
from typing import Dict, Any, List
from app.agents.state import AgentState
from app.threat_intel.service import threat_intel_service

def threat_intel_node(state: AgentState) -> Dict[str, Any]:
    """
    Agent 3: Threat Intelligence Agent
    Queries threat intelligence for IPs identified by Log Investigation Agent.
    """
    log_findings = state.get("log_findings", {})
    traces = list(state.get("traces", []))
    step_id = len(traces) + 1
    ts_now = datetime.utcnow().isoformat() + "Z"

    # Identify all candidate IPs (both source and destination)
    suspicious_ips = log_findings.get("suspicious_ips", [])
    destination_ips = log_findings.get("destination_ips", [])
    all_ips = list(set(suspicious_ips + destination_ips))

    threat_findings: List[Dict[str, Any]] = []

    for ip in all_ips:
        res = threat_intel_service.lookup_indicator(ip, "IP")
        threat_findings.append({
            "indicator": ip,
            "indicator_type": "IP",
            "reputation_score": res.get("reputation_score", 0.0),
            "is_malicious": res.get("is_malicious", False),
            "source": res.get("source", "MOCK_FEED"),
            "is_simulated": res.get("is_simulated", True),
            "summary": res.get("summary", ""),
            "details": res.get("details", {})
        })

    malicious_found = [f for f in threat_findings if f["is_malicious"]]

    mal_summary = ", ".join([f"{f['indicator']} ({f['reputation_score']}/100)" for f in malicious_found]) or "None (indicators rated benign/unrated)"
    trace_step = {
        "step_id": step_id,
        "agent_name": "Threat Intelligence Agent",
        "action": "Indicator Reputation and Threat Feeds Lookup",
        "status": "COMPLETED",
        "timestamp": ts_now,
        "thought": (
            f"Querying threat intelligence repositories for {len(all_ips)} indicator(s): {', '.join(all_ips) or 'No external IPs'}. "
            f"Checking for known C2 infrastructure, scanners, or abuse reports."
        ),
        "tool_name": "query_threat_intelligence",
        "tool_input": {"indicators": all_ips},
        "tool_output": {"total_queried": len(all_ips), "malicious_count": len(malicious_found)},
        "findings_summary": (
            f"Evaluated {len(all_ips)} indicator(s). Flagged {len(malicious_found)} confirmed high-risk indicator(s): {mal_summary}."
        )
    }

    traces.append(trace_step)

    return {
        "threat_intel_findings": threat_findings,
        "traces": traces
    }

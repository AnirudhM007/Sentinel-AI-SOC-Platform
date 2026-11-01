from datetime import datetime
from typing import Dict, Any
from app.agents.state import AgentState
from app.agents.tools import build_chronological_timeline, aggregate_ip_activity, profile_user_activity

def log_investigation_node(state: AgentState) -> Dict[str, Any]:
    """
    Agent 2: Log Investigation Agent
    Executes deep log correlation, builds chronological timeline, aggregates entity profiles using Pandas.
    """
    events = state.get("events", [])
    alerts = state.get("alerts", [])
    traces = list(state.get("traces", []))
    step_id = len(traces) + 1
    ts_now = datetime.utcnow().isoformat() + "Z"

    # 1. Build chronological timeline
    timeline = build_chronological_timeline(events, limit=50)

    # 2. Extract targeted users, hosts, and candidate IPs
    all_users = list(set(e.get("username") for e in events if e.get("username") and e.get("username") != "unknown"))
    all_hosts = list(set(e.get("hostname") for e in events if e.get("hostname") and e.get("hostname") != "unknown"))
    candidate_ips = list(set(e.get("source_ip") for e in events if e.get("source_ip") and e.get("source_ip") not in ["127.0.0.1", "::1", "-", ""]))
    dest_ips = list(set(e.get("destination_ip") for e in events if e.get("destination_ip") and e.get("destination_ip") not in ["127.0.0.1", "-", ""]))

    # 3. Analyze candidate IPs with Pandas
    ip_profiles = {}
    for ip in candidate_ips[:5]:
        ip_profiles[ip] = aggregate_ip_activity(events, ip)

    # 4. User profiles
    user_profiles = {}
    for u in all_users[:5]:
        user_profiles[u] = profile_user_activity(events, u)

    # 5. Detect sequential patterns
    has_success_post_fail = any(
        a.get("rule_id") == "RULE-SUSP-AUTH-SUCCESS" for a in alerts
    )
    unusual_sequence = "Normal linear log progression."
    if has_success_post_fail:
        unusual_sequence = "CRITICAL SEQUENCE: Rapid failed authentication attempts culminated in an interactive session establishment."
    elif len(candidate_ips) > 0 and len(all_users) > 3:
        unusual_sequence = "MULTIPLE TARGET SEQUENCE: Single source entity systematically enumerating credentials across accounts."

    log_findings = {
        "event_timeline": timeline,
        "affected_hosts": all_hosts or ["unknown-host"],
        "targeted_users": all_users or ["system"],
        "suspicious_ips": candidate_ips,
        "destination_ips": dest_ips,
        "ip_profiles": ip_profiles,
        "user_profiles": user_profiles,
        "anomaly_sequence_summary": unusual_sequence,
        "total_events_analyzed": len(events)
    }

    # Record trace
    trace_step = {
        "step_id": step_id,
        "agent_name": "Log Investigation Agent",
        "action": "Chronological Correlation and Entity Profiling",
        "status": "COMPLETED",
        "timestamp": ts_now,
        "thought": (
            f"Correlating {len(events)} events into chronological sequence. "
            f"Extracted {len(candidate_ips)} source IPs and {len(all_users)} targeted user accounts. "
            f"Executing Pandas profile aggregations."
        ),
        "tool_name": "build_chronological_timeline_and_profiles",
        "tool_input": {"events_count": len(events), "unique_ips": len(candidate_ips)},
        "tool_output": {
            "timeline_length": len(timeline),
            "candidate_ips": candidate_ips,
            "targeted_users": all_users,
            "affected_hosts": all_hosts
        },
        "findings_summary": (
            f"Constructed timeline of {len(timeline)} events. Identified {len(candidate_ips)} source IP(s): {', '.join(candidate_ips) or 'None'}. "
            f"Sequence pattern: {unusual_sequence}"
        )
    }

    traces.append(trace_step)

    return {
        "log_findings": log_findings,
        "traces": traces
    }

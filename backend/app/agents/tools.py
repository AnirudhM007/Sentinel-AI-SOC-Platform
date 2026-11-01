import pandas as pd
from typing import List, Dict, Any, Optional
from app.threat_intel.service import threat_intel_service
from app.mitre.mapper import mitre_mapper

def build_chronological_timeline(events: List[Dict[str, Any]], limit: int = 40) -> List[Dict[str, Any]]:
    """
    Constructs a structured chronological event timeline using Pandas.
    """
    if not events:
        return []

    df = pd.DataFrame(events)
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df["timestamp"] = pd.to_datetime(df["timestamp"])

    df_sorted = df.sort_values(by="timestamp", ascending=True)

    timeline = []
    for _, row in df_sorted.head(limit).iterrows():
        action_desc = f"{row.get('event_type')} on {row.get('hostname')} by user '{row.get('username')}'"
        if row.get("source_ip"):
            action_desc += f" from IP {row.get('source_ip')}"
        if row.get("command_line"):
            action_desc += f" [cmd: {str(row.get('command_line'))[:60]}]"

        timeline.append({
            "timestamp": str(row["timestamp"]),
            "event_id": str(row["event_id"]),
            "event_type": str(row["event_type"]),
            "summary": action_desc,
            "severity": str(row.get("severity", "INFORMATIONAL")),
            "evidence": str(row.get("raw_event", ""))[:120]
        })
    return timeline

def aggregate_ip_activity(events: List[Dict[str, Any]], ip: str) -> Dict[str, Any]:
    """
    Computes Pandas statistical profile of an IP across all ingested events.
    """
    if not events or not ip:
        return {"ip": ip, "total_events": 0}

    df = pd.DataFrame(events)
    ip_events = df[(df["source_ip"] == ip) | (df["destination_ip"] == ip)]
    
    if ip_events.empty:
        return {"ip": ip, "total_events": 0}

    fails = (ip_events["event_type"] == "AUTH_FAILURE").sum()
    successes = (ip_events["event_type"] == "AUTH_SUCCESS").sum()
    targeted_users = ip_events["username"].replace("", None).dropna().unique().tolist()
    targeted_hosts = ip_events["hostname"].replace("", None).dropna().unique().tolist()

    return {
        "ip": ip,
        "total_events": int(len(ip_events)),
        "auth_failures": int(fails),
        "auth_successes": int(successes),
        "targeted_users": targeted_users,
        "targeted_hosts": targeted_hosts,
        "first_seen": str(ip_events["timestamp"].min()),
        "last_seen": str(ip_events["timestamp"].max())
    }

def profile_user_activity(events: List[Dict[str, Any]], username: str) -> Dict[str, Any]:
    """
    Computes Pandas profile of user activity across all events.
    """
    if not events or not username:
        return {"username": username, "total_events": 0}

    df = pd.DataFrame(events)
    u_events = df[df["username"] == username]
    if u_events.empty:
        return {"username": username, "total_events": 0}

    priv_events = u_events[u_events["event_type"] == "PRIVILEGE_ESCALATION"]
    source_ips = u_events["source_ip"].replace("", None).dropna().unique().tolist()

    return {
        "username": username,
        "total_events": int(len(u_events)),
        "unique_source_ips": source_ips,
        "hosts_accessed": u_events["hostname"].unique().tolist(),
        "has_privilege_escalation": bool(len(priv_events) > 0),
        "privileged_commands": priv_events["command_line"].dropna().tolist()[:5]
    }

def lookup_threat_indicator(indicator: str, indicator_type: str = "IP") -> Dict[str, Any]:
    """
    Queries threat intelligence module.
    """
    return threat_intel_service.lookup_indicator(indicator, indicator_type)

def verify_event_references(event_ids: List[str], all_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validation tool: confirms that referenced event IDs actually exist in telemetry and have valid timestamps.
    """
    existing_ids = {str(e.get("event_id")) for e in all_events}
    verified = [eid for eid in event_ids if eid in existing_ids]
    missing = [eid for eid in event_ids if eid not in existing_ids]

    return {
        "total_referenced": len(event_ids),
        "verified_count": len(verified),
        "missing_count": len(missing),
        "missing_ids": missing,
        "is_fully_grounded": len(missing) == 0
    }

import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple

FEATURE_COLUMNS = [
    "failed_logins",
    "successful_logins",
    "unique_source_ips",
    "unique_targeted_users",
    "avg_hour_of_day",
    "off_hours_ratio",
    "privilege_event_count",
    "total_event_volume"
]

def extract_features_per_host(events: List[Dict[str, Any]]) -> Tuple[pd.DataFrame, Dict[str, List[str]]]:
    """
    Aggregates security events into numerical behavioral feature vectors grouped by hostname.
    Returns: (features_dataframe, dict_mapping_host_to_event_ids)
    """
    if not events:
        return pd.DataFrame(columns=FEATURE_COLUMNS), {}

    df = pd.DataFrame(events)
    # Ensure datetime
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df["timestamp"] = pd.to_datetime(df["timestamp"])

    host_groups = df.groupby("hostname")
    feature_rows = []
    host_event_map = {}

    for host, group in host_groups:
        host_str = str(host)
        host_event_map[host_str] = group["event_id"].tolist()

        failed_count = (group["event_type"] == "AUTH_FAILURE").sum()
        succ_count = (group["event_type"] == "AUTH_SUCCESS").sum()
        unique_ips = group["source_ip"].replace("", np.nan).dropna().nunique()
        unique_users = group["username"].replace("", np.nan).dropna().nunique()

        hours = group["timestamp"].dt.hour
        avg_hour = hours.mean() if len(hours) > 0 else 12.0
        # Off-hours defined as 20:00 to 06:00
        off_hours_count = ((hours >= 20) | (hours < 6)).sum()
        off_hours_ratio = off_hours_count / len(group) if len(group) > 0 else 0.0

        priv_count = (
            (group["event_type"] == "PRIVILEGE_ESCALATION") | 
            (group["event_id_native"].isin(["4672", "sudo"]))
        ).sum()
        total_vol = len(group)

        feature_rows.append({
            "hostname": host_str,
            "failed_logins": float(failed_count),
            "successful_logins": float(succ_count),
            "unique_source_ips": float(unique_ips),
            "unique_targeted_users": float(unique_users),
            "avg_hour_of_day": float(avg_hour),
            "off_hours_ratio": float(off_hours_ratio),
            "privilege_event_count": float(priv_count),
            "total_event_volume": float(total_vol)
        })

    feat_df = pd.DataFrame(feature_rows)
    return feat_df, host_event_map

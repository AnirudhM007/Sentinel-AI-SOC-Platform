import csv
import io
import uuid
from datetime import datetime
from typing import List, Dict, Any

EVENT_ID_MAP = {
    "4624": {"event_type": "AUTH_SUCCESS", "status": "SUCCESS", "severity": "INFORMATIONAL"},
    "4625": {"event_type": "AUTH_FAILURE", "status": "FAILURE", "severity": "LOW"},
    "4672": {"event_type": "PRIVILEGE_ESCALATION", "status": "SUCCESS", "severity": "MEDIUM"},
    "4720": {"event_type": "USER_CREATE", "status": "SUCCESS", "severity": "MEDIUM"},
    "4688": {"event_type": "PROCESS_CREATE", "status": "SUCCESS", "severity": "INFORMATIONAL"},
    "7045": {"event_type": "SERVICE_INSTALL", "status": "SUCCESS", "severity": "HIGH"},
    "5156": {"event_type": "NETWORK_CONNECT", "status": "SUCCESS", "severity": "INFORMATIONAL"},
}

def parse_windows_timestamp(val: str) -> datetime:
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(val.strip(), fmt)
        except (ValueError, AttributeError):
            continue
    return datetime.utcnow()

def parse_windows_event_csv(content: str, filename: str = "windows_security.csv") -> List[Dict[str, Any]]:
    events = []
    f = io.StringIO(content.strip())
    reader = csv.DictReader(f)

    for row in reader:
        # Standardize column headers to lowercase
        norm_row = {k.strip().lower(): v.strip() for k, v in row.items() if k}
        
        event_id_native = (
            norm_row.get("eventid") or 
            norm_row.get("event_id") or 
            norm_row.get("id") or 
            ""
        )
        meta = EVENT_ID_MAP.get(event_id_native, {
            "event_type": "SYSTEM_LOG",
            "status": "UNKNOWN",
            "severity": "INFORMATIONAL"
        })

        ts_str = (
            norm_row.get("timecreated") or 
            norm_row.get("timestamp") or 
            norm_row.get("date") or 
            ""
        )
        ts = parse_windows_timestamp(ts_str)

        username = (
            norm_row.get("targetusername") or 
            norm_row.get("username") or 
            norm_row.get("user") or 
            norm_row.get("subjectusername") or 
            "unknown"
        )
        hostname = (
            norm_row.get("computer") or 
            norm_row.get("hostname") or 
            norm_row.get("computername") or 
            "WIN-HOST"
        )
        source_ip = (
            norm_row.get("ipaddress") or 
            norm_row.get("source_ip") or 
            norm_row.get("ip") or 
            norm_row.get("workstationname") or 
            ""
        )
        # Filter out local loopback notation if needed
        if source_ip in ["-", "::1", "127.0.0.1"]:
            source_ip = "127.0.0.1"

        dest_ip = norm_row.get("destination_ip") or norm_row.get("dest_ip") or ""
        proc_name = (
            norm_row.get("processname") or 
            norm_row.get("process_name") or 
            norm_row.get("newprocessname") or 
            ""
        )
        cmd_line = (
            norm_row.get("commandline") or 
            norm_row.get("command_line") or 
            norm_row.get("message") or 
            ""
        )

        events.append({
            "event_id": f"evt-{uuid.uuid4().hex[:12]}",
            "timestamp": ts,
            "hostname": hostname,
            "username": username,
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "event_type": meta["event_type"],
            "event_id_native": str(event_id_native),
            "process_name": proc_name,
            "command_line": cmd_line,
            "status": meta["status"],
            "severity": meta["severity"],
            "raw_event": str(row),
            "file_source": filename
        })

    return events

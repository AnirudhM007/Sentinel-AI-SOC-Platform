import json
import csv
import io
import uuid
from datetime import datetime
from typing import List, Dict, Any
from app.parsers.windows_events import parse_windows_timestamp

def parse_generic_json(content: str, filename: str = "events.json") -> List[Dict[str, Any]]:
    events = []
    content_clean = content.strip()
    
    # Try parsing as whole JSON array or single object
    raw_items = []
    try:
        data = json.loads(content_clean)
        if isinstance(data, list):
            raw_items = data
        elif isinstance(data, dict):
            raw_items = [data]
    except json.JSONDecodeError:
        # Try JSON Lines (one JSON object per line)
        for line in content_clean.splitlines():
            line = line.strip()
            if line:
                try:
                    raw_items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    for item in raw_items:
        ts_val = item.get("timestamp") or item.get("time") or item.get("@timestamp")
        ts = parse_windows_timestamp(str(ts_val)) if ts_val else datetime.utcnow()

        events.append({
            "event_id": str(item.get("event_id") or f"evt-{uuid.uuid4().hex[:12]}"),
            "timestamp": ts,
            "hostname": str(item.get("hostname") or item.get("host") or "unknown"),
            "username": str(item.get("username") or item.get("user") or "unknown"),
            "source_ip": str(item.get("source_ip") or item.get("src_ip") or item.get("ip") or ""),
            "destination_ip": str(item.get("destination_ip") or item.get("dst_ip") or ""),
            "event_type": str(item.get("event_type") or item.get("type") or "SYSTEM_LOG").upper(),
            "event_id_native": str(item.get("event_id_native") or item.get("id") or ""),
            "process_name": str(item.get("process_name") or item.get("process") or ""),
            "command_line": str(item.get("command_line") or item.get("cmd") or ""),
            "status": str(item.get("status") or "UNKNOWN").upper(),
            "severity": str(item.get("severity") or "INFORMATIONAL").upper(),
            "raw_event": json.dumps(item),
            "file_source": filename
        })

    return events

def parse_generic_csv(content: str, filename: str = "events.csv") -> List[Dict[str, Any]]:
    events = []
    f = io.StringIO(content.strip())
    reader = csv.DictReader(f)

    for row in reader:
        norm_row = {k.strip().lower(): v.strip() for k, v in row.items() if k}
        ts_val = norm_row.get("timestamp") or norm_row.get("time") or norm_row.get("date")
        ts = parse_windows_timestamp(str(ts_val)) if ts_val else datetime.utcnow()

        events.append({
            "event_id": str(norm_row.get("event_id") or f"evt-{uuid.uuid4().hex[:12]}"),
            "timestamp": ts,
            "hostname": str(norm_row.get("hostname") or norm_row.get("host") or "unknown"),
            "username": str(norm_row.get("username") or norm_row.get("user") or "unknown"),
            "source_ip": str(norm_row.get("source_ip") or norm_row.get("src_ip") or norm_row.get("ip") or ""),
            "destination_ip": str(norm_row.get("destination_ip") or norm_row.get("dst_ip") or ""),
            "event_type": str(norm_row.get("event_type") or norm_row.get("type") or "SYSTEM_LOG").upper(),
            "event_id_native": str(norm_row.get("event_id_native") or norm_row.get("id") or ""),
            "process_name": str(norm_row.get("process_name") or norm_row.get("process") or ""),
            "command_line": str(norm_row.get("command_line") or norm_row.get("cmd") or ""),
            "status": str(norm_row.get("status") or "UNKNOWN").upper(),
            "severity": str(norm_row.get("severity") or "INFORMATIONAL").upper(),
            "raw_event": str(row),
            "file_source": filename
        })

    return events

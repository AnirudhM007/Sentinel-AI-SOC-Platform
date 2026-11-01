import re
import uuid
from datetime import datetime
from typing import List, Dict, Any

SSH_FAILED_PATTERN = re.compile(
    r'(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Failed password for (invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
    re.IGNORECASE
)

SSH_ACCEPTED_PATTERN = re.compile(
    r'(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Accepted (password|publickey) for (?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
    re.IGNORECASE
)

SUDO_PATTERN = re.compile(
    r'(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s*:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<cmd>.*)',
    re.IGNORECASE
)

USERADD_PATTERN = re.compile(
    r'(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+useradd\[(?P<pid>\d+)\]:\s+new user: name=(?P<user>\S+)',
    re.IGNORECASE
)

def parse_syslog_timestamp(month_str: str, day_str: str, time_str: str, year: int = None) -> datetime:
    if year is None:
        year = datetime.utcnow().year
    dt_str = f"{year} {month_str} {day_str} {time_str}"
    try:
        return datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        # Fallback to current time
        return datetime.utcnow()

def parse_linux_auth_log(content: str, filename: str = "auth.log") -> List[Dict[str, Any]]:
    events = []
    lines = content.strip().splitlines()
    year = datetime.utcnow().year

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        match_fail = SSH_FAILED_PATTERN.search(line_clean)
        if match_fail:
            ts = parse_syslog_timestamp(match_fail.group("month"), match_fail.group("day"), match_fail.group("time"), year)
            events.append({
                "event_id": f"evt-{uuid.uuid4().hex[:12]}",
                "timestamp": ts,
                "hostname": match_fail.group("host"),
                "username": match_fail.group("user"),
                "source_ip": match_fail.group("ip"),
                "destination_ip": "",
                "event_type": "AUTH_FAILURE",
                "event_id_native": "sshd_failed",
                "process_name": "sshd",
                "command_line": "",
                "status": "FAILURE",
                "severity": "LOW",
                "raw_event": line_clean,
                "file_source": filename
            })
            continue

        match_succ = SSH_ACCEPTED_PATTERN.search(line_clean)
        if match_succ:
            ts = parse_syslog_timestamp(match_succ.group("month"), match_succ.group("day"), match_succ.group("time"), year)
            events.append({
                "event_id": f"evt-{uuid.uuid4().hex[:12]}",
                "timestamp": ts,
                "hostname": match_succ.group("host"),
                "username": match_succ.group("user"),
                "source_ip": match_succ.group("ip"),
                "destination_ip": "",
                "event_type": "AUTH_SUCCESS",
                "event_id_native": "sshd_accepted",
                "process_name": "sshd",
                "command_line": "",
                "status": "SUCCESS",
                "severity": "INFORMATIONAL",
                "raw_event": line_clean,
                "file_source": filename
            })
            continue

        match_sudo = SUDO_PATTERN.search(line_clean)
        if match_sudo:
            ts = parse_syslog_timestamp(match_sudo.group("month"), match_sudo.group("day"), match_sudo.group("time"), year)
            events.append({
                "event_id": f"evt-{uuid.uuid4().hex[:12]}",
                "timestamp": ts,
                "hostname": match_sudo.group("host"),
                "username": match_sudo.group("user"),
                "source_ip": "",
                "destination_ip": "",
                "event_type": "PRIVILEGE_ESCALATION",
                "event_id_native": "sudo",
                "process_name": "sudo",
                "command_line": match_sudo.group("cmd").strip(),
                "status": "SUCCESS",
                "severity": "MEDIUM",
                "raw_event": line_clean,
                "file_source": filename
            })
            continue

        match_useradd = USERADD_PATTERN.search(line_clean)
        if match_useradd:
            ts = parse_syslog_timestamp(match_useradd.group("month"), match_useradd.group("day"), match_useradd.group("time"), year)
            events.append({
                "event_id": f"evt-{uuid.uuid4().hex[:12]}",
                "timestamp": ts,
                "hostname": match_useradd.group("host"),
                "username": match_useradd.group("user"),
                "source_ip": "",
                "destination_ip": "",
                "event_type": "USER_CREATE",
                "event_id_native": "useradd",
                "process_name": "useradd",
                "command_line": line_clean,
                "status": "SUCCESS",
                "severity": "MEDIUM",
                "raw_event": line_clean,
                "file_source": filename
            })
            continue

        # Generic fallback for syslog line
        parts = line_clean.split(maxsplit=4)
        if len(parts) >= 5:
            try:
                ts = parse_syslog_timestamp(parts[0], parts[1], parts[2], year)
                events.append({
                    "event_id": f"evt-{uuid.uuid4().hex[:12]}",
                    "timestamp": ts,
                    "hostname": parts[3],
                    "username": "unknown",
                    "source_ip": "",
                    "destination_ip": "",
                    "event_type": "SYSTEM_LOG",
                    "event_id_native": "syslog",
                    "process_name": parts[4].split(":")[0] if ":" in parts[4] else "system",
                    "command_line": "",
                    "status": "INFORMATIONAL",
                    "severity": "INFORMATIONAL",
                    "raw_event": line_clean,
                    "file_source": filename
                })
            except Exception:
                pass

    return events

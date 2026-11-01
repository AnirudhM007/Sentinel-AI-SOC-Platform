import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any

class DetectionRule:
    def __init__(self, rule_id: str, name: str, default_severity: str, description: str):
        self.rule_id = rule_id
        self.name = name
        self.default_severity = default_severity
        self.description = description

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        raise NotImplementedError

class SSHBruteForceRule(DetectionRule):
    def __init__(self, threshold: int = 5, window_minutes: int = 15):
        super().__init__(
            rule_id="RULE-SSH-BRUTEFORCE",
            name="SSH Authentication Brute Force Attack",
            default_severity="HIGH",
            description=f"Detected {threshold}+ failed SSH authentication attempts from a single source IP within a {window_minutes}-minute window."
        )
        self.threshold = threshold
        self.window_minutes = window_minutes

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        # Filter for SSH / Auth failures
        fails = [
            e for e in events 
            if e.get("event_type") == "AUTH_FAILURE" and e.get("source_ip")
        ]
        
        # Group by source_ip
        ip_groups: Dict[str, List[Dict[str, Any]]] = {}
        for ev in fails:
            ip = ev["source_ip"]
            ip_groups.setdefault(ip, []).append(ev)

        for ip, ev_list in ip_groups.items():
            if len(ev_list) >= self.threshold:
                ev_list_sorted = sorted(ev_list, key=lambda x: x["timestamp"])
                first_ts = ev_list_sorted[0]["timestamp"]
                last_ts = ev_list_sorted[-1]["timestamp"]
                
                # Check time delta
                if isinstance(first_ts, datetime) and isinstance(last_ts, datetime):
                    if (last_ts - first_ts) <= timedelta(minutes=self.window_minutes * 2):
                        detections.append({
                            "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
                            "title": f"SSH Brute Force from {ip}",
                            "detection_type": "RULE",
                            "rule_id": self.rule_id,
                            "severity": "HIGH",
                            "description": f"Identified {len(ev_list)} failed SSH authentication attempts originating from IP address {ip}.",
                            "confidence": 0.95,
                            "triggering_event_ids": [e["event_id"] for e in ev_list],
                            "relevant_fields": {
                                "source_ip": ip,
                                "failed_count": len(ev_list),
                                "targeted_users": list(set(e["username"] for e in ev_list)),
                                "first_seen": str(first_ts),
                                "last_seen": str(last_ts),
                            },
                            "timestamp": last_ts
                        })
        return detections

class SuspiciousSuccessfulAuthRule(DetectionRule):
    def __init__(self, failure_threshold: int = 3, window_minutes: int = 30):
        super().__init__(
            rule_id="RULE-SUSP-AUTH-SUCCESS",
            name="Successful Authentication Following Repeated Failures",
            default_severity="CRITICAL",
            description="Detected a successful logon event from an IP address or user that previously generated multiple authentication failures."
        )
        self.failure_threshold = failure_threshold
        self.window_minutes = window_minutes

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        sorted_events = sorted(events, key=lambda x: x["timestamp"])
        
        # Track failures per (source_ip, username)
        failure_tracker: Dict[str, List[Dict[str, Any]]] = {}

        for ev in sorted_events:
            src_ip = ev.get("source_ip", "")
            user = ev.get("username", "")
            key = f"{src_ip}:{user}" if src_ip else user

            if ev.get("event_type") == "AUTH_FAILURE":
                failure_tracker.setdefault(key, []).append(ev)
            elif ev.get("event_type") == "AUTH_SUCCESS":
                prior_fails = failure_tracker.get(key, [])
                # Also check matching by IP alone if user varied
                ip_fails = [f for f_key, f_list in failure_tracker.items() if src_ip and f_key.startswith(f"{src_ip}:") for f in f_list]
                
                relevant_fails = prior_fails if len(prior_fails) >= self.failure_threshold else (ip_fails if len(ip_fails) >= self.failure_threshold else [])
                
                if len(relevant_fails) >= self.failure_threshold:
                    # Potential compromised account or brute-force success
                    trigger_ids = [f["event_id"] for f in relevant_fails[-self.failure_threshold:]] + [ev["event_id"]]
                    detections.append({
                        "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
                        "title": f"Compromise Alert: Successful Auth Post-Failures ({user})",
                        "detection_type": "RULE",
                        "rule_id": self.rule_id,
                        "severity": "CRITICAL",
                        "description": f"User '{user}' successfully authenticated from {src_ip} immediately following {len(relevant_fails)} failed attempts.",
                        "confidence": 0.98,
                        "triggering_event_ids": trigger_ids,
                        "relevant_fields": {
                            "source_ip": src_ip,
                            "username": user,
                            "prior_failed_count": len(relevant_fails),
                            "success_timestamp": str(ev["timestamp"]),
                            "hostname": ev.get("hostname", "unknown")
                        },
                        "timestamp": ev["timestamp"]
                    })
                    # Clear out tracker for this key to prevent duplicates
                    failure_tracker[key] = []
        return detections

class WindowsLogonBurstRule(DetectionRule):
    def __init__(self, threshold: int = 5):
        super().__init__(
            rule_id="RULE-WIN-4625-BURST",
            name="Multiple Windows Logon Failures (Event 4625)",
            default_severity="HIGH",
            description=f"Identified multiple Windows Security Event 4625 logon failures across systems."
        )
        self.threshold = threshold

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        win_fails = [e for e in events if str(e.get("event_id_native")) == "4625"]
        if len(win_fails) >= self.threshold:
            targets = list(set(e.get("username") for e in win_fails if e.get("username")))
            hosts = list(set(e.get("hostname") for e in win_fails if e.get("hostname")))
            last_ts = max(e["timestamp"] for e in win_fails)
            detections.append({
                "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
                "title": f"Windows Logon Failure Burst ({len(win_fails)} events)",
                "detection_type": "RULE",
                "rule_id": self.rule_id,
                "severity": "HIGH",
                "description": f"Encountered {len(win_fails)} Windows 4625 failure events targeting users: {targets[:5]} on host(s) {hosts}.",
                "confidence": 0.92,
                "triggering_event_ids": [e["event_id"] for e in win_fails],
                "relevant_fields": {
                    "targeted_users": targets,
                    "affected_hosts": hosts,
                    "total_failures": len(win_fails)
                },
                "timestamp": last_ts
            })
        return detections

class PrivilegeEscalationRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE-PRIV-ESCALATION",
            name="Potential Privilege Escalation Activity",
            default_severity="HIGH",
            description="Identified administrative privilege assignment (Event 4672) or suspicious sudo invocation."
        )

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        priv_events = [
            e for e in events 
            if e.get("event_type") == "PRIVILEGE_ESCALATION" or str(e.get("event_id_native")) in ["4672", "sudo"]
        ]
        for ev in priv_events:
            detections.append({
                "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
                "title": f"Privilege Escalation on {ev.get('hostname', 'host')}",
                "detection_type": "RULE",
                "rule_id": self.rule_id,
                "severity": "HIGH",
                "description": f"User '{ev.get('username')}' acquired elevated privileges or executed privileged command: {ev.get('command_line') or 'Special Privileges Assigned'}.",
                "confidence": 0.88,
                "triggering_event_ids": [ev["event_id"]],
                "relevant_fields": {
                    "username": ev.get("username"),
                    "hostname": ev.get("hostname"),
                    "command_line": ev.get("command_line"),
                    "process_name": ev.get("process_name")
                },
                "timestamp": ev["timestamp"]
            })
        return detections

class AccountCreationRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE-ACCOUNT-CREATION",
            name="User Account Created",
            default_severity="MEDIUM",
            description="Detected creation of a new user account (Event 4720 or useradd)."
        )

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        user_creates = [
            e for e in events 
            if e.get("event_type") == "USER_CREATE" or str(e.get("event_id_native")) in ["4720", "useradd"]
        ]
        for ev in user_creates:
            detections.append({
                "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
                "title": f"New User Account Created: {ev.get('username')}",
                "detection_type": "RULE",
                "rule_id": self.rule_id,
                "severity": "MEDIUM",
                "description": f"New local account '{ev.get('username')}' created on {ev.get('hostname')}.",
                "confidence": 0.95,
                "triggering_event_ids": [ev["event_id"]],
                "relevant_fields": {
                    "username": ev.get("username"),
                    "hostname": ev.get("hostname"),
                    "raw": ev.get("raw_event")
                },
                "timestamp": ev["timestamp"]
            })
        return detections

class SuspiciousProcessExecutionRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE-SUSP-PROCESS",
            name="Suspicious Process Execution",
            default_severity="HIGH",
            description="Detected execution of recon or exploitation utilities (e.g., mimikatz, whoami, nmap, netcat, certutil, base64 powershell)."
        )
        self.suspicious_keywords = [
            "mimikatz", "certutil", "nc.exe", "netcat", "whoami", "nmap", 
            "powershell -enc", "-encodedcommand", "curl", "wget", "id", "/etc/shadow"
        ]

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        for ev in events:
            cmd = (ev.get("command_line") or "").lower()
            proc = (ev.get("process_name") or "").lower()
            matched = [kw for kw in self.suspicious_keywords if kw in cmd or kw in proc]
            if matched:
                detections.append({
                    "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
                    "title": f"Suspicious Command Execution ({matched[0]})",
                    "detection_type": "RULE",
                    "rule_id": self.rule_id,
                    "severity": "HIGH",
                    "description": f"Host {ev.get('hostname')} executed command matching suspicious pattern '{matched[0]}': {ev.get('command_line') or ev.get('process_name')}.",
                    "confidence": 0.90,
                    "triggering_event_ids": [ev["event_id"]],
                    "relevant_fields": {
                        "matched_keyword": matched[0],
                        "process_name": ev.get("process_name"),
                        "command_line": ev.get("command_line"),
                        "username": ev.get("username"),
                        "hostname": ev.get("hostname")
                    },
                    "timestamp": ev["timestamp"]
                })
        return detections

class SuspiciousNetworkConnectionRule(DetectionRule):
    def __init__(self, high_frequency_threshold: int = 10):
        super().__init__(
            rule_id="RULE-SUSP-NETWORK",
            name="Unusual Network Outbound Connections",
            default_severity="MEDIUM",
            description="Detected multiple outbound network connections to external or non-standard endpoints."
        )
        self.threshold = high_frequency_threshold

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        net_events = [e for e in events if e.get("event_type") == "NETWORK_CONNECT" and e.get("destination_ip")]
        
        # Group by dest_ip
        dest_groups: Dict[str, List[Dict[str, Any]]] = {}
        for ev in net_events:
            dst = ev["destination_ip"]
            dest_groups.setdefault(dst, []).append(ev)

        for dst, ev_list in dest_groups.items():
            if len(ev_list) >= self.threshold or any(dst.startswith(prefix) for prefix in ["198.51.100.", "203.0.113.", "185.220."]):
                last_ts = max(e["timestamp"] for e in ev_list)
                detections.append({
                    "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
                    "title": f"High Volume Outbound Traffic to {dst}",
                    "detection_type": "RULE",
                    "rule_id": self.rule_id,
                    "severity": "HIGH" if len(ev_list) >= self.threshold else "MEDIUM",
                    "description": f"Detected {len(ev_list)} connection attempts to destination IP {dst}.",
                    "confidence": 0.85,
                    "triggering_event_ids": [e["event_id"] for e in ev_list],
                    "relevant_fields": {
                        "destination_ip": dst,
                        "connection_count": len(ev_list),
                        "source_hosts": list(set(e.get("hostname", "unknown") for e in ev_list))
                    },
                    "timestamp": last_ts
                })
        return detections

class PasswordSprayingRule(DetectionRule):
    def __init__(self, unique_users_threshold: int = 3):
        super().__init__(
            rule_id="RULE-PASSWORD-SPRAYING",
            name="Repeated Failures Across Multiple Accounts (Password Spraying)",
            default_severity="HIGH",
            description=f"Identified authentication failures targeting {unique_users_threshold}+ unique usernames from the same source IP."
        )
        self.unique_users_threshold = unique_users_threshold

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        fails = [e for e in events if e.get("event_type") == "AUTH_FAILURE" and e.get("source_ip")]
        
        ip_users: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for ev in fails:
            src = ev["source_ip"]
            user = ev.get("username", "unknown")
            ip_users.setdefault(src, {}).setdefault(user, []).append(ev)

        for src, user_dict in ip_users.items():
            if len(user_dict) >= self.unique_users_threshold:
                all_evs = [ev for u_evs in user_dict.values() for ev in u_evs]
                last_ts = max(e["timestamp"] for e in all_evs)
                detections.append({
                    "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
                    "title": f"Password Spraying Campaign from {src}",
                    "detection_type": "RULE",
                    "rule_id": self.rule_id,
                    "severity": "HIGH",
                    "description": f"Source IP {src} attempted authenticating against {len(user_dict)} different accounts: {list(user_dict.keys())[:5]}.",
                    "confidence": 0.94,
                    "triggering_event_ids": [e["event_id"] for e in all_evs],
                    "relevant_fields": {
                        "source_ip": src,
                        "unique_targeted_users": list(user_dict.keys()),
                        "total_attempts": len(all_evs)
                    },
                    "timestamp": last_ts
                })
        return detections

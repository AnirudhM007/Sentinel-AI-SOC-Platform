import os
import json
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.parsers.normalizer import detect_and_normalize
from app.detection.engine import detection_engine
from app.ml.model import anomaly_detector
from app.models.log_event import LogEvent
from app.models.alert import Alert

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

SCENARIOS_META = {
    "scenario_1": {
        "id": "scenario_1",
        "title": "SSH Authentication Brute Force",
        "filename": "scenario_1_ssh_bruteforce.log",
        "description": "Repeated failed SSH attempts from scanner IP (198.51.100.45) followed by successful interactive login.",
        "simulated": True,
        "category": "Credential Access"
    },
    "scenario_2": {
        "id": "scenario_2",
        "title": "Suspicious Windows Authentication & Privileges",
        "filename": "scenario_2_windows_auth.csv",
        "description": "Windows 4625 failed logins followed by 4624 successful logon and 4672 special privilege assignment.",
        "simulated": True,
        "category": "Privilege Escalation"
    },
    "scenario_3": {
        "id": "scenario_3",
        "title": "Privilege Escalation & Account Backdoor",
        "filename": "scenario_3_privilege_escalation.json",
        "description": "Unauthorized sudo execution, download of secondary staging payload, and creation of local backdoor user.",
        "simulated": True,
        "category": "Persistence"
    },
    "scenario_4": {
        "id": "scenario_4",
        "title": "Suspicious Outbound C2 Network Activity",
        "filename": "scenario_4_suspicious_network.csv",
        "description": "High-frequency beaconing connections to known external command-and-control IP (203.0.113.19).",
        "simulated": True,
        "category": "Command and Control"
    },
    "scenario_5": {
        "id": "scenario_5",
        "title": "Benign Operational Telemetry",
        "filename": "scenario_5_benign_traffic.log",
        "description": "Expected routine system logons and maintenance cron scripts; baseline verification with zero malicious alerts.",
        "simulated": True,
        "category": "Benign Baseline"
    },
    "scenario_6": {
        "id": "scenario_6",
        "title": "C2 Packet Capture & DNS Exfiltration (PCAP)",
        "filename": "scenario_6_c2_capture.pcap",
        "description": "Raw packet capture (.pcap) containing DNS beacon queries, HTTP stage2 fetch, reverse shell on port 4444, and TLS SNI traffic.",
        "simulated": True,
        "category": "Network & C2"
    }
}

def load_scenario(scenario_id: str, db: Session) -> Dict[str, Any]:
    meta = SCENARIOS_META.get(scenario_id)
    if not meta:
        raise ValueError(f"Unknown scenario ID: {scenario_id}")

    filepath = os.path.join(DATA_DIR, meta["filename"])
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Scenario file not found: {filepath}")

    with open(filepath, "rb") as f:
        content = f.read()

    # 1. Normalize events
    normalized_events, stats = detect_and_normalize(content, meta["filename"])

    # 2. Persist events to DB
    for ev in normalized_events:
        db_ev = LogEvent(
            event_id=ev["event_id"],
            timestamp=ev["timestamp"],
            hostname=ev.get("hostname", "unknown"),
            username=ev.get("username", "unknown"),
            source_ip=ev.get("source_ip", ""),
            destination_ip=ev.get("destination_ip", ""),
            event_type=ev.get("event_type", "SYSTEM_LOG"),
            event_id_native=ev.get("event_id_native", ""),
            process_name=ev.get("process_name", ""),
            command_line=ev.get("command_line", ""),
            status=ev.get("status", "UNKNOWN"),
            severity=ev.get("severity", "INFORMATIONAL"),
            raw_event=ev.get("raw_event", ""),
            file_source=f"[SIMULATED] {meta['title']}"
        )
        db.add(db_ev)

    # 3. Run Rule-based Detection
    rule_alerts = detection_engine.run_detection(normalized_events)

    # 4. Run ML Anomaly Detection
    ml_alerts = anomaly_detector.detect_anomalies(normalized_events)

    all_alerts = rule_alerts + ml_alerts

    # 5. Persist Alerts to DB
    for alt in all_alerts:
        db_alt = Alert(
            alert_id=alt["alert_id"],
            title=alt["title"],
            detection_type=alt.get("detection_type", "RULE"),
            rule_id=alt.get("rule_id", ""),
            severity=alt.get("severity", "MEDIUM"),
            description=alt["description"],
            confidence=alt.get("confidence", 1.0),
            triggering_event_ids=json.dumps(alt.get("triggering_event_ids", [])),
            relevant_fields=json.dumps(alt.get("relevant_fields", {})),
            status="NEW",
            timestamp=alt.get("timestamp")
        )
        db.add(db_alt)

    db.commit()

    return {
        "scenario_id": scenario_id,
        "title": meta["title"],
        "description": meta["description"],
        "events_ingested": len(normalized_events),
        "alerts_generated": len(all_alerts),
        "rule_alerts_count": len(rule_alerts),
        "ml_alerts_count": len(ml_alerts),
        "alerts_summary": [{"alert_id": a["alert_id"], "title": a["title"], "severity": a["severity"]} for a in all_alerts]
    }

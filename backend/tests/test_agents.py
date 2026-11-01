import datetime
from app.agents.workflow import investigation_graph
from app.agents.state import AgentState

def test_full_investigation_graph_execution():
    base_time = datetime.datetime(2026, 10, 31, 22, 15, 0)
    events = [
        {
            "event_id": f"evt-{i}",
            "timestamp": base_time + datetime.timedelta(seconds=i*3),
            "hostname": "srv-edge-01",
            "username": "admin",
            "source_ip": "198.51.100.45",
            "destination_ip": "",
            "event_type": "AUTH_FAILURE",
            "event_id_native": "sshd_failed",
            "process_name": "sshd",
            "command_line": "",
            "status": "FAILURE",
            "severity": "LOW",
            "raw_event": "Failed password for admin"
        }
        for i in range(5)
    ]
    # Add successful auth and privilege command
    events.append({
        "event_id": "evt-succ",
        "timestamp": base_time + datetime.timedelta(seconds=30),
        "hostname": "srv-edge-01",
        "username": "ubuntu",
        "source_ip": "198.51.100.45",
        "destination_ip": "",
        "event_type": "AUTH_SUCCESS",
        "event_id_native": "sshd_accepted",
        "process_name": "sshd",
        "command_line": "",
        "status": "SUCCESS",
        "severity": "INFORMATIONAL",
        "raw_event": "Accepted password for ubuntu"
    })
    events.append({
        "event_id": "evt-priv",
        "timestamp": base_time + datetime.timedelta(seconds=45),
        "hostname": "srv-edge-01",
        "username": "ubuntu",
        "source_ip": "",
        "destination_ip": "",
        "event_type": "PRIVILEGE_ESCALATION",
        "event_id_native": "sudo",
        "process_name": "sudo",
        "command_line": "/usr/bin/whoami",
        "status": "SUCCESS",
        "severity": "MEDIUM",
        "raw_event": "sudo whoami"
    })

    alerts = [
        {
            "alert_id": "ALT-001",
            "title": "SSH Brute Force from 198.51.100.45",
            "detection_type": "RULE",
            "rule_id": "RULE-SSH-BRUTEFORCE",
            "severity": "HIGH",
            "description": "5 failed SSH attempts",
            "confidence": 0.95,
            "triggering_event_ids": [f"evt-{i}" for i in range(5)],
            "relevant_fields": {"source_ip": "198.51.100.45"},
            "timestamp": str(base_time)
        },
        {
            "alert_id": "ALT-002",
            "title": "Compromise Alert: Successful Auth Post-Failures",
            "detection_type": "RULE",
            "rule_id": "RULE-SUSP-AUTH-SUCCESS",
            "severity": "CRITICAL",
            "description": "Interactive login succeeded",
            "confidence": 0.98,
            "triggering_event_ids": ["evt-4", "evt-succ"],
            "relevant_fields": {"source_ip": "198.51.100.45", "username": "ubuntu"},
            "timestamp": str(base_time)
        }
    ]

    initial_state: AgentState = {
        "investigation_id": "INV-TEST-001",
        "title": "Test SSH Brute Force Investigation",
        "events": events,
        "alerts": alerts,
        "triage_verdict": {},
        "log_findings": {},
        "threat_intel_findings": [],
        "mitre_mappings": [],
        "incident_analysis": {},
        "validation_result": {},
        "final_report": {},
        "traces": [],
        "iteration_count": 0,
        "error_logs": []
    }

    # Execute LangGraph workflow
    result = investigation_graph.invoke(initial_state)

    # Assertions
    assert "triage_verdict" in result
    assert result["triage_verdict"]["is_suspicious"] is True
    assert len(result["traces"]) >= 6  # Triage, Log, Threat, MITRE, Analysis, Validation, Report

    report = result["final_report"]
    assert report["severity"] == "CRITICAL"
    assert len(report["mitre_attack_mappings"]) > 0
    assert len(report["threat_intelligence_findings"]) > 0
    assert report["validation_status"] == "PASSED"
    assert len(report["recommended_remediation"]) > 0

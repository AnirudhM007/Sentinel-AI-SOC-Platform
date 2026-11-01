import datetime
from app.detection.engine import detection_engine

def test_ssh_brute_force_rule():
    base_time = datetime.datetime(2026, 10, 31, 20, 0, 0)
    events = [
        {
            "event_id": f"evt-{i}",
            "timestamp": base_time + datetime.timedelta(seconds=i*10),
            "hostname": "srv-linux",
            "username": f"user{i}",
            "source_ip": "198.51.100.45",
            "event_type": "AUTH_FAILURE",
            "status": "FAILURE"
        }
        for i in range(6)
    ]
    alerts = detection_engine.run_detection(events)
    ssh_alerts = [a for a in alerts if a["rule_id"] == "RULE-SSH-BRUTEFORCE"]
    assert len(ssh_alerts) == 1
    assert ssh_alerts[0]["severity"] == "HIGH"
    assert ssh_alerts[0]["relevant_fields"]["failed_count"] == 6

def test_suspicious_successful_auth_rule():
    base_time = datetime.datetime(2026, 10, 31, 20, 0, 0)
    events = [
        {
            "event_id": f"evt-{i}",
            "timestamp": base_time + datetime.timedelta(seconds=i*5),
            "hostname": "srv-linux",
            "username": "admin",
            "source_ip": "198.51.100.45",
            "event_type": "AUTH_FAILURE",
            "status": "FAILURE"
        }
        for i in range(4)
    ]
    # Subsequent successful auth
    events.append({
        "event_id": "evt-succ",
        "timestamp": base_time + datetime.timedelta(seconds=30),
        "hostname": "srv-linux",
        "username": "admin",
        "source_ip": "198.51.100.45",
        "event_type": "AUTH_SUCCESS",
        "status": "SUCCESS"
    })
    alerts = detection_engine.run_detection(events)
    comp_alerts = [a for a in alerts if a["rule_id"] == "RULE-SUSP-AUTH-SUCCESS"]
    assert len(comp_alerts) == 1
    assert comp_alerts[0]["severity"] == "CRITICAL"

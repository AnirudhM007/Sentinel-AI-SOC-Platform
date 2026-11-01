from app.mitre.mapper import mitre_mapper

def test_mitre_mapping_ssh_bruteforce():
    alerts = [{"rule_id": "RULE-SSH-BRUTEFORCE", "title": "SSH Brute Force from 198.51.100.45", "description": ""}]
    events = [{"event_type": "AUTH_FAILURE"}]
    mappings = mitre_mapper.map_behaviors(alerts, events)
    tech_ids = [m["technique_id"] for m in mappings]
    assert "T1110.001" in tech_ids  # Brute Force: Password Guessing
    assert "T1021.004" in tech_ids  # Remote Services: SSH

def test_mitre_mapping_privilege_escalation():
    alerts = [{"rule_id": "RULE-PRIV-ESCALATION", "title": "Privilege Escalation on host", "description": ""}]
    events = [{"event_type": "PRIVILEGE_ESCALATION", "command_line": "sudo bash"}]
    mappings = mitre_mapper.map_behaviors(alerts, events)
    tech_ids = [m["technique_id"] for m in mappings]
    assert "T1548.003" in tech_ids  # Sudo and Sudo Caching

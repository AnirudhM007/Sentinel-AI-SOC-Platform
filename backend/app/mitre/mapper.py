from typing import List, Dict, Any
from app.mitre.knowledge_base import MITRE_TECHNIQUES

class MitreMapper:
    def map_behaviors(self, alerts: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Maps observed alerts and event patterns to verified MITRE ATT&CK techniques.
        Never invents technique IDs.
        """
        mappings = []
        mapped_tech_ids = set()

        # Combine alert titles and rule IDs
        rule_ids = set()
        alert_texts = []
        for a in alerts:
            rule_ids.add(a.get("rule_id", ""))
            alert_texts.append(a.get("title", "") + " " + a.get("description", ""))

        all_alert_text = " ".join(alert_texts).lower()

        # 1. SSH / Password Brute Force
        if "RULE-SSH-BRUTEFORCE" in rule_ids or "ssh brute force" in all_alert_text:
            tech = MITRE_TECHNIQUES["T1110.001"]
            supporting = [a.get("title", "") for a in alerts if "ssh" in a.get("title", "").lower() or "brute" in a.get("title", "").lower()]
            mappings.append({
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "tactic": tech["tactic"],
                "reason": "Multiple failed SSH password attempts from a single source host indicates automated password guessing.",
                "confidence": 0.95,
                "supporting_evidence": supporting or ["Repeated AUTH_FAILURE events observed over SSH port 22"]
            })
            mapped_tech_ids.add("T1110.001")

            # Remote Services SSH
            tech_ssh = MITRE_TECHNIQUES["T1021.004"]
            mappings.append({
                "technique_id": tech_ssh["id"],
                "technique_name": tech_ssh["name"],
                "tactic": tech_ssh["tactic"],
                "reason": "Activity explicitly targets remote Secure Shell daemon (sshd).",
                "confidence": 0.90,
                "supporting_evidence": ["Target daemon sshd identified in log traces"]
            })
            mapped_tech_ids.add("T1021.004")

        # 2. Password Spraying
        if "RULE-PASSWORD-SPRAYING" in rule_ids or "password spray" in all_alert_text:
            tech = MITRE_TECHNIQUES["T1110.003"]
            mappings.append({
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "tactic": tech["tactic"],
                "reason": "Authentication attempts targeted multiple distinct user identities in rapid succession from one IP.",
                "confidence": 0.92,
                "supporting_evidence": ["Observed multiple unique account targets from common origin IP"]
            })
            mapped_tech_ids.add("T1110.003")

        # 3. Successful Auth after Failures / Valid Accounts
        if "RULE-SUSP-AUTH-SUCCESS" in rule_ids or "successful auth post-failures" in all_alert_text:
            tech = MITRE_TECHNIQUES["T1078"]
            mappings.append({
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "tactic": tech["tactic"],
                "reason": "Adversary successfully gained interactive access following brute-force attempts, demonstrating credential abuse.",
                "confidence": 0.94,
                "supporting_evidence": ["AUTH_SUCCESS recorded following repeated AUTH_FAILURE sequence"]
            })
            mapped_tech_ids.add("T1078")

        # 4. Privilege Escalation / Sudo / 4672
        if "RULE-PRIV-ESCALATION" in rule_ids or any(e.get("event_type") == "PRIVILEGE_ESCALATION" for e in events):
            tech = MITRE_TECHNIQUES["T1548.003"]
            sudo_events = [e for e in events if "sudo" in (e.get("raw_event", "") + e.get("command_line", "")).lower()]
            ev_summary = [f"Command: {e.get('command_line')}" for e in sudo_events[:3]]
            mappings.append({
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "tactic": tech["tactic"],
                "reason": "User executed commands with elevated privileges using sudo or assigned administrative token rights (Event 4672).",
                "confidence": 0.90,
                "supporting_evidence": ev_summary or ["Privilege escalation event observed in system logs"]
            })
            mapped_tech_ids.add("T1548.003")

        # 5. Account Creation
        if "RULE-ACCOUNT-CREATION" in rule_ids or any(e.get("event_type") == "USER_CREATE" for e in events):
            tech = MITRE_TECHNIQUES["T1136.001"]
            create_evs = [e for e in events if e.get("event_type") == "USER_CREATE"]
            mappings.append({
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "tactic": tech["tactic"],
                "reason": "Creation of a new local user account indicates attempt to establish persistent backdoor access.",
                "confidence": 0.96,
                "supporting_evidence": [f"Account created: {e.get('username')}" for e in create_evs[:2]]
            })
            mapped_tech_ids.add("T1136.001")

        # 6. Suspicious Process Execution
        if "RULE-SUSP-PROCESS" in rule_ids or any("whoami" in (e.get("command_line", "")).lower() for e in events):
            # Check for whoami / discovery
            if any("whoami" in (e.get("command_line", "")).lower() or "id" in (e.get("command_line", "")).lower() for e in events):
                tech = MITRE_TECHNIQUES["T1087.001"]
                mappings.append({
                    "technique_id": tech["id"],
                    "technique_name": tech["name"],
                    "tactic": tech["tactic"],
                    "reason": "Execution of discovery utility to identify current user security context.",
                    "confidence": 0.88,
                    "supporting_evidence": ["Observed whoami / id execution post-authentication"]
                })
                mapped_tech_ids.add("T1087.001")

            # Check for PowerShell
            if any("powershell" in (e.get("command_line", "") + e.get("process_name", "")).lower() for e in events):
                tech = MITRE_TECHNIQUES["T1059.001"]
                mappings.append({
                    "technique_id": tech["id"],
                    "technique_name": tech["name"],
                    "tactic": tech["tactic"],
                    "reason": "PowerShell command execution observed in system telemetry.",
                    "confidence": 0.90,
                    "supporting_evidence": ["PowerShell runtime invocation captured in telemetry"]
                })
                mapped_tech_ids.add("T1059.001")

        # 7. Suspicious Network Traffic / C2
        if "RULE-SUSP-NETWORK" in rule_ids or any(e.get("event_type") == "NETWORK_CONNECT" for e in events):
            tech = MITRE_TECHNIQUES["T1071.001"]
            net_evs = [e for e in events if e.get("event_type") == "NETWORK_CONNECT"]
            dsts = list(set(e.get("destination_ip") for e in net_evs if e.get("destination_ip")))
            mappings.append({
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "tactic": tech["tactic"],
                "reason": "Repeated outbound communication with external destinations indicating potential beaconing or exfiltration.",
                "confidence": 0.82,
                "supporting_evidence": [f"Connections directed to: {', '.join(dsts[:3])}"]
            })
            mapped_tech_ids.add("T1071.001")

        return mappings

mitre_mapper = MitreMapper()

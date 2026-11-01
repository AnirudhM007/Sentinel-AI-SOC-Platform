from typing import Dict, Any

MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1110.001": {
        "id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to systematically guess the passwords of users across systems to compromise credentials.",
        "url": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "T1110.003": {
        "id": "T1110.003",
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt a single or small set of passwords against many different accounts to avoid account lockout.",
        "url": "https://attack.mitre.org/techniques/T1110/003/"
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence / Privilege Escalation / Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access or Persistence.",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "T1021.004": {
        "id": "T1021.004",
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into remote machines via Secure Shell (SSH) protocol.",
        "url": "https://attack.mitre.org/techniques/T1021/004/"
    },
    "T1548.003": {
        "id": "T1548.003",
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation / Defense Evasion",
        "description": "Adversaries may execute commands as the root user using sudo or exploit sudoers configuration errors.",
        "url": "https://attack.mitre.org/techniques/T1548/003/"
    },
    "T1078.002": {
        "id": "T1078.002",
        "name": "Valid Accounts: Domain Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "description": "Adversaries may compromise and abuse domain accounts to navigate an enterprise environment.",
        "url": "https://attack.mitre.org/techniques/T1078/002/"
    },
    "T1136.001": {
        "id": "T1136.001",
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "description": "Adversaries may create a local account to maintain access to victim systems.",
        "url": "https://attack.mitre.org/techniques/T1136/001/"
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for executing malicious actions and downloading stages.",
        "url": "https://attack.mitre.org/techniques/T1059/001/"
    },
    "T1087.001": {
        "id": "T1087.001",
        "name": "Account Discovery: Local Account",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of local system accounts using commands like whoami or id.",
        "url": "https://attack.mitre.org/techniques/T1087/001/"
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts using scanners or port sweeps.",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (e.g. HTTP, HTTPS) to blend in with normal network traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "T1543.003": {
        "id": "T1543.003",
        "name": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Adversaries may create or modify Windows services to execute malicious binaries on boot.",
        "url": "https://attack.mitre.org/techniques/T1543/003/"
    }
}

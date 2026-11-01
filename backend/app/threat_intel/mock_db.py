from typing import Dict, Any

MOCK_THREAT_DATABASE: Dict[str, Dict[str, Any]] = {
    "198.51.100.45": {
        "reputation_score": 92.0,
        "is_malicious": True,
        "category": "Brute Force / SSH Scanner",
        "isp": "Digital Ocean Suspicious Host",
        "country": "NL",
        "reports_count": 148,
        "last_reported": "2026-10-31T18:22:10Z",
        "tags": ["ssh-bruteforce", "scanner", "botnet"]
    },
    "203.0.113.19": {
        "reputation_score": 88.0,
        "is_malicious": True,
        "category": "Command and Control (C2)",
        "isp": "Bulletproof Hosting Ltd",
        "country": "RU",
        "reports_count": 94,
        "last_reported": "2026-10-30T11:05:00Z",
        "tags": ["c2", "cobalt-strike", "data-exfil"]
    },
    "185.220.101.5": {
        "reputation_score": 96.0,
        "is_malicious": True,
        "category": "Tor Exit Node / Anonymizer",
        "isp": "Tor Relay Network",
        "country": "DE",
        "reports_count": 312,
        "last_reported": "2026-11-01T08:14:00Z",
        "tags": ["tor-exit", "anonymization", "high-risk"]
    },
    "45.33.32.156": {
        "reputation_score": 45.0,
        "is_malicious": False,
        "category": "Port Scanning / Research",
        "isp": "Linode, LLC",
        "country": "US",
        "reports_count": 8,
        "last_reported": "2026-09-15T00:00:00Z",
        "tags": ["reconnaissance", "security-research"]
    },
    "8.8.8.8": {
        "reputation_score": 0.0,
        "is_malicious": False,
        "category": "Legitimate Public DNS",
        "isp": "Google LLC",
        "country": "US",
        "reports_count": 0,
        "last_reported": None,
        "tags": ["benign", "dns-resolver"]
    },
    "1.1.1.1": {
        "reputation_score": 0.0,
        "is_malicious": False,
        "category": "Legitimate Public DNS",
        "isp": "Cloudflare, Inc.",
        "country": "US",
        "reports_count": 0,
        "last_reported": None,
        "tags": ["benign", "dns-resolver"]
    },
    "192.168.1.100": {
        "reputation_score": 0.0,
        "is_malicious": False,
        "category": "Private RFC 1918 Address",
        "isp": "Local Area Network",
        "country": "INTERNAL",
        "reports_count": 0,
        "last_reported": None,
        "tags": ["private-ip", "internal"]
    },
    "10.0.0.15": {
        "reputation_score": 0.0,
        "is_malicious": False,
        "category": "Private RFC 1918 Address",
        "isp": "Internal Enterprise Subnet",
        "country": "INTERNAL",
        "reports_count": 0,
        "last_reported": None,
        "tags": ["private-ip", "workstation"]
    }
}

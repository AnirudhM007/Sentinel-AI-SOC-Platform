import hashlib
from typing import List, Dict, Any, Tuple, Union
from app.parsers.linux_auth import parse_linux_auth_log
from app.parsers.windows_events import parse_windows_event_csv
from app.parsers.generic_parser import parse_generic_json, parse_generic_csv
from app.parsers.pcap_parser import parse_pcap_bytes

def detect_and_normalize(content: Union[str, bytes], filename: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Auto-detect log format and normalize into standard schema.
    Supports:
    - PCAP / PCAPNG network packet captures (.pcap, .pcapng, .cap)
    - Linux authentication / syslog text logs
    - Windows Security Events CSV exports
    - Generic SIEM JSON exports
    - Generic CSV security logs
    Returns (normalized_events, stats_dict).
    """
    fn_lower = filename.lower()
    raw_events: List[Dict[str, Any]] = []
    format_detected = "UNKNOWN"

    # 1. PCAP / Binary packet capture detection
    is_pcap_file = fn_lower.endswith((".pcap", ".pcapng", ".cap"))
    raw_bytes = content if isinstance(content, bytes) else content.encode("latin-1", errors="replace")
    has_pcap_magic = len(raw_bytes) >= 4 and raw_bytes[:4] in (
        b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1',
        b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d',
        b'\x0a\x0d\x0d\x0a'
    )

    if is_pcap_file or has_pcap_magic:
        raw_events = parse_pcap_bytes(raw_bytes, filename)
        format_detected = "PCAP_NETWORK_CAPTURE"
    else:
        # Convert to text string for text-based parsers
        text_content = content if isinstance(content, str) else content.decode("utf-8", errors="replace")
        
        if fn_lower.endswith(".json") or text_content.strip().startswith(("{", "[")):
            raw_events = parse_generic_json(text_content, filename)
            format_detected = "JSON"
        elif fn_lower.endswith(".csv") or ("eventid" in text_content.lower() and "," in text_content):
            if "eventid" in text_content.lower() or "targetusername" in text_content.lower():
                raw_events = parse_windows_event_csv(text_content, filename)
                format_detected = "WINDOWS_CSV"
            else:
                raw_events = parse_generic_csv(text_content, filename)
                format_detected = "GENERIC_CSV"
        else:
            # Default to Linux auth/syslog text parser
            raw_events = parse_linux_auth_log(text_content, filename)
            format_detected = "LINUX_AUTH_SYSLOG"

    # 2. De-duplication and sanity validation
    seen_hashes = set()
    normalized_events = []
    invalid_records = 0

    for ev in raw_events:
        # Ensure mandatory attributes
        if not ev.get("event_type") or not ev.get("raw_event"):
            invalid_records += 1
            continue

        # Signature hash for de-duplication
        sig_data = f"{ev.get('timestamp')}|{ev.get('hostname')}|{ev.get('username')}|{ev.get('source_ip')}|{ev.get('destination_ip')}|{ev.get('raw_event')}"
        sig_hash = hashlib.sha256(sig_data.encode("utf-8")).hexdigest()
        if sig_hash in seen_hashes:
            continue
        seen_hashes.add(sig_hash)

        # Standardize severities
        sev = str(ev.get("severity", "INFORMATIONAL")).upper()
        if sev not in ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            sev = "INFORMATIONAL"
        ev["severity"] = sev

        normalized_events.append(ev)

    stats = {
        "filename": filename,
        "format_detected": format_detected,
        "total_parsed": len(raw_events),
        "valid_events": len(normalized_events),
        "duplicates_dropped": len(raw_events) - len(normalized_events) - invalid_records,
        "invalid_records": invalid_records
    }

    return normalized_events, stats

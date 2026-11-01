import pytest
from app.parsers.linux_auth import parse_linux_auth_log
from app.parsers.windows_events import parse_windows_event_csv
from app.parsers.generic_parser import parse_generic_json, parse_generic_csv
from app.parsers.normalizer import detect_and_normalize

def test_linux_auth_parser():
    sample = (
        "Oct 31 12:00:01 host1 sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 44212 ssh2\n"
        "Oct 31 12:00:10 host1 sshd[1236]: Accepted password for root from 192.168.1.50 port 44214 ssh2\n"
        "Oct 31 12:01:00 host1 sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash"
    )
    events = parse_linux_auth_log(sample)
    assert len(events) == 3
    assert events[0]["event_type"] == "AUTH_FAILURE"
    assert events[0]["username"] == "admin"
    assert events[0]["source_ip"] == "192.168.1.50"
    assert events[1]["event_type"] == "AUTH_SUCCESS"
    assert events[2]["event_type"] == "PRIVILEGE_ESCALATION"

def test_windows_event_parser():
    sample = (
        "TimeCreated,EventID,Computer,TargetUserName,IPAddress\n"
        "2026-10-31 14:00:00,4625,WIN-DC,admin,10.0.0.5\n"
        "2026-10-31 14:01:00,4624,WIN-DC,admin,10.0.0.5"
    )
    events = parse_windows_event_csv(sample)
    assert len(events) == 2
    assert events[0]["event_type"] == "AUTH_FAILURE"
    assert events[0]["event_id_native"] == "4625"
    assert events[1]["event_type"] == "AUTH_SUCCESS"
    assert events[1]["event_id_native"] == "4624"

def test_generic_json_parser():
    sample = '[{"event_id": "test-1", "timestamp": "2026-10-31T10:00:00Z", "hostname": "web-01", "username": "alice", "event_type": "AUTH_SUCCESS", "severity": "INFORMATIONAL"}]'
    events = parse_generic_json(sample)
    assert len(events) == 1
    assert events[0]["hostname"] == "web-01"
    assert events[0]["event_type"] == "AUTH_SUCCESS"

def test_detect_and_normalize_deduplication():
    sample = (
        "Oct 31 12:00:01 host1 sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 44212 ssh2\n"
        "Oct 31 12:00:01 host1 sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 44212 ssh2"
    )
    events, stats = detect_and_normalize(sample, "auth.log")
    assert len(events) == 1
    assert stats["duplicates_dropped"] == 1

def test_pcap_parser_and_normalization():
    import struct
    # Construct minimal PCAP with 1 TCP packet
    global_hdr = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    eth_hdr = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00'
    ip_hdr = b'\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00' + bytes([192, 168, 1, 10]) + bytes([198, 51, 100, 45])
    tcp_hdr = struct.pack('!HHIIH', 49152, 443, 1000, 0, (5 << 12) | 0x02) + b'\x00\x00\x00\x00\x00\x00'
    pkt_data = eth_hdr + ip_hdr + tcp_hdr
    pkt_hdr = struct.pack('<IIII', 1700000000, 500000, len(pkt_data), len(pkt_data))
    pcap_bytes = global_hdr + pkt_hdr + pkt_data

    events, stats = detect_and_normalize(pcap_bytes, "traffic.pcap")
    assert len(events) == 1
    assert stats["format_detected"] == "PCAP_NETWORK_CAPTURE"
    assert events[0]["event_type"] == "NETWORK_CONNECT"
    assert events[0]["destination_ip"] == "198.51.100.45"


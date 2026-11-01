import struct
import socket
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

def _format_ip(addr_bytes: bytes) -> str:
    """Format 4 bytes into IPv4 dot notation or 16 bytes into IPv6."""
    if len(addr_bytes) == 4:
        return socket.inet_ntoa(addr_bytes)
    elif len(addr_bytes) == 16:
        return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    return "0.0.0.0"

def _parse_dns_query(payload: bytes) -> Optional[str]:
    """Parse standard DNS query payload to extract queried domain name."""
    try:
        if len(payload) < 12:
            return None
        # DNS Header: ID (2), Flags (2), QDCOUNT (2), ...
        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount == 0:
            return None
        
        offset = 12
        labels = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                break
            if length > 63: # Pointer or corrupted
                break
            offset += 1
            if offset + length > len(payload):
                break
            labels.append(payload[offset:offset+length].decode("ascii", errors="replace"))
            offset += length
        if labels:
            return ".".join(labels)
    except Exception:
        pass
    return None

def _parse_tls_sni(payload: bytes) -> Optional[str]:
    """Extract Server Name Indication (SNI) from TLS Client Hello."""
    try:
        # TLS Handshake (0x16), Version (0x03, 0x01/03), Client Hello (0x01)
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        
        # Session ID length
        sess_id_len = payload[43]
        pos = 44 + sess_id_len
        if pos + 2 > len(payload):
            return None
        
        # Cipher Suites
        cipher_len = struct.unpack("!H", payload[pos:pos+2])[0]
        pos += 2 + cipher_len
        if pos + 1 > len(payload):
            return None
            
        # Compression methods
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
            
        # Extensions Length
        exts_len = struct.unpack("!H", payload[pos:pos+2])[0]
        pos += 2
        end_exts = pos + exts_len

        while pos + 4 <= min(end_exts, len(payload)):
            ext_type, ext_data_len = struct.unpack("!HH", payload[pos:pos+4])
            pos += 4
            if ext_type == 0x0000: # SNI Extension
                if pos + 5 <= len(payload):
                    # server_name_list_length (2), server_name_type (1: host_name), server_name_length (2)
                    name_len = struct.unpack("!H", payload[pos+3:pos+5])[0]
                    name_bytes = payload[pos+5:pos+5+name_len]
                    return name_bytes.decode("ascii", errors="replace")
            pos += ext_data_len
    except Exception:
        pass
    return None

def _parse_http(payload: bytes) -> Optional[str]:
    """Extract HTTP Request line and Host header."""
    try:
        text = payload[:1024].decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        first_line = lines[0]
        if any(first_line.startswith(m) for m in ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "CONNECT "]):
            host = ""
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break
            return f"{first_line} [Host: {host}]" if host else first_line
    except Exception:
        pass
    return None

def parse_pcap_bytes(raw_bytes: bytes, filename: str = "network_capture.pcap") -> List[Dict[str, Any]]:
    """
    Parse PCAP and PCAPNG binary captures into normalized security event records.
    Supports classic PCAP (little/big endian, micro/nano resolution) and basic PCAPNG.
    """
    events: List[Dict[str, Any]] = []
    if len(raw_bytes) < 24:
        return events

    magic = raw_bytes[:4]
    little_endian = False
    is_nanosec = False
    is_pcapng = False

    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        little_endian = True
        is_nanosec = (magic == b'\x4d\x3c\xb2\xa1')
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        little_endian = False
        is_nanosec = (magic == b'\xa1\xb2\x3c\x4d')
    elif magic == b'\x0a\x0d\x0d\x0a': # PCAPNG Section Header Block
        is_pcapng = True
    else:
        # Not a recognized PCAP magic
        return events

    endian = "<" if little_endian else ">"

    if not is_pcapng:
        # Standard PCAP Global Header: 24 bytes
        # magic (4), v_major (2), v_minor (2), thiszone (4), sigfigs (4), snaplen (4), network (4)
        _, _, _, _, _, _, link_type = struct.unpack(f"{endian}IHHiIII", raw_bytes[:24])
        offset = 24
        
        while offset + 16 <= len(raw_bytes):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", raw_bytes[offset:offset+16])
            offset += 16
            
            if offset + incl_len > len(raw_bytes):
                break
                
            packet_data = raw_bytes[offset:offset+incl_len]
            offset += incl_len

            ev = _parse_packet(packet_data, ts_sec, ts_usec, is_nanosec, link_type, filename)
            if ev:
                events.append(ev)
    else:
        # Basic PCAPNG Block Parser (Enhanced Packet Block: 0x00000006)
        offset = 0
        while offset + 8 <= len(raw_bytes):
            block_type, block_len = struct.unpack("<II", raw_bytes[offset:offset+8])
            if block_len < 12 or offset + block_len > len(raw_bytes):
                break
            
            if block_type == 0x00000006: # Enhanced Packet Block
                # iface_id (4), ts_high (4), ts_low (4), cap_len (4), orig_len (4)
                if block_len >= 28:
                    iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack("<IIIII", raw_bytes[offset+8:offset+28])
                    ts_raw = (ts_high << 32) | ts_low
                    ts_sec = ts_raw // 1000000
                    ts_usec = ts_raw % 1000000
                    
                    pkt_data = raw_bytes[offset+28:offset+28+cap_len]
                    ev = _parse_packet(pkt_data, ts_sec, ts_usec, False, 1, filename)
                    if ev:
                        events.append(ev)
            offset += block_len

    return events

def _parse_packet(data: bytes, ts_sec: int, ts_sub: int, is_nanosec: bool, link_type: int, filename: str) -> Optional[Dict[str, Any]]:
    """Parse raw link-layer packet frame into normalized telemetry event."""
    try:
        # Determine timestamp as datetime object (naive UTC for SQLite)
        dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc).replace(tzinfo=None)

        # Strip Ethernet header (14 bytes) for LINKTYPE_ETHERNET (1)
        net_offset = 0
        eth_type = 0x0800
        if link_type == 1: # Ethernet
            if len(data) < 14:
                return None
            eth_type = struct.unpack("!H", data[12:14])[0]
            net_offset = 14
        elif link_type in (12, 101): # Raw IP
            net_offset = 0

        # Check IPv4 (0x0800)
        if eth_type == 0x0800:
            if len(data) < net_offset + 20:
                return None
            ip_hdr = data[net_offset:net_offset+20]
            ver_ihl = ip_hdr[0]
            ihl = (ver_ihl & 0x0F) * 4
            protocol = ip_hdr[9]
            src_ip = _format_ip(ip_hdr[12:16])
            dst_ip = _format_ip(ip_hdr[16:20])

            trans_offset = net_offset + ihl
            proto_name = "IP"
            src_port = 0
            dst_port = 0
            detail = ""
            event_type = "NETWORK_CONNECT"
            process_name = "network"
            hostname = dst_ip
            severity = "INFORMATIONAL"

            # TCP (6)
            if protocol == 6:
                if len(data) >= trans_offset + 20:
                    src_port, dst_port, _, _, offset_flags = struct.unpack("!HHIIH", data[trans_offset:trans_offset+14])
                    flags = offset_flags & 0x01FF
                    tcp_hdr_len = ((offset_flags >> 12) & 0x0F) * 4
                    payload = data[trans_offset+tcp_hdr_len:]

                    flag_names = []
                    if flags & 0x02: flag_names.append("SYN")
                    if flags & 0x10: flag_names.append("ACK")
                    if flags & 0x01: flag_names.append("FIN")
                    if flags & 0x04: flag_names.append("RST")
                    if flags & 0x08: flag_names.append("PSH")
                    flag_str = "+".join(flag_names) or "TCP"

                    proto_name = f"TCP/{dst_port}"
                    process_name = f"tcp:{dst_port}"

                    # DPI Application Layer inspection
                    if dst_port in (80, 8080, 8000) or src_port in (80, 8080):
                        http_summary = _parse_http(payload)
                        if http_summary:
                            event_type = "HTTP_REQUEST"
                            detail = http_summary
                            process_name = "http"
                    elif dst_port in (443, 8443) or src_port in (443, 8443):
                        sni = _parse_tls_sni(payload)
                        if sni:
                            event_type = "TLS_HANDSHAKE"
                            hostname = sni
                            detail = f"TLS SNI: {sni}"
                            process_name = "tls"
                    elif dst_port in (22, 2222):
                        process_name = "ssh"
                        detail = f"SSH Handshake {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

                    if not detail:
                        detail = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{flag_str}]"

            # UDP (17)
            elif protocol == 17:
                if len(data) >= trans_offset + 8:
                    src_port, dst_port, _, _ = struct.unpack("!HHHH", data[trans_offset:trans_offset+8])
                    payload = data[trans_offset+8:]
                    proto_name = f"UDP/{dst_port}"
                    process_name = f"udp:{dst_port}"

                    if dst_port == 53 or src_port == 53:
                        query_domain = _parse_dns_query(payload)
                        if query_domain:
                            event_type = "DNS_QUERY"
                            hostname = query_domain
                            detail = f"DNS Query: {query_domain}"
                            process_name = "dns"
                    if not detail:
                        detail = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

            # ICMP (1)
            elif protocol == 1:
                proto_name = "ICMP"
                process_name = "icmp"
                detail = f"ICMP Echo/Control {src_ip} -> {dst_ip}"

            # Assign Severity for Outbound / Suspicious Traffic
            if dst_ip.startswith(("198.51.100.", "203.0.113.", "185.220.", "45.33.")):
                severity = "HIGH"
            elif any(s in detail.lower() for s in ["evil", "beacon", "c2", "miner", "mimikatz"]):
                severity = "CRITICAL"
            elif dst_port in (4444, 1337, 8888, 6667): # Common reverse shell / IRC C2 ports
                severity = "HIGH"

            ev_id = f"PCAP-{uuid.uuid4().hex[:12].upper()}"
            raw_preview = data[:min(64, len(data))].hex()

            return {
                "event_id": ev_id,
                "timestamp": dt,
                "hostname": hostname,
                "username": "network",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "event_type": event_type,
                "event_id_native": proto_name,
                "process_name": process_name,
                "command_line": detail,
                "status": "SUCCESS",
                "severity": severity,
                "raw_event": f"[{filename}] {detail} | Hex: {raw_preview}",
                "file_source": filename
            }

    except Exception:
        pass
    return None

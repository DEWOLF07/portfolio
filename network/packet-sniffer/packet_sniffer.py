#!/usr/bin/env python3
"""
Packet Sniffer — watches raw TCP/UDP traffic on your machine in real time.
Works like a stripped down Wireshark. Opens a raw socket so the OS hands us
entire packets before filtering — IP header, TCP/UDP header, payload and all.

Run: sudo python3 packet_sniffer.py [count]
"""

import socket
import struct
import sys
import os

PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

PORTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-ALT", 27017: "MongoDB",
}


def create_raw_socket():
    # Raw sockets bypass OS filtering : requires root/admin
    try:
        if os.name == "nt":
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((socket.gethostbyname(socket.gethostname()), 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        return sock
    except PermissionError:
        print("Run with sudo — raw sockets require root.")
        sys.exit(1)


def parse_ip_header(data):
    # IP header is always 20 bytes. Every router on earth reads this same structure.
    # ! = network byte order (big endian), B = 1 byte, H = 2 bytes, 4s = 4-byte string
    ip = struct.unpack("!BBHHHBBH4s4s", data[:20])
    ihl = (ip[0] & 0xF) * 4
    return {
        "ttl":        ip[5],
        "protocol":   ip[6],
        "src_ip":     socket.inet_ntoa(ip[8]),
        "dst_ip":     socket.inet_ntoa(ip[9]),
        "header_end": ihl,
    }


def parse_tcp_header(data, offset):
    tcp = struct.unpack("!HHLLBBHHH", data[offset:offset + 20])
    flags = tcp[5]
    active = []
    if flags & 0x02: active.append("SYN")
    if flags & 0x10: active.append("ACK")
    if flags & 0x01: active.append("FIN")
    if flags & 0x04: active.append("RST")
    if flags & 0x08: active.append("PSH")
    return {
        "src_port":    tcp[0],
        "dst_port":    tcp[1],
        "seq":         tcp[2],
        "ack":         tcp[3],
        "flags":       " | ".join(active) or "NONE",
        "payload_start": offset + (tcp[4] >> 4) * 4,
    }


def parse_udp_header(data, offset):
    udp = struct.unpack("!HHHH", data[offset:offset + 8])
    return {"src_port": udp[0], "dst_port": udp[1], "payload_start": offset + 8}


def hex_dump(data, max_bytes=64):
    lines = []
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i + 16]
        hex_part  = " ".join(f"{b:02x}" for b in chunk).ljust(48)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_part}  {ascii_part}")
    return "\n".join(lines)


def port_label(port):
    return f"{port}({PORTS.get(port, '?')})" if port in PORTS else str(port)


def handshake_label(flags):
    if "SYN" in flags and "ACK" not in flags: return "  >> handshake: SYN"
    if "SYN" in flags and "ACK" in flags:     return "  >> handshake: SYN-ACK"
    if "FIN" in flags:                         return "  >> teardown: FIN"
    return ""


def sniff(count=20):
    print(f"[*] Capturing {count} packets...\n")
    sock = create_raw_socket()

    for i in range(1, count + 1):
        raw, _ = sock.recvfrom(65535)
        ip    = parse_ip_header(raw)
        proto = PROTOCOL_MAP.get(ip["protocol"], f"PROTO-{ip['protocol']}")

        print(f"{'─' * 60}")
        print(f"  #{i} {proto}  {ip['src_ip']} → {ip['dst_ip']}  TTL={ip['ttl']}")

        if ip["protocol"] == 6:  # TCP
            tcp = parse_tcp_header(raw, ip["header_end"])
            print(f"  {port_label(tcp['src_port'])} → {port_label(tcp['dst_port'])}  [{tcp['flags']}]")
            print(f"  seq={tcp['seq']}  ack={tcp['ack']}")
            label = handshake_label(tcp["flags"])
            if label:
                print(label)
            payload = raw[tcp["payload_start"]:]
            if payload:
                print(f"  payload ({len(payload)}B):\n{hex_dump(payload)}")

        elif ip["protocol"] == 17:  # UDP
            udp = parse_udp_header(raw, ip["header_end"])
            print(f"  {port_label(udp['src_port'])} → {port_label(udp['dst_port'])}")
            if 53 in (udp["src_port"], udp["dst_port"]):
                print("  >> DNS")
            payload = raw[udp["payload_start"]:]
            if payload:
                print(f"  payload ({len(payload)}B):\n{hex_dump(payload)}")

        print()

    if os.name == "nt":
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sock.close()
    print(f"[+] Done — {count} packets captured.")


if __name__ == "__main__":
    sniff(int(sys.argv[1]) if len(sys.argv) > 1 else 20)

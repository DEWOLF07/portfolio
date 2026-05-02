import socket
import struct
import sys
import os

# protocols i know about — number comes from the IP header
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# well known ports so i can show a name instead of just a number
PORTS = {
    22: "SSH", 53: "DNS", 80: "HTTP",
    443: "HTTPS", 3306: "MySQL", 8080: "HTTP-ALT",
}


# raw sockets let us see all traffic, not just our own — needs root/sudo
def create_raw_socket():
    try:
        if os.name == "nt":  # windows needs extra setup
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((socket.gethostbyname(socket.gethostname()), 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        return sock
    except PermissionError:
        print("Run with sudo — raw sockets need root.")
        sys.exit(1)


# read the first 20 bytes of every packet — thats always the IP header
# struct.unpack reads raw bytes according to a format — like a recipe
def parse_ip(data):
    ip = struct.unpack("!BBHHHBBH4s4s", data[:20])
    header_length = (ip[0] & 0xF) * 4  # first byte encodes the header size
    return {
        "src":      socket.inet_ntoa(ip[8]),   # convert raw bytes to "x.x.x.x"
        "dst":      socket.inet_ntoa(ip[9]),
        "ttl":      ip[5],
        "protocol": ip[6],
        "hdr_end":  header_length,
    }


# TCP header sits right after the IP header — has ports, flags, sequence numbers
def parse_tcp(data, offset):
    tcp = struct.unpack("!HHLLBBHHH", data[offset:offset + 20])

    # flags are packed into one byte as individual bits — check each one
    flags = tcp[5]
    active = []
    if flags & 0x02: active.append("SYN")   # starting a connection
    if flags & 0x10: active.append("ACK")   # acknowledging data
    if flags & 0x01: active.append("FIN")   # closing a connection
    if flags & 0x04: active.append("RST")   # hard reset

    return {
        "src_port":    tcp[0],
        "dst_port":    tcp[1],
        "flags":       " | ".join(active) or "NONE",
        "payload_at":  offset + (tcp[4] >> 4) * 4,
    }


# UDP is simpler than TCP — just source port, dest port, then payload
def parse_udp(data, offset):
    udp = struct.unpack("!HHHH", data[offset:offset + 8])
    return {
        "src_port":   udp[0],
        "dst_port":   udp[1],
        "payload_at": offset + 8,
    }


# show raw bytes as hex + readable ascii — same as Wireshark
def hex_dump(data, max_bytes=48):
    lines = []
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i + 16]
        hex_part   = " ".join(f"{b:02x}" for b in chunk).ljust(48)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {hex_part}  {ascii_part}")
    return "\n".join(lines)


def port_label(port):
    # show "80(HTTP)" instead of just "80" for known ports
    return f"{port}({PORTS[port]})" if port in PORTS else str(port)


def sniff(count=10):
    print(f"[*] Capturing {count} packets — run with sudo if nothing shows up\n")
    sock = create_raw_socket()

    for i in range(1, count + 1):
        raw, _ = sock.recvfrom(65535)
        ip = parse_ip(raw)
        proto = PROTOCOLS.get(ip["protocol"], f"PROTO-{ip['protocol']}")

        print(f"--- #{i} {proto}  {ip['src']} → {ip['dst']}  TTL={ip['ttl']}")

        if ip["protocol"] == 6:  # TCP
            tcp = parse_tcp(raw, ip["hdr_end"])
            print(f"  {port_label(tcp['src_port'])} → {port_label(tcp['dst_port'])}  [{tcp['flags']}]")
            payload = raw[tcp["payload_at"]:]
            if payload:
                print(f"  payload ({len(payload)} bytes):")
                print(hex_dump(payload))

        elif ip["protocol"] == 17:  # UDP
            udp = parse_udp(raw, ip["hdr_end"])
            print(f"  {port_label(udp['src_port'])} → {port_label(udp['dst_port'])}")
            if 53 in (udp["src_port"], udp["dst_port"]):
                print("  >> DNS query/response")
            payload = raw[udp["payload_at"]:]
            if payload:
                print(f"  payload ({len(payload)} bytes):")
                print(hex_dump(payload))

        print()

    if os.name == "nt":
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sock.close()
    print(f"[+] Done — {count} packets captured.")


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    sniff(count)

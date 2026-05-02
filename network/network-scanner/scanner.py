import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

# ports we care about and what they mean , risk is how bad it is if exposed
SERVICES = {
    21:    ("FTP",        "HIGH",     "unencrypted file transfer"),
    22:    ("SSH",        "LOW",      "secure shell"),
    23:    ("TELNET",     "CRITICAL", "unencrypted shell — never expose this"),
    80:    ("HTTP",       "MEDIUM",   "web server"),
    443:   ("HTTPS",      "LOW",      "encrypted web"),
    445:   ("SMB",        "CRITICAL", "windows file sharing — often exploited"),
    3306:  ("MySQL",      "CRITICAL", "database — should never be public"),
    3389:  ("RDP",        "HIGH",     "remote desktop"),
    6379:  ("Redis",      "CRITICAL", "often has no password by default"),
    8080:  ("HTTP-ALT",   "MEDIUM",   "secondary web port"),
    27017: ("MongoDB",    "CRITICAL", "often has no password by default"),
}

PORTS = sorted(SERVICES.keys())


# try connecting to a port , returns True if open, False if not
def is_port_open(ip, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        open = s.connect_ex((ip, port)) == 0
        s.close()
        return open
    except OSError:
        return False


# once connected, try to read whatever the server says first (its "banner")
# this often reveals the software name and version
def grab_banner(s, ip, port):
    try:
        s.settimeout(2.0)
        if port in (80, 8080):  # HTTP needs a request first before it responds
            s.send(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        return banner.split("\n")[0][:80] if banner else None
    except (socket.timeout, OSError):
        return None


# scan one port and return what was found
def scan_port(ip, port):
    name, risk, _ = SERVICES.get(port, ("?", "UNKNOWN", ""))
    result = {"port": port, "open": False, "service": name, "risk": risk, "banner": None}

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        if s.connect_ex((ip, port)) == 0:
            result["open"] = True
            result["banner"] = grab_banner(s, ip, port)
        s.close()
    except OSError:
        pass

    return result


# scan all ports on a host in parallel — sequential(one by one) would take way too long
def scan_host(ip):
    print(f"\n[*] Scanning {ip}...")

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in PORTS}
        open_ports = [
            f.result() for f in as_completed(futures)
            if f.result()["open"]
        ]

    return sorted(open_ports, key=lambda x: x["port"])


# add up the risk of all open ports and return a summary
def calculate_risk(open_ports):
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1}
    score = sum(weights.get(p["risk"], 1) for p in open_ports)

    if score >= 20:   level = "CRITICAL"
    elif score >= 10: level = "HIGH"
    elif score >= 5:  level = "MEDIUM"
    else:             level = "LOW"

    return level, score


# print everything that was found in a readable way
def print_results(ip, open_ports):
    risk_level, score = calculate_risk(open_ports)
    icons = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[ok]"}

    print(f"\n{'=' * 50}")
    print(f"  {ip}")
    print(f"  Risk: {icons[risk_level]} {risk_level}  (score: {score})  open ports: {len(open_ports)}")

    if not open_ports:
        print("  No open ports found.")
        return

    print(f"\n  {'PORT':<8} {'SERVICE':<14} {'RISK':<10} BANNER")
    print(f"  {'-' * 46}")

    for p in open_ports:
        banner = (p["banner"] or "")[:28]
        print(f"  {p['port']:<8} {p['service']:<14} {p['risk']:<10} {banner}")

    # call out the dangerous ones specifically
    flagged = [p for p in open_ports if p["risk"] in ("CRITICAL", "HIGH")]
    if flagged:
        print(f"\n  Warnings:")
        for p in flagged:
            _, _, note = SERVICES.get(p["port"], ("", "", "no info"))
            print(f"    - port {p['port']} ({p['service']}): {note}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <IP>")
        print("       python3 scanner.py 192.168.1.1")
        return

    ip = sys.argv[1]
    start = time.time()

    ports = scan_host(ip)
    print_results(ip, ports)

    print(f"\n  {len(PORTS)} ports checked in {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()

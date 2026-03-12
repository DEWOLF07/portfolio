#!/usr/bin/env python3
"""
Network Scanner — discovers live hosts and open ports on a network.
For each open port it grabs the service banner (version string the server
announces on connect) and flags anything that looks risky/sus.

Run: python3 scanner.py <IP or CIDR>
     python3 scanner.py 192.168.1.0/24
     python3 scanner.py 192.168.1.1

Only scan networks you own or have explicit permission to test.
"""

import socket
import threading
import sys
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

SERVICES = {
    21:    ("FTP",        "HIGH",     "unencrypted file transfer"),
    22:    ("SSH",        "LOW",      "secure shell — check version"),
    23:    ("TELNET",     "CRITICAL", "unencrypted shell — never expose"),
    25:    ("SMTP",       "MEDIUM",   "mail server"),
    53:    ("DNS",        "MEDIUM",   "name resolution"),
    80:    ("HTTP",       "MEDIUM",   "web server"),
    110:   ("POP3",       "HIGH",     "unencrypted mail"),
    143:   ("IMAP",       "HIGH",     "unencrypted mail"),
    443:   ("HTTPS",      "LOW",      "encrypted web"),
    445:   ("SMB",        "CRITICAL", "windows file sharing — EternalBlue target"),
    3306:  ("MySQL",      "CRITICAL", "database — should never be internet-facing"),
    3389:  ("RDP",        "HIGH",     "remote desktop"),
    5432:  ("PostgreSQL", "CRITICAL", "database — should never be internet-facing"),
    6379:  ("Redis",      "CRITICAL", "often no auth by default"),
    8080:  ("HTTP-ALT",   "MEDIUM",   "secondary web port"),
    8443:  ("HTTPS-ALT",  "LOW",      "secondary https"),
    27017: ("MongoDB",    "CRITICAL", "often no auth by default"),
}

PORTS = sorted(SERVICES.keys())


def is_alive(ip: str, timeout=1.0) -> bool:
    # Try a few common ports : if anything responds (even refused), means host is up
    for port in [80, 443, 22, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) in (0, 111):
                s.close()
                return True
            s.close()
        except OSError:
            continue
    return False


def discover(cidr: str) -> list:
    try:
        hosts = list(ipaddress.ip_network(cidr, strict=False).hosts())[:256]
    except ValueError as e:
        print(f"Invalid network: {e}")
        return []

    print(f"\n[*] Sweeping {cidr} ({len(hosts)} addresses)...\n")
    live, lock = [], threading.Lock()

    def check(ip):
        if is_alive(str(ip)):
            with lock:
                live.append(str(ip))
                print(f"  [+] {ip}")

    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(check, hosts)

    return sorted(live, key=lambda x: ipaddress.ip_address(x))


def scan_port(ip: str, port: int, timeout=1.0) -> dict:
    name, risk, _ = SERVICES.get(port, ("?", "UNKNOWN", ""))
    result = {"port": port, "state": "closed", "service": name, "risk": risk, "banner": None}

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        conn = s.connect_ex((ip, port))

        if conn == 0:
            result["state"] = "open"
            try:
                s.settimeout(2.0)
                if port in (80, 8080, 443, 8443):
                    s.send(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                if banner:
                    result["banner"] = banner.split("\n")[0][:100]
            except (socket.timeout, OSError):
                pass
        elif conn != 111:
            result["state"] = "filtered"

        s.close()
    except (socket.timeout, OSError):
        result["state"] = "filtered"

    return result


def scan_host(ip: str) -> list:
    # Parallel port scan : sequential would take minutes, threads make it about 10s
    with ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in PORTS}
        return sorted(
            (f.result() for f in as_completed(futures) if f.result()["state"] == "open"),
            key=lambda x: x["port"]
        )


def risk_score(ports: list) -> dict:
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1}
    total   = sum(weights.get(p["risk"], 1) for p in ports)
    level   = "CRITICAL" if total >= 20 else "HIGH" if total >= 10 else "MEDIUM" if total >= 5 else "LOW"
    flagged = [f"{p['port']} ({p['service']}) [{p['risk']}]"
               for p in ports if p["risk"] in ("CRITICAL", "HIGH")]
    return {"level": level, "score": total, "flagged": flagged}


def guess_os(ports: list) -> str:
    nums    = {p["port"] for p in ports}
    banners = " ".join(p.get("banner") or "" for p in ports).lower()
    if 3389 in nums and 445 in nums: return "likely Windows Server"
    if 3389 in nums:                 return "likely Windows"
    if "ubuntu" in banners:          return "Ubuntu Linux"
    if "nginx"  in banners:          return "Linux + Nginx"
    if "apache" in banners:          return "Linux + Apache"
    if 22 in nums:                   return "Unix-like"
    return "unknown"


def print_results(ip: str, ports: list):
    risk = risk_score(ports)
    icons = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[ok]"}

    print(f"\n{'=' * 58}")
    print(f"  {ip}  —  {guess_os(ports)}")
    print(f"  Risk: {icons.get(risk['level'],'?')} {risk['level']}  open ports: {len(ports)}")

    if ports:
        print(f"\n  {'PORT':<8} {'SERVICE':<14} {'RISK':<10} BANNER")
        print(f"  {'─' * 52}")
        for p in ports:
            print(f"  {p['port']:<8} {p['service']:<14} {p['risk']:<10} {(p['banner'] or '')[:28]}")

    if risk["flagged"]:
        print(f"\n  Findings:")
        for f in risk["flagged"]:
            _, _, note = SERVICES.get(int(f.split()[0]), ("", "", ""))
            print(f"    - {f}  —  {note}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <IP or CIDR>")
        print("       python3 scanner.py 192.168.1.1")
        print("       python3 scanner.py 192.168.1.0/24")
        return

    target = sys.argv[1]

    if "/" in target:
        live = discover(target)
        if not live:
            print("No hosts found.")
            return
        print(f"\n[*] {len(live)} hosts up. Scanning ports...\n")
        results = []
        for ip in live:
            ports = scan_host(ip)
            print_results(ip, ports)
            results.append(ports)

        all_ports = [p for r in results for p in r]
        freq = Counter(p["port"] for p in all_ports)
        print(f"\nSummary — {len(results)} hosts, {len(all_ports)} open ports")
        for port, count in freq.most_common(5):
            print(f"  {port} ({SERVICES.get(port, ('?',))[0]}): {count} host(s)")
    else:
        print(f"\n[*] Scanning {target}...")
        start = time.time()
        ports = scan_host(target)
        print_results(target, ports)
        print(f"\n  {len(PORTS)} ports checked in {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()

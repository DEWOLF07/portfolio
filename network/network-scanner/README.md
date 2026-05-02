# Network Scanner

Discovers live hosts and open ports on a network, grabs service banners, and flags anything that represents a real security risk. Same core technique used by nmap.

## How it works

Before you can secure a network you need to know what's on it — and what it looks like from the outside. This is reconnaissance, the first step in any security audit or penetration test.

**Host discovery** sweeps an IP range to find which addresses are alive. It tries connecting to a handful of common ports — if anything responds, even a refused connection, the host is up. Fifty threads run in parallel so a /24 sweep (254 addresses) finishes in seconds.

**Port scanning** attempts a TCP connect on each port in the list. A completed connection means open. Connection refused means closed. No response at all means filtered — a firewall is silently dropping the packets. That distinction matters because filtered ports reveal firewall rules even when nothing is listening.

**Banner grabbing** reads the first bytes a service sends back after a connection opens. Most services announce themselves immediately — SSH prints its version string, HTTP servers return headers with software names. That version is what you'd cross-reference against known CVEs to find exploitable vulnerabilities.

**Risk scoring** assigns a weight to each service based on what it is and how commonly it's exploited. An exposed Redis instance with no authentication is critical. Telnet is critical — it sends everything including passwords in plaintext. The scores combine into an overall host risk level.

An open port is an attack surface. The fewer services visible from outside, the smaller the target.

## Run

```bash
python3 scanner.py 127.0.0.1            # single host
python3 scanner.py 192.168.1.1
python3 scanner.py 192.168.1.0/24       # entire subnet
```

⚠️Only scan networks you own or have permission to test.


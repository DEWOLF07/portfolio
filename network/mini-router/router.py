#!/usr/bin/env python3
"""
Mini Router Simulation — simulates how a real router forwards packets.
Builds a routing table, runs longest prefix match on each destination IP,
decrements TTL, and traces packets across a two-router topology.

Run: python3 router.py
"""

import time
from dataclasses import dataclass
from typing import Optional


def ip_to_int(ip: str) -> int:
    p = ip.split(".")
    return (int(p[0]) << 24) | (int(p[1]) << 16) | (int(p[2]) << 8) | int(p[3])


def prefix_mask(length: int) -> int:
    return 0 if length == 0 else ((1 << 32) - 1) ^ ((1 << (32 - length)) - 1)


def in_network(ip: str, network: str, prefix: int) -> bool:
    mask = prefix_mask(prefix)
    return (ip_to_int(ip) & mask) == (ip_to_int(network) & mask)


@dataclass
class Packet:
    src: str
    dst: str
    ttl: int
    protocol: str
    payload: str
    src_port: int = 0
    dst_port: int = 0


@dataclass
class Route:
    network:   str
    prefix:    int
    next_hop:  str
    interface: str
    origin:    str = "STATIC"


@dataclass
class Interface:
    name:      str
    ip:        str
    network:   str
    prefix:    int
    link_to:   str = ""


class Router:
    def __init__(self, name: str, rid: str):
        self.name   = name
        self.rid    = rid
        self.table: list[Route]          = []
        self.ifaces: dict[str, Interface] = {}

    def add_interface(self, iface: Interface):
        self.ifaces[iface.name] = iface
        # Directly connected networks get added automatically
        self.add_route(Route(iface.network, iface.prefix, iface.ip, iface.name, "CONNECTED"))

    def add_route(self, route: Route):
        self.table.append(route)
        # Keep most specific routes first so the first match is always the best
        self.table.sort(key=lambda r: r.prefix, reverse=True)

    def best_route(self, dst: str) -> Optional[Route]:
        # Longest prefix match : the core algorithm every router runs
        return next((r for r in self.table if in_network(dst, r.network, r.prefix)), None)

    def is_mine(self, ip: str) -> bool:
        return any(i.ip == ip for i in self.ifaces.values())

    def forward(self, pkt: Packet, incoming: str) -> dict:
        if self.is_mine(pkt.dst):
            return {"action": "DELIVER", "reason": f"{pkt.dst} is local"}

        pkt.ttl -= 1
        if pkt.ttl <= 0:
            return {"action": "DROP_TTL", "reason": "TTL expired — sends ICMP Time Exceeded"}

        route = self.best_route(pkt.dst)
        if not route:
            return {"action": "DROP_NO_ROUTE", "reason": f"no route to {pkt.dst}"}

        return {
            "action":   "FORWARD",
            "out":      route.interface,
            "next_hop": route.next_hop,
            "reason":   f"matched {route.network}/{route.prefix} ({route.origin})",
        }


def build_network():
    # Simulates: your home  ISP edge router → internet core → Google
    isp = Router("ISP-Edge", "10.0.0.1")
    isp.add_interface(Interface("eth0", "192.168.1.1", "192.168.1.0", 24, "home network"))
    isp.add_interface(Interface("eth1", "10.0.0.1",   "10.0.0.0",   30, "core router"))
    isp.add_route(Route("8.8.0.0",     16, "10.0.0.2", "eth1", "BGP"))
    isp.add_route(Route("142.250.0.0", 15, "10.0.0.2", "eth1", "BGP"))
    isp.add_route(Route("0.0.0.0",      0, "10.0.0.2", "eth1", "STATIC"))  # default route

    core = Router("Internet-Core", "10.0.0.2")
    core.add_interface(Interface("eth0", "10.0.0.2",    "10.0.0.0",    30, "ISP edge"))
    core.add_interface(Interface("eth1", "8.8.8.1",     "8.8.8.0",     24, "Google DNS"))
    core.add_interface(Interface("eth2", "142.250.0.1", "142.250.0.0", 15, "Google CDN"))
    core.add_route(Route("192.168.0.0", 16, "10.0.0.1", "eth0", "OSPF"))
    core.add_route(Route("0.0.0.0",      0, "10.0.0.1", "eth0", "STATIC"))

    return isp, core


def show_table(router: Router):
    print(f"\n  Routing table — {router.name}")
    print(f"  {'Network':<22} {'Next-Hop':<16} {'Interface':<8} Origin")
    print(f"  {'─' * 56}")
    for r in router.table:
        print(f"  {r.network}/{r.prefix:<18} {r.next_hop:<16} {r.interface:<8} {r.origin}")


def trace(src, dst, proto, payload, sport=0, dport=80):
    isp, core = build_network()
    pkt = Packet(src, dst, 64, proto, payload, sport, dport)

    print(f"\n{'=' * 60}")
    print(f"  {src} → {dst}  [{proto}:{dport}]")
    print(f"  \"{payload[:45]}\"")
    print(f"{'─' * 60}")

    icons = {"FORWARD": "→", "DELIVER": "✓", "DROP_TTL": "✗", "DROP_NO_ROUTE": "✗"}

    for hop, (router, iface) in enumerate([(isp, "eth0"), (core, "eth0")], 1):
        r = router.forward(pkt, iface)
        print(f"  hop {hop}  {router.name}")
        print(f"    {icons.get(r['action'], '?')} {r['action']}  —  {r['reason']}")
        if r["action"] == "FORWARD":
            print(f"    out {r['out']} → {r['next_hop']}  TTL now {pkt.ttl}")
        print()
        if r["action"] != "FORWARD":
            break
        time.sleep(0.15)


def main():
    print("Mini Router Simulation")
    print("Topology: home (192.168.1.x) → ISP → core → Google (8.8.x / 142.250.x)")

    isp, core = build_network()
    show_table(isp)
    show_table(core)

    print("\n\n--- DNS lookup ---")
    trace("192.168.1.100", "8.8.8.8", "UDP", "query: google.com", 54321, 53)

    print("--- HTTPS connection ---")
    trace("192.168.1.100", "142.250.80.46", "TCP", "SYN — initiating connection", 49152, 443)

    print("--- TTL=1 (traceroute technique) ---")
    pkt = Packet("192.168.1.100", "8.8.8.8", 1, "UDP", "probe", 12345, 33434)
    r = isp.forward(pkt, "eth0")
    print(f"  hop 1  {isp.name}")
    print(f"    ✗ {r['action']}  —  {r['reason']}")
    print("\n  traceroute works by sending TTL=1, 2, 3... each router that drops")
    print("  the packet replies with ICMP Time Exceeded, revealing the path.")


if __name__ == "__main__":
    main()

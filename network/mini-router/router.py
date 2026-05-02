# where to send each IP — in real life this would be thousands of entries
routing_table = {
    "8.8.8.8":       "Router B",  # Google DNS
    "142.250.80.46": "Router B",  # Google website
    "192.168.1.1":   "local",     # your own network
}


# a packet is just a bundle of info traveling across the network
def make_packet(src, dst, message):
    return {"src": src, "dst": dst, "ttl": 3, "message": message}


# each router runs this — decide whether to drop, deliver, or pass it along
def forward(router_name, packet):
    print(f"\n[{router_name}] got packet → going to: {packet['dst']}")

    # every hop costs one TTL, hits zero means it's been traveling too long
    packet["ttl"] -= 1
    if packet["ttl"] <= 0:
        print("  ✗ TTL hit zero — packet dropped!")
        return None

    # look up the destination in our routing table
    next_hop = routing_table.get(packet["dst"])

    if next_hop is None:
        print(f"  ✗ No route to {packet['dst']} — dropped!")
        return None

    if next_hop == "local":
        print(f"  ✓ It's local — delivering: '{packet['message']}'")
        return None

    print(f"  → sending to {next_hop}  (TTL left: {packet['ttl']})")
    return next_hop


# simulates the full journey of a packet through our two routers
def send_packet(src, dst, message):
    print(f"\n--- {src} → {dst}: '{message}' ---")

    packet = make_packet(src, dst, message)

    for hop in ["Router A", "Router B"]:
        result = forward(hop, packet)
        if result is None:  # either delivered or dropped
            break

    print(f"  [arrived at {dst}]")


def main():
    # normal DNS request
    send_packet("192.168.1.100", "8.8.8.8", "what is google.com's IP?")

    # normal web request
    send_packet("192.168.1.100", "142.250.80.46", "GET /index.html")

    # TTL = 1 so it dies at the first router — this is exactly how traceroute works
    print("\n--- TTL test ---")
    pkt = make_packet("192.168.1.100", "8.8.8.8", "probe")
    pkt["ttl"] = 1
    forward("Router A", pkt)


if __name__ == "__main__":
    main()

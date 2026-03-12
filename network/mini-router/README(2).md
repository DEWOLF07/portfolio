# Mini Router

Simulates what a real router does — receives a packet, looks up the destination in a routing table, and forwards it out the right interface. Traces traffic across a two-router topology that mirrors how a home network connects to the internet.

## How it works

A router is fundamentally just a table lookup. Every packet that arrives gets its destination IP matched against a list of known network prefixes, and the most specific match wins. That algorithm — longest-prefix-match — is what every router runs, from your home box to a Cisco backbone carrying billions of packets a day.

The simulation builds two routers: an ISP edge and an internet core. Routes are added statically and via simulated BGP, which is the protocol real ISPs use to exchange routing information globally. Without BGP, no router would know how to reach networks it isn't directly connected to.

Subnetting is what makes it all work. An address like `192.168.1.0/24` means the first 24 bits identify the network and the last 8 identify individual hosts. The router ANDs the destination IP against the subnet mask and checks for a match — pure bitwise math, done millions of times per second in hardware on real devices.

TTL is the safety valve. Every packet starts with a counter (64 on Linux, 128 on Windows) that drops by 1 at each hop. When it hits zero the router discards the packet and sends an ICMP Time Exceeded message back to the sender. Traceroute exploits this deliberately — it sends packets with TTL=1, then TTL=2, then TTL=3, and collects the Time Exceeded replies to map every hop along the path.

## Run

```bash
python3 router.py
```

No root needed — pure simulation.

## Scenarios

- **DNS lookup** — UDP packet from home to `8.8.8.8:53`, traced through both routers
- **HTTPS connection** — TCP SYN to Google's CDN, shows BGP route matching
- **TTL expiry** — packet with TTL=1, dropped at hop 1, demonstrates the traceroute technique

# Packet Sniffer

Captures live TCP/UDP traffic and reads it at the byte level — IP headers, flags, ports, payloads. No Wireshark, no libraries, just Python's raw socket API.

## How it works

Every piece of data sent over a network is broken into packets. Each one has layers — an IP header telling routers where it's going, a TCP or UDP header telling the OS which app gets it, and the actual payload at the end.

Normal programs use regular sockets where the OS handles all the filtering. A raw socket skips that entirely. You get the whole packet in binary and parse it yourself. The IP header is always 20 bytes with a fixed structure, so `struct.unpack` pulls out the fields directly — source IP, destination IP, protocol, TTL.

TTL (Time To Live) starts at 64 and drops by 1 at every router hop. When it hits zero the packet is dropped — that's how the internet prevents a misrouted packet from bouncing around forever.

TCP adds reliability on top of IP. Before any data moves, both sides run a handshake — SYN, SYN-ACK, ACK — three packets just to agree they're ready. Every browser tab, every API call, every SSH session starts with those three. You can watch them appear here in real time.

UDP skips all of that. No handshake, no acknowledgment, no guaranteed delivery. DNS uses UDP for exactly that reason — speed over reliability.

## Run

```bash
sudo python3 packet_sniffer.py        # capture 20 packets
sudo python3 packet_sniffer.py 50     # capture more
```

Requires root — raw sockets bypass OS-level filtering. On Windows run as Administrator.

## What to watch

Open a browser while it's running. You'll see DNS queries fire before every new domain, then the TCP handshake to the server, then HTTPS traffic. The whole sequence plays out at the byte level.

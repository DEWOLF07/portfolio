using System;
using System.Collections.Generic;

// a packet is just a bundle of info traveling across the network
class Packet
{
    public string Src, Dst, Message;
    public int Ttl;

    public Packet(string src, string dst, string message)
    {
        Src = src;
        Dst = dst;
        Message = message;
        Ttl = 3;
    }
}

class Router
{
    // where to send each IP : in real life this would be a lot of entries
    static Dictionary<string, string> routingTable = new Dictionary<string, string>
    {
        { "8.8.8.8",       "Router B" },  // Google DNS
        { "142.250.80.46", "Router B" },  // Google website
        { "192.168.1.1",   "local"    },  // Local host
    };

    // each router runs this : decide whether to drop, deliver, or pass it along
    static string Forward(string routerName, Packet packet)
    {
        Console.WriteLine($"\n[{routerName}] got packet → going to: {packet.Dst}");

        // every hop costs one TTL, if it hits zero means its been traveling too long
        packet.Ttl--;
        if (packet.Ttl <= 0)
        {
            Console.WriteLine(" TTL hit zero - packet dropped");
            return null;
        }

        // look up the destination in our routing table
        if (!routingTable.TryGetValue(packet.Dst, out string nextHop))
        {
            Console.WriteLine($" No route to {packet.Dst} - dropped");
            return null;
        }

        if (nextHop == "local")
        {
            Console.WriteLine($" It's local - delivering: '{packet.Message}'");
            return null;
        }

        Console.WriteLine($"  -> sending to {nextHop}  (TTL left: {packet.Ttl})");
        return nextHop;
    }

    // simulates the full journey of a packet through our two routers
    static void SendPacket(string src, string dst, string message)
    {
        Console.WriteLine($"\n--- {src} -> {dst}: '{message}' ---");

        var packet = new Packet(src, dst, message);

        foreach (string hop in new[] { "Router A", "Router B" })
        {
            string result = Forward(hop, packet);
            if (result == null)  // either delivered or dropped
                break;
        }

        Console.WriteLine($"  [arrived at {dst}]");
    }

    static void Main()
    {
        // a DNS request
        SendPacket("192.168.1.100", "8.8.8.8", "what is google.com's IP?");

        // a web request
        SendPacket("192.168.1.100", "142.250.80.46", "GET /index.html");

        // TTL = 1 so it dies at the first router — this is how traceroute works
        Console.WriteLine("\n--- TTL test ---");
        var pkt = new Packet("192.168.1.100", "8.8.8.8", "probe");
        pkt.Ttl = 1;
        Forward("Router A", pkt);
    }
}

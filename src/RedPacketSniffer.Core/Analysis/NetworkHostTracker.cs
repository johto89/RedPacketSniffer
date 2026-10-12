using System.Net;
using System.Net.Sockets;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// Passive Network Host Discovery — xay dung network map tu observed traffic
///
/// Red team use cases:
/// - Passive recon: phat hien host tren mang ma khong can scan (no ARP/ICMP scan)
/// - OS Fingerprint: doan OS tu TTL/HopLimit (Linux ~64, Windows ~128, Cisco ~255)
/// - Service discovery: track open ports tu observed TCP connections
/// - Traffic profiling: bytes/packets per host, top talkers
/// - MAC vendor: OUI lookup (first 3 bytes of MAC)
/// - Gateway detection: host nhan nhieu traffic nhat tu nhieu source
/// - Subnet mapping: group hosts theo /24 (IPv4) hoac /64 (IPv6)
/// - IPv6 recon: track link-local, unique local, global unicast hosts
/// </summary>
public sealed class NetworkHostTracker
{
    private readonly Dictionary<string, NetworkHost> _hosts = new(); // IP -> host info
    private readonly object _lock = new();
    private long _nextId = 1;

    public event Action<NetworkHost>? OnHostUpdated;

    // Common OUI prefixes (first 3 bytes MAC -> vendor)
    private static readonly Dictionary<string, string> OuiTable = new(StringComparer.OrdinalIgnoreCase)
    {
        // Virtual/Cloud
        {"00:50:56", "VMware"}, {"00:0C:29", "VMware"}, {"00:05:69", "VMware"},
        {"00:1C:14", "VMware"}, {"00:15:5D", "Hyper-V"}, {"08:00:27", "VirtualBox"},
        {"0A:00:27", "VirtualBox"}, {"52:54:00", "QEMU/KVM"},
        // Network equipment
        {"00:00:0C", "Cisco"}, {"00:1A:A1", "Cisco"}, {"00:1B:54", "Cisco"},
        {"00:26:CB", "Cisco"}, {"F4:CF:E2", "Cisco"}, {"00:1E:BD", "Cisco"},
        {"00:17:94", "Cisco"}, {"00:1C:57", "Cisco"},
        {"00:1A:1E", "Aruba"}, {"00:0B:86", "Aruba"}, {"24:DE:C6", "Aruba"},
        {"00:04:96", "Extreme"}, {"B4:DE:31", "Extreme"},
        {"00:1B:17", "Palo Alto"}, {"00:1B:21", "Palo Alto"},
        {"00:09:0F", "Fortinet"}, {"00:23:20", "Nicira/OVS"},
        {"00:1E:67", "Intel"}, {"00:1C:C0", "Intel"},
        {"00:1F:29", "Hewlett Packard"}, {"00:30:6E", "Hewlett Packard"},
        {"00:1A:4B", "Hewlett Packard"}, {"78:AC:C0", "Hewlett Packard"},
        {"00:1E:0B", "Hewlett Packard"}, {"3C:D9:2B", "Hewlett Packard"},
        {"EC:B1:D7", "Hewlett Packard"},
        // Servers/storage
        {"00:25:90", "Super Micro"}, {"0C:C4:7A", "Super Micro"},
        {"00:17:A4", "Global Technologie"}, {"00:1E:C9", "Dell"},
        {"D4:AE:52", "Dell"}, {"F0:1F:AF", "Dell"}, {"B0:83:FE", "Dell"},
        {"00:10:18", "Broadcom"}, {"00:1A:A0", "Dell"},
        // Common vendors
        {"00:50:F2", "Microsoft"}, {"00:03:FF", "Microsoft"},
        {"00:0D:3A", "Microsoft"}, {"60:45:BD", "Microsoft"},
        {"28:18:78", "Microsoft"},
        {"3C:22:FB", "Apple"}, {"A4:83:E7", "Apple"}, {"F0:18:98", "Apple"},
        {"AC:87:A3", "Apple"}, {"DC:A9:04", "Apple"}, {"F8:FF:C2", "Apple"},
        {"00:1E:C2", "Apple"}, {"00:25:00", "Apple"},
        {"B4:2E:99", "Samsung"}, {"00:21:19", "Samsung"}, {"EC:1F:72", "Samsung"},
        {"00:1A:8A", "Samsung"},
        {"20:47:47", "Dell"}, {"00:06:5B", "Dell"},
        {"00:1B:63", "Apple"},
        // IoT / Embedded
        {"B8:27:EB", "Raspberry Pi"}, {"DC:A6:32", "Raspberry Pi"},
        {"E4:5F:01", "Raspberry Pi"},
        {"60:01:94", "Espressif"}, {"24:62:AB", "Espressif"},
        {"AC:67:B2", "Espressif"}, {"30:AE:A4", "Espressif"},
    };

    public void Analyze(CapturedPacket packet)
    {
        if (string.IsNullOrEmpty(packet.SourceIP) || string.IsNullOrEmpty(packet.DestIP))
            return;

        // Update source host
        UpdateHost(packet.SourceIP, packet.SourceMac, packet, isSender: true);

        // Update destination host
        UpdateHost(packet.DestIP, packet.DestMac, packet, isSender: false);
    }

    private void UpdateHost(string ip, string mac, CapturedPacket packet, bool isSender)
    {
        // Skip broadcast/multicast — IPv4
        if (ip == "255.255.255.255" || ip.StartsWith("224.") || ip.StartsWith("239.") || ip == "0.0.0.0")
            return;

        // Skip multicast/unspecified — IPv6
        // ff00::/8 = multicast, :: = unspecified
        if (ip.StartsWith("ff", StringComparison.OrdinalIgnoreCase) && ip.Contains(':'))
            return;
        if (ip == "::" || ip == "::0")
            return;

        NetworkHost host;

        lock (_lock)
        {
            if (!_hosts.TryGetValue(ip, out host!))
            {
                bool isV6 = ip.Contains(':');
                host = new NetworkHost
                {
                    Id = _nextId++,
                    IpAddress = ip,
                    FirstSeen = packet.Timestamp,
                    IsPrivate = IsPrivateIP(ip),
                    IsIPv6 = isV6,
                    Subnet = isV6 ? GetSubnet64(ip) : GetSubnet24(ip),
                    ScopeTag = isV6 ? GetIPv6Scope(ip) : null
                };
                _hosts[ip] = host;
            }

            host.LastSeen = packet.Timestamp;

            // MAC address
            if (!string.IsNullOrEmpty(mac) && mac != "00:00:00:00:00:00" &&
                (string.IsNullOrEmpty(host.MacAddress) || host.MacAddress == "00:00:00:00:00:00"))
            {
                host.MacAddress = mac;
                host.Vendor = LookupVendor(mac);
            }

            // OS fingerprint tu TTL/HopLimit (chi co nghia khi host la sender)
            // IPv6 HopLimit tuong duong IPv4 TTL — cung pattern OS fingerprinting
            if (isSender && packet.IpProtocol > 0)
            {
                int ttl = packet.TTL;
                if (ttl > 0)
                {
                    host.LastTtl = ttl;
                    host.OsGuess = GuessOs(ttl);
                }
            }

            // Track ports (observed services)
            if (packet.IpProtocol == 6 || packet.IpProtocol == 17) // TCP or UDP
            {
                if (isSender)
                {
                    // Source port > 1024 thi la client, dest port la server port
                    if (packet.DestPort > 0 && packet.DestPort <= 1024)
                    {
                        // Packet di toi well-known port -> dest host co service
                    }
                    host.PacketsSent++;
                    host.BytesSent += packet.Length;
                }
                else
                {
                    // Host nay la destination
                    ushort port = packet.DestPort;
                    if (port > 0 && packet.IpProtocol == 6) // TCP dest port
                    {
                        if (!host.OpenPorts.Contains(port) && port <= 49151)
                        {
                            host.OpenPorts.Add(port);
                            host.OpenPorts.Sort();
                        }
                    }
                    host.PacketsReceived++;
                    host.BytesReceived += packet.Length;
                }
            }
            else
            {
                if (isSender)
                {
                    host.PacketsSent++;
                    host.BytesSent += packet.Length;
                }
                else
                {
                    host.PacketsReceived++;
                    host.BytesReceived += packet.Length;
                }
            }

            // Track unique peers
            string peerIp = isSender ? packet.DestIP! : packet.SourceIP!;
            if (!host.Peers.Contains(peerIp))
            {
                host.Peers.Add(peerIp);
                if (host.Peers.Count > 200) // cap
                    host.Peers.RemoveAt(0);
            }

            // Detect hostnames tu DNS (application protocol hint)
            if (!string.IsNullOrEmpty(packet.ApplicationProtocol))
            {
                if (!host.Protocols.Contains(packet.ApplicationProtocol))
                    host.Protocols.Add(packet.ApplicationProtocol);
            }

            // Anomaly detection
            DetectAnomalies(host);
        }

        OnHostUpdated?.Invoke(host);
    }

    private void DetectAnomalies(NetworkHost host)
    {
        host.AnomalyFlags.Clear();

        // Gateway candidate: nhieu peers
        if (host.Peers.Count > 20)
            host.AnomalyFlags.Add("GATEWAY_CANDIDATE");

        // Top talker: > 100MB transferred
        long totalBytes = host.BytesSent + host.BytesReceived;
        if (totalBytes > 100_000_000)
            host.AnomalyFlags.Add("TOP_TALKER");

        // Nhiều open ports -> potential server
        if (host.OpenPorts.Count >= 5)
            host.AnomalyFlags.Add("MULTI_SERVICE");

        // Sensitive services
        if (host.OpenPorts.Any(p => p == 23 || p == 21))
            host.AnomalyFlags.Add("INSECURE_SERVICE");

        if (host.OpenPorts.Any(p => p == 3389))
            host.AnomalyFlags.Add("RDP_ENABLED");

        if (host.OpenPorts.Any(p => p == 445 || p == 139))
            host.AnomalyFlags.Add("SMB_ENABLED");

        // Asymmetric traffic (big sender, small receiver -> potential exfil)
        if (host.BytesSent > 10_000_000 && host.BytesReceived > 0)
        {
            double ratio = (double)host.BytesSent / host.BytesReceived;
            if (ratio > 10)
                host.AnomalyFlags.Add("HIGH_UPLOAD_RATIO");
        }

        // --- IPv6-specific anomalies ---
        if (host.IsIPv6)
        {
            // IPv6 host dung global unicast trong mang private -> co the la tunnel/6to4
            if (!host.IsPrivate && host.ScopeTag == "Global")
            {
                // Check xem co host v4 nao cung MAC khong -> dual-stack tracking
                // Annotation only, khong block
            }

            // Link-local host ma co traffic toi non-link-local peer -> routing anomaly
            if (host.ScopeTag == "Link-Local")
            {
                bool hasNonLinkLocalPeer = host.Peers.Any(p =>
                    !p.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase) &&
                    p.Contains(':'));
                if (hasNonLinkLocalPeer)
                    host.AnomalyFlags.Add("V6_LINKLOCAL_ROUTED");
            }

            // Host nhan nhieu Router Advertisement -> potential RA flood / SLAAC attack
            if (host.Protocols.Contains("ICMPv6-RA"))
                host.AnomalyFlags.Add("V6_RA_RECEIVER");
        }
    }

    private static string GuessOs(int ttl)
    {
        // TTL (IPv4) va HopLimit (IPv6) dung cung initial value pattern
        if (ttl <= 64 && ttl > 32)
            return "Linux/Unix";
        if (ttl <= 128 && ttl > 64)
            return "Windows";
        if (ttl <= 255 && ttl > 128)
            return "Cisco/Network";
        if (ttl <= 32)
            return "Embedded/IoT";
        return "Unknown";
    }

    private static string LookupVendor(string mac)
    {
        if (string.IsNullOrEmpty(mac) || mac.Length < 8) return "";

        // Normalize MAC format -> XX:XX:XX
        string prefix = mac[..8].ToUpperInvariant();
        if (OuiTable.TryGetValue(prefix, out string? vendor))
            return vendor;

        return "";
    }

    /// <summary>
    /// Check private/local address cho ca IPv4 va IPv6.
    /// IPv4: RFC 1918 (10/8, 172.16/12, 192.168/16) + link-local (169.254/16)
    /// IPv6: link-local (fe80::/10), unique local (fc00::/7 = fc/fd), loopback (::1)
    /// </summary>
    private static bool IsPrivateIP(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return false;
        byte[] bytes = addr.GetAddressBytes();

        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // ::1 loopback
            if (IPAddress.IsLoopback(addr))
                return true;

            // fe80::/10 — link-local
            if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80)
                return true;

            // fc00::/7 — unique local address (fc/fd prefix)
            if ((bytes[0] & 0xFE) == 0xFC)
                return true;

            // ::ffff:0:0/96 — IPv4-mapped IPv6 (check inner IPv4)
            bool isV4Mapped = true;
            for (int i = 0; i < 10; i++)
            {
                if (bytes[i] != 0) { isV4Mapped = false; break; }
            }
            if (isV4Mapped && bytes[10] == 0xFF && bytes[11] == 0xFF)
            {
                return bytes[12] == 10 ||
                       (bytes[12] == 172 && bytes[13] >= 16 && bytes[13] <= 31) ||
                       (bytes[12] == 192 && bytes[13] == 168) ||
                       (bytes[12] == 169 && bytes[13] == 254);
            }

            return false;
        }

        // IPv4
        if (bytes.Length != 4) return false;
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               (bytes[0] == 169 && bytes[1] == 254); // link-local
    }

    /// <summary>
    /// IPv4 subnet /24
    /// </summary>
    private static string GetSubnet24(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return "";
        byte[] bytes = addr.GetAddressBytes();
        if (bytes.Length != 4) return "";
        return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.0/24";
    }

    /// <summary>
    /// IPv6 subnet /64 — standard interface identifier boundary.
    /// Lay 8 bytes dau (network prefix), zero out 8 bytes sau (interface ID).
    /// </summary>
    private static string GetSubnet64(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return "";
        byte[] bytes = addr.GetAddressBytes();
        if (bytes.Length != 16) return "";

        // Zero out interface ID (bytes 8-15)
        byte[] prefix = new byte[16];
        Array.Copy(bytes, 0, prefix, 0, 8);
        // bytes 8-15 remain 0

        var prefixAddr = new IPAddress(prefix);
        return $"{prefixAddr}/64";
    }

    /// <summary>
    /// Phan loai IPv6 scope — huu ich cho recon/anomaly detection:
    /// - Link-Local (fe80::/10): chi valid tren 1 link
    /// - Unique Local (fc00::/7): tuong duong RFC 1918 private
    /// - Global: routable tren Internet
    /// - Loopback (::1)
    /// - IPv4-Mapped (::ffff:x.x.x.x)
    /// </summary>
    private static string? GetIPv6Scope(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return null;
        if (addr.AddressFamily != AddressFamily.InterNetworkV6) return null;

        if (IPAddress.IsLoopback(addr))
            return "Loopback";

        byte[] bytes = addr.GetAddressBytes();

        // fe80::/10
        if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80)
            return "Link-Local";

        // fc00::/7
        if ((bytes[0] & 0xFE) == 0xFC)
            return "Unique-Local";

        // ::ffff:0:0/96
        bool isV4Mapped = true;
        for (int i = 0; i < 10; i++)
        {
            if (bytes[i] != 0) { isV4Mapped = false; break; }
        }
        if (isV4Mapped && bytes[10] == 0xFF && bytes[11] == 0xFF)
            return "IPv4-Mapped";

        return "Global";
    }

    public List<NetworkHost> GetAllHosts()
    {
        lock (_lock) { return _hosts.Values.ToList(); }
    }

    public List<NetworkHost> GetPrivateHosts()
    {
        lock (_lock) { return _hosts.Values.Where(h => h.IsPrivate).ToList(); }
    }

    /// <summary>
    /// Lay hosts theo address family — huu ich cho filtering tren UI
    /// </summary>
    public List<NetworkHost> GetIPv6Hosts()
    {
        lock (_lock) { return _hosts.Values.Where(h => h.IsIPv6).ToList(); }
    }

    public List<NetworkHost> GetIPv4Hosts()
    {
        lock (_lock) { return _hosts.Values.Where(h => !h.IsIPv6).ToList(); }
    }

    public NetworkSummary GetSummary()
    {
        lock (_lock)
        {
            var subnets = _hosts.Values
                .Where(h => h.IsPrivate && !string.IsNullOrEmpty(h.Subnet))
                .GroupBy(h => h.Subnet)
                .ToDictionary(g => g.Key, g => g.Count());

            var topTalkers = _hosts.Values
                .OrderByDescending(h => h.BytesSent + h.BytesReceived)
                .Take(10)
                .Select(h => new HostTrafficInfo
                {
                    Ip = h.IpAddress,
                    IsIPv6 = h.IsIPv6,
                    BytesSent = h.BytesSent,
                    BytesReceived = h.BytesReceived,
                    PacketsSent = h.PacketsSent,
                    PacketsReceived = h.PacketsReceived
                })
                .ToList();

            // IPv6 scope distribution — bao nhieu host moi scope
            var v6Scopes = _hosts.Values
                .Where(h => h.IsIPv6 && !string.IsNullOrEmpty(h.ScopeTag))
                .GroupBy(h => h.ScopeTag)
                .ToDictionary(g => g.Key!, g => g.Count());

            return new NetworkSummary
            {
                TotalHosts = _hosts.Count,
                PrivateHosts = _hosts.Values.Count(h => h.IsPrivate),
                PublicHosts = _hosts.Values.Count(h => !h.IsPrivate),
                IPv4Hosts = _hosts.Values.Count(h => !h.IsIPv6),
                IPv6Hosts = _hosts.Values.Count(h => h.IsIPv6),
                Subnets = subnets,
                TopTalkers = topTalkers,
                OsDistribution = _hosts.Values
                    .Where(h => !string.IsNullOrEmpty(h.OsGuess) && h.OsGuess != "Unknown")
                    .GroupBy(h => h.OsGuess)
                    .ToDictionary(g => g.Key, g => g.Count()),
                IPv6ScopeDistribution = v6Scopes
            };
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _hosts.Clear();
            _nextId = 1;
        }
    }
}

public class NetworkHost
{
    public long Id { get; init; }
    public string IpAddress { get; init; } = "";
    public string MacAddress { get; set; } = "";
    public string Vendor { get; set; } = "";
    public string OsGuess { get; set; } = "";
    public int LastTtl { get; set; }
    public bool IsPrivate { get; init; }
    public bool IsIPv6 { get; init; }
    public string Subnet { get; init; } = "";

    /// <summary>
    /// IPv6 scope: Link-Local, Unique-Local, Global, Loopback, IPv4-Mapped.
    /// Null cho IPv4 hosts.
    /// </summary>
    public string? ScopeTag { get; init; }

    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
    public List<ushort> OpenPorts { get; set; } = new();
    public List<string> Protocols { get; set; } = new();
    public List<string> Peers { get; set; } = new();
    public long PacketsSent { get; set; }
    public long PacketsReceived { get; set; }
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public List<string> AnomalyFlags { get; set; } = new();
}

public class NetworkSummary
{
    public int TotalHosts { get; init; }
    public int PrivateHosts { get; init; }
    public int PublicHosts { get; init; }
    public int IPv4Hosts { get; init; }
    public int IPv6Hosts { get; init; }
    public Dictionary<string, int> Subnets { get; init; } = new();
    public List<HostTrafficInfo> TopTalkers { get; init; } = new();
    public Dictionary<string, int> OsDistribution { get; init; } = new();
    public Dictionary<string, int> IPv6ScopeDistribution { get; init; } = new();
}

public class HostTrafficInfo
{
    public string Ip { get; init; } = "";
    public bool IsIPv6 { get; init; }
    public long BytesSent { get; init; }
    public long BytesReceived { get; init; }
    public long PacketsSent { get; init; }
    public long PacketsReceived { get; init; }
}

using System.Net;

namespace RedPacketSniffer.Core.Capture;

/// <summary>
/// Filter cấu hình capture — lọc ở tầng application (sau khi đọc packet từ driver)
/// Khác với NDIS static filter (lọc ở kernel) — dùng cả hai cho hiệu suất tốt nhất
/// </summary>
public sealed class CaptureFilter
{
    /// <summary>TCP, UDP, ICMP, ARP, hoặc null = tất cả</summary>
    public HashSet<string>? Protocols { get; set; }

    /// <summary>Chỉ capture packet có port trong danh sách (src hoặc dst)</summary>
    public HashSet<ushort>? Ports { get; set; }

    /// <summary>Chỉ capture packet liên quan đến IP này</summary>
    public HashSet<string>? IpAddresses { get; set; }

    /// <summary>Loại trừ packet có IP này ở src hoặc dst (vd: IP máy mình). Ưu tiên hơn IpAddresses.</summary>
    public HashSet<string>? ExcludedIpAddresses { get; set; }

    /// <summary>Subnet filter dạng CIDR, vd: "192.168.1.0/24"</summary>
    public string? Subnet { get; set; }

    /// <summary>Chỉ capture direction cụ thể, null = cả hai</summary>
    public PacketDirection? Direction { get; set; }

    /// <summary>Bật/tắt promiscuous mode trên adapter</summary>
    public bool Promiscuous { get; set; } = false;

    /// <summary>Số packet tối đa capture, 0 = unlimited</summary>
    public long MaxPackets { get; set; } = 0;

    /// <summary>Số bytes tối đa capture, 0 = unlimited</summary>
    public long MaxBytes { get; set; } = 0;

    /// <summary>Snap length — giới hạn kích thước mỗi packet (bytes), 0 = full packet</summary>
    public int SnapLength { get; set; } = 0;

    /// <summary>
    /// Kiểm tra packet có match filter không
    /// </summary>
    public bool Matches(CapturedPacket packet)
    {
        // Direction filter
        if (Direction.HasValue && packet.Direction != Direction.Value)
            return false;

        // Protocol filter
        if (Protocols is { Count: > 0 })
        {
            bool match = false;
            foreach (var proto in Protocols)
            {
                match = proto.ToUpperInvariant() switch
                {
                    "TCP" => packet.IpProtocol == 6,
                    "UDP" => packet.IpProtocol == 17,
                    "ICMP" => packet.IpProtocol == 1,
                    "IGMP" => packet.IpProtocol == 2,
                    "GRE" => packet.IpProtocol == 47,
                    "ESP" => packet.IpProtocol == 50,
                    "AH" => packet.IpProtocol == 51,
                    "IKE" => packet.ApplicationProtocol == "IKE" || packet.ApplicationProtocol == "NAT-T",
                    "NAT-T" => packet.ApplicationProtocol == "NAT-T",
                    "EIGRP" => packet.IpProtocol == 88,
                    "OSPF" => packet.IpProtocol == 89,
                    "VRRP" => packet.IpProtocol == 112,
                    "ARP" => packet.EtherType == 0x0806,
                    "STP" => packet.ApplicationProtocol == "STP",
                    "CDP" => packet.ApplicationProtocol == "CDP",
                    "LLDP" => packet.EtherType == 0x88CC,
                    "HSRP" => packet.ApplicationProtocol == "HSRP",
                    _ => false
                };
                if (match) break;
            }
            if (!match) return false;
        }

        // Port filter
        if (Ports is { Count: > 0 })
        {
            if (!Ports.Contains(packet.SourcePort) && !Ports.Contains(packet.DestPort))
                return false;
        }

        // IP filter (include)
        if (IpAddresses is { Count: > 0 })
        {
            if (packet.SourceIP == null && packet.DestIP == null)
                return false;
            if (!IpAddresses.Contains(packet.SourceIP ?? "") && !IpAddresses.Contains(packet.DestIP ?? ""))
                return false;
        }

        // IP exclude filter — ưu tiên hơn include (dùng để ẩn IP máy mình)
        if (ExcludedIpAddresses is { Count: > 0 })
        {
            if (packet.SourceIP != null && ExcludedIpAddresses.Contains(packet.SourceIP))
                return false;
            if (packet.DestIP != null && ExcludedIpAddresses.Contains(packet.DestIP))
                return false;
        }

        // Subnet filter
        if (!string.IsNullOrEmpty(Subnet))
        {
            if (packet.SourceIP == null && packet.DestIP == null)
                return false;
            if (!IsInSubnet(packet.SourceIP, Subnet) && !IsInSubnet(packet.DestIP, Subnet))
                return false;
        }

        return true;
    }

    private static bool IsInSubnet(string? ipStr, string cidr)
    {
        if (string.IsNullOrEmpty(ipStr)) return false;

        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) || !int.TryParse(parts[1], out int prefixLen))
            return false;
        if (!IPAddress.TryParse(ipStr, out var ip))
            return false;

        var networkBytes = network.GetAddressBytes();
        var ipBytes = ip.GetAddressBytes();
        if (networkBytes.Length != ipBytes.Length) return false;

        int fullBytes = prefixLen / 8;
        int remainingBits = prefixLen % 8;

        for (int i = 0; i < fullBytes && i < networkBytes.Length; i++)
        {
            if (networkBytes[i] != ipBytes[i]) return false;
        }

        if (remainingBits > 0 && fullBytes < networkBytes.Length)
        {
            byte mask = (byte)(0xFF << (8 - remainingBits));
            if ((networkBytes[fullBytes] & mask) != (ipBytes[fullBytes] & mask))
                return false;
        }

        return true;
    }
}

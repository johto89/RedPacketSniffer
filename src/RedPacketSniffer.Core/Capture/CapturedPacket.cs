using System.Net;

namespace RedPacketSniffer.Core.Capture;

/// <summary>
/// A captured packet — holds both the raw data and the parsed headers.
/// </summary>
public sealed record CapturedPacket
{
    public long Id { get; init; }
    public DateTime Timestamp { get; init; }
    public PacketDirection Direction { get; init; }
    public int Length { get; init; }

    // Layer 2
    public string SourceMac { get; init; } = "";
    public string DestMac { get; init; } = "";
    public ushort EtherType { get; init; }
    public string EtherTypeStr => EtherType switch
    {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        0x8100 => "802.1Q",
        0x88A8 => "QinQ",
        0x9100 => "QinQ",
        0x88CC => "LLDP",
        0x8809 => "LACP",
        0x0000 => IsLlcFrame ? "LLC" : "Unknown",
        _ => $"0x{EtherType:X4}"
    };

    /// <summary>True if this is an 802.2 LLC frame (EtherType field &lt; 0x0600 = length).</summary>
    public bool IsLlcFrame { get; init; }

    /// <summary>VLAN ID (12-bit) from the 802.1Q tag; 0 if there is no VLAN.</summary>
    public ushort VlanId { get; init; }

    /// <summary>Outer VLAN ID for QinQ (802.1ad); 0 if there is none.</summary>
    public ushort OuterVlanId { get; init; }

    // Layer 3 (IPv4 / IPv6)
    public string? SourceIP { get; init; }
    public string? DestIP { get; init; }
    public byte IpProtocol { get; init; }
    public byte TTL { get; init; }
    public bool IsIPv6 { get; init; }
    public string ProtocolStr => IpProtocol switch
    {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        58 => "ICMPv6",
        88 => "EIGRP",
        89 => "OSPF",
        112 => "VRRP",
        _ => $"Proto({IpProtocol})"
    };

    // Layer 4
    public ushort SourcePort { get; init; }
    public ushort DestPort { get; init; }
    public byte TcpFlags { get; init; }

    /// <summary>TCP sequence number in host byte order — consumed by the TCP stream reassembler.</summary>
    public uint TcpSeq { get; init; }

    public string TcpFlagsStr
    {
        get
        {
            if (IpProtocol != 6) return "";
            var flags = new List<string>();
            if ((TcpFlags & 0x02) != 0) flags.Add("SYN");
            if ((TcpFlags & 0x10) != 0) flags.Add("ACK");
            if ((TcpFlags & 0x01) != 0) flags.Add("FIN");
            if ((TcpFlags & 0x04) != 0) flags.Add("RST");
            if ((TcpFlags & 0x08) != 0) flags.Add("PSH");
            if ((TcpFlags & 0x20) != 0) flags.Add("URG");
            return string.Join(",", flags);
        }
    }

    // TCP Options — parsed following the PacketDotNet pattern
    /// <summary>TCP Maximum Segment Size (option 2).</summary>
    public ushort TcpMss { get; set; }
    /// <summary>TCP Window Scale factor (option 3) — shift count, 0-14.</summary>
    public byte TcpWindowScale { get; set; }
    /// <summary>TCP SACK Permitted (option 4).</summary>
    public bool TcpSackPermitted { get; set; }
    /// <summary>TCP Timestamps — TSval (option 8).</summary>
    public uint TcpTimestampValue { get; set; }
    /// <summary>TCP Timestamps — TSecr (option 8).</summary>
    public uint TcpTimestampEcho { get; set; }
    /// <summary>Readable TCP options summary.</summary>
    public string? TcpOptionsStr { get; set; }

    // Layer 7 hints (filled by analyzers)
    public string? ApplicationProtocol { get; set; }
    public string? Info { get; set; }

    /// <summary>GRE inner protocol info once decapsulated.</summary>
    public string? GreInnerInfo { get; set; }

    // Raw payload — used for deep analysis

    /// <summary>
    /// Byte offset of the L4 payload (TCP/UDP data) within <see cref="RawData"/>.
    /// Filled by PacketParser during parsing, so VLAN/QinQ tags and IPv6 extension
    /// headers are already accounted for. A value of -1 means no payload was located
    /// (non-TCP/UDP, a truncated frame, or an unparsed packet).
    ///
    /// This is the single source of truth for the payload offset: computing it once
    /// in the parser (which already walks the VLAN tags and IPv6 extension headers)
    /// avoids the earlier bug where GetPayload() re-derived the offset and skipped
    /// the VLAN tags, returning payload shifted by 4-8 bytes on tagged networks.
    /// </summary>
    public int PayloadOffset { get; init; } = -1;

    // Raw payload bytes — full captured frame (Ethernet header onwards)
    public byte[] RawData { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// Return the L4 payload (TCP/UDP data) using the offset computed by PacketParser.
    /// No re-parsing happens here, so VLAN/QinQ tags and IPv6 extension headers are
    /// handled correctly and stay consistent with PacketParser.
    /// Returns an empty span when there is no payload or the frame is truncated.
    /// </summary>
    public ReadOnlySpan<byte> GetPayload()
    {
        if (PayloadOffset < 0 || PayloadOffset >= RawData.Length)
            return ReadOnlySpan<byte>.Empty;

        return RawData.AsSpan(PayloadOffset);
    }

    /// <summary>
    /// One-line summary for display in the web UI.
    /// </summary>
    public string GetSummary()
    {
        if (!string.IsNullOrEmpty(Info)) return Info;
        if (EtherType == 0x0806) return "ARP";
        if (SourceIP == null) return $"{EtherTypeStr} {Length}B";

        string prefix = IsIPv6 ? "v6" : "";
        var proto = IpProtocol == 6 ? "TCP" : IpProtocol == 17 ? "UDP" :
                    IpProtocol == 58 ? "ICMPv6" : ProtocolStr;
        if (SourcePort > 0)
            return $"{prefix}{proto} {SourceIP}:{SourcePort} -> {DestIP}:{DestPort} [{TcpFlagsStr}]";
        return $"{prefix}{proto} {SourceIP} -> {DestIP}";
    }
}

public enum PacketDirection
{
    /// <summary>Packet being sent out to the network (outbound).</summary>
    Outbound,
    /// <summary>Packet received from the network (inbound).</summary>
    Inbound
}

using System.Net;
using System.Runtime.InteropServices;

namespace RedPacketSniffer.Core.NdisApi;

/// <summary>
/// Ethernet header — 14 bytes đầu của mọi frame
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct EthernetHeader
{
    public MacAddress Destination;
    public MacAddress Source;
    public ushort ProtocolBE; // Big-endian EtherType

    public ushort Protocol => NetUtils.Ntohs(ProtocolBE);

    public const ushort ETH_P_IP = 0x0800;
    public const ushort ETH_P_ARP = 0x0806;
    public const ushort ETH_P_RARP = 0x8035;
    public const ushort ETH_P_IPV6 = 0x86DD;
    public const ushort ETH_P_8021Q = 0x8100; // VLAN tagged
    public const ushort ETH_P_LLDP = 0x88CC; // Link Layer Discovery Protocol
    public const ushort ETH_P_LACP = 0x8809; // Link Aggregation Control Protocol
    public const int SIZE = 14;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct MacAddress
{
    public byte B0, B1, B2, B3, B4, B5;

    public override readonly string ToString() => $"{B0:X2}:{B1:X2}:{B2:X2}:{B3:X2}:{B4:X2}:{B5:X2}";

    public readonly bool IsBroadcast => B0 == 0xFF && B1 == 0xFF && B2 == 0xFF && B3 == 0xFF && B4 == 0xFF && B5 == 0xFF;

    public readonly bool IsMulticast => (B0 & 0x01) != 0;
}

/// <summary>
/// IPv4 header — kích thước tối thiểu 20 bytes, tối đa 60 bytes (có options)
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IPv4Header
{
    public byte VersionAndIHL;  // Version (4 bit cao) + IHL (4 bit thấp)
    public byte TOS;
    public ushort TotalLengthBE;
    public ushort IdentificationBE;
    public ushort FlagsAndFragmentBE;
    public byte TTL;
    public byte Protocol;
    public ushort ChecksumBE;
    public uint SourceBE;
    public uint DestinationBE;

    public readonly int HeaderLength => (VersionAndIHL & 0x0F) * 4;
    public readonly int Version => (VersionAndIHL >> 4) & 0x0F;
    public readonly ushort TotalLength => NetUtils.Ntohs(TotalLengthBE);

    public readonly IPAddress SourceAddress => new(SourceBE);
    public readonly IPAddress DestinationAddress => new(DestinationBE);

    // IP protocol numbers
    public const byte PROTO_ICMP = 1;
    public const byte PROTO_IGMP = 2;
    public const byte PROTO_TCP = 6;
    public const byte PROTO_UDP = 17;
    public const byte PROTO_GRE = 47;
    public const byte PROTO_EIGRP = 88;
    public const byte PROTO_OSPF = 89;
    public const byte PROTO_VRRP = 112;
    public const int MIN_SIZE = 20;
}

/// <summary>
/// TCP header — 20 bytes minimum
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct TcpHeader
{
    public ushort SourcePortBE;
    public ushort DestPortBE;
    public uint SequenceBE;
    public uint AckBE;
    public byte DataOffsetAndReserved; // DataOffset (4 bit cao) in 32-bit words
    public byte Flags;
    public ushort WindowBE;
    public ushort ChecksumBE;
    public ushort UrgentPointerBE;

    public readonly ushort SourcePort => NetUtils.Ntohs(SourcePortBE);
    public readonly ushort DestPort => NetUtils.Ntohs(DestPortBE);
    public readonly int DataOffset => ((DataOffsetAndReserved >> 4) & 0x0F) * 4;

    // TCP Flags
    public const byte FIN = 0x01;
    public const byte SYN = 0x02;
    public const byte RST = 0x04;
    public const byte PSH = 0x08;
    public const byte ACK = 0x10;
    public const byte URG = 0x20;
    public const int MIN_SIZE = 20;
}

/// <summary>
/// UDP header — luôn 8 bytes
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct UdpHeader
{
    public ushort SourcePortBE;
    public ushort DestPortBE;
    public ushort LengthBE;
    public ushort ChecksumBE;

    public readonly ushort SourcePort => NetUtils.Ntohs(SourcePortBE);
    public readonly ushort DestPort => NetUtils.Ntohs(DestPortBE);
    public readonly ushort Length => NetUtils.Ntohs(LengthBE);
    public const int SIZE = 8;
}

/// <summary>
/// ARP header
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ArpHeader
{
    public ushort HardwareTypeBE;
    public ushort ProtocolTypeBE;
    public byte HardwareSize;
    public byte ProtocolSize;
    public ushort OpcodeBE;
    // Phần còn lại variable — cho IPv4/Ethernet:
    public MacAddress SenderMac;
    public uint SenderIpBE;
    public MacAddress TargetMac;
    public uint TargetIpBE;

    public readonly ushort Opcode => NetUtils.Ntohs(OpcodeBE);
    public const ushort ARP_REQUEST = 1;
    public const ushort ARP_REPLY = 2;
}

/// <summary>
/// Utility network byte-order conversions
/// </summary>
public static class NetUtils
{
    public static ushort Ntohs(ushort netshort)
    {
        return (ushort)(((netshort >> 8) & 0x00FF) | ((netshort << 8) & 0xFF00));
    }

    public static uint Ntohl(uint netlong)
    {
        return ((netlong >> 24) & 0xFF)
             | ((netlong >> 8) & 0xFF00)
             | ((netlong << 8) & 0xFF0000)
             | ((netlong << 24) & 0xFF000000);
    }

    public static string IpToString(uint ipBE)
    {
        return new IPAddress(ipBE).ToString();
    }
}

// ============================================================
// Layer 2 Protocol Structures
// ============================================================

/// <summary>
/// LLC (Logical Link Control) header — 802.2
/// Dùng bởi STP, CDP (qua SNAP)
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LlcHeader
{
    public byte DSAP;
    public byte SSAP;
    public byte Control;

    // STP dùng DSAP=SSAP=0x42
    public const byte SAP_STP = 0x42;
    // SNAP extension dùng DSAP=SSAP=0xAA
    public const byte SAP_SNAP = 0xAA;
    public const int SIZE = 3;
}

/// <summary>
/// SNAP (Sub-Network Access Protocol) header — theo sau LLC
/// OUI + Protocol Type xác định protocol (CDP dùng OUI 00:00:0C type 0x2000)
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct SnapHeader
{
    public byte OUI0, OUI1, OUI2;
    public ushort ProtocolTypeBE;

    public readonly ushort ProtocolType => NetUtils.Ntohs(ProtocolTypeBE);
    public const ushort SNAP_CDP = 0x2000;
    public const ushort SNAP_DTP = 0x2004;
    public const int SIZE = 5;
}

/// <summary>
/// STP BPDU (Bridge Protocol Data Unit) — Configuration BPDU
/// Dst MAC: 01:80:C2:00:00:00
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct StpBpdu
{
    public ushort ProtocolIdBE;
    public byte Version;
    public byte Type; // 0=Config, 0x80=TCN, 2=RST
    public byte Flags; // bit 0=TC, bit 7=TCA
    public ushort RootPriorityBE;
    // Root Bridge ID: 8 bytes (2 priority + 6 MAC) — simplified
    // Full BPDU is 35+ bytes, parse dynamically

    public const byte TYPE_CONFIG = 0x00;
    public const byte TYPE_TCN = 0x80;
    public const byte TYPE_RST = 0x02;
    public const int MIN_SIZE = 4; // protocol_id + version + type
}

/// <summary>
/// ICMP header — deep parse type/code
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IcmpHeader
{
    public byte Type;
    public byte Code;
    public ushort ChecksumBE;
    public uint RestBE; // Depends on type

    // Common ICMP types
    public const byte ECHO_REPLY = 0;
    public const byte DEST_UNREACHABLE = 3;
    public const byte REDIRECT = 5;
    public const byte ECHO_REQUEST = 8;
    public const byte TIME_EXCEEDED = 11;
    public const byte TIMESTAMP_REQUEST = 13;
    public const byte TIMESTAMP_REPLY = 14;
    public const byte ADDRESS_MASK_REQUEST = 17;
    public const byte ADDRESS_MASK_REPLY = 18;
    public const int SIZE = 8;
}

/// <summary>
/// OSPF header — IP protocol 89
/// Auth type 0=None, 1=Plaintext, 2=MD5 (Cryptographic)
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct OspfHeader
{
    public byte Version;
    public byte Type; // 1=Hello, 2=DBD, 3=LSR, 4=LSU, 5=LSAck
    public ushort PacketLengthBE;
    public uint RouterIdBE;
    public uint AreaIdBE;
    public ushort ChecksumBE;
    public ushort AuthTypeBE;
    // Auth data: 8 bytes (cho plaintext hoặc MD5 metadata)
    public ulong AuthData;

    public readonly ushort AuthType => NetUtils.Ntohs(AuthTypeBE);
    public readonly ushort PacketLength => NetUtils.Ntohs(PacketLengthBE);

    public const byte TYPE_HELLO = 1;
    public const byte TYPE_DB_DESC = 2;
    public const byte TYPE_LS_REQUEST = 3;
    public const byte TYPE_LS_UPDATE = 4;
    public const byte TYPE_LS_ACK = 5;

    public const ushort AUTH_NONE = 0;
    public const ushort AUTH_PLAINTEXT = 1;
    public const ushort AUTH_MD5 = 2;
    public const int SIZE = 24;
}

/// <summary>
/// OSPF Hello packet — theo sau OSPF header
/// Chứa network mask, hello/dead interval, neighbors
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct OspfHello
{
    public uint NetworkMaskBE;
    public ushort HelloIntervalBE;
    public byte Options;
    public byte Priority;
    public uint DeadIntervalBE;
    public uint DesignatedRouterBE;
    public uint BackupDesignatedRouterBE;
    // Tiếp theo là danh sách neighbor router IDs (mỗi cái 4 bytes)

    public readonly ushort HelloInterval => NetUtils.Ntohs(HelloIntervalBE);
    public readonly uint DeadInterval => NetUtils.Ntohl(DeadIntervalBE);
    public const int SIZE = 20;
}

/// <summary>
/// EIGRP header — IP protocol 88
/// Multicast 224.0.0.10
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct EigrpHeader
{
    public byte Version;
    public byte Opcode; // 1=Update, 3=Query, 4=Reply, 5=Hello/Ack
    public ushort ChecksumBE;
    public uint FlagsBE;
    public uint SeqBE;
    public uint AckBE;
    public uint VridBE; // Virtual Router ID (top 16 bits) + AS Number (bottom 16 bits in older format)
    // Thực tế EIGRP dùng AS number riêng, parse từ TLV

    public const byte OPCODE_UPDATE = 1;
    public const byte OPCODE_QUERY = 3;
    public const byte OPCODE_REPLY = 4;
    public const byte OPCODE_HELLO = 5;
    public const int SIZE = 20;
}

/// <summary>
/// VRRP header — IP protocol 112
/// Multicast 224.0.0.18
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct VrrpHeader
{
    public byte VersionAndType; // Version (4 bit cao) + Type (4 bit thấp)
    public byte VirtualRouterId;
    public byte Priority;
    public byte CountIpAddrs;
    public byte AuthType; // 0=None, 1=Simple text, 2=IP Auth Header (deprecated)
    public byte AdvertInterval;
    public ushort ChecksumBE;
    // Tiếp theo: IP addresses (4 bytes mỗi cái × CountIpAddrs)

    public readonly int Version => (VersionAndType >> 4) & 0x0F;
    public readonly int Type => VersionAndType & 0x0F;

    public const byte AUTH_NONE = 0;
    public const byte AUTH_SIMPLE = 1;
    public const int SIZE = 8;
}

/// <summary>
/// HSRP (Hot Standby Router Protocol) — Cisco proprietary
/// UDP port 1985 (v1) hoặc 2029 (v2), multicast 224.0.0.2 (v1) hoặc 224.0.0.102 (v2)
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HsrpHeader
{
    public byte Version;
    public byte Opcode; // 0=Hello, 1=Coup, 2=Resign, 3=Advertise (v2)
    public byte State;  // 0=Initial, 1=Learn, 2=Listen, 4=Speak, 8=Standby, 16=Active
    public byte HelloTime;
    public byte HoldTime;
    public byte Priority;
    public byte Group;
    public byte Reserved;
    // Auth data: 8 bytes (plaintext password — SECURITY ISSUE)
    public ulong AuthData;
    public uint VirtualIpBE;

    public const byte STATE_ACTIVE = 16;
    public const byte STATE_STANDBY = 8;
    public const byte STATE_SPEAK = 4;
    public const int SIZE = 20;
}

/// <summary>
/// GRE header — IP protocol 47
/// Tunnel protocol, encapsulates other protocols
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct GreHeader
{
    public ushort FlagsAndVersionBE;
    public ushort ProtocolTypeBE; // EtherType of encapsulated protocol

    public readonly ushort ProtocolType => NetUtils.Ntohs(ProtocolTypeBE);
    public readonly ushort FlagsAndVersion => NetUtils.Ntohs(FlagsAndVersionBE);
    public readonly bool HasChecksum => (FlagsAndVersion & 0x8000) != 0;
    public readonly bool HasKey => (FlagsAndVersion & 0x2000) != 0;
    public readonly bool HasSequence => (FlagsAndVersion & 0x1000) != 0;
    public readonly int Version => FlagsAndVersion & 0x0007;

    /// <summary>
    /// Tính header length dựa trên flags — PacketDotNet pattern
    /// Base 4 bytes + 4 cho mỗi optional field (checksum, key, sequence)
    /// </summary>
    public readonly int HeaderLength
    {
        get
        {
            int len = SIZE;
            if (HasChecksum) len += 4; // Checksum (2) + Reserved1 (2)
            if (HasKey) len += 4;
            if (HasSequence) len += 4;
            return len;
        }
    }

    public const int SIZE = 4;
}

// ============================================================
// IPv6 — EtherType 0x86DD
// ============================================================

/// <summary>
/// IPv6 header — luôn 40 bytes fixed (extension headers nằm sau)
/// Pattern học từ PacketDotNet: extension header walking loop
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IPv6Header
{
    public uint VersionClassFlowBE; // Version(4) + Traffic Class(8) + Flow Label(20)
    public ushort PayloadLengthBE;
    public byte NextHeader; // Same values as IPv4 Protocol + extension header types
    public byte HopLimit;   // Tương đương TTL
    // Source: 16 bytes
    public ulong SourceHi;
    public ulong SourceLo;
    // Destination: 16 bytes
    public ulong DestHi;
    public ulong DestLo;

    public readonly ushort PayloadLength => NetUtils.Ntohs(PayloadLengthBE);
    public readonly uint VersionClassFlow => NetUtils.Ntohl(VersionClassFlowBE);
    public readonly int Version => (int)((VersionClassFlow >> 28) & 0x0F);
    public readonly byte TrafficClass => (byte)((VersionClassFlow >> 20) & 0xFF);
    public readonly uint FlowLabel => VersionClassFlow & 0xFFFFF;

    // Extension header types (NextHeader values)
    public const byte PROTO_HOP_BY_HOP = 0;
    public const byte PROTO_ICMPV6 = 58;
    public const byte PROTO_NONE = 59;     // No next header
    public const byte PROTO_DESTINATION = 60;
    public const byte PROTO_ROUTING = 43;
    public const byte PROTO_FRAGMENT = 44;
    public const byte PROTO_AH = 51;       // Authentication Header
    public const byte PROTO_ESP = 50;      // Encapsulating Security Payload
    public const byte PROTO_MOBILITY = 135;

    public const int SIZE = 40;

    /// <summary>
    /// Check if nextHeader is an extension header type that needs walking
    /// </summary>
    public static bool IsExtensionHeader(byte nextHeader)
    {
        return nextHeader switch
        {
            PROTO_HOP_BY_HOP or PROTO_DESTINATION or PROTO_ROUTING
                or PROTO_FRAGMENT or PROTO_AH or PROTO_MOBILITY => true,
            _ => false
        };
    }
}

/// <summary>
/// ICMPv6 header — IPv6 Next Header = 58
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ICMPv6Header
{
    public byte Type;
    public byte Code;
    public ushort ChecksumBE;
    public uint BodyBE;

    // ICMPv6 types
    public const byte DEST_UNREACHABLE = 1;
    public const byte PACKET_TOO_BIG = 2;
    public const byte TIME_EXCEEDED = 3;
    public const byte PARAMETER_PROBLEM = 4;
    public const byte ECHO_REQUEST = 128;
    public const byte ECHO_REPLY = 129;
    // NDP types
    public const byte ROUTER_SOLICITATION = 133;
    public const byte ROUTER_ADVERTISEMENT = 134;
    public const byte NEIGHBOR_SOLICITATION = 135;
    public const byte NEIGHBOR_ADVERTISEMENT = 136;
    public const byte REDIRECT = 137;
    // MLD
    public const byte MLD_QUERY = 130;
    public const byte MLD_REPORT = 131;
    public const byte MLD_DONE = 132;
    public const byte MLD2_REPORT = 143;

    public const int SIZE = 8;
}

// ============================================================
// DHCP — UDP port 67/68
// ============================================================

/// <summary>
/// DHCP (Bootstrap/DHCP) header — RFC 2131
/// Magic cookie: 0x63825363 tại offset 236
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DhcpHeader
{
    public byte Op;        // 1=BOOTREQUEST, 2=BOOTREPLY
    public byte HType;     // Hardware type (1=Ethernet)
    public byte HLen;      // Hardware address length (6 for Ethernet)
    public byte Hops;
    public uint XidBE;     // Transaction ID
    public ushort SecsBE;
    public ushort FlagsBE;
    public uint ClientIpBE;  // ciaddr
    public uint YourIpBE;    // yiaddr — offered IP
    public uint ServerIpBE;  // siaddr — next server
    public uint RelayIpBE;   // giaddr — relay agent
    // chaddr: 16 bytes (first 6 = MAC for Ethernet)
    // sname: 64 bytes
    // file: 128 bytes
    // Total fixed: 236 bytes, then magic cookie (4 bytes) + options

    public readonly uint Xid => NetUtils.Ntohl(XidBE);
    public readonly bool IsBroadcast => (NetUtils.Ntohs(FlagsBE) & 0x8000) != 0;

    public const byte OP_REQUEST = 1;
    public const byte OP_REPLY = 2;
    public const uint MAGIC_COOKIE = 0x63825363;
    public const int FIXED_SIZE = 236; // Trước magic cookie
    public const int OPTIONS_OFFSET = 240; // 236 + 4 (magic cookie)

    // DHCP message types (option 53)
    public const byte MSG_DISCOVER = 1;
    public const byte MSG_OFFER = 2;
    public const byte MSG_REQUEST = 3;
    public const byte MSG_DECLINE = 4;
    public const byte MSG_ACK = 5;
    public const byte MSG_NAK = 6;
    public const byte MSG_RELEASE = 7;
    public const byte MSG_INFORM = 8;
}

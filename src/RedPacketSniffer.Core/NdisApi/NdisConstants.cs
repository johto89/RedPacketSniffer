using System;

namespace RedPacketSniffer.Core.NdisApi;

/// <summary>
/// WinpkFilter NDIS API constants, enums and flags.
/// Covers adapter modes, packet types, filter definitions, NDIS flags, and driver constants.
/// </summary>
public static class NdisConst
{
    // ─────────────────────────────────────────────
    // Size constants
    // ─────────────────────────────────────────────
    public const int ADAPTER_NAME_SIZE = 256;
    public const int ADAPTER_LIST_SIZE = 32;
    public const int ETHER_ADDR_LENGTH = 6;
    public const int MAX_ETHER_FRAME = 1514;
    public const int INTERMEDIATE_BUFFER_RESERVED_LENGTH = 4;

    // WAN / RAS
    /// <summary>Buffer length for RAS_LINK_INFO.ProtocolBuffer (2048 for Windows 10+)</summary>
    public const int RAS_LINK_BUFFER_LENGTH = 2048;
    public const int RAS_LINKS_MAX = 256;

    // Driver name
    public const string NDISRD_DRIVER_NAME = "NDISRD";

    // ─────────────────────────────────────────────
    // IOCTL index constants
    // ─────────────────────────────────────────────
    public const uint FILE_DEVICE_NDISRD = 0x00008300;
    public const uint NDISRD_IOCTL_INDEX = 0x830;

    // ─────────────────────────────────────────────
    // Backward-compatible constants
    // These values are now defined as enum members in MSTCP_FLAGS,
    // PACKET_FLAG, and NDIS_PACKET_TYPE. These aliases exist so
    // existing code that references NdisConst.* keeps compiling.
    // ─────────────────────────────────────────────

    // MSTCP_FLAGS
    public const uint MSTCP_FLAG_SENT_TUNNEL   = (uint)MSTCP_FLAGS.MSTCP_FLAG_SENT_TUNNEL;
    public const uint MSTCP_FLAG_RECV_TUNNEL   = (uint)MSTCP_FLAGS.MSTCP_FLAG_RECV_TUNNEL;
    public const uint MSTCP_FLAG_TUNNEL        = (uint)MSTCP_FLAGS.MSTCP_FLAG_TUNNEL;
    public const uint MSTCP_FLAG_SENT_LISTEN   = (uint)MSTCP_FLAGS.MSTCP_FLAG_SENT_LISTEN;
    public const uint MSTCP_FLAG_RECV_LISTEN   = (uint)MSTCP_FLAGS.MSTCP_FLAG_RECV_LISTEN;
    public const uint MSTCP_FLAG_LISTEN        = (uint)MSTCP_FLAGS.MSTCP_FLAG_LISTEN;
    public const uint MSTCP_FLAG_FILTER_DIRECT = (uint)MSTCP_FLAGS.MSTCP_FLAG_FILTER_DIRECT;
    public const uint MSTCP_FLAG_LOOPBACK_FILTER = (uint)MSTCP_FLAGS.MSTCP_FLAG_LOOPBACK_FILTER;
    public const uint MSTCP_FLAG_LOOPBACK_BLOCK  = (uint)MSTCP_FLAGS.MSTCP_FLAG_LOOPBACK_BLOCK;

    // PACKET_FLAG
    public const uint PACKET_FLAG_ON_SEND    = (uint)PACKET_FLAG.PACKET_FLAG_ON_SEND;
    public const uint PACKET_FLAG_ON_RECEIVE = (uint)PACKET_FLAG.PACKET_FLAG_ON_RECEIVE;

    // NDIS_PACKET_TYPE
    public const uint NDIS_PACKET_TYPE_DIRECTED       = (uint)NDIS_PACKET_TYPE.NDIS_PACKET_TYPE_DIRECTED;
    public const uint NDIS_PACKET_TYPE_MULTICAST      = (uint)NDIS_PACKET_TYPE.NDIS_PACKET_TYPE_MULTICAST;
    public const uint NDIS_PACKET_TYPE_ALL_MULTICAST   = (uint)NDIS_PACKET_TYPE.NDIS_PACKET_TYPE_ALL_MULTICAST;
    public const uint NDIS_PACKET_TYPE_BROADCAST       = (uint)NDIS_PACKET_TYPE.NDIS_PACKET_TYPE_BROADCAST;
    public const uint NDIS_PACKET_TYPE_PROMISCUOUS     = (uint)NDIS_PACKET_TYPE.NDIS_PACKET_TYPE_PROMISCUOUS;
}

/// <summary>
/// Adapter mode flags - determines how the WinpkFilter driver handles packets for an adapter.
/// Tunnel mode intercepts packets (original is dropped).
/// Listen mode copies packets (original still delivered).
/// </summary>
[Flags]
public enum MSTCP_FLAGS : uint
{
    /// <summary>No flags set</summary>
    MSTCP_FLAG_NONE = 0x00000000,

    /// <summary>Intercept packets sent by MSTCP to network (outbound tunnel - original dropped)</summary>
    MSTCP_FLAG_SENT_TUNNEL = 0x00000001,
    /// <summary>Intercept packets from network to MSTCP (inbound tunnel - original dropped)</summary>
    MSTCP_FLAG_RECV_TUNNEL = 0x00000002,
    /// <summary>Intercept all packets in both directions (tunnel mode)</summary>
    MSTCP_FLAG_TUNNEL = MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL,

    /// <summary>Copy outbound packets sent by MSTCP (listen mode - original still delivered)</summary>
    MSTCP_FLAG_SENT_LISTEN = 0x00000004,
    /// <summary>Copy inbound packets from network (listen mode - original still delivered)</summary>
    MSTCP_FLAG_RECV_LISTEN = 0x00000008,
    /// <summary>Copy all packets in both directions (listen mode)</summary>
    MSTCP_FLAG_LISTEN = MSTCP_FLAG_SENT_LISTEN | MSTCP_FLAG_RECV_LISTEN,

    /// <summary>In promiscuous mode, filter non-local packets from reaching TCP/IP stack</summary>
    MSTCP_FLAG_FILTER_DIRECT = 0x00000010,
    /// <summary>Pass loopback packets through the filter pipeline</summary>
    MSTCP_FLAG_LOOPBACK_FILTER = 0x00000020,
    /// <summary>Silently drop loopback packets (use with promiscuous mode)</summary>
    MSTCP_FLAG_LOOPBACK_BLOCK = 0x00000040,
}

/// <summary>
/// Packet direction flags used in INTERMEDIATE_BUFFER.m_dwDeviceFlags and STATIC_FILTER.m_dwDirectionFlags.
/// </summary>
[Flags]
public enum PACKET_FLAG : uint
{
    /// <summary>Packet captured on send path (outbound)</summary>
    PACKET_FLAG_ON_SEND = 0x00000001,
    /// <summary>Packet captured on receive path (inbound)</summary>
    PACKET_FLAG_ON_RECEIVE = 0x00000002,
}

/// <summary>
/// NDIS hardware packet filter types as defined in ndis.h.
/// Used with OID_GEN_CURRENT_PACKET_FILTER to set adapter receive mode.
/// </summary>
[Flags]
public enum NDIS_PACKET_TYPE : uint
{
    NDIS_PACKET_TYPE_NONE = 0x0000,
    /// <summary>Directed (unicast) packets addressed to this station</summary>
    NDIS_PACKET_TYPE_DIRECTED = 0x0001,
    /// <summary>Multicast packets in the multicast address list</summary>
    NDIS_PACKET_TYPE_MULTICAST = 0x0002,
    /// <summary>All multicast packets regardless of address list</summary>
    NDIS_PACKET_TYPE_ALL_MULTICAST = 0x0004,
    /// <summary>Broadcast packets</summary>
    NDIS_PACKET_TYPE_BROADCAST = 0x0008,
    /// <summary>Source-routed packets (Token Ring)</summary>
    NDIS_PACKET_TYPE_SOURCE_ROUTING = 0x0010,
    /// <summary>Promiscuous mode - receive all packets on the wire</summary>
    NDIS_PACKET_TYPE_PROMISCUOUS = 0x0020,
    /// <summary>SMT packets (FDDI)</summary>
    NDIS_PACKET_TYPE_SMT = 0x0040,
    /// <summary>All packets sent by installed protocols and all promiscuous mode packets</summary>
    NDIS_PACKET_TYPE_ALL_LOCAL = 0x0080,
    /// <summary>Group address packets (Token Ring)</summary>
    NDIS_PACKET_TYPE_GROUP = 0x1000,
    /// <summary>All functional address packets (Token Ring)</summary>
    NDIS_PACKET_TYPE_ALL_FUNCTIONAL = 0x2000,
    /// <summary>Functional address packets in the current address</summary>
    NDIS_PACKET_TYPE_FUNCTIONAL = 0x4000,
    /// <summary>NIC driver MAC frames</summary>
    NDIS_PACKET_TYPE_MAC_FRAME = 0x8000,

    // 802.11 wireless types
    /// <summary>802.11 raw data frames (includes FCS)</summary>
    NDIS_PACKET_TYPE_802_11_RAW_DATA = 0x00010000,
    /// <summary>802.11 directed management frames</summary>
    NDIS_PACKET_TYPE_802_11_DIRECTED_MGMT = 0x00020000,
    /// <summary>802.11 broadcast management frames</summary>
    NDIS_PACKET_TYPE_802_11_BROADCAST_MGMT = 0x00040000,
    /// <summary>802.11 multicast management frames</summary>
    NDIS_PACKET_TYPE_802_11_MULTICAST_MGMT = 0x00080000,
    /// <summary>802.11 all multicast management frames</summary>
    NDIS_PACKET_TYPE_802_11_ALL_MULTICAST_MGMT = 0x00100000,
    /// <summary>802.11 promiscuous management frames</summary>
    NDIS_PACKET_TYPE_802_11_PROMISCUOUS_MGMT = 0x00200000,
    /// <summary>802.11 raw management frames</summary>
    NDIS_PACKET_TYPE_802_11_RAW_MGMT = 0x00400000,
    /// <summary>802.11 directed control frames</summary>
    NDIS_PACKET_TYPE_802_11_DIRECTED_CTRL = 0x00800000,
    /// <summary>802.11 broadcast control frames</summary>
    NDIS_PACKET_TYPE_802_11_BROADCAST_CTRL = 0x01000000,
    /// <summary>802.11 promiscuous control frames</summary>
    NDIS_PACKET_TYPE_802_11_PROMISCUOUS_CTRL = 0x02000000,

    /// <summary>Combination of all 802.11 filter types for maximum WiFi capture</summary>
    NDIS_PACKET_TYPE_ALL_802_11_FILTERS =
        NDIS_PACKET_TYPE_DIRECTED |
        NDIS_PACKET_TYPE_MULTICAST |
        NDIS_PACKET_TYPE_ALL_MULTICAST |
        NDIS_PACKET_TYPE_BROADCAST |
        NDIS_PACKET_TYPE_PROMISCUOUS |
        NDIS_PACKET_TYPE_802_11_RAW_DATA |
        NDIS_PACKET_TYPE_802_11_DIRECTED_MGMT |
        NDIS_PACKET_TYPE_802_11_BROADCAST_MGMT |
        NDIS_PACKET_TYPE_802_11_MULTICAST_MGMT |
        NDIS_PACKET_TYPE_802_11_ALL_MULTICAST_MGMT |
        NDIS_PACKET_TYPE_802_11_PROMISCUOUS_MGMT |
        NDIS_PACKET_TYPE_802_11_RAW_MGMT |
        NDIS_PACKET_TYPE_802_11_DIRECTED_CTRL |
        NDIS_PACKET_TYPE_802_11_BROADCAST_CTRL |
        NDIS_PACKET_TYPE_802_11_PROMISCUOUS_CTRL,
}

/// <summary>
/// NDIS per-packet flags from ndis.h.
/// These appear in NdisMIndicateReceivePacket and NdisSend paths.
/// </summary>
[Flags]
public enum NDIS_FLAGS : uint
{
    /// <summary>Mask for protocol ID in the flags field (lower 4 bits)</summary>
    NDIS_FLAGS_PROTOCOL_ID_MASK = 0x0000000F,
    /// <summary>Packet is a multicast packet</summary>
    NDIS_FLAGS_MULTICAST_PACKET = 0x00000010,
    NDIS_FLAGS_RESERVED2 = 0x00000020,
    NDIS_FLAGS_RESERVED3 = 0x00000040,
    /// <summary>Do not loopback this packet</summary>
    NDIS_FLAGS_DONT_LOOPBACK = 0x00000080,
    /// <summary>This packet is a loopback packet</summary>
    NDIS_FLAGS_IS_LOOPBACK_PACKET = 0x00000100,
    /// <summary>Send this packet as loopback only (do not transmit on wire)</summary>
    NDIS_FLAGS_LOOPBACK_ONLY = 0x00000200,
    NDIS_FLAGS_RESERVED4 = 0x00000400,
    /// <summary>Packet buffer is double-buffered</summary>
    NDIS_FLAGS_DOUBLE_BUFFERED = 0x00000800,
    /// <summary>Packet was sent at DPC level</summary>
    NDIS_FLAGS_SENT_AT_DPC = 0x00001000,
    /// <summary>Packet uses scatter/gather buffer list</summary>
    NDIS_FLAGS_USES_SG_BUFFER_LIST = 0x00002000,
    /// <summary>Packet uses original packet descriptor</summary>
    NDIS_FLAGS_USES_ORIGINAL_PACKET = 0x00004000,
    /// <summary>Packet data is padded</summary>
    NDIS_FLAGS_PADDED = 0x00010000,
    /// <summary>Translate at top of stack</summary>
    NDIS_FLAGS_XLATE_AT_TOP = 0x00020000,
}

/// <summary>
/// Static filter action - what to do when a packet matches a filter rule.
/// </summary>
public enum FILTER_PACKET_ACTION : uint
{
    /// <summary>Allow the packet through</summary>
    FILTER_PACKET_PASS = 0x00000001,
    /// <summary>Drop the packet silently</summary>
    FILTER_PACKET_DROP = 0x00000002,
    /// <summary>Redirect the packet to the client application for inspection</summary>
    FILTER_PACKET_REDIRECT = 0x00000003,
}

/// <summary>
/// Flags indicating which layers of a static filter rule are active.
/// </summary>
[Flags]
public enum STATIC_FILTER_FIELDS : uint
{
    /// <summary>Match packet against data link layer (Ethernet 802.3) filter</summary>
    DATA_LINK_LAYER_VALID = 0x00000001,
    /// <summary>Match packet against network layer (IPv4/IPv6) filter</summary>
    NETWORK_LAYER_VALID = 0x00000002,
    /// <summary>Match packet against transport layer (TCP/UDP) filter</summary>
    TRANSPORT_LAYER_VALID = 0x00000004,
}

/// <summary>
/// Union selector flags for filter sub-structures.
/// Each filter layer union uses this to select which member is active.
/// </summary>
public enum FILTER_SELECT_FLAGS : uint
{
    /// <summary>Data link layer: Ethernet 802.3 filter</summary>
    ETH_802_3 = 0x00000001,
    /// <summary>Network layer: IPv4 filter</summary>
    IPV4 = 0x00000001,
    /// <summary>Network layer: IPv6 filter</summary>
    IPV6 = 0x00000002,
    /// <summary>Transport layer: TCP/UDP filter</summary>
    TCPUDP = 0x00000001,
}

/// <summary>
/// Ethernet 802.3 filter valid fields.
/// </summary>
[Flags]
public enum ETH_802_3_FLAGS : uint
{
    /// <summary>Match source MAC address</summary>
    ETH_802_3_SRC_ADDRESS = 0x00000001,
    /// <summary>Match destination MAC address</summary>
    ETH_802_3_DEST_ADDRESS = 0x00000002,
    /// <summary>Match EtherType protocol field</summary>
    ETH_802_3_PROTOCOL = 0x00000004,
}

/// <summary>
/// IPv4 filter valid fields.
/// </summary>
[Flags]
public enum IP_V4_FILTER_FIELDS : uint
{
    /// <summary>Match source IPv4 address</summary>
    IP_V4_FILTER_SRC_ADDRESS = 0x00000001,
    /// <summary>Match destination IPv4 address</summary>
    IP_V4_FILTER_DEST_ADDRESS = 0x00000002,
    /// <summary>Match IP protocol number (TCP=6, UDP=17, ICMP=1, etc.)</summary>
    IP_V4_FILTER_PROTOCOL = 0x00000004,
}

/// <summary>
/// IPv6 filter valid fields.
/// </summary>
[Flags]
public enum IP_V6_FILTER_FIELDS : uint
{
    /// <summary>Match source IPv6 address</summary>
    IP_V6_FILTER_SRC_ADDRESS = 0x00000001,
    /// <summary>Match destination IPv6 address</summary>
    IP_V6_FILTER_DEST_ADDRESS = 0x00000002,
    /// <summary>Match next header protocol number</summary>
    IP_V6_FILTER_PROTOCOL = 0x00000004,
}

/// <summary>
/// IPv6 address type selector for IP_ADDRESS_V6 union.
/// </summary>
public enum IP_ADDRESS_V6_TYPE : uint
{
    /// <summary>Address is specified as subnet (address + mask)</summary>
    IP_SUBNET_V6_TYPE = 0x00000001,
    /// <summary>Address is specified as range (start + end)</summary>
    IP_RANGE_V6_TYPE = 0x00000002,
}

/// <summary>
/// TCP/UDP filter valid fields.
/// </summary>
[Flags]
public enum TCPUDP_FILTER_FIELDS : uint
{
    /// <summary>Match source port</summary>
    TCPUDP_SRC_PORT = 0x00000001,
    /// <summary>Match destination port</summary>
    TCPUDP_DEST_PORT = 0x00000002,
    /// <summary>Match TCP flags (SYN, ACK, FIN, RST, etc.)</summary>
    TCPUDP_TCP_FLAGS = 0x00000004,
}

/// <summary>
/// NDIS medium type — identifies the physical medium of a network adapter.
/// Used in TCP_AdapterList.m_nAdapterMediumList to classify adapter types.
///
/// Values from ndis.h NDIS_MEDIUM enumeration.
/// NdisMediumDefault and NdisMedium802_3 share value 0 (Ethernet is the default).
/// </summary>
public enum NDIS_MEDIUM : uint
{
    /// <summary>Default medium (same as 802.3 Ethernet)</summary>
    NdisMediumDefault = 0,
    /// <summary>Ethernet 802.3</summary>
    NdisMedium802_3 = 0,
    /// <summary>Token Ring 802.5</summary>
    NdisMedium802_5 = 1,
    /// <summary>FDDI (Fiber Distributed Data Interface)</summary>
    NdisMediumFddi = 2,
    /// <summary>WAN (Wide Area Network)</summary>
    NdisMediumWan = 3,
    /// <summary>LocalTalk (legacy Apple)</summary>
    NdisMediumLocalTalk = 4,
    /// <summary>DIX (DEC-Intel-Xerox Ethernet)</summary>
    NdisMediumDix = 5,
    /// <summary>ARCNET raw</summary>
    NdisMediumArcnetRaw = 6,
    /// <summary>ARCNET 878.2</summary>
    NdisMediumArcnet878_2 = 7,
    /// <summary>ATM (Asynchronous Transfer Mode)</summary>
    NdisMediumAtm = 8,
    /// <summary>Wireless WAN (cellular, satellite)</summary>
    NdisMediumWirelessWan = 9,
    /// <summary>IrDA (Infrared Data Association)</summary>
    NdisMediumIrda = 10,
    /// <summary>BPC (Broadcast PC)</summary>
    NdisMediumBpc = 11,
    /// <summary>Connection-oriented WAN</summary>
    NdisMediumCoWan = 12,
    /// <summary>IEEE 1394 (FireWire)</summary>
    NdisMedium1394 = 13,
    /// <summary>InfiniBand</summary>
    NdisMediumInfiniBand = 14,
    /// <summary>Tunnel adapter</summary>
    NdisMediumTunnel = 15,
    /// <summary>Native 802.11 (Wi-Fi)</summary>
    NdisMediumNative802_11 = 16,
    /// <summary>Loopback adapter</summary>
    NdisMediumLoopback = 17,
    /// <summary>WiMAX (Worldwide Interoperability for Microwave Access)</summary>
    NdisMediumWiMAX = 18,
    /// <summary>Generic IP medium</summary>
    NdisMediumIP = 19,
    /// <summary>Upper bound (not a valid medium type)</summary>
    NdisMediumMax = 20,
}

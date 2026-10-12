using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace RedPacketSniffer.Core.NdisApi;

// ═════════════════════════════════════════════════════════════════
// Core NDIS driver structures
// ═════════════════════════════════════════════════════════════════

/// <summary>
/// TCP/IP adapter list returned by GetTcpipBoundAdaptersInfo.
/// Contains up to ADAPTER_LIST_SIZE adapters with names, handles, MAC addresses, and MTU.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct TCP_AdapterList
{
    public uint m_nAdapterCount;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = NdisConst.ADAPTER_LIST_SIZE * NdisConst.ADAPTER_NAME_SIZE)]
    public byte[] m_szAdapterNameList;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = NdisConst.ADAPTER_LIST_SIZE)]
    public IntPtr[] m_nAdapterHandle;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = NdisConst.ADAPTER_LIST_SIZE)]
    public uint[] m_nAdapterMediumList;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = NdisConst.ADAPTER_LIST_SIZE * NdisConst.ETHER_ADDR_LENGTH)]
    public byte[] m_czCurrentAddress;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = NdisConst.ADAPTER_LIST_SIZE)]
    public ushort[] m_usMTU;

    /// <summary>
    /// Gets the internal name (GUID path) of the adapter at the given index.
    /// </summary>
    public readonly string GetInternalName(int index)
    {
        var name = Encoding.ASCII.GetString(m_szAdapterNameList, index * NdisConst.ADAPTER_NAME_SIZE, NdisConst.ADAPTER_NAME_SIZE);
        int nullIdx = name.IndexOf('\0');
        return nullIdx >= 0 ? name[..nullIdx] : name;
    }

    /// <summary>
    /// Gets the MAC address bytes for the adapter at the given index.
    /// </summary>
    public readonly byte[] GetMacAddress(int index)
    {
        var mac = new byte[NdisConst.ETHER_ADDR_LENGTH];
        Array.Copy(m_czCurrentAddress, index * NdisConst.ETHER_ADDR_LENGTH, mac, 0, NdisConst.ETHER_ADDR_LENGTH);
        return mac;
    }

    /// <summary>
    /// Gets the MAC address as formatted string XX:XX:XX:XX:XX:XX.
    /// </summary>
    public readonly string GetMacAddressString(int index)
    {
        var mac = GetMacAddress(index);
        return $"{mac[0]:X2}:{mac[1]:X2}:{mac[2]:X2}:{mac[3]:X2}:{mac[4]:X2}:{mac[5]:X2}";
    }
}

/// <summary>
/// Doubly-linked list entry — kernel list header in INTERMEDIATE_BUFFER.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LIST_ENTRY
{
    public IntPtr Flink;
    public IntPtr Blink;
}

/// <summary>
/// Union of LIST_ENTRY (used by kernel) and adapter handle (used by Fast I/O).
/// First 2*sizeof(IntPtr) bytes of INTERMEDIATE_BUFFER serve dual purpose.
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct LIST_ENTRY_OR_ADAPTER_HANDLE
{
    /// <summary>Kernel-mode linked list entry</summary>
    [FieldOffset(0)]
    public LIST_ENTRY m_qLink;

    /// <summary>Adapter handle for Fast I/O path</summary>
    [FieldOffset(0)]
    public IntPtr m_hAdapter;
}

/// <summary>
/// Intermediate buffer containing a captured/injected packet.
/// m_dwDeviceFlags indicates direction (PACKET_FLAG_ON_SEND / PACKET_FLAG_ON_RECEIVE).
/// m_IBuffer contains the raw Ethernet frame starting from the Ethernet header.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct INTERMEDIATE_BUFFER
{
    /// <summary>Union: kernel list entry or adapter handle (for Fast I/O)</summary>
    public LIST_ENTRY_OR_ADAPTER_HANDLE m_qLink_hAdapter;

    /// <summary>Packet direction flags (PACKET_FLAG_ON_SEND or PACKET_FLAG_ON_RECEIVE)</summary>
    public uint m_dwDeviceFlags;

    /// <summary>Actual length of data in m_IBuffer</summary>
    public uint m_Length;

    /// <summary>NDIS packet flags</summary>
    public uint m_Flags;

    /// <summary>802.1Q VLAN tag information</summary>
    public uint m_8021q;

    /// <summary>Filter identifier that matched this packet</summary>
    public uint m_FilterID;

    /// <summary>Reserved for future use</summary>
    public fixed uint m_Reserved[NdisConst.INTERMEDIATE_BUFFER_RESERVED_LENGTH];

    /// <summary>Raw Ethernet frame data</summary>
    public fixed byte m_IBuffer[NdisConst.MAX_ETHER_FRAME];

    /// <summary>
    /// Convenience property for adapter handle (union with m_qLink).
    /// Used in Fast I/O path where kernel list entry is not needed.
    /// </summary>
    public IntPtr AdapterHandle
    {
        get => m_qLink_hAdapter.m_hAdapter;
        set => m_qLink_hAdapter.m_hAdapter = value;
    }

    /// <summary>Byte offset of m_IBuffer within the struct</summary>
    public static readonly IntPtr BufferOffset = Marshal.OffsetOf(typeof(INTERMEDIATE_BUFFER), nameof(m_IBuffer));

    /// <summary>Size of the struct in bytes</summary>
    public static readonly int Size = sizeof(INTERMEDIATE_BUFFER);

    /// <summary>Size of the header (struct minus m_IBuffer)</summary>
    public static readonly int SizeOfHeader = Size - NdisConst.MAX_ETHER_FRAME;
}

/// <summary>
/// Container for a pointer to INTERMEDIATE_BUFFER.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct NDISRD_ETH_Packet
{
    public IntPtr Buffer;
}

/// <summary>
/// Single-packet read/write request.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ETH_REQUEST
{
    public IntPtr hAdapterHandle;
    public NDISRD_ETH_Packet EthPacket;
}

/// <summary>
/// Batch multi-packet read/write request — higher throughput than ETH_REQUEST.
/// dwPacketsNumber: requested count; dwPacketsSuccess: actual count processed by driver.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ETH_M_REQUEST
{
    public IntPtr hAdapterHandle;
    public uint dwPacketsNumber;
    public uint dwPacketsSuccess;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public NDISRD_ETH_Packet[] EthPacket;
}

/// <summary>
/// Adapter mode configuration: sets listen/tunnel/filter flags for an adapter.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ADAPTER_MODE
{
    public IntPtr hAdapterHandle;
    public uint dwFlags;
}

/// <summary>
/// NDIS OID request structure for querying/setting adapter properties.
/// Data field is variable-length (allocated beyond the struct).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct PACKET_OID_DATA
{
    public IntPtr hAdapterHandle;
    public uint Oid;
    public uint Length;
    public fixed byte Data[1]; // Variable length
}

// ═════════════════════════════════════════════════════════════════
// RAS / WAN link structures
// ═════════════════════════════════════════════════════════════════

/// <summary>
/// WAN link information for a single RAS connection.
/// Contains link speed, MTU, remote/local MAC addresses, and protocol-specific data.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct RAS_LINK_INFO
{
    /// <summary>Link speed in units of 100 bps</summary>
    public uint LinkSpeed;

    /// <summary>Maximum total size of a packet that the protocol can send (MTU)</summary>
    public uint MaximumTotalSize;

    /// <summary>Remote node MAC address (Ethernet-style, set by NDISWAN)</summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = NdisConst.ETHER_ADDR_LENGTH)]
    public byte[] RemoteAddress;

    /// <summary>Local node MAC address (Ethernet-style, set by NDISWAN)</summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = NdisConst.ETHER_ADDR_LENGTH)]
    public byte[] LocalAddress;

    /// <summary>Number of valid bytes in ProtocolBuffer</summary>
    public uint ProtocolBufferLength;

    /// <summary>
    /// Protocol-specific connection data.
    /// Max observed: 600 bytes on Vista, 1200 on Windows 10.
    /// Buffer size is RAS_LINK_BUFFER_LENGTH (2048).
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = NdisConst.RAS_LINK_BUFFER_LENGTH)]
    public byte[] ProtocolBuffer;
}

/// <summary>
/// Collection of RAS link information for an adapter.
/// Used with GetRasLinks IOCTL to enumerate WAN connections.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct RAS_LINKS
{
    /// <summary>Number of active RAS links</summary>
    public uint nNumberOfLinks;

    /// <summary>Array of RAS link info (max RAS_LINKS_MAX entries)</summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = NdisConst.RAS_LINKS_MAX)]
    public RAS_LINK_INFO[] RasLinks;

    /// <summary>Size of the entire RAS_LINKS struct in bytes</summary>
    public static readonly int Size = Marshal.SizeOf<RAS_LINKS>();
}

// ═════════════════════════════════════════════════════════════════
// Fast I/O structures — shared memory for high-performance packet I/O
// ═════════════════════════════════════════════════════════════════

/// <summary>
/// Split view of the Fast I/O write union: packet count + write-in-progress flag.
/// Both fields are volatile for lock-free coordination with the kernel driver.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct FAST_IO_WRITE_UNION_SPLIT
{
    /// <summary>Number of packets available in this section</summary>
    public volatile ushort number_of_packets;

    /// <summary>Non-zero while the driver is writing to this section</summary>
    public volatile ushort write_in_progress_flag;
}

/// <summary>
/// Union for atomic read of packet count + write flag as a single 32-bit int,
/// or split access to individual fields.
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct FAST_IO_WRITE_UNION
{
    /// <summary>Split access: separate packet count and write flag</summary>
    [FieldOffset(0)]
    public FAST_IO_WRITE_UNION_SPLIT split;

    /// <summary>Joined access: both fields as one volatile int for atomic operations</summary>
    [FieldOffset(0)]
    public volatile int join;
}

/// <summary>
/// Header of a Fast I/O shared memory section.
/// Contains write state and read-in-progress flag for lock-free producer/consumer.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct FAST_IO_SECTION_HEADER
{
    /// <summary>Write state (packet count + write-in-progress)</summary>
    public FAST_IO_WRITE_UNION fast_io_write_union;

    /// <summary>Non-zero while user-mode is reading from this section</summary>
    public volatile int read_in_progress_flag;

    /// <summary>Size of the header in bytes</summary>
    public static readonly int Size = Marshal.SizeOf<FAST_IO_SECTION_HEADER>();
}

/// <summary>
/// Fast I/O shared memory section containing a header followed by a variable-length
/// array of INTERMEDIATE_BUFFER packets. The driver and user-mode coordinate via
/// the header flags for lock-free packet exchange.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct FAST_IO_SECTION
{
    /// <summary>Section header with synchronization flags</summary>
    public FAST_IO_SECTION_HEADER fast_io_header;

    /// <summary>
    /// First element of the variable-length INTERMEDIATE_BUFFER array.
    /// Access the full array through IntermediateBuffers property.
    /// </summary>
    public INTERMEDIATE_BUFFER fast_io_packets;

    /// <summary>
    /// Gets a Span over the INTERMEDIATE_BUFFER array based on current packet count.
    /// </summary>
    public unsafe Span<INTERMEDIATE_BUFFER> IntermediateBuffers
    {
        get
        {
#if NETCOREAPP
            return MemoryMarshal.CreateSpan(ref fast_io_packets, fast_io_header.fast_io_write_union.split.number_of_packets);
#else
            fixed (INTERMEDIATE_BUFFER* packets = &fast_io_packets)
            {
                return new Span<INTERMEDIATE_BUFFER>(packets, fast_io_header.fast_io_write_union.split.number_of_packets);
            }
#endif
        }
    }

    /// <summary>Size of just the header (without any INTERMEDIATE_BUFFER)</summary>
    public static readonly int SizeOfHeader = FAST_IO_SECTION_HEADER.Size;
}

/// <summary>
/// Parameters for InitializeFastIo IOCTL call.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct INITIALIZE_FAST_IO_PARAMS
{
    /// <summary>Adapter handle to initialize Fast I/O for</summary>
    public IntPtr hAdapterHandle;

    /// <summary>Pointer to the shared memory section for Fast I/O</summary>
    public IntPtr pFastIoSection;

    /// <summary>Size of the shared memory section in bytes</summary>
    public uint dwFastIoSectionSize;
}

// ═════════════════════════════════════════════════════════════════
// IPv6 address structures
// ═════════════════════════════════════════════════════════════════

/// <summary>
/// 128-bit IPv6 address as 16 individual bytes.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IN6_ADDR
{
    public byte b0, b1, b2, b3, b4, b5, b6, b7;
    public byte b8, b9, b10, b11, b12, b13, b14, b15;

    /// <summary>
    /// Initializes from an IPAddress (must be IPv6).
    /// </summary>
    public IN6_ADDR(IPAddress ipAddress) : this(ipAddress.GetAddressBytes()) { }

    /// <summary>
    /// Initializes from a 16-byte array.
    /// </summary>
    public IN6_ADDR(byte[] bytes)
        : this()
    {
        if (bytes.Length != 16)
            throw new ArgumentException("IPv6 address must be exactly 16 bytes.", nameof(bytes));

        b0 = bytes[0]; b1 = bytes[1]; b2 = bytes[2]; b3 = bytes[3];
        b4 = bytes[4]; b5 = bytes[5]; b6 = bytes[6]; b7 = bytes[7];
        b8 = bytes[8]; b9 = bytes[9]; b10 = bytes[10]; b11 = bytes[11];
        b12 = bytes[12]; b13 = bytes[13]; b14 = bytes[14]; b15 = bytes[15];
    }

    /// <summary>
    /// Converts to IPAddress.
    /// </summary>
    public readonly IPAddress ToIPAddress()
    {
        return new IPAddress(new[] { b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 });
    }

    /// <summary>
    /// Converts to 16-byte array.
    /// </summary>
    public readonly byte[] ToBytes()
    {
        return new[] { b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 };
    }
}

// ═════════════════════════════════════════════════════════════════
// Static filter structures — driver-level packet filtering
// ═════════════════════════════════════════════════════════════════

// --- IPv4 filter types ---

/// <summary>
/// IPv4 subnet: address + mask.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IP_SUBNET_V4
{
    public uint m_Ip;
    public uint m_IpMask;

    public IP_SUBNET_V4(uint ip, uint mask)
    {
        m_Ip = ip;
        m_IpMask = mask;
    }
}

/// <summary>
/// IPv4 range: start address to end address.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IP_RANGE_V4
{
    public uint m_StartIp;
    public uint m_EndIp;

    public IP_RANGE_V4(uint start, uint end)
    {
        m_StartIp = start;
        m_EndIp = end;
    }
}

/// <summary>
/// IPv4 address type selector for IP_ADDRESS_V4 union.
/// </summary>
public enum IP_ADDRESS_V4_TYPE : uint
{
    /// <summary>Address specified as subnet (address + mask)</summary>
    IP_SUBNET_V4_TYPE = 0x00000001,
    /// <summary>Address specified as range (start + end)</summary>
    IP_RANGE_V4_TYPE = 0x00000002,
}

/// <summary>
/// IPv4 address union: either a subnet or a range.
/// </summary>
[StructLayout(LayoutKind.Explicit, Pack = 1)]
public struct IP_ADDRESS_V4
{
    /// <summary>Which type is active</summary>
    [FieldOffset(0)]
    public IP_ADDRESS_V4_TYPE m_AddressType;

    /// <summary>Subnet (address + mask)</summary>
    [FieldOffset(4)]
    public IP_SUBNET_V4 m_IpSubnet;

    /// <summary>Range (start + end)</summary>
    [FieldOffset(4)]
    public IP_RANGE_V4 m_IpRange;
}

/// <summary>
/// IPv4 filter: matches source/dest address and protocol.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IP_V4_FILTER
{
    /// <summary>Which fields are active (IP_V4_FILTER_FIELDS flags)</summary>
    public IP_V4_FILTER_FIELDS m_ValidFields;

    /// <summary>Source address filter</summary>
    public IP_ADDRESS_V4 m_SrcAddress;

    /// <summary>Destination address filter</summary>
    public IP_ADDRESS_V4 m_DestAddress;

    /// <summary>IP protocol number (TCP=6, UDP=17, ICMP=1)</summary>
    public byte m_Protocol;

    private readonly byte m_Padding1;
    private readonly byte m_Padding2;
    private readonly byte m_Padding3;
}

// --- IPv6 filter types ---

/// <summary>
/// IPv6 subnet: address + mask (128-bit each).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IP_SUBNET_V6
{
    public IN6_ADDR m_Ip;
    public IN6_ADDR m_IpMask;

    public IP_SUBNET_V6(IN6_ADDR ip, IN6_ADDR mask)
    {
        m_Ip = ip;
        m_IpMask = mask;
    }

    public IP_SUBNET_V6(IPAddress ip, IPAddress mask)
    {
        m_Ip = new IN6_ADDR(ip);
        m_IpMask = new IN6_ADDR(mask);
    }
}

/// <summary>
/// IPv6 range: start address to end address (128-bit each).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IP_RANGE_V6
{
    public IN6_ADDR m_StartIp;
    public IN6_ADDR m_EndIp;

    public IP_RANGE_V6(IN6_ADDR start, IN6_ADDR end)
    {
        m_StartIp = start;
        m_EndIp = end;
    }

    public IP_RANGE_V6(IPAddress start, IPAddress end)
    {
        m_StartIp = new IN6_ADDR(start);
        m_EndIp = new IN6_ADDR(end);
    }
}

/// <summary>
/// IPv6 address union: either a subnet or a range.
/// </summary>
[StructLayout(LayoutKind.Explicit, Pack = 1)]
public struct IP_ADDRESS_V6
{
    /// <summary>Which type is active (IP_SUBNET_V6_TYPE or IP_RANGE_V6_TYPE)</summary>
    [FieldOffset(0)]
    public IP_ADDRESS_V6_TYPE m_AddressType;

    /// <summary>Subnet (address + mask)</summary>
    [FieldOffset(4)]
    public IP_SUBNET_V6 m_IpSubnet;

    /// <summary>Range (start + end)</summary>
    [FieldOffset(4)]
    public IP_RANGE_V6 m_IpRange;
}

/// <summary>
/// IPv6 filter: matches source/dest address and next header protocol.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IP_V6_FILTER
{
    /// <summary>Which fields are active (IP_V6_FILTER_FIELDS flags)</summary>
    public IP_V6_FILTER_FIELDS m_ValidFields;

    /// <summary>Source address filter</summary>
    public IP_ADDRESS_V6 m_SrcAddress;

    /// <summary>Destination address filter</summary>
    public IP_ADDRESS_V6 m_DestAddress;

    /// <summary>Next header protocol number</summary>
    public byte m_Protocol;

    private readonly byte m_Padding1;
    private readonly byte m_Padding2;
    private readonly byte m_Padding3;
}

// --- Ethernet filter ---

/// <summary>
/// Ethernet 802.3 filter: matches source/dest MAC and EtherType.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct ETH_802_3_FILTER
{
    /// <summary>Which fields are active (ETH_802_3_FLAGS)</summary>
    public ETH_802_3_FLAGS m_ValidFields;

    /// <summary>Source MAC address (6 bytes)</summary>
    public fixed byte m_SrcAddress[NdisConst.ETHER_ADDR_LENGTH];

    /// <summary>Destination MAC address (6 bytes)</summary>
    public fixed byte m_DestAddress[NdisConst.ETHER_ADDR_LENGTH];

    /// <summary>EtherType (e.g. 0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP)</summary>
    public ushort m_Protocol;

    private readonly ushort m_Padding;

    /// <summary>Copies source MAC address to byte array.</summary>
    public byte[] GetSourceAddress()
    {
        byte[] bytes = new byte[NdisConst.ETHER_ADDR_LENGTH];
        for (int i = 0; i < NdisConst.ETHER_ADDR_LENGTH; i++)
            bytes[i] = m_SrcAddress[i];
        return bytes;
    }

    /// <summary>Copies destination MAC address to byte array.</summary>
    public byte[] GetDestinationAddress()
    {
        byte[] bytes = new byte[NdisConst.ETHER_ADDR_LENGTH];
        for (int i = 0; i < NdisConst.ETHER_ADDR_LENGTH; i++)
            bytes[i] = m_DestAddress[i];
        return bytes;
    }

    /// <summary>Sets source MAC address from byte array.</summary>
    public void SetSourceAddress(byte[] bytes)
    {
        for (int i = 0; i < NdisConst.ETHER_ADDR_LENGTH; i++)
            m_SrcAddress[i] = bytes[i];
    }

    /// <summary>Sets destination MAC address from byte array.</summary>
    public void SetDestinationAddress(byte[] bytes)
    {
        for (int i = 0; i < NdisConst.ETHER_ADDR_LENGTH; i++)
            m_DestAddress[i] = bytes[i];
    }
}

// --- TCP/UDP filter ---

/// <summary>
/// Port range for TCP/UDP filtering.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct PORT_RANGE
{
    public ushort m_StartRange;
    public ushort m_EndRange;

    public PORT_RANGE(ushort port)
    {
        m_StartRange = port;
        m_EndRange = port;
    }

    public PORT_RANGE(ushort start, ushort end)
    {
        m_StartRange = start;
        m_EndRange = end;
    }
}

/// <summary>
/// TCP/UDP filter: matches source/dest port ranges and TCP flags.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct TCPUDP_FILTER
{
    /// <summary>Which fields are active (TCPUDP_FILTER_FIELDS flags)</summary>
    public TCPUDP_FILTER_FIELDS m_ValidFields;

    /// <summary>Source port range</summary>
    public PORT_RANGE m_SourcePort;

    /// <summary>Destination port range</summary>
    public PORT_RANGE m_DestPort;

    /// <summary>TCP flags mask (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04, etc.)</summary>
    public byte m_TCPFlags;

    private readonly byte m_Padding1;
    private readonly byte m_Padding2;
    private readonly byte m_Padding3;
}

// --- Layer filter wrappers ---

/// <summary>
/// Data link layer (L2) filter. Union selector must be ETH_802_3.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DATA_LINK_LAYER_FILTER
{
    /// <summary>Must be FILTER_SELECT_FLAGS.ETH_802_3</summary>
    public FILTER_SELECT_FLAGS m_dwUnionSelector;

    /// <summary>Ethernet 802.3 filter</summary>
    public ETH_802_3_FILTER m_Eth8023Filter;
}

/// <summary>
/// Network layer (L3) filter. Union selector determines IPv4 or IPv6.
/// </summary>
[StructLayout(LayoutKind.Explicit, Pack = 1)]
public struct NETWORK_LAYER_FILTER
{
    /// <summary>Set to FILTER_SELECT_FLAGS.IPV4 or FILTER_SELECT_FLAGS.IPV6</summary>
    [FieldOffset(0)]
    public FILTER_SELECT_FLAGS m_dwUnionSelector;

    /// <summary>IPv4 filter (active when selector = IPV4)</summary>
    [FieldOffset(4)]
    public IP_V4_FILTER m_IPv4;

    /// <summary>IPv6 filter (active when selector = IPV6)</summary>
    [FieldOffset(4)]
    public IP_V6_FILTER m_IPv6;
}

/// <summary>
/// Transport layer (L4) filter. Union selector must be TCPUDP.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct TRANSPORT_LAYER_FILTER
{
    /// <summary>Must be FILTER_SELECT_FLAGS.TCPUDP</summary>
    public FILTER_SELECT_FLAGS m_dwUnionSelector;

    /// <summary>TCP/UDP port and flags filter</summary>
    public TCPUDP_FILTER m_TcpUdp;
}

// --- Static filter entry and table ---

/// <summary>
/// Single static filter rule with per-rule statistics counters.
/// Combines adapter, direction, action, and multi-layer match criteria.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct STATIC_FILTER
{
    /// <summary>Adapter handle (stored as ulong for alignment)</summary>
    public ulong m_Adapter;

    /// <summary>Packet direction to match (PACKET_FLAG_ON_SEND / ON_RECEIVE)</summary>
    public PACKET_FLAG m_dwDirectionFlags;

    /// <summary>Action when packet matches (pass / drop / redirect)</summary>
    public FILTER_PACKET_ACTION m_FilterAction;

    /// <summary>Which layer filters are active</summary>
    public STATIC_FILTER_FIELDS m_ValidFields;

    /// <summary>Timestamp of last counters reset (seconds since 1 Jan 1980)</summary>
    public uint m_LastReset;

    /// <summary>Incoming packets matched by this filter</summary>
    public ulong m_PacketsIn;

    /// <summary>Incoming bytes matched by this filter</summary>
    public ulong m_BytesIn;

    /// <summary>Outgoing packets matched by this filter</summary>
    public ulong m_PacketsOut;

    /// <summary>Outgoing bytes matched by this filter</summary>
    public ulong m_BytesOut;

    /// <summary>Data link layer (Ethernet) filter criteria</summary>
    public DATA_LINK_LAYER_FILTER m_DataLinkFilter;

    /// <summary>Network layer (IPv4/IPv6) filter criteria</summary>
    public NETWORK_LAYER_FILTER m_NetworkFilter;

    /// <summary>Transport layer (TCP/UDP) filter criteria</summary>
    public TRANSPORT_LAYER_FILTER m_TransportFilter;

    /// <summary>Convenience property for adapter handle as IntPtr</summary>
    public IntPtr AdapterHandle
    {
        get => (IntPtr)m_Adapter;
        set => m_Adapter = (ulong)value;
    }

    /// <summary>Size of STATIC_FILTER in bytes</summary>
    public static readonly int Size = Marshal.SizeOf<STATIC_FILTER>();
}

/// <summary>
/// Table of static filter rules passed to the WinpkFilter driver.
/// Variable-length: m_TableSize entries follow the header.
/// Allocate with Marshal.AllocHGlobal(SizeOfHeader + count * STATIC_FILTER.Size).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct STATIC_FILTER_TABLE
{
    /// <summary>Number of STATIC_FILTER entries</summary>
    public uint m_TableSize;

    private readonly uint m_Padding;

    /// <summary>
    /// First element of the variable-length STATIC_FILTER array.
    /// Use StaticFilters property for span access.
    /// </summary>
    public STATIC_FILTER m_StaticFilters;

    /// <summary>
    /// Gets a Span over the STATIC_FILTER array based on m_TableSize.
    /// </summary>
    public unsafe Span<STATIC_FILTER> StaticFilters
    {
        get
        {
#if NETCOREAPP
            return MemoryMarshal.CreateSpan(ref m_StaticFilters, (int)m_TableSize);
#else
            fixed (STATIC_FILTER* pFilter = &m_StaticFilters)
            {
                return new Span<STATIC_FILTER>(pFilter, (int)m_TableSize);
            }
#endif
        }
    }

    /// <summary>
    /// Indexer for individual filter entries.
    /// </summary>
    public STATIC_FILTER this[int index]
    {
        get => StaticFilters[index];
        set => StaticFilters[index] = value;
    }

    /// <summary>Size of header only (without the variable filter array)</summary>
    public static readonly int SizeOfHeader = Marshal.SizeOf<STATIC_FILTER_TABLE>() - STATIC_FILTER.Size;
}

using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Export;

/// <summary>
/// Load PCAP file (libpcap format) → List&lt;CapturedPacket&gt;
/// Supports cả little-endian (0xA1B2C3D4) và big-endian (0xD4C3B2A1) magic
/// Tương thích file từ Wireshark, tcpdump, NetworkMiner
/// </summary>
public static class PcapReader
{
    private const uint PCAP_MAGIC_LE = 0xA1B2C3D4;
    private const uint PCAP_MAGIC_BE = 0xD4C3B2A1;
    private const uint PCAP_MAGIC_NS_LE = 0xA1B23C4D; // Nanosecond resolution
    private const uint PCAP_MAGIC_NS_BE = 0x4D3CB2A1;

    /// <summary>
    /// Đọc PCAP file từ đường dẫn
    /// </summary>
    public static PcapReadResult ReadFile(string filePath, int maxPackets = 0)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Read(stream, maxPackets);
    }

    /// <summary>
    /// Đọc PCAP từ byte array
    /// </summary>
    public static PcapReadResult ReadBytes(byte[] data, int maxPackets = 0)
    {
        using var stream = new MemoryStream(data, writable: false);
        return Read(stream, maxPackets);
    }

    /// <summary>
    /// Đọc PCAP từ stream
    /// </summary>
    public static PcapReadResult Read(Stream stream, int maxPackets = 0)
    {
        using var reader = new BinaryReader(stream);
        var result = new PcapReadResult();

        // Read global header (24 bytes)
        if (stream.Length < 24)
        {
            result.Error = "File quá nhỏ — không phải PCAP format";
            return result;
        }

        uint magic = reader.ReadUInt32();
        bool needSwap;
        bool isNanosecond;

        if (magic == PCAP_MAGIC_LE)
        {
            needSwap = false;
            isNanosecond = false;
        }
        else if (magic == PCAP_MAGIC_BE)
        {
            needSwap = true;
            isNanosecond = false;
        }
        else if (magic == PCAP_MAGIC_NS_LE)
        {
            needSwap = false;
            isNanosecond = true;
        }
        else if (magic == PCAP_MAGIC_NS_BE)
        {
            needSwap = true;
            isNanosecond = true;
        }
        else
        {
            result.Error = $"Magic number không hợp lệ: 0x{magic:X8}. Không phải PCAP file (có thể là pcapng — chưa hỗ trợ).";
            return result;
        }

        ushort versionMajor = ReadUInt16(reader, needSwap);
        ushort versionMinor = ReadUInt16(reader, needSwap);
        int thisZone = ReadInt32(reader, needSwap);
        uint sigFigs = ReadUInt32(reader, needSwap);
        uint snapLen = ReadUInt32(reader, needSwap);
        uint linkType = ReadUInt32(reader, needSwap);

        result.VersionMajor = versionMajor;
        result.VersionMinor = versionMinor;
        result.SnapLength = (int)snapLen;
        result.LinkType = (int)linkType;

        if (linkType != 1) // LINKTYPE_ETHERNET
        {
            result.Error = $"Link type {linkType} không được hỗ trợ. Chỉ hỗ trợ LINKTYPE_ETHERNET (1).";
            return result;
        }

        // Read packet records
        long packetId = 0;
        while (stream.Position < stream.Length - 15) // Cần ít nhất 16 bytes cho packet header
        {
            if (maxPackets > 0 && result.Packets.Count >= maxPackets)
                break;

            try
            {
                uint tsSec = ReadUInt32(reader, needSwap);
                uint tsFrac = ReadUInt32(reader, needSwap);
                uint capturedLen = ReadUInt32(reader, needSwap);
                uint originalLen = ReadUInt32(reader, needSwap);

                if (capturedLen > 262144) // Sanity check — > 256KB là bất thường
                {
                    result.Error = $"Captured length quá lớn ({capturedLen} bytes) tại packet {packetId + 1}. File có thể bị corrupt.";
                    break;
                }

                if (stream.Position + capturedLen > stream.Length)
                {
                    result.Error = $"File bị cắt tại packet {packetId + 1} (cần {capturedLen} bytes, còn {stream.Length - stream.Position})";
                    break;
                }

                byte[] rawData = reader.ReadBytes((int)capturedLen);

                // Convert timestamp
                DateTime timestamp;
                if (isNanosecond)
                {
                    long ticks = (long)tsSec * TimeSpan.TicksPerSecond + (long)tsFrac / 100;
                    timestamp = DateTimeOffset.FromUnixTimeSeconds(0).AddTicks(ticks).UtcDateTime;
                }
                else
                {
                    timestamp = DateTimeOffset.FromUnixTimeSeconds(tsSec).AddMicroseconds(tsFrac).UtcDateTime;
                }

                packetId++;

                // Parse packet — sử dụng PacketParser logic nhưng từ raw bytes
                var packet = ParseFromRawBytes(packetId, timestamp, rawData, (int)originalLen);
                result.Packets.Add(packet);
                result.TotalBytes += rawData.Length;
            }
            catch (EndOfStreamException)
            {
                break;
            }
        }

        return result;
    }

    /// <summary>
    /// Parse raw Ethernet bytes thành CapturedPacket (không qua INTERMEDIATE_BUFFER)
    /// </summary>
    private static unsafe CapturedPacket ParseFromRawBytes(long id, DateTime timestamp, byte[] rawData, int originalLength)
    {
        var packet = new CapturedPacket
        {
            Id = id,
            Timestamp = timestamp,
            Direction = PacketDirection.Inbound, // Loaded from file — direction unknown
            Length = originalLength,
            RawData = rawData
        };

        if (rawData.Length < 14) return packet;

        fixed (byte* pBuf = rawData)
        {
            // Parse Ethernet
            packet = packet with
            {
                SourceMac = $"{rawData[6]:X2}:{rawData[7]:X2}:{rawData[8]:X2}:{rawData[9]:X2}:{rawData[10]:X2}:{rawData[11]:X2}",
                DestMac = $"{rawData[0]:X2}:{rawData[1]:X2}:{rawData[2]:X2}:{rawData[3]:X2}:{rawData[4]:X2}:{rawData[5]:X2}",
                EtherType = (ushort)((rawData[12] << 8) | rawData[13])
            };

            // Delegate to PacketParser for full parsing
            // Simplified — extract IP/protocol basics
            ushort etherType = packet.EtherType;
            int offset = 14;

            // 802.1Q
            if (etherType == 0x8100 && rawData.Length >= offset + 4)
            {
                etherType = (ushort)((rawData[offset + 2] << 8) | rawData[offset + 3]);
                offset += 4;
                packet = packet with { EtherType = etherType };
            }

            // LLC frame
            if (etherType < 0x0600 && rawData.Length >= offset + 3)
            {
                packet = packet with { IsLlcFrame = true };
                byte dsap = rawData[offset];
                byte ssap = rawData[offset + 1];
                if (dsap == 0x42 && ssap == 0x42)
                    packet.ApplicationProtocol = "STP";
                else if (dsap == 0xAA && ssap == 0xAA && rawData.Length >= offset + 8)
                {
                    // SNAP
                    if (rawData[offset + 3] == 0 && rawData[offset + 4] == 0 && rawData[offset + 5] == 0x0C)
                    {
                        ushort snapType = (ushort)((rawData[offset + 6] << 8) | rawData[offset + 7]);
                        if (snapType == 0x2000)
                            packet.ApplicationProtocol = "CDP";
                    }
                }
            }
            // LLDP
            else if (etherType == 0x88CC)
            {
                packet.ApplicationProtocol = "LLDP";
            }
            // IPv4
            else if (etherType == 0x0800 && rawData.Length >= offset + 20)
            {
                byte ihl = (byte)((rawData[offset] & 0x0F) * 4);
                byte protocol = rawData[offset + 9];
                byte ttl = rawData[offset + 8];

                string srcIp = $"{rawData[offset + 12]}.{rawData[offset + 13]}.{rawData[offset + 14]}.{rawData[offset + 15]}";
                string dstIp = $"{rawData[offset + 16]}.{rawData[offset + 17]}.{rawData[offset + 18]}.{rawData[offset + 19]}";

                packet = packet with
                {
                    SourceIP = srcIp,
                    DestIP = dstIp,
                    IpProtocol = protocol,
                    TTL = ttl
                };

                int transportOffset = offset + ihl;

                if (protocol == 6 && rawData.Length >= transportOffset + 20) // TCP
                {
                    ushort srcPort = (ushort)((rawData[transportOffset] << 8) | rawData[transportOffset + 1]);
                    ushort dstPort = (ushort)((rawData[transportOffset + 2] << 8) | rawData[transportOffset + 3]);
                    byte flags = rawData[transportOffset + 13];
                    packet = packet with { SourcePort = srcPort, DestPort = dstPort, TcpFlags = flags };
                }
                else if (protocol == 17 && rawData.Length >= transportOffset + 8) // UDP
                {
                    ushort srcPort = (ushort)((rawData[transportOffset] << 8) | rawData[transportOffset + 1]);
                    ushort dstPort = (ushort)((rawData[transportOffset + 2] << 8) | rawData[transportOffset + 3]);
                    packet = packet with { SourcePort = srcPort, DestPort = dstPort };
                }

                // Set application protocol
                packet.ApplicationProtocol = protocol switch
                {
                    1 => "ICMP",
                    2 => "IGMP",
                    47 => "GRE",
                    88 => "EIGRP",
                    89 => "OSPF",
                    112 => "VRRP",
                    _ => packet.ApplicationProtocol
                };
            }
            // ARP
            else if (etherType == 0x0806 && rawData.Length >= offset + 28)
            {
                packet = packet with { IpProtocol = 0 };
                packet.ApplicationProtocol = "ARP";
            }
        }

        return packet;
    }

    // ============================================================
    // Byte-order helpers
    // ============================================================

    private static ushort ReadUInt16(BinaryReader reader, bool swap)
    {
        ushort v = reader.ReadUInt16();
        return swap ? (ushort)(((v >> 8) & 0xFF) | ((v << 8) & 0xFF00)) : v;
    }

    private static int ReadInt32(BinaryReader reader, bool swap)
    {
        return (int)ReadUInt32(reader, swap);
    }

    private static uint ReadUInt32(BinaryReader reader, bool swap)
    {
        uint v = reader.ReadUInt32();
        if (!swap) return v;
        return ((v >> 24) & 0xFF) | ((v >> 8) & 0xFF00) | ((v << 8) & 0xFF0000) | ((v << 24) & 0xFF000000);
    }
}

/// <summary>
/// Kết quả đọc PCAP file
/// </summary>
public class PcapReadResult
{
    public List<CapturedPacket> Packets { get; } = new();
    public string? Error { get; set; }
    public int VersionMajor { get; set; }
    public int VersionMinor { get; set; }
    public int SnapLength { get; set; }
    public int LinkType { get; set; }
    public long TotalBytes { get; set; }
    public bool Success => Error == null && Packets.Count > 0;
}

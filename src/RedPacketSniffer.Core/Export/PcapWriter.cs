using System.Buffers.Binary;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Export;

/// <summary>
/// Xuất captured packets ra PCAP file format (libpcap)
/// Tương thích hoàn toàn với Wireshark, tshark, tcpdump, NetworkMiner
///
/// Format spec:
/// - Global Header (24 bytes): magic, version, timezone, accuracy, snaplen, linktype
/// - Per-Packet Record: timestamp (sec + usec), captured length, original length, packet data
///
/// Link-layer type: LINKTYPE_ETHERNET (1) — vì capture từ NDIS filter
/// Byte order: Little-endian (magic = 0xA1B2C3D4)
/// </summary>
public sealed class PcapWriter : IDisposable
{
    // PCAP Global Header constants
    private const uint PCAP_MAGIC = 0xA1B2C3D4;     // Little-endian
    private const ushort VERSION_MAJOR = 2;
    private const ushort VERSION_MINOR = 4;
    private const uint SNAPLEN = 65535;               // Max capture length
    private const uint LINKTYPE_ETHERNET = 1;

    private Stream? _stream;
    private BinaryWriter? _writer;
    private int _packetCount;
    private readonly object _writeLock = new();

    /// <summary>
    /// Tạo PCAP file mới
    /// </summary>
    public void Open(string filePath)
    {
        _stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.Read, 65536);
        _writer = new BinaryWriter(_stream);
        _packetCount = 0;
        WriteGlobalHeader();
    }

    /// <summary>
    /// Tạo PCAP trên memory stream (cho download qua HTTP)
    /// </summary>
    public MemoryStream CreateInMemory()
    {
        var ms = new MemoryStream();
        _stream = ms;
        _writer = new BinaryWriter(ms, System.Text.Encoding.UTF8, leaveOpen: true);
        _packetCount = 0;
        WriteGlobalHeader();
        return ms;
    }

    /// <summary>
    /// Ghi global header — phải gọi trước khi write packet
    /// </summary>
    private void WriteGlobalHeader()
    {
        if (_writer == null) throw new InvalidOperationException("Stream not opened");

        _writer.Write(PCAP_MAGIC);           // Magic number
        _writer.Write(VERSION_MAJOR);         // Version major
        _writer.Write(VERSION_MINOR);         // Version minor
        _writer.Write((int)0);                // Timezone offset (GMT)
        _writer.Write((uint)0);               // Timestamp accuracy
        _writer.Write(SNAPLEN);               // Snap length
        _writer.Write(LINKTYPE_ETHERNET);     // Link-layer type
    }

    /// <summary>
    /// Ghi 1 packet vào PCAP
    /// </summary>
    public void WritePacket(CapturedPacket packet)
    {
        if (_writer == null) throw new InvalidOperationException("Stream not opened");
        if (packet.RawData.Length == 0) return;

        lock (_writeLock)
        {
            // Timestamp → seconds + microseconds since Unix epoch
            long unixMs = new DateTimeOffset(packet.Timestamp).ToUnixTimeMilliseconds();
            uint tsSec = (uint)(unixMs / 1000);
            uint tsUsec = (uint)((unixMs % 1000) * 1000);

            // Packet record header (16 bytes)
            _writer.Write(tsSec);                          // Timestamp seconds
            _writer.Write(tsUsec);                         // Timestamp microseconds
            _writer.Write((uint)packet.RawData.Length);    // Captured length
            _writer.Write((uint)packet.RawData.Length);    // Original length

            // Packet data (raw Ethernet frame)
            _writer.Write(packet.RawData);

            _packetCount++;
        }
    }

    /// <summary>
    /// Ghi danh sách packet
    /// </summary>
    public void WritePackets(IReadOnlyList<CapturedPacket> packets)
    {
        foreach (var packet in packets)
        {
            WritePacket(packet);
        }
    }

    /// <summary>
    /// Xuất tất cả packets ra byte array (PCAP format)
    /// </summary>
    public static byte[] ExportToBytes(IReadOnlyList<CapturedPacket> packets)
    {
        using var writer = new PcapWriter();
        var ms = writer.CreateInMemory();
        writer.WritePackets(packets);
        writer.Flush();
        return ms.ToArray();
    }

    /// <summary>
    /// Xuất ra file
    /// </summary>
    public static int ExportToFile(string filePath, IReadOnlyList<CapturedPacket> packets)
    {
        using var writer = new PcapWriter();
        writer.Open(filePath);
        writer.WritePackets(packets);
        return packets.Count;
    }

    public int PacketCount => _packetCount;

    public void Flush()
    {
        lock (_writeLock)
        {
            _writer?.Flush();
            _stream?.Flush();
        }
    }

    public void Dispose()
    {
        _writer?.Dispose();
        // Không dispose _stream nếu là MemoryStream (leaveOpen)
        if (_stream is FileStream fs)
            fs.Dispose();
    }
}

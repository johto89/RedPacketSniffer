using System.Net;
using System.Text;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// Phân tích DNS traffic — trích xuất queries và responses
///
/// DNS packet structure (after UDP header):
/// - Transaction ID (2 bytes)
/// - Flags (2 bytes): QR(1), Opcode(4), AA(1), TC(1), RD(1), RA(1), Z(3), RCODE(4)
/// - Question Count (2 bytes)
/// - Answer Count (2 bytes)
/// - Authority Count (2 bytes)
/// - Additional Count (2 bytes)
/// - Questions section
/// - Answers section (in responses)
///
/// Hữu ích cho red team:
/// - Recon: xem domain nào đang resolve (target enumeration)
/// - Detect DNS tunneling (unusual query types, long subdomain names)
/// - Detect internal domain names (leak information)
/// - Track C2 callbacks (periodic DNS queries to suspicious domains)
/// </summary>
public sealed class DnsAnalyzer
{
    private readonly List<DnsRecord> _records = new();
    private readonly object _lock = new();
    private readonly Dictionary<string, int> _queryCount = new(); // domain -> count

    public event Action<DnsRecord>? OnDnsRecord;

    /// <summary>
    /// Phân tích packet cho DNS traffic
    /// </summary>
    public void Analyze(CapturedPacket packet)
    {
        // DNS = UDP port 53 (hoặc TCP port 53 cho large responses)
        if (packet.IpProtocol != 17 && packet.IpProtocol != 6) return;
        if (packet.SourcePort != 53 && packet.DestPort != 53) return;
        if (packet.RawData.Length == 0) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 12) return; // DNS header minimum

        try
        {
            ParseDns(payload, packet);
        }
        catch
        {
            // Skip malformed DNS
        }
    }

    private void ParseDns(ReadOnlySpan<byte> data, CapturedPacket packet)
    {
        // DNS Header
        ushort transactionId = (ushort)((data[0] << 8) | data[1]);
        ushort flags = (ushort)((data[2] << 8) | data[3]);
        bool isResponse = (flags & 0x8000) != 0;
        byte opcode = (byte)((flags >> 11) & 0x0F);
        byte rcode = (byte)(flags & 0x0F);
        ushort qdCount = (ushort)((data[4] << 8) | data[5]);
        ushort anCount = (ushort)((data[6] << 8) | data[7]);

        int offset = 12; // After header

        // Parse question section
        string queryName = "";
        ushort queryType = 0;
        ushort queryClass = 0;

        if (qdCount > 0 && offset < data.Length)
        {
            queryName = ReadDnsName(data, ref offset);
            if (offset + 4 <= data.Length)
            {
                queryType = (ushort)((data[offset] << 8) | data[offset + 1]);
                queryClass = (ushort)((data[offset + 2] << 8) | data[offset + 3]);
                offset += 4;
            }
        }

        if (string.IsNullOrEmpty(queryName)) return;

        var record = new DnsRecord
        {
            Timestamp = packet.Timestamp,
            PacketId = packet.Id,
            TransactionId = transactionId,
            IsResponse = isResponse,
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            QueryName = queryName,
            QueryType = queryType,
            QueryTypeStr = GetDnsTypeStr(queryType),
            ResponseCode = rcode,
            ResponseCodeStr = GetRcodeStr(rcode)
        };

        // Parse answers nếu là response
        if (isResponse && anCount > 0)
        {
            var answers = new List<string>();
            for (int i = 0; i < anCount && offset < data.Length - 10; i++)
            {
                try
                {
                    // Name (có thể là pointer)
                    string ansName = ReadDnsName(data, ref offset);
                    if (offset + 10 > data.Length) break;

                    ushort aType = (ushort)((data[offset] << 8) | data[offset + 1]);
                    ushort aClass = (ushort)((data[offset + 2] << 8) | data[offset + 3]);
                    uint ttl = (uint)((data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7]);
                    ushort rdLength = (ushort)((data[offset + 8] << 8) | data[offset + 9]);
                    offset += 10;

                    if (offset + rdLength > data.Length) break;

                    string answerStr = aType switch
                    {
                        1 when rdLength == 4 => // A record
                            new IPAddress(data.Slice(offset, 4)).ToString(),
                        28 when rdLength == 16 => // AAAA record
                            new IPAddress(data.Slice(offset, 16)).ToString(),
                        5 or 2 or 12 or 15 => // CNAME, NS, PTR, MX
                            ReadDnsName(data, ref offset) is string n ? n : "",
                        _ => $"[{GetDnsTypeStr(aType)} len={rdLength}]"
                    };

                    if (aType != 5 && aType != 2 && aType != 12 && aType != 15)
                        offset += rdLength;

                    if (!string.IsNullOrEmpty(answerStr))
                        answers.Add($"{GetDnsTypeStr(aType)}:{answerStr} (TTL:{ttl})");
                }
                catch { break; }
            }
            record.Answers = answers;
        }

        // Detect anomalies
        DetectAnomalies(record);

        // Track query frequency
        string domainKey = queryName.ToLowerInvariant();
        lock (_lock)
        {
            _queryCount[domainKey] = _queryCount.GetValueOrDefault(domainKey) + 1;
            record.QueryFrequency = _queryCount[domainKey];
            _records.Add(record);
        }

        OnDnsRecord?.Invoke(record);
    }

    private void DetectAnomalies(DnsRecord record)
    {
        var flags = new List<string>();

        // Long subdomain names — potential DNS tunneling
        string[] labels = record.QueryName.Split('.');
        if (labels.Any(l => l.Length > 40))
            flags.Add("TUNNEL_SUSPECT: subdomain label > 40 chars");
        if (record.QueryName.Length > 150)
            flags.Add("TUNNEL_SUSPECT: total name > 150 chars");

        // TXT queries — often used for DNS tunneling / C2
        if (record.QueryType == 16) // TXT
            flags.Add("TXT_QUERY: commonly used for DNS tunneling/C2");

        // Unusual record types
        if (record.QueryType == 10 || record.QueryType == 99) // NULL or SPF
            flags.Add("UNUSUAL_TYPE: rare query type");

        // High entropy subdomain — possible data exfiltration
        if (labels.Length > 0 && CalculateEntropy(labels[0]) > 4.0 && labels[0].Length > 15)
            flags.Add("HIGH_ENTROPY: possible data exfiltration via DNS");

        // NXDOMAIN responses — could be DGA domain
        if (record.IsResponse && record.ResponseCode == 3)
            flags.Add("NXDOMAIN: domain does not exist");

        record.AnomalyFlags = flags;
    }

    private static double CalculateEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        var freq = new Dictionary<char, int>();
        foreach (char c in s)
            freq[c] = freq.GetValueOrDefault(c) + 1;
        double entropy = 0;
        foreach (var count in freq.Values)
        {
            double p = (double)count / s.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>
    /// Đọc DNS name (hỗ trợ compression pointers)
    /// </summary>
    private static string ReadDnsName(ReadOnlySpan<byte> data, ref int offset)
    {
        var parts = new List<string>();
        int maxJumps = 10; // Tránh infinite loop
        int jumps = 0;
        bool jumped = false;
        int savedOffset = -1;

        while (offset < data.Length && jumps < maxJumps)
        {
            byte len = data[offset];

            if (len == 0)
            {
                offset++;
                break;
            }

            // Compression pointer: 2 high bits = 11
            if ((len & 0xC0) == 0xC0)
            {
                if (offset + 1 >= data.Length) break;
                if (!jumped) savedOffset = offset + 2;
                offset = ((len & 0x3F) << 8) | data[offset + 1];
                jumped = true;
                jumps++;
                continue;
            }

            offset++;
            if (offset + len > data.Length) break;

            parts.Add(Encoding.ASCII.GetString(data.Slice(offset, len)));
            offset += len;
        }

        if (jumped && savedOffset >= 0)
            offset = savedOffset;

        return string.Join(".", parts);
    }

    public List<DnsRecord> GetAllRecords()
    {
        lock (_lock) { return new List<DnsRecord>(_records); }
    }

    public Dictionary<string, int> GetTopDomains(int count = 20)
    {
        lock (_lock)
        {
            return _queryCount
                .OrderByDescending(kv => kv.Value)
                .Take(count)
                .ToDictionary(kv => kv.Key, kv => kv.Value);
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _records.Clear();
            _queryCount.Clear();
        }
    }

    private static string GetDnsTypeStr(ushort type) => type switch
    {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA",
        12 => "PTR", 15 => "MX", 16 => "TXT", 28 => "AAAA",
        33 => "SRV", 35 => "NAPTR", 43 => "DS", 46 => "RRSIG",
        47 => "NSEC", 48 => "DNSKEY", 52 => "TLSA", 65 => "HTTPS",
        255 => "ANY", 257 => "CAA",
        _ => $"TYPE{type}"
    };

    private static string GetRcodeStr(byte rcode) => rcode switch
    {
        0 => "NOERROR", 1 => "FORMERR", 2 => "SERVFAIL",
        3 => "NXDOMAIN", 4 => "NOTIMP", 5 => "REFUSED",
        _ => $"RCODE{rcode}"
    };
}

/// <summary>
/// DNS record (query hoặc response)
/// </summary>
public class DnsRecord
{
    public DateTime Timestamp { get; init; }
    public long PacketId { get; init; }
    public ushort TransactionId { get; init; }
    public bool IsResponse { get; init; }
    public string SourceIP { get; init; } = "";
    public string DestIP { get; init; } = "";
    public string QueryName { get; init; } = "";
    public ushort QueryType { get; init; }
    public string QueryTypeStr { get; init; } = "";
    public byte ResponseCode { get; set; }
    public string ResponseCodeStr { get; set; } = "";
    public List<string> Answers { get; set; } = new();
    public List<string> AnomalyFlags { get; set; } = new();
    public int QueryFrequency { get; set; }
}

using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// Track TCP connections — state machine cho mỗi TCP session
///
/// TCP State transitions tracked:
///   SYN → SYN_SENT
///   SYN+ACK → SYN_RECEIVED (3-way handshake in progress)
///   ACK (after SYN+ACK) → ESTABLISHED
///   FIN → FIN_WAIT / CLOSE_WAIT
///   FIN+ACK (both sides) → CLOSED
///   RST → RESET
///
/// Hữu ích cho red team:
/// - Detect port scanning (nhiều SYN không có ACK)
/// - Detect C2 beaconing (periodic connections tới cùng IP:Port)
/// - Track lateral movement (internal → internal connections)
/// - Detect half-open connections (SYN flood)
/// - Identify long-lived connections (tunneling, persistent C2)
/// </summary>
public sealed class TcpConnectionTracker
{
    private readonly Dictionary<string, TcpConnection> _connections = new();
    private readonly object _lock = new();
    private long _connectionIdCounter;

    // Anomaly detection
    private readonly Dictionary<string, int> _synCountBySource = new(); // source IP → SYN count
    private readonly Dictionary<string, List<DateTime>> _connectionTimes = new(); // dest key → timestamps

    public event Action<TcpConnection>? OnConnectionUpdated;

    /// <summary>
    /// Phân tích packet cho TCP connection tracking
    /// </summary>
    public void Analyze(CapturedPacket packet)
    {
        if (packet.IpProtocol != 6) return; // TCP only
        if (packet.SourceIP == null || packet.DestIP == null) return;
        if (packet.SourcePort == 0 && packet.DestPort == 0) return;

        byte flags = packet.TcpFlags;
        bool syn = (flags & 0x02) != 0;
        bool ack = (flags & 0x10) != 0;
        bool fin = (flags & 0x01) != 0;
        bool rst = (flags & 0x04) != 0;

        // Connection key: luôn sort IP:Port để cả 2 hướng cùng 1 key
        string key = MakeKey(packet.SourceIP, packet.SourcePort, packet.DestIP, packet.DestPort);

        lock (_lock)
        {
            if (!_connections.TryGetValue(key, out var conn))
            {
                // Chỉ tạo connection mới khi thấy SYN (không phải SYN+ACK)
                if (!syn || ack) return;

                conn = new TcpConnection
                {
                    Id = Interlocked.Increment(ref _connectionIdCounter),
                    Key = key,
                    ClientIP = packet.SourceIP,
                    ClientPort = packet.SourcePort,
                    ServerIP = packet.DestIP,
                    ServerPort = packet.DestPort,
                    State = TcpState.SynSent,
                    StartTime = packet.Timestamp,
                    LastActivity = packet.Timestamp,
                    PacketCount = 1,
                    BytesTransferred = packet.Length
                };

                _connections[key] = conn;

                // Track SYN count per source (scan detection)
                string srcKey = packet.SourceIP;
                _synCountBySource[srcKey] = _synCountBySource.GetValueOrDefault(srcKey) + 1;

                // Track connection timing (beacon detection)
                string destKey = $"{packet.DestIP}:{packet.DestPort}";
                if (!_connectionTimes.ContainsKey(destKey))
                    _connectionTimes[destKey] = new List<DateTime>();
                _connectionTimes[destKey].Add(packet.Timestamp);

                DetectAnomalies(conn);
                OnConnectionUpdated?.Invoke(conn);
                return;
            }

            // Update existing connection
            conn.LastActivity = packet.Timestamp;
            conn.PacketCount++;
            conn.BytesTransferred += packet.Length;

            // Track bytes per direction
            if (packet.SourceIP == conn.ClientIP && packet.SourcePort == conn.ClientPort)
                conn.ClientBytes += packet.Length;
            else
                conn.ServerBytes += packet.Length;

            // State machine transitions
            var prevState = conn.State;

            if (rst)
            {
                conn.State = TcpState.Reset;
                conn.EndTime = packet.Timestamp;
            }
            else if (syn && ack && conn.State == TcpState.SynSent)
            {
                conn.State = TcpState.SynReceived;
            }
            else if (ack && !syn && !fin && conn.State == TcpState.SynReceived)
            {
                conn.State = TcpState.Established;
            }
            else if (fin)
            {
                if (conn.State == TcpState.Established)
                {
                    conn.State = TcpState.FinWait;
                    conn.FinInitiator = packet.SourceIP;
                }
                else if (conn.State == TcpState.FinWait)
                {
                    // Second FIN — closing
                    conn.State = TcpState.Closing;
                }
            }
            else if (ack && conn.State == TcpState.Closing)
            {
                conn.State = TcpState.Closed;
                conn.EndTime = packet.Timestamp;
            }

            if (conn.State != prevState)
            {
                DetectAnomalies(conn);
            }

            OnConnectionUpdated?.Invoke(conn);
        }
    }

    private void DetectAnomalies(TcpConnection conn)
    {
        var flags = new List<string>();

        // Port scan detection: source có quá nhiều SYN
        if (_synCountBySource.TryGetValue(conn.ClientIP, out int synCount) && synCount > 20)
        {
            flags.Add($"PORT_SCAN: {synCount} SYN packets from {conn.ClientIP}");
        }

        // Half-open detection: SYN_SENT quá lâu không established
        if (conn.State == TcpState.SynSent)
        {
            var elapsed = conn.LastActivity - conn.StartTime;
            if (elapsed.TotalSeconds > 5)
                flags.Add("HALF_OPEN: SYN without response > 5s");
        }

        // Long-lived connection (>30 min established)
        if (conn.State == TcpState.Established)
        {
            var duration = conn.LastActivity - conn.StartTime;
            if (duration.TotalMinutes > 30)
                flags.Add($"LONG_LIVED: connection active {duration.TotalMinutes:F0}min");
        }

        // Beacon detection: periodic connections to same dest
        string destKey = $"{conn.ServerIP}:{conn.ServerPort}";
        if (_connectionTimes.TryGetValue(destKey, out var times) && times.Count >= 5)
        {
            // Tính interval trung bình giữa các connection
            var intervals = new List<double>();
            for (int i = 1; i < times.Count; i++)
                intervals.Add((times[i] - times[i - 1]).TotalSeconds);

            double avgInterval = intervals.Average();
            double stdDev = Math.Sqrt(intervals.Average(v => Math.Pow(v - avgInterval, 2)));

            // Nếu std deviation thấp → periodic → beacon suspect
            if (avgInterval > 0 && stdDev / avgInterval < 0.3)
            {
                flags.Add($"BEACON_SUSPECT: {times.Count} connections, avg interval {avgInterval:F1}s (std {stdDev:F1}s)");
            }
        }

        // Internal→Internal lateral movement
        if (IsPrivateIP(conn.ClientIP) && IsPrivateIP(conn.ServerIP))
        {
            // Suspicious ports cho lateral movement
            if (conn.ServerPort is 445 or 135 or 139 or 3389 or 5985 or 5986 or 22)
            {
                flags.Add($"LATERAL_MOVE: internal→internal on port {conn.ServerPort}");
            }
        }

        conn.AnomalyFlags = flags;
    }

    private static bool IsPrivateIP(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return false;
        return ip.StartsWith("10.") ||
               ip.StartsWith("172.16.") || ip.StartsWith("172.17.") || ip.StartsWith("172.18.") ||
               ip.StartsWith("172.19.") || ip.StartsWith("172.20.") || ip.StartsWith("172.21.") ||
               ip.StartsWith("172.22.") || ip.StartsWith("172.23.") || ip.StartsWith("172.24.") ||
               ip.StartsWith("172.25.") || ip.StartsWith("172.26.") || ip.StartsWith("172.27.") ||
               ip.StartsWith("172.28.") || ip.StartsWith("172.29.") || ip.StartsWith("172.30.") ||
               ip.StartsWith("172.31.") ||
               ip.StartsWith("192.168.");
    }

    private static string MakeKey(string ip1, ushort port1, string ip2, ushort port2)
    {
        string a = $"{ip1}:{port1}";
        string b = $"{ip2}:{port2}";
        return string.CompareOrdinal(a, b) < 0 ? $"{a}<>{b}" : $"{b}<>{a}";
    }

    public List<TcpConnection> GetAllConnections()
    {
        lock (_lock)
        {
            return _connections.Values.ToList();
        }
    }

    public List<TcpConnection> GetActiveConnections()
    {
        lock (_lock)
        {
            return _connections.Values
                .Where(c => c.State == TcpState.Established || c.State == TcpState.SynSent || c.State == TcpState.SynReceived)
                .OrderByDescending(c => c.LastActivity)
                .ToList();
        }
    }

    public Dictionary<TcpState, int> GetStateSummary()
    {
        lock (_lock)
        {
            return _connections.Values
                .GroupBy(c => c.State)
                .ToDictionary(g => g.Key, g => g.Count());
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _connections.Clear();
            _synCountBySource.Clear();
            _connectionTimes.Clear();
        }
    }
}

public enum TcpState
{
    SynSent,
    SynReceived,
    Established,
    FinWait,
    Closing,
    Closed,
    Reset
}

public class TcpConnection
{
    public long Id { get; init; }
    public string Key { get; init; } = "";
    public string ClientIP { get; init; } = "";
    public ushort ClientPort { get; init; }
    public string ServerIP { get; init; } = "";
    public ushort ServerPort { get; init; }
    public TcpState State { get; set; }
    public string StateStr => State.ToString();
    public DateTime StartTime { get; init; }
    public DateTime LastActivity { get; set; }
    public DateTime? EndTime { get; set; }
    public int PacketCount { get; set; }
    public long BytesTransferred { get; set; }
    public long ClientBytes { get; set; }
    public long ServerBytes { get; set; }
    public string? FinInitiator { get; set; }
    public List<string> AnomalyFlags { get; set; } = new();

    public double DurationSeconds => EndTime.HasValue
        ? (EndTime.Value - StartTime).TotalSeconds
        : (LastActivity - StartTime).TotalSeconds;
}

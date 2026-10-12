using RedPacketSniffer.Core.Analysis;
using RedPacketSniffer.Core.Capture;
using RedPacketSniffer.Core.Export;

namespace RedPacketSniffer.Services;

/// <summary>
/// Singleton service quan ly PacketCaptureEngine — bridge giua Core engine va Web layer
/// Tich hop CredentialExtractor + ProtocolWeaknessDetector real-time
/// </summary>
public sealed class CaptureService : IDisposable
{
    private readonly PacketCaptureEngine _engine = new();
    private readonly ILogger<CaptureService> _logger;
    private readonly List<CapturedPacket> _capturedPackets = new();
    private readonly ReaderWriterLockSlim _lock = new();
    private const int MAX_BUFFER_SIZE = 50000; // Giu toi da 50K packet trong memory

    // Analysis engines
    private readonly CredentialExtractor _credentialExtractor = new();
    private readonly ProtocolWeaknessDetector _weaknessDetector = new();
    private readonly DnsAnalyzer _dnsAnalyzer = new();
    private readonly TcpConnectionTracker _tcpTracker = new();
    private readonly HttpRequestLogger _httpLogger = new();
    private readonly NetworkHostTracker _hostTracker = new();
    private readonly L2L3ProtocolAnalyzer _l2l3Analyzer = new();
    private readonly VoipAnalyzer _voipAnalyzer = new();
    private ArpSpoofer? _arpSpoofer;
    private VlanHopper? _vlanHopper;

    public event Action<CapturedPacket>? OnPacketCaptured;
    public event Action<ExtractedCredential>? OnCredentialFound;
    public event Action<DetectedWeakness>? OnWeaknessDetected;
    public event Action<DnsRecord>? OnDnsRecord;
    public event Action<TcpConnection>? OnTcpConnectionUpdated;
    public event Action<HttpLogEntry>? OnHttpEntry;
    public event Action<NetworkHost>? OnHostUpdated;
    public event Action<L2L3Finding>? OnL2L3Finding;
    public event Action<VoipFinding>? OnVoipFinding;
    public event Action<string>? OnError;
    public event Action<CaptureState>? OnStateChanged;

    public CaptureService(ILogger<CaptureService> logger)
    {
        _logger = logger;
        _engine.OnPacketCaptured += HandlePacket;
        _engine.OnError += err =>
        {
            _logger.LogError("Capture error: {Error}", err);
            OnError?.Invoke(err);
        };
        _engine.OnStateChanged += state => OnStateChanged?.Invoke(state);

        // Forward analysis events
        _credentialExtractor.OnCredentialFound += cred =>
        {
            _logger.LogWarning("Credential found: {Protocol} {User}@{Host}", cred.Protocol, cred.Username, cred.Host);
            OnCredentialFound?.Invoke(cred);
        };
        _weaknessDetector.OnWeaknessDetected += weakness =>
        {
            _logger.LogWarning("Weakness detected: [{Severity}] {Name}", weakness.SeverityStr, weakness.Name);
            OnWeaknessDetected?.Invoke(weakness);
        };
        _dnsAnalyzer.OnDnsRecord += record =>
        {
            OnDnsRecord?.Invoke(record);
        };
        _tcpTracker.OnConnectionUpdated += conn =>
        {
            OnTcpConnectionUpdated?.Invoke(conn);
        };
        _httpLogger.OnHttpEntry += entry =>
        {
            OnHttpEntry?.Invoke(entry);
        };
        _hostTracker.OnHostUpdated += host =>
        {
            OnHostUpdated?.Invoke(host);
        };
        _l2l3Analyzer.OnFinding += finding =>
        {
            OnL2L3Finding?.Invoke(finding);
        };
        _voipAnalyzer.OnFinding += finding =>
        {
            _logger.LogWarning("VoIP finding: [{Severity}] {Title}", finding.Severity, finding.Title);
            OnVoipFinding?.Invoke(finding);
        };
        _voipAnalyzer.OnCredentialFound += cred =>
        {
            _logger.LogWarning("SIP credential: {User}@{Realm}", cred.Username, cred.Realm);
        };
    }

    public CaptureState State => _engine.State;
    public long TotalPackets => _engine.TotalPackets;
    public long FilteredPackets => _engine.FilteredPackets;
    public long TotalBytes => _engine.TotalBytes;
    public TimeSpan CaptureElapsed => _engine.CaptureElapsed;

    public DriverInfo Open()
    {
        var info = _engine.Open();
        _logger.LogInformation("WinpkFilter driver opened, version: {Version}", info.Version);
        return info;
    }

    public List<AdapterInfo> GetAdapters()
    {
        var adapters = _engine.GetAdapters();
        _logger.LogInformation("Found {Count} adapters", adapters.Count);
        return adapters;
    }

    public void SelectAdapter(int index)
    {
        _engine.SelectAdapter(index);
        _logger.LogInformation("Selected adapter index: {Index}", index);
    }

    public void SetFilter(CaptureFilter filter)
    {
        _engine.SetFilter(filter);
    }

    public void StartCapture()
    {
        ClearBuffer();
        _credentialExtractor.Clear();
        _weaknessDetector.Clear();
        _dnsAnalyzer.Clear();
        _tcpTracker.Clear();
        _httpLogger.Clear();
        _hostTracker.Clear();
        _l2l3Analyzer.Clear();
        _voipAnalyzer.Clear();
        _engine.StartCapture();
        _logger.LogInformation("Capture started");
    }

    public async Task StopCaptureAsync()
    {
        await _engine.StopCaptureAsync();
        _logger.LogInformation("Capture stopped. Total: {Total}, Filtered: {Filtered}, Creds: {Creds}, Weaknesses: {Weak}",
            TotalPackets, FilteredPackets,
            _credentialExtractor.GetAllCredentials().Count,
            _weaknessDetector.GetAllWeaknesses().Count);
    }

    /// <summary>
    /// Lay N packet gan nhat tu buffer
    /// </summary>
    public List<CapturedPacket> GetRecentPackets(int count = 100, int offset = 0)
    {
        _lock.EnterReadLock();
        try
        {
            int start = Math.Max(0, _capturedPackets.Count - count - offset);
            int take = Math.Min(count, _capturedPackets.Count - start);
            return _capturedPackets.GetRange(start, take);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    /// Lay tat ca packet trong buffer (cho export)
    /// </summary>
    public List<CapturedPacket> GetAllPackets()
    {
        _lock.EnterReadLock();
        try
        {
            return new List<CapturedPacket>(_capturedPackets);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    /// Lay credentials da trich xuat
    /// </summary>
    public List<ExtractedCredential> GetCredentials() => _credentialExtractor.GetAllCredentials();

    /// <summary>
    /// Lay weaknesses da phat hien
    /// </summary>
    public List<DetectedWeakness> GetWeaknesses() => _weaknessDetector.GetAllWeaknesses();

    /// <summary>
    /// Lay weakness summary theo category
    /// </summary>
    public Dictionary<string, int> GetWeaknessSummary() => _weaknessDetector.GetWeaknessSummary();

    /// <summary>
    /// Lay DNS records
    /// </summary>
    public List<DnsRecord> GetDnsRecords() => _dnsAnalyzer.GetAllRecords();

    /// <summary>
    /// Lay top domains theo query count
    /// </summary>
    public Dictionary<string, int> GetTopDomains(int count = 20) => _dnsAnalyzer.GetTopDomains(count);

    /// <summary>
    /// Lay tat ca TCP connections
    /// </summary>
    public List<TcpConnection> GetTcpConnections() => _tcpTracker.GetAllConnections();

    /// <summary>
    /// Lay active TCP connections
    /// </summary>
    public List<TcpConnection> GetActiveTcpConnections() => _tcpTracker.GetActiveConnections();

    /// <summary>
    /// Lay HTTP log entries
    /// </summary>
    public List<HttpLogEntry> GetHttpEntries() => _httpLogger.GetAllEntries();

    /// <summary>
    /// Lay top HTTP hosts
    /// </summary>
    public Dictionary<string, int> GetTopHosts(int count = 20) => _httpLogger.GetTopHosts(count);

    /// <summary>
    /// Lay discovered network hosts
    /// </summary>
    public List<NetworkHost> GetNetworkHosts() => _hostTracker.GetAllHosts();

    /// <summary>
    /// Lay network summary
    /// </summary>
    public NetworkSummary GetNetworkSummary() => _hostTracker.GetSummary();

    /// <summary>
    /// Lay L2/L3 protocol findings
    /// </summary>
    public List<L2L3Finding> GetL2L3Findings() => _l2l3Analyzer.GetAllFindings();

    /// <summary>
    /// Lay L2/L3 summary
    /// </summary>
    public L2L3Summary GetL2L3Summary() => _l2l3Analyzer.GetSummary();

    /// <summary>
    /// Lay OSPF routers
    /// </summary>
    public List<OspfRouterInfo> GetOspfRouters() => _l2l3Analyzer.GetOspfRouters();

    /// <summary>
    /// Lay CDP devices
    /// </summary>
    public List<CdpDeviceInfo> GetCdpDevices() => _l2l3Analyzer.GetCdpDevices();

    /// <summary>
    /// Lay HSRP groups
    /// </summary>
    public List<HsrpGroupInfo> GetHsrpGroups() => _l2l3Analyzer.GetHsrpGroups();

    // === VoIP ===
    public List<VoipFinding> GetVoipFindings() => _voipAnalyzer.GetSummary().TotalCredentials > 0 || _voipAnalyzer.GetSummary().TotalCalls > 0
        ? new List<VoipFinding>() : new(); // Findings come via event
    public List<SipCredential> GetSipCredentials() => _voipAnalyzer.GetCredentials();
    public List<SipCall> GetSipCalls() => _voipAnalyzer.GetCalls();
    public List<RtpStream> GetRtpStreams() => _voipAnalyzer.GetRtpStreams();
    public List<StunBinding> GetStunBindings() => _voipAnalyzer.GetStunBindings();
    public VoipSummary GetVoipSummary() => _voipAnalyzer.GetSummary();

    // === ARP Spoofer ===
    public ArpSpoofer GetOrCreateArpSpoofer()
    {
        if (_arpSpoofer == null)
        {
            _arpSpoofer = new ArpSpoofer(_engine);
            _arpSpoofer.OnLog += msg => _logger.LogInformation("ArpSpoof: {Msg}", msg);
        }
        return _arpSpoofer;
    }

    public ArpSpoofStatus? GetArpSpoofStatus() => _arpSpoofer?.GetStatus();

    // === VLAN Hopper ===
    public VlanHopper GetOrCreateVlanHopper()
    {
        if (_vlanHopper == null)
        {
            _vlanHopper = new VlanHopper(_engine);
            _vlanHopper.OnLog += msg => _logger.LogInformation("VlanHop: {Msg}", msg);
        }
        return _vlanHopper;
    }

    public VlanHopStatusInfo? GetVlanHopStatus() => _vlanHopper?.GetStatus();

    /// <summary>
    /// Export PCAP file bytes
    /// </summary>
    public byte[] ExportPcap()
    {
        var packets = GetAllPackets();
        return PcapWriter.ExportToBytes(packets);
    }

    /// <summary>
    /// Generate report data
    /// </summary>
    public ReportData GenerateReport()
    {
        var packets = GetAllPackets();
        var creds = GetCredentials();
        var weaknesses = GetWeaknesses();
        return ReportGenerator.GenerateData(packets, creds, weaknesses, CaptureElapsed);
    }

    public CaptureStats GetStats()
    {
        return new CaptureStats
        {
            State = State.ToString(),
            TotalPackets = TotalPackets,
            FilteredPackets = FilteredPackets,
            TotalBytes = TotalBytes,
            BufferSize = GetBufferCount(),
            ElapsedSeconds = (int)CaptureElapsed.TotalSeconds,
            PacketsPerSecond = CaptureElapsed.TotalSeconds > 0
                ? (long)(FilteredPackets / CaptureElapsed.TotalSeconds)
                : 0,
            CredentialsFound = _credentialExtractor.GetAllCredentials().Count,
            WeaknessesDetected = _weaknessDetector.GetAllWeaknesses().Count,
            DnsQueries = _dnsAnalyzer.GetAllRecords().Count,
            TcpConnections = _tcpTracker.GetAllConnections().Count,
            HttpRequests = _httpLogger.GetAllEntries().Count,
            NetworkHosts = _hostTracker.GetAllHosts().Count,
            L2L3Findings = _l2l3Analyzer.GetAllFindings().Count,
            VoipCreds = _voipAnalyzer.GetCredentials().Count,
            VoipCalls = _voipAnalyzer.GetCalls().Count,
            RtpStreams = _voipAnalyzer.GetRtpStreams().Count,
            ArpSpoofState = _arpSpoofer?.State.ToString() ?? "Idle",
            ArpSpoofPackets = _arpSpoofer?.PacketsSent ?? 0,
            VlanHopState = _vlanHopper?.State.ToString() ?? "Idle",
            VlanHopMethod = _vlanHopper?.ActiveMethod.ToString() ?? "None",
            VlanHopDtpDetected = _vlanHopper?.DtpDetected ?? false
        };
    }

    private void HandlePacket(CapturedPacket packet)
    {
        // Buffer packet
        _lock.EnterWriteLock();
        try
        {
            _capturedPackets.Add(packet);
            // Evict oldest khi buffer full
            if (_capturedPackets.Count > MAX_BUFFER_SIZE)
            {
                _capturedPackets.RemoveRange(0, _capturedPackets.Count - MAX_BUFFER_SIZE);
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }

        // Run analysis on every packet
        _credentialExtractor.Analyze(packet);
        _weaknessDetector.Analyze(packet);
        _dnsAnalyzer.Analyze(packet);
        _tcpTracker.Analyze(packet);
        _httpLogger.Analyze(packet);
        _hostTracker.Analyze(packet);
        _l2l3Analyzer.Analyze(packet);
        _voipAnalyzer.Analyze(packet);
        _vlanHopper?.AnalyzePacket(packet);

        OnPacketCaptured?.Invoke(packet);
    }

    private int GetBufferCount()
    {
        _lock.EnterReadLock();
        try { return _capturedPackets.Count; }
        finally { _lock.ExitReadLock(); }
    }

    private void ClearBuffer()
    {
        _lock.EnterWriteLock();
        try { _capturedPackets.Clear(); }
        finally { _lock.ExitWriteLock(); }
    }

    public void Dispose()
    {
        _engine.OnPacketCaptured -= HandlePacket;
        _arpSpoofer?.Dispose();
        _vlanHopper?.Dispose();
        _engine.Dispose();
        _lock.Dispose();
    }
}

public class CaptureStats
{
    public string State { get; init; } = "";
    public long TotalPackets { get; init; }
    public long FilteredPackets { get; init; }
    public long TotalBytes { get; init; }
    public int BufferSize { get; init; }
    public int ElapsedSeconds { get; init; }
    public long PacketsPerSecond { get; init; }
    public int CredentialsFound { get; init; }
    public int WeaknessesDetected { get; init; }
    public int DnsQueries { get; init; }
    public int TcpConnections { get; init; }
    public int HttpRequests { get; init; }
    public int NetworkHosts { get; init; }
    public int L2L3Findings { get; init; }
    public int VoipCreds { get; init; }
    public int VoipCalls { get; init; }
    public int RtpStreams { get; init; }
    public string ArpSpoofState { get; init; } = "Idle";
    public int ArpSpoofPackets { get; init; }
    public string VlanHopState { get; init; } = "Idle";
    public string VlanHopMethod { get; init; } = "None";
    public bool VlanHopDtpDetected { get; init; }
}

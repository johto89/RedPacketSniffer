using Microsoft.AspNetCore.SignalR;
using RedPacketSniffer.Core.Analysis;
using RedPacketSniffer.Core.Capture;
using RedPacketSniffer.Core.Export;
using RedPacketSniffer.Services;

namespace RedPacketSniffer.Hubs;

/// <summary>
/// SignalR Hub — stream packet/credential/weakness real-time toi browser
///
/// Client methods (server -> client):
///   PacketBatch(batch)                — batch packets moi 100ms
///   CredentialFound(credentials)      — credential moi trich xuat
///   WeaknessDetected(weaknesses)      — weakness moi phat hien
///   StatsUpdate(stats)                — cap nhat thong ke moi giay
///   StateChanged(state)               — capture state thay doi
///   ErrorOccurred(message)            — loi
///
/// Server methods (client -> server):
///   StartCapture(adapterIndex, filter) — bat dau capture
///   StopCapture()                      — dung capture
///   GetAdapters()                      — liet ke adapter
///   GetStats()                         — lay stats hien tai
///   GetRecentPackets(count)            — lay packet buffer
///   GetCredentials()                   — lay tat ca credentials
///   GetWeaknesses()                    — lay tat ca weaknesses
/// </summary>
public class PacketHub : Hub
{
    private readonly CaptureService _captureService;
    private readonly ILogger<PacketHub> _logger;

    public PacketHub(CaptureService captureService, ILogger<PacketHub> logger)
    {
        _captureService = captureService;
        _logger = logger;
    }

    public override async Task OnConnectedAsync()
    {
        _logger.LogInformation("Client connected: {ConnectionId}", Context.ConnectionId);

        // Gui state hien tai cho client moi connect
        await Clients.Caller.SendAsync("StateChanged", _captureService.State.ToString());
        await Clients.Caller.SendAsync("StatsUpdate", _captureService.GetStats());

        await base.OnConnectedAsync();
    }

    /// <summary>
    /// Mo driver va liet ke adapter
    /// </summary>
    public async Task<object> GetAdapters()
    {
        try
        {
            if (_captureService.State == CaptureState.Idle)
            {
                var driverInfo = _captureService.Open();
                await Clients.All.SendAsync("DriverInfo", new { driverInfo.Version });
            }

            var adapters = _captureService.GetAdapters();
            return new { success = true, adapters };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetAdapters failed");
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Bat dau capture tren adapter da chon
    /// </summary>
    public async Task<object> StartCapture(int adapterIndex, CaptureFilterDto? filterDto = null)
    {
        try
        {
            _captureService.SelectAdapter(adapterIndex);

            var filter = new CaptureFilter();
            if (filterDto != null)
            {
                if (!string.IsNullOrEmpty(filterDto.Protocols))
                    filter.Protocols = new HashSet<string>(filterDto.Protocols.Split(',', StringSplitOptions.RemoveEmptyEntries));
                if (!string.IsNullOrEmpty(filterDto.Ports))
                    filter.Ports = new HashSet<ushort>(filterDto.Ports.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(ushort.Parse));
                if (!string.IsNullOrEmpty(filterDto.IpAddresses))
                    filter.IpAddresses = new HashSet<string>(filterDto.IpAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                if (!string.IsNullOrEmpty(filterDto.ExcludedIpAddresses))
                    filter.ExcludedIpAddresses = new HashSet<string>(filterDto.ExcludedIpAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                filter.Subnet = filterDto.Subnet;
                filter.Promiscuous = filterDto.Promiscuous;
                filter.MaxPackets = filterDto.MaxPackets;
            }

            _captureService.SetFilter(filter);
            _captureService.StartCapture();

            await Clients.All.SendAsync("StateChanged", "Capturing");
            return new { success = true };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "StartCapture failed");
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Dung capture
    /// </summary>
    public async Task<object> StopCapture()
    {
        try
        {
            await _captureService.StopCaptureAsync();
            await Clients.All.SendAsync("StateChanged", "Ready");
            return new { success = true, stats = _captureService.GetStats() };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "StopCapture failed");
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Lay stats hien tai
    /// </summary>
    public CaptureStats GetStats() => _captureService.GetStats();

    /// <summary>
    /// Lay N packet gan nhat tu buffer
    /// </summary>
    public List<PacketDto> GetRecentPackets(int count = 200)
    {
        return _captureService.GetRecentPackets(Math.Min(count, 1000))
            .Select(PacketDto.FromPacket)
            .ToList();
    }

    /// <summary>
    /// Lay tat ca credentials da trich xuat
    /// </summary>
    public List<CredentialDto> GetCredentials()
    {
        return _captureService.GetCredentials()
            .Select(CredentialDto.FromCredential)
            .ToList();
    }

    /// <summary>
    /// Lay tat ca weaknesses da phat hien
    /// </summary>
    public List<WeaknessDto> GetWeaknesses()
    {
        return _captureService.GetWeaknesses()
            .Select(WeaknessDto.FromWeakness)
            .ToList();
    }

    /// <summary>
    /// Lay tat ca DNS records
    /// </summary>
    public List<DnsRecordDto> GetDnsRecords()
    {
        return _captureService.GetDnsRecords()
            .Select(DnsRecordDto.FromRecord)
            .ToList();
    }

    /// <summary>
    /// Lay top domains
    /// </summary>
    public Dictionary<string, int> GetTopDomains(int count = 20)
    {
        return _captureService.GetTopDomains(count);
    }

    /// <summary>
    /// Lay tat ca TCP connections
    /// </summary>
    public List<TcpConnectionDto> GetTcpConnections()
    {
        return _captureService.GetTcpConnections()
            .Select(TcpConnectionDto.FromConnection)
            .ToList();
    }

    /// <summary>
    /// Lay HTTP log entries
    /// </summary>
    public List<HttpLogEntryDto> GetHttpEntries()
    {
        return _captureService.GetHttpEntries()
            .Select(HttpLogEntryDto.FromEntry)
            .ToList();
    }

    /// <summary>
    /// Lay top HTTP hosts
    /// </summary>
    public Dictionary<string, int> GetTopHosts(int count = 20)
    {
        return _captureService.GetTopHosts(count);
    }

    /// <summary>
    /// Lay discovered network hosts
    /// </summary>
    public List<NetworkHostDto> GetNetworkHosts()
    {
        return _captureService.GetNetworkHosts()
            .Select(NetworkHostDto.FromHost)
            .ToList();
    }

    /// <summary>
    /// Lay network summary
    /// </summary>
    public object GetNetworkSummary()
    {
        return _captureService.GetNetworkSummary();
    }

    /// <summary>
    /// Lay L2/L3 protocol findings
    /// </summary>
    public List<L2L3FindingDto> GetL2L3Findings()
    {
        return _captureService.GetL2L3Findings()
            .Select(L2L3FindingDto.FromFinding)
            .ToList();
    }

    /// <summary>
    /// Lay L2/L3 summary
    /// </summary>
    public object GetL2L3Summary()
    {
        return _captureService.GetL2L3Summary();
    }

    /// <summary>
    /// Lay OSPF routers
    /// </summary>
    public object GetOspfRouters()
    {
        return _captureService.GetOspfRouters();
    }

    /// <summary>
    /// Lay CDP devices
    /// </summary>
    public object GetCdpDevices()
    {
        return _captureService.GetCdpDevices();
    }

    /// <summary>
    /// Lay HSRP groups
    /// </summary>
    public object GetHsrpGroups()
    {
        return _captureService.GetHsrpGroups();
    }

    /// <summary>
    /// Generate report data
    /// </summary>
    public object GetReport()
    {
        try
        {
            return new { success = true, report = _captureService.GenerateReport() };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    // ============================================================
    // VoIP / SIP / WebRTC
    // ============================================================

    /// <summary>
    /// Lay SIP credentials da trich xuat (Digest Auth, Basic Auth)
    /// </summary>
    public object GetSipCredentials()
    {
        return _captureService.GetSipCredentials().Select(c => new
        {
            c.Timestamp,
            c.SourceIp,
            c.DestIp,
            c.Username,
            c.Realm,
            c.Nonce,
            c.Uri,
            c.Response,
            c.Algorithm,
            c.HashcatFormat
        }).ToList();
    }

    /// <summary>
    /// Lay SIP calls (INVITE lifecycle)
    /// </summary>
    public object GetSipCalls()
    {
        return _captureService.GetSipCalls().Select(c => new
        {
            c.CallId,
            c.Caller,
            c.Callee,
            c.UserAgent,
            c.StartTime,
            c.EndTime,
            DurationSeconds = c.Duration.TotalSeconds,
            c.State,
            c.SourceIp,
            c.DestIp
        }).ToList();
    }

    /// <summary>
    /// Lay RTP streams phat hien duoc
    /// </summary>
    public object GetRtpStreams()
    {
        return _captureService.GetRtpStreams().Select(s => new
        {
            s.SourceIp,
            s.SourcePort,
            s.DestIp,
            s.DestPort,
            s.PayloadType,
            s.Codec,
            s.PacketCount,
            IsCleartext = !s.IsEncrypted,
            s.FirstSeen,
            s.LastSeen
        }).ToList();
    }

    /// <summary>
    /// Lay STUN/TURN bindings (WebRTC NAT traversal)
    /// </summary>
    public object GetStunBindings()
    {
        return _captureService.GetStunBindings().Select(b => new
        {
            b.SourceIp,
            b.SourcePort,
            b.DestIp,
            b.DestPort,
            b.MappedAddress,
            b.Method,
            b.IsRequest,
            b.Timestamp
        }).ToList();
    }

    /// <summary>
    /// Lay VoIP summary
    /// </summary>
    public object GetVoipSummary()
    {
        return _captureService.GetVoipSummary();
    }

    // ============================================================
    // ARP Spoofing (MITM)
    // ============================================================

    /// <summary>
    /// Auto-detect gateway IP/MAC
    /// </summary>
    public object ArpSpoofAutoDetect()
    {
        try
        {
            var spoofer = _captureService.GetOrCreateArpSpoofer();
            var result = spoofer.AutoDetectGateway();
            if (result == null)
                return new { success = false, error = "Default gateway not found" };
            return new { success = true, ip = result.Value.ip, mac = result.Value.mac };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Cau hinh ARP spoof: gateway IP, MAC, interval
    /// </summary>
    public object ArpSpoofConfigure(string gatewayIp, string gatewayMac, int intervalMs = 2000)
    {
        try
        {
            var spoofer = _captureService.GetOrCreateArpSpoofer();
            spoofer.Configure(gatewayIp, gatewayMac, intervalMs);
            return new { success = true };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Them target IP/MAC cho ARP spoof
    /// </summary>
    public object ArpSpoofAddTarget(string targetIp, string targetMac)
    {
        try
        {
            var spoofer = _captureService.GetOrCreateArpSpoofer();
            spoofer.AddTarget(targetIp, targetMac);
            return new { success = true, status = spoofer.GetStatus() };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Xoa target khoi ARP spoof
    /// </summary>
    public object ArpSpoofRemoveTarget(string targetIp)
    {
        try
        {
            var spoofer = _captureService.GetOrCreateArpSpoofer();
            spoofer.RemoveTarget(targetIp);
            return new { success = true, status = spoofer.GetStatus() };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Bat dau ARP spoofing
    /// </summary>
    public async Task<object> ArpSpoofStart()
    {
        try
        {
            var spoofer = _captureService.GetOrCreateArpSpoofer();
            spoofer.Start();
            await Clients.All.SendAsync("ArpSpoofStateChanged", "Running");
            return new { success = true, status = spoofer.GetStatus() };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Dung ARP spoofing + restore ARP table
    /// </summary>
    public async Task<object> ArpSpoofStop()
    {
        try
        {
            var spoofer = _captureService.GetOrCreateArpSpoofer();
            await spoofer.StopAsync();
            await Clients.All.SendAsync("ArpSpoofStateChanged", "Idle");
            return new { success = true, status = spoofer.GetStatus() };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Lay trang thai ARP spoof hien tai
    /// </summary>
    public object GetArpSpoofStatus()
    {
        var status = _captureService.GetArpSpoofStatus();
        if (status == null)
            return new { state = "Idle", packetsSent = 0, targets = new List<object>() };
        return status;
    }

    /// <summary>
    /// Resolve MAC address tu ARP cache cho 1 IP (dung cho ARP spoof target)
    /// </summary>
    public object ArpResolveMac(string targetIp)
    {
        try
        {
            // Tim trong discovered hosts truoc
            var hosts = _captureService.GetNetworkHosts();
            var host = hosts.FirstOrDefault(h => h.IpAddress == targetIp && !string.IsNullOrEmpty(h.MacAddress));
            if (host != null)
            {
                return new { success = true, mac = host.MacAddress, source = "discovered" };
            }

            // Fallback: doc tu ARP cache he thong
            string? mac = ResolveMacFromArpCache(targetIp);
            if (mac != null)
            {
                return new { success = true, mac = mac, source = "arp-cache" };
            }

            return new { success = false, error = $"MAC for {targetIp} not found. Ping the target first, then try again." };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Lay danh sach private hosts da discover (cho ARP spoof target picker)
    /// </summary>
    public object GetArpSpoofCandidates()
    {
        try
        {
            var hosts = _captureService.GetNetworkHosts()
                .Where(h => h.IsPrivate && !string.IsNullOrEmpty(h.MacAddress))
                .Select(h => new
                {
                    ip = h.IpAddress,
                    mac = h.MacAddress,
                    vendor = h.Vendor,
                    os = h.OsGuess,
                    lastSeen = h.LastSeen.ToString("HH:mm:ss")
                })
                .ToList();
            return new { success = true, hosts = hosts };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message, hosts = new List<object>() };
        }
    }

    // ============================================================
    // VLAN Hopping
    // ============================================================

    /// <summary>
    /// Cau hinh VLAN Hopping: target VLAN, native VLAN, DTP probe timeout
    /// </summary>
    public object VlanHopConfigure(int targetVlan, int nativeVlan = 1, int dtpProbeTimeoutSec = 30)
    {
        try
        {
            var hopper = _captureService.GetOrCreateVlanHopper();
            hopper.Configure(targetVlan, nativeVlan, dtpProbeTimeoutSec);
            return new { success = true };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Bat dau VLAN Hopping workflow (auto DTP probe → fallback double tagging)
    /// </summary>
    public async Task<object> VlanHopStart()
    {
        try
        {
            var hopper = _captureService.GetOrCreateVlanHopper();
            hopper.Start();
            await Clients.All.SendAsync("VlanHopStateChanged", hopper.GetStatus());
            return new { success = true, status = hopper.GetStatus() };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Dung VLAN Hopping
    /// </summary>
    public async Task<object> VlanHopStop()
    {
        try
        {
            var hopper = _captureService.GetOrCreateVlanHopper();
            await hopper.StopAsync();
            await Clients.All.SendAsync("VlanHopStateChanged", hopper.GetStatus());
            return new { success = true, status = hopper.GetStatus() };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Lay trang thai VLAN Hopping hien tai
    /// </summary>
    public object GetVlanHopStatus()
    {
        var status = _captureService.GetVlanHopStatus();
        if (status == null)
            return new { state = "Idle", activeMethod = "None", targetVlan = 0, nativeVlan = 1,
                         dtpDetected = false, trunkEstablished = false, dtpFramesSent = 0, doubleTagFramesSent = 0 };
        return status;
    }

    /// <summary>
    /// Gui ARP request double-tagged vao target VLAN
    /// </summary>
    public object VlanHopArpRequest(string targetIp)
    {
        try
        {
            var hopper = _captureService.GetOrCreateVlanHopper();
            bool sent = hopper.SendDoubleTaggedArpRequest(targetIp);
            return new { success = sent, status = hopper.GetStatus() };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    /// <summary>
    /// Auto-detect VLAN info tu L2L3 analyzer (CDP native VLAN, DTP discovery)
    /// </summary>
    public object VlanHopAutoDetect()
    {
        try
        {
            // Tim native VLAN tu CDP/LLDP findings
            int detectedNativeVlan = 1;
            bool dtpSeen = false;

            var cdpDevices = _captureService.GetCdpDevices();
            if (cdpDevices.Count > 0)
            {
                var withVlan = cdpDevices.FirstOrDefault(d => int.TryParse(d.NativeVlan, out var v) && v > 0);
                if (withVlan != null && int.TryParse(withVlan.NativeVlan, out var parsedVlan))
                    detectedNativeVlan = parsedVlan;
            }

            // Check DTP tu L2L3 findings
            var l2l3Findings = _captureService.GetL2L3Findings();
            dtpSeen = l2l3Findings.Any(f =>
                f.Protocol.Contains("DTP", StringComparison.OrdinalIgnoreCase) ||
                f.Title.Contains("DTP", StringComparison.OrdinalIgnoreCase));

            // Cung check VlanHopper status (neu da chay truoc do)
            var hopStatus = _captureService.GetVlanHopStatus();
            if (hopStatus?.DtpDetected == true)
                dtpSeen = true;

            return new
            {
                success = true,
                nativeVlan = detectedNativeVlan,
                dtpDetected = dtpSeen,
                cdpDeviceCount = cdpDevices.Count,
                hint = dtpSeen
                    ? "DTP detected — DTP Spoofing is possible"
                    : "No DTP seen — will fall back to Double Tagging"
            };
        }
        catch (Exception ex)
        {
            return new { success = false, error = ex.Message };
        }
    }

    private static string? ResolveMacFromArpCache(string ip)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("arp", $"-a {ip}")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return null;
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);
            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (!trimmed.StartsWith(ip)) continue;
                var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                    return parts[1].Replace('-', ':').ToUpperInvariant();
            }
        }
        catch { }
        return null;
    }
}

// ============================================================
// DTOs
// ============================================================

/// <summary>
/// DTO cho filter tu client
/// </summary>
public class CaptureFilterDto
{
    public string? Protocols { get; set; }    // "TCP,UDP"
    public string? Ports { get; set; }        // "80,443,8080"
    public string? IpAddresses { get; set; }  // "192.168.1.1,10.0.0.1"
    public string? ExcludedIpAddresses { get; set; }  // "192.168.0.104" — IP máy mình cần ẩn
    public string? Subnet { get; set; }       // "192.168.1.0/24"
    public bool Promiscuous { get; set; }
    public long MaxPackets { get; set; }
}

/// <summary>
/// DTO packet gui qua SignalR — nhe hon CapturedPacket (khong gui RawData)
/// </summary>
public class PacketDto
{
    public long Id { get; init; }
    public string Timestamp { get; init; } = "";
    public string Direction { get; init; } = "";
    public int Length { get; init; }
    public string SrcMac { get; init; } = "";
    public string DstMac { get; init; } = "";
    public string EtherType { get; init; } = "";
    public string? SrcIP { get; init; }
    public string? DstIP { get; init; }
    public string Protocol { get; init; } = "";
    public ushort SrcPort { get; init; }
    public ushort DstPort { get; init; }
    public string TcpFlags { get; init; } = "";
    public string? AppProtocol { get; init; }
    public string Summary { get; init; } = "";

    // New fields from PacketDotNet improvements
    public bool IsIPv6 { get; init; }
    public ushort VlanId { get; init; }
    public ushort OuterVlanId { get; init; }
    public string? TcpOptions { get; init; }
    public string? GreInnerInfo { get; init; }

    public string? RawDataBase64 { get; init; }

    public static PacketDto FromPacket(CapturedPacket p) => new()
    {
        Id = p.Id,
        Timestamp = p.Timestamp.ToString("HH:mm:ss.fff"),
        Direction = p.Direction == PacketDirection.Outbound ? "OUT" : "IN",
        Length = p.Length,
        SrcMac = p.SourceMac,
        DstMac = p.DestMac,
        EtherType = p.EtherTypeStr,
        SrcIP = p.SourceIP,
        DstIP = p.DestIP,
        Protocol = p.IsIPv6 && p.IpProtocol == 58 ? "ICMPv6" : p.ProtocolStr,
        SrcPort = p.SourcePort,
        DstPort = p.DestPort,
        TcpFlags = p.TcpFlagsStr,
        AppProtocol = p.ApplicationProtocol,
        Summary = p.GetSummary(),
        IsIPv6 = p.IsIPv6,
        VlanId = p.VlanId,
        OuterVlanId = p.OuterVlanId,
        TcpOptions = p.TcpOptionsStr,
        GreInnerInfo = p.GreInnerInfo,
        RawDataBase64 = p.RawData.Length > 0 ? Convert.ToBase64String(p.RawData) : null
    };
}

/// <summary>
/// DTO credential gui qua SignalR
/// </summary>
public class CredentialDto
{
    public string Timestamp { get; init; } = "";
    public string Protocol { get; init; } = "";
    public string SourceIP { get; init; } = "";
    public string DestIP { get; init; } = "";
    public ushort DestPort { get; init; }
    public string Host { get; init; } = "";
    public string Username { get; init; } = "";
    public string Password { get; init; } = "";
    public string Severity { get; init; } = "";
    public string RawData { get; init; } = "";

    public static CredentialDto FromCredential(ExtractedCredential c) => new()
    {
        Timestamp = c.Timestamp.ToString("HH:mm:ss.fff"),
        Protocol = c.Protocol,
        SourceIP = c.SourceIP,
        DestIP = c.DestIP,
        DestPort = c.DestPort,
        Host = c.Host,
        Username = c.Username,
        Password = c.Password,
        Severity = c.SeverityStr,
        RawData = c.RawData
    };
}

/// <summary>
/// DTO weakness gui qua SignalR
/// </summary>
public class WeaknessDto
{
    public string Timestamp { get; init; } = "";
    public string Category { get; init; } = "";
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string SourceIP { get; init; } = "";
    public string DestIP { get; init; } = "";
    public ushort Port { get; init; }
    public string Severity { get; init; } = "";
    public string ExploitPath { get; init; } = "";
    public string Mitigation { get; init; } = "";
    public long PacketId { get; init; }

    public static WeaknessDto FromWeakness(DetectedWeakness w) => new()
    {
        Timestamp = w.Timestamp.ToString("HH:mm:ss.fff"),
        Category = w.Category,
        Name = w.Name,
        Description = w.Description,
        SourceIP = w.SourceIP,
        DestIP = w.DestIP,
        Port = w.Port,
        Severity = w.SeverityStr,
        ExploitPath = w.ExploitPath,
        Mitigation = w.Mitigation,
        PacketId = w.PacketId
    };
}

/// <summary>
/// DTO DNS record gui qua SignalR
/// </summary>
public class DnsRecordDto
{
    public string Timestamp { get; init; } = "";
    public long PacketId { get; init; }
    public ushort TransactionId { get; init; }
    public bool IsResponse { get; init; }
    public string SourceIP { get; init; } = "";
    public string DestIP { get; init; } = "";
    public string QueryName { get; init; } = "";
    public string QueryType { get; init; } = "";
    public string ResponseCode { get; init; } = "";
    public List<string> Answers { get; init; } = new();
    public List<string> AnomalyFlags { get; init; } = new();
    public int QueryFrequency { get; init; }

    public static DnsRecordDto FromRecord(DnsRecord r) => new()
    {
        Timestamp = r.Timestamp.ToString("HH:mm:ss.fff"),
        PacketId = r.PacketId,
        TransactionId = r.TransactionId,
        IsResponse = r.IsResponse,
        SourceIP = r.SourceIP,
        DestIP = r.DestIP,
        QueryName = r.QueryName,
        QueryType = r.QueryTypeStr,
        ResponseCode = r.ResponseCodeStr,
        Answers = r.Answers,
        AnomalyFlags = r.AnomalyFlags,
        QueryFrequency = r.QueryFrequency
    };
}

/// <summary>
/// DTO TCP connection gui qua SignalR
/// </summary>
public class TcpConnectionDto
{
    public long Id { get; init; }
    public string ClientIP { get; init; } = "";
    public ushort ClientPort { get; init; }
    public string ServerIP { get; init; } = "";
    public ushort ServerPort { get; init; }
    public string State { get; init; } = "";
    public string StartTime { get; init; } = "";
    public string LastActivity { get; init; } = "";
    public double DurationSeconds { get; init; }
    public int PacketCount { get; init; }
    public long BytesTransferred { get; init; }
    public long ClientBytes { get; init; }
    public long ServerBytes { get; init; }
    public List<string> AnomalyFlags { get; init; } = new();

    public static TcpConnectionDto FromConnection(TcpConnection c) => new()
    {
        Id = c.Id,
        ClientIP = c.ClientIP,
        ClientPort = c.ClientPort,
        ServerIP = c.ServerIP,
        ServerPort = c.ServerPort,
        State = c.StateStr,
        StartTime = c.StartTime.ToString("HH:mm:ss.fff"),
        LastActivity = c.LastActivity.ToString("HH:mm:ss.fff"),
        DurationSeconds = c.DurationSeconds,
        PacketCount = c.PacketCount,
        BytesTransferred = c.BytesTransferred,
        ClientBytes = c.ClientBytes,
        ServerBytes = c.ServerBytes,
        AnomalyFlags = c.AnomalyFlags
    };
}

/// <summary>
/// DTO HTTP log entry gui qua SignalR
/// </summary>
public class HttpLogEntryDto
{
    public string Timestamp { get; init; } = "";
    public long PacketId { get; init; }
    public bool IsRequest { get; init; }
    public string SourceIP { get; init; } = "";
    public string DestIP { get; init; } = "";
    public ushort SourcePort { get; init; }
    public ushort DestPort { get; init; }
    // Request
    public string Method { get; init; } = "";
    public string Url { get; init; } = "";
    public string FullUrl { get; init; } = "";
    public string Host { get; init; } = "";
    public string UserAgent { get; init; } = "";
    public string Referer { get; init; } = "";
    public string ContentType { get; init; } = "";
    public string CookieHeader { get; init; } = "";
    public string Authorization { get; init; } = "";
    public string Body { get; init; } = "";
    // Response
    public int StatusCode { get; init; }
    public string StatusText { get; init; } = "";
    public string ServerHeader { get; init; } = "";
    public string ContentLength { get; init; } = "";
    public string Location { get; init; } = "";
    public List<string> SetCookieNames { get; init; } = new();
    // Common
    public List<string> AnomalyFlags { get; init; } = new();

    public static HttpLogEntryDto FromEntry(HttpLogEntry e) => new()
    {
        Timestamp = e.Timestamp.ToString("HH:mm:ss.fff"),
        PacketId = e.PacketId,
        IsRequest = e.IsRequest,
        SourceIP = e.SourceIP,
        DestIP = e.DestIP,
        SourcePort = e.SourcePort,
        DestPort = e.DestPort,
        Method = e.Method,
        Url = e.Url,
        FullUrl = e.FullUrl,
        Host = e.Host,
        UserAgent = e.UserAgent,
        Referer = e.Referer,
        ContentType = e.ContentType,
        CookieHeader = e.CookieHeader,
        Authorization = e.Authorization,
        Body = e.Body,
        StatusCode = e.StatusCode,
        StatusText = e.StatusText,
        ServerHeader = e.ServerHeader,
        ContentLength = e.ContentLength,
        Location = e.Location,
        SetCookieNames = e.SetCookies.Select(c => c.Name).ToList(),
        AnomalyFlags = e.AnomalyFlags
    };
}

/// <summary>
/// DTO network host gui qua SignalR
/// </summary>
public class NetworkHostDto
{
    public long Id { get; init; }
    public string IpAddress { get; init; } = "";
    public string MacAddress { get; init; } = "";
    public string Vendor { get; init; } = "";
    public string OsGuess { get; init; } = "";
    public int LastTtl { get; init; }
    public bool IsPrivate { get; init; }
    public string Subnet { get; init; } = "";
    public string FirstSeen { get; init; } = "";
    public string LastSeen { get; init; } = "";
    public List<ushort> OpenPorts { get; init; } = new();
    public List<string> Protocols { get; init; } = new();
    public int PeerCount { get; init; }
    public long PacketsSent { get; init; }
    public long PacketsReceived { get; init; }
    public long BytesSent { get; init; }
    public long BytesReceived { get; init; }
    public List<string> AnomalyFlags { get; init; } = new();

    public static NetworkHostDto FromHost(NetworkHost h) => new()
    {
        Id = h.Id,
        IpAddress = h.IpAddress,
        MacAddress = h.MacAddress,
        Vendor = h.Vendor,
        OsGuess = h.OsGuess,
        LastTtl = h.LastTtl,
        IsPrivate = h.IsPrivate,
        Subnet = h.Subnet,
        FirstSeen = h.FirstSeen.ToString("HH:mm:ss.fff"),
        LastSeen = h.LastSeen.ToString("HH:mm:ss.fff"),
        OpenPorts = h.OpenPorts,
        Protocols = h.Protocols,
        PeerCount = h.Peers.Count,
        PacketsSent = h.PacketsSent,
        PacketsReceived = h.PacketsReceived,
        BytesSent = h.BytesSent,
        BytesReceived = h.BytesReceived,
        AnomalyFlags = h.AnomalyFlags
    };
}

/// <summary>
/// DTO L2/L3 finding gui qua SignalR
/// </summary>
public class L2L3FindingDto
{
    public long Id { get; init; }
    public string Protocol { get; init; } = "";
    public string Severity { get; init; } = "";
    public string Category { get; init; } = "";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string SourceIp { get; init; } = "";
    public string Timestamp { get; init; } = "";

    public static L2L3FindingDto FromFinding(L2L3Finding f) => new()
    {
        Id = f.Id,
        Protocol = f.Protocol,
        Severity = f.Severity,
        Category = f.Category,
        Title = f.Title,
        Detail = f.Detail,
        SourceIp = f.SourceIp,
        Timestamp = f.Timestamp.ToString("HH:mm:ss.fff")
    };
}

/// <summary>
/// DTO VoIP finding gui qua SignalR
/// </summary>
public class VoipFindingDto
{
    public long Id { get; init; }
    public string Protocol { get; init; } = "";
    public string Severity { get; init; } = "";
    public string Category { get; init; } = "";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string SourceIp { get; init; } = "";
    public string DestIp { get; init; } = "";
    public string Timestamp { get; init; } = "";

    public static VoipFindingDto FromFinding(VoipFinding f) => new()
    {
        Id = f.Id,
        Protocol = f.Protocol,
        Severity = f.Severity,
        Category = f.Category,
        Title = f.Title,
        Detail = f.Detail,
        SourceIp = f.SourceIp,
        DestIp = "",
        Timestamp = f.Timestamp.ToString("HH:mm:ss.fff")
    };
}

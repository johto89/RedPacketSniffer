using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// Deep L2/L3 Protocol Analyzer — phân tích sâu routing/switching protocols
///
/// Red team use cases:
/// - OSPF: detect plaintext auth (type 0/1) vs MD5 (type 2), extract password, router topology
/// - STP: detect topology changes (TC flag), root bridge takeover opportunity
/// - CDP/LLDP: information disclosure — device name, platform, IPs, VLANs, ports
/// - HSRP/VRRP: detect plaintext auth, gateway hijack opportunity
/// - EIGRP: unauthenticated neighbor injection
/// - ICMP: redirect attacks (MITM), network mapping via unreachable/TTL exceeded
/// - GRE: tunnel detection — potential lateral movement path
/// </summary>
public sealed class L2L3ProtocolAnalyzer
{
    private readonly List<L2L3Finding> _findings = new();
    private readonly Dictionary<string, OspfRouterInfo> _ospfRouters = new();
    private readonly Dictionary<string, CdpDeviceInfo> _cdpDevices = new();
    private readonly Dictionary<string, LldpDeviceInfo> _lldpDevices = new();
    private readonly Dictionary<int, HsrpGroupInfo> _hsrpGroups = new();
    private readonly Dictionary<int, VrrpGroupInfo> _vrrpGroups = new();
    private readonly Dictionary<string, EigrpNeighborInfo> _eigrpNeighbors = new();
    private readonly Dictionary<string, StpBridgeInfo> _stpBridges = new();
    private readonly object _lock = new();
    private long _nextId = 1;

    public event Action<L2L3Finding>? OnFinding;

    public void Analyze(CapturedPacket packet)
    {
        if (string.IsNullOrEmpty(packet.ApplicationProtocol) && string.IsNullOrEmpty(packet.Info))
            return;

        string proto = packet.ApplicationProtocol ?? "";

        switch (proto)
        {
            case "OSPF":
                AnalyzeOspf(packet);
                break;
            case "STP":
                AnalyzeStp(packet);
                break;
            case "CDP":
                AnalyzeCdp(packet);
                break;
            case "LLDP":
                AnalyzeLldp(packet);
                break;
            case "HSRP":
                AnalyzeHsrp(packet);
                break;
            case "VRRP":
                AnalyzeVrrp(packet);
                break;
            case "EIGRP":
                AnalyzeEigrp(packet);
                break;
            case "ICMP":
                AnalyzeIcmp(packet);
                break;
            case "GRE":
                AnalyzeGre(packet);
                break;
        }
    }

    // ============================================================
    // OSPF Analysis
    // ============================================================

    private void AnalyzeOspf(CapturedPacket packet)
    {
        string info = packet.Info ?? "";
        string srcIp = packet.SourceIP ?? "";

        // Extract router info
        string routerId = ExtractField(info, "Router=");
        string area = ExtractField(info, "Area=");
        string authType = "";

        if (info.Contains("Auth=NONE"))
            authType = "NONE";
        else if (info.Contains("Auth=PLAINTEXT"))
            authType = "PLAINTEXT";
        else if (info.Contains("Auth=MD5"))
            authType = "MD5";

        lock (_lock)
        {
            if (!string.IsNullOrEmpty(routerId) && !_ospfRouters.ContainsKey(routerId))
            {
                var router = new OspfRouterInfo
                {
                    RouterId = routerId,
                    SourceIp = srcIp,
                    Area = area,
                    AuthType = authType,
                    FirstSeen = packet.Timestamp,
                    LastSeen = packet.Timestamp
                };
                _ospfRouters[routerId] = router;

                // Finding: new OSPF router discovered
                AddFinding(new L2L3Finding
                {
                    Protocol = "OSPF",
                    Severity = "INFO",
                    Category = "DISCOVERY",
                    Title = "OSPF Router Discovered",
                    Detail = $"Router ID={routerId} IP={srcIp} Area={area} Auth={authType}",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }
            else if (!string.IsNullOrEmpty(routerId))
            {
                _ospfRouters[routerId].LastSeen = packet.Timestamp;
            }

            // Security findings
            if (authType == "NONE")
            {
                AddFinding(new L2L3Finding
                {
                    Protocol = "OSPF",
                    Severity = "CRITICAL",
                    Category = "AUTH_WEAKNESS",
                    Title = "OSPF No Authentication",
                    Detail = $"Router {routerId} ({srcIp}) Area={area} dùng OSPF không có authentication. " +
                             "Attacker có thể inject route giả, gây routing loop hoặc MITM.",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }
            else if (authType == "PLAINTEXT")
            {
                string password = ExtractField(info, "Password=\"");
                if (!string.IsNullOrEmpty(password) && password.Contains('"'))
                    password = password[..password.IndexOf('"')];

                AddFinding(new L2L3Finding
                {
                    Protocol = "OSPF",
                    Severity = "CRITICAL",
                    Category = "CREDENTIAL_LEAK",
                    Title = "OSPF Plaintext Password Captured",
                    Detail = $"Router {routerId} ({srcIp}) dùng plaintext auth. " +
                             $"Password=\"{password}\". Có thể dùng để inject route.",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }
            else if (authType == "MD5")
            {
                string keyId = ExtractField(info, "KeyID=");
                AddFinding(new L2L3Finding
                {
                    Protocol = "OSPF",
                    Severity = "LOW",
                    Category = "AUTH_INFO",
                    Title = "OSPF MD5 Authentication",
                    Detail = $"Router {routerId} ({srcIp}) Area={area} dùng MD5 auth KeyID={keyId}. " +
                             "Có thể offline brute-force MD5 hash từ captured packet.",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }

            // Hello packet — extract DR/BDR/neighbors
            if (info.Contains("Hello") && info.Contains("DR="))
            {
                string dr = ExtractField(info, "DR=");
                string bdr = ExtractField(info, "BDR=");
                string neighbors = ExtractField(info, "Neighbors=");

                if (!string.IsNullOrEmpty(routerId) && _ospfRouters.TryGetValue(routerId, out var router))
                {
                    router.DR = dr;
                    router.BDR = bdr;
                    router.IsHello = true;
                }
            }
        }
    }

    // ============================================================
    // STP Analysis
    // ============================================================

    private void AnalyzeStp(CapturedPacket packet)
    {
        string info = packet.Info ?? "";
        string srcMac = packet.SourceMac;

        lock (_lock)
        {
            // Track bridge
            if (!_stpBridges.ContainsKey(srcMac))
            {
                _stpBridges[srcMac] = new StpBridgeInfo
                {
                    BridgeMac = srcMac,
                    FirstSeen = packet.Timestamp
                };

                AddFinding(new L2L3Finding
                {
                    Protocol = "STP",
                    Severity = "INFO",
                    Category = "DISCOVERY",
                    Title = "STP Bridge Discovered",
                    Detail = info,
                    SourceIp = srcMac,
                    Timestamp = packet.Timestamp
                });
            }
            _stpBridges[srcMac].LastSeen = packet.Timestamp;

            // Topology Change detection
            if (info.Contains("[TC]"))
            {
                AddFinding(new L2L3Finding
                {
                    Protocol = "STP",
                    Severity = "HIGH",
                    Category = "TOPOLOGY_CHANGE",
                    Title = "STP Topology Change Detected",
                    Detail = $"Bridge {srcMac} đang quảng bá Topology Change. " +
                             "Có thể do STP attack (root bridge takeover) hoặc network reconfiguration. " +
                             info,
                    SourceIp = srcMac,
                    Timestamp = packet.Timestamp
                });
            }

            // TCN (Topology Change Notification)
            if (info.Contains("Topology Change"))
            {
                AddFinding(new L2L3Finding
                {
                    Protocol = "STP",
                    Severity = "MEDIUM",
                    Category = "TOPOLOGY_CHANGE",
                    Title = "STP TCN BPDU",
                    Detail = $"TCN BPDU từ {srcMac}. MAC table sẽ bị flush — potential recon opportunity. {info}",
                    SourceIp = srcMac,
                    Timestamp = packet.Timestamp
                });
            }
        }
    }

    // ============================================================
    // CDP Analysis
    // ============================================================

    private void AnalyzeCdp(CapturedPacket packet)
    {
        string info = packet.Info ?? "";
        string deviceId = ExtractField(info, "Device=");
        string platform = ExtractField(info, "Platform=");
        string portId = ExtractField(info, "Port=");
        string ip = ExtractField(info, "IP=");
        string vlan = ExtractField(info, "VLAN=");

        lock (_lock)
        {
            string key = !string.IsNullOrEmpty(deviceId) ? deviceId : packet.SourceMac;
            bool isNew = !_cdpDevices.ContainsKey(key);

            _cdpDevices[key] = new CdpDeviceInfo
            {
                DeviceId = deviceId,
                Platform = platform,
                PortId = portId,
                IpAddress = ip,
                NativeVlan = vlan,
                SourceMac = packet.SourceMac,
                FirstSeen = isNew ? packet.Timestamp : _cdpDevices[key].FirstSeen,
                LastSeen = packet.Timestamp
            };

            if (isNew)
            {
                // CDP always leaks info — this is a finding
                AddFinding(new L2L3Finding
                {
                    Protocol = "CDP",
                    Severity = "HIGH",
                    Category = "INFO_DISCLOSURE",
                    Title = "CDP Information Disclosure",
                    Detail = $"Device={deviceId} Platform={platform} Port={portId} IP={ip} VLAN={vlan}. " +
                             "CDP leaks device identity, software version, IP addresses, VLAN info. " +
                             "Disable CDP trên port không cần thiết: 'no cdp enable'.",
                    SourceIp = ip,
                    Timestamp = packet.Timestamp
                });
            }
        }
    }

    // ============================================================
    // LLDP Analysis
    // ============================================================

    private void AnalyzeLldp(CapturedPacket packet)
    {
        string info = packet.Info ?? "";
        string sysName = ExtractField(info, "Name=");
        string chassisId = ExtractField(info, "Chassis=");
        string portId = ExtractField(info, "Port=");
        string sysDesc = ExtractField(info, "Desc=");

        lock (_lock)
        {
            string key = !string.IsNullOrEmpty(sysName) ? sysName :
                         !string.IsNullOrEmpty(chassisId) ? chassisId : packet.SourceMac;
            bool isNew = !_lldpDevices.ContainsKey(key);

            _lldpDevices[key] = new LldpDeviceInfo
            {
                SystemName = sysName,
                ChassisId = chassisId,
                PortId = portId,
                SystemDesc = sysDesc,
                SourceMac = packet.SourceMac,
                FirstSeen = isNew ? packet.Timestamp : _lldpDevices[key].FirstSeen,
                LastSeen = packet.Timestamp
            };

            if (isNew)
            {
                AddFinding(new L2L3Finding
                {
                    Protocol = "LLDP",
                    Severity = "MEDIUM",
                    Category = "INFO_DISCLOSURE",
                    Title = "LLDP Information Disclosure",
                    Detail = $"Name={sysName} Chassis={chassisId} Port={portId} Desc={sysDesc}. " +
                             "LLDP reveals network topology and device info.",
                    SourceIp = packet.SourceMac,
                    Timestamp = packet.Timestamp
                });
            }
        }
    }

    // ============================================================
    // HSRP Analysis
    // ============================================================

    private void AnalyzeHsrp(CapturedPacket packet)
    {
        string info = packet.Info ?? "";
        string srcIp = packet.SourceIP ?? "";

        // Extract group number
        string groupStr = ExtractField(info, "Group=");
        if (!int.TryParse(groupStr?.Split(' ')[0], out int group)) return;

        string state = ExtractField(info, "State=");
        string priority = ExtractField(info, "Priority=");
        string vip = ExtractField(info, "VIP=");
        string auth = "";

        if (info.Contains("Auth=\""))
        {
            int start = info.IndexOf("Auth=\"") + 6;
            int end = info.IndexOf('"', start);
            if (end > start) auth = info[start..end];
        }

        lock (_lock)
        {
            bool isNew = !_hsrpGroups.ContainsKey(group);
            _hsrpGroups[group] = new HsrpGroupInfo
            {
                Group = group,
                State = state?.Split(' ')[0] ?? "",
                Priority = priority?.Split(' ')[0] ?? "",
                VirtualIp = vip?.Split(' ')[0] ?? "",
                ActiveRouter = srcIp,
                Auth = auth,
                FirstSeen = isNew ? packet.Timestamp : _hsrpGroups[group].FirstSeen,
                LastSeen = packet.Timestamp
            };

            if (isNew)
            {
                AddFinding(new L2L3Finding
                {
                    Protocol = "HSRP",
                    Severity = "INFO",
                    Category = "DISCOVERY",
                    Title = "HSRP Group Discovered",
                    Detail = $"Group={group} State={state} VIP={vip} Priority={priority} Router={srcIp}",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }

            // Plaintext auth = gateway hijack opportunity
            if (!string.IsNullOrEmpty(auth))
            {
                AddFinding(new L2L3Finding
                {
                    Protocol = "HSRP",
                    Severity = "CRITICAL",
                    Category = "CREDENTIAL_LEAK",
                    Title = "HSRP Plaintext Authentication",
                    Detail = $"Group={group} VIP={vip} Auth=\"{auth}\". " +
                             "HSRP dùng plaintext password. Attacker có thể hijack gateway bằng cách " +
                             "gửi HSRP Hello với priority cao hơn và password này.",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }
        }
    }

    // ============================================================
    // VRRP Analysis
    // ============================================================

    private void AnalyzeVrrp(CapturedPacket packet)
    {
        string info = packet.Info ?? "";
        string srcIp = packet.SourceIP ?? "";

        string vridStr = ExtractField(info, "VRID=");
        if (!int.TryParse(vridStr?.Split(' ')[0], out int vrid)) return;

        string priority = ExtractField(info, "Priority=");
        string vip = ExtractField(info, "VIP=");

        lock (_lock)
        {
            bool isNew = !_vrrpGroups.ContainsKey(vrid);
            _vrrpGroups[vrid] = new VrrpGroupInfo
            {
                Vrid = vrid,
                Priority = priority?.Split(' ')[0] ?? "",
                VirtualIp = vip?.Split(' ')[0] ?? "",
                MasterRouter = srcIp,
                FirstSeen = isNew ? packet.Timestamp : _vrrpGroups[vrid].FirstSeen,
                LastSeen = packet.Timestamp
            };

            if (isNew)
            {
                AddFinding(new L2L3Finding
                {
                    Protocol = "VRRP",
                    Severity = "INFO",
                    Category = "DISCOVERY",
                    Title = "VRRP Instance Discovered",
                    Detail = $"VRID={vrid} Priority={priority} VIP={vip} Master={srcIp}",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }

            if (info.Contains("Auth=NONE"))
            {
                AddFinding(new L2L3Finding
                {
                    Protocol = "VRRP",
                    Severity = "HIGH",
                    Category = "AUTH_WEAKNESS",
                    Title = "VRRP No Authentication",
                    Detail = $"VRID={vrid} VIP={vip} không có authentication. " +
                             "Attacker có thể hijack virtual gateway bằng VRRP advertisement với priority cao hơn.",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }
            else if (info.Contains("Auth=SIMPLE"))
            {
                AddFinding(new L2L3Finding
                {
                    Protocol = "VRRP",
                    Severity = "HIGH",
                    Category = "AUTH_WEAKNESS",
                    Title = "VRRP Simple Text Authentication",
                    Detail = $"VRID={vrid} VIP={vip} dùng simple text auth (deprecated). Password có thể sniff được.",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }
        }
    }

    // ============================================================
    // EIGRP Analysis
    // ============================================================

    private void AnalyzeEigrp(CapturedPacket packet)
    {
        string info = packet.Info ?? "";
        string srcIp = packet.SourceIP ?? "";

        lock (_lock)
        {
            bool isNew = !_eigrpNeighbors.ContainsKey(srcIp);
            if (isNew)
            {
                _eigrpNeighbors[srcIp] = new EigrpNeighborInfo
                {
                    IpAddress = srcIp,
                    FirstSeen = packet.Timestamp
                };

                AddFinding(new L2L3Finding
                {
                    Protocol = "EIGRP",
                    Severity = "INFO",
                    Category = "DISCOVERY",
                    Title = "EIGRP Neighbor Discovered",
                    Detail = $"Neighbor={srcIp} {info}",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }
            _eigrpNeighbors[srcIp].LastSeen = packet.Timestamp;

            if (info.Contains("Auth=NONE [INSECURE]"))
            {
                AddFinding(new L2L3Finding
                {
                    Protocol = "EIGRP",
                    Severity = "CRITICAL",
                    Category = "AUTH_WEAKNESS",
                    Title = "EIGRP No Authentication",
                    Detail = $"EIGRP neighbor {srcIp} không có authentication. " +
                             "Attacker có thể inject route giả, gây routing loop, blackhole, hoặc redirect traffic. " +
                             "Dùng Loki hoặc custom tool để exploit.",
                    SourceIp = srcIp,
                    Timestamp = packet.Timestamp
                });
            }
        }
    }

    // ============================================================
    // ICMP Analysis
    // ============================================================

    private void AnalyzeIcmp(CapturedPacket packet)
    {
        string info = packet.Info ?? "";

        if (info.Contains("[POTENTIAL_MITM]"))
        {
            AddFinding(new L2L3Finding
            {
                Protocol = "ICMP",
                Severity = "HIGH",
                Category = "ATTACK_INDICATOR",
                Title = "ICMP Redirect Detected",
                Detail = $"{info}. ICMP Redirect có thể là dấu hiệu MITM attack — " +
                         "attacker redirect traffic qua gateway giả. Disable ICMP redirect: " +
                         "'net.ipv4.conf.all.accept_redirects=0' (Linux) hoặc 'no ip redirects' (Cisco).",
                SourceIp = packet.SourceIP ?? "",
                Timestamp = packet.Timestamp
            });
        }
    }

    // ============================================================
    // GRE Analysis
    // ============================================================

    private void AnalyzeGre(CapturedPacket packet)
    {
        lock (_lock)
        {
            AddFinding(new L2L3Finding
            {
                Protocol = "GRE",
                Severity = "MEDIUM",
                Category = "TUNNEL_DETECTED",
                Title = "GRE Tunnel Traffic",
                Detail = $"{packet.SourceIP} -> {packet.DestIP}: {packet.Info}. " +
                         "GRE tunnel có thể là lateral movement path hoặc data exfiltration channel.",
                SourceIp = packet.SourceIP ?? "",
                Timestamp = packet.Timestamp
            });
        }
    }

    // ============================================================
    // Getters
    // ============================================================

    public List<L2L3Finding> GetAllFindings()
    {
        lock (_lock) { return _findings.ToList(); }
    }

    public List<L2L3Finding> GetFindingsBySeverity(string severity)
    {
        lock (_lock) { return _findings.Where(f => f.Severity == severity).ToList(); }
    }

    public List<OspfRouterInfo> GetOspfRouters()
    {
        lock (_lock) { return _ospfRouters.Values.ToList(); }
    }

    public List<CdpDeviceInfo> GetCdpDevices()
    {
        lock (_lock) { return _cdpDevices.Values.ToList(); }
    }

    public List<LldpDeviceInfo> GetLldpDevices()
    {
        lock (_lock) { return _lldpDevices.Values.ToList(); }
    }

    public List<HsrpGroupInfo> GetHsrpGroups()
    {
        lock (_lock) { return _hsrpGroups.Values.ToList(); }
    }

    public List<VrrpGroupInfo> GetVrrpGroups()
    {
        lock (_lock) { return _vrrpGroups.Values.ToList(); }
    }

    public List<EigrpNeighborInfo> GetEigrpNeighbors()
    {
        lock (_lock) { return _eigrpNeighbors.Values.ToList(); }
    }

    public L2L3Summary GetSummary()
    {
        lock (_lock)
        {
            return new L2L3Summary
            {
                TotalFindings = _findings.Count,
                Critical = _findings.Count(f => f.Severity == "CRITICAL"),
                High = _findings.Count(f => f.Severity == "HIGH"),
                Medium = _findings.Count(f => f.Severity == "MEDIUM"),
                Low = _findings.Count(f => f.Severity == "LOW"),
                Info = _findings.Count(f => f.Severity == "INFO"),
                OspfRouters = _ospfRouters.Count,
                CdpDevices = _cdpDevices.Count,
                LldpDevices = _lldpDevices.Count,
                HsrpGroups = _hsrpGroups.Count,
                VrrpGroups = _vrrpGroups.Count,
                EigrpNeighbors = _eigrpNeighbors.Count,
                StpBridges = _stpBridges.Count,
                ProtocolCounts = _findings.GroupBy(f => f.Protocol)
                    .ToDictionary(g => g.Key, g => g.Count())
            };
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _findings.Clear();
            _ospfRouters.Clear();
            _cdpDevices.Clear();
            _lldpDevices.Clear();
            _hsrpGroups.Clear();
            _vrrpGroups.Clear();
            _eigrpNeighbors.Clear();
            _stpBridges.Clear();
            _nextId = 1;
        }
    }

    // ============================================================
    // Helpers
    // ============================================================

    private void AddFinding(L2L3Finding finding)
    {
        finding.Id = _nextId++;
        _findings.Add(finding);
        // Cap findings
        if (_findings.Count > 5000)
            _findings.RemoveAt(0);

        OnFinding?.Invoke(finding);
    }

    private static string ExtractField(string info, string prefix)
    {
        int idx = info.IndexOf(prefix, StringComparison.Ordinal);
        if (idx < 0) return "";
        int start = idx + prefix.Length;
        int end = info.IndexOf(' ', start);
        return end > start ? info[start..end] : info[start..];
    }
}

// ============================================================
// Data Models
// ============================================================

public class L2L3Finding
{
    public long Id { get; set; }
    public string Protocol { get; init; } = "";
    public string Severity { get; init; } = ""; // CRITICAL, HIGH, MEDIUM, LOW, INFO
    public string Category { get; init; } = ""; // AUTH_WEAKNESS, CREDENTIAL_LEAK, INFO_DISCLOSURE, etc.
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string SourceIp { get; init; } = "";
    public DateTime Timestamp { get; init; }
}

public class OspfRouterInfo
{
    public string RouterId { get; init; } = "";
    public string SourceIp { get; init; } = "";
    public string Area { get; init; } = "";
    public string AuthType { get; set; } = "";
    public string DR { get; set; } = "";
    public string BDR { get; set; } = "";
    public bool IsHello { get; set; }
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
}

public class CdpDeviceInfo
{
    public string DeviceId { get; init; } = "";
    public string Platform { get; init; } = "";
    public string PortId { get; init; } = "";
    public string IpAddress { get; init; } = "";
    public string NativeVlan { get; init; } = "";
    public string SourceMac { get; init; } = "";
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
}

public class LldpDeviceInfo
{
    public string SystemName { get; init; } = "";
    public string ChassisId { get; init; } = "";
    public string PortId { get; init; } = "";
    public string SystemDesc { get; init; } = "";
    public string SourceMac { get; init; } = "";
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
}

public class HsrpGroupInfo
{
    public int Group { get; init; }
    public string State { get; set; } = "";
    public string Priority { get; set; } = "";
    public string VirtualIp { get; set; } = "";
    public string ActiveRouter { get; set; } = "";
    public string Auth { get; set; } = "";
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
}

public class VrrpGroupInfo
{
    public int Vrid { get; init; }
    public string Priority { get; set; } = "";
    public string VirtualIp { get; set; } = "";
    public string MasterRouter { get; set; } = "";
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
}

public class EigrpNeighborInfo
{
    public string IpAddress { get; init; } = "";
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
}

public class StpBridgeInfo
{
    public string BridgeMac { get; init; } = "";
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
}

public class L2L3Summary
{
    public int TotalFindings { get; init; }
    public int Critical { get; init; }
    public int High { get; init; }
    public int Medium { get; init; }
    public int Low { get; init; }
    public int Info { get; init; }
    public int OspfRouters { get; init; }
    public int CdpDevices { get; init; }
    public int LldpDevices { get; init; }
    public int HsrpGroups { get; init; }
    public int VrrpGroups { get; init; }
    public int EigrpNeighbors { get; init; }
    public int StpBridges { get; init; }
    public Dictionary<string, int> ProtocolCounts { get; init; } = new();
}

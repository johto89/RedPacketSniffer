using System.Net;
using System.Security.Cryptography;
using System.Text;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// Detects protocol weaknesses and misconfigurations in network traffic.
///
/// Weakness categories:
/// 1. Name Resolution Poisoning: LLMNR, NBT-NS, mDNS
/// 2. Proxy/WPAD abuse
/// 3. Cleartext protocol usage
/// 4. NTLM relay opportunity
/// 5. ARP anomalies (gratuitous ARP, ARP spoofing)
/// 6. SMB signing not required
/// 7. DHCPv6 spoofing opportunity
/// 8. IP fragmentation evasion (overlapping / tiny fragments)
/// 9. Slowloris-style HTTP DoS
///
/// Each weakness carries:
/// - Technical description
/// - Impact assessment for red team
/// - Suggested exploitation path
///
/// Threading: every mutable shared collection is guarded by <see cref="_lock"/>.
/// <see cref="Analyze"/> is therefore safe to call from multiple capture threads.
/// The <see cref="OnWeaknessDetected"/> event is always raised OUTSIDE the lock, so
/// handlers may call back into this instance without deadlocking.
/// </summary>
public sealed class ProtocolWeaknessDetector
{
    private readonly List<DetectedWeakness> _weaknesses = new();
    private readonly object _lock = new();

    // Deduplication with a time window so long-running captures keep re-alerting
    // instead of going silent forever, and so memory stays bounded (evicted by age).
    private readonly Dictionary<string, DateTime> _seen = new(); // signature -> last report time
    private DateTime _lastSeenCleanup = DateTime.MinValue;

    // ARP IP -> last observed sender MAC (used to detect IP/MAC re-binding)
    private readonly Dictionary<string, string> _arpIpToMac = new();

    // IP fragment tracking: key = "srcIP-dstIP-identification" -> list of (offset, length, time)
    private readonly Dictionary<string, List<(int offset, int length, DateTime time)>> _fragmentTracker = new();
    private DateTime _lastFragmentCleanup = DateTime.MinValue;

    // Slowloris tracking: key = "srcIP:srcPort-dstIP:dstPort" (per TCP connection)
    private readonly Dictionary<string, SlowlorisState> _slowlorisTracker = new();
    private DateTime _lastSlowlorisCleanup = DateTime.MinValue;

    // --- NEW: Role conflict tracker (FHRP, DHCP, STP, RA) ---
    // key = "role:identifier" -> claimant (MAC or IP) of the authoritative source
    private readonly Dictionary<string, string> _roleAuthority = new();

    // --- NEW: DHCPv4 server tracker ---
    private readonly Dictionary<string, DateTime> _dhcpv4Servers = new(); // serverIP -> last seen

    // --- NEW: DNS response tracker for spoofing detection ---
    // key = "txid:qname" -> (answerIP, sourceIP, time)
    private readonly Dictionary<string, (string answer, string source, DateTime time)> _dnsResponses = new();
    private DateTime _lastDnsCleanup = DateTime.MinValue;

    // --- NEW: Stealth scan tracker ---
    // key = "srcIP" -> (count of anomalous TCP flags, first seen, last seen)
    private readonly Dictionary<string, (int count, DateTime first, DateTime last)> _stealthScanTracker = new();
    private DateTime _lastStealthScanCleanup = DateTime.MinValue;

    // --- NEW: SYN flood tracker ---
    // key = "srcIP->dstIP" -> (synCount, synAckCount, firstSeen)
    // NOTE: Not yet used by any Check method. When implementing CheckSynFlood,
    // apply time-based eviction + hard cap (MaxSynFloodEntries) before insert,
    // following the same pattern as _stealthScanTracker.
    private readonly Dictionary<string, (int syn, int ack, DateTime first)> _synFloodTracker = new();
    private DateTime _lastSynFloodCleanup = DateTime.MinValue;

    // --- TLS metadata tracking (Gap 1) ---
    // key = "srcIP:srcPort-dstIP:dstPort" -> TlsSessionInfo
    private readonly Dictionary<string, TlsSessionInfo> _tlsSessions = new();
    private DateTime _lastTlsSessionCleanup = DateTime.MinValue;

    // --- SMB session tracking (Gap 3) ---
    // key = "srcIP-dstIP" -> list of named pipes seen
    private readonly Dictionary<string, HashSet<string>> _smbNamedPipes = new();
    private DateTime _lastSmbPipeCleanup = DateTime.MinValue;

    // --- TLS Decryptor integration ---
    // Optional: when set, TLS Application Data records are decrypted using SSLKEYLOGFILE keys.
    // Set via SetTlsDecryptor(). The decryptor's OnRecordDecrypted event can be used
    // to feed decrypted plaintext back to HttpRequestLogger, CredentialExtractor, etc.
    private TlsDecryptor? _tlsDecryptor;

    // Within this window an identical signature will not be reported again.
    private static readonly TimeSpan DedupWindow = TimeSpan.FromMinutes(5);
    // Signatures older than this are evicted to bound memory usage.
    private static readonly TimeSpan SeenMaxAge = TimeSpan.FromMinutes(30);

    // ---------- Hard size caps to prevent unbounded memory growth ----------
    private const int MaxWeaknesses          = 5000;
    private const int MaxSeenSignatures      = 10000;
    private const int MaxArpEntries          = 2000;
    private const int MaxFragmentEntries     = 1000;
    private const int MaxSlowlorisEntries    = 2000;
    private const int MaxRoleEntries         = 500;
    private const int MaxDhcpv4Servers       = 100;
    private const int MaxDnsResponses        = 5000;
    private const int MaxStealthScanEntries  = 2000;
    private const int MaxSynFloodEntries     = 2000;
    private const int MaxTlsSessions         = 3000;
    private const int MaxSmbPipeEntries      = 1000;

    public event Action<DetectedWeakness>? OnWeaknessDetected;

    /// <summary>Raised when a parsing/analysis error is swallowed. Useful during development.</summary>
    public event Action<Exception>? OnError;

    /// <summary>
    /// Attach a <see cref="TlsDecryptor"/> instance for SSLKEYLOGFILE-based decryption.
    /// When set, ServerHello parsing automatically registers sessions with the decryptor,
    /// and TLS Application Data records are forwarded for decryption.
    /// Thread-safe: can be called at any time; takes effect on next packet.
    /// </summary>
    public void SetTlsDecryptor(TlsDecryptor? decryptor)
    {
        lock (_lock)
        {
            _tlsDecryptor = decryptor;
        }
    }

    /// <summary>
    /// Analyzes a single packet for protocol weaknesses.
    /// </summary>
    public void Analyze(CapturedPacket packet)
    {
        if (packet.RawData.Length == 0) return;

        try
        {
            // IP fragment overlap detection (before protocol checks)
            if (packet.EtherType == 0x0800) // IPv4
            {
                CheckIpFragmentOverlap(packet);
                CheckIcmpRedirect(packet);       // ICMP type 5
            }

            // UDP-based weaknesses
            if (packet.IpProtocol == 17) // UDP
            {
                CheckLlmnr(packet);
                CheckNbtNs(packet);
                CheckMdns(packet);
                CheckDhcpv6(packet);
                CheckSsdp(packet);
                CheckSnmpCommunity(packet);       // [G] SNMP v1/v2c
                CheckDhcpv4Rogue(packet);         // [E] Rogue DHCPv4
                CheckHsrp(packet);                // [D] HSRP (UDP 1985)
                CheckGlbp(packet);                // [D] GLBP (UDP 3222)
                CheckDnsSpoofing(packet);         // DNS spoofing (UDP 53)
                CheckWsDiscovery(packet);         // WS-Discovery (UDP 3702)
            }

            // TCP-based weaknesses
            if (packet.IpProtocol == 6) // TCP
            {
                CheckWpad(packet);
                CheckCleartextProtocol(packet);
                CheckNtlmRelay(packet);
                CheckSmbSigning(packet);
                CheckSlowloris(packet);
                CheckSmbv1(packet);               // SMBv1 detection
                CheckNtlmv1Downgrade(packet);     // NTLMv1 in SMB
                CheckLdapCleartext(packet);       // LDAP simple bind
                CheckHttpBasicAuth(packet);       // HTTP Basic Auth
                CheckSmtpCleartext(packet);       // SMTP cleartext
                CheckStealthScan(packet);         // Stealth scan detection
            }

            // ARP anomalies
            if (packet.EtherType == 0x0806)
            {
                CheckArpAnomaly(packet);
            }

            // --- L2 protocols (non-IP) ---
            // [A] CDP: dst MAC 01:00:0C:CC:CC:CC with SNAP proto 0x2000
            // [A] LLDP: EtherType 0x88CC
            if (packet.EtherType == 0x88CC)
            {
                CheckLldp(packet);
            }
            CheckCdp(packet); // CDP uses SNAP, check raw frame

            // [B] DTP: dst 01:00:0C:CC:CC:CC, SNAP proto 0x2004
            CheckDtp(packet);

            // [C] STP BPDU: dst 01:80:C2:00:00:00, LLC DSAP/SSAP 0x42
            CheckStpBpdu(packet);

            // [D] VRRP: IP protocol 112
            if (packet.IpProtocol == 112)
            {
                CheckVrrp(packet);
            }

            // [F] IPv6 RA (ICMPv6 type 134) and NDP NA (ICMPv6 type 136)
            if (packet.EtherType == 0x86DD) // IPv6
            {
                CheckIpv6RogueRa(packet);
                CheckNdpSpoof(packet);
            }

            // VLAN double-tagging (QinQ)
            CheckVlanDoubleTag(packet);

            // TLS analysis
            if (packet.IpProtocol == 6)
            {
                CheckTlsDowngrade(packet);
                CheckTlsMetadata(packet);          // [Gap1] SNI, JA3/JA3S, cert anomaly
                CheckSmbNamedPipe(packet);          // [Gap3] Named pipe / lateral movement
                CheckSmbRelayIndicator(packet);     // [Gap3] SMB relay chain detection
                CheckNtlmHashExtraction(packet);    // [Gap3] NTLM hash extraction (all ports)
                CheckRdpWeakness(packet);           // [Gap8] RDP protocol detection
                CheckWinRm(packet);                 // [Gap8] WinRM/PSRemoting detection
            }

            // Enterprise protocol analysis (works on both TCP and UDP where applicable)
            if (packet.IpProtocol == 17) // UDP
            {
                CheckDohDot(packet);                // [Gap8] External DNS / DoH indicator
                CheckRadiusTacacs(packet);           // [Gap8] RADIUS (UDP 1812/1813)
                CheckQuicHttp3(packet);             // [Gap8] QUIC/HTTP3 (UDP 443)
                CheckDot1xEap(packet);              // [Gap8] 802.1X EAP (via RADIUS)
            }
            if (packet.IpProtocol == 6) // TCP — TACACS+ runs on TCP 49
            {
                CheckRadiusTacacs(packet);           // [Gap8] TACACS+ (TCP 49)
            }
        }
        catch (Exception ex)
        {
            OnError?.Invoke(ex);
        }
    }

    public List<DetectedWeakness> GetAllWeaknesses()
    {
        lock (_lock) { return new List<DetectedWeakness>(_weaknesses); }
    }

    public Dictionary<string, int> GetWeaknessSummary()
    {
        lock (_lock)
        {
            return _weaknesses
                .GroupBy(w => w.Category)
                .ToDictionary(g => g.Key, g => g.Count());
        }
    }

    // ============================================================
    // [Gap6] Structured Reporting: JSON, HTML, CSV, Timeline
    // ============================================================

    /// <summary>
    /// Exports all findings as a structured JSON string suitable for automated tooling,
    /// SIEM ingestion, or structured report generation.
    /// </summary>
    public string ExportJson()
    {
        var weaknesses = GetAllWeaknesses();
        var sb = new StringBuilder(weaknesses.Count * 512);
        sb.AppendLine("{");
        sb.AppendLine("  \"report\": {");
        sb.AppendLine($"    \"generated\": \"{DateTime.UtcNow:O}\",");
        sb.AppendLine($"    \"tool\": \"RedPacketSniffer — ProtocolWeaknessDetector\",");
        sb.AppendLine($"    \"totalFindings\": {weaknesses.Count},");

        // Severity breakdown
        var bySeverity = weaknesses.GroupBy(w => w.Severity).OrderByDescending(g => g.Key);
        sb.AppendLine("    \"severityBreakdown\": {");
        sb.AppendLine(string.Join(",\n", bySeverity.Select(g =>
            $"      \"{g.Key}\": {g.Count()}")));
        sb.AppendLine("    },");

        // Findings
        sb.AppendLine("    \"findings\": [");
        for (int i = 0; i < weaknesses.Count; i++)
        {
            var w = weaknesses[i];
            sb.AppendLine("      {");
            sb.AppendLine($"        \"id\": {i + 1},");
            sb.AppendLine($"        \"timestamp\": \"{w.Timestamp:O}\",");
            sb.AppendLine($"        \"severity\": \"{w.SeverityStr}\",");
            sb.AppendLine($"        \"cvssEstimate\": {EstimateCvss(w.Severity):F1},");
            sb.AppendLine($"        \"category\": {JsonEscape(w.Category)},");
            sb.AppendLine($"        \"name\": {JsonEscape(w.Name)},");
            sb.AppendLine($"        \"description\": {JsonEscape(w.Description)},");
            sb.AppendLine($"        \"sourceIP\": {JsonEscape(w.SourceIP)},");
            sb.AppendLine($"        \"destIP\": {JsonEscape(w.DestIP)},");
            sb.AppendLine($"        \"port\": {w.Port},");
            sb.AppendLine($"        \"exploitPath\": {JsonEscape(w.ExploitPath)},");
            sb.AppendLine($"        \"mitigation\": {JsonEscape(w.Mitigation)},");
            sb.AppendLine($"        \"packetId\": {w.PacketId}");
            sb.Append("      }");
            if (i < weaknesses.Count - 1) sb.AppendLine(",");
            else sb.AppendLine();
        }
        sb.AppendLine("    ]");
        sb.AppendLine("  }");
        sb.AppendLine("}");
        return sb.ToString();
    }

    /// <summary>
    /// Exports findings as an HTML report with severity coloring, summary table,
    /// and detailed findings list. Suitable for stakeholder delivery.
    /// </summary>
    public string ExportHtml(string title = "RedPacketSniffer — Security Assessment Report")
    {
        var weaknesses = GetAllWeaknesses();
        var sb = new StringBuilder(weaknesses.Count * 1024);

        sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.AppendLine($"<title>{HtmlEscape(title)}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body{font-family:'Segoe UI',Arial,sans-serif;margin:40px;color:#222;background:#fafafa}");
        sb.AppendLine("h1{color:#1a1a2e;border-bottom:3px solid #e94560}");
        sb.AppendLine("h2{color:#1a1a2e;margin-top:30px}");
        sb.AppendLine("table{border-collapse:collapse;width:100%;margin:15px 0}");
        sb.AppendLine("th,td{border:1px solid #ddd;padding:8px 12px;text-align:left}");
        sb.AppendLine("th{background:#1a1a2e;color:#fff}");
        sb.AppendLine("tr:nth-child(even){background:#f2f2f2}");
        sb.AppendLine(".critical{background:#ff4757;color:#fff;padding:2px 8px;border-radius:3px;font-weight:bold}");
        sb.AppendLine(".high{background:#ff6348;color:#fff;padding:2px 8px;border-radius:3px;font-weight:bold}");
        sb.AppendLine(".medium{background:#ffa502;color:#fff;padding:2px 8px;border-radius:3px}");
        sb.AppendLine(".low{background:#2ed573;color:#fff;padding:2px 8px;border-radius:3px}");
        sb.AppendLine(".info{background:#1e90ff;color:#fff;padding:2px 8px;border-radius:3px}");
        sb.AppendLine(".finding{border:1px solid #ddd;margin:15px 0;padding:15px;background:#fff;border-radius:5px}");
        sb.AppendLine(".finding-header{display:flex;justify-content:space-between;align-items:center}");
        sb.AppendLine(".detail-label{font-weight:bold;color:#555;min-width:120px;display:inline-block}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine($"<h1>{HtmlEscape(title)}</h1>");
        sb.AppendLine($"<p><strong>Generated:</strong> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>");
        sb.AppendLine($"<p><strong>Total Findings:</strong> {weaknesses.Count}</p>");

        // Executive summary
        sb.AppendLine("<h2>Executive Summary</h2>");
        sb.AppendLine("<table><tr><th>Severity</th><th>Count</th><th>CVSS Range</th></tr>");
        foreach (var sev in new[] { WeaknessSeverity.Critical, WeaknessSeverity.High,
                                     WeaknessSeverity.Medium, WeaknessSeverity.Low, WeaknessSeverity.Info })
        {
            int count = weaknesses.Count(w => w.Severity == sev);
            if (count > 0)
            {
                string sevName = sev.ToString().ToUpperInvariant();
                sb.AppendLine($"<tr><td><span class=\"{sev.ToString().ToLowerInvariant()}\">{sevName}</span></td>" +
                              $"<td>{count}</td><td>{GetCvssRange(sev)}</td></tr>");
            }
        }
        sb.AppendLine("</table>");

        // Category breakdown
        sb.AppendLine("<h2>Findings by Category</h2>");
        sb.AppendLine("<table><tr><th>Category</th><th>Count</th><th>Highest Severity</th></tr>");
        foreach (var grp in weaknesses.GroupBy(w => w.Category).OrderByDescending(g => g.Max(w => w.Severity)))
        {
            var maxSev = grp.Max(w => w.Severity);
            sb.AppendLine($"<tr><td>{HtmlEscape(grp.Key)}</td><td>{grp.Count()}</td>" +
                          $"<td><span class=\"{maxSev.ToString().ToLowerInvariant()}\">{maxSev.ToString().ToUpperInvariant()}</span></td></tr>");
        }
        sb.AppendLine("</table>");

        // Timeline
        sb.AppendLine("<h2>Attack Timeline</h2>");
        sb.AppendLine("<table><tr><th>Time</th><th>Severity</th><th>Finding</th><th>Source</th><th>Target</th></tr>");
        foreach (var w in weaknesses.OrderBy(w => w.Timestamp))
        {
            string sevClass = w.Severity.ToString().ToLowerInvariant();
            sb.AppendLine($"<tr><td>{w.Timestamp:HH:mm:ss.fff}</td>" +
                          $"<td><span class=\"{sevClass}\">{w.SeverityStr}</span></td>" +
                          $"<td>{HtmlEscape(w.Name)}</td>" +
                          $"<td>{HtmlEscape(w.SourceIP)}</td>" +
                          $"<td>{HtmlEscape(w.DestIP)}:{w.Port}</td></tr>");
        }
        sb.AppendLine("</table>");

        // Detailed findings
        sb.AppendLine("<h2>Detailed Findings</h2>");
        int findingNum = 0;
        foreach (var w in weaknesses.OrderByDescending(w => w.Severity).ThenBy(w => w.Timestamp))
        {
            findingNum++;
            string sevClass = w.Severity.ToString().ToLowerInvariant();
            sb.AppendLine($"<div class=\"finding\">");
            sb.AppendLine($"<div class=\"finding-header\"><h3>#{findingNum}: {HtmlEscape(w.Name)}</h3>" +
                          $"<span class=\"{sevClass}\">{w.SeverityStr} (CVSS ~{EstimateCvss(w.Severity):F1})</span></div>");
            sb.AppendLine($"<p><span class=\"detail-label\">Category:</span> {HtmlEscape(w.Category)}</p>");
            sb.AppendLine($"<p><span class=\"detail-label\">Timestamp:</span> {w.Timestamp:O}</p>");
            sb.AppendLine($"<p><span class=\"detail-label\">Source:</span> {HtmlEscape(w.SourceIP)} → {HtmlEscape(w.DestIP)}:{w.Port}</p>");
            sb.AppendLine($"<p><span class=\"detail-label\">Description:</span> {HtmlEscape(w.Description)}</p>");
            sb.AppendLine($"<p><span class=\"detail-label\">Exploit Path:</span> {HtmlEscape(w.ExploitPath)}</p>");
            sb.AppendLine($"<p><span class=\"detail-label\">Mitigation:</span> {HtmlEscape(w.Mitigation)}</p>");
            sb.AppendLine($"<p><span class=\"detail-label\">Packet ID:</span> {w.PacketId}</p>");
            sb.AppendLine("</div>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    /// <summary>
    /// Exports findings as CSV for import into Excel/SIEM.
    /// </summary>
    public string ExportCsv()
    {
        var weaknesses = GetAllWeaknesses();
        var sb = new StringBuilder(weaknesses.Count * 256);
        sb.AppendLine("ID,Timestamp,Severity,CVSS,Category,Name,SourceIP,DestIP,Port,Description,ExploitPath,Mitigation,PacketId");
        int id = 0;
        foreach (var w in weaknesses.OrderByDescending(w => w.Severity).ThenBy(w => w.Timestamp))
        {
            id++;
            sb.AppendLine($"{id},{w.Timestamp:O},{w.SeverityStr},{EstimateCvss(w.Severity):F1}," +
                          $"{CsvEscape(w.Category)},{CsvEscape(w.Name)}," +
                          $"{CsvEscape(w.SourceIP)},{CsvEscape(w.DestIP)},{w.Port}," +
                          $"{CsvEscape(w.Description)},{CsvEscape(w.ExploitPath)},{CsvEscape(w.Mitigation)},{w.PacketId}");
        }
        return sb.ToString();
    }

    /// <summary>
    /// Returns a chronological timeline of findings, grouped into phases
    /// (Reconnaissance, Credential Capture, Lateral Movement, Protocol Weakness).
    /// </summary>
    public List<TimelineEntry> GetTimeline()
    {
        var weaknesses = GetAllWeaknesses();
        return weaknesses
            .OrderBy(w => w.Timestamp)
            .Select((w, i) => new TimelineEntry
            {
                Order = i + 1,
                Timestamp = w.Timestamp,
                Phase = ClassifyPhase(w.Category),
                Severity = w.SeverityStr,
                Finding = w.Name,
                SourceIP = w.SourceIP,
                DestIP = w.DestIP,
                Port = w.Port
            })
            .ToList();
    }

    /// <summary>
    /// Returns a host-centric evidence summary: for each unique host, lists
    /// all findings associated with it (as source or destination).
    /// </summary>
    public Dictionary<string, List<DetectedWeakness>> GetHostEvidence()
    {
        var weaknesses = GetAllWeaknesses();
        var result = new Dictionary<string, List<DetectedWeakness>>();

        foreach (var w in weaknesses)
        {
            if (!string.IsNullOrEmpty(w.SourceIP))
            {
                if (!result.TryGetValue(w.SourceIP, out var srcList))
                {
                    srcList = new List<DetectedWeakness>();
                    result[w.SourceIP] = srcList;
                }
                srcList.Add(w);
            }
            if (!string.IsNullOrEmpty(w.DestIP) && w.DestIP != w.SourceIP)
            {
                if (!result.TryGetValue(w.DestIP, out var dstList))
                {
                    dstList = new List<DetectedWeakness>();
                    result[w.DestIP] = dstList;
                }
                dstList.Add(w);
            }
        }

        return result;
    }

    /// <summary>
    /// Maps WeaknessSeverity to an estimated CVSS 3.1 base score range.
    /// These are approximate values based on the severity category; actual
    /// CVSS scores depend on the specific vulnerability characteristics.
    /// </summary>
    private static float EstimateCvss(WeaknessSeverity severity) => severity switch
    {
        WeaknessSeverity.Critical => 9.1f,
        WeaknessSeverity.High => 7.5f,
        WeaknessSeverity.Medium => 5.3f,
        WeaknessSeverity.Low => 3.1f,
        WeaknessSeverity.Info => 0.0f,
        _ => 0.0f
    };

    private static string GetCvssRange(WeaknessSeverity severity) => severity switch
    {
        WeaknessSeverity.Critical => "9.0 – 10.0",
        WeaknessSeverity.High => "7.0 – 8.9",
        WeaknessSeverity.Medium => "4.0 – 6.9",
        WeaknessSeverity.Low => "0.1 – 3.9",
        WeaknessSeverity.Info => "N/A (Informational)",
        _ => "Unknown"
    };

    private static string ClassifyPhase(string category) => category switch
    {
        "Name Resolution Poisoning" or "Service Discovery" or "QUIC/HTTP3" or "DNS Security" => "Reconnaissance",
        "NTLM Hash Capture" or "NTLM Relay" or "NTLM Downgrade" or "SMB Authentication"
            or "Authentication Infrastructure" or "802.1X / NAC" => "Credential Capture",
        "SMB Lateral Movement" or "WinRM Activity" or "PowerShell Remoting"
            or "WinRM Weakness" or "RDP Weakness" or "RDP Exposure" => "Lateral Movement",
        "TLS Weakness" or "TLS Metadata" or "TLS Threat Intelligence"
            or "TLS Certificate Anomaly" => "Encrypted Traffic Analysis",
        _ => "Protocol Weakness"
    };

    private static string JsonEscape(string s)
    {
        if (string.IsNullOrEmpty(s)) return "\"\"";
        return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"")
                       .Replace("\n", "\\n").Replace("\r", "\\r")
                       .Replace("\t", "\\t") + "\"";
    }

    private static string HtmlEscape(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
    }

    private static string CsvEscape(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        if (s.Contains(',') || s.Contains('"') || s.Contains('\n'))
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }

    public void Clear()
    {
        lock (_lock)
        {
            _weaknesses.Clear();
            _seen.Clear();
            _arpIpToMac.Clear();
            _fragmentTracker.Clear();
            _slowlorisTracker.Clear();
            _roleAuthority.Clear();
            _dhcpv4Servers.Clear();
            _dnsResponses.Clear();
            _stealthScanTracker.Clear();
            _synFloodTracker.Clear();
            _tlsSessions.Clear();
            _smbNamedPipes.Clear();
            _lastSeenCleanup = DateTime.MinValue;
            _lastFragmentCleanup = DateTime.MinValue;
            _lastSlowlorisCleanup = DateTime.MinValue;
            _lastDnsCleanup = DateTime.MinValue;
            _lastStealthScanCleanup = DateTime.MinValue;
            _lastSynFloodCleanup = DateTime.MinValue;
            _lastTlsSessionCleanup = DateTime.MinValue;
            _lastSmbPipeCleanup = DateTime.MinValue;
        }
    }

    // ============================================================
    // Deduplication helpers (must be called under _lock, except MarkSeen)
    // ============================================================

    private void CleanupSeenLocked(DateTime now)
    {
        if ((now - _lastSeenCleanup).TotalSeconds < 60) return;
        _lastSeenCleanup = now;

        var cutoff = now - SeenMaxAge;
        var stale = _seen.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
        foreach (var k in stale) _seen.Remove(k);

        // Hard cap: if time-based eviction is not enough, drop oldest entries.
        if (_seen.Count > MaxSeenSignatures)
        {
            int toRemove = _seen.Count - MaxSeenSignatures + MaxSeenSignatures / 4;
            foreach (var k in _seen.OrderBy(kv => kv.Value).Take(toRemove).Select(kv => kv.Key).ToList())
                _seen.Remove(k);
        }
    }

    /// <summary>Returns true if this signature should be reported now (first time, or window expired).</summary>
    private bool MarkSeenLocked(string sig, DateTime now)
    {
        if (_seen.TryGetValue(sig, out var last) && (now - last) < DedupWindow)
            return false;
        _seen[sig] = now;
        return true;
    }

    private bool MarkSeen(string sig, DateTime now)
    {
        lock (_lock)
        {
            CleanupSeenLocked(now);
            return MarkSeenLocked(sig, now);
        }
    }

    // ============================================================
    // LLMNR Detection (UDP 5355)
    // ============================================================

    private void CheckLlmnr(CapturedPacket packet)
    {
        if (packet.DestPort != 5355 && packet.SourcePort != 5355) return;

        // LLMNR queries are sent to multicast 224.0.0.252
        bool isQuery = packet.DestPort == 5355;

        // The queried name is high-value intel: it lets a red team craft a matching
        // Responder host name. LLMNR uses DNS wire format.
        string? queriedName = isQuery && TryParseDnsQuestionName(packet.GetPayload(), out var n) ? n : null;

        string sig = $"LLMNR-{packet.SourceIP}-{queriedName ?? "resp"}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Name Resolution Poisoning",
            Name = "LLMNR Detected",
            Description = isQuery
                ? $"Host {packet.SourceIP} is sending an LLMNR query" +
                  (queriedName != null ? $" for '{queriedName}'. " : ". ") +
                  "LLMNR can be poisoned by any attacker on the same broadcast segment."
                : $"Host {packet.SourceIP} is responding to LLMNR.",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = 5355,
            Severity = WeaknessSeverity.High,
            ExploitPath = "Use Responder or Inveigh to poison LLMNR -> capture NTLMv2 hash -> crack or relay.",
            Mitigation = "Disable LLMNR via GPO: Computer Configuration > Administrative Templates > Network > " +
                         "DNS Client > 'Turn Off Multicast Name Resolution' = Enabled.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // NBT-NS Detection (UDP 137)
    // ============================================================

    private void CheckNbtNs(CapturedPacket packet)
    {
        if (packet.DestPort != 137 && packet.SourcePort != 137) return;

        bool isQuery = packet.DestPort == 137;

        // Parse the NetBIOS opcode so we describe the packet accurately, and decode the
        // (first-level encoded) queried name for intel.
        var payload = packet.GetPayload();
        int? nbOpcode = TryParseNbnsOpcode(payload);

        // Opcode 0 = query. Anything else (registration/release/refresh) is not a name query.
        // We still report queries; other opcodes are less interesting for poisoning.
        if (isQuery && nbOpcode.HasValue && nbOpcode.Value != 0) return;

        string? queriedName = TryParseNetbiosName(payload, out var nm) ? nm : null;

        string sig = $"NBTNS-{packet.SourceIP}-{queriedName ?? "resp"}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Name Resolution Poisoning",
            Name = "NBT-NS (NetBIOS Name Service) Detected",
            Description = isQuery
                ? $"Host {packet.SourceIP} is broadcasting an NBT-NS name query" +
                  (queriedName != null ? $" for '{queriedName}'. " : ". ") +
                  "Like LLMNR, it is trivially poisonable and usually fires as a fallback when DNS fails."
                : $"Host {packet.SourceIP} is responding to NBT-NS.",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = 137,
            Severity = WeaknessSeverity.High,
            ExploitPath = "Responder/Inveigh poison NBT-NS -> capture NTLMv2 hash. Commonly triggered when DNS resolution fails.",
            Mitigation = "Disable NetBIOS over TCP/IP per adapter: Network Properties > IPv4 > Advanced > WINS > " +
                         "'Disable NetBIOS over TCP/IP', or push it via DHCP option 001.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // mDNS Detection (UDP 5353)
    // ============================================================

    private void CheckMdns(CapturedPacket packet)
    {
        if (packet.DestPort != 5353 && packet.SourcePort != 5353) return;

        bool isQuery = packet.DestPort == 5353;
        string? queriedName = isQuery && TryParseDnsQuestionName(packet.GetPayload(), out var n) ? n : null;

        string sig = $"MDNS-{packet.SourceIP}-{queriedName ?? "resp"}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Name Resolution Poisoning",
            Name = "mDNS (Multicast DNS) Detected",
            Description = $"Host {packet.SourceIP} is using mDNS (multicast 224.0.0.251:5353)" +
                          (queriedName != null ? $", querying '{queriedName}'. " : ". ") +
                          "It can be spoofed on the local segment.",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = 5353,
            Severity = WeaknessSeverity.Medium,
            ExploitPath = "mDNS poisoning works like LLMNR but is less common on Windows enterprise; it mostly affects Apple/Linux hosts.",
            Mitigation = "Disable the mDNS service or firewall-block outbound UDP 5353 where it is not required.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // WPAD Detection (HTTP)
    // ============================================================

    private void CheckWpad(CapturedPacket packet)
    {
        if (packet.DestPort != 80 && packet.SourcePort != 80) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 20) return;

        string payloadStr;
        try { payloadStr = Encoding.ASCII.GetString(payload[..Math.Min(payload.Length, 500)]); }
        catch (Exception ex) { OnError?.Invoke(ex); return; }

        // WPAD request: GET /wpad.dat or Host: wpad.xxx
        bool isWpadRequest = payloadStr.Contains("/wpad.dat", StringComparison.OrdinalIgnoreCase)
                          || payloadStr.Contains("Host: wpad", StringComparison.OrdinalIgnoreCase);

        if (!isWpadRequest) return;

        string sig = $"WPAD-{packet.SourceIP}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Proxy Auto-Discovery Abuse",
            Name = "WPAD Request Detected",
            Description = $"Host {packet.SourceIP} is requesting WPAD configuration (wpad.dat). " +
                          "If no WPAD server exists, the client falls back to LLMNR/NBT-NS resolution, which can be poisoned. " +
                          "Note: the higher-risk fallback shows up as an LLMNR/NBT-NS query for the name 'wpad'.",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = 80,
            Severity = WeaknessSeverity.High,
            ExploitPath = "Responder in WPAD mode -> MitM all HTTP traffic from the victim, or serve a malicious wpad.dat " +
                          "to route traffic through an attacker-controlled proxy.",
            Mitigation = "Disable WPAD: GPO > User Configuration > Windows Settings > Internet Settings > Connections > " +
                         "LAN Settings > uncheck 'Automatically detect settings'. Also create a DNS record for " +
                         "wpad.<domain> pointing to a benign host so the name never falls back to multicast.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // Cleartext Protocol Detection
    // ============================================================

    private void CheckCleartextProtocol(CapturedPacket packet)
    {
        // Only flag when there is actual application data. A bare SYN to port 23 during a
        // port scan must not be reported as "Telnet cleartext traffic".
        if (packet.GetPayload().Length == 0) return;

        // Heuristic: the lower of the two ports is assumed to be the server/well-known port.
        // This misses non-standard data channels (e.g. FTP passive high ports) but avoids
        // guessing wrong on ephemeral client ports.
        ushort serverPort = Math.Min(packet.SourcePort, packet.DestPort);
        string? protoName = serverPort switch
        {
            21 => "FTP",
            23 => "Telnet",
            110 => "POP3",
            143 => "IMAP",
            _ => null
        };

        if (protoName == null) return;

        string sig = $"CLEARTEXT-{protoName}-{packet.SourceIP}-{packet.DestIP}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Cleartext Protocol",
            Name = $"{protoName} Cleartext Traffic",
            Description = $"Cleartext {protoName} traffic between {packet.SourceIP} and {packet.DestIP}:{serverPort}. " +
                          "Credentials and data can be sniffed by any attacker on the same segment.",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = serverPort,
            Severity = WeaknessSeverity.High,
            ExploitPath = $"Passive sniffing, or ARP spoof + MitM, to capture {protoName} credentials.",
            Mitigation = protoName switch
            {
                "FTP" => "Migrate to SFTP (port 22) or FTPS (port 990).",
                "Telnet" => "Migrate to SSH (port 22).",
                "POP3" => "Enable POP3S (port 995) or move to IMAP over TLS.",
                "IMAP" => "Enable IMAPS (port 993).",
                _ => $"Enable TLS/SSL for {protoName}."
            },
            PacketId = packet.Id
        });
    }

    // ============================================================
    // NTLM Relay Opportunity (NTLM auth over HTTP without TLS)
    // ============================================================

    private void CheckNtlmRelay(CapturedPacket packet)
    {
        // Requests go to 80/8080; server challenges come from 80/8080. Match symmetrically.
        bool httpPort = packet.DestPort is 80 or 8080 || packet.SourcePort is 80 or 8080;
        if (!httpPort) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 30) return;

        string payloadStr;
        try { payloadStr = Encoding.ASCII.GetString(payload[..Math.Min(payload.Length, 1000)]); }
        catch (Exception ex) { OnError?.Invoke(ex); return; }

        if (!payloadStr.Contains("NTLM", StringComparison.OrdinalIgnoreCase) &&
            !payloadStr.Contains("Negotiate", StringComparison.OrdinalIgnoreCase))
            return;

        bool isNtlmAuth = payloadStr.Contains("Authorization: NTLM", StringComparison.OrdinalIgnoreCase)
                       || payloadStr.Contains("Authorization: Negotiate", StringComparison.OrdinalIgnoreCase)
                       || payloadStr.Contains("WWW-Authenticate: NTLM", StringComparison.OrdinalIgnoreCase)
                       || payloadStr.Contains("WWW-Authenticate: Negotiate", StringComparison.OrdinalIgnoreCase);

        if (!isNtlmAuth) return;

        string sig = $"NTLM-RELAY-{packet.SourceIP}-{packet.DestIP}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "NTLM Relay",
            Name = "NTLM Authentication over HTTP (No TLS)",
            Description = $"NTLM authentication between {packet.SourceIP} and {packet.DestIP} over cleartext HTTP. " +
                          "The NTLMv2 exchange can be captured and relayed to SMB/LDAP/MSSQL targets.",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = packet.DestPort,
            Severity = WeaknessSeverity.Critical,
            ExploitPath = "ntlmrelayx.py (Impacket) relays the captured NTLM auth to an SMB share, LDAP, or MSSQL. " +
                          "If the target does not enforce SMB signing -> shell. Against LDAP -> create a machine account or configure delegation.",
            Mitigation = "Enable Extended Protection for Authentication (EPA), enforce SMB signing, enable LDAP signing/channel binding, " +
                         "and restrict NTLM via GPO: Security Settings > Local Policies > Security Options > 'Network Security: Restrict NTLM'.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // SMB Signing Detection (SMB2 Negotiate Response)
    // ============================================================

    private void CheckSmbSigning(CapturedPacket packet)
    {
        if (packet.DestPort != 445 && packet.SourcePort != 445) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 70) return;

        // Locate an SMB2 header: 0xFE 'S' 'M' 'B'
        for (int i = 0; i + 66 < payload.Length; i++)
        {
            if (payload[i] != 0xFE || payload[i + 1] != 'S' || payload[i + 2] != 'M' || payload[i + 3] != 'B')
                continue;

            // SMB2 sync header layout (offsets from header start i):
            //   +12 Command (2, LE)
            //   +16 Flags   (4, LE)  bit0 SMB2_FLAGS_SERVER_TO_REDIR = response
            ushort command = (ushort)(payload[i + 12] | (payload[i + 13] << 8));
            bool isResponse = (payload[i + 16] & 0x01) != 0;

            // We only care about the server's Negotiate RESPONSE. The server's SecurityMode
            // is authoritative for whether signing is required; the client's request is not.
            if (command != 0x0000 /* SMB2 NEGOTIATE */ || !isResponse)
            {
                break;
            }

            // SMB2 Negotiate Response body starts at i + 64. SecurityMode is at body offset +2,
            // i.e. absolute offset i + 66. (Fixed: previous code read i + 68 = DialectRevision.)
            byte securityMode = payload[i + 66];

            // SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x01
            // SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x02
            bool signingRequired = (securityMode & 0x02) != 0;

            if (!signingRequired)
            {
                string sig = $"SMB-NOSIGN-{packet.SourceIP}";
                if (MarkSeen(sig, packet.Timestamp))
                {
                    ReportWeaknessWithEvidence(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "SMB Signing",
                        Name = "SMB Signing Not Required",
                        Description = $"Server {packet.SourceIP} does not require SMB signing (SecurityMode: 0x{securityMode:X2}). " +
                                      "This allows NTLM relay attacks against it.",
                        SourceIP = packet.SourceIP ?? "",
                        DestIP = packet.DestIP ?? "",
                        Port = 445,
                        Severity = WeaknessSeverity.Critical,
                        ExploitPath = "ntlmrelayx.py relays NTLMv2 auth to this server -> code execution if the relayed account is a local admin. " +
                                      "Chain with Responder/mitm6 to trigger the authentication.",
                        Mitigation = "Enable SMB signing: GPO > Computer Configuration > Policies > Windows Settings > Security Settings > " +
                                     "Local Policies > Security Options > 'Microsoft network server: Digitally sign communications (always)' = Enabled.",
                        PacketId = packet.Id
                    }, packet.RawData);
                }
            }
            break;
        }
    }

    // ============================================================
    // ARP Anomaly Detection
    // ============================================================

    private void CheckArpAnomaly(CapturedPacket packet)
    {
        byte[] data = packet.RawData;
        if (data.Length < 42) return; // Ethernet (14) + ARP (28) minimum

        // Account for an 802.1Q VLAN tag (0x8100), same as the fragment parser does.
        int arpOffset = 14;
        ushort ethType = (ushort)((data[12] << 8) | data[13]);
        if (ethType == 0x8100)
        {
            if (data.Length < 46) return;
            arpOffset = 18;
        }

        if (arpOffset + 28 > data.Length) return;

        // Validate this is ARP over Ethernet/IPv4 before trusting fixed field offsets.
        byte hlen = data[arpOffset + 4]; // hardware address length, 6 for Ethernet
        byte plen = data[arpOffset + 5]; // protocol address length, 4 for IPv4
        if (hlen != 6 || plen != 4) return;

        ushort opcode = (ushort)((data[arpOffset + 6] << 8) | data[arpOffset + 7]);

        // Sender hardware address is the ARP field (offset +8), which is the correct source
        // for IP->MAC binding. The Ethernet source MAC can differ (itself a spoofing hint).
        string senderMac = FormatMac(data, arpOffset + 8);
        string senderIp = new IPAddress(new ReadOnlySpan<byte>(data, arpOffset + 14, 4)).ToString();
        string targetIp = new IPAddress(new ReadOnlySpan<byte>(data, arpOffset + 24, 4)).ToString();

        var pending = new List<DetectedWeakness>();

        lock (_lock)
        {
            CleanupSeenLocked(packet.Timestamp);

            // Gratuitous ARP: sender IP == target IP in a request.
            if (senderIp == targetIp && opcode == 1)
            {
                string sig = $"GARP-{senderIp}-{senderMac}";
                if (MarkSeenLocked(sig, packet.Timestamp))
                {
                    pending.Add(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "ARP Anomaly",
                        Name = "Gratuitous ARP Detected",
                        Description = $"Host {senderIp} ({senderMac}) sent a gratuitous ARP. " +
                                      "This may be a legitimate announcement or an ARP spoofing attempt.",
                        SourceIP = senderIp,
                        DestIP = targetIp,
                        Port = 0,
                        Severity = WeaknessSeverity.Medium,
                        ExploitPath = "If attacker-originated, the ARP caches of hosts on the segment are now poisoned.",
                        Mitigation = "Enable Dynamic ARP Inspection (DAI) on the switch and monitor for gratuitous ARP.",
                        PacketId = packet.Id
                    });
                }
            }

            // IP/MAC re-binding on ARP replies -> possible spoofing. Report each genuine
            // transition (including A->B->A flapping) rather than only the first change ever.
            if (opcode == 2)
            {
                if (_arpIpToMac.TryGetValue(senderIp, out string? previousMac) && previousMac != senderMac)
                {
                    // Signature encodes the specific transition so flapping is not suppressed,
                    // while an identical repeated transition is deduped within the window.
                    string sig = $"ARP-CHANGE-{senderIp}-{previousMac}->{senderMac}";
                    if (MarkSeenLocked(sig, packet.Timestamp))
                    {
                        pending.Add(new DetectedWeakness
                        {
                            Timestamp = packet.Timestamp,
                            Category = "ARP Anomaly",
                            Name = "ARP Cache Poisoning Detected",
                            Description = $"IP {senderIp} changed MAC address: {previousMac} -> {senderMac}. " +
                                          "This is consistent with an active ARP spoofing / MitM attack.",
                            SourceIP = senderIp,
                            DestIP = "",
                            Port = 0,
                            Severity = WeaknessSeverity.Critical,
                            ExploitPath = "An attacker is performing ARP spoofing to MitM the victim's traffic.",
                            Mitigation = "Verify immediately with 'arp -a'. Enable DAI on the switch and use static ARP entries for critical servers.",
                            PacketId = packet.Id
                        });
                    }
                }
                // Hard cap: ARP table in a /24 segment has at most ~254 entries,
                // but in a bridged or /16 environment it can grow. Drop oldest 25%
                // when exceeding the cap (no timestamps, so just clear the excess).
                if (_arpIpToMac.Count >= MaxArpEntries && !_arpIpToMac.ContainsKey(senderIp))
                {
                    int toRemove = _arpIpToMac.Count / 4;
                    foreach (var k in _arpIpToMac.Keys.Take(toRemove).ToList())
                        _arpIpToMac.Remove(k);
                }
                _arpIpToMac[senderIp] = senderMac;
            }
        }

        foreach (var w in pending) ReportWeakness(w);
    }

    // ============================================================
    // DHCPv6 Detection (UDP 546/547)
    // ============================================================

    private void CheckDhcpv6(CapturedPacket packet)
    {
        if (packet.DestPort != 547 && packet.SourcePort != 547 &&
            packet.DestPort != 546 && packet.SourcePort != 546) return;

        string sig = $"DHCPV6-{packet.SourceIP}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        bool isSolicit = packet.DestPort == 547;
        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "IPv6 Attack Surface",
            Name = "DHCPv6 Traffic Detected",
            Description = isSolicit
                ? $"Host {packet.SourceIP} is sending a DHCPv6 Solicit. IPv6 is enabled on this network and is exposed to the mitm6 attack."
                : $"DHCPv6 server response from {packet.SourceIP}.",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = isSolicit ? (ushort)547 : (ushort)546,
            Severity = WeaknessSeverity.High,
            ExploitPath = "mitm6 -> rogue DHCPv6 server -> set attacker as the DNS server -> relay NTLM auth -> domain compromise. " +
                          "Chain with ntlmrelayx for the full attack.",
            Mitigation = "Disable IPv6 where it is not needed (GPO or network adapter), enable DHCPv6 Guard on the switch, " +
                         "and block rogue ICMPv6 Router Advertisements (RA Guard).",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // SSDP Detection (UDP 1900)
    // ============================================================

    private void CheckSsdp(CapturedPacket packet)
    {
        if (packet.DestPort != 1900) return;

        string sig = $"SSDP-{packet.SourceIP}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Service Discovery",
            Name = "SSDP/UPnP Broadcast",
            Description = $"Host {packet.SourceIP} is sending SSDP discovery (multicast 239.255.255.250:1900). " +
                          "UPnP services may expose additional attack surface.",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = 1900,
            Severity = WeaknessSeverity.Low,
            ExploitPath = "Enumerate UPnP services -> exploit known issues (e.g. port-forwarding abuse, memory-safety bugs).",
            Mitigation = "Disable the SSDP Discovery service and disable UPnP on routers/switches.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // IP Fragment Overlap / Tiny Fragment Detection
    // ============================================================

    private void CheckIpFragmentOverlap(CapturedPacket packet)
    {
        byte[] data = packet.RawData;
        if (data.Length < 34) return; // Ethernet (14) + IPv4 (20) minimum

        int ipOffset = 14;

        // 802.1Q VLAN tag shifts the IPv4 header by 4 bytes.
        ushort ethType = (ushort)((data[12] << 8) | data[13]);
        if (ethType == 0x8100 && data.Length >= 38)
            ipOffset = 18;

        if (ipOffset + 20 > data.Length) return;

        ushort identification = (ushort)((data[ipOffset + 4] << 8) | data[ipOffset + 5]);
        ushort flagsAndFrag = (ushort)((data[ipOffset + 6] << 8) | data[ipOffset + 7]);

        bool moreFragments = (flagsAndFrag & 0x2000) != 0;  // MF bit
        int fragmentOffset = (flagsAndFrag & 0x1FFF) * 8;    // fragment offset in bytes

        // Only fragmented packets are of interest (MF=1 or offset > 0).
        if (!moreFragments && fragmentOffset == 0) return;

        int ipHeaderLen = (data[ipOffset] & 0x0F) * 4;
        ushort totalLength = (ushort)((data[ipOffset + 2] << 8) | data[ipOffset + 3]);
        int payloadLength = totalLength - ipHeaderLen;
        if (payloadLength <= 0) return;

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";
        string fragKey = $"{src}-{dst}-{identification}";

        var pending = new List<DetectedWeakness>();

        lock (_lock)
        {
            CleanupSeenLocked(packet.Timestamp);

            // Evict stale reassembly state every 30 seconds.
            if ((packet.Timestamp - _lastFragmentCleanup).TotalSeconds > 30)
            {
                var cutoff = packet.Timestamp.AddSeconds(-60);
                var staleKeys = _fragmentTracker
                    .Where(kv => kv.Value.All(f => f.time < cutoff))
                    .Select(kv => kv.Key).ToList();
                foreach (var k in staleKeys) _fragmentTracker.Remove(k);
                _lastFragmentCleanup = packet.Timestamp;

                // Hard cap after time-based eviction.
                if (_fragmentTracker.Count > MaxFragmentEntries)
                {
                    int toRemove = _fragmentTracker.Count - MaxFragmentEntries + MaxFragmentEntries / 4;
                    foreach (var k in _fragmentTracker.Keys.Take(toRemove).ToList())
                        _fragmentTracker.Remove(k);
                }
            }

            if (!_fragmentTracker.TryGetValue(fragKey, out var fragments))
            {
                if (_fragmentTracker.Count >= MaxFragmentEntries) return;
                fragments = new List<(int offset, int length, DateTime time)>();
                _fragmentTracker[fragKey] = fragments;
            }

            // Check overlap against previously seen fragments of the same datagram.
            foreach (var existing in fragments)
            {
                int existingEnd = existing.offset + existing.length;
                int newEnd = fragmentOffset + payloadLength;

                if (fragmentOffset < existingEnd && newEnd > existing.offset)
                {
                    int overlapStart = Math.Max(fragmentOffset, existing.offset);
                    int overlapEnd = Math.Min(newEnd, existingEnd);
                    int overlapBytes = overlapEnd - overlapStart;

                    string sig = $"FRAG-OVERLAP-{src}-{dst}-{identification}";
                    if (MarkSeenLocked(sig, packet.Timestamp))
                    {
                        pending.Add(new DetectedWeakness
                        {
                            Timestamp = packet.Timestamp,
                            Category = "IP Fragment Attack",
                            Name = "IP Overlapping Fragments Detected",
                            Description = $"Overlapping fragments from {src} -> {dst} (IP ID: 0x{identification:X4}). " +
                                          $"A fragment at offset {fragmentOffset} ({payloadLength}B) overlaps one at offset {existing.offset} ({existing.length}B) " +
                                          $"by {overlapBytes} bytes. This technique overwrites the TCP header (port/flags) after inspection to evade firewalls/IDS.",
                            SourceIP = src,
                            DestIP = dst,
                            Port = 0,
                            Severity = WeaknessSeverity.Critical,
                            ExploitPath = "Overlapping fragments rewrite the TCP destination port after the firewall has inspected the first fragment (e.g. 80 -> 4444), " +
                                          "or overwrite payload to bypass signature-based IDS. Divergent reassembly policies between the firewall (first-wins) and the " +
                                          "target OS (last-wins) create the evasion gap. Tools: fragroute, Scapy, nmap --mtu.",
                            Mitigation = "Drop overlapping fragments at the firewall (Cisco 'fragment-guard', Palo Alto zone protection profile). " +
                                         "Enable full fragment reassembly on the IDS/IPS before inspection, and drop unnecessary fragmented traffic.",
                            PacketId = packet.Id
                        });
                    }
                    break;
                }
            }

            fragments.Add((fragmentOffset, payloadLength, packet.Timestamp));

            // Tiny first fragment (< 68 bytes, RFC 791 minimum). Splits the TCP header across
            // fragments so a stateless IDS/firewall cannot read the destination port or flags.
            if (fragmentOffset == 0 && payloadLength < 68)
            {
                string sig = $"TINY-FRAG-{src}-{dst}";
                if (MarkSeenLocked(sig, packet.Timestamp))
                {
                    pending.Add(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "IP Fragment Attack",
                        Name = "Tiny IP Fragment Detected",
                        Description = $"The first fragment from {src} -> {dst} carries only {payloadLength} bytes of payload, " +
                                      "below the 68-byte minimum (RFC 791). The TCP header is split, so an IDS/firewall cannot read the " +
                                      "destination port or TCP flags from this fragment.",
                        SourceIP = src,
                        DestIP = dst,
                        Port = 0,
                        Severity = WeaknessSeverity.High,
                        ExploitPath = "Tiny fragments split the TCP header: fragment 1 carries only the source port, fragment 2 carries the destination port + flags. " +
                                      "A stateless firewall inspects only fragment 1 and never sees the true destination port. Tools: nmap -f, fragroute.",
                        Mitigation = "Drop first fragments with payload < 68 bytes (Cisco ACL: 'deny tcp any any fragments'), or enable full reassembly before inspection.",
                        PacketId = packet.Id
                    });
                }
            }
        }

        foreach (var w in pending) ReportWeakness(w);
    }

    // ============================================================
    // Slowloris HTTP DoS Detection
    // ============================================================

    private void CheckSlowloris(CapturedPacket packet)
    {
        if (packet.DestPort != 80 && packet.DestPort != 8080 && packet.DestPort != 8443 &&
            packet.DestPort != 443 && packet.DestPort != 8888) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length == 0) return;

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";
        // Per-connection key (4-tuple). Slowloris opens many parallel half-open connections;
        // keeping state per connection is what makes the pattern visible.
        string connKey = $"{src}:{packet.SourcePort}-{dst}:{packet.DestPort}";

        string payloadStr;
        try { payloadStr = Encoding.ASCII.GetString(payload[..Math.Min(payload.Length, 500)]); }
        catch (Exception ex) { OnError?.Invoke(ex); return; }

        bool hasHttpMethod = payloadStr.StartsWith("GET ", StringComparison.Ordinal)
                          || payloadStr.StartsWith("POST ", StringComparison.Ordinal)
                          || payloadStr.StartsWith("HEAD ", StringComparison.Ordinal)
                          || payloadStr.StartsWith("PUT ", StringComparison.Ordinal)
                          || payloadStr.StartsWith("DELETE ", StringComparison.Ordinal)
                          || payloadStr.StartsWith("OPTIONS ", StringComparison.Ordinal);

        bool hasCompleteHeaders = payloadStr.Contains("\r\n\r\n");

        var pending = new List<DetectedWeakness>();

        lock (_lock)
        {
            CleanupSeenLocked(packet.Timestamp);

            // Evict idle connection state every 60 seconds.
            if ((packet.Timestamp - _lastSlowlorisCleanup).TotalSeconds > 60)
            {
                var cutoff = packet.Timestamp.AddMinutes(-5);
                var staleKeys = _slowlorisTracker
                    .Where(kv => kv.Value.LastSeen < cutoff)
                    .Select(kv => kv.Key).ToList();
                foreach (var k in staleKeys) _slowlorisTracker.Remove(k);
                _lastSlowlorisCleanup = packet.Timestamp;

                // Hard cap after time-based eviction.
                if (_slowlorisTracker.Count > MaxSlowlorisEntries)
                {
                    int toRemove = _slowlorisTracker.Count - MaxSlowlorisEntries + MaxSlowlorisEntries / 4;
                    foreach (var k in _slowlorisTracker.OrderBy(kv => kv.Value.LastSeen).Take(toRemove).Select(kv => kv.Key).ToList())
                        _slowlorisTracker.Remove(k);
                }
            }

            if (!_slowlorisTracker.TryGetValue(connKey, out var state))
            {
                if (_slowlorisTracker.Count >= MaxSlowlorisEntries) return;
                state = new SlowlorisState { FirstSeen = packet.Timestamp };
                _slowlorisTracker[connKey] = state;
            }
            state.LastSeen = packet.Timestamp;
            state.TotalPackets++;

            if (hasHttpMethod)
            {
                state.RequestCount++;
                if (!hasCompleteHeaders)
                    state.IncompleteHeaderCount++;
            }
            else if (payload.Length < 50 && !hasCompleteHeaders)
            {
                // Slowloris keep-alive: a single dripped header line such as "X-a: b\r\n".
                if (payloadStr.Contains(": ") && payloadStr.Contains("\r\n") && !payloadStr.Contains("\r\n\r\n"))
                    state.DripHeaderCount++;
            }

            double durationSec = (state.LastSeen - state.FirstSeen).TotalSeconds;

            // Pattern 1: many incomplete requests over a sustained period.
            if (state.IncompleteHeaderCount >= 5 && durationSec > 30)
            {
                string sig = $"SLOWLORIS-{connKey}";
                if (MarkSeenLocked(sig, packet.Timestamp))
                {
                    pending.Add(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "HTTP DoS Attack",
                        Name = "Slowloris HTTP Attack Detected",
                        Description = $"Source {src}:{packet.SourcePort} sent {state.IncompleteHeaderCount} HTTP requests with incomplete headers " +
                                      $"(missing \\r\\n\\r\\n) to {dst}:{packet.DestPort} over {durationSec:F0}s. " +
                                      "Slowloris holds connections open by sending HTTP headers one line at a time and never completing the request, " +
                                      "exhausting the server's connection/thread pool.",
                        SourceIP = src,
                        DestIP = dst,
                        Port = packet.DestPort,
                        Severity = WeaknessSeverity.High,
                        ExploitPath = "slowloris.py opens hundreds of connections, each sending a partial HTTP header every few seconds. " +
                                      "Apache (prefork/worker) is especially vulnerable due to MaxRequestWorkers; IIS and Nginx (event-driven) are more resilient.",
                        Mitigation = "Lower the request header timeout (Apache: RequestReadTimeout header=10-20). Limit concurrent connections per IP " +
                                     "(iptables connlimit, mod_qos). Front the server with a reverse proxy (Nginx/HAProxy) with short timeouts. " +
                                     "Enable mod_reqtimeout or mod_antiloris.",
                        PacketId = packet.Id
                    });
                }
            }

            // Pattern 2: sustained drip headers on a single connection (classic Slowloris keep-alive).
            if (state.DripHeaderCount >= 10 && durationSec > 20)
            {
                string sig = $"SLOWLORIS-DRIP-{connKey}";
                if (MarkSeenLocked(sig, packet.Timestamp))
                {
                    pending.Add(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "HTTP DoS Attack",
                        Name = "Slowloris Drip Header Pattern",
                        Description = $"Source {src}:{packet.SourcePort} sent {state.DripHeaderCount} dripped HTTP header lines to {dst}:{packet.DestPort} " +
                                      $"over {durationSec:F0}s, each packet carrying a single header line (< 50 bytes). " +
                                      "This is the Slowloris keep-alive pattern: sending 'X-a: b\\r\\n' every few seconds so the connection never times out.",
                        SourceIP = src,
                        DestIP = dst,
                        Port = packet.DestPort,
                        Severity = WeaknessSeverity.High,
                        ExploitPath = "Drip headers keep the connection alive indefinitely; many such connections cause denial of service. " +
                                      "Variants: R.U.D.Y (slow POST body), Apache Range Header attack.",
                        Mitigation = "Set a minimum data-rate threshold (Apache: RequestReadTimeout header=10-20 MinRate=500). Rate-limit per IP. " +
                                     "Add a WAF rule to detect incomplete-request patterns.",
                        PacketId = packet.Id
                    });
                }
            }
        }

        foreach (var w in pending) ReportWeakness(w);
    }

    // ============================================================
    // Role conflict helper (architectural suggestion #2)
    // ============================================================

    /// <summary>
    /// Detects when a second source claims an authoritative role that was already held by
    /// a different source. Used by FHRP, rogue DHCP, STP root, rogue RA detectors.
    /// Returns (isConflict, previousClaimant) under _lock.
    /// </summary>
    private (bool conflict, string? previous) DetectRoleConflictLocked(string role, string claimant)
    {
        if (_roleAuthority.TryGetValue(role, out var prev) && prev != claimant)
        {
            _roleAuthority[role] = claimant; // update to latest
            return (true, prev);
        }

        // Hard cap: role table is small (one entry per FHRP group/DHCP scope/STP root),
        // but a flood of crafted packets could grow it. Drop oldest 25% on overflow.
        if (_roleAuthority.Count >= MaxRoleEntries && !_roleAuthority.ContainsKey(role))
        {
            int toRemove = _roleAuthority.Count / 4;
            foreach (var k in _roleAuthority.Keys.Take(toRemove).ToList())
                _roleAuthority.Remove(k);
        }

        _roleAuthority[role] = claimant;
        return (false, null);
    }

    // ============================================================
    // [A] CDP Recon Intel (SNAP proto 0x2000, dst 01:00:0C:CC:CC:CC)
    // ============================================================

    private void CheckCdp(CapturedPacket packet)
    {
        byte[] data = packet.RawData;
        if (data.Length < 26) return;

        // Check dst MAC = 01:00:0C:CC:CC:CC
        if (data[0] != 0x01 || data[1] != 0x00 || data[2] != 0x0C ||
            data[3] != 0xCC || data[4] != 0xCC || data[5] != 0xCC) return;

        // SNAP header after LLC: check for OUI 00:00:0C and protocol 0x2000
        // LLC is at offset 14 (after Ethernet header), SNAP OUI at 17, protocol at 20
        int llcOffset = 14;
        ushort ethType = (ushort)((data[12] << 8) | data[13]);
        if (ethType == 0x8100) llcOffset = 18; // skip VLAN tag

        if (llcOffset + 8 > data.Length) return;

        // LLC: DSAP=0xAA, SSAP=0xAA, Control=0x03 (SNAP)
        if (data[llcOffset] != 0xAA || data[llcOffset + 1] != 0xAA || data[llcOffset + 2] != 0x03) return;

        // SNAP OUI: 00:00:0C (Cisco)
        if (data[llcOffset + 3] != 0x00 || data[llcOffset + 4] != 0x00 || data[llcOffset + 5] != 0x0C) return;

        // SNAP protocol: 0x2000 = CDP
        ushort snapProto = (ushort)((data[llcOffset + 6] << 8) | data[llcOffset + 7]);
        if (snapProto != 0x2000) return;

        string srcMac = FormatMac(data, 6);
        string sig = $"CDP-{srcMac}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        // Parse CDP TLVs for intel (best-effort)
        int cdpStart = llcOffset + 8 + 4; // skip SNAP header + CDP version(1) + TTL(1) + checksum(2)
        var intel = ParseCdpTlvs(data, cdpStart);

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Recon Intel",
            Name = "CDP (Cisco Discovery Protocol) Leak",
            Description = $"Device {srcMac} is broadcasting CDP." +
                          (intel.deviceId != null ? $" Device: {intel.deviceId}." : "") +
                          (intel.platform != null ? $" Platform: {intel.platform}." : "") +
                          (intel.mgmtIp != null ? $" Management IP: {intel.mgmtIp}." : "") +
                          (intel.nativeVlan != null ? $" Native VLAN: {intel.nativeVlan}." : "") +
                          (intel.portId != null ? $" Port: {intel.portId}." : "") +
                          " CDP leaks device model, IOS version, management IP, and native VLAN to any listener on the segment.",
            SourceIP = intel.mgmtIp ?? "",
            DestIP = "",
            Port = 0,
            Severity = WeaknessSeverity.Medium,
            ExploitPath = "Passive recon: harvest device models, IOS versions (CVE lookup), management IPs (SSH/SNMP targets), " +
                          "native VLAN (VLAN hopping via DTP or 802.1Q double-tag), and port IDs (physical topology mapping). " +
                          "No packets need to be sent.",
            Mitigation = "Disable CDP on all access-facing ports: 'no cdp enable' per interface. " +
                         "Use LLDP selectively if neighbor discovery is required.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // [A] LLDP Recon Intel (EtherType 0x88CC)
    // ============================================================

    private void CheckLldp(CapturedPacket packet)
    {
        byte[] data = packet.RawData;
        if (data.Length < 20) return;

        // Dst MAC should be 01:80:C2:00:00:0E (or 01:80:C2:00:00:00/03)
        string srcMac = FormatMac(data, 6);

        string sig = $"LLDP-{srcMac}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        // Parse LLDP TLVs (best-effort)
        int tlvStart = 14; // after Ethernet header
        ushort ethType = (ushort)((data[12] << 8) | data[13]);
        if (ethType == 0x8100) tlvStart = 18;
        var intel = ParseLldpTlvs(data, tlvStart);

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Recon Intel",
            Name = "LLDP (Link Layer Discovery Protocol) Leak",
            Description = $"Device {srcMac} is broadcasting LLDP." +
                          (intel.systemName != null ? $" System: {intel.systemName}." : "") +
                          (intel.systemDesc != null ? $" Description: {intel.systemDesc}." : "") +
                          (intel.mgmtIp != null ? $" Management IP: {intel.mgmtIp}." : "") +
                          (intel.portId != null ? $" Port: {intel.portId}." : "") +
                          " LLDP exposes system identity, management address, and port information.",
            SourceIP = intel.mgmtIp ?? "",
            DestIP = "",
            Port = 0,
            Severity = WeaknessSeverity.Medium,
            ExploitPath = "Passive recon: system names reveal hostnames and roles, management IPs are SSH/SNMP targets, " +
                          "system descriptions expose OS versions for CVE matching. No traffic needs to be generated.",
            Mitigation = "Disable LLDP on access-facing ports. On Cisco: 'no lldp transmit' per interface. " +
                         "On Juniper: 'set protocols lldp interface <if> disable'.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // [B] DTP Detection (SNAP proto 0x2004, dst 01:00:0C:CC:CC:CC)
    // ============================================================

    private void CheckDtp(CapturedPacket packet)
    {
        byte[] data = packet.RawData;
        if (data.Length < 26) return;

        // dst MAC = 01:00:0C:CC:CC:CC
        if (data[0] != 0x01 || data[1] != 0x00 || data[2] != 0x0C ||
            data[3] != 0xCC || data[4] != 0xCC || data[5] != 0xCC) return;

        int llcOffset = 14;
        ushort ethType = (ushort)((data[12] << 8) | data[13]);
        if (ethType == 0x8100) llcOffset = 18;
        if (llcOffset + 8 > data.Length) return;

        // SNAP: 0xAA 0xAA 0x03 + OUI 00:00:0C
        if (data[llcOffset] != 0xAA || data[llcOffset + 1] != 0xAA || data[llcOffset + 2] != 0x03) return;
        if (data[llcOffset + 3] != 0x00 || data[llcOffset + 4] != 0x00 || data[llcOffset + 5] != 0x0C) return;

        ushort snapProto = (ushort)((data[llcOffset + 6] << 8) | data[llcOffset + 7]);
        if (snapProto != 0x2004) return;

        string srcMac = FormatMac(data, 6);
        string sig = $"DTP-{srcMac}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "VLAN Hopping Surface",
            Name = "DTP (Dynamic Trunking Protocol) Detected",
            Description = $"Switch port connected to {srcMac} is negotiating trunk mode via DTP. " +
                          "An attacker can spoof a DTP Desirable frame to force the port into trunk mode, " +
                          "gaining access to all VLANs carried on that trunk.",
            SourceIP = "",
            DestIP = "",
            Port = 0,
            Severity = WeaknessSeverity.Critical,
            ExploitPath = "Yersinia or custom Scapy: send DTP Desirable -> port becomes trunk -> " +
                          "attacker sends 802.1Q-tagged frames to any VLAN. " +
                          "Chain with ARP spoofing inside the target VLAN for MitM.",
            Mitigation = "Set all access ports to 'switchport mode access' and 'switchport nonegotiate'. " +
                         "Trunk ports should be explicitly configured as 'switchport mode trunk' with 'switchport nonegotiate'. " +
                         "Prune unnecessary VLANs from trunks.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // [C] STP BPDU Detection (dst 01:80:C2:00:00:00, LLC 0x42)
    // ============================================================

    private void CheckStpBpdu(CapturedPacket packet)
    {
        byte[] data = packet.RawData;
        if (data.Length < 21) return;

        // dst MAC = 01:80:C2:00:00:00
        if (data[0] != 0x01 || data[1] != 0x80 || data[2] != 0xC2 ||
            data[3] != 0x00 || data[4] != 0x00 || data[5] != 0x00) return;

        int llcOffset = 14;
        ushort ethType = (ushort)((data[12] << 8) | data[13]);
        if (ethType == 0x8100) llcOffset = 18;
        if (llcOffset + 3 > data.Length) return;

        // LLC: DSAP=0x42, SSAP=0x42
        if (data[llcOffset] != 0x42 || data[llcOffset + 1] != 0x42) return;

        string srcMac = FormatMac(data, 6);

        // Parse root bridge ID from BPDU if possible (offset +11 from LLC for config BPDU)
        string? rootBridgeId = null;
        int bpduStart = llcOffset + 3; // after LLC header
        if (bpduStart + 35 <= data.Length)
        {
            // Root Bridge ID is at BPDU offset +5..+12 (8 bytes: priority 2 + MAC 6)
            ushort rootPriority = (ushort)((data[bpduStart + 5] << 8) | data[bpduStart + 6]);
            string rootMac = FormatMac(data, bpduStart + 7);
            rootBridgeId = $"{rootPriority}/{rootMac}";
        }

        // Detect role conflict: a second bridge claiming root on this segment
        var pending = new List<DetectedWeakness>();
        lock (_lock)
        {
            CleanupSeenLocked(packet.Timestamp);

            string sig = $"STP-BPDU-{srcMac}";
            if (MarkSeenLocked(sig, packet.Timestamp))
            {
                pending.Add(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "L2 Attack Surface",
                    Name = "STP BPDU Detected on Segment",
                    Description = $"Switch {srcMac} is sending STP BPDUs on this segment" +
                                  (rootBridgeId != null ? $" (current root: {rootBridgeId})" : "") +
                                  ". If BPDU Guard is not enabled, an attacker can send a superior BPDU " +
                                  "to become the root bridge and MitM all L2 traffic.",
                    SourceIP = "",
                    DestIP = "",
                    Port = 0,
                    Severity = WeaknessSeverity.High,
                    ExploitPath = "Yersinia or Scapy: send BPDU with priority 0 -> become root bridge -> " +
                                  "all traffic routes through attacker's bridge -> passive sniffing or active MitM. " +
                                  "STP convergence takes ~30s (or ~1s with RSTP).",
                    Mitigation = "Enable BPDU Guard on all access ports: 'spanning-tree bpduguard enable'. " +
                                 "Enable Root Guard on designated ports toward the access layer. " +
                                 "Consider deploying 802.1s (MST) with a known root bridge priority.",
                    PacketId = packet.Id
                });
            }

            // Track root bridge conflict
            if (rootBridgeId != null)
            {
                var (conflict, prevRoot) = DetectRoleConflictLocked("STP-ROOT", rootBridgeId);
                if (conflict)
                {
                    string conflictSig = $"STP-ROOT-CONFLICT-{rootBridgeId}";
                    if (MarkSeenLocked(conflictSig, packet.Timestamp))
                    {
                        pending.Add(new DetectedWeakness
                        {
                            Timestamp = packet.Timestamp,
                            Category = "L2 Attack Surface",
                            Name = "STP Root Bridge Change Detected",
                            Description = $"STP root bridge changed: {prevRoot} -> {rootBridgeId}. " +
                                          "This may indicate a root bridge takeover attack or legitimate topology change.",
                            SourceIP = "",
                            DestIP = "",
                            Port = 0,
                            Severity = WeaknessSeverity.Critical,
                            ExploitPath = "If attacker-initiated, all L2 traffic now flows through the rogue root bridge.",
                            Mitigation = "Verify immediately. Enable Root Guard and BPDU Guard on access ports.",
                            PacketId = packet.Id
                        });
                    }
                }
            }
        }
        foreach (var w in pending) ReportWeakness(w);
    }

    // ============================================================
    // [D] HSRP Detection (UDP 1985)
    // ============================================================

    private void CheckHsrp(CapturedPacket packet)
    {
        if (packet.DestPort != 1985 && packet.SourcePort != 1985) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 20) return;

        string src = packet.SourceIP ?? "";

        // HSRP version: byte 0. Group: byte 1. State: byte 2. Priority: byte 5 (v1)
        byte version = payload[0];
        byte state = payload[2];
        byte priority = payload[5];

        // HSRPv1: auth at offset 8, 8 bytes (default: "cisco\0\0\0")
        string? authString = null;
        if (version == 0 && payload.Length >= 16)
        {
            try
            {
                var authBytes = payload.Slice(8, 8);
                authString = Encoding.ASCII.GetString(authBytes).TrimEnd('\0');
            }
            catch { /* ignore parse errors */ }
        }

        var pending = new List<DetectedWeakness>();
        lock (_lock)
        {
            CleanupSeenLocked(packet.Timestamp);

            string sig = $"HSRP-{src}";
            if (MarkSeenLocked(sig, packet.Timestamp))
            {
                string stateStr = state switch { 0 => "Initial", 1 => "Learn", 2 => "Listen", 4 => "Speak", 8 => "Standby", 16 => "Active", _ => $"0x{state:X2}" };
                pending.Add(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "FHRP Attack Surface",
                    Name = "HSRP Traffic Detected",
                    Description = $"Router {src} is participating in HSRP (state: {stateStr}, priority: {priority})" +
                                  (authString != null ? $", auth string: '{authString}'" : "") +
                                  (authString == "cisco" ? " (DEFAULT PASSWORD)" : "") +
                                  ". An attacker can send HSRP with higher priority to take over the virtual gateway.",
                    SourceIP = src,
                    DestIP = packet.DestIP ?? "",
                    Port = 1985,
                    Severity = WeaknessSeverity.Critical,
                    ExploitPath = "Yersinia/Scapy: send HSRP Hello with priority 255 + correct auth (default 'cisco') -> " +
                                  "become Active router -> all default gateway traffic routes through attacker -> MitM." +
                                  (authString == "cisco" ? " AUTH IS DEFAULT — exploitation is trivial." : ""),
                    Mitigation = "Use HSRP MD5 authentication (key-chain). Set high priority on legitimate routers. " +
                                 "Filter HSRP (UDP 1985) on access ports via ACL.",
                    PacketId = packet.Id
                });
            }

            // Track FHRP role conflict
            var (conflict, prev) = DetectRoleConflictLocked($"HSRP-GW-{packet.DestIP}", src);
            if (conflict)
            {
                string conflictSig = $"HSRP-CONFLICT-{src}";
                if (MarkSeenLocked(conflictSig, packet.Timestamp))
                {
                    pending.Add(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "FHRP Attack Surface",
                        Name = "HSRP Gateway Conflict",
                        Description = $"A second HSRP speaker appeared: {prev} was authoritative, now {src} is also claiming the role. " +
                                      "This may indicate a gateway takeover attack.",
                        SourceIP = src,
                        DestIP = packet.DestIP ?? "",
                        Port = 1985,
                        Severity = WeaknessSeverity.Critical,
                        ExploitPath = "If attacker-originated, default gateway traffic is now being intercepted.",
                        Mitigation = "Verify legitimate HSRP peers. Enable MD5 authentication.",
                        PacketId = packet.Id
                    });
                }
            }
        }
        foreach (var w in pending) ReportWeakness(w);
    }

    // ============================================================
    // [D] VRRP Detection (IP protocol 112)
    // ============================================================

    private void CheckVrrp(CapturedPacket packet)
    {
        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 8) return;

        string src = packet.SourceIP ?? "";

        // VRRP header: version+type (byte 0), VRID (byte 1), priority (byte 2)
        byte vridField = payload[1];
        byte priority = payload[2];
        byte versionType = payload[0];
        int version = (versionType >> 4) & 0x0F;

        string sig = $"VRRP-{src}-{vridField}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "FHRP Attack Surface",
            Name = "VRRP Traffic Detected",
            Description = $"Router {src} is participating in VRRPv{version} (VRID: {vridField}, priority: {priority}). " +
                          "An attacker can inject VRRP advertisements with priority 255 to become the Master router.",
            SourceIP = src,
            DestIP = packet.DestIP ?? "",
            Port = 0,
            Severity = WeaknessSeverity.High,
            ExploitPath = "Scapy/Loki: send VRRP Advertisement with priority 255 -> become Master -> " +
                          "intercept all default gateway traffic. VRRPv2 has no authentication by default.",
            Mitigation = "Use VRRP authentication (MD5 for VRRPv3, plain-text/HMAC for VRRPv2). " +
                         "Filter IP protocol 112 on access ports. Set preempt-delay to slow takeover.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // [D] GLBP Detection (UDP 3222)
    // ============================================================

    private void CheckGlbp(CapturedPacket packet)
    {
        if (packet.DestPort != 3222 && packet.SourcePort != 3222) return;

        string src = packet.SourceIP ?? "";
        string sig = $"GLBP-{src}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "FHRP Attack Surface",
            Name = "GLBP Traffic Detected",
            Description = $"Router {src} is participating in GLBP (Gateway Load Balancing Protocol). " +
                          "GLBP assigns virtual MACs to multiple routers; an attacker can claim AVG (Active Virtual Gateway) " +
                          "or inject AVF (Active Virtual Forwarder) entries to intercept a portion of traffic.",
            SourceIP = src,
            DestIP = packet.DestIP ?? "",
            Port = 3222,
            Severity = WeaknessSeverity.High,
            ExploitPath = "Yersinia/Scapy: claim AVG with higher priority or inject AVF with attacker MAC -> " +
                          "a fraction (or all) of gateway traffic routes through attacker. " +
                          "GLBP is Cisco-proprietary and rarely authenticated.",
            Mitigation = "Use GLBP MD5 authentication. Filter UDP 3222 on access ports. " +
                         "Consider migrating to HSRP or VRRP with proper authentication.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // [E] Rogue DHCPv4 Detection (UDP 67/68)
    // ============================================================

    private void CheckDhcpv4Rogue(CapturedPacket packet)
    {
        // DHCP server responses come FROM port 67
        if (packet.SourcePort != 67) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 240) return; // minimum DHCP message

        // BOOTP op: 2 = reply (server -> client)
        if (payload[0] != 2) return;

        // Extract server identifier from option 54 if present
        string serverIp = packet.SourceIP ?? "";
        string? optServerIp = TryParseDhcpOption54(payload);
        string serverId = optServerIp ?? serverIp;

        var pending = new List<DetectedWeakness>();
        lock (_lock)
        {
            CleanupSeenLocked(packet.Timestamp);

            // Evict stale DHCP servers
            var cutoff = packet.Timestamp.AddMinutes(-10);
            var stale = _dhcpv4Servers.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
            foreach (var k in stale) _dhcpv4Servers.Remove(k);

            // Hard cap: legitimate networks have a handful of DHCP servers.
            // A flood of spoofed DHCP replies could grow this dictionary.
            if (_dhcpv4Servers.Count >= MaxDhcpv4Servers && !_dhcpv4Servers.ContainsKey(serverId))
            {
                int toRemove = _dhcpv4Servers.Count / 4;
                foreach (var k in _dhcpv4Servers.OrderBy(kv => kv.Value).Take(toRemove).Select(kv => kv.Key).ToList())
                    _dhcpv4Servers.Remove(k);
            }

            _dhcpv4Servers[serverId] = packet.Timestamp;

            // If we see more than one DHCP server, flag rogue DHCP
            if (_dhcpv4Servers.Count >= 2)
            {
                string allServers = string.Join(", ", _dhcpv4Servers.Keys);
                string sig = $"ROGUE-DHCP-{allServers}";
                if (MarkSeenLocked(sig, packet.Timestamp))
                {
                    pending.Add(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "Rogue Service",
                        Name = "Multiple DHCP Servers Detected (Possible Rogue)",
                        Description = $"Multiple DHCPv4 servers detected on the segment: {allServers}. " +
                                      "A rogue DHCP server can push attacker-controlled DNS (option 6) and gateway (option 3) " +
                                      "to clients, enabling full MitM.",
                        SourceIP = serverId,
                        DestIP = packet.DestIP ?? "",
                        Port = 67,
                        Severity = WeaknessSeverity.Critical,
                        ExploitPath = "Rogue DHCP server (Ettercap, Responder, or custom): push attacker as default gateway (option 3) " +
                                      "and DNS server (option 6) -> MitM all client traffic. " +
                                      "DHCP starvation (gobbler) first to exhaust legitimate leases, then serve rogue offers.",
                        Mitigation = "Enable DHCP Snooping on the switch: only trusted (uplink) ports may serve DHCP. " +
                                     "Limit DHCP rate on untrusted ports. Deploy 802.1X for port-level access control.",
                        PacketId = packet.Id
                    });
                }
            }
            else
            {
                // Single server — just log for recon
                string sig = $"DHCPV4-SERVER-{serverId}";
                if (MarkSeenLocked(sig, packet.Timestamp))
                {
                    pending.Add(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "Recon Intel",
                        Name = "DHCPv4 Server Identified",
                        Description = $"DHCPv4 server at {serverId} is serving leases on this segment.",
                        SourceIP = serverId,
                        DestIP = packet.DestIP ?? "",
                        Port = 67,
                        Severity = WeaknessSeverity.Info,
                        ExploitPath = "If DHCP Snooping is not enabled, a rogue DHCP server on an access port can race this server.",
                        Mitigation = "Enable DHCP Snooping; mark this server's port as trusted.",
                        PacketId = packet.Id
                    });
                }
            }
        }
        foreach (var w in pending) ReportWeakness(w);
    }

    // ============================================================
    // [F] IPv6 Rogue Router Advertisement (ICMPv6 type 134)
    // ============================================================

    private void CheckIpv6RogueRa(CapturedPacket packet)
    {
        byte[] data = packet.RawData;
        // IPv6: EtherType 0x86DD, IPv6 header 40 bytes after Ethernet
        int ipv6Offset = 14;
        ushort ethType = (ushort)((data[12] << 8) | data[13]);
        if (ethType == 0x8100) ipv6Offset = 18;
        if (ipv6Offset + 40 > data.Length) return;

        // Next Header at offset +6 in IPv6; ICMPv6 = 58
        byte nextHeader = data[ipv6Offset + 6];
        if (nextHeader != 58) return;

        int icmpv6Offset = ipv6Offset + 40;
        if (icmpv6Offset + 4 > data.Length) return;

        // ICMPv6 type 134 = Router Advertisement
        byte icmpType = data[icmpv6Offset];
        if (icmpType != 134) return;

        string src = packet.SourceIP ?? "";

        var pending = new List<DetectedWeakness>();
        lock (_lock)
        {
            CleanupSeenLocked(packet.Timestamp);

            string sig = $"IPV6-RA-{src}";
            if (MarkSeenLocked(sig, packet.Timestamp))
            {
                pending.Add(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "IPv6 Attack Surface",
                    Name = "IPv6 Router Advertisement Detected",
                    Description = $"Router {src} is sending IPv6 Router Advertisements. " +
                                  "A rogue RA can set the attacker as the default IPv6 gateway and DNS server (RDNSS option), " +
                                  "hijacking traffic from all IPv6-enabled hosts on the segment.",
                    SourceIP = src,
                    DestIP = packet.DestIP ?? "",
                    Port = 0,
                    Severity = WeaknessSeverity.High,
                    ExploitPath = "fake_router6 / Scapy: send RA with high Router Preference + RDNSS pointing to attacker -> " +
                                  "hosts prefer IPv6 gateway -> all DNS and default traffic routes through attacker. " +
                                  "Chain with mitm6 + ntlmrelayx for AD compromise.",
                    Mitigation = "Enable RA Guard on the switch (access ports). Deploy IPv6 ACLs to allow RAs only from known routers. " +
                                 "Disable IPv6 via GPO where it is not required.",
                    PacketId = packet.Id
                });
            }

            var (conflict, prev) = DetectRoleConflictLocked("IPV6-ROUTER", src);
            if (conflict)
            {
                string conflictSig = $"IPV6-RA-CONFLICT-{src}";
                if (MarkSeenLocked(conflictSig, packet.Timestamp))
                {
                    pending.Add(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "IPv6 Attack Surface",
                        Name = "Multiple IPv6 Routers Detected (Possible Rogue RA)",
                        Description = $"A second IPv6 router appeared: previously {prev}, now also {src}. " +
                                      "This is consistent with a rogue RA attack (fake_router6 / mitm6).",
                        SourceIP = src,
                        DestIP = packet.DestIP ?? "",
                        Port = 0,
                        Severity = WeaknessSeverity.Critical,
                        ExploitPath = "If attacker-originated, IPv6-enabled hosts may already be routing through the rogue gateway.",
                        Mitigation = "Verify legitimate IPv6 routers immediately. Enable RA Guard.",
                        PacketId = packet.Id
                    });
                }
            }
        }
        foreach (var w in pending) ReportWeakness(w);
    }

    // ============================================================
    // [F] NDP Spoofing (ICMPv6 type 136 Neighbor Advertisement)
    // ============================================================

    private void CheckNdpSpoof(CapturedPacket packet)
    {
        byte[] data = packet.RawData;
        int ipv6Offset = 14;
        ushort ethType = (ushort)((data[12] << 8) | data[13]);
        if (ethType == 0x8100) ipv6Offset = 18;
        if (ipv6Offset + 40 > data.Length) return;

        byte nextHeader = data[ipv6Offset + 6];
        if (nextHeader != 58) return;

        int icmpv6Offset = ipv6Offset + 40;
        if (icmpv6Offset + 8 > data.Length) return;

        // ICMPv6 type 136 = Neighbor Advertisement
        byte icmpType = data[icmpv6Offset];
        if (icmpType != 136) return;

        // Flags: byte 4 of ICMPv6 body. Override flag = bit 5 (0x20)
        byte flags = data[icmpv6Offset + 4];
        bool overrideFlag = (flags & 0x20) != 0;

        if (!overrideFlag) return; // only unsolicited NAs with Override are suspicious

        string src = packet.SourceIP ?? "";
        string sig = $"NDP-OVERRIDE-{src}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "IPv6 Attack Surface",
            Name = "NDP Neighbor Advertisement with Override Flag",
            Description = $"Host {src} sent an unsolicited Neighbor Advertisement with the Override flag set. " +
                          "This is the IPv6 equivalent of gratuitous ARP and can be used to poison neighbor caches " +
                          "(IPv6 ARP spoofing).",
            SourceIP = src,
            DestIP = packet.DestIP ?? "",
            Port = 0,
            Severity = WeaknessSeverity.High,
            ExploitPath = "parasite6 / Scapy: send NA with Override for victim's IPv6 -> poison neighbor cache -> MitM. " +
                          "NDP spoofing is structurally identical to ARP spoofing but operates at the IPv6 layer.",
            Mitigation = "Enable ND Inspection (Cisco) or RA Guard with SEND (SEcure Neighbor Discovery, RFC 3971). " +
                         "Monitor neighbor tables for unexpected changes.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // [G] SNMP v1/v2c Community String Detection (UDP 161/162)
    // ============================================================

    private void CheckSnmpCommunity(CapturedPacket packet)
    {
        if (packet.DestPort != 161 && packet.SourcePort != 161 &&
            packet.DestPort != 162 && packet.SourcePort != 162) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 10) return;

        // Minimal ASN.1/BER parse: SEQUENCE (0x30), then version INTEGER (0x02 0x01 val)
        // then community OCTET STRING (0x04 len bytes)
        if (payload[0] != 0x30) return; // not a SEQUENCE

        // Skip SEQUENCE length (may be 1 or 2 bytes)
        int pos = 1;
        pos += SkipBerLength(payload, pos);
        if (pos >= payload.Length) return;

        // version: INTEGER (0x02)
        if (pos >= payload.Length || payload[pos] != 0x02) return;
        pos++;
        if (pos >= payload.Length) return;
        int verLen = payload[pos]; pos++;
        if (pos + verLen > payload.Length) return;
        int snmpVersion = (verLen == 1) ? payload[pos] : -1;
        pos += verLen;

        // Only SNMPv1 (version=0) and SNMPv2c (version=1)
        if (snmpVersion != 0 && snmpVersion != 1) return;

        // community: OCTET STRING (0x04)
        if (pos >= payload.Length || payload[pos] != 0x04) return;
        pos++;
        if (pos >= payload.Length) return;
        int comLen = payload[pos]; pos++;

        // Handle multi-byte length
        if ((comLen & 0x80) != 0)
        {
            int numBytes = comLen & 0x7F;
            if (numBytes > 2 || pos + numBytes > payload.Length) return;
            comLen = 0;
            for (int i = 0; i < numBytes; i++) comLen = (comLen << 8) | payload[pos + i];
            pos += numBytes;
        }

        if (comLen <= 0 || comLen > 256 || pos + comLen > payload.Length) return;

        string community;
        try { community = Encoding.ASCII.GetString(payload.Slice(pos, comLen)); }
        catch { return; }

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";
        string versionStr = snmpVersion == 0 ? "v1" : "v2c";

        string sig = $"SNMP-{versionStr}-{src}-{dst}-{community}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        bool isDefault = community is "public" or "private" or "community";
        bool isTrap = packet.DestPort == 162 || packet.SourcePort == 162;

        ReportWeaknessWithEvidence(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Recon Intel",
            Name = $"SNMP {versionStr} Community String Captured",
            Description = $"SNMP {versionStr} {(isTrap ? "trap" : "request")} between {src} and {dst} " +
                          $"with community string '{community}'" +
                          (isDefault ? " (DEFAULT COMMUNITY)" : "") +
                          ". SNMP v1/v2c transmits the community string in cleartext.",
            SourceIP = src,
            DestIP = dst,
            Port = isTrap ? (ushort)162 : (ushort)161,
            Severity = isDefault ? WeaknessSeverity.Critical : WeaknessSeverity.High,
            ExploitPath = $"Use captured community '{community}' to query device config via snmpwalk/snmpget. " +
                          (community == "private" ? "The 'private' community typically has WRITE access -> modify device config remotely. " : "") +
                          "Extract: running-config, interface list, ARP table, routing table, firmware version.",
            Mitigation = "Migrate to SNMPv3 with authPriv (SHA + AES). If v2c is required, use non-default community strings " +
                         "and restrict SNMP access via ACL to management stations only.",
            PacketId = packet.Id
        }, packet.RawData);
    }

    // ============================================================
    // SMBv1 Detection (header 0xFF 'S' 'M' 'B')
    // ============================================================

    private void CheckSmbv1(CapturedPacket packet)
    {
        if (packet.DestPort != 445 && packet.SourcePort != 445) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 36) return;

        // Look for SMB1 header: 0xFF 'S' 'M' 'B'
        for (int i = 0; i + 35 < payload.Length && i < 100; i++)
        {
            if (payload[i] != 0xFF || payload[i + 1] != 'S' || payload[i + 2] != 'M' || payload[i + 3] != 'B')
                continue;

            // SMB1 command at offset +4
            byte command = payload[i + 4];
            string src = packet.SourceIP ?? "";
            string dst = packet.DestIP ?? "";

            string sig = $"SMBV1-{src}-{dst}";
            if (!MarkSeen(sig, packet.Timestamp)) return;

            ReportWeaknessWithEvidence(new DetectedWeakness
            {
                Timestamp = packet.Timestamp,
                Category = "Legacy Protocol",
                Name = "SMBv1 Traffic Detected",
                Description = $"SMBv1 traffic between {src} and {dst} (command: 0x{command:X2}). " +
                              "SMBv1 is vulnerable to EternalBlue (MS17-010) and other critical exploits. " +
                              "Its presence also indicates a possible downgrade attack if SMBv2/v3 should be available.",
                SourceIP = src,
                DestIP = dst,
                Port = 445,
                Severity = WeaknessSeverity.Critical,
                ExploitPath = "EternalBlue (MS17-010) -> remote code execution without authentication. " +
                              "SMBv1 also lacks proper signing enforcement, making relay attacks trivial. " +
                              "Tools: Metasploit ms17_010_eternalblue, nmap --script smb-vuln-ms17-010.",
                Mitigation = "Disable SMBv1: PowerShell 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'. " +
                             "GPO: Computer Configuration > Administrative Templates > Network > Lanman Server > " +
                             "'SMB 1.0/CIFS File Sharing Support' = Disabled. Audit with: Get-SmbServerConfiguration | Select EnableSMB1Protocol.",
                PacketId = packet.Id
            }, packet.RawData);
            return;
        }
    }

    // ============================================================
    // NTLMv1 Downgrade Detection (NTLMSSP in SMB)
    // ============================================================

    private void CheckNtlmv1Downgrade(CapturedPacket packet)
    {
        if (packet.DestPort != 445 && packet.SourcePort != 445) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 50) return;

        // Search for NTLMSSP signature in payload
        ReadOnlySpan<byte> ntlmSig = "NTLMSSP\0"u8;
        int ntlmPos = -1;
        for (int i = 0; i + ntlmSig.Length + 20 < payload.Length && i < 500; i++)
        {
            if (payload.Slice(i, ntlmSig.Length).SequenceEqual(ntlmSig))
            {
                ntlmPos = i;
                break;
            }
        }
        if (ntlmPos < 0) return;

        // NTLMSSP message type at offset +8 (4 bytes LE): 3 = AUTHENTICATE
        if (ntlmPos + 28 > payload.Length) return;
        uint msgType = (uint)(payload[ntlmPos + 8] | (payload[ntlmPos + 9] << 8) |
                              (payload[ntlmPos + 10] << 16) | (payload[ntlmPos + 11] << 24));
        if (msgType != 3) return; // only AUTHENTICATE messages

        // NtChallengeResponse: length at offset +20 (2 bytes LE), max length +22
        ushort ntRespLen = (ushort)(payload[ntlmPos + 20] | (payload[ntlmPos + 21] << 8));

        // NTLMv1: NtChallengeResponse length = 24
        // NTLMv2: NtChallengeResponse length >= 56 (usually much longer)
        if (ntRespLen != 24) return;

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        string sig = $"NTLMV1-{src}-{dst}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "NTLM Downgrade",
            Name = "NTLMv1 Authentication Detected (SMB)",
            Description = $"NTLMv1 authentication from {src} to {dst} over SMB. " +
                          "NtChallengeResponse length is 24 bytes, indicating NTLMv1 (not NTLMv2). " +
                          "NTLMv1 hashes are trivially crackable via rainbow tables or crack.sh.",
            SourceIP = src,
            DestIP = dst,
            Port = 445,
            Severity = WeaknessSeverity.Critical,
            ExploitPath = "Capture NTLMv1 challenge+response -> submit to crack.sh for instant NTLM hash recovery. " +
                          "NTLMv1 with ESS can be cracked in ~30 minutes. The recovered NTLM hash enables pass-the-hash. " +
                          "Also relayable to any target that does not enforce NTLMv2.",
            Mitigation = "Enforce NTLMv2: GPO > Security Settings > Local Policies > Security Options > " +
                         "'Network Security: LAN Manager authentication level' = 'Send NTLMv2 response only. Refuse LM & NTLM'. " +
                         "Set minimum session security to require NTLMv2 and 128-bit encryption.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // LDAP Cleartext Simple Bind (TCP 389)
    // ============================================================

    private void CheckLdapCleartext(CapturedPacket packet)
    {
        if (packet.DestPort != 389 && packet.SourcePort != 389) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 14) return;

        // ASN.1/BER: SEQUENCE (0x30) > messageID (0x02) > BindRequest APPLICATION[0] (0x60)
        // Then version INTEGER, name OCTET STRING, authentication CHOICE:
        //   [0] simple (0x80) = password in cleartext
        if (payload[0] != 0x30) return;

        // Walk: skip SEQUENCE length, skip messageID, find 0x60 (BindRequest)
        int pos = 1;
        pos += SkipBerLength(payload, pos);

        // Skip messageID (tag 0x02)
        if (pos >= payload.Length || payload[pos] != 0x02) return;
        pos++;
        if (pos >= payload.Length) return;
        int idLen = payload[pos]; pos++;
        pos += idLen;

        if (pos >= payload.Length || payload[pos] != 0x60) return; // BindRequest
        pos++;
        pos += SkipBerLength(payload, pos);

        // Skip version INTEGER
        if (pos >= payload.Length || payload[pos] != 0x02) return;
        pos++;
        if (pos >= payload.Length) return;
        int verLen = payload[pos]; pos++;
        pos += verLen;

        // Skip bind DN (OCTET STRING 0x04)
        if (pos >= payload.Length || payload[pos] != 0x04) return;
        pos++;
        if (pos >= payload.Length) return;
        int dnLen = payload[pos]; pos++;
        if ((dnLen & 0x80) != 0)
        {
            int nb = dnLen & 0x7F;
            if (nb > 2 || pos + nb > payload.Length) return;
            dnLen = 0;
            for (int i = 0; i < nb; i++) dnLen = (dnLen << 8) | payload[pos + i];
            pos += nb;
        }

        string? bindDn = null;
        if (dnLen > 0 && pos + dnLen <= payload.Length)
        {
            try { bindDn = Encoding.UTF8.GetString(payload.Slice(pos, Math.Min(dnLen, 200))); }
            catch { /* ignore */ }
        }
        pos += dnLen;

        // Check authentication tag: 0x80 = simple (cleartext password)
        if (pos >= payload.Length || payload[pos] != 0x80) return;

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        string sig = $"LDAP-SIMPLE-{src}-{dst}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeaknessWithEvidence(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Cleartext Protocol",
            Name = "LDAP Simple Bind (Cleartext Password)",
            Description = $"LDAP simple bind from {src} to {dst}:389" +
                          (bindDn != null ? $" as '{bindDn}'" : "") +
                          ". The password is transmitted in cleartext. " +
                          "This also indicates LDAP signing is not enforced, making the connection relayable.",
            SourceIP = src,
            DestIP = dst,
            Port = 389,
            Severity = WeaknessSeverity.Critical,
            ExploitPath = "Passive sniff to capture plaintext credentials. " +
                          "LDAP without signing/channel binding is also an NTLM relay target: " +
                          "ntlmrelayx --target ldap://{dst} -> create machine account or configure RBCD for domain takeover.",
            Mitigation = "Enforce LDAPS (port 636) or LDAP with STARTTLS. " +
                         "Enable LDAP signing: GPO > Default Domain Controllers Policy > 'LDAP server signing requirements' = 'Require signing'. " +
                         "Enable LDAP channel binding: 'Domain controller: LDAP server channel binding token requirements' = 'Always'.",
            PacketId = packet.Id
        }, packet.RawData);
    }

    // ============================================================
    // HTTP Basic Auth / Cleartext Credentials
    // ============================================================

    private void CheckHttpBasicAuth(CapturedPacket packet)
    {
        bool httpPort = packet.DestPort is 80 or 8080 or 8888 || packet.SourcePort is 80 or 8080 or 8888;
        if (!httpPort) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 30) return;

        string payloadStr;
        try { payloadStr = Encoding.ASCII.GetString(payload[..Math.Min(payload.Length, 2000)]); }
        catch { return; }

        bool hasBasicAuth = payloadStr.Contains("Authorization: Basic ", StringComparison.OrdinalIgnoreCase);

        // Also check for password in POST body / query string
        bool hasPasswordInBody = false;
        if (payloadStr.StartsWith("POST ", StringComparison.Ordinal))
        {
            hasPasswordInBody = payloadStr.Contains("password=", StringComparison.OrdinalIgnoreCase)
                             || payloadStr.Contains("passwd=", StringComparison.OrdinalIgnoreCase)
                             || payloadStr.Contains("pwd=", StringComparison.OrdinalIgnoreCase);
        }

        if (!hasBasicAuth && !hasPasswordInBody) return;

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";
        string finding = hasBasicAuth ? "HTTP Basic Authentication (base64-encoded credentials)" : "Password in HTTP POST body";

        string sig = $"HTTP-CRED-{src}-{dst}-{(hasBasicAuth ? "basic" : "post")}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeaknessWithEvidence(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Cleartext Protocol",
            Name = "HTTP Cleartext Credentials",
            Description = $"{finding} from {src} to {dst} over cleartext HTTP. " +
                          (hasBasicAuth ? "Basic Auth is base64-encoded (NOT encrypted) and trivially decoded." :
                           "Form credentials are transmitted in the POST body without encryption."),
            SourceIP = src,
            DestIP = dst,
            Port = Math.Min(packet.SourcePort, packet.DestPort),
            Severity = WeaknessSeverity.Critical,
            ExploitPath = "Passive sniffing or ARP spoof + MitM to capture credentials. " +
                          (hasBasicAuth ? "base64 -d on the Authorization header value yields username:password." :
                           "URL-decode the POST body to extract the password field."),
            Mitigation = "Enforce HTTPS (TLS) for all authenticated endpoints. Deploy HSTS headers. " +
                         "Redirect HTTP to HTTPS at the load balancer or web server.",
            PacketId = packet.Id
        }, packet.RawData);
    }

    // ============================================================
    // SMTP Cleartext / AUTH Detection (TCP 25/587)
    // ============================================================

    private void CheckSmtpCleartext(CapturedPacket packet)
    {
        ushort serverPort = Math.Min(packet.SourcePort, packet.DestPort);
        if (serverPort != 25 && serverPort != 587) return;
        if (packet.GetPayload().Length == 0) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        string payloadStr;
        try { payloadStr = Encoding.ASCII.GetString(payload[..Math.Min(payload.Length, 500)]); }
        catch { return; }

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        // Check for AUTH LOGIN / AUTH PLAIN (cleartext SMTP auth)
        bool hasAuth = payloadStr.Contains("AUTH LOGIN", StringComparison.OrdinalIgnoreCase)
                    || payloadStr.Contains("AUTH PLAIN", StringComparison.OrdinalIgnoreCase);

        if (hasAuth)
        {
            string sig = $"SMTP-AUTH-{src}-{dst}";
            if (!MarkSeen(sig, packet.Timestamp)) return;

            ReportWeaknessWithEvidence(new DetectedWeakness
            {
                Timestamp = packet.Timestamp,
                Category = "Cleartext Protocol",
                Name = "SMTP Cleartext Authentication",
                Description = $"SMTP AUTH LOGIN/PLAIN from {src} to {dst}:{serverPort}. " +
                              "Credentials are base64-encoded (not encrypted) in the SMTP session.",
                SourceIP = src,
                DestIP = dst,
                Port = serverPort,
                Severity = WeaknessSeverity.Critical,
                ExploitPath = "Capture AUTH LOGIN base64 lines -> decode to username + password. " +
                              "These credentials often work for webmail, VPN, or other services (password reuse).",
                Mitigation = "Enforce SMTPS (port 465) or SMTP with mandatory STARTTLS (port 587). " +
                             "Configure MTA to reject AUTH before STARTTLS negotiation.",
                PacketId = packet.Id
            }, packet.RawData);
            return;
        }

        // General SMTP cleartext traffic (non-auth)
        bool isSmtpTraffic = payloadStr.StartsWith("EHLO ", StringComparison.OrdinalIgnoreCase)
                          || payloadStr.StartsWith("HELO ", StringComparison.OrdinalIgnoreCase)
                          || payloadStr.StartsWith("MAIL FROM:", StringComparison.OrdinalIgnoreCase)
                          || payloadStr.StartsWith("220 ", StringComparison.Ordinal);

        if (!isSmtpTraffic) return;

        string sig2 = $"SMTP-CLEAR-{src}-{dst}";
        if (!MarkSeen(sig2, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Cleartext Protocol",
            Name = "SMTP Cleartext Traffic",
            Description = $"Cleartext SMTP traffic between {src} and {dst}:{serverPort}. " +
                          "Email contents and headers are visible to any attacker on the segment.",
            SourceIP = src,
            DestIP = dst,
            Port = serverPort,
            Severity = WeaknessSeverity.High,
            ExploitPath = "Passive sniffing to read email content. If AUTH is used later in this session, credentials are also exposed.",
            Mitigation = "Enforce STARTTLS or use SMTPS (port 465). Configure 'smtp_tls_security_level = encrypt' on Postfix.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // DNS Spoofing Detection (UDP 53)
    // ============================================================

    private void CheckDnsSpoofing(CapturedPacket packet)
    {
        if (packet.SourcePort != 53) return; // only DNS responses

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 12) return;

        // DNS header: Transaction ID (2 bytes), flags (2 bytes)
        ushort txId = (ushort)((payload[0] << 8) | payload[1]);
        ushort flags = (ushort)((payload[2] << 8) | payload[3]);
        bool isResponse = (flags & 0x8000) != 0;
        if (!isResponse) return;

        // Parse question name for the key
        if (!TryParseDnsQuestionName(payload, out var qname)) return;

        string src = packet.SourceIP ?? "";
        string key = $"{txId}:{qname}";

        // Simple answer fingerprint: first A/AAAA answer IP
        string answerFp = $"{src}";

        var pending = new List<DetectedWeakness>();
        lock (_lock)
        {
            // Evict stale DNS responses
            if ((packet.Timestamp - _lastDnsCleanup).TotalSeconds > 30)
            {
                var cutoff = packet.Timestamp.AddSeconds(-10);
                var stale = _dnsResponses.Where(kv => kv.Value.time < cutoff).Select(kv => kv.Key).ToList();
                foreach (var k in stale) _dnsResponses.Remove(k);
                _lastDnsCleanup = packet.Timestamp;

                // Hard cap after time-based eviction.
                if (_dnsResponses.Count > MaxDnsResponses)
                {
                    int toRemove = _dnsResponses.Count - MaxDnsResponses + MaxDnsResponses / 4;
                    foreach (var k2 in _dnsResponses.OrderBy(kv => kv.Value.time).Take(toRemove).Select(kv => kv.Key).ToList())
                        _dnsResponses.Remove(k2);
                }
            }

            if (_dnsResponses.TryGetValue(key, out var prev))
            {
                // Two responses for the same txid+qname from different sources
                if (prev.source != src)
                {
                    string sig = $"DNS-SPOOF-{key}";
                    if (MarkSeenLocked(sig, packet.Timestamp))
                    {
                        pending.Add(new DetectedWeakness
                        {
                            Timestamp = packet.Timestamp,
                            Category = "DNS Spoofing",
                            Name = "DNS Response Conflict Detected",
                            Description = $"Two DNS responses for '{qname}' (txid: 0x{txId:X4}) from different sources: " +
                                          $"{prev.source} and {src}. This is consistent with a DNS spoofing or cache poisoning attack.",
                            SourceIP = src,
                            DestIP = packet.DestIP ?? "",
                            Port = 53,
                            Severity = WeaknessSeverity.Critical,
                            ExploitPath = "Attacker races the legitimate DNS server to inject a forged response with the correct txid. " +
                                          "If accepted, the client resolves to the attacker's IP -> phishing, credential theft, MitM.",
                            Mitigation = "Use DNSSEC to validate response authenticity. Use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT). " +
                                         "Randomize source port for DNS queries (beyond txid entropy). Monitor for duplicate responses.",
                            PacketId = packet.Id
                        });
                    }
                }
            }
            else
            {
                if (_dnsResponses.Count < MaxDnsResponses)
                    _dnsResponses[key] = (answerFp, src, packet.Timestamp);
            }
        }
        foreach (var w in pending) ReportWeakness(w);
    }

    // ============================================================
    // ICMP Redirect Detection (ICMP type 5)
    // ============================================================

    private void CheckIcmpRedirect(CapturedPacket packet)
    {
        if (packet.IpProtocol != 1) return; // ICMP

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 8) return;

        byte icmpType = payload[0];
        if (icmpType != 5) return; // type 5 = Redirect

        byte code = payload[1];
        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        // Gateway IP is at offset 4 (4 bytes)
        string? gatewayIp = null;
        if (payload.Length >= 8)
        {
            gatewayIp = new IPAddress(payload.Slice(4, 4).ToArray()).ToString();
        }

        string sig = $"ICMP-REDIRECT-{src}-{dst}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        string codeStr = code switch
        {
            0 => "Redirect for Network",
            1 => "Redirect for Host",
            2 => "Redirect for TOS and Network",
            3 => "Redirect for TOS and Host",
            _ => $"code {code}"
        };

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Routing Attack",
            Name = "ICMP Redirect Detected",
            Description = $"ICMP Redirect ({codeStr}) from {src} to {dst}" +
                          (gatewayIp != null ? $", redirecting to gateway {gatewayIp}" : "") +
                          ". On modern networks, ICMP Redirects are almost always an attack — " +
                          "they force the victim to reroute traffic through an attacker-controlled gateway.",
            SourceIP = src,
            DestIP = dst,
            Port = 0,
            Severity = WeaknessSeverity.High,
            ExploitPath = "Attacker sends ICMP Redirect -> victim updates routing table -> traffic for specific destinations " +
                          "routes through attacker's IP -> MitM. Requires attacker to be on the same segment.",
            Mitigation = "Disable ICMP Redirect acceptance: Linux: 'sysctl net.ipv4.conf.all.accept_redirects=0'. " +
                         "Windows: 'netsh interface ipv4 set global icmpredirects=disabled'. " +
                         "Drop ICMP type 5 at the firewall.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // Stealth Scan Detection (TCP flag anomalies)
    // ============================================================

    private void CheckStealthScan(CapturedPacket packet)
    {
        byte[] data = packet.RawData;
        // Need to read TCP flags from raw data
        // Find TCP header offset
        int ipOffset = 14;
        ushort ethType = (ushort)((data[12] << 8) | data[13]);
        if (ethType == 0x8100) ipOffset = 18;
        if (ipOffset + 20 > data.Length) return;

        int ipHeaderLen = (data[ipOffset] & 0x0F) * 4;
        int tcpOffset = ipOffset + ipHeaderLen;
        if (tcpOffset + 14 > data.Length) return;

        // TCP flags at offset +13 in TCP header
        byte flags = data[tcpOffset + 13];

        bool isNull = flags == 0x00;
        bool isFinOnly = flags == 0x01;
        bool isXmas = (flags & 0x29) == 0x29; // FIN+PSH+URG

        if (!isNull && !isFinOnly && !isXmas) return;

        string src = packet.SourceIP ?? "";
        string scanType = isNull ? "NULL" : isFinOnly ? "FIN" : "Xmas";

        var pending = new List<DetectedWeakness>();
        lock (_lock)
        {
            // Evict stale scan trackers
            if ((packet.Timestamp - _lastStealthScanCleanup).TotalSeconds > 60)
            {
                var cutoff = packet.Timestamp.AddMinutes(-5);
                var stale = _stealthScanTracker.Where(kv => kv.Value.last < cutoff).Select(kv => kv.Key).ToList();
                foreach (var k in stale) _stealthScanTracker.Remove(k);
                _lastStealthScanCleanup = packet.Timestamp;

                // Hard cap after time-based eviction.
                if (_stealthScanTracker.Count > MaxStealthScanEntries)
                {
                    int toRemove = _stealthScanTracker.Count - MaxStealthScanEntries + MaxStealthScanEntries / 4;
                    foreach (var k2 in _stealthScanTracker.OrderBy(kv => kv.Value.last).Take(toRemove).Select(kv => kv.Key).ToList())
                        _stealthScanTracker.Remove(k2);
                }
            }

            if (!_stealthScanTracker.TryGetValue(src, out var state))
            {
                if (_stealthScanTracker.Count >= MaxStealthScanEntries) return;
                state = (1, packet.Timestamp, packet.Timestamp);
            }
            else
            {
                state = (state.count + 1, state.first, packet.Timestamp);
            }
            _stealthScanTracker[src] = state;

            // Alert on individual anomalous packets (deduped)
            string sig = $"STEALTH-{scanType}-{src}";
            if (MarkSeenLocked(sig, packet.Timestamp))
            {
                pending.Add(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "Reconnaissance",
                    Name = $"TCP {scanType} Scan Detected",
                    Description = $"Source {src} sent a TCP {scanType} packet to {packet.DestIP}:{packet.DestPort} " +
                                  $"(flags: 0x{flags:X2}). These flag combinations do not occur in normal traffic " +
                                  "and are characteristic of stealth port scanning (nmap -sN/-sF/-sX).",
                    SourceIP = src,
                    DestIP = packet.DestIP ?? "",
                    Port = packet.DestPort,
                    Severity = WeaknessSeverity.Medium,
                    ExploitPath = $"TCP {scanType} scan: used to enumerate open/closed ports while evading stateless firewalls " +
                                  "that only inspect SYN packets. Open ports silently drop these packets; closed ports reply with RST.",
                    Mitigation = "Deploy a stateful firewall or IDS that inspects TCP flag combinations. " +
                                 "Drop packets with invalid flag combinations at the perimeter. " +
                                 "Rate-limit new connections per source IP.",
                    PacketId = packet.Id
                });
            }

            // Aggregate alert for sustained scanning
            if (state.count >= 20 && (state.last - state.first).TotalSeconds > 5)
            {
                string aggSig = $"STEALTH-SCAN-AGG-{src}";
                if (MarkSeenLocked(aggSig, packet.Timestamp))
                {
                    pending.Add(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "Reconnaissance",
                        Name = "Sustained Stealth Port Scan",
                        Description = $"Source {src} has sent {state.count} anomalous TCP flag packets over " +
                                      $"{(state.last - state.first).TotalSeconds:F0}s. This indicates an active port scan.",
                        SourceIP = src,
                        DestIP = packet.DestIP ?? "",
                        Port = 0,
                        Severity = WeaknessSeverity.High,
                        ExploitPath = "Attacker is enumerating open ports for subsequent exploitation.",
                        Mitigation = "Block the source IP. Investigate for lateral movement if the source is internal.",
                        PacketId = packet.Id
                    });
                }
            }
        }
        foreach (var w in pending) ReportWeakness(w);
    }

    // ============================================================
    // VLAN Double-Tagging / QinQ Detection
    // ============================================================

    private void CheckVlanDoubleTag(CapturedPacket packet)
    {
        byte[] data = packet.RawData;
        if (data.Length < 22) return;

        ushort outerType = (ushort)((data[12] << 8) | data[13]);
        // Outer tag: 0x8100 (802.1Q) or 0x88A8 (802.1ad/QinQ)
        if (outerType != 0x8100 && outerType != 0x88A8) return;

        // Inner tag at offset 16-17
        if (data.Length < 22) return;
        ushort innerType = (ushort)((data[16] << 8) | data[17]);
        if (innerType != 0x8100) return;

        // This is a double-tagged frame
        ushort outerVlan = (ushort)(((data[14] << 8) | data[15]) & 0x0FFF);
        ushort innerVlan = (ushort)(((data[18] << 8) | data[19]) & 0x0FFF);

        string srcMac = FormatMac(data, 6);
        string sig = $"QINQ-{srcMac}-{outerVlan}-{innerVlan}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "VLAN Hopping Surface",
            Name = "VLAN Double-Tagging (QinQ) Detected",
            Description = $"Double-tagged 802.1Q frame from {srcMac}: outer VLAN {outerVlan}, inner VLAN {innerVlan}. " +
                          "If the outer VLAN matches the native VLAN of the trunk port, the switch strips the outer tag " +
                          "and forwards the inner-tagged frame to the target VLAN — a VLAN hopping attack.",
            SourceIP = "",
            DestIP = "",
            Port = 0,
            Severity = WeaknessSeverity.High,
            ExploitPath = "Scapy: craft Ether/Dot1Q(vlan=nativeVLAN)/Dot1Q(vlan=targetVLAN)/payload. " +
                          "The switch strips the outer tag (native VLAN) and forwards the inner tag to the target VLAN. " +
                          "One-way only (no return path), but useful for injecting ARP, DHCP, or other broadcast traffic.",
            Mitigation = "Set the native VLAN to an unused VLAN ID (not VLAN 1). " +
                         "Explicitly tag all traffic on trunk ports: 'switchport trunk native vlan <unused>'. " +
                         "Enable VLAN access-list filtering.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // TLS Downgrade Detection (ClientHello/ServerHello version)
    // ============================================================

    private void CheckTlsDowngrade(CapturedPacket packet)
    {
        // Look at common TLS ports
        ushort serverPort = Math.Min(packet.SourcePort, packet.DestPort);
        if (serverPort != 443 && serverPort != 8443 && serverPort != 993 &&
            serverPort != 995 && serverPort != 636 && serverPort != 465 &&
            serverPort != 5061 && serverPort != 3389) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 11) return;

        // TLS record: ContentType=22 (Handshake) at byte 0
        if (payload[0] != 22) return;

        // Record version at bytes 1-2
        ushort recordVersion = (ushort)((payload[1] << 8) | payload[2]);

        // Handshake message type at byte 5: 1=ClientHello, 2=ServerHello
        if (payload.Length < 44) return;
        byte hsType = payload[5];
        if (hsType != 1 && hsType != 2) return;

        // Client/Server version at bytes 9-10 in handshake
        ushort hsVersion = (ushort)((payload[9] << 8) | payload[10]);

        // Flag if version < TLS 1.2 (0x0303)
        // SSLv3 = 0x0300, TLS 1.0 = 0x0301, TLS 1.1 = 0x0302
        if (hsVersion >= 0x0303) return; // TLS 1.2+ is fine

        string versionName = hsVersion switch
        {
            0x0300 => "SSLv3",
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0200 => "SSLv2",
            _ => $"0x{hsVersion:X4}"
        };

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";
        string msgType = hsType == 1 ? "ClientHello" : "ServerHello";

        string sig = $"TLS-DOWNGRADE-{src}-{dst}-{serverPort}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "TLS Weakness",
            Name = $"Weak TLS Version ({versionName}) in {msgType}",
            Description = $"{msgType} from {src} to {dst}:{serverPort} uses {versionName}. " +
                          "Versions below TLS 1.2 are vulnerable to POODLE, BEAST, Lucky13, and other attacks. " +
                          (hsType == 2 ? "The SERVER chose this version, indicating it does not enforce modern TLS." :
                           "The CLIENT is offering a deprecated version."),
            SourceIP = src,
            DestIP = dst,
            Port = serverPort,
            Severity = hsVersion <= 0x0300 ? WeaknessSeverity.Critical : WeaknessSeverity.High,
            ExploitPath = versionName switch
            {
                "SSLv3" => "POODLE attack (CVE-2014-3566): decrypt one byte per ~256 requests. SSLv3 should never be used.",
                "SSLv2" => "SSLv2 is completely broken. DROWN attack (CVE-2016-0800) can decrypt TLS sessions if SSLv2 is available.",
                "TLS 1.0" => "BEAST (CVE-2011-3389): CBC mode chosen-plaintext attack. PCI DSS prohibits TLS 1.0 since June 2018.",
                "TLS 1.1" => "No known practical attacks, but deprecated by RFC 8996 (March 2021). Indicates outdated server/client config.",
                _ => "Deprecated TLS version with known weaknesses."
            },
            Mitigation = "Server: disable SSLv3, TLS 1.0, and TLS 1.1. Apache: 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'. " +
                         "Nginx: 'ssl_protocols TLSv1.2 TLSv1.3'. IIS: disable via registry or IISCrypto tool. " +
                         "Client: update browser/application to a version that supports TLS 1.2+.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // WS-Discovery Detection (UDP 3702)
    // ============================================================

    private void CheckWsDiscovery(CapturedPacket packet)
    {
        if (packet.DestPort != 3702) return;

        string sig = $"WSDISCOVERY-{packet.SourceIP}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "Service Discovery",
            Name = "WS-Discovery Broadcast",
            Description = $"Host {packet.SourceIP} is sending WS-Discovery (multicast UDP 3702). " +
                          "WS-Discovery is used by printers, cameras, and IoT devices. " +
                          "These devices often have weak credentials, outdated firmware, and large attack surfaces.",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = 3702,
            Severity = WeaknessSeverity.Low,
            ExploitPath = "Enumerate discovered devices -> check for default credentials, known CVEs, or exposed management interfaces. " +
                          "Printers often store print jobs (data exfil) and may have LDAP credentials for scan-to-email.",
            Mitigation = "Segment IoT/printer devices into a dedicated VLAN with restricted inter-VLAN routing. " +
                         "Disable WS-Discovery where not needed. Firewall-block UDP 3702 on non-printer segments.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // Parsing helpers
    // ============================================================

    private static string FormatMac(byte[] data, int offset)
    {
        var sb = new StringBuilder(17);
        for (int k = 0; k < 6; k++)
        {
            if (k > 0) sb.Append(':');
            sb.Append(data[offset + k].ToString("X2"));
        }
        return sb.ToString();
    }

    /// <summary>
    /// Parses the first question name from a DNS-format message (DNS / LLMNR / mDNS).
    /// Assumes <paramref name="dns"/> is the application-layer payload starting at the DNS header.
    /// Returns false on any malformed input rather than throwing.
    /// </summary>
    private static bool TryParseDnsQuestionName(ReadOnlySpan<byte> dns, out string name)
    {
        name = "";
        if (dns.Length < 13) return false; // 12-byte header + at least one label byte

        int pos = 12; // question section begins right after the header
        var sb = new StringBuilder();
        int guard = 0;

        while (pos < dns.Length && guard++ < 128)
        {
            byte len = dns[pos];
            if (len == 0) break;                 // end of name
            if ((len & 0xC0) != 0) return false; // compression pointer not expected in a question
            pos++;
            if (pos + len > dns.Length) return false;

            if (sb.Length > 0) sb.Append('.');
            for (int j = 0; j < len; j++)
            {
                byte b = dns[pos + j];
                sb.Append(b >= 32 && b < 127 ? (char)b : '?');
            }
            pos += len;
        }

        name = sb.ToString();
        return name.Length > 0;
    }

    /// <summary>Returns the NBNS opcode (0 = query) from the NBNS header, or null if unparseable.</summary>
    private static int? TryParseNbnsOpcode(ReadOnlySpan<byte> nbns)
    {
        if (nbns.Length < 4) return null;
        // NBNS flags are at offset 2-3; opcode is bits 11-14 of that 16-bit field.
        ushort flags = (ushort)((nbns[2] << 8) | nbns[3]);
        return (flags >> 11) & 0x0F;
    }

    /// <summary>
    /// Decodes the first-level-encoded NetBIOS name from an NBNS question and appends its suffix,
    /// e.g. "FILESERVER&lt;20&gt;". Returns false on malformed input.
    /// </summary>
    private static bool TryParseNetbiosName(ReadOnlySpan<byte> nbns, out string name)
    {
        name = "";
        const int header = 12;
        if (nbns.Length < header + 1 + 32) return false;

        if (nbns[header] != 0x20) return false; // encoded name length must be 32
        int p = header + 1;

        Span<char> decoded = stackalloc char[16];
        for (int i = 0; i < 16; i++)
        {
            int hi = nbns[p + i * 2] - 'A';
            int lo = nbns[p + i * 2 + 1] - 'A';
            if (hi is < 0 or > 15 || lo is < 0 or > 15) return false;
            decoded[i] = (char)((hi << 4) | lo);
        }

        string trimmed = new string(decoded[..15]).TrimEnd(' ', '\0');
        byte suffix = (byte)decoded[15];
        if (trimmed.Length == 0) return false;

        name = $"{trimmed}<{suffix:X2}>";
        return true;
    }

    /// <summary>
    /// Skips an ASN.1/BER length field and returns the number of bytes consumed (not the value).
    /// </summary>
    private static int SkipBerLength(ReadOnlySpan<byte> data, int pos)
    {
        if (pos >= data.Length) return 0;
        byte first = data[pos];
        if ((first & 0x80) == 0) return 1; // short form: 1 byte
        int numBytes = first & 0x7F;
        return 1 + numBytes; // long form: 1 + numBytes
    }

    /// <summary>Parses CDP TLVs to extract device-id, platform, management IP, native VLAN, port-id.</summary>
    private static (string? deviceId, string? platform, string? mgmtIp, string? nativeVlan, string? portId)
        ParseCdpTlvs(byte[] data, int start)
    {
        string? deviceId = null, platform = null, mgmtIp = null, nativeVlan = null, portId = null;
        int pos = start;
        int guard = 0;

        while (pos + 4 <= data.Length && guard++ < 50)
        {
            ushort tlvType = (ushort)((data[pos] << 8) | data[pos + 1]);
            ushort tlvLen = (ushort)((data[pos + 2] << 8) | data[pos + 3]);
            if (tlvLen < 4 || pos + tlvLen > data.Length) break;

            int valueStart = pos + 4;
            int valueLen = tlvLen - 4;

            try
            {
                switch (tlvType)
                {
                    case 0x0001: // Device-ID
                        deviceId = Encoding.ASCII.GetString(data, valueStart, valueLen).TrimEnd('\0');
                        break;
                    case 0x0003: // Port-ID
                        portId = Encoding.ASCII.GetString(data, valueStart, valueLen).TrimEnd('\0');
                        break;
                    case 0x0006: // Platform
                        platform = Encoding.ASCII.GetString(data, valueStart, valueLen).TrimEnd('\0');
                        break;
                    case 0x0016: // Management Address
                        // Simplified: address starts at valueStart+4 for IPv4 (type=1, len=4)
                        if (valueLen >= 9 && data[valueStart + 1] == 1 && data[valueStart + 2] == 4)
                        {
                            mgmtIp = new IPAddress(new ReadOnlySpan<byte>(data, valueStart + 3, 4)).ToString();
                        }
                        break;
                    case 0x000A: // Native VLAN
                        if (valueLen >= 2)
                        {
                            ushort vlan = (ushort)((data[valueStart] << 8) | data[valueStart + 1]);
                            nativeVlan = vlan.ToString();
                        }
                        break;
                }
            }
            catch { /* skip malformed TLV */ }

            pos += tlvLen;
        }

        return (deviceId, platform, mgmtIp, nativeVlan, portId);
    }

    /// <summary>Parses LLDP TLVs to extract system name, system description, management IP, port ID.</summary>
    private static (string? systemName, string? systemDesc, string? mgmtIp, string? portId)
        ParseLldpTlvs(byte[] data, int start)
    {
        string? systemName = null, systemDesc = null, mgmtIp = null, portId = null;
        int pos = start;
        int guard = 0;

        while (pos + 2 <= data.Length && guard++ < 50)
        {
            ushort typeLen = (ushort)((data[pos] << 8) | data[pos + 1]);
            int tlvType = (typeLen >> 9) & 0x7F;
            int tlvLen = typeLen & 0x01FF;
            pos += 2;

            if (tlvType == 0 && tlvLen == 0) break; // End of LLDPDU
            if (pos + tlvLen > data.Length) break;

            try
            {
                switch (tlvType)
                {
                    case 2: // Port ID
                        if (tlvLen > 1)
                            portId = Encoding.ASCII.GetString(data, pos + 1, tlvLen - 1).TrimEnd('\0');
                        break;
                    case 5: // System Name
                        systemName = Encoding.ASCII.GetString(data, pos, tlvLen).TrimEnd('\0');
                        break;
                    case 6: // System Description
                        systemDesc = Encoding.ASCII.GetString(data, pos, Math.Min(tlvLen, 100)).TrimEnd('\0');
                        break;
                    case 8: // Management Address
                        // addr string length (1 byte), addr subtype (1 byte), addr (4 for IPv4)
                        if (tlvLen >= 7 && data[pos + 1] == 1) // subtype 1 = IPv4
                        {
                            mgmtIp = new IPAddress(new ReadOnlySpan<byte>(data, pos + 2, 4)).ToString();
                        }
                        break;
                }
            }
            catch { /* skip malformed TLV */ }

            pos += tlvLen;
        }

        return (systemName, systemDesc, mgmtIp, portId);
    }

    /// <summary>Extracts DHCP option 54 (Server Identifier) from a DHCP payload.</summary>
    private static string? TryParseDhcpOption54(ReadOnlySpan<byte> payload)
    {
        // DHCP options start at offset 240 (after fixed BOOTP fields + magic cookie 99.130.83.99)
        if (payload.Length < 244) return null;

        // Verify magic cookie
        if (payload[236] != 99 || payload[237] != 130 || payload[238] != 83 || payload[239] != 99)
            return null;

        int pos = 240;
        int guard = 0;
        while (pos + 2 < payload.Length && guard++ < 200)
        {
            byte optType = payload[pos];
            if (optType == 255) break; // End
            if (optType == 0) { pos++; continue; } // Pad

            byte optLen = payload[pos + 1];
            pos += 2;
            if (pos + optLen > payload.Length) break;

            if (optType == 54 && optLen == 4) // Server Identifier
            {
                return new IPAddress(payload.Slice(pos, 4).ToArray()).ToString();
            }

            pos += optLen;
        }
        return null;
    }

    // ============================================================
    // [Gap1] TLS Metadata: SNI, JA3/JA3S, Certificate Anomaly
    // ============================================================

    private void CheckTlsMetadata(CapturedPacket packet)
    {
        // Only on TLS ports (extend as needed)
        ushort serverPort = Math.Min(packet.SourcePort, packet.DestPort);
        if (serverPort != 443 && serverPort != 8443 && serverPort != 993 &&
            serverPort != 995 && serverPort != 636 && serverPort != 465 &&
            serverPort != 5061 && serverPort != 3389 && serverPort != 5986 &&
            serverPort != 8080 && serverPort != 8444) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 11) return;

        byte contentType = payload[0];

        // TLS record: ContentType=22 (Handshake) or 23 (Application Data)
        if (contentType != 22 && contentType != 23) return;

        // Record length
        int recordLen = (payload[3] << 8) | payload[4];
        if (payload.Length < 5 + recordLen) return;

        if (contentType == 22) // Handshake
        {
            byte hsType = payload[5];

            if (hsType == 1) // ClientHello
            {
                ParseClientHello(packet, payload, serverPort);
            }
            else if (hsType == 2) // ServerHello
            {
                ParseServerHello(packet, payload, serverPort);
            }
            else if (hsType == 11) // Certificate
            {
                ParseCertificateMessage(packet, payload, serverPort);
            }
        }
        else // contentType == 23: Application Data — forward to TlsDecryptor
        {
            TryDecryptApplicationData(packet, payload, serverPort);
        }
    }

    /// <summary>
    /// Forward a TLS Application Data record to the attached <see cref="TlsDecryptor"/>
    /// for decryption. The decryptor fires <see cref="TlsDecryptor.OnRecordDecrypted"/>
    /// if decryption succeeds.
    /// </summary>
    private void TryDecryptApplicationData(CapturedPacket packet, ReadOnlySpan<byte> payload, ushort serverPort)
    {
        TlsDecryptor? decryptor;
        lock (_lock)
        {
            decryptor = _tlsDecryptor;
        }
        if (decryptor == null) return;

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        // Determine direction: if source port is the server port, it's server→client
        bool isClientToServer = packet.DestPort == serverPort;

        // Connection key must match the one used in RegisterSession (from ParseServerHello):
        // "clientIP:clientPort-serverIP:serverPort"
        string connectionKey = isClientToServer
            ? $"{src}:{packet.SourcePort}-{dst}:{packet.DestPort}"
            : $"{dst}:{packet.DestPort}-{src}:{packet.SourcePort}";

        try
        {
            decryptor.DecryptAndNotify(connectionKey, isClientToServer, payload);
        }
        catch (Exception ex)
        {
            OnError?.Invoke(ex);
        }
    }

    private void ParseClientHello(CapturedPacket packet, ReadOnlySpan<byte> payload, ushort serverPort)
    {
        // Handshake header: type(1) + length(3) + version(2) + random(32) = 38 bytes from record start
        if (payload.Length < 43) return;

        int pos = 5; // after record header
        // Skip handshake type(1) + length(3)
        pos += 4;

        // Client version (2 bytes)
        ushort clientVersion = (ushort)((payload[pos] << 8) | payload[pos + 1]);
        pos += 2;

        // Random (32 bytes) — save for TlsDecryptor session registration
        byte[] clientRandom = payload.Slice(pos, 32).ToArray();
        pos += 32;

        // Session ID
        if (pos >= payload.Length) return;
        int sessionIdLen = payload[pos]; pos++;
        pos += sessionIdLen;

        // Cipher suites
        if (pos + 2 > payload.Length) return;
        int cipherSuitesLen = (payload[pos] << 8) | payload[pos + 1]; pos += 2;
        if (pos + cipherSuitesLen > payload.Length) return;

        var cipherSuites = new List<ushort>();
        for (int i = 0; i < cipherSuitesLen; i += 2)
        {
            ushort cs = (ushort)((payload[pos + i] << 8) | payload[pos + i + 1]);
            // Skip GREASE values (0x?A?A pattern)
            if ((cs & 0x0F0F) == 0x0A0A) continue;
            cipherSuites.Add(cs);
        }
        pos += cipherSuitesLen;

        // Compression methods
        if (pos >= payload.Length) return;
        int compLen = payload[pos]; pos++;
        pos += compLen;

        // Extensions
        string? sni = null;
        var extensions = new List<ushort>();
        var ellipticCurves = new List<ushort>();
        var ecPointFormats = new List<byte>();

        if (pos + 2 <= payload.Length)
        {
            int extTotalLen = (payload[pos] << 8) | payload[pos + 1]; pos += 2;
            int extEnd = Math.Min(pos + extTotalLen, payload.Length);

            while (pos + 4 <= extEnd)
            {
                ushort extType = (ushort)((payload[pos] << 8) | payload[pos + 1]);
                int extLen = (payload[pos + 2] << 8) | payload[pos + 3];
                pos += 4;
                if (pos + extLen > extEnd) break;

                // Skip GREASE extension types
                if ((extType & 0x0F0F) != 0x0A0A)
                    extensions.Add(extType);

                // SNI (ext type 0)
                if (extType == 0 && extLen >= 5)
                {
                    // SNI list: total length(2) + type(1) + name length(2) + name
                    int sniListLen = (payload[pos] << 8) | payload[pos + 1];
                    if (pos + 2 + sniListLen <= extEnd && sniListLen >= 3)
                    {
                        byte sniType = payload[pos + 2]; // 0 = host_name
                        int sniNameLen = (payload[pos + 3] << 8) | payload[pos + 4];
                        if (sniType == 0 && sniNameLen > 0 && pos + 5 + sniNameLen <= extEnd)
                        {
                            try
                            {
                                sni = Encoding.ASCII.GetString(
                                    payload.Slice(pos + 5, Math.Min(sniNameLen, 253)));
                            }
                            catch { /* malformed */ }
                        }
                    }
                }

                // Supported Groups / Elliptic Curves (ext type 0x000A)
                if (extType == 0x000A && extLen >= 4)
                {
                    int curveListLen = (payload[pos] << 8) | payload[pos + 1];
                    int curveEnd = Math.Min(2 + curveListLen, extLen);
                    for (int i = 2; i + 1 < curveEnd && pos + i + 1 < extEnd; i += 2)
                    {
                        ushort curve = (ushort)((payload[pos + i] << 8) | payload[pos + i + 1]);
                        if ((curve & 0x0F0F) != 0x0A0A) // skip GREASE
                            ellipticCurves.Add(curve);
                    }
                }

                // EC Point Formats (ext type 0x000B)
                if (extType == 0x000B && extLen >= 1)
                {
                    int pfLen = payload[pos];
                    int pfEnd = Math.Min(1 + pfLen, extLen);
                    for (int i = 1; i < pfEnd && pos + i < extEnd; i++)
                        ecPointFormats.Add(payload[pos + i]);
                }

                pos += extLen;
            }
        }

        // Build JA3 string: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        string ja3Raw = $"{clientVersion}," +
                        $"{string.Join("-", cipherSuites)}," +
                        $"{string.Join("-", extensions)}," +
                        $"{string.Join("-", ellipticCurves)}," +
                        $"{string.Join("-", ecPointFormats)}";

        string ja3Hash = ComputeMd5(ja3Raw);

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        // Store session info
        string sessionKey = $"{src}:{packet.SourcePort}-{dst}:{packet.DestPort}";
        lock (_lock)
        {
            CleanupTlsSessionsLocked(packet.Timestamp);
            if (_tlsSessions.Count < MaxTlsSessions)
            {
                _tlsSessions[sessionKey] = new TlsSessionInfo
                {
                    Ja3 = ja3Hash,
                    Ja3Raw = ja3Raw,
                    Sni = sni,
                    ClientVersion = clientVersion,
                    Timestamp = packet.Timestamp,
                    ClientRandom = clientRandom
                };
            }
        }

        // Report SNI for visibility (Info level — always useful for red team reconnaissance)
        if (!string.IsNullOrEmpty(sni))
        {
            string sniSig = $"TLS-SNI-{src}-{sni}";
            if (MarkSeen(sniSig, packet.Timestamp))
            {
                ReportWeakness(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "TLS Metadata",
                    Name = $"TLS SNI: {sni}",
                    Description = $"Client {src} connecting to {dst}:{serverPort} with SNI '{sni}'. " +
                                  "Even without decryption, SNI reveals the target hostname. " +
                                  $"JA3 fingerprint: {ja3Hash}",
                    SourceIP = src,
                    DestIP = dst,
                    Port = serverPort,
                    Severity = WeaknessSeverity.Info,
                    ExploitPath = "SNI enables traffic classification and targeted interception. " +
                                  "JA3 hash identifies the client application (e.g., known C2 frameworks have well-documented JA3 hashes). " +
                                  "Compare against threat intel databases: ja3er.com, Salesforce/JA3 GitHub repo.",
                    Mitigation = "Deploy Encrypted Client Hello (ECH/ESNI) to hide SNI. " +
                                 "Use TLS 1.3 with ECH-supporting CDN to prevent SNI-based filtering.",
                    PacketId = packet.Id
                });
            }
        }

        // Flag known-suspicious JA3 hashes (common C2/malware frameworks)
        // These are well-known JA3 hashes from threat intelligence
        string? knownThreat = ja3Hash switch
        {
            "e7d705a3286e19ea42f587b344ee6865" => "Metasploit/Meterpreter",
            "72a589da586844d7f0818ce684948eea" => "Cobalt Strike (default profile)",
            "a0e9f5d64349fb13191bc781f81f42e1" => "Cobalt Strike (modified)",
            "4d7a28d6f2263ed61de88ca66eb011e3" => "PoshC2",
            "3b5074b1b5d032e5620f69f9f700ff0e" => "Empire",
            "1a451a97e2d66a7e0f9c8cc5d91be30b" => "Sliver C2",
            _ => null
        };

        if (knownThreat != null)
        {
            string threatSig = $"TLS-JA3-THREAT-{src}-{ja3Hash}";
            if (MarkSeen(threatSig, packet.Timestamp))
            {
                ReportWeaknessWithEvidence(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "TLS Threat Intelligence",
                    Name = $"Known Malicious JA3 Fingerprint ({knownThreat})",
                    Description = $"Client {src} TLS ClientHello matches JA3 hash {ja3Hash}, " +
                                  $"associated with {knownThreat}. SNI: {sni ?? "(none)"}. " +
                                  "This does not confirm compromise but warrants immediate investigation.",
                    SourceIP = src,
                    DestIP = dst,
                    Port = serverPort,
                    Severity = WeaknessSeverity.Critical,
                    ExploitPath = $"If this is truly {knownThreat}: the host {src} is likely already compromised. " +
                                  "The C2 channel is active and the attacker has an implant running on this machine.",
                    Mitigation = "Isolate host immediately. Collect memory dump and disk image for forensics. " +
                                 "Block destination IP/domain at firewall. Check for lateral movement from this host. " +
                                 "Review authentication logs for the compromised account.",
                    PacketId = packet.Id
                }, packet.RawData);
            }
        }
    }

    private void ParseServerHello(CapturedPacket packet, ReadOnlySpan<byte> payload, ushort serverPort)
    {
        if (payload.Length < 43) return;

        int pos = 9; // after record(5) + hs type(1) + hs length(3)

        ushort serverVersion = (ushort)((payload[pos] << 8) | payload[pos + 1]);
        pos += 2;

        // Random (32 bytes) — save for TlsDecryptor
        byte[] serverRandom = payload.Slice(pos, 32).ToArray();
        pos += 32;

        // Session ID
        if (pos >= payload.Length) return;
        int sessionIdLen = payload[pos]; pos++;
        pos += sessionIdLen;

        // Cipher suite selected (2 bytes)
        if (pos + 2 > payload.Length) return;
        ushort selectedCipher = (ushort)((payload[pos] << 8) | payload[pos + 1]);
        pos += 2;

        // Compression method (1 byte)
        if (pos >= payload.Length) return;
        pos++;

        // Extensions
        var serverExtensions = new List<ushort>();
        if (pos + 2 <= payload.Length)
        {
            int extTotalLen = (payload[pos] << 8) | payload[pos + 1]; pos += 2;
            int extEnd = Math.Min(pos + extTotalLen, payload.Length);

            while (pos + 4 <= extEnd)
            {
                ushort extType = (ushort)((payload[pos] << 8) | payload[pos + 1]);
                int extLen = (payload[pos + 2] << 8) | payload[pos + 3];
                pos += 4;
                if (pos + extLen > extEnd) break;

                if ((extType & 0x0F0F) != 0x0A0A) // skip GREASE
                    serverExtensions.Add(extType);

                pos += extLen;
            }
        }

        // JA3S: TLSVersion,CipherSuite,Extensions
        string ja3sRaw = $"{serverVersion},{selectedCipher},{string.Join("-", serverExtensions)}";
        string ja3sHash = ComputeMd5(ja3sRaw);

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        // Match with ClientHello session
        string sessionKey = $"{dst}:{packet.DestPort}-{src}:{packet.SourcePort}";
        string? ja3 = null;
        string? sni = null;
        lock (_lock)
        {
            if (_tlsSessions.TryGetValue(sessionKey, out var info))
            {
                ja3 = info.Ja3;
                sni = info.Sni;
            }
        }

        // Detect weak cipher selection
        bool isWeakCipher = IsWeakCipherSuite(selectedCipher);
        bool isNullCipher = (selectedCipher & 0xFF) == 0; // NULL cipher
        bool isExportCipher = selectedCipher >= 0x0003 && selectedCipher <= 0x000B; // EXPORT ciphers
        bool isRc4 = selectedCipher == 0x0005 || selectedCipher == 0x002F ||
                     selectedCipher == 0x0004 || selectedCipher == 0xC011 || selectedCipher == 0xC007;

        if (isWeakCipher || isNullCipher || isExportCipher || isRc4)
        {
            string cipherName = $"0x{selectedCipher:X4}";
            string weakness = isNullCipher ? "NULL cipher (no encryption)" :
                              isExportCipher ? "EXPORT-grade cipher (breakable)" :
                              isRc4 ? "RC4 cipher (RFC 7465 prohibited)" :
                              "weak cipher suite";

            string cipherSig = $"TLS-WEAKCIPHER-{src}-{dst}-{serverPort}";
            if (MarkSeen(cipherSig, packet.Timestamp))
            {
                ReportWeaknessWithEvidence(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "TLS Weakness",
                    Name = $"Weak TLS Cipher Selected ({weakness})",
                    Description = $"Server {src}:{serverPort} selected cipher {cipherName} ({weakness}). " +
                                  $"JA3S: {ja3sHash}. " +
                                  (sni != null ? $"SNI: {sni}. " : "") +
                                  (isNullCipher ? "Traffic is NOT encrypted despite TLS negotiation." :
                                   isExportCipher ? "EXPORT ciphers use <=40-bit keys, trivially breakable." :
                                   isRc4 ? "RC4 is prohibited by RFC 7465. Vulnerable to plaintext recovery attacks." :
                                   "This cipher has known vulnerabilities."),
                    SourceIP = src,
                    DestIP = dst,
                    Port = serverPort,
                    Severity = isNullCipher ? WeaknessSeverity.Critical :
                               isExportCipher ? WeaknessSeverity.Critical :
                               WeaknessSeverity.High,
                    ExploitPath = isNullCipher ? "MITM: traffic is plaintext despite TLS wrapper. Sniff directly." :
                                  isExportCipher ? "FREAK/Logjam attack: force EXPORT cipher, break 40-bit key in seconds." :
                                  isRc4 ? "RC4 NOMORE attack: recover plaintext in ~75 hours of captured traffic." :
                                  "Cipher-specific attacks depending on suite.",
                    Mitigation = "Server: configure strong cipher suites only. Mozilla SSL Configuration Generator " +
                                 "provides recommended configs. Minimum: AES-128-GCM or AES-256-GCM with TLS 1.2+.",
                    PacketId = packet.Id
                }, packet.RawData);
            }
        }

        // --- TLS Decryptor: register session with client_random + server_random ---
        // The decryptor uses these to derive encryption keys from SSLKEYLOGFILE material.
        TlsDecryptor? decryptor;
        byte[]? clientRandom = null;
        lock (_lock)
        {
            decryptor = _tlsDecryptor;
            if (decryptor != null && _tlsSessions.TryGetValue(sessionKey, out var sessionInfo))
            {
                clientRandom = sessionInfo.ClientRandom;
                // Store ServerHello data back into session info for reference
                sessionInfo.ServerRandom = serverRandom;
                sessionInfo.SelectedCipher = selectedCipher;
                sessionInfo.NegotiatedVersion = serverVersion;
            }
        }

        if (decryptor != null && clientRandom != null)
        {
            try
            {
                // Determine actual TLS version: if ServerHello says 0x0303 but
                // supported_versions extension selects 0x0304, that's TLS 1.3.
                // For simplicity, use serverVersion directly — TLS 1.3 servers
                // using supported_versions ext will still show 0x0303 in the
                // version field, so we check if any extension was 0x002B (supported_versions)
                // and the selected cipher is a TLS 1.3 suite (0x1301-0x1303).
                ushort effectiveVersion = serverVersion;
                if (serverVersion == 0x0303 &&
                    selectedCipher >= 0x1301 && selectedCipher <= 0x1303)
                {
                    effectiveVersion = 0x0304; // TLS 1.3
                }

                decryptor.RegisterSession(
                    sessionKey, clientRandom, serverRandom,
                    selectedCipher, effectiveVersion);
            }
            catch (Exception ex)
            {
                OnError?.Invoke(ex);
            }
        }
    }

    private void ParseCertificateMessage(CapturedPacket packet, ReadOnlySpan<byte> payload, ushort serverPort)
    {
        // TLS Certificate message: record(5) + hs type(1) + hs length(3) + cert list length(3) = 12
        if (payload.Length < 15) return;

        int pos = 5 + 4; // record header + handshake header

        // Certificates list length (3 bytes)
        int certsListLen = (payload[pos] << 16) | (payload[pos + 1] << 8) | payload[pos + 2];
        pos += 3;
        if (pos + certsListLen > payload.Length) return;

        // Parse first certificate only (the server's cert)
        if (pos + 3 > payload.Length) return;
        int certLen = (payload[pos] << 16) | (payload[pos + 1] << 8) | payload[pos + 2];
        pos += 3;
        if (pos + certLen > payload.Length || certLen < 10) return;

        // Look for anomalies in the raw DER certificate
        // We do lightweight checks without full ASN.1 parsing

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        // Check 1: Self-signed indicator — issuer = subject
        // In DER, the certificate has: SEQUENCE { tbsCertificate { ... issuer ... subject ... } }
        // A crude but effective check: if the cert is very small (<500 bytes), likely self-signed
        bool likelySelfSigned = certLen < 500;

        // Check 2: Look for common test/invalid CN patterns in the raw bytes
        string? suspiciousCn = null;
        try
        {
            // Search for common suspicious patterns in the certificate bytes
            var certSlice = payload.Slice(pos, Math.Min(certLen, 2000));
            string certAscii = Encoding.ASCII.GetString(certSlice);

            // Suspicious CN patterns (common in MITM tools)
            string[] suspiciousPatterns = {
                "mitmproxy", "BurpSuite", "Fiddler", "ZAP Root CA",
                "Charles Proxy", "OWASP", "DO_NOT_TRUST",
                "Sniffing", "sslsplit", "SSLsplit", "bettercap",
                "localhost", "test", "example", "selfsigned",
                "default", "Untrusted"
            };

            foreach (var pattern in suspiciousPatterns)
            {
                if (certAscii.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    suspiciousCn = pattern;
                    break;
                }
            }
        }
        catch { /* encoding issue, skip */ }

        // Check 3: Detect very short RSA key (< 2048 bits)
        // RSA public key in DER is indicated by OID 1.2.840.113549.1.1.1
        // followed by BIT STRING containing the key. Key size ~= bitstring length * 8
        ReadOnlySpan<byte> rsaOid = new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
        bool hasWeakKey = false;
        var certData = payload.Slice(pos, Math.Min(certLen, 2000));
        for (int i = 0; i + rsaOid.Length + 10 < certData.Length; i++)
        {
            if (certData.Slice(i, rsaOid.Length).SequenceEqual(rsaOid))
            {
                // Found RSA OID. The BIT STRING containing the key follows.
                // Approximate key size from remaining cert structure.
                // If total cert < 600 bytes with RSA, key is likely < 2048 bits
                if (certLen < 600) hasWeakKey = true;
                break;
            }
        }

        if (suspiciousCn != null)
        {
            string sig = $"TLS-MITM-CERT-{src}-{dst}-{serverPort}";
            if (MarkSeen(sig, packet.Timestamp))
            {
                ReportWeaknessWithEvidence(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "TLS Certificate Anomaly",
                    Name = $"Suspicious TLS Certificate (MITM Indicator: {suspiciousCn})",
                    Description = $"Server {src}:{serverPort} presented a certificate containing '{suspiciousCn}'. " +
                                  "This pattern is commonly associated with MITM proxy tools intercepting TLS traffic. " +
                                  "If this is not an authorized inspection proxy, the connection is being intercepted.",
                    SourceIP = src,
                    DestIP = dst,
                    Port = serverPort,
                    Severity = WeaknessSeverity.Critical,
                    ExploitPath = "If a MITM proxy is active: all 'encrypted' traffic through this proxy is fully visible to the operator. " +
                                  "Credentials, session tokens, and sensitive data are exposed.",
                    Mitigation = "Investigate whether this is an authorized TLS inspection proxy. " +
                                 "Enable certificate pinning in critical applications. " +
                                 "Deploy Certificate Transparency monitoring.",
                    PacketId = packet.Id
                }, packet.RawData);
            }
        }

        if (likelySelfSigned && suspiciousCn == null)
        {
            string sig = $"TLS-SELFSIGNED-{src}-{serverPort}";
            if (MarkSeen(sig, packet.Timestamp))
            {
                ReportWeakness(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "TLS Certificate Anomaly",
                    Name = "Likely Self-Signed Certificate",
                    Description = $"Server {src}:{serverPort} presented a very small certificate ({certLen} bytes), " +
                                  "indicating a likely self-signed certificate. " +
                                  "Self-signed certs bypass the CA trust chain and may indicate a test server, " +
                                  "a misconfigured service, or a MITM attack.",
                    SourceIP = src,
                    DestIP = dst,
                    Port = serverPort,
                    Severity = WeaknessSeverity.Medium,
                    ExploitPath = "Self-signed certificates are trivially spoofable. An attacker can present their own " +
                                  "self-signed cert to MITM the connection. Users conditioned to accept cert warnings " +
                                  "will not notice the substitution.",
                    Mitigation = "Deploy certificates from a trusted CA (Let's Encrypt for public, internal CA for enterprise). " +
                                 "Enforce certificate validation in all clients. Deploy HSTS with includeSubDomains.",
                    PacketId = packet.Id
                });
            }
        }

        if (hasWeakKey)
        {
            string sig = $"TLS-WEAKKEY-{src}-{serverPort}";
            if (MarkSeen(sig, packet.Timestamp))
            {
                ReportWeakness(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "TLS Certificate Anomaly",
                    Name = "Weak RSA Key Size",
                    Description = $"Server {src}:{serverPort} certificate appears to use an RSA key shorter than 2048 bits. " +
                                  "Keys under 2048 bits are considered factorizable with sufficient resources. " +
                                  "NIST deprecated 1024-bit RSA in 2013.",
                    SourceIP = src,
                    DestIP = dst,
                    Port = serverPort,
                    Severity = WeaknessSeverity.High,
                    ExploitPath = "1024-bit RSA can be factored by nation-state actors. 512-bit RSA is breakable on commodity hardware. " +
                                  "Factoring the key allows forging the certificate and MITMing all connections.",
                    Mitigation = "Regenerate the certificate with RSA >= 2048 bits (preferably 4096) or ECDSA P-256/P-384.",
                    PacketId = packet.Id
                });
            }
        }
    }

    private static bool IsWeakCipherSuite(ushort cipher)
    {
        // NULL ciphers
        if (cipher == 0x0000 || cipher == 0x0001 || cipher == 0x0002) return true;
        // EXPORT ciphers (0x0003-0x000B, 0x0060-0x0066)
        if (cipher >= 0x0003 && cipher <= 0x000B) return true;
        if (cipher >= 0x0060 && cipher <= 0x0066) return true;
        // DES ciphers
        if (cipher == 0x0009 || cipher == 0x000C || cipher == 0x0015 || cipher == 0x001A) return true;
        // RC4 ciphers
        if (cipher == 0x0005 || cipher == 0x0004 || cipher == 0x0017 || cipher == 0x0018) return true;
        if (cipher == 0xC002 || cipher == 0xC007 || cipher == 0xC00C || cipher == 0xC011) return true;
        // 3DES (Sweet32)
        if (cipher == 0x000A || cipher == 0x000D || cipher == 0x0010 || cipher == 0x0013 || cipher == 0x0016) return true;
        return false;
    }

    private static string ComputeMd5(string input)
    {
        byte[] hash = System.Security.Cryptography.MD5.HashData(Encoding.ASCII.GetBytes(input));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private void CleanupTlsSessionsLocked(DateTime now)
    {
        if ((now - _lastTlsSessionCleanup).TotalSeconds < 60) return;
        _lastTlsSessionCleanup = now;

        var cutoff = now - TimeSpan.FromMinutes(10);
        var stale = _tlsSessions.Where(kv => kv.Value.Timestamp < cutoff)
                                .Select(kv => kv.Key).ToList();
        foreach (var k in stale) _tlsSessions.Remove(k);

        if (_tlsSessions.Count > MaxTlsSessions)
        {
            int toRemove = _tlsSessions.Count - MaxTlsSessions + MaxTlsSessions / 4;
            foreach (var k in _tlsSessions.OrderBy(kv => kv.Value.Timestamp).Take(toRemove).Select(kv => kv.Key).ToList())
                _tlsSessions.Remove(k);
        }
    }

    // ============================================================
    // [Gap3] SMB Named Pipe Detection (Lateral Movement Indicator)
    // ============================================================

    private void CheckSmbNamedPipe(CapturedPacket packet)
    {
        if (packet.DestPort != 445 && packet.SourcePort != 445) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 80) return;

        // Find SMB2 header
        for (int i = 0; i + 70 < payload.Length && i < 200; i++)
        {
            if (payload[i] != 0xFE || payload[i + 1] != 'S' || payload[i + 2] != 'M' || payload[i + 3] != 'B')
                continue;

            ushort command = (ushort)(payload[i + 12] | (payload[i + 13] << 8));
            bool isResponse = (payload[i + 16] & 0x01) != 0;

            // SMB2_CREATE (0x0005) request — opening a file/pipe
            if (command != 0x0005 || isResponse) break;

            // SMB2 CREATE request body starts at i + 64
            // Name offset at body + 44 (2 bytes LE), Name length at body + 46 (2 bytes LE)
            int bodyStart = i + 64;
            if (bodyStart + 48 > payload.Length) break;

            ushort nameOffset = (ushort)(payload[bodyStart + 44] | (payload[bodyStart + 45] << 8));
            ushort nameLen = (ushort)(payload[bodyStart + 46] | (payload[bodyStart + 47] << 8));

            // nameOffset is relative to SMB2 header start
            int nameAbsPos = i + nameOffset;
            if (nameAbsPos + nameLen > payload.Length || nameLen == 0 || nameLen > 512) break;

            string? pipeName = null;
            try
            {
                pipeName = Encoding.Unicode.GetString(payload.Slice(nameAbsPos, nameLen)).TrimEnd('\0');
            }
            catch { break; }

            if (string.IsNullOrEmpty(pipeName)) break;

            // Known suspicious named pipes (lateral movement / RPC)
            string pipeNameLower = pipeName.ToLowerInvariant();
            string? pipeCategory = pipeNameLower switch
            {
                "svcctl" => "Service Control Manager — used by PsExec, sc.exe for remote service creation",
                "atsvc" => "Task Scheduler — used for remote scheduled task creation",
                "winreg" => "Remote Registry — used for remote registry access and SAM dump",
                "samr" => "SAM Remote — used for user enumeration and SAM database access",
                "lsarpc" => "LSA Remote — policy enumeration, trust relationships",
                "drsuapi" => "Directory Replication — used by DCSync to extract AD credentials",
                "epmapper" => "Endpoint Mapper — RPC service enumeration",
                "srvsvc" => "Server Service — share enumeration (NetShareEnumAll)",
                "wkssvc" => "Workstation Service — workstation info enumeration",
                "spoolss" => "Print Spooler — PrintNightmare (CVE-2021-34527), SpoolSample (coerce auth)",
                "netlogon" => "Netlogon — ZeroLogon (CVE-2020-1472) if unpatched",
                "browser" => "Browser Service — used for NetBIOS browsing, can be leveraged for relay",
                _ => null
            };

            if (pipeCategory == null)
            {
                // Check for IPC$ access (general lateral movement indicator)
                if (pipeNameLower.StartsWith("ipc$", StringComparison.Ordinal))
                    pipeCategory = "IPC$ null session — prerequisite for many remote management tools";
                else
                    break; // Not a suspicious pipe
            }

            string src = packet.SourceIP ?? "";
            string dst = packet.DestIP ?? "";

            // Track unique pipes per source-dest pair
            string trackKey = $"{src}-{dst}";
            bool isNew;
            lock (_lock)
            {
                CleanupSmbPipesLocked(packet.Timestamp);
                if (!_smbNamedPipes.TryGetValue(trackKey, out var pipes))
                {
                    if (_smbNamedPipes.Count >= MaxSmbPipeEntries) break;
                    pipes = new HashSet<string>();
                    _smbNamedPipes[trackKey] = pipes;
                }
                isNew = pipes.Add(pipeNameLower);
            }

            if (!isNew) break; // Already seen this pipe for this pair

            WeaknessSeverity severity = pipeNameLower switch
            {
                "drsuapi" => WeaknessSeverity.Critical,  // DCSync
                "svcctl" => WeaknessSeverity.High,        // Remote exec
                "atsvc" => WeaknessSeverity.High,         // Remote exec
                "spoolss" => WeaknessSeverity.High,       // PrintNightmare
                "netlogon" => WeaknessSeverity.High,      // ZeroLogon
                "samr" => WeaknessSeverity.High,          // SAM dump
                "winreg" => WeaknessSeverity.High,        // Remote registry
                _ => WeaknessSeverity.Medium
            };

            string sig = $"SMB-PIPE-{src}-{dst}-{pipeNameLower}";
            if (MarkSeen(sig, packet.Timestamp))
            {
                ReportWeaknessWithEvidence(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "SMB Lateral Movement",
                    Name = $"Named Pipe Access: {pipeName}",
                    Description = $"Host {src} opened named pipe '{pipeName}' on {dst}:445. " +
                                  $"Purpose: {pipeCategory}. " +
                                  "Named pipe access to administrative services is a strong indicator of lateral movement or reconnaissance.",
                    SourceIP = src,
                    DestIP = dst,
                    Port = 445,
                    Severity = severity,
                    ExploitPath = pipeNameLower switch
                    {
                        "drsuapi" => "DCSync attack: Mimikatz 'lsadump::dcsync /domain:X /user:krbtgt' extracts ALL domain password hashes.",
                        "svcctl" => "PsExec/sc.exe creates a remote service -> arbitrary code execution as SYSTEM.",
                        "spoolss" => "PrintNightmare: load malicious DLL via AddPrinterDriverEx -> SYSTEM. SpoolSample: coerce authentication for relay.",
                        "samr" => "Enumerate users, groups. With admin: dump SAM hashes (Impacket secretsdump.py).",
                        "winreg" => "Access remote registry: dump SAM/SYSTEM/SECURITY hives for offline hash extraction.",
                        _ => $"Pipe '{pipeName}' enables remote administration. Verify if this access is authorized."
                    },
                    Mitigation = "Restrict SMB access with Windows Firewall: block TCP 445 between workstations. " +
                                 "Use AdminSDHolder and Protected Users group. Enable SMB auditing (Event IDs 5140, 5145). " +
                                 "For PrintSpooler: disable if not needed (Stop-Service Spooler; Set-Service Spooler -StartupType Disabled).",
                    PacketId = packet.Id
                }, packet.RawData);
            }
            break;
        }
    }

    private void CleanupSmbPipesLocked(DateTime now)
    {
        if ((now - _lastSmbPipeCleanup).TotalSeconds < 120) return;
        _lastSmbPipeCleanup = now;

        // Simple cleanup: if over cap, drop oldest half
        if (_smbNamedPipes.Count > MaxSmbPipeEntries)
        {
            int toRemove = _smbNamedPipes.Count / 2;
            foreach (var k in _smbNamedPipes.Keys.Take(toRemove).ToList())
                _smbNamedPipes.Remove(k);
        }
    }

    // ============================================================
    // [Gap3] SMB Relay Chain Detection
    // ============================================================

    private void CheckSmbRelayIndicator(CapturedPacket packet)
    {
        // Detect potential relay: NTLM auth on HTTP closely followed by SMB session setup
        // from the same source. This method checks for SMB2 SESSION_SETUP (command 0x0001)
        // with NTLMSSP AUTHENTICATE message, combined with relay-favorable conditions.
        if (packet.DestPort != 445 && packet.SourcePort != 445) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 100) return;

        // Find SMB2 header
        for (int i = 0; i + 70 < payload.Length && i < 200; i++)
        {
            if (payload[i] != 0xFE || payload[i + 1] != 'S' || payload[i + 2] != 'M' || payload[i + 3] != 'B')
                continue;

            ushort command = (ushort)(payload[i + 12] | (payload[i + 13] << 8));
            bool isResponse = (payload[i + 16] & 0x01) != 0;

            // SESSION_SETUP (0x0001) request
            if (command != 0x0001 || isResponse) break;

            // Check for NTLMSSP in the session setup buffer
            ReadOnlySpan<byte> ntlmSig = "NTLMSSP\0"u8;
            int ntlmPos = -1;
            for (int j = i + 64; j + ntlmSig.Length + 30 < payload.Length && j < i + 500; j++)
            {
                if (payload.Slice(j, ntlmSig.Length).SequenceEqual(ntlmSig))
                {
                    ntlmPos = j;
                    break;
                }
            }
            if (ntlmPos < 0) break;

            // NTLMSSP message type: 3 = AUTHENTICATE
            if (ntlmPos + 28 > payload.Length) break;
            uint msgType = (uint)(payload[ntlmPos + 8] | (payload[ntlmPos + 9] << 8) |
                                  (payload[ntlmPos + 10] << 16) | (payload[ntlmPos + 11] << 24));
            if (msgType != 3) break;

            // Extract domain and username from NTLMSSP AUTHENTICATE
            // DomainName: length at +28, offset at +32 (from NTLMSSP start)
            // UserName: length at +36, offset at +40
            string domain = "", userName = "";
            if (ntlmPos + 44 <= payload.Length)
            {
                ushort domLen = (ushort)(payload[ntlmPos + 28] | (payload[ntlmPos + 29] << 8));
                uint domOff = (uint)(payload[ntlmPos + 32] | (payload[ntlmPos + 33] << 8) |
                                     (payload[ntlmPos + 34] << 16) | (payload[ntlmPos + 35] << 24));
                ushort userLen = (ushort)(payload[ntlmPos + 36] | (payload[ntlmPos + 37] << 8));
                uint userOff = (uint)(payload[ntlmPos + 40] | (payload[ntlmPos + 41] << 8) |
                                      (payload[ntlmPos + 42] << 16) | (payload[ntlmPos + 43] << 24));

                int domAbsPos = ntlmPos + (int)domOff;
                int userAbsPos = ntlmPos + (int)userOff;

                try
                {
                    if (domLen > 0 && domLen <= 200 && domAbsPos >= 0 && domAbsPos + domLen <= payload.Length)
                        domain = Encoding.Unicode.GetString(payload.Slice(domAbsPos, domLen));
                    if (userLen > 0 && userLen <= 200 && userAbsPos >= 0 && userAbsPos + userLen <= payload.Length)
                        userName = Encoding.Unicode.GetString(payload.Slice(userAbsPos, userLen));
                }
                catch { /* encoding issue */ }
            }

            // NtChallengeResponse length at +20
            ushort ntRespLen = (ushort)(payload[ntlmPos + 20] | (payload[ntlmPos + 21] << 8));
            bool isNtlmV1 = ntRespLen == 24;

            string src = packet.SourceIP ?? "";
            string dst = packet.DestIP ?? "";
            string userInfo = !string.IsNullOrEmpty(userName)
                ? $"{domain}\\{userName}"
                : "unknown user";

            string sig = $"SMB-SESSION-{src}-{dst}-{userInfo}";
            if (MarkSeen(sig, packet.Timestamp))
            {
                ReportWeaknessWithEvidence(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "SMB Authentication",
                    Name = $"SMB Session Setup: {userInfo}",
                    Description = $"NTLM{(isNtlmV1 ? "v1" : "v2")} authentication from {src} as '{userInfo}' to {dst}:445. " +
                                  "This captures the full NTLM exchange. " +
                                  (isNtlmV1 ? "NTLMv1 hash is trivially crackable." :
                                   "NTLMv2 hash can be cracked offline (hashcat mode 5600) or relayed."),
                    SourceIP = src,
                    DestIP = dst,
                    Port = 445,
                    Severity = isNtlmV1 ? WeaknessSeverity.Critical : WeaknessSeverity.High,
                    ExploitPath = isNtlmV1
                        ? $"NTLMv1 hash for {userInfo}: submit to crack.sh for near-instant recovery. " +
                          "Recovered NTLM hash enables pass-the-hash to any service accepting NTLM."
                        : $"NTLMv2 hash for {userInfo}: hashcat -m 5600 for offline cracking. " +
                          "If SMB signing is not required on {dst}, this auth can be relayed in real-time with ntlmrelayx.",
                    Mitigation = "Enforce NTLMv2 and SMB signing. Restrict NTLM via GPO. " +
                                 "Consider migrating to Kerberos-only authentication. " +
                                 "Enable Extended Protection for Authentication (EPA).",
                    PacketId = packet.Id
                }, packet.RawData);
            }
            break;
        }
    }

    // ============================================================
    // [Gap3] NTLM Hash Extraction (Multi-protocol)
    // ============================================================

    private void CheckNtlmHashExtraction(CapturedPacket packet)
    {
        // Extract NTLM auth from non-SMB protocols (HTTP, LDAP, MSSQL, etc.)
        // SMB is already handled by CheckSmbRelayIndicator and CheckNtlmv1Downgrade
        if (packet.SourcePort == 445 || packet.DestPort == 445) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 50) return;

        // Search for NTLMSSP signature
        ReadOnlySpan<byte> ntlmSig = "NTLMSSP\0"u8;
        int ntlmPos = -1;
        for (int i = 0; i + ntlmSig.Length + 30 < payload.Length && i < 500; i++)
        {
            if (payload.Slice(i, ntlmSig.Length).SequenceEqual(ntlmSig))
            {
                ntlmPos = i;
                break;
            }
        }
        if (ntlmPos < 0) return;

        if (ntlmPos + 44 > payload.Length) return;
        uint msgType = (uint)(payload[ntlmPos + 8] | (payload[ntlmPos + 9] << 8) |
                              (payload[ntlmPos + 10] << 16) | (payload[ntlmPos + 11] << 24));
        if (msgType != 3) return; // Only AUTHENTICATE messages have the hash

        // Extract user info
        string domain = "", userName = "";
        ushort domLen = (ushort)(payload[ntlmPos + 28] | (payload[ntlmPos + 29] << 8));
        uint domOff = (uint)(payload[ntlmPos + 32] | (payload[ntlmPos + 33] << 8) |
                             (payload[ntlmPos + 34] << 16) | (payload[ntlmPos + 35] << 24));
        ushort userLen = (ushort)(payload[ntlmPos + 36] | (payload[ntlmPos + 37] << 8));
        uint userOff = (uint)(payload[ntlmPos + 40] | (payload[ntlmPos + 41] << 8) |
                              (payload[ntlmPos + 42] << 16) | (payload[ntlmPos + 43] << 24));

        try
        {
            int domAbsPos = ntlmPos + (int)domOff;
            int userAbsPos = ntlmPos + (int)userOff;
            if (domLen > 0 && domLen <= 200 && domAbsPos >= 0 && domAbsPos + domLen <= payload.Length)
                domain = Encoding.Unicode.GetString(payload.Slice(domAbsPos, domLen));
            if (userLen > 0 && userLen <= 200 && userAbsPos >= 0 && userAbsPos + userLen <= payload.Length)
                userName = Encoding.Unicode.GetString(payload.Slice(userAbsPos, userLen));
        }
        catch { return; }

        ushort ntRespLen = (ushort)(payload[ntlmPos + 20] | (payload[ntlmPos + 21] << 8));
        bool isNtlmV1 = ntRespLen == 24;

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";
        string userInfo = !string.IsNullOrEmpty(userName) ? $"{domain}\\{userName}" : "unknown";

        // Determine protocol by port
        ushort serverPort = Math.Min(packet.SourcePort, packet.DestPort);
        string protocol = serverPort switch
        {
            80 or 8080 => "HTTP",
            389 => "LDAP",
            1433 => "MSSQL",
            5985 or 5986 => "WinRM",
            25 or 587 => "SMTP",
            143 or 993 => "IMAP",
            110 or 995 => "POP3",
            _ => $"TCP/{serverPort}"
        };

        string sig = $"NTLM-AUTH-{protocol}-{src}-{dst}-{userInfo}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeaknessWithEvidence(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "NTLM Hash Capture",
            Name = $"NTLM{(isNtlmV1 ? "v1" : "v2")} Authentication over {protocol}",
            Description = $"NTLM{(isNtlmV1 ? "v1" : "v2")} authentication captured: {userInfo} from {src} to {dst}:{serverPort} ({protocol}). " +
                          (isNtlmV1 ? "NTLMv1 hash is recoverable in seconds via rainbow table or crack.sh." :
                           "NTLMv2 hash can be cracked offline. Weak passwords fall in minutes."),
            SourceIP = src,
            DestIP = dst,
            Port = serverPort,
            Severity = isNtlmV1 ? WeaknessSeverity.Critical : WeaknessSeverity.High,
            ExploitPath = isNtlmV1
                ? $"NTLMv1 {userInfo}: recover NTLM hash -> pass-the-hash to SMB/WinRM/RDP/MSSQL."
                : $"NTLMv2 {userInfo}: hashcat -m 5600 <hash> -a 0 rockyou.txt. " +
                  $"If {protocol} is unencrypted, relay with ntlmrelayx --target smb://<target>.",
            Mitigation = $"Require Kerberos authentication for {protocol}. Disable NTLM via GPO. " +
                         "At minimum, enforce NTLMv2: 'Network Security: LAN Manager authentication level' = " +
                         "'Send NTLMv2 response only. Refuse LM & NTLM'.",
            PacketId = packet.Id
        }, packet.RawData);
    }

    // ============================================================
    // [Gap8] RDP Protocol Detection
    // ============================================================

    private void CheckRdpWeakness(CapturedPacket packet)
    {
        if (packet.DestPort != 3389 && packet.SourcePort != 3389) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 11) return;

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";
        bool isToServer = packet.DestPort == 3389;

        // RDP Connection Request (X.224 CR): TPKT header (03 00 xx xx) + X.224 CR (0xE0)
        if (payload[0] == 0x03 && payload[1] == 0x00 && payload.Length >= 11)
        {
            byte x224Type = (byte)(payload[5] >> 4);
            if (x224Type == 0x0E) // Connection Request
            {
                // Check for NLA (CredSSP) in the requestedProtocols field
                // At X.224 variable data, look for "Cookie:" or RDP Negotiation Request
                bool hasNla = false;

                // RDP Neg Request structure: type(1)=0x01, flags(1), length(2)=0x0008, requestedProtocols(4)
                // Bit 0 = TLS, Bit 1 = CredSSP (NLA), Bit 2 = RDSTLS
                for (int i = 11; i + 8 <= payload.Length; i++)
                {
                    if (payload[i] == 0x01 && payload[i + 2] == 0x08 && payload[i + 3] == 0x00)
                    {
                        uint reqProto = (uint)(payload[i + 4] | (payload[i + 5] << 8) |
                                               (payload[i + 6] << 16) | (payload[i + 7] << 24));
                        hasNla = (reqProto & 0x02) != 0; // CredSSP bit
                        break;
                    }
                }

                if (!hasNla)
                {
                    string sig = $"RDP-NONLA-{src}-{dst}";
                    if (MarkSeen(sig, packet.Timestamp))
                    {
                        ReportWeaknessWithEvidence(new DetectedWeakness
                        {
                            Timestamp = packet.Timestamp,
                            Category = "RDP Weakness",
                            Name = "RDP Without NLA (Network Level Authentication)",
                            Description = $"RDP connection from {src} to {dst}:3389 does not request CredSSP/NLA. " +
                                          "Without NLA, the RDP server exposes its login screen before authentication, " +
                                          "enabling credential brute-force, BlueKeep (CVE-2019-0708), and MITM attacks.",
                            SourceIP = src,
                            DestIP = dst,
                            Port = 3389,
                            Severity = WeaknessSeverity.High,
                            ExploitPath = "Without NLA: 1) BlueKeep (CVE-2019-0708) if unpatched Windows 7/2008 R2 -> pre-auth RCE. " +
                                          "2) MITM with Seth/rdp-sec-check to downgrade and capture cleartext credentials. " +
                                          "3) Brute-force via crowbar/hydra against exposed login screen.",
                            Mitigation = "Enable NLA: GPO > Computer Configuration > Admin Templates > Windows Components > Remote Desktop Services > " +
                                         "RD Session Host > Security > 'Require user authentication for remote connections by using NLA' = Enabled. " +
                                         "Restrict RDP access to VPN/jump servers only.",
                            PacketId = packet.Id
                        }, packet.RawData);
                    }
                }

                // Always report RDP service visibility
                string rdpSig = $"RDP-SERVICE-{dst}";
                if (MarkSeen(rdpSig, packet.Timestamp))
                {
                    ReportWeakness(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "RDP Exposure",
                        Name = "RDP Service Accessible",
                        Description = $"RDP service on {dst}:3389 is accessible from {src}. " +
                                      "RDP is a primary target for ransomware operators and initial access brokers.",
                        SourceIP = src,
                        DestIP = dst,
                        Port = 3389,
                        Severity = WeaknessSeverity.Medium,
                        ExploitPath = "RDP brute-force (crowbar, hydra), credential stuffing, CVE exploitation " +
                                      "(BlueKeep, DejaBlue CVE-2019-1181/1182). " +
                                      "Post-auth: session hijacking via tscon, RDP clipboard exfiltration.",
                        Mitigation = "Restrict RDP access behind VPN. Use RD Gateway. " +
                                     "Enable NLA and strong password policy. Block 3389 from untrusted networks.",
                        PacketId = packet.Id
                    });
                }
            }
        }
    }

    // ============================================================
    // [Gap8] WinRM / PowerShell Remoting Detection
    // ============================================================

    private void CheckWinRm(CapturedPacket packet)
    {
        // WinRM: HTTP on 5985, HTTPS on 5986
        if (packet.DestPort != 5985 && packet.SourcePort != 5985 &&
            packet.DestPort != 5986 && packet.SourcePort != 5986) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 20) return;

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";
        bool isToServer = packet.DestPort == 5985 || packet.DestPort == 5986;
        ushort serverPort = isToServer ? packet.DestPort : packet.SourcePort;
        bool isEncrypted = serverPort == 5986;

        // Look for WinRM SOAP envelope markers
        bool isWinRm = false;
        // Check for HTTP POST with /wsman path
        ReadOnlySpan<byte> wsmanPath = "/wsman"u8;
        ReadOnlySpan<byte> soapAction = "schemas.dmtf.org/wbem/wsman"u8;
        ReadOnlySpan<byte> psRemoting = "http://schemas.microsoft.com/powershell"u8;

        for (int i = 0; i + 20 < payload.Length && i < 500; i++)
        {
            if (payload.Slice(i, Math.Min(wsmanPath.Length, payload.Length - i)).SequenceEqual(wsmanPath))
            {
                isWinRm = true;
                break;
            }
            if (i + soapAction.Length < payload.Length &&
                payload.Slice(i, Math.Min(soapAction.Length, payload.Length - i)).SequenceEqual(soapAction))
            {
                isWinRm = true;
                break;
            }
        }

        // Traffic on 5985/5986 is assumed WinRM even without explicit SOAP markers,
        // since these are the well-known WinRM ports and non-WinRM services rarely bind here.
        if (!isWinRm)
        {
            // Only flag if there's actual application data (not bare SYN/ACK)
            if (payload.Length < 10) return;
            isWinRm = true;
        }

        // Check for PowerShell Remoting specifically
        bool isPsRemoting = false;
        for (int i = 0; i + psRemoting.Length < payload.Length && i < 500; i++)
        {
            if (payload.Slice(i, Math.Min(psRemoting.Length, payload.Length - i)).SequenceEqual(psRemoting))
            {
                isPsRemoting = true;
                break;
            }
        }

        if (!isEncrypted && isToServer)
        {
            string sig = $"WINRM-CLEARTEXT-{src}-{dst}";
            if (MarkSeen(sig, packet.Timestamp))
            {
                ReportWeaknessWithEvidence(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "WinRM Weakness",
                    Name = isPsRemoting ? "PowerShell Remoting over HTTP (Cleartext)" : "WinRM over HTTP (Cleartext)",
                    Description = $"WinRM traffic from {src} to {dst}:5985 over cleartext HTTP. " +
                                  (isPsRemoting ? "PowerShell Remoting commands and output can be sniffed. " : "") +
                                  "Credentials (NTLM or Kerberos tokens) are exposed to network-level capture.",
                    SourceIP = src,
                    DestIP = dst,
                    Port = 5985,
                    Severity = WeaknessSeverity.High,
                    ExploitPath = "ARP spoof + packet capture to intercept WinRM commands and responses. " +
                                  "NTLM auth on HTTP WinRM is relayable. " +
                                  "Extract PowerShell commands to understand what the admin is doing -> learn infrastructure.",
                    Mitigation = "Configure WinRM to use HTTPS (5986) with a valid certificate: " +
                                 "'winrm quickconfig -transport:https'. Disable HTTP listener: " +
                                 "'winrm delete winrm/config/listener?Address=*+Transport=HTTP'. " +
                                 "Restrict WinRM access via Windows Firewall or GPO.",
                    PacketId = packet.Id
                }, packet.RawData);
            }
        }

        // Report WinRM activity for lateral movement tracking
        if (isToServer)
        {
            string actSig = $"WINRM-ACTIVITY-{src}-{dst}";
            if (MarkSeen(actSig, packet.Timestamp))
            {
                ReportWeakness(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = isPsRemoting ? "PowerShell Remoting" : "WinRM Activity",
                    Name = isPsRemoting
                        ? $"PowerShell Remoting: {src} → {dst}"
                        : $"WinRM Session: {src} → {dst}",
                    Description = $"WinRM{(isPsRemoting ? "/PSRemoting" : "")} activity from {src} to {dst}:{serverPort}" +
                                  $"{(isEncrypted ? " (HTTPS)" : " (HTTP)")}. " +
                                  "WinRM is the primary lateral movement vector in modern Windows environments.",
                    SourceIP = src,
                    DestIP = dst,
                    Port = serverPort,
                    Severity = WeaknessSeverity.Info,
                    ExploitPath = "If attacker has valid credentials: Enter-PSSession, Invoke-Command for remote code execution. " +
                                  "Evil-WinRM for interactive shell. " +
                                  "WinRM is used by many attack tools: CrackMapExec, Covenant, PowerShell Empire.",
                    Mitigation = "Restrict WinRM to admin jump servers via GPO. " +
                                 "Enable PowerShell ScriptBlock Logging (Event ID 4104) and Module Logging. " +
                                 "Deploy Constrained Language Mode for non-admin users.",
                    PacketId = packet.Id
                });
            }
        }
    }

    // ============================================================
    // [Gap8] DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT) Detection
    // ============================================================

    private void CheckDohDot(CapturedPacket packet)
    {
        // DoT: TCP 853 — already handled by TLS on non-standard port, but we flag it specifically
        // DoH: HTTPS on known DoH resolver IPs — hard to distinguish from regular HTTPS without SNI
        // Here we check for UDP DNS to known DoH providers (which means the client isn't using DoH yet)
        // AND flag DoT connections on TCP 853

        // Check if DNS traffic is going to a known public DoH/DoT provider
        // This is useful intel: it reveals DNS bypass attempts
        string? dstIp = packet.DestIP;
        if (string.IsNullOrEmpty(dstIp)) return;

        // Known public DNS providers
        bool isPublicDns = dstIp switch
        {
            "8.8.8.8" or "8.8.4.4" => true,            // Google
            "1.1.1.1" or "1.0.0.1" => true,            // Cloudflare
            "9.9.9.9" or "149.112.112.112" => true,    // Quad9
            "208.67.222.222" or "208.67.220.220" => true, // OpenDNS
            _ => false
        };

        if (!isPublicDns) return;

        // Flag external DNS usage (bypassing internal DNS infrastructure)
        if (packet.DestPort == 53)
        {
            string sig = $"DNS-EXTERNAL-{packet.SourceIP}-{dstIp}";
            if (MarkSeen(sig, packet.Timestamp))
            {
                ReportWeakness(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "DNS Security",
                    Name = $"External DNS Usage ({dstIp})",
                    Description = $"Host {packet.SourceIP} is sending DNS queries to external resolver {dstIp}:53 " +
                                  "instead of the internal DNS server. This bypasses DNS security controls, " +
                                  "logging, and split-horizon DNS configurations.",
                    SourceIP = packet.SourceIP ?? "",
                    DestIP = dstIp,
                    Port = 53,
                    Severity = WeaknessSeverity.Medium,
                    ExploitPath = "External DNS bypasses: internal DNS logging, DNS-based security filtering (RPZ, sinkholing), " +
                                  "split-DNS for internal resources. Attackers use this for C2 DNS tunneling that evades internal monitoring.",
                    Mitigation = "Block outbound DNS (UDP/TCP 53) to non-internal DNS servers at the firewall. " +
                                 "Force all DNS through internal resolvers. Deploy DNS query logging. " +
                                 "Consider deploying encrypted DNS internally (DoH/DoT to internal resolver).",
                    PacketId = packet.Id
                });
            }
        }
    }

    // ============================================================
    // [Gap8] RADIUS / TACACS+ Detection
    // ============================================================

    private void CheckRadiusTacacs(CapturedPacket packet)
    {
        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        // RADIUS: UDP 1812 (auth), 1813 (accounting) — only on UDP
        if (packet.IpProtocol == 17 &&
            (packet.DestPort == 1812 || packet.SourcePort == 1812 ||
             packet.DestPort == 1813 || packet.SourcePort == 1813))
        {
            ReadOnlySpan<byte> payload = packet.GetPayload();
            if (payload.Length < 20) return; // RADIUS minimum length

            // RADIUS header: Code(1) + Identifier(1) + Length(2) + Authenticator(16)
            byte code = payload[0];
            // Valid RADIUS codes: 1=Access-Request, 2=Accept, 3=Reject, 4=Accounting-Request, 5=Accounting-Response
            if (code < 1 || code > 5) return;

            string codeName = code switch
            {
                1 => "Access-Request",
                2 => "Access-Accept",
                3 => "Access-Reject",
                4 => "Accounting-Request",
                5 => "Accounting-Response",
                _ => $"Code-{code}"
            };

            string sig = $"RADIUS-{src}-{dst}-{codeName}";
            if (MarkSeen(sig, packet.Timestamp))
            {
                ReportWeakness(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "Authentication Infrastructure",
                    Name = $"RADIUS {codeName} Traffic",
                    Description = $"RADIUS {codeName} from {src} to {dst}:{(packet.DestPort == 1812 || packet.DestPort == 1813 ? packet.DestPort : packet.SourcePort)}. " +
                                  "RADIUS is a critical authentication infrastructure component. " +
                                  "RADIUS uses MD5-based shared secret, which is vulnerable if the secret is weak.",
                    SourceIP = src,
                    DestIP = dst,
                    Port = packet.DestPort == 1812 || packet.DestPort == 1813 ? packet.DestPort : packet.SourcePort,
                    Severity = WeaknessSeverity.Info,
                    ExploitPath = "If RADIUS shared secret is cracked (dictionary attack on captured authenticator): " +
                                  "forge Access-Accept responses -> bypass all RADIUS-backed authentication. " +
                                  "RADIUS traffic over UDP is unencrypted (except passwords, which use MD5 XOR).",
                    Mitigation = "Use strong RADIUS shared secrets (32+ random characters). " +
                                 "Deploy RadSec (RADIUS over TLS, RFC 6614) to encrypt RADIUS traffic. " +
                                 "Restrict RADIUS ports to known NAS devices only.",
                    PacketId = packet.Id
                });
            }
        }

        // TACACS+: TCP 49 — only on TCP
        if (packet.IpProtocol == 6 &&
            (packet.DestPort == 49 || packet.SourcePort == 49))
        {
            ReadOnlySpan<byte> payload = packet.GetPayload();
            if (payload.Length < 12) return; // TACACS+ header minimum

            // TACACS+ header: Version(1) + Type(1) + SeqNo(1) + Flags(1) + SessionId(4) + Length(4)
            byte version = payload[0];
            byte majorVer = (byte)(version >> 4);
            if (majorVer != 0x0C) return; // TACACS+ major version = 0xC

            byte type = payload[1];
            byte flags = payload[3];
            bool isEncrypted = (flags & 0x01) == 0; // TAC_PLUS_UNENCRYPTED_FLAG = 0x01 means NOT encrypted

            string typeName = type switch
            {
                1 => "Authentication",
                2 => "Authorization",
                3 => "Accounting",
                _ => $"Type-{type}"
            };

            if (!isEncrypted)
            {
                string sig = $"TACACS-CLEARTEXT-{src}-{dst}";
                if (MarkSeen(sig, packet.Timestamp))
                {
                    ReportWeaknessWithEvidence(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "Authentication Infrastructure",
                        Name = "TACACS+ Cleartext (Unencrypted)",
                        Description = $"TACACS+ {typeName} from {src} to {dst}:49 with TAC_PLUS_UNENCRYPTED_FLAG set. " +
                                      "Credentials are transmitted in cleartext. This is extremely rare in production " +
                                      "and likely indicates misconfiguration or a downgrade attack.",
                        SourceIP = src,
                        DestIP = dst,
                        Port = 49,
                        Severity = WeaknessSeverity.Critical,
                        ExploitPath = "Directly capture network device admin credentials (routers, switches, firewalls). " +
                                      "TACACS+ cleartext exposes usernames, passwords, and authorization commands in plaintext.",
                        Mitigation = "Ensure TACACS+ is configured with a shared key on both client and server. " +
                                     "The key must not be empty. Verify: 'show tacacs-server' on network devices.",
                        PacketId = packet.Id
                    }, packet.RawData);
                }
            }
            else
            {
                string sig = $"TACACS-{src}-{dst}-{typeName}";
                if (MarkSeen(sig, packet.Timestamp))
                {
                    ReportWeakness(new DetectedWeakness
                    {
                        Timestamp = packet.Timestamp,
                        Category = "Authentication Infrastructure",
                        Name = $"TACACS+ {typeName} Traffic",
                        Description = $"TACACS+ {typeName} from {src} to {dst}:49 (encrypted). " +
                                      "TACACS+ uses a weak obfuscation scheme (MD5-based XOR) rather than true encryption.",
                        SourceIP = src,
                        DestIP = dst,
                        Port = 49,
                        Severity = WeaknessSeverity.Low,
                        ExploitPath = "TACACS+ 'encryption' is MD5-based XOR with the shared secret. If the secret is leaked or brute-forced, " +
                                      "all captured traffic can be decrypted. Tools: loki (tacacs+ cracker), Wireshark TACACS+ dissector.",
                        Mitigation = "Use long random shared keys (32+ chars). Consider TACACS+ over IPSec tunnels. " +
                                     "Restrict TCP 49 to management VLANs only.",
                        PacketId = packet.Id
                    });
                }
            }
        }
    }

    // ============================================================
    // [Gap8] 802.1X / EAP Detection (via RADIUS)
    // ============================================================

    private void CheckDot1xEap(CapturedPacket packet)
    {
        // EAP over RADIUS: RADIUS Access-Request with EAP-Message attribute (type 79)
        if (packet.DestPort != 1812 && packet.SourcePort != 1812) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 24) return;

        byte code = payload[0];
        if (code != 1 && code != 2 && code != 3) return; // Access-Request/Accept/Reject

        // Parse RADIUS attributes looking for EAP-Message (type 79)
        int pos = 20; // After RADIUS header
        ushort pktLen = (ushort)((payload[2] << 8) | payload[3]);
        int end = Math.Min(pktLen, payload.Length);

        bool hasEap = false;
        byte eapType = 0;

        while (pos + 2 <= end)
        {
            byte attrType = payload[pos];
            byte attrLen = payload[pos + 1];
            if (attrLen < 2 || pos + attrLen > end) break;

            if (attrType == 79 && attrLen >= 6) // EAP-Message
            {
                hasEap = true;
                // EAP header: Code(1) + Id(1) + Length(2) + Type(1)
                if (pos + 6 < end)
                    eapType = payload[pos + 6]; // EAP type within the attribute value
                break;
            }
            pos += attrLen;
        }

        if (!hasEap) return;

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        string eapTypeName = eapType switch
        {
            1 => "Identity",
            4 => "MD5-Challenge",
            6 => "GTC",
            13 => "EAP-TLS",
            21 => "EAP-TTLS",
            25 => "PEAP",
            43 => "EAP-FAST",
            _ => $"Type-{eapType}"
        };

        // MD5-Challenge is critically weak
        if (eapType == 4)
        {
            string sig = $"EAP-MD5-{src}-{dst}";
            if (MarkSeen(sig, packet.Timestamp))
            {
                ReportWeaknessWithEvidence(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "802.1X / NAC",
                    Name = "EAP-MD5 Challenge (Weak Authentication)",
                    Description = $"802.1X authentication using EAP-MD5 detected between {src} and RADIUS server {dst}. " +
                                  "EAP-MD5 does not provide mutual authentication and the challenge-response " +
                                  "can be captured and cracked offline.",
                    SourceIP = src,
                    DestIP = dst,
                    Port = 1812,
                    Severity = WeaknessSeverity.High,
                    ExploitPath = "Capture EAP-MD5 challenge+response -> offline dictionary attack to recover credentials. " +
                                  "No mutual auth = rogue RADIUS server attack. NAC bypass with recovered credentials.",
                    Mitigation = "Migrate to EAP-TLS (certificate-based) or PEAP-MSCHAPv2 at minimum. " +
                                 "EAP-TLS provides mutual authentication and is the gold standard for 802.1X.",
                    PacketId = packet.Id
                }, packet.RawData);
            }
        }
        else if (eapType != 1) // Skip Identity (noise)
        {
            string sig = $"EAP-{eapTypeName}-{src}-{dst}";
            if (MarkSeen(sig, packet.Timestamp))
            {
                ReportWeakness(new DetectedWeakness
                {
                    Timestamp = packet.Timestamp,
                    Category = "802.1X / NAC",
                    Name = $"802.1X Authentication ({eapTypeName})",
                    Description = $"802.1X/EAP authentication ({eapTypeName}) between {src} and RADIUS server {dst}. " +
                                  "802.1X is deployed as a NAC (Network Access Control) mechanism.",
                    SourceIP = src,
                    DestIP = dst,
                    Port = 1812,
                    Severity = WeaknessSeverity.Info,
                    ExploitPath = eapType switch
                    {
                        25 => "PEAP: rogue AP with hostapd-mana -> capture MSCHAPv2 handshake -> crack with hashcat -m 5500.",
                        21 => "EAP-TTLS: similar to PEAP, rogue AP attack to capture inner authentication.",
                        6 => "GTC: one-time token, limited offline attack surface but vulnerable to rogue AP capture.",
                        13 => "EAP-TLS: strongest 802.1X method. Attack requires compromising a client certificate.",
                        _ => "Investigate EAP type for specific attack vectors."
                    },
                    Mitigation = "Deploy EAP-TLS with client certificates for strongest 802.1X security. " +
                                 "Enable server certificate validation on all supplicants. " +
                                 "Deploy rogue AP detection (WIDS).",
                    PacketId = packet.Id
                });
            }
        }
    }

    // ============================================================
    // [Gap8] QUIC / HTTP/3 Detection (UDP 443)
    // ============================================================

    private void CheckQuicHttp3(CapturedPacket packet)
    {
        // QUIC uses UDP 443 (primarily)
        if (packet.DestPort != 443 && packet.SourcePort != 443) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 5) return;

        // QUIC long header: first byte bit 7 (0x80) = 1 (long header), bit 6 (0x40) = 1 (fixed bit for QUIC v1)
        // QUIC Initial packets: Form bit (0x80) = 1, Fixed bit (0x40) = 1
        byte firstByte = payload[0];
        bool isLongHeader = (firstByte & 0x80) != 0;
        bool isFixedBit = (firstByte & 0x40) != 0;

        if (!isLongHeader || !isFixedBit) return;

        // Version field at bytes 1-4 (for long header)
        if (payload.Length < 5) return;
        uint version = (uint)((payload[1] << 24) | (payload[2] << 16) | (payload[3] << 8) | payload[4]);

        // Known QUIC versions
        string? versionName = version switch
        {
            0x00000001 => "QUIC v1 (RFC 9000)",
            0x6B3343CF => "QUIC v2 (RFC 9369)",
            0xFF000000 or 0xFF00001D or 0xFF00001E or 0xFF00001F or 0xFF000020 => "QUIC draft",
            0x00000000 => "Version Negotiation",
            _ => null
        };

        // Check for QUIC GREASE versions (0x?a?a?a?a pattern)
        if (versionName == null && (version & 0x0F0F0F0F) == 0x0A0A0A0A)
            return; // GREASE version, ignore

        if (versionName == null && version != 0) return; // Unknown, not QUIC

        string src = packet.SourceIP ?? "";
        string dst = packet.DestIP ?? "";

        string sig = $"QUIC-{src}-{dst}";
        if (!MarkSeen(sig, packet.Timestamp)) return;

        ReportWeakness(new DetectedWeakness
        {
            Timestamp = packet.Timestamp,
            Category = "QUIC/HTTP3",
            Name = $"QUIC Traffic Detected ({versionName ?? $"version 0x{version:X8}"})",
            Description = $"QUIC connection from {src} to {dst}:443 ({versionName ?? "unknown version"}). " +
                          "QUIC encrypts most metadata that TCP+TLS exposes, including SNI in QUIC v2. " +
                          "Traditional network monitoring tools cannot inspect QUIC content.",
            SourceIP = src,
            DestIP = dst,
            Port = 443,
            Severity = WeaknessSeverity.Info,
            ExploitPath = "QUIC limits network visibility: no TCP handshake to fingerprint, encrypted headers, " +
                          "0-RTT resumption may expose replay attacks. " +
                          "Passive sniffing is largely ineffective against QUIC traffic.",
            Mitigation = "If QUIC visibility is required: block UDP 443 to force fallback to TCP+TLS (inspectable). " +
                         "Deploy QUIC-aware DPI (e.g., nDPI, Zeek with QUIC analyzer). " +
                         "For enterprises: Chrome policy 'QuicAllowed = false' disables QUIC in managed browsers.",
            PacketId = packet.Id
        });
    }

    // ============================================================
    // Reporting
    // ============================================================

    private void ReportWeakness(DetectedWeakness weakness)
    {
        lock (_lock)
        {
            if (_weaknesses.Count >= MaxWeaknesses)
            {
                // Drop oldest 25% to make room. The list is chronological,
                // so removing from the front preserves the most recent findings.
                _weaknesses.RemoveRange(0, _weaknesses.Count / 4);
            }
            _weaknesses.Add(weakness);
        }
        OnWeaknessDetected?.Invoke(weakness); // raised outside the lock
    }

    /// <summary>
    /// Report a weakness with raw Ethernet frame evidence attached. Used for high-value
    /// findings where the raw packet is needed for forensic proof (credential capture, MITM,
    /// lateral movement). Evidence is truncated to <see cref="MaxEvidenceBytes"/> to bound memory.
    /// </summary>
    private void ReportWeaknessWithEvidence(DetectedWeakness weakness, byte[] rawFrame)
    {
        if (rawFrame != null && rawFrame.Length > 0)
        {
            int cap = Math.Min(rawFrame.Length, MaxEvidenceBytes);
            weakness.RawEvidence = new byte[cap];
            Array.Copy(rawFrame, weakness.RawEvidence, cap);
        }
        ReportWeakness(weakness);
    }

    /// <summary>Max raw evidence bytes stored per finding (16 KB — enough for credential payloads).</summary>
    private const int MaxEvidenceBytes = 16 * 1024;

    // ============================================================
    // [Gap6] Evidence Packaging — PCAP export for findings
    // ============================================================

    /// <summary>
    /// Exports all findings that carry raw evidence into PCAP files grouped by host,
    /// plus an index JSON mapping each file to its findings. Returns the number of
    /// PCAP files written. Each PCAP is named by host IP and is directly viewable in
    /// Wireshark, tcpdump, or any PCAP-compatible tool.
    /// <para>
    /// Directory structure:
    ///   outputDir/
    ///     evidence_index.json       — maps host → findings with evidence
    ///     host_10.0.0.5.pcap        — all evidence packets involving 10.0.0.5
    ///     host_192.168.1.100.pcap
    ///     all_evidence.pcap          — single file with every evidence packet
    /// </para>
    /// </summary>
    public int ExportEvidencePackage(string outputDir)
    {
        if (!Directory.Exists(outputDir))
            Directory.CreateDirectory(outputDir);

        var withEvidence = GetAllWeaknesses().Where(w => w.RawEvidence != null).ToList();
        if (withEvidence.Count == 0) return 0;

        // Group by host (both source and destination)
        var hostPackets = new Dictionary<string, List<(DetectedWeakness finding, byte[] evidence)>>();
        foreach (var w in withEvidence)
        {
            var entry = (w, w.RawEvidence!);
            void AddToHost(string ip)
            {
                if (string.IsNullOrEmpty(ip)) return;
                if (!hostPackets.TryGetValue(ip, out var list))
                {
                    list = new List<(DetectedWeakness, byte[])>();
                    hostPackets[ip] = list;
                }
                list.Add(entry);
            }
            AddToHost(w.SourceIP);
            if (w.DestIP != w.SourceIP) AddToHost(w.DestIP);
        }

        int filesWritten = 0;

        // Write per-host PCAP files
        foreach (var (host, packets) in hostPackets)
        {
            string safeHost = host.Replace(':', '-');  // IPv6 safety
            string pcapPath = Path.Combine(outputDir, $"host_{safeHost}.pcap");
            WritePcapFile(pcapPath, packets.Select(p => (p.finding.Timestamp, p.evidence)));
            filesWritten++;
        }

        // Write combined PCAP
        string allPath = Path.Combine(outputDir, "all_evidence.pcap");
        WritePcapFile(allPath, withEvidence
            .OrderBy(w => w.Timestamp)
            .Select(w => (w.Timestamp, w.RawEvidence!)));
        filesWritten++;

        // Write evidence index JSON
        WriteEvidenceIndex(Path.Combine(outputDir, "evidence_index.json"), withEvidence, hostPackets);
        filesWritten++;

        return filesWritten;
    }

    /// <summary>
    /// Writes a PCAP file with the given packets. Uses LINKTYPE_ETHERNET (1) since
    /// <see cref="DetectedWeakness.RawEvidence"/> stores full Ethernet frames from
    /// <c>CapturedPacket.RawData</c>.
    /// </summary>
    private static void WritePcapFile(string path, IEnumerable<(DateTime timestamp, byte[] frame)> packets)
    {
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        using var bw = new BinaryWriter(fs);

        // PCAP global header (24 bytes)
        bw.Write(0xA1B2C3D4u);   // magic number (native byte order)
        bw.Write((ushort)2);      // version major
        bw.Write((ushort)4);      // version minor
        bw.Write(0);              // thiszone (GMT to local correction)
        bw.Write(0u);             // sigfigs (accuracy of timestamps)
        bw.Write(65535u);         // snaplen (max length of captured packets)
        bw.Write(1u);             // link-layer type: LINKTYPE_ETHERNET

        foreach (var (ts, frame) in packets)
        {
            // Convert DateTime to Unix epoch seconds + microseconds.
            // Guard: pre-epoch timestamps clamp to zero.
            long unixUs = (ts.ToUniversalTime().Ticks - 621355968000000000L) / 10;
            if (unixUs < 0) unixUs = 0;
            uint tsSec = (uint)(unixUs / 1_000_000);
            uint tsUsec = (uint)(unixUs % 1_000_000);

            // Packet record header (16 bytes)
            bw.Write(tsSec);                     // timestamp seconds
            bw.Write(tsUsec);                    // timestamp microseconds
            bw.Write((uint)frame.Length);         // captured length
            bw.Write((uint)frame.Length);         // original length
            bw.Write(frame);                     // packet data
        }
    }

    private void WriteEvidenceIndex(string path,
        List<DetectedWeakness> withEvidence,
        Dictionary<string, List<(DetectedWeakness finding, byte[] evidence)>> hostPackets)
    {
        var sb = new StringBuilder(4096);
        sb.AppendLine("{");
        sb.AppendLine($"  \"generated\": \"{DateTime.UtcNow:O}\",");
        sb.AppendLine($"  \"totalEvidencePackets\": {withEvidence.Count},");
        sb.AppendLine($"  \"totalHosts\": {hostPackets.Count},");
        sb.AppendLine("  \"hosts\": {");

        int hostIdx = 0;
        foreach (var (host, packets) in hostPackets.OrderBy(kv => kv.Key))
        {
            string safeHost = host.Replace(':', '-');
            sb.AppendLine($"    {JsonEscape(host)}: {{");
            sb.AppendLine($"      \"pcapFile\": \"host_{safeHost}.pcap\",");
            sb.AppendLine($"      \"findingCount\": {packets.Count},");
            sb.AppendLine("      \"findings\": [");

            for (int i = 0; i < packets.Count; i++)
            {
                var w = packets[i].finding;
                sb.AppendLine("        {");
                sb.AppendLine($"          \"timestamp\": \"{w.Timestamp:O}\",");
                sb.AppendLine($"          \"severity\": \"{w.SeverityStr}\",");
                sb.AppendLine($"          \"name\": {JsonEscape(w.Name)},");
                sb.AppendLine($"          \"category\": {JsonEscape(w.Category)},");
                sb.AppendLine($"          \"evidenceBytes\": {w.RawEvidence!.Length},");
                sb.AppendLine($"          \"packetId\": {w.PacketId}");
                sb.Append("        }");
                sb.AppendLine(i < packets.Count - 1 ? "," : "");
            }

            sb.AppendLine("      ]");
            sb.Append("    }");
            hostIdx++;
            sb.AppendLine(hostIdx < hostPackets.Count ? "," : "");
        }

        sb.AppendLine("  }");
        sb.AppendLine("}");
        File.WriteAllText(path, sb.ToString());
    }
}

/// <summary>
/// A detected protocol weakness.
/// </summary>
public class DetectedWeakness
{
    public DateTime Timestamp { get; init; }
    public string Category { get; init; } = "";
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string SourceIP { get; init; } = "";
    public string DestIP { get; init; } = "";
    public ushort Port { get; init; }
    public WeaknessSeverity Severity { get; init; }
    public string ExploitPath { get; init; } = "";
    public string Mitigation { get; init; } = "";
    public long PacketId { get; init; }

    /// <summary>
    /// Raw Ethernet frame bytes captured at detection time. Nullable: only populated
    /// for high-value findings (credential captures, MITM indicators, lateral movement).
    /// Suitable for PCAP evidence export.
    /// </summary>
    public byte[]? RawEvidence { get; internal set; }

    public string SeverityStr => Severity switch
    {
        WeaknessSeverity.Critical => "CRITICAL",
        WeaknessSeverity.High => "HIGH",
        WeaknessSeverity.Medium => "MEDIUM",
        WeaknessSeverity.Low => "LOW",
        WeaknessSeverity.Info => "INFO",
        _ => "UNKNOWN"
    };
}

public enum WeaknessSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Per-connection tracking state for Slowloris detection.
/// </summary>
internal class SlowlorisState
{
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public int TotalPackets { get; set; }
    public int RequestCount { get; set; }
    public int IncompleteHeaderCount { get; set; }
    public int DripHeaderCount { get; set; }
}

/// <summary>
/// Tracks TLS session metadata extracted from ClientHello/ServerHello.
/// </summary>
internal class TlsSessionInfo
{
    public string Ja3 { get; init; } = "";
    public string Ja3Raw { get; init; } = "";
    public string? Sni { get; init; }
    public ushort ClientVersion { get; init; }
    public DateTime Timestamp { get; init; }

    // --- TLS Decryptor integration ---
    // Stored from ClientHello, consumed by ParseServerHello to register with TlsDecryptor.
    public byte[]? ClientRandom { get; set; }

    // Stored from ServerHello for decryptor registration.
    public byte[]? ServerRandom { get; set; }
    public ushort SelectedCipher { get; set; }
    public ushort NegotiatedVersion { get; set; }
}

/// <summary>
/// A single entry in the attack timeline reconstruction.
/// </summary>
public class TimelineEntry
{
    public int Order { get; init; }
    public DateTime Timestamp { get; init; }
    public string Phase { get; init; } = "";
    public string Severity { get; init; } = "";
    public string Finding { get; init; } = "";
    public string SourceIP { get; init; } = "";
    public string DestIP { get; init; } = "";
    public ushort Port { get; init; }
}
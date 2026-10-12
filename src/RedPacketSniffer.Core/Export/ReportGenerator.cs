using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RedPacketSniffer.Core.Analysis;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Export;

/// <summary>
/// Tạo summary report từ capture session
///
/// Report bao gồm:
/// 1. Session overview: thời gian, tổng packet, bytes
/// 2. Protocol distribution: TCP/UDP/ICMP/ARP breakdown
/// 3. Top talkers: IP gửi/nhận nhiều nhất
/// 4. Credentials found (từ CredentialExtractor)
/// 5. Weaknesses detected (từ ProtocolWeaknessDetector)
/// 6. Port distribution
/// 7. Timeline (packet rate theo thời gian)
///
/// Output formats: HTML report (standalone) + JSON data
/// </summary>
public sealed class ReportGenerator
{
    /// <summary>
    /// Tạo report data từ capture session
    /// </summary>
    public static ReportData GenerateData(
        IReadOnlyList<CapturedPacket> packets,
        IReadOnlyList<ExtractedCredential> credentials,
        IReadOnlyList<DetectedWeakness> weaknesses,
        TimeSpan captureElapsed)
    {
        var report = new ReportData
        {
            GeneratedAt = DateTime.Now,
            CaptureStart = packets.Count > 0 ? packets[0].Timestamp : DateTime.Now,
            CaptureEnd = packets.Count > 0 ? packets[^1].Timestamp : DateTime.Now,
            CaptureElapsedSeconds = (int)captureElapsed.TotalSeconds,
            TotalPackets = packets.Count,
            TotalBytes = packets.Sum(p => (long)p.Length)
        };

        // Protocol distribution
        var protoDist = packets
            .GroupBy(p => p.IpProtocol switch
            {
                6 => "TCP",
                17 => "UDP",
                1 => "ICMP",
                _ => p.EtherType == 0x0806 ? "ARP" : "Other"
            })
            .ToDictionary(g => g.Key, g => g.Count());
        report.ProtocolDistribution = protoDist;

        // Application protocol distribution
        var appProtoDist = packets
            .Where(p => !string.IsNullOrEmpty(p.ApplicationProtocol))
            .GroupBy(p => p.ApplicationProtocol!)
            .OrderByDescending(g => g.Count())
            .Take(15)
            .ToDictionary(g => g.Key, g => g.Count());
        report.AppProtocolDistribution = appProtoDist;

        // Top talkers — source IP
        var topSrc = packets
            .Where(p => p.SourceIP != null)
            .GroupBy(p => p.SourceIP!)
            .Select(g => new TalkerInfo
            {
                IP = g.Key,
                PacketCount = g.Count(),
                ByteCount = g.Sum(p => (long)p.Length)
            })
            .OrderByDescending(t => t.PacketCount)
            .Take(10)
            .ToList();
        report.TopSourceIPs = topSrc;

        // Top talkers — dest IP
        var topDst = packets
            .Where(p => p.DestIP != null)
            .GroupBy(p => p.DestIP!)
            .Select(g => new TalkerInfo
            {
                IP = g.Key,
                PacketCount = g.Count(),
                ByteCount = g.Sum(p => (long)p.Length)
            })
            .OrderByDescending(t => t.PacketCount)
            .Take(10)
            .ToList();
        report.TopDestIPs = topDst;

        // Top conversations (src-dst pairs)
        var topConversations = packets
            .Where(p => p.SourceIP != null && p.DestIP != null)
            .GroupBy(p =>
            {
                // Normalize: smaller IP first
                var ips = new[] { p.SourceIP!, p.DestIP! };
                Array.Sort(ips, StringComparer.Ordinal);
                return $"{ips[0]} <-> {ips[1]}";
            })
            .Select(g => new ConversationInfo
            {
                Endpoints = g.Key,
                PacketCount = g.Count(),
                ByteCount = g.Sum(p => (long)p.Length)
            })
            .OrderByDescending(c => c.PacketCount)
            .Take(10)
            .ToList();
        report.TopConversations = topConversations;

        // Port distribution (top 15 server ports)
        var portDist = packets
            .Where(p => p.SourcePort > 0)
            .Select(p => Math.Min(p.SourcePort, p.DestPort))
            .GroupBy(port => port)
            .OrderByDescending(g => g.Count())
            .Take(15)
            .ToDictionary(g => g.Key, g => g.Count());
        report.TopPorts = portDist;

        // Direction split
        report.InboundPackets = packets.Count(p => p.Direction == PacketDirection.Inbound);
        report.OutboundPackets = packets.Count(p => p.Direction == PacketDirection.Outbound);

        // Credentials
        report.Credentials = credentials.Select(c => new CredentialInfo
        {
            Timestamp = c.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
            Protocol = c.Protocol,
            SourceIP = c.SourceIP,
            DestIP = c.DestIP,
            Host = c.Host,
            Username = c.Username,
            Password = c.Password,
            Severity = c.SeverityStr
        }).ToList();

        // Weaknesses
        report.Weaknesses = weaknesses.Select(w => new WeaknessInfo
        {
            Timestamp = w.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
            Category = w.Category,
            Name = w.Name,
            Description = w.Description,
            SourceIP = w.SourceIP,
            Severity = w.SeverityStr,
            ExploitPath = w.ExploitPath,
            Mitigation = w.Mitigation
        }).ToList();

        // Weakness summary by category
        report.WeaknessSummary = weaknesses
            .GroupBy(w => w.Category)
            .ToDictionary(g => g.Key, g => g.Count());

        return report;
    }

    /// <summary>
    /// Export report data ra JSON
    /// </summary>
    public static string ExportJson(ReportData report)
    {
        return JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }

    /// <summary>
    /// Export standalone HTML report
    /// </summary>
    public static string ExportHtml(ReportData report)
    {
        var sb = new StringBuilder();

        sb.Append("""
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Red Packet Sniffer - Capture Report</title>
<style>
:root { --bg:#1a1a2e; --bg2:#16213e; --bg3:#0f3460; --text:#e0e0e0; --text2:#a0a0b0; --accent:#00d4ff; --red:#ff4444; --green:#44ff44; --yellow:#ffbb33; --orange:#ff8800; --border:#2a2a4a; }
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',sans-serif; background:var(--bg); color:var(--text); font-size:14px; padding:20px; }
h1 { color:var(--red); margin-bottom:4px; }
h1 span { color:var(--accent); }
h2 { color:var(--accent); margin:24px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--border); font-size:18px; }
h3 { color:var(--text); margin:16px 0 8px; font-size:15px; }
.subtitle { color:var(--text2); margin-bottom:20px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; margin-bottom:20px; }
.card { background:var(--bg2); border:1px solid var(--border); border-radius:6px; padding:14px; }
.card .label { color:var(--text2); font-size:12px; text-transform:uppercase; }
.card .value { color:var(--accent); font-size:24px; font-weight:bold; margin-top:4px; }
.card .value.red { color:var(--red); }
.card .value.green { color:var(--green); }
.card .value.yellow { color:var(--yellow); }
table { width:100%; border-collapse:collapse; margin-bottom:16px; }
th { background:var(--bg3); color:var(--accent); padding:8px 10px; text-align:left; font-size:12px; font-weight:600; }
td { padding:6px 10px; border-bottom:1px solid var(--border); font-size:13px; }
tr:hover { background:rgba(15,52,96,0.3); }
.severity-critical { color:var(--red); font-weight:bold; }
.severity-high { color:var(--orange); font-weight:bold; }
.severity-medium { color:var(--yellow); }
.severity-low { color:var(--text2); }
.severity-info { color:var(--accent); }
.bar-wrap { display:flex; align-items:center; gap:8px; margin-bottom:4px; }
.bar-label { min-width:80px; text-align:right; color:var(--text2); font-size:12px; }
.bar { height:18px; border-radius:3px; min-width:2px; }
.bar-value { font-size:12px; color:var(--text2); }
.exploit-path { background:rgba(255,68,68,0.1); border-left:3px solid var(--red); padding:6px 10px; margin:4px 0; font-size:12px; }
.mitigation { background:rgba(68,255,68,0.1); border-left:3px solid var(--green); padding:6px 10px; margin:4px 0; font-size:12px; }
.footer { margin-top:30px; padding-top:12px; border-top:1px solid var(--border); color:var(--text2); font-size:11px; text-align:center; }
</style>
</head>
<body>
""");

        // Header
        sb.Append($"""
<h1>RED <span>Packet Sniffer</span> - Capture Report</h1>
<p class="subtitle">Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss} | Capture: {report.CaptureStart:HH:mm:ss} - {report.CaptureEnd:HH:mm:ss} ({report.CaptureElapsedSeconds}s)</p>
""");

        // Overview cards
        sb.Append("""
<h2>Overview</h2>
<div class="grid">
""");
        AppendCard(sb, "Total Packets", report.TotalPackets.ToString("N0"), "");
        AppendCard(sb, "Total Bytes", FormatBytes(report.TotalBytes), "");
        AppendCard(sb, "Inbound", report.InboundPackets.ToString("N0"), "green");
        AppendCard(sb, "Outbound", report.OutboundPackets.ToString("N0"), "yellow");
        AppendCard(sb, "Credentials Found", report.Credentials.Count.ToString(), report.Credentials.Count > 0 ? "red" : "");
        AppendCard(sb, "Weaknesses", report.Weaknesses.Count.ToString(), report.Weaknesses.Count > 0 ? "red" : "");
        sb.Append("</div>");

        // Protocol distribution
        sb.Append("<h2>Protocol Distribution</h2>");
        int maxProto = report.ProtocolDistribution.Values.DefaultIfEmpty(1).Max();
        var protoColors = new Dictionary<string, string>
        {
            ["TCP"] = "#4488ff", ["UDP"] = "#bb44ff", ["ICMP"] = "#ffbb33",
            ["ARP"] = "#ff8800", ["Other"] = "#666"
        };
        foreach (var (proto, count) in report.ProtocolDistribution.OrderByDescending(kv => kv.Value))
        {
            string color = protoColors.GetValueOrDefault(proto, "#4488ff");
            int width = (int)(count * 400.0 / maxProto);
            double pct = report.TotalPackets > 0 ? count * 100.0 / report.TotalPackets : 0;
            sb.Append($"""
<div class="bar-wrap"><span class="bar-label">{proto}</span><div class="bar" style="width:{width}px;background:{color}"></div><span class="bar-value">{count:N0} ({pct:F1}%)</span></div>
""");
        }

        // Top Source IPs
        if (report.TopSourceIPs.Count > 0)
        {
            sb.Append("<h2>Top Source IPs</h2><table><tr><th>#</th><th>IP Address</th><th>Packets</th><th>Bytes</th></tr>");
            int rank = 1;
            foreach (var t in report.TopSourceIPs)
            {
                sb.Append($"<tr><td>{rank++}</td><td>{Esc(t.IP)}</td><td>{t.PacketCount:N0}</td><td>{FormatBytes(t.ByteCount)}</td></tr>");
            }
            sb.Append("</table>");
        }

        // Top Dest IPs
        if (report.TopDestIPs.Count > 0)
        {
            sb.Append("<h2>Top Destination IPs</h2><table><tr><th>#</th><th>IP Address</th><th>Packets</th><th>Bytes</th></tr>");
            int rank = 1;
            foreach (var t in report.TopDestIPs)
            {
                sb.Append($"<tr><td>{rank++}</td><td>{Esc(t.IP)}</td><td>{t.PacketCount:N0}</td><td>{FormatBytes(t.ByteCount)}</td></tr>");
            }
            sb.Append("</table>");
        }

        // Top conversations
        if (report.TopConversations.Count > 0)
        {
            sb.Append("<h2>Top Conversations</h2><table><tr><th>#</th><th>Endpoints</th><th>Packets</th><th>Bytes</th></tr>");
            int rank = 1;
            foreach (var c in report.TopConversations)
            {
                sb.Append($"<tr><td>{rank++}</td><td>{Esc(c.Endpoints)}</td><td>{c.PacketCount:N0}</td><td>{FormatBytes(c.ByteCount)}</td></tr>");
            }
            sb.Append("</table>");
        }

        // Port distribution
        if (report.TopPorts.Count > 0)
        {
            sb.Append("<h2>Top Ports</h2><table><tr><th>Port</th><th>Count</th><th>Service</th></tr>");
            foreach (var (port, count) in report.TopPorts.OrderByDescending(kv => kv.Value))
            {
                sb.Append($"<tr><td>{port}</td><td>{count:N0}</td><td>{GetServiceName(port)}</td></tr>");
            }
            sb.Append("</table>");
        }

        // Credentials
        sb.Append("<h2>Extracted Credentials</h2>");
        if (report.Credentials.Count == 0)
        {
            sb.Append("<p style='color:var(--text2)'>No credentials captured in cleartext traffic.</p>");
        }
        else
        {
            sb.Append("<table><tr><th>Time</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Username</th><th>Password</th><th>Severity</th></tr>");
            foreach (var c in report.Credentials)
            {
                string sevClass = $"severity-{c.Severity.ToLowerInvariant()}";
                sb.Append($"<tr><td>{Esc(c.Timestamp)}</td><td>{Esc(c.Protocol)}</td><td>{Esc(c.SourceIP)}</td><td>{Esc(c.DestIP)}</td><td><strong>{Esc(c.Username)}</strong></td><td>{Esc(c.Password)}</td><td class='{sevClass}'>{c.Severity}</td></tr>");
            }
            sb.Append("</table>");
        }

        // Weaknesses
        sb.Append("<h2>Detected Weaknesses</h2>");
        if (report.Weaknesses.Count == 0)
        {
            sb.Append("<p style='color:var(--text2)'>No protocol weaknesses detected.</p>");
        }
        else
        {
            // Summary by category
            sb.Append("<h3>Summary by Category</h3><div class='grid'>");
            foreach (var (cat, count) in report.WeaknessSummary.OrderByDescending(kv => kv.Value))
            {
                AppendCard(sb, cat, count.ToString(), count > 2 ? "red" : "yellow");
            }
            sb.Append("</div>");

            // Detail table
            sb.Append("<h3>Details</h3>");
            foreach (var w in report.Weaknesses)
            {
                string sevClass = $"severity-{w.Severity.ToLowerInvariant()}";
                sb.Append($"""
<div style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:10px">
<div style="display:flex;justify-content:space-between;margin-bottom:6px"><strong>{Esc(w.Name)}</strong><span class="{sevClass}">{w.Severity}</span></div>
<div style="font-size:12px;color:var(--text2);margin-bottom:4px">{Esc(w.Category)} | {Esc(w.SourceIP)} | {Esc(w.Timestamp)}</div>
<div style="margin-bottom:6px">{Esc(w.Description)}</div>
<div class="exploit-path"><strong>Exploit Path:</strong> {Esc(w.ExploitPath)}</div>
<div class="mitigation"><strong>Mitigation:</strong> {Esc(w.Mitigation)}</div>
</div>
""");
            }
        }

        // Footer
        sb.Append($"""
<div class="footer">Red Packet Sniffer - CMC Red Team | Report generated {report.GeneratedAt:yyyy-MM-dd HH:mm:ss}</div>
</body></html>
""");

        return sb.ToString();
    }

    private static void AppendCard(StringBuilder sb, string label, string value, string colorClass)
    {
        string cls = string.IsNullOrEmpty(colorClass) ? "value" : $"value {colorClass}";
        sb.Append($"""<div class="card"><div class="label">{Esc(label)}</div><div class="{cls}">{Esc(value)}</div></div>""");
    }

    private static string Esc(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1048576 => $"{bytes / 1024.0:F1} KB",
        < 1073741824 => $"{bytes / 1048576.0:F1} MB",
        _ => $"{bytes / 1073741824.0:F2} GB"
    };

    private static string GetServiceName(ushort port) => port switch
    {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP",
        53 => "DNS", 67 => "DHCP", 68 => "DHCP", 80 => "HTTP",
        110 => "POP3", 135 => "RPC", 137 => "NetBIOS", 139 => "NetBIOS",
        143 => "IMAP", 389 => "LDAP", 443 => "HTTPS", 445 => "SMB",
        465 => "SMTPS", 587 => "SMTP", 636 => "LDAPS", 993 => "IMAPS",
        995 => "POP3S", 1433 => "MSSQL", 1521 => "Oracle", 3306 => "MySQL",
        3389 => "RDP", 5432 => "PostgreSQL", 5900 => "VNC", 5985 => "WinRM",
        5986 => "WinRM-S", 8080 => "HTTP-Proxy", 8443 => "HTTPS-Alt",
        _ => ""
    };
}

// ============================================================
// Report Data Models
// ============================================================

public class ReportData
{
    public DateTime GeneratedAt { get; set; }
    public DateTime CaptureStart { get; set; }
    public DateTime CaptureEnd { get; set; }
    public int CaptureElapsedSeconds { get; set; }
    public int TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public int InboundPackets { get; set; }
    public int OutboundPackets { get; set; }
    public Dictionary<string, int> ProtocolDistribution { get; set; } = new();
    public Dictionary<string, int> AppProtocolDistribution { get; set; } = new();
    public List<TalkerInfo> TopSourceIPs { get; set; } = new();
    public List<TalkerInfo> TopDestIPs { get; set; } = new();
    public List<ConversationInfo> TopConversations { get; set; } = new();
    public Dictionary<ushort, int> TopPorts { get; set; } = new();
    public List<CredentialInfo> Credentials { get; set; } = new();
    public List<WeaknessInfo> Weaknesses { get; set; } = new();
    public Dictionary<string, int> WeaknessSummary { get; set; } = new();
}

public class TalkerInfo
{
    public string IP { get; set; } = "";
    public int PacketCount { get; set; }
    public long ByteCount { get; set; }
}

public class ConversationInfo
{
    public string Endpoints { get; set; } = "";
    public int PacketCount { get; set; }
    public long ByteCount { get; set; }
}

public class CredentialInfo
{
    public string Timestamp { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string SourceIP { get; set; } = "";
    public string DestIP { get; set; } = "";
    public string Host { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Severity { get; set; } = "";
}

public class WeaknessInfo
{
    public string Timestamp { get; set; } = "";
    public string Category { get; set; } = "";
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string SourceIP { get; set; } = "";
    public string Severity { get; set; } = "";
    public string ExploitPath { get; set; } = "";
    public string Mitigation { get; set; } = "";
}

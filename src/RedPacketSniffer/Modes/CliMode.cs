using RedPacketSniffer.Core.Analysis;
using RedPacketSniffer.Core.Capture;
using RedPacketSniffer.Core.Export;

namespace RedPacketSniffer.Modes;

/// <summary>
/// Console Mode — Interactive terminal UI cho packet capture + analysis
/// </summary>
public static class CliMode
{
    // Core engine
    private static readonly PacketCaptureEngine _engine = new();

    // Analysis engines
    private static readonly CredentialExtractor _credExtractor = new();
    private static readonly ProtocolWeaknessDetector _weakDetector = new();
    private static readonly DnsAnalyzer _dnsAnalyzer = new();
    private static readonly TcpConnectionTracker _tcpTracker = new();
    private static readonly HttpRequestLogger _httpLogger = new();
    private static readonly NetworkHostTracker _hostTracker = new();
    private static readonly L2L3ProtocolAnalyzer _l2l3Analyzer = new();
    private static readonly VoipAnalyzer _voipAnalyzer = new();
    private static ArpSpoofer? _arpSpoofer;
    private static VlanHopper? _vlanHopper;

    // Packet buffer
    private static readonly List<CapturedPacket> _packets = new();
    private static readonly object _lock = new();
    private const int MAX_BUFFER = 50000;

    // State
    private static bool _showLivePackets = true;
    private static bool _showAlerts = true;
    private static long _displayedPacketCount = 0;
    private static int _consoleWidth = 120;

    // Colors
    private static readonly ConsoleColor DefaultColor = ConsoleColor.Gray;

    public static async Task<int> RunAsync(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        try
        {
            _consoleWidth = Math.Max(80, Console.WindowWidth);
        }
        catch { _consoleWidth = 120; }

        // Parse command line args
        var cliArgs = ParseArgs(args);

        PrintBanner();

        // --list mode
        if (cliArgs.ListOnly)
        {
            return RunListAdapters();
        }

        // Wire events
        WireEvents();

        // Open driver
        DriverInfo driverInfo;
        try
        {
            driverInfo = _engine.Open();
            WriteColored($"  WinpkFilter driver v{driverInfo.Version} loaded", ConsoleColor.Green);
            Console.WriteLine();
        }
        catch (Exception ex)
        {
            WriteColored($"  [ERROR] Cannot open WinpkFilter driver: {ex.Message}", ConsoleColor.Red);
            WriteColored("  Make sure WinpkFilter is installed and running as Administrator", ConsoleColor.Yellow);
            return 1;
        }

        // Batch mode: --adapter + --pcap + --duration
        if (cliArgs.AutoAdapter >= 0 && !string.IsNullOrEmpty(cliArgs.PcapOutput) && cliArgs.Duration > 0)
        {
            return await RunBatchMode(cliArgs);
        }

        // Auto-start nếu có --adapter
        if (cliArgs.AutoAdapter >= 0)
        {
            var adapters = _engine.GetAdapters();
            if (cliArgs.AutoAdapter < adapters.Count)
            {
                _engine.SelectAdapter(cliArgs.AutoAdapter);
                _engine.StartCapture();
                WriteColored($"  Auto-started capture on adapter [{cliArgs.AutoAdapter}]", ConsoleColor.Green);
                Console.WriteLine();
            }
        }

        // Interactive mode
        await RunInteractive();
        return 0;
    }

    static void PrintBanner()
    {
        Console.Clear();
        WriteColored(@"
  ╔══════════════════════════════════════════════════╗
  ║                                                  ║
  ║   ██████╗ ██████╗ ███████╗                       ║
  ║   ██╔══██╗██╔══██╗██╔════╝  Red Packet Sniffer  ║
  ║   ██████╔╝██████╔╝███████╗  CMC Red Team         ║
  ║   ██╔══██╗██╔═══╝ ╚════██║  Console Mode         ║
  ║   ██║  ██║██║     ███████║  v1.0                  ║
  ║   ╚═╝  ╚═╝╚═╝     ╚══════╝                       ║
  ║                                                  ║
  ╚══════════════════════════════════════════════════╝
", ConsoleColor.Red);
    }

    static void WireEvents()
    {
        _engine.OnPacketCaptured += packet =>
        {
            // Buffer
            lock (_lock)
            {
                _packets.Add(packet);
                if (_packets.Count > MAX_BUFFER)
                    _packets.RemoveRange(0, _packets.Count - MAX_BUFFER);
            }

            // Analysis pipeline
            _credExtractor.Analyze(packet);
            _weakDetector.Analyze(packet);
            _dnsAnalyzer.Analyze(packet);
            _tcpTracker.Analyze(packet);
            _httpLogger.Analyze(packet);
            _hostTracker.Analyze(packet);
            _l2l3Analyzer.Analyze(packet);
            _voipAnalyzer.Analyze(packet);
            _vlanHopper?.AnalyzePacket(packet);

            // Live display
            if (_showLivePackets)
            {
                PrintPacketLine(packet);
            }
        };

        _credExtractor.OnCredentialFound += cred =>
        {
            if (_showAlerts)
            {
                Console.WriteLine();
                WriteColored($"  [CREDENTIAL] {cred.Protocol} | {cred.SourceIP} -> {cred.DestIP}:{cred.DestPort} | User: {cred.Username} | Pass: {cred.Password}", ConsoleColor.Red);
            }
        };

        _weakDetector.OnWeaknessDetected += weakness =>
        {
            if (_showAlerts)
            {
                Console.WriteLine();
                WriteColored($"  [WEAKNESS] [{weakness.SeverityStr}] {weakness.Name} | {weakness.SourceIP} -> {weakness.DestIP}", ConsoleColor.Yellow);
            }
        };

        _l2l3Analyzer.OnFinding += finding =>
        {
            if (_showAlerts && finding.Severity is "CRITICAL" or "HIGH")
            {
                var color = finding.Severity == "CRITICAL" ? ConsoleColor.Red : ConsoleColor.DarkYellow;
                Console.WriteLine();
                WriteColored($"  [L2/L3] [{finding.Severity}] {finding.Protocol}: {finding.Title} | {finding.SourceIp}", color);
                WriteColored($"          {finding.Detail}", ConsoleColor.DarkGray);
            }
        };

        _voipAnalyzer.OnFinding += finding =>
        {
            if (_showAlerts && finding.Severity is "CRITICAL" or "HIGH")
            {
                var color = finding.Severity == "CRITICAL" ? ConsoleColor.Red : ConsoleColor.DarkYellow;
                Console.WriteLine();
                WriteColored($"  [VoIP] [{finding.Severity}] {finding.Protocol}: {finding.Title} | {finding.SourceIp}", color);
                WriteColored($"         {finding.Detail}", ConsoleColor.DarkGray);
            }
        };

        _voipAnalyzer.OnCredentialFound += cred =>
        {
            if (_showAlerts)
            {
                Console.WriteLine();
                WriteColored($"  [SIP-CRED] {cred.Username}@{cred.Realm} | {cred.SourceIp} -> {cred.DestIp} | Algo: {cred.Algorithm}", ConsoleColor.Red);
                if (!string.IsNullOrEmpty(cred.HashcatFormat))
                    WriteColored($"             Hashcat: {cred.HashcatFormat}", ConsoleColor.DarkRed);
            }
        };

        _engine.OnError += err =>
        {
            WriteColored($"\n  [ERROR] {err}", ConsoleColor.Red);
        };
    }

    static void PrintPacketLine(CapturedPacket p)
    {
        _displayedPacketCount++;
        var dir = p.Direction == PacketDirection.Outbound ? "OUT" : " IN";
        var dirColor = p.Direction == PacketDirection.Outbound ? ConsoleColor.DarkYellow : ConsoleColor.Green;
        var proto = p.ApplicationProtocol ?? p.ProtocolStr;
        var protoColor = proto switch
        {
            "DNS" => ConsoleColor.Cyan,
            "HTTP" => ConsoleColor.Green,
            "HTTPS" or "TLS" => ConsoleColor.DarkGreen,
            "TCP" => ConsoleColor.Blue,
            "UDP" => ConsoleColor.Magenta,
            "ARP" => ConsoleColor.DarkYellow,
            "ICMP" => ConsoleColor.Yellow,
            _ => ConsoleColor.Gray
        };

        string src = p.SourceIP != null
            ? (p.SourcePort > 0 ? $"{p.SourceIP}:{p.SourcePort}" : p.SourceIP)
            : p.SourceMac;
        string dst = p.DestIP != null
            ? (p.DestPort > 0 ? $"{p.DestIP}:{p.DestPort}" : p.DestIP)
            : p.DestMac;

        string line = $"  {p.Id,6} {p.Timestamp:HH:mm:ss.fff} ";
        Console.ForegroundColor = DefaultColor;
        Console.Write(line);

        Console.ForegroundColor = dirColor;
        Console.Write($"{dir} ");

        Console.ForegroundColor = DefaultColor;
        Console.Write($"{src,-22} -> {dst,-22} ");

        Console.ForegroundColor = protoColor;
        Console.Write($"{proto,-8} ");

        Console.ForegroundColor = DefaultColor;
        string info = p.GetSummary();
        int maxInfo = Math.Max(10, _consoleWidth - 85);
        if (info.Length > maxInfo) info = info[..maxInfo] + "...";
        Console.Write($"{p.Length,5}B {info}");

        Console.ResetColor();
        Console.WriteLine();
    }

    // ==============================================
    // Interactive Mode
    // ==============================================
    static async Task RunInteractive()
    {
        PrintHelp();

        while (true)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("\n  rps> ");
            Console.ResetColor();

            string? input = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(input)) continue;

            string[] parts = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            string cmd = parts[0].ToLowerInvariant();

            try
            {
                switch (cmd)
                {
                    case "help" or "h" or "?":
                        PrintHelp();
                        break;

                    case "adapters" or "list" or "ls":
                        ListAdapters();
                        break;

                    case "select" or "sel":
                        if (parts.Length < 2 || !int.TryParse(parts[1], out int idx))
                        {
                            WriteColored("  Usage: select <adapter_index>", ConsoleColor.Yellow);
                            break;
                        }
                        _engine.SelectAdapter(idx);
                        WriteColored($"  Selected adapter [{idx}]", ConsoleColor.Green);
                        break;

                    case "start":
                        ClearAnalysis();
                        var filter = new CaptureFilter();
                        for (int i = 1; i < parts.Length; i++)
                        {
                            var kv = parts[i].Split('=', 2);
                            if (kv.Length != 2) continue;
                            switch (kv[0].ToLower())
                            {
                                case "proto" or "protocol":
                                    filter.Protocols = new HashSet<string>(kv[1].Split(','));
                                    break;
                                case "port":
                                    filter.Ports = new HashSet<ushort>(kv[1].Split(',').Select(ushort.Parse));
                                    break;
                                case "ip":
                                    filter.IpAddresses = new HashSet<string>(kv[1].Split(','));
                                    break;
                                case "subnet":
                                    filter.Subnet = kv[1];
                                    break;
                            }
                        }
                        _engine.SetFilter(filter);
                        _engine.StartCapture();
                        WriteColored("  Capture started (press 'p' to pause display, 's' to stop)", ConsoleColor.Green);
                        break;

                    case "stop":
                        await _engine.StopCaptureAsync();
                        WriteColored("  Capture stopped", ConsoleColor.Yellow);
                        PrintStats();
                        break;

                    case "stats" or "stat":
                        PrintStats();
                        break;

                    case "creds" or "credentials":
                        PrintCredentials();
                        break;

                    case "weak" or "weaknesses":
                        PrintWeaknesses();
                        break;

                    case "dns":
                        int dnsCount = parts.Length > 1 && int.TryParse(parts[1], out int dc) ? dc : 30;
                        PrintDnsRecords(dnsCount);
                        break;

                    case "tcp" or "connections":
                        PrintTcpConnections();
                        break;

                    case "http":
                        int httpCount = parts.Length > 1 && int.TryParse(parts[1], out int hc) ? hc : 30;
                        PrintHttpEntries(httpCount);
                        break;

                    case "hosts":
                        PrintHosts();
                        break;

                    case "protocols" or "l2l3" or "l2":
                        PrintL2L3Findings();
                        break;

                    case "voip" or "sip":
                        PrintVoipFindings();
                        break;

                    case "arpspoof" or "arp" or "mitm":
                        await HandleArpSpoofCommand(parts);
                        break;

                    case "vlanhop" or "vlan" or "dtp":
                        await HandleVlanHopCommand(parts);
                        break;

                    case "pcap" or "export":
                        string pcapFile = parts.Length > 1 ? parts[1] : $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap";
                        ExportPcap(pcapFile);
                        break;

                    case "report":
                        string reportFile = parts.Length > 1 ? parts[1] : $"report_{DateTime.Now:yyyyMMdd_HHmmss}.html";
                        ExportReport(reportFile);
                        break;

                    case "live" or "l":
                        _showLivePackets = !_showLivePackets;
                        WriteColored($"  Live packet display: {(_showLivePackets ? "ON" : "OFF")}", ConsoleColor.Cyan);
                        break;

                    case "alerts" or "a":
                        _showAlerts = !_showAlerts;
                        WriteColored($"  Alert display: {(_showAlerts ? "ON" : "OFF")}", ConsoleColor.Cyan);
                        break;

                    case "clear" or "cls":
                        Console.Clear();
                        PrintBanner();
                        break;

                    case "filter" or "f":
                        if (parts.Length < 2)
                        {
                            WriteColored("  Usage: filter <text> — search packets by keyword", ConsoleColor.Yellow);
                            break;
                        }
                        string keyword = string.Join(' ', parts[1..]).ToLowerInvariant();
                        SearchPackets(keyword);
                        break;

                    case "quit" or "exit" or "q":
                        if (_engine.State == CaptureState.Capturing)
                            await _engine.StopCaptureAsync();
                        WriteColored("  Bye!", ConsoleColor.Green);
                        _engine.Dispose();
                        return;

                    default:
                        WriteColored($"  Unknown command: {cmd}. Type 'help' for commands.", ConsoleColor.Yellow);
                        break;
                }
            }
            catch (Exception ex)
            {
                WriteColored($"  [ERROR] {ex.Message}", ConsoleColor.Red);
            }
        }
    }

    // ==============================================
    // Commands
    // ==============================================
    static int RunListAdapters()
    {
        try
        {
            var info = _engine.Open();
            WriteColored($"  WinpkFilter driver v{info.Version}", ConsoleColor.Green);
            ListAdapters();
            return 0;
        }
        catch (Exception ex)
        {
            WriteColored($"  [ERROR] {ex.Message}", ConsoleColor.Red);
            return 1;
        }
    }

    static void ListAdapters()
    {
        var adapters = _engine.GetAdapters();
        Console.WriteLine();
        WriteColored($"  Found {adapters.Count} network adapters:", ConsoleColor.Cyan);
        Console.WriteLine("  " + new string('─', 90));
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  {"#",-4} {"Name",-35} {"MAC",-20} {"MTU",-6} {"Type",-8}");
        Console.ResetColor();
        Console.WriteLine("  " + new string('─', 90));

        foreach (var a in adapters)
        {
            var typeTag = a.IsWanAdapter ? "WAN" : "LAN";
            var typeColor = a.IsWanAdapter ? ConsoleColor.Yellow : ConsoleColor.Green;
            Console.Write($"  {a.Index,-4} {TruncStr(a.FriendlyName, 35),-35} {a.MacAddress,-20} {a.MTU,-6} ");
            Console.ForegroundColor = typeColor;
            Console.Write($"{typeTag,-8}");
            Console.ResetColor();
            Console.WriteLine();
        }
        Console.WriteLine("  " + new string('─', 90));
    }

    static void PrintStats()
    {
        int packetCount;
        lock (_lock) { packetCount = _packets.Count; }

        Console.WriteLine();
        WriteColored("  ╔═══════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteColored("  ║         Capture Statistics             ║", ConsoleColor.Cyan);
        WriteColored("  ╠═══════════════════════════════════════╣", ConsoleColor.Cyan);
        PrintStatRow("State", _engine.State.ToString(), _engine.State == CaptureState.Capturing ? ConsoleColor.Green : ConsoleColor.Yellow);
        PrintStatRow("Total Packets", _engine.TotalPackets.ToString("N0"));
        PrintStatRow("Filtered Packets", _engine.FilteredPackets.ToString("N0"));
        PrintStatRow("Total Bytes", FormatBytes(_engine.TotalBytes));
        PrintStatRow("Duration", $"{_engine.CaptureElapsed.TotalSeconds:F1}s");
        double pps = _engine.CaptureElapsed.TotalSeconds > 0
            ? _engine.FilteredPackets / _engine.CaptureElapsed.TotalSeconds : 0;
        PrintStatRow("Packets/sec", $"{pps:F0}");
        PrintStatRow("Buffer", packetCount.ToString("N0"));
        WriteColored("  ╠═══════════════════════════════════════╣", ConsoleColor.Cyan);
        PrintStatRow("Credentials", _credExtractor.GetAllCredentials().Count.ToString(), ConsoleColor.Red);
        PrintStatRow("Weaknesses", _weakDetector.GetAllWeaknesses().Count.ToString(), ConsoleColor.Yellow);
        PrintStatRow("DNS Records", _dnsAnalyzer.GetAllRecords().Count.ToString());
        PrintStatRow("TCP Connections", _tcpTracker.GetAllConnections().Count.ToString());
        PrintStatRow("HTTP Entries", _httpLogger.GetAllEntries().Count.ToString());
        PrintStatRow("Network Hosts", _hostTracker.GetAllHosts().Count.ToString());
        PrintStatRow("L2/L3 Findings", _l2l3Analyzer.GetAllFindings().Count.ToString(), ConsoleColor.Magenta);
        var voipSum = _voipAnalyzer.GetSummary();
        PrintStatRow("SIP Credentials", voipSum.TotalCredentials.ToString(), voipSum.TotalCredentials > 0 ? ConsoleColor.Red : null);
        PrintStatRow("SIP Calls", voipSum.TotalCalls.ToString());
        PrintStatRow("RTP Streams", voipSum.TotalRtpStreams.ToString());
        PrintStatRow("STUN Bindings", voipSum.TotalStunBindings.ToString());
        if (_arpSpoofer != null)
        {
            WriteColored("  ╠═══════════════════════════════════════╣", ConsoleColor.Cyan);
            PrintStatRow("ARP Spoof State", _arpSpoofer.State.ToString(), _arpSpoofer.State == ArpSpoofState.Running ? ConsoleColor.Red : null);
            PrintStatRow("ARP Pkts Sent", _arpSpoofer.PacketsSent.ToString());
            PrintStatRow("ARP Targets", _arpSpoofer.TargetCount.ToString());
        }
        if (_vlanHopper != null)
        {
            WriteColored("  ╠═══════════════════════════════════════╣", ConsoleColor.Cyan);
            PrintStatRow("VLAN Hop State", _vlanHopper.State.ToString(),
                _vlanHopper.State == VlanHopState.DtpSpoofing ? ConsoleColor.Red :
                _vlanHopper.State == VlanHopState.DoubleTagging ? ConsoleColor.Yellow : null);
            PrintStatRow("VLAN Method", _vlanHopper.ActiveMethod.ToString());
            PrintStatRow("DTP Detected", _vlanHopper.DtpDetected ? "YES" : "NO",
                _vlanHopper.DtpDetected ? ConsoleColor.Red : null);
            PrintStatRow("Trunk Up", _vlanHopper.TrunkEstablished ? "YES" : "NO",
                _vlanHopper.TrunkEstablished ? ConsoleColor.Red : null);
        }
        WriteColored("  ╚═══════════════════════════════════════╝", ConsoleColor.Cyan);
    }

    static void PrintCredentials()
    {
        var creds = _credExtractor.GetAllCredentials();
        if (creds.Count == 0)
        {
            WriteColored("  No credentials captured", ConsoleColor.Yellow);
            return;
        }

        Console.WriteLine();
        WriteColored($"  ═══ Captured Credentials ({creds.Count}) ═══", ConsoleColor.Red);
        Console.WriteLine();

        foreach (var c in creds)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  [{c.Timestamp:HH:mm:ss}] ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{c.Protocol,-12} ");
            Console.ForegroundColor = DefaultColor;
            Console.Write($"{c.SourceIP} -> {c.DestIP}:{c.DestPort}  ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"User: {c.Username}  ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"Pass: {c.Password}");
            Console.ResetColor();
            Console.WriteLine();
            if (!string.IsNullOrEmpty(c.Host))
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"               Host: {c.Host}");
                Console.ResetColor();
            }
        }
    }

    static void PrintWeaknesses()
    {
        var weaks = _weakDetector.GetAllWeaknesses();
        if (weaks.Count == 0)
        {
            WriteColored("  No weaknesses detected", ConsoleColor.Yellow);
            return;
        }

        Console.WriteLine();
        WriteColored($"  ═══ Protocol Weaknesses ({weaks.Count}) ═══", ConsoleColor.Yellow);
        Console.WriteLine();

        foreach (var w in weaks)
        {
            var sevColor = w.SeverityStr switch
            {
                "Critical" => ConsoleColor.Red,
                "High" => ConsoleColor.DarkYellow,
                "Medium" => ConsoleColor.Yellow,
                _ => ConsoleColor.Gray
            };

            Console.ForegroundColor = sevColor;
            Console.Write($"  [{w.SeverityStr,-8}] ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{w.Name}");
            Console.ResetColor();
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"             {w.SourceIP} -> {w.DestIP}:{w.Port} | {w.Category}");
            Console.WriteLine($"             {w.Description}");
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine($"             Exploit: {w.ExploitPath}");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"             Fix: {w.Mitigation}");
            Console.ResetColor();
            Console.WriteLine();
        }
    }

    static void PrintDnsRecords(int count)
    {
        var records = _dnsAnalyzer.GetAllRecords();
        if (records.Count == 0)
        {
            WriteColored("  No DNS records captured", ConsoleColor.Yellow);
            return;
        }

        var topDomains = _dnsAnalyzer.GetTopDomains(10);
        Console.WriteLine();
        WriteColored($"  ═══ DNS Records ({records.Count} total, showing last {Math.Min(count, records.Count)}) ═══", ConsoleColor.Cyan);

        if (topDomains.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  Top domains:", ConsoleColor.White);
            foreach (var kv in topDomains)
            {
                Console.WriteLine($"    {kv.Value,4}x  {kv.Key}");
            }
        }

        Console.WriteLine();
        var subset = records.TakeLast(count).Reverse();
        foreach (var r in subset)
        {
            var typeColor = r.IsResponse ? ConsoleColor.Green : ConsoleColor.Blue;
            var typeLabel = r.IsResponse ? "RESP" : "QUERY";

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  [{r.Timestamp:HH:mm:ss}] ");
            Console.ForegroundColor = typeColor;
            Console.Write($"{typeLabel,-5} ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{r.QueryName,-40} ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{r.QueryTypeStr,-6} ");

            if (r.Answers.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write(string.Join(", ", r.Answers.Take(3)));
            }

            Console.ResetColor();
            Console.WriteLine();

            foreach (var flag in r.AnomalyFlags)
            {
                WriteColored($"           ⚠ {flag}", ConsoleColor.DarkYellow);
            }
        }
    }

    static void PrintTcpConnections()
    {
        var conns = _tcpTracker.GetAllConnections();
        if (conns.Count == 0)
        {
            WriteColored("  No TCP connections tracked", ConsoleColor.Yellow);
            return;
        }

        Console.WriteLine();
        WriteColored($"  ═══ TCP Connections ({conns.Count}) ═══", ConsoleColor.Blue);
        Console.WriteLine();

        var sorted = conns.OrderByDescending(c => c.AnomalyFlags.Count)
                          .ThenByDescending(c => c.BytesTransferred);

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  {"State",-12} {"Client",-22} {"Server",-22} {"Pkts",-8} {"Bytes",-12} {"Duration",-10} Anomalies");
        Console.ResetColor();
        Console.WriteLine("  " + new string('─', 110));

        foreach (var c in sorted.Take(50))
        {
            var stateColor = c.StateStr switch
            {
                "Established" => ConsoleColor.Green,
                "SynSent" or "SynReceived" => ConsoleColor.Yellow,
                "FinWait" or "Closing" => ConsoleColor.DarkYellow,
                "Reset" => ConsoleColor.Red,
                _ => ConsoleColor.DarkGray
            };

            Console.ForegroundColor = stateColor;
            Console.Write($"  {c.StateStr,-12} ");
            Console.ForegroundColor = DefaultColor;
            Console.Write($"{c.ClientIP + ":" + c.ClientPort,-22} {c.ServerIP + ":" + c.ServerPort,-22} ");
            Console.Write($"{c.PacketCount,-8} {FormatBytes(c.BytesTransferred),-12} ");

            string dur = c.DurationSeconds < 60 ? $"{c.DurationSeconds:F1}s" : $"{c.DurationSeconds / 60:F1}m";
            Console.Write($"{dur,-10} ");

            if (c.AnomalyFlags.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write(string.Join(" | ", c.AnomalyFlags));
            }
            Console.ResetColor();
            Console.WriteLine();
        }
    }

    static void PrintHttpEntries(int count)
    {
        var entries = _httpLogger.GetAllEntries();
        if (entries.Count == 0)
        {
            WriteColored("  No HTTP traffic captured", ConsoleColor.Yellow);
            return;
        }

        var topHosts = _httpLogger.GetTopHosts(10);
        Console.WriteLine();
        WriteColored($"  ═══ HTTP Traffic ({entries.Count} total, showing last {Math.Min(count, entries.Count)}) ═══", ConsoleColor.Green);

        if (topHosts.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  Top hosts:", ConsoleColor.White);
            foreach (var kv in topHosts)
            {
                Console.WriteLine($"    {kv.Value,4}x  {kv.Key}");
            }
        }

        Console.WriteLine();
        var subset = entries.TakeLast(count).Reverse();
        foreach (var e in subset)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  [{e.Timestamp:HH:mm:ss}] ");

            if (e.IsRequest)
            {
                var methodColor = e.Method switch
                {
                    "GET" => ConsoleColor.Green,
                    "POST" => ConsoleColor.DarkYellow,
                    "PUT" => ConsoleColor.Yellow,
                    "DELETE" => ConsoleColor.Red,
                    _ => ConsoleColor.Cyan
                };
                Console.ForegroundColor = methodColor;
                Console.Write($"{e.Method,-7} ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{e.Host} ");
                Console.ForegroundColor = ConsoleColor.Cyan;

                string url = e.Url;
                int maxUrl = Math.Max(20, _consoleWidth - 60);
                if (url.Length > maxUrl) url = url[..maxUrl] + "...";
                Console.Write(url);
            }
            else
            {
                var statusColor = e.StatusCode < 300 ? ConsoleColor.Green :
                                  e.StatusCode < 400 ? ConsoleColor.Blue :
                                  e.StatusCode < 500 ? ConsoleColor.DarkYellow : ConsoleColor.Red;
                Console.ForegroundColor = statusColor;
                Console.Write($"  <- {e.StatusCode} {e.StatusText}");
                if (!string.IsNullOrEmpty(e.ServerHeader))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($" ({e.ServerHeader})");
                }
            }

            Console.ResetColor();
            Console.WriteLine();

            foreach (var flag in e.AnomalyFlags)
            {
                WriteColored($"           ⚠ {flag}", ConsoleColor.DarkYellow);
            }
        }
    }

    static void PrintHosts()
    {
        var hosts = _hostTracker.GetAllHosts();
        if (hosts.Count == 0)
        {
            WriteColored("  No network hosts discovered", ConsoleColor.Yellow);
            return;
        }

        var summary = _hostTracker.GetSummary();
        Console.WriteLine();
        WriteColored($"  ═══ Network Hosts ({summary.TotalHosts}: {summary.PrivateHosts} private, {summary.PublicHosts} public) ═══", ConsoleColor.Magenta);

        if (summary.Subnets.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  Subnets:", ConsoleColor.White);
            foreach (var kv in summary.Subnets.OrderByDescending(kv => kv.Value))
            {
                Console.WriteLine($"    {kv.Key,-20} {kv.Value} hosts");
            }
        }

        if (summary.OsDistribution.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  OS distribution:", ConsoleColor.White);
            foreach (var kv in summary.OsDistribution.OrderByDescending(kv => kv.Value))
            {
                Console.WriteLine($"    {kv.Key,-16} {kv.Value}");
            }
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  {"IP",-18} {"Type",-5} {"MAC",-18} {"Vendor",-14} {"OS",-12} {"Ports",-25} {"Traffic",-14} Anomalies");
        Console.ResetColor();
        Console.WriteLine("  " + new string('─', 130));

        var sorted = hosts.OrderByDescending(h => h.IsPrivate)
                          .ThenByDescending(h => h.BytesSent + h.BytesReceived)
                          .Take(60);

        foreach (var h in sorted)
        {
            var typeColor = h.IsPrivate ? ConsoleColor.Green : ConsoleColor.DarkYellow;
            var typeLabel = h.IsPrivate ? "LAN" : "WAN";

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  {h.IpAddress,-18} ");
            Console.ForegroundColor = typeColor;
            Console.Write($"{typeLabel,-5} ");
            Console.ForegroundColor = DefaultColor;

            string mac = h.MacAddress.Length > 17 ? h.MacAddress[..17] : h.MacAddress;
            Console.Write($"{mac,-18} ");
            Console.Write($"{TruncStr(h.Vendor, 14),-14} ");

            var osColor = h.OsGuess switch
            {
                "Linux/Unix" => ConsoleColor.Yellow,
                "Windows" => ConsoleColor.Blue,
                "Cisco/Network" => ConsoleColor.Magenta,
                _ => ConsoleColor.DarkGray
            };
            Console.ForegroundColor = osColor;
            Console.Write($"{TruncStr(h.OsGuess, 12),-12} ");

            Console.ForegroundColor = ConsoleColor.Cyan;
            string ports = h.OpenPorts.Count > 0
                ? string.Join(",", h.OpenPorts.Take(8)) + (h.OpenPorts.Count > 8 ? $"..+{h.OpenPorts.Count - 8}" : "")
                : "-";
            Console.Write($"{TruncStr(ports, 25),-25} ");

            Console.ForegroundColor = DefaultColor;
            Console.Write($"{FormatBytes(h.BytesSent + h.BytesReceived),-14} ");

            if (h.AnomalyFlags.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write(string.Join(" ", h.AnomalyFlags));
            }

            Console.ResetColor();
            Console.WriteLine();
        }
    }

    static void PrintL2L3Findings()
    {
        var findings = _l2l3Analyzer.GetAllFindings();
        var summary = _l2l3Analyzer.GetSummary();

        if (findings.Count == 0)
        {
            WriteColored("  No L2/L3 protocol findings", ConsoleColor.Yellow);
            return;
        }

        Console.WriteLine();
        WriteColored($"  ═══ L2/L3 Protocol Findings ({findings.Count}) ═══", ConsoleColor.Magenta);
        Console.WriteLine();

        if (summary.Critical > 0) { Console.ForegroundColor = ConsoleColor.Red; Console.Write($"  CRITICAL:{summary.Critical}  "); }
        if (summary.High > 0) { Console.ForegroundColor = ConsoleColor.DarkYellow; Console.Write($"HIGH:{summary.High}  "); }
        if (summary.Medium > 0) { Console.ForegroundColor = ConsoleColor.Yellow; Console.Write($"MEDIUM:{summary.Medium}  "); }
        if (summary.Low > 0) { Console.ForegroundColor = ConsoleColor.Gray; Console.Write($"LOW:{summary.Low}  "); }
        if (summary.Info > 0) { Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write($"INFO:{summary.Info}  "); }
        Console.ResetColor();
        Console.WriteLine();

        if (summary.ProtocolCounts.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  Protocols detected:", ConsoleColor.White);
            foreach (var kv in summary.ProtocolCounts.OrderByDescending(kv => kv.Value))
            {
                Console.WriteLine($"    {kv.Key,-10} {kv.Value} findings");
            }
        }

        Console.WriteLine();
        if (summary.OspfRouters > 0) Console.WriteLine($"    OSPF Routers:   {summary.OspfRouters}");
        if (summary.CdpDevices > 0) Console.WriteLine($"    CDP Devices:    {summary.CdpDevices}");
        if (summary.LldpDevices > 0) Console.WriteLine($"    LLDP Devices:   {summary.LldpDevices}");
        if (summary.HsrpGroups > 0) Console.WriteLine($"    HSRP Groups:    {summary.HsrpGroups}");
        if (summary.VrrpGroups > 0) Console.WriteLine($"    VRRP Instances: {summary.VrrpGroups}");
        if (summary.EigrpNeighbors > 0) Console.WriteLine($"    EIGRP Neighbors:{summary.EigrpNeighbors}");
        if (summary.StpBridges > 0) Console.WriteLine($"    STP Bridges:    {summary.StpBridges}");

        Console.WriteLine();
        var sorted2 = findings
            .OrderBy(f => f.Severity switch { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4 })
            .ThenByDescending(f => f.Timestamp);

        foreach (var f in sorted2)
        {
            var sevColor = f.Severity switch
            {
                "CRITICAL" => ConsoleColor.Red,
                "HIGH" => ConsoleColor.DarkYellow,
                "MEDIUM" => ConsoleColor.Yellow,
                "LOW" => ConsoleColor.Gray,
                _ => ConsoleColor.DarkGray
            };

            Console.ForegroundColor = sevColor;
            Console.Write($"  [{f.Severity,-8}] ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{f.Protocol,-8} ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(f.Title);
            Console.ResetColor();
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"             [{f.Timestamp:HH:mm:ss}] {f.SourceIp} | {f.Category}");

            if (f.Severity is "CRITICAL" or "HIGH" || findings.Count <= 20)
            {
                string detail = f.Detail;
                if (detail.Length > 150) detail = detail[..147] + "...";
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"             {detail}");
            }
            Console.ResetColor();
        }

        var routers = _l2l3Analyzer.GetOspfRouters();
        if (routers.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  ─── OSPF Routers ───", ConsoleColor.Cyan);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {"RouterID",-16} {"IP",-16} {"Area",-10} {"Auth",-12} {"DR",-16} {"BDR",-16}");
            Console.ResetColor();
            foreach (var r in routers)
            {
                var authColor = r.AuthType switch { "NONE" => ConsoleColor.Red, "PLAINTEXT" => ConsoleColor.Red, "MD5" => ConsoleColor.Green, _ => ConsoleColor.DarkGray };
                Console.Write($"  {r.RouterId,-16} {r.SourceIp,-16} {r.Area,-10} ");
                Console.ForegroundColor = authColor;
                Console.Write($"{r.AuthType,-12} ");
                Console.ResetColor();
                Console.WriteLine($"{r.DR,-16} {r.BDR,-16}");
            }
        }

        var cdpDevs = _l2l3Analyzer.GetCdpDevices();
        if (cdpDevs.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  ─── CDP Devices ───", ConsoleColor.Cyan);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {"DeviceID",-24} {"Platform",-20} {"IP",-16} {"Port",-16} {"VLAN",-6}");
            Console.ResetColor();
            foreach (var d in cdpDevs)
            {
                Console.WriteLine($"  {TruncStr(d.DeviceId, 24),-24} {TruncStr(d.Platform, 20),-20} {d.IpAddress,-16} {d.PortId,-16} {d.NativeVlan,-6}");
            }
        }

        var hsrpGroups = _l2l3Analyzer.GetHsrpGroups();
        if (hsrpGroups.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  ─── HSRP Groups ───", ConsoleColor.Cyan);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {"Group",-8} {"State",-12} {"VIP",-16} {"Priority",-10} {"Active",-16} {"Auth",-10}");
            Console.ResetColor();
            foreach (var g in hsrpGroups)
            {
                var authColor = !string.IsNullOrEmpty(g.Auth) ? ConsoleColor.Red : ConsoleColor.DarkGray;
                Console.Write($"  {g.Group,-8} {g.State,-12} {g.VirtualIp,-16} {g.Priority,-10} {g.ActiveRouter,-16} ");
                Console.ForegroundColor = authColor;
                Console.Write($"{(string.IsNullOrEmpty(g.Auth) ? "-" : g.Auth),-10}");
                Console.ResetColor();
                Console.WriteLine();
            }
        }
    }

    static void SearchPackets(string keyword)
    {
        List<CapturedPacket> snapshot;
        lock (_lock) { snapshot = new List<CapturedPacket>(_packets); }

        var matches = snapshot.Where(p =>
        {
            string text = $"{p.SourceIP} {p.DestIP} {p.SourcePort} {p.DestPort} {p.ProtocolStr} {p.ApplicationProtocol} {p.GetSummary()} {p.SourceMac} {p.DestMac}".ToLowerInvariant();
            return text.Contains(keyword);
        }).TakeLast(50).ToList();

        Console.WriteLine();
        WriteColored($"  Found {matches.Count} packets matching '{keyword}':", ConsoleColor.Cyan);
        Console.WriteLine();
        foreach (var p in matches)
        {
            PrintPacketLine(p);
        }
    }

    static void ExportPcap(string filename)
    {
        List<CapturedPacket> snapshot;
        lock (_lock) { snapshot = new List<CapturedPacket>(_packets); }

        if (snapshot.Count == 0)
        {
            WriteColored("  No packets to export", ConsoleColor.Yellow);
            return;
        }

        var pcapBytes = PcapWriter.ExportToBytes(snapshot);
        File.WriteAllBytes(filename, pcapBytes);
        WriteColored($"  Exported {snapshot.Count} packets to {filename} ({FormatBytes(pcapBytes.Length)})", ConsoleColor.Green);
    }

    static void ExportReport(string filename)
    {
        List<CapturedPacket> snapshot;
        lock (_lock) { snapshot = new List<CapturedPacket>(_packets); }

        var creds = _credExtractor.GetAllCredentials();
        var weaks = _weakDetector.GetAllWeaknesses();
        var reportData = ReportGenerator.GenerateData(snapshot, creds, weaks, _engine.CaptureElapsed);
        var html = ReportGenerator.ExportHtml(reportData);
        File.WriteAllText(filename, html);
        WriteColored($"  Exported report to {filename}", ConsoleColor.Green);
    }

    static void ClearAnalysis()
    {
        lock (_lock) { _packets.Clear(); }
        _credExtractor.Clear();
        _weakDetector.Clear();
        _dnsAnalyzer.Clear();
        _tcpTracker.Clear();
        _httpLogger.Clear();
        _hostTracker.Clear();
        _l2l3Analyzer.Clear();
        _voipAnalyzer.Clear();
        _displayedPacketCount = 0;
    }

    // ==============================================
    // Batch Mode
    // ==============================================
    static async Task<int> RunBatchMode(CliArgs cliArgs)
    {
        var adapters = _engine.GetAdapters();
        if (cliArgs.AutoAdapter >= adapters.Count)
        {
            WriteColored($"  [ERROR] Adapter index {cliArgs.AutoAdapter} out of range (max {adapters.Count - 1})", ConsoleColor.Red);
            return 1;
        }

        _showLivePackets = false;
        _engine.SelectAdapter(cliArgs.AutoAdapter);

        var filter = new CaptureFilter();
        if (!string.IsNullOrEmpty(cliArgs.FilterProto))
            filter.Protocols = new HashSet<string>(cliArgs.FilterProto.Split(','));
        if (!string.IsNullOrEmpty(cliArgs.FilterPort))
            filter.Ports = new HashSet<ushort>(cliArgs.FilterPort.Split(',').Select(ushort.Parse));
        _engine.SetFilter(filter);

        WriteColored($"  Batch mode: adapter [{cliArgs.AutoAdapter}], duration {cliArgs.Duration}s, output {cliArgs.PcapOutput}", ConsoleColor.Cyan);
        _engine.StartCapture();
        WriteColored("  Capturing...", ConsoleColor.Green);

        await Task.Delay(cliArgs.Duration * 1000);

        await _engine.StopCaptureAsync();

        ExportPcap(cliArgs.PcapOutput!);

        if (!string.IsNullOrEmpty(cliArgs.ReportOutput))
            ExportReport(cliArgs.ReportOutput);

        PrintStats();
        if (_credExtractor.GetAllCredentials().Count > 0)
            PrintCredentials();
        if (_weakDetector.GetAllWeaknesses().Count > 0)
            PrintWeaknesses();

        _engine.Dispose();
        return 0;
    }

    // ==============================================
    // VoIP
    // ==============================================
    static void PrintVoipFindings()
    {
        var summary = _voipAnalyzer.GetSummary();
        var creds = _voipAnalyzer.GetCredentials();
        var calls = _voipAnalyzer.GetCalls();
        var streams = _voipAnalyzer.GetRtpStreams();
        var stun = _voipAnalyzer.GetStunBindings();

        if (summary.TotalCredentials == 0 && summary.TotalCalls == 0 && summary.TotalRtpStreams == 0 && summary.TotalStunBindings == 0)
        {
            WriteColored("  No VoIP/SIP/WebRTC traffic captured", ConsoleColor.Yellow);
            return;
        }

        Console.WriteLine();
        WriteColored($"  ═══ VoIP / SIP / WebRTC ═══", ConsoleColor.Magenta);
        Console.WriteLine();
        Console.WriteLine($"    SIP Credentials: {summary.TotalCredentials}  |  Calls: {summary.TotalCalls}  |  RTP Streams: {summary.TotalRtpStreams}  |  STUN Bindings: {summary.TotalStunBindings}");

        if (creds.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  ─── SIP Credentials ───", ConsoleColor.Red);
            foreach (var c in creds)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"  [{c.Timestamp:HH:mm:ss}] ");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"{c.Username}@{c.Realm} ");
                Console.ForegroundColor = DefaultColor;
                Console.Write($"| {c.SourceIp} -> {c.DestIp} | Algo: {c.Algorithm}");
                Console.ResetColor();
                Console.WriteLine();

                if (!string.IsNullOrEmpty(c.HashcatFormat))
                {
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    string hc = c.HashcatFormat.Length > 100 ? c.HashcatFormat[..97] + "..." : c.HashcatFormat;
                    Console.WriteLine($"             Hashcat (11400): {hc}");
                    Console.ResetColor();
                }
            }
        }

        if (calls.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  ─── SIP Calls ───", ConsoleColor.Cyan);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {"State",-12} {"From",-24} {"To",-24} {"Duration",-10} {"User-Agent"}");
            Console.ResetColor();
            Console.WriteLine("  " + new string('─', 100));

            foreach (var c in calls)
            {
                var stateColor = c.State switch
                {
                    "Active" or "INVITE" => ConsoleColor.Green,
                    "Ringing" => ConsoleColor.Yellow,
                    "Completed" or "BYE" => ConsoleColor.DarkGray,
                    _ => ConsoleColor.White
                };
                double dur = c.Duration.TotalSeconds;
                Console.ForegroundColor = stateColor;
                Console.Write($"  {c.State,-12} ");
                Console.ForegroundColor = DefaultColor;
                Console.Write($"{TruncStr(c.Caller, 24),-24} {TruncStr(c.Callee, 24),-24} ");
                Console.Write($"{dur:F0}s".PadRight(10));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"{TruncStr(c.UserAgent, 30)}");
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        if (streams.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  ─── RTP Streams ───", ConsoleColor.Cyan);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {"Source",-22} {"Dest",-22} {"Codec",-12} {"Pkts",-8} {"Cleartext"}");
            Console.ResetColor();
            Console.WriteLine("  " + new string('─', 80));

            foreach (var s in streams)
            {
                Console.ForegroundColor = DefaultColor;
                Console.Write($"  {s.SourceIp + ":" + s.SourcePort,-22} {s.DestIp + ":" + s.DestPort,-22} ");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"{s.Codec,-12} ");
                Console.Write($"{s.PacketCount,-8} ");
                bool cleartext = !s.IsEncrypted;
                Console.ForegroundColor = cleartext ? ConsoleColor.Red : ConsoleColor.Green;
                Console.Write(cleartext ? "YES" : "NO");
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        if (stun.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  ─── STUN/TURN Bindings ───", ConsoleColor.Cyan);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {"Source",-22} {"STUN Server",-22} {"Method",-16} {"Mapped Address"}");
            Console.ResetColor();
            Console.WriteLine("  " + new string('─', 90));

            foreach (var b in stun)
            {
                Console.ForegroundColor = DefaultColor;
                Console.Write($"  {b.SourceIp + ":" + b.SourcePort,-22} {b.DestIp + ":" + b.DestPort,-22} {b.Method,-16} ");
                if (!string.IsNullOrEmpty(b.MappedAddress))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write(b.MappedAddress);
                }
                Console.ResetColor();
                Console.WriteLine();
            }
        }
    }

    // ==============================================
    // ARP Spoofing
    // ==============================================
    static async Task HandleArpSpoofCommand(string[] parts)
    {
        string sub = parts.Length > 1 ? parts[1].ToLower() : "status";

        switch (sub)
        {
            case "detect" or "auto":
            {
                _arpSpoofer ??= new ArpSpoofer(_engine);
                _arpSpoofer.OnLog += msg => WriteColored($"  [ARP] {msg}", ConsoleColor.DarkYellow);
                var gw = _arpSpoofer.AutoDetectGateway();
                if (gw == null)
                {
                    WriteColored("  Không tìm thấy default gateway", ConsoleColor.Red);
                }
                else
                {
                    WriteColored($"  Gateway IP: {gw.Value.ip}  MAC: {(string.IsNullOrEmpty(gw.Value.mac) ? "(chưa resolve — ping trước)" : gw.Value.mac)}", ConsoleColor.Green);
                }
                break;
            }

            case "configure" or "config":
            {
                if (parts.Length < 4)
                {
                    WriteColored("  Usage: arpspoof configure <gateway_ip> <gateway_mac> [interval_ms]", ConsoleColor.Yellow);
                    break;
                }
                _arpSpoofer ??= new ArpSpoofer(_engine);
                _arpSpoofer.OnLog += msg => WriteColored($"  [ARP] {msg}", ConsoleColor.DarkYellow);
                int interval = parts.Length > 4 && int.TryParse(parts[4], out int iv) ? iv : 2000;
                _arpSpoofer.Configure(parts[2], parts[3], interval);
                WriteColored("  ARP spoof configured", ConsoleColor.Green);
                break;
            }

            case "add":
            {
                if (_arpSpoofer == null)
                {
                    WriteColored("  Gọi 'arpspoof configure' trước", ConsoleColor.Red);
                    break;
                }
                if (parts.Length < 4)
                {
                    WriteColored("  Usage: arpspoof add <target_ip> <target_mac>", ConsoleColor.Yellow);
                    break;
                }
                _arpSpoofer.AddTarget(parts[2], parts[3]);
                break;
            }

            case "remove" or "rm":
            {
                if (_arpSpoofer == null) break;
                if (parts.Length < 3)
                {
                    WriteColored("  Usage: arpspoof remove <target_ip>", ConsoleColor.Yellow);
                    break;
                }
                _arpSpoofer.RemoveTarget(parts[2]);
                break;
            }

            case "start":
            {
                if (_arpSpoofer == null)
                {
                    WriteColored("  Gọi 'arpspoof configure' và 'arpspoof add' trước", ConsoleColor.Red);
                    break;
                }
                _arpSpoofer.Start();
                WriteColored("  ARP spoofing STARTED — traffic sẽ đi qua máy này", ConsoleColor.Red);
                break;
            }

            case "stop":
            {
                if (_arpSpoofer == null || _arpSpoofer.State != ArpSpoofState.Running)
                {
                    WriteColored("  ARP spoofing không đang chạy", ConsoleColor.Yellow);
                    break;
                }
                await _arpSpoofer.StopAsync();
                WriteColored("  ARP spoofing STOPPED — ARP tables restored", ConsoleColor.Green);
                break;
            }

            case "status" or "info":
            {
                if (_arpSpoofer == null)
                {
                    WriteColored("  ARP Spoofer chưa khởi tạo. Dùng 'arpspoof configure' để bắt đầu.", ConsoleColor.Yellow);
                    break;
                }
                var status = _arpSpoofer.GetStatus();
                Console.WriteLine();
                WriteColored("  ═══ ARP Spoof Status ═══", ConsoleColor.Red);
                var stateColor = status.State == "Running" ? ConsoleColor.Red : ConsoleColor.Green;
                PrintStatRow("State", status.State, stateColor);
                PrintStatRow("Gateway", $"{status.GatewayIp} ({status.GatewayMac})");
                PrintStatRow("Attacker MAC", status.AttackerMac);
                PrintStatRow("Interval", $"{status.IntervalMs}ms");
                PrintStatRow("Packets Sent", status.PacketsSent.ToString());
                PrintStatRow("Targets", status.Targets.Count.ToString());
                foreach (var t in status.Targets)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($"  ║    ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write($"{t.Ip,-18} {t.Mac,-20}");
                    if (t.LastPoisoned > DateTime.MinValue)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.Write($" Last: {t.LastPoisoned:HH:mm:ss}");
                    }
                    Console.ResetColor();
                    Console.WriteLine();
                }
                break;
            }

            default:
                WriteColored("  ARP Spoof commands:", ConsoleColor.Cyan);
                PrintHelpRow("arpspoof detect", "Auto-detect gateway IP/MAC");
                PrintHelpRow("arpspoof configure <gw_ip> <gw_mac> [interval]", "Set gateway");
                PrintHelpRow("arpspoof add <ip> <mac>", "Add target (victim)");
                PrintHelpRow("arpspoof remove <ip>", "Remove target");
                PrintHelpRow("arpspoof start", "Start ARP poisoning");
                PrintHelpRow("arpspoof stop", "Stop + restore ARP tables");
                PrintHelpRow("arpspoof status", "Show current status");
                break;
        }
    }

    // ==============================================
    // VLAN Hopping
    // ==============================================
    static async Task HandleVlanHopCommand(string[] parts)
    {
        string sub = parts.Length > 1 ? parts[1].ToLower() : "status";

        switch (sub)
        {
            case "configure" or "config":
            {
                if (parts.Length < 3)
                {
                    WriteColored("  Usage: vlanhop configure <target_vlan> [native_vlan] [dtp_timeout_sec]", ConsoleColor.Yellow);
                    WriteColored("  Example: vlanhop configure 20          — hop vào VLAN 20, native=1, DTP probe 30s", ConsoleColor.DarkGray);
                    WriteColored("  Example: vlanhop configure 20 1 15     — VLAN 20, native=1, DTP probe 15s", ConsoleColor.DarkGray);
                    break;
                }
                if (!int.TryParse(parts[2], out int targetVlan) || targetVlan < 1 || targetVlan > 4094)
                {
                    WriteColored("  Target VLAN phải là số từ 1-4094", ConsoleColor.Red);
                    break;
                }
                int nativeVlan = parts.Length > 3 && int.TryParse(parts[3], out int nv) ? nv : 1;
                int dtpTimeout = parts.Length > 4 && int.TryParse(parts[4], out int dt) ? dt : 30;

                _vlanHopper ??= new VlanHopper(_engine);
                _vlanHopper.OnLog += msg => WriteColored($"  [VLAN] {msg}", ConsoleColor.Magenta);
                _vlanHopper.OnDtpDetected += info =>
                    WriteColored($"  [VLAN] ⚡ DTP frame from {info.SourceMac}!", ConsoleColor.Red);
                _vlanHopper.Configure(targetVlan, nativeVlan, dtpTimeout);
                WriteColored($"  VLAN Hopping configured — target VLAN {targetVlan}, native VLAN {nativeVlan}", ConsoleColor.Green);
                break;
            }

            case "start":
            {
                if (_vlanHopper == null)
                {
                    WriteColored("  Gọi 'vlanhop configure <target_vlan>' trước", ConsoleColor.Red);
                    break;
                }
                WriteColored("  VLAN Hopping starting...", ConsoleColor.Magenta);
                WriteColored("  Phase 1: Probing DTP — nếu switch bật DTP sẽ negotiate trunk", ConsoleColor.DarkGray);
                WriteColored("  Phase 2: Nếu không có DTP → fallback Double Tagging (one-way)", ConsoleColor.DarkGray);
                _vlanHopper.Start();
                break;
            }

            case "stop":
            {
                if (_vlanHopper == null || _vlanHopper.State == VlanHopState.Idle)
                {
                    WriteColored("  VLAN Hopping không đang chạy", ConsoleColor.Yellow);
                    break;
                }
                await _vlanHopper.StopAsync();
                WriteColored("  VLAN Hopping STOPPED", ConsoleColor.Green);
                break;
            }

            case "arpreq":
            {
                // Gửi ARP request double-tagged vào target VLAN
                if (_vlanHopper == null || _vlanHopper.ActiveMethod == VlanHopMethod.None)
                {
                    WriteColored("  VLAN Hopping chưa active. Gọi 'vlanhop start' trước.", ConsoleColor.Red);
                    break;
                }
                if (parts.Length < 3)
                {
                    WriteColored("  Usage: vlanhop arpreq <target_ip>", ConsoleColor.Yellow);
                    WriteColored("  Gửi ARP request double-tagged vào target VLAN (one-way probe)", ConsoleColor.DarkGray);
                    break;
                }
                bool sent = _vlanHopper.SendDoubleTaggedArpRequest(parts[2]);
                WriteColored(sent
                    ? $"  Double-tagged ARP request sent for {parts[2]}"
                    : $"  Failed to send ARP request", sent ? ConsoleColor.Green : ConsoleColor.Red);
                break;
            }

            case "status" or "info":
            {
                if (_vlanHopper == null)
                {
                    WriteColored("  VLAN Hopper chưa khởi tạo. Dùng 'vlanhop configure' để bắt đầu.", ConsoleColor.Yellow);
                    break;
                }
                var status = _vlanHopper.GetStatus();
                Console.WriteLine();
                WriteColored("  ═══ VLAN Hopping Status ═══", ConsoleColor.Magenta);

                var stateColor = status.State switch
                {
                    "DtpSpoofing" => ConsoleColor.Red,
                    "DoubleTagging" => ConsoleColor.Yellow,
                    "ProbingDtp" => ConsoleColor.Cyan,
                    _ => ConsoleColor.Green
                };
                PrintStatRow("State", status.State, stateColor);
                PrintStatRow("Method", status.ActiveMethod);
                PrintStatRow("Target VLAN", status.TargetVlan.ToString());
                PrintStatRow("Native VLAN", status.NativeVlan.ToString());
                PrintStatRow("DTP Detected", status.DtpDetected ? "YES" : "NO",
                    status.DtpDetected ? ConsoleColor.Red : ConsoleColor.DarkGray);
                if (status.DtpDetected && status.DtpLastSeen.HasValue)
                    PrintStatRow("DTP Last Seen", status.DtpLastSeen.Value.ToString("HH:mm:ss"));
                PrintStatRow("Trunk Established", status.TrunkEstablished ? "YES" : "NO",
                    status.TrunkEstablished ? ConsoleColor.Red : ConsoleColor.DarkGray);
                PrintStatRow("DTP Frames Sent", status.DtpFramesSent.ToString());
                PrintStatRow("DTP Frames Received", status.DtpFramesReceived.ToString());
                PrintStatRow("Double-Tag Sent", status.DoubleTagFramesSent.ToString());
                if (!string.IsNullOrEmpty(status.DetectedVtpDomain))
                    PrintStatRow("VTP Domain", status.DetectedVtpDomain);
                break;
            }

            default:
                WriteColored("  VLAN Hopping commands:", ConsoleColor.Cyan);
                PrintHelpRow("vlanhop configure <vlan> [native] [timeout]", "Configure target VLAN");
                PrintHelpRow("vlanhop start", "Start: probe DTP → trunk or double-tag");
                PrintHelpRow("vlanhop stop", "Stop VLAN hopping");
                PrintHelpRow("vlanhop arpreq <ip>", "Send double-tagged ARP request");
                PrintHelpRow("vlanhop status", "Show current status");
                Console.WriteLine();
                WriteColored("  Workflow:", ConsoleColor.DarkGray);
                WriteColored("    1. vlanhop configure 20         — target VLAN 20", ConsoleColor.DarkGray);
                WriteColored("    2. vlanhop start                — auto DTP probe → fallback double tag", ConsoleColor.DarkGray);
                WriteColored("    3. arpspoof configure ...        — nếu DTP thành công, MITM trong VLAN 20", ConsoleColor.DarkGray);
                break;
        }
    }

    // ==============================================
    // Help
    // ==============================================
    static void PrintHelp()
    {
        Console.WriteLine();
        WriteColored("  ═══════════════════════ Commands ═══════════════════════", ConsoleColor.Cyan);
        Console.WriteLine();
        PrintHelpRow("adapters / list", "List network adapters");
        PrintHelpRow("select <N>", "Select adapter by index");
        PrintHelpRow("start [filters]", "Start capture (e.g. start proto=TCP port=80,443)");
        PrintHelpRow("stop", "Stop capture");
        Console.WriteLine();
        PrintHelpRow("stats", "Show capture statistics");
        PrintHelpRow("creds", "Show captured credentials");
        PrintHelpRow("weak", "Show detected weaknesses");
        PrintHelpRow("dns [N]", "Show DNS records (default: last 30)");
        PrintHelpRow("tcp", "Show TCP connections");
        PrintHelpRow("http [N]", "Show HTTP traffic (default: last 30)");
        PrintHelpRow("hosts", "Show discovered network hosts");
        PrintHelpRow("protocols / l2l3", "Show L2/L3 protocol findings (OSPF, CDP, HSRP...)");
        PrintHelpRow("voip / sip", "Show VoIP/SIP/WebRTC findings (credentials, calls, RTP)");
        PrintHelpRow("arpspoof", "ARP spoofing commands (detect, configure, add, start, stop)");
        PrintHelpRow("vlanhop", "VLAN hopping commands (configure, start, stop, status, arpreq)");
        PrintHelpRow("filter <text>", "Search packets by keyword");
        Console.WriteLine();
        PrintHelpRow("pcap [file]", "Export PCAP file");
        PrintHelpRow("report [file]", "Export HTML report");
        PrintHelpRow("live / l", "Toggle live packet display");
        PrintHelpRow("alerts / a", "Toggle credential/weakness alerts");
        PrintHelpRow("clear", "Clear screen");
        PrintHelpRow("quit / q", "Exit");
        Console.WriteLine();
        WriteColored("  ═══════════════════════════════════════════════════════", ConsoleColor.Cyan);
        Console.WriteLine();
        WriteColored("  CLI usage:", ConsoleColor.White);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("    RedPacketSniffer.exe --cli --list                                  List adapters");
        Console.WriteLine("    RedPacketSniffer.exe --cli --adapter 0                             Interactive mode, auto-start");
        Console.WriteLine("    RedPacketSniffer.exe --cli --adapter 0 --pcap out.pcap --duration 60   Batch: capture 60s, export");
        Console.ResetColor();
    }

    // ==============================================
    // Helpers
    // ==============================================
    static void WriteColored(string text, ConsoleColor color)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    static void PrintStatRow(string label, string value, ConsoleColor? valueColor = null)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  ║  {label,-22} ");
        Console.ForegroundColor = valueColor ?? ConsoleColor.White;
        Console.Write($"{value,-14}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("║");
        Console.ResetColor();
    }

    static void PrintHelpRow(string cmd, string desc)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"  {cmd,-22} ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(desc);
        Console.ResetColor();
    }

    static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1048576) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1073741824) return $"{bytes / 1048576.0:F1} MB";
        return $"{bytes / 1073741824.0:F2} GB";
    }

    static string TruncStr(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length > max ? s[..(max - 2)] + ".." : s;
    }

    static CliArgs ParseArgs(string[] args)
    {
        var result = new CliArgs();
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLower())
            {
                case "--list" or "-l":
                    result.ListOnly = true;
                    break;
                case "--adapter" or "-a":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out int idx))
                        result.AutoAdapter = idx;
                    break;
                case "--pcap" or "-o":
                    if (i + 1 < args.Length) result.PcapOutput = args[++i];
                    break;
                case "--report" or "-r":
                    if (i + 1 < args.Length) result.ReportOutput = args[++i];
                    break;
                case "--duration" or "-d":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out int dur))
                        result.Duration = dur;
                    break;
                case "--proto":
                    if (i + 1 < args.Length) result.FilterProto = args[++i];
                    break;
                case "--port":
                    if (i + 1 < args.Length) result.FilterPort = args[++i];
                    break;
            }
        }
        return result;
    }
}

class CliArgs
{
    public bool ListOnly { get; set; }
    public int AutoAdapter { get; set; } = -1;
    public string? PcapOutput { get; set; }
    public string? ReportOutput { get; set; }
    public int Duration { get; set; }
    public string? FilterProto { get; set; }
    public string? FilterPort { get; set; }
}

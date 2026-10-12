using RedPacketSniffer.Modes;

/// <summary>
/// Red Packet Sniffer — CMC Red Team
/// Unified tool: --cli for console mode, --web for web dashboard
///
/// Usage:
///   RedPacketSniffer.exe --cli                    — interactive console mode
///   RedPacketSniffer.exe --web                    — web dashboard (http://localhost:5000)
///   RedPacketSniffer.exe --cli --adapter 0        — console mode, auto-start on adapter 0
///   RedPacketSniffer.exe --cli --list             — list adapters
///   RedPacketSniffer.exe --cli --adapter 0 --pcap output.pcap --duration 60
///   RedPacketSniffer.exe --web --port 8080        — web mode on custom port
///   RedPacketSniffer.exe                          — default: --cli
/// </summary>

// Determine mode from args
string mode = "cli"; // default
int port = 5000;
var filteredArgs = new List<string>();

for (int i = 0; i < args.Length; i++)
{
    switch (args[i].ToLower())
    {
        case "--cli":
            mode = "cli";
            break;
        case "--web":
            mode = "web";
            break;
        case "--port" or "-p":
            if (i + 1 < args.Length && int.TryParse(args[i + 1], out int p))
            {
                port = p;
                i++; // skip next
            }
            break;
        default:
            filteredArgs.Add(args[i]);
            break;
    }
}

if (mode == "web")
{
    await WebMode.RunAsync(filteredArgs.ToArray(), port);
}
else
{
    var exitCode = await CliMode.RunAsync(filteredArgs.ToArray());
    Environment.Exit(exitCode);
}

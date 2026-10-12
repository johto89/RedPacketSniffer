# Red Packet Sniffer

**Kernel-level network packet capture & security analysis toolkit for Windows**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Red Packet Sniffer is a Windows-native packet capture and network security analysis tool built on the **WinpkFilter NDIS kernel-mode filter driver**. It captures traffic directly from the NDIS layer — below most user-mode network stacks — providing visibility that standard socket-based sniffers miss.

Designed for red teamers and security researchers who need more than passive capture: built-in credential extraction, protocol weakness detection, ARP spoofing with automatic IP forwarding, VLAN hopping (DTP spoofing + double tagging), and Layer 2/3 protocol analysis — all in a single binary with both CLI and web dashboard modes.

## Why Red Packet Sniffer?

| Feature | Wireshark | Red Packet Sniffer |
|---------|-----------|-------------------|
| Capture method | WinPcap/Npcap (user-mode) | WinpkFilter NDIS (kernel-mode) |
| Real-time credential extraction | ✗ Manual filter | ✓ Automatic (HTTP, FTP, SMTP, POP3, IMAP, Telnet, SIP) |
| Protocol weakness detection | ✗ | ✓ 20+ weakness patterns |
| ARP spoofing (MITM) | ✗ | ✓ Built-in with auto IP forwarding |
| VLAN hopping | ✗ | ✓ DTP spoofing + double tagging |
| Web dashboard | ✗ | ✓ Real-time SignalR dashboard |
| Network host mapping | ✗ Manual | ✓ Auto OS fingerprint, open ports |
| Single binary | ✗ | ✓ CLI + Web in one executable |

## Features

### Capture Engine
- Kernel-level capture via WinpkFilter NDIS filter driver
- IPv4, IPv6 (extension headers, scope classification)
- Full protocol parsing: TCP (options), UDP, ICMP/ICMPv6, ARP, DNS, DHCP, HTTP, SIP/RTP
- GRE tunnel decapsulation, VLAN (802.1Q), QinQ
- BPF-like capture filter (protocol, IP, port, subnet)

### 11 Analysis Modules

| Module | Description |
|--------|-------------|
| **CredentialExtractor** | Extract plaintext credentials (HTTP Basic/Digest, FTP, SMTP, POP3, IMAP, Telnet) |
| **ProtocolWeaknessDetector** | Detect weak protocols and misconfigurations (weak TLS, missing HSTS, unencrypted auth) |
| **DnsAnalyzer** | DNS query/response analysis, tunneling detection, DGA domain detection |
| **TcpConnectionTracker** | TCP session tracking, SYN flood detection, RST injection detection |
| **HttpRequestLogger** | Full HTTP request/response logging with URL, cookie, form data extraction |
| **NetworkHostTracker** | Real-time network mapping — hosts, MACs, OS fingerprint, open ports |
| **L2L3ProtocolAnalyzer** | Layer 2/3 deep analysis — ARP, VLAN, MPLS, LLDP, STP, CDP, OSPF, HSRP, DTP |
| **VoipAnalyzer** | SIP signaling analysis, RTP stream detection, STUN binding discovery |
| **ArpSpoofer** | ARP cache poisoning for MITM testing with automatic IP forwarding via `netsh` |
| **VlanHopper** | VLAN hopping — auto DTP probe → DTP spoofing or double tagging fallback |
| **PcapReader/Writer** | PCAP import/export compatible with Wireshark |

### Dual Mode Operation
- **CLI Mode** — Interactive terminal with real-time packet display, built-in commands for all modules
- **Web Mode** — Browser dashboard with SignalR real-time streaming, point-and-click controls

### Export & Reporting
- PCAP export (Wireshark compatible)
- PCAP import for offline analysis
- HTML report with statistics
- JSON report for pipeline integration

## Requirements

| Requirement | Details |
|-------------|---------|
| OS | Windows 10/11 or Windows Server 2016+ (x64) |
| Runtime | .NET 8.0+ |
| Driver | [WinpkFilter](https://www.ntkernel.com/windows-packet-filter/) NDIS driver installed and running |
| Privileges | **Administrator** (kernel driver requires elevation) |
| Build | .NET 8.0 SDK |

## Quick Start

```powershell
# Clone
git clone https://github.com/AresDefenseProject/RedPacketSniffer.git
cd RedPacketSniffer

# Build
dotnet build RedPacketSniffer.sln -c Release

# Run CLI mode
RedPacketSniffer.exe --cli

# Run Web dashboard
RedPacketSniffer.exe --web
```

> See [tutorial.md](tutorial.md) for comprehensive usage guide.

## Project Structure

```
RedPacketSniffer.sln
├── src/
│   ├── RedPacketSniffer/                  # Unified executable (CLI + Web)
│   │   ├── Program.cs                     # Entry point & argument parser
│   │   ├── Modes/
│   │   │   ├── CliMode.cs                 # Console interactive mode
│   │   │   └── WebMode.cs                 # ASP.NET Core + SignalR mode
│   │   ├── Hubs/
│   │   │   └── PacketHub.cs               # SignalR hub for real-time streaming
│   │   ├── Services/
│   │   │   ├── CaptureService.cs          # Singleton capture bridge
│   │   │   └── PacketBroadcastService.cs  # Background event batching (100ms)
│   │   └── wwwroot/
│   │       └── index.html                 # Web dashboard SPA
│   │
│   └── RedPacketSniffer.Core/             # Core library (zero web dependencies)
│       ├── NdisApi/                        # WinpkFilter P/Invoke wrapper
│       ├── Capture/                        # Engine, parser, filter, packet model
│       ├── Analysis/                       # All 11 analysis modules
│       └── Export/                         # PCAP, HTML, JSON export
```

## Security Notice

This tool is built for **authorized security testing only**.

- Credential extraction, ARP spoofing, and VLAN hopping require explicit written authorization
- Always obtain proper approval before capturing traffic on any network
- Comply with local laws and your organization's security policies
- Never use on production networks without stakeholder consent

## License

[MIT License](LICENSE) — free to use, modify, and distribute.

## Author

**Johto Robbie** — Security Researcher

---

*Built with WinpkFilter NDIS driver, .NET 8.0, ASP.NET Core SignalR*

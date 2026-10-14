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

## Publish (run on machines without .NET)

Self-contained publish bundles the .NET 8 runtime — the target machine needs
no .NET installed (WinpkFilter driver + Administrator rights are still required).

```powershell
dotnet publish src/RedPacketSniffer/RedPacketSniffer.csproj -c Release -r win-x64 --self-contained true -o .\publish\win-x64
```

Copy the whole `publish\win-x64` folder to the target machine and run
`RedPacketSniffer.exe --web` as Administrator. (~150MB — mostly the .NET runtime.)

Single-file alternative (~70MB, slower first start — verify the dashboard loads fully):
```powershell
dotnet publish src/RedPacketSniffer/RedPacketSniffer.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o .\publish\single
```

Do not enable trimming (`PublishTrimmed`) — it breaks SignalR/reflection.

## ⚠ IP Forwarding (required for ARP Spoofing)

During ARP spoofing the victim's traffic flows through your machine. Windows drops packets
not addressed to itself by default, so the victim **loses connectivity** unless forwarding is on.
The tool enables it automatically on `ArpSpoofStart` and restores the previous state on
`ArpSpoofStop` (per-interface + `IPEnableRouter` registry, verified against the sniffing NIC —
see the `Sniffing interface: ...` log line).

If the tool reports it cannot enable forwarding (missing privileges, GPO restriction),
check and enable it manually **as Administrator** on the interface you want to sniff
(e.g. `"Wi-Fi"` or `"Ethernet"` — list them with `netsh interface show interface`).

**1. Check Forwarding**

The `Forwarding` line must read `enabled` on the interface you want to sniff.
```cmd
CMD:
netsh interface ipv4 show interface "Wi-Fi"
netsh interface ipv4 show interface "Ethernet"
```

and
```powershell
PowerShell:
Get-NetIPInterface -InterfaceAlias "Wi-Fi" -AddressFamily IPv4 | Select-Object InterfaceAlias, Forwarding
Get-NetIPInterface -InterfaceAlias "Ethernet" -AddressFamily IPv4 | Select-Object InterfaceAlias, Forwarding
```

**2. Enable Forwarding if disabled**
```cmd
CMD:
netsh interface ipv4 set interface "Wi-Fi" forwarding=enabled
netsh interface ipv4 set interface "Ethernet" forwarding=enabled
```
and
```powershell
PowerShell:
Set-NetIPInterface -InterfaceAlias "Wi-Fi" -AddressFamily IPv4 -Forwarding Enabled
Set-NetIPInterface -InterfaceAlias "Ethernet" -AddressFamily IPv4 -Forwarding Enabled
```

Disable it when finished (`... forwarding=disabled` / `-Forwarding Disabled`).

> Notes:
> - `netsh interface ipv4 show global` does **not** display the forwarding state — always check per-interface as above.
> - Spoofed MAC + Windows forwarding guarantees an outage (the NIC drops frames sent to an unknown MAC), so the tool refuses to `Start()` while a spoofed MAC is set.
> - VLAN hopping (DTP/double tagging) practically only works over **wired Ethernet** — Wi-Fi client mode has VLAN tags stripped by the AP.


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

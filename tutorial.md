# Red Packet Sniffer Tutorial

This tutorial walks you through every feature of Red Packet Sniffer — from installation to advanced attack modules. Each section is self-contained; jump to whatever you need.

---

## Table of Contents

- [Section 1: Installation](#section-1-installation)
- [Section 2: Understanding the Architecture](#section-2-understanding-the-architecture)
- [Section 3: First Capture](#section-3-first-capture)
- [Section 4: CLI Mode — Commands Reference](#section-4-cli-mode--commands-reference)
- [Section 5: Capture Filters](#section-5-capture-filters)
- [Section 6: Credential Extraction](#section-6-credential-extraction)
- [Section 7: Protocol Weakness Detection](#section-7-protocol-weakness-detection)
- [Section 8: DNS Analysis](#section-8-dns-analysis)
- [Section 9: TCP Connection Tracking & Stream Reassembly](#section-9-tcp-connection-tracking--stream-reassembly)
- [Section 10: HTTP Request Logging](#section-10-http-request-logging)
- [Section 11: Network Host Discovery](#section-11-network-host-discovery)
- [Section 12: Layer 2/3 Protocol Analysis](#section-12-layer-23-protocol-analysis)
- [Section 13: VoIP Analysis](#section-13-voip-analysis)
- [Section 14: ARP Spoofing (MITM)](#section-14-arp-spoofing-mitm)
- [Section 15: VLAN Hopping](#section-15-vlan-hopping)
- [Section 16: Full Attack Chain — VLAN Hopping + ARP Spoofing](#section-16-full-attack-chain--vlan-hopping--arp-spoofing)
- [Section 17: Export & Reporting](#section-17-export--reporting)
- [Section 18: Web Dashboard Mode](#section-18-web-dashboard-mode)
- [Section 19: PCAP Import (Offline Analysis)](#section-19-pcap-import-offline-analysis)
- [Section 20: Tips & Troubleshooting](#section-20-tips--troubleshooting)

---

## Section 1: Installation

### 1.1 Install WinpkFilter Driver

Red Packet Sniffer uses WinpkFilter — a kernel-mode NDIS filter driver — for packet capture. You must install it first.

1. Download WinpkFilter SDK from [ntkernel.com](https://www.ntkernel.com/windows-packet-filter/)
2. Run the installer with Administrator privileges
3. Verify the driver service is running:

```powershell
sc query ndisrd
```

Expected output should show `STATE: 4 RUNNING`.

4. Copy `ndisapi.dll` (x64) to the same directory as `RedPacketSniffer.exe`.

### 1.2 Install .NET 8.0 Runtime

Download from [dotnet.microsoft.com](https://dotnet.microsoft.com/download/dotnet/8.0).

### 1.3 Build from Source

```powershell
git clone https://github.com/AresDefenseProject/RedPacketSniffer.git
cd RedPacketSniffer

dotnet build RedPacketSniffer.sln -c Release

# Or publish as self-contained (no .NET runtime needed on target)
dotnet publish src/RedPacketSniffer/RedPacketSniffer.csproj -c Release -r win-x64 --self-contained
```

### 1.4 Verify Installation

```powershell
# Must run as Administrator
RedPacketSniffer.exe --cli --list
```

If you see a list of network adapters, everything is working.

---

## Section 2: Understanding the Architecture

Before diving in, understand how Red Packet Sniffer works internally — this will clarify why the commands are structured the way they are.

### 2.1 How Capture and Analysis Work Together

```
                          ┌─────────────────────┐
   Network Adapter ──────►│  Capture Engine      │
   (WinpkFilter NDIS)     │  (kernel-mode copy)  │
                          └─────────┬───────────┘
                                    │ Every packet
                                    ▼
                          ┌──────────────────────────┐
                          │  13 Analysis Modules      │  ← ALL run simultaneously
                          │                          │     on EVERY captured packet
                          │  • CredentialExtractor    │
                          │  • ProtocolWeaknessDetect │ ← TLS/SMB/Enterprise depth
                          │  • KerberosAnalyzer       │ ← AS-REQ/TGS/Roasting
                          │  • DnsAnalyzer            │
                          │  • TcpConnectionTracker   │
                          │  • TcpStreamReassembler   │ ← Ordered stream rebuild
                          │  • HttpRequestLogger      │
                          │  • NetworkHostTracker     │
                          │  • L2L3ProtocolAnalyzer   │
                          │  • VoipAnalyzer           │
                          │  • VlanHopper (passive)   │
                          └──────────┬───────────────┘
                                     │ Results stored in memory
                                     ▼
                          ┌──────────────────────────┐
                          │  View Results             │
                          │  CLI: creds, alerts,      │
                          │       dns, http, ...      │
                          │  Web: tabs in UI          │
                          │                          │
                          │  Evidence Export:          │
                          │   Per-host PCAP + JSON    │
                          └──────────────────────────┘
```

Key points:
- **Analysis is real-time, not post-capture.** All 13 modules run on every packet the moment it arrives. You don't need to stop capture first.
- **View commands show accumulated results.** `creds`, `weak`, `dns`, `http`, `hosts`, `tcp`, `l2l3`, `voip` — these show what the modules have found so far. They are not filters — they are result viewers.
- **Toggle display without stopping capture.** `live` (or `l`) toggles packet output on/off — capture and analysis keep running in background. `alerts` (or `a`) toggles credential/weakness alert display.
- **Capture filters** (`filter tcp port 80`) limit **which packets the engine captures**. They work at the capture level, before analysis.
- **Display filters** (web mode only) limit **which packets are shown on screen** without affecting capture or analysis.

### 2.2 Passive vs Active Modules

| Type | Modules | What They Do |
|------|---------|-------------|
| **Passive** (read-only) | CredentialExtractor, ProtocolWeaknessDetector, KerberosAnalyzer, DnsAnalyzer, TcpConnectionTracker, TcpStreamReassembler, HttpRequestLogger, NetworkHostTracker, L2L3ProtocolAnalyzer, VoipAnalyzer | Analyze captured packets without sending anything to the network |
| **Active** (inject packets) | ArpSpoofer, VlanHopper | Send crafted packets into the network — require explicit start |
| **Coordinator** | CredentialCaptureCoordinator | Routes extracted credentials from all passive modules into a unified store |

Passive modules run automatically whenever capture is running. The `CredentialCaptureCoordinator` aggregates credential findings from CredentialExtractor, KerberosAnalyzer, and ProtocolWeaknessDetector into a single view. Active modules (ARP Spoofing, VLAN Hopping) must be configured and started manually — they modify network behavior.

### 2.3 Capture Modes: LISTEN

Red Packet Sniffer uses **LISTEN mode** — it copies packets for inspection without intercepting or modifying the original traffic flow. Normal network communication is unaffected by passive capture. Only ARP Spoofing and VLAN Hopping actively inject packets.

---

## Section 3: First Capture

### 3.1 Launch CLI Mode

```powershell
# Run as Administrator (required for kernel driver)
RedPacketSniffer.exe --cli
```

You will see the Red Packet Sniffer banner and the interactive prompt.

### 3.2 List Adapters

The tool automatically opens the WinpkFilter driver and lists available adapters:

```
[0] Ethernet - Intel(R) I211 Gigabit Network Connection
    MAC: AA:BB:CC:DD:EE:FF
[1] Wi-Fi - Intel(R) Wi-Fi 6 AX200
    MAC: 11:22:33:44:55:66
[2] vEthernet (WSL) - Hyper-V Virtual Ethernet Adapter
    MAC: 00:15:5D:xx:xx:xx
```

### 3.3 Select Adapter & Start Capture

```
> select 0
  Selected adapter [0]
> start
  Capture started (press 'p' to pause display, 's' to stop)
```

From this moment, all 13 analysis modules are running. Packets stream in real-time:

```
     1 14:30:01.234  IN 192.168.1.100:54321  -> 8.8.8.8:53             DNS       72B Query google.com
     2 14:30:01.240  IN 8.8.8.8:53           -> 192.168.1.100:54321    DNS      104B Response
     3 14:30:01.245 OUT 192.168.1.100:49152  -> 142.250.80.46:443     TCP       66B SYN
```

### 3.4 Toggle Display (While Capture Is Running)

Packet output chạy liên tục có thể khó đọc. Dùng `live` để tắt/bật hiển thị packet — capture và analysis vẫn chạy nền:

```
> live
  Live packet display: OFF       ← packet ngừng in ra, capture vẫn chạy

> creds                          ← gõ lệnh phân tích thoải mái
> weak
> dns

> live
  Live packet display: ON        ← bật lại xem packet
```

Tương tự `alerts` (hoặc `a`) tắt/bật alert credential/weakness real-time.

### 3.5 View Analysis Results (While Capture Is Running)

You don't need to stop capture to view results. At any time:

```
> creds          # Credentials extracted so far
> weak           # Security weaknesses detected so far
> dns            # DNS queries/responses seen so far
> http           # HTTP requests logged so far
> hosts          # Network hosts discovered so far
> tcp            # TCP connections tracked so far
> l2l3           # Layer 2/3 protocol findings so far
> voip           # VoIP/SIP findings so far
> stats          # Capture stats (packets, bytes, PPS)
```

Each command shows the **accumulated results** from all packets analyzed up to that point. Run it again later to see updated results as more traffic is captured.

### 3.6 Stop Capture

```
> stop
[*] Capture stopped. Total: 1523, Filtered: 1523, Creds: 0, Weaknesses: 12
```

After stopping, all results remain in memory. You can still view them with the same commands, and export to PCAP or HTML report.

### 3.7 Quick Start (One Command)

```powershell
# Auto-select adapter 0 and start capture immediately
RedPacketSniffer.exe --cli --adapter 0

# With time limit (seconds)
RedPacketSniffer.exe --cli --adapter 0 --duration 120

# With auto PCAP export
RedPacketSniffer.exe --cli --adapter 0 --pcap capture.pcap --duration 60
```

---

## Section 4: CLI Mode — Commands Reference

Once in interactive mode, these commands are available:

### Capture Control

| Command | Description |
|---------|-------------|
| `start [filters]` | Start packet capture (all analysis modules activate) |
| `stop` | Stop capture (results stay in memory) |
| `stats` | Show capture statistics (packets, bytes, duration, pps) |
| `clear` | Clear screen |
| `live` (or `l`) | Toggle real-time packet display on/off — capture vẫn chạy, chỉ tắt output |
| `alerts` (or `a`) | Toggle credential/weakness alert display on/off |

### Analysis Result Viewers

These commands view the results that analysis modules have produced from captured traffic. They work during or after capture.

| Command | Module | What It Shows |
|---------|--------|---------------|
| `creds` | CredentialExtractor | Credentials found in plaintext traffic |
| `weak` | ProtocolWeaknessDetector | Insecure protocols and misconfigurations |
| `dns [N]` | DnsAnalyzer | DNS query/response records and top domains (default: last 30) |
| `tcp` | TcpConnectionTracker | TCP connection states and statistics |
| `http [N]` | HttpRequestLogger | HTTP request/response log (default: last 30) |
| `hosts` | NetworkHostTracker | Discovered network hosts with OS/MAC/ports |
| `l2l3` (or `protocols`) | L2L3ProtocolAnalyzer | Layer 2/3 findings (CDP, STP, OSPF, DTP...) |
| `voip` (or `sip`) | VoipAnalyzer | SIP calls, RTP streams, STUN bindings |

### Capture Filter Commands

| Command | Description |
|---------|-------------|
| `filter <expr>` | Limit capture to matching packets (see [Section 5](#section-5-capture-filters)) |
| `filter clear` | Remove filter, capture everything |
| `filter show` | Display active filter |

### Export Commands

| Command | Description |
|---------|-------------|
| `export pcap <filename>` | Export captured packets to PCAP file |
| `export evidence <directory>` | Export evidence package (per-host PCAPs + JSON index) |
| `export report <filename>` | Export HTML report |

### Active Attack Commands

| Command | Description |
|---------|-------------|
| `arpspoof ...` | ARP spoofing — see [Section 14](#section-14-arp-spoofing-mitm) |
| `vlanhop ...` | VLAN hopping — see [Section 15](#section-15-vlan-hopping) |

### General

| Command | Description |
|---------|-------------|
| `help` | Show all available commands |
| `quit` / `exit` | Exit program |

---

## Section 5: Capture Filters

Capture filters limit **which packets the engine captures**. Unlike display filters (web-only), capture filters prevent packets from reaching the analysis modules entirely — unmatched packets are ignored.

### 5.1 When to Use

- Use capture filters to reduce noise on busy networks
- Use them to focus analysis on specific hosts or protocols
- Don't use them if you want full visibility (e.g., during host discovery)

### 5.2 Filter Syntax

```
filter <protocol> [host <ip>] [port <port>] [net <subnet>]
```

### 5.3 Examples

```bash
# Capture only TCP traffic
filter tcp

# Capture only traffic to/from a specific host
filter host 192.168.1.1

# Capture HTTP and HTTPS
filter tcp port 80,443

# Capture DNS only
filter udp port 53

# Capture a subnet
filter net 10.0.0.0/24

# Combine
filter tcp port 80,443 host 192.168.1.100

# Remove filter (capture everything)
filter clear
```

### 5.4 Web Dashboard — Display Filter

In web mode, the display filter bar filters **which captured packets are shown on screen** — it does not affect capture or analysis. All packets are still captured and analyzed; the filter only hides rows from the packet table.

```
# Free text search
http

# Structured
ip.src==192.168.1.100
ip.dst==10.0.0.1
proto==TCP
port==443

# Combine with AND/OR
ip.src==192.168.1.100 && proto==TCP
proto==UDP || proto==ICMP
```

---

## Section 6: Credential Extraction

The `CredentialExtractor` module runs automatically during capture. It inspects every packet payload and extracts credentials transmitted in plaintext.

### 6.1 Supported Protocols

| Protocol | What Gets Extracted |
|----------|-------------------|
| HTTP Basic Auth | Username + password (Base64 decoded) |
| HTTP Digest Auth | Username + realm + nonce |
| HTTP Form POST | Username/password fields from login forms |
| FTP | USER + PASS commands |
| SMTP | AUTH PLAIN/LOGIN credentials |
| POP3 | USER + PASS commands |
| IMAP | LOGIN credentials |
| Telnet | Username + password sequences |
| SIP | Digest authentication credentials |
| **Kerberos** | AS-REQ (username + realm), TGS-REQ (SPN targeting), AS-REP Roasting (encrypted part for offline crack) |
| **NTLM (multi-protocol)** | NTLMv1/v2 hash extraction from SMB, HTTP, LDAP, MSSQL, WinRM — full `user::domain::challenge::response` format |
| **SNMP** | Community string capture (v1/v2c) |
| **LDAP** | Simple Bind cleartext password |

### 6.2 Kerberos Credential Capture

The `KerberosAnalyzer` module (integrated via `CredentialCaptureCoordinator`) passively captures Kerberos authentication traffic:

- **AS-REQ** — Extracts username and realm from initial authentication requests. Reveals which accounts are actively authenticating.
- **TGS-REQ** — Captures the Service Principal Name (SPN) being requested. Identifies Kerberoastable services.
- **AS-REP Roasting** — Detects accounts with `DONT_REQUIRE_PREAUTH` flag. Extracts the encrypted timestamp for offline password cracking with Hashcat (`mode 18200`).

### 6.3 NTLM Hash Extraction

The `ProtocolWeaknessDetector` extracts NTLM challenge-response hashes across multiple protocols, not just SMB:

```
Protocols monitored for NTLM: SMB, HTTP, LDAP, MSSQL, WinRM
Output format: user::domain::challenge::NTLMv2_response
```

Extracted hashes can be relayed (ntlmrelayx) or cracked offline (Hashcat mode 5600 for NTLMv2, 5500 for NTLMv1). The detector also flags NTLMv1 downgrade — a critical finding because NTLMv1 is trivially crackable.

### 6.4 View Extracted Credentials

**CLI** (during or after capture):
```
> creds
```

Output:
```
[!] Credentials Found: 6
 #1 [HTTP]      admin:Password123 @ 192.168.1.50 (Basic Auth)
 #2 [FTP]       backup:Qwerty!99 @ 10.0.0.5:21
 #3 [TELNET]    root:toor @ 172.16.0.1:23
 #4 [KERBEROS]  jdoe@CORP.LOCAL (AS-REQ) @ 10.0.0.10
 #5 [NTLM]      admin::CORP::aabb...:ccdd... @ 10.0.0.20 (SMB NTLMv2)
 #6 [SNMP]      community=public @ 10.0.0.30 (SNMPv2c)
```

**Web:** Navigate to the **Security** tab → Credentials section. New credentials appear in real-time as they're found.

### 6.5 How It Works

Multiple modules contribute credentials through the `CredentialCaptureCoordinator`:

1. **CredentialExtractor** — Pattern-matches cleartext protocols (HTTP, FTP, SMTP, POP3, IMAP, Telnet, SIP)
2. **KerberosAnalyzer** — Parses Kerberos AS-REQ/TGS-REQ/AS-REP on UDP/TCP port 88
3. **ProtocolWeaknessDetector** — Extracts NTLM hashes, SNMP community strings, LDAP simple bind passwords

All findings merge into a single credential store, deduplicated, accessible via `creds` command or Web Security tab.

---

## Section 7: Protocol Weakness Detection

The `ProtocolWeaknessDetector` runs automatically during capture. It performs deep protocol analysis across TLS, SMB, enterprise infrastructure protocols, and network-layer attacks — going far beyond simple pattern matching.

### 7.1 Detection Categories

| Category | Detections |
|----------|------------|
| **Name Resolution Poisoning** | LLMNR, NBT-NS, mDNS — broadcasts vulnerable to responder-style attacks |
| **TLS/SSL Analysis** | JA3/JA3S fingerprinting, weak cipher suites, TLS 1.0/1.1, self-signed certs, weak RSA keys (<2048 bit), MITM certificate detection, SNI extraction, known C2 JA3 hash matching |
| **SMB Deep Analysis** | SMB signing not required, SMBv1 detection, Named Pipe lateral movement (drsuapi, svcctl, spoolss, samr, winreg, atsvc, srvsvc), NTLM relay chain detection, NTLMv1 downgrade |
| **Kerberos** | AS-REQ credential capture, AS-REP Roasting detection, TGS-REQ SPN extraction (via KerberosAnalyzer) |
| **NTLM Multi-Protocol** | NTLMv1/v2 hash extraction from SMB, HTTP, LDAP, MSSQL, WinRM in crackable format |
| **Enterprise Remote Access** | RDP without NLA, WinRM/PSRemoting cleartext (HTTP on 5985), WinRM over HTTPS activity |
| **AAA Protocols** | RADIUS cleartext detection, TACACS+ unencrypted, SNMP community string capture (v1/v2c) |
| **802.1X/EAP** | EAP-MD5 challenge detection (hash crackable offline), weak EAP method identification |
| **Modern Protocols** | QUIC/HTTP3 detection (evades traditional inspection), DNS-over-HTTPS (DoH), DNS-over-TLS (DoT) |
| **Cleartext Credentials** | HTTP Basic Auth, LDAP Simple Bind, SMTP AUTH, FTP plaintext |
| **Network Layer Attacks** | DNS spoofing (conflicting answers), ICMP Redirect, NDP Override (IPv6), IP fragment overlapping, stealth scan detection (XMAS/NULL/FIN), Slowloris DoS |
| **L2 Attacks** | Gratuitous ARP, VLAN double-tagging detection (QinQ), DTP enabled, unauthenticated OSPF/HSRP |
| **Broadcast/Discovery** | SSDP/UPnP, WS-Discovery, DHCPv6 spoofing opportunity, CDP/LLDP information disclosure |

### 7.2 TLS Metadata Analysis (Deep)

The detector performs full TLS ClientHello/ServerHello parsing for passive intelligence gathering:

**JA3/JA3S Fingerprinting**
- Computes JA3 hash from ClientHello (TLS version, cipher suites, extensions, elliptic curves, point formats)
- Computes JA3S hash from ServerHello (TLS version, selected cipher, extensions)
- Cross-references JA3 against a built-in database of known C2 frameworks (Cobalt Strike, Metasploit, Empire, Covenant, Sliver, Brute Ratel, Havoc, Mythic)
- **CRITICAL** alert when a known malicious JA3 hash is detected

**Weak Cipher Detection**
- Flags negotiated cipher suites using: RC4, DES, 3DES, NULL encryption, EXPORT grade, MD5-based MACs, anonymous key exchange
- Reports the exact cipher suite name and both endpoints

**Certificate Analysis**
- Detects self-signed certificates (issuer == subject)
- Flags RSA keys below 2048 bits
- **MITM Certificate Detection**: identifies certificates where the issuer CN contains known interception proxy names (mitmproxy, Burp Suite, ZAP, Charles, Fiddler)

**SNI Extraction**
- Extracts Server Name Indication from ClientHello for passive domain reconnaissance

### 7.3 SMB Deep Analysis

**Named Pipe Lateral Movement Detection**

Monitors SMB2 Tree Connect and Create requests for high-value named pipes that indicate active lateral movement:

| Named Pipe | Significance |
|------------|-------------|
| `drsuapi` | DCSync attack — domain replication, credential dumping |
| `svcctl` | Remote service creation — common in psexec-style attacks |
| `spoolss` | PrintNightmare / Print Spooler exploitation |
| `samr` | SAM database enumeration — user/group reconnaissance |
| `winreg` | Remote registry access |
| `atsvc` | AT Scheduler — legacy remote task execution |
| `srvsvc` | Server Service — share enumeration |

Each detection includes the pipe name, source/destination, and severity based on the pipe's attack significance (Critical for drsuapi/svcctl, High for others).

**NTLM Relay Chain Detection**

Tracks NTLM authentication patterns across SMB sessions to identify relay attacks:
- Detects when the same NTLM challenge appears across multiple sessions (challenge reuse)
- Flags when a host authenticates to a target immediately after receiving an inbound authentication (relay timing pattern)
- Reports severity based on the authentication direction and NTLMv1/v2 version

**SMB Signing & Version**
- Detects SMB2 Negotiate responses with signing not required — enables relay attacks
- Flags any SMBv1 traffic — EternalBlue and other critical vulnerabilities

### 7.4 Enterprise Protocol Detection

**RDP (Remote Desktop Protocol)**
- Detects RDP connections without Network Level Authentication (NLA) — allows unauthenticated access to the login screen
- Parses RDP negotiation to identify security mode (Standard RDP Security vs NLA/CredSSP)

**WinRM / PowerShell Remoting**
- **CRITICAL**: WinRM over HTTP (port 5985) — credentials and commands sent in cleartext
- Monitors WinRM over HTTPS (port 5986) for activity tracking

**RADIUS / TACACS+**
- Detects RADIUS traffic and flags cleartext RADIUS (without RadSec/TLS)
- Flags TACACS+ unencrypted sessions — TCP port 49 without encryption flag
- TACACS+ is particularly dangerous when unencrypted because it carries full command authorization logs

**SNMP Community String Capture**
- Captures SNMPv1/v2c community strings from GET/SET/TRAP packets
- Reports as credential-level finding because community strings are effectively passwords for network device management

**802.1X / EAP**
- Detects EAP-MD5 challenge-response — hash can be cracked offline
- Identifies weak EAP methods that don't provide mutual authentication

**QUIC / HTTP3 / Encrypted DNS**
- Detects QUIC traffic (UDP, initial packets with version field) — evades traditional network monitoring
- Flags DNS-over-HTTPS (DoH) connections to known resolver IPs (Cloudflare, Google, Quad9)
- Detects DNS-over-TLS (DoT) on port 853

### 7.5 Network Layer Attack Detection

**DNS Spoofing Detection**
- Tracks DNS transaction IDs and responses
- Alerts when the same query receives conflicting answers from different sources — strong indicator of DNS poisoning

**ICMP Redirect**
- Detects ICMP Type 5 (Redirect) messages — can be used to reroute traffic through an attacker

**NDP Override (IPv6)**
- Detects Neighbor Advertisement with Override flag — IPv6 equivalent of ARP spoofing

**Stealth Scan Detection**
- Tracks anomalous TCP flags per source IP: XMAS (FIN+PSH+URG), NULL (no flags), bare FIN
- Alerts when threshold exceeded within time window — indicates active reconnaissance

**IP Fragment Evasion**
- Detects overlapping IP fragments — classic IDS evasion technique
- Flags tiny fragments (< 64 bytes) that may be used to split headers across fragments

### 7.6 Evidence Packaging

High-severity findings (CRITICAL and HIGH) automatically attach the raw Ethernet frame that triggered the detection. This evidence can be exported as PCAP files — see [Section 17](#section-17-export--reporting).

Findings with evidence attached:
- SMB Signing Not Required, SMBv1 Traffic, Named Pipe Lateral Movement, SMB NTLM Relay
- NTLM Hash Extraction (all protocols), SNMP Community String
- LDAP Cleartext Password, HTTP Basic Auth, SMTP Cleartext
- TLS MITM Certificate, Weak TLS Cipher, Known Malicious JA3
- RDP Without NLA, WinRM Cleartext
- TACACS+ Cleartext, EAP-MD5 Challenge

### 7.7 View Detected Weaknesses

**CLI** (during or after capture):
```
> weak
```

Output:
```
Security Weaknesses Detected: 24
 [CRITICAL] SMB Signing Not Required — 10.0.0.5 (relay possible)
 [CRITICAL] Known Malicious JA3 — 192.168.1.50 → 45.33.32.156 (Cobalt Strike)
 [CRITICAL] LDAP Cleartext Password — 10.0.0.10 → 10.0.0.2:389
 [CRITICAL] Named Pipe: drsuapi — 10.0.0.20 → 10.0.0.2 (DCSync)
 [HIGH]     NTLM Hash: admin::CORP — 10.0.0.30 (NTLMv2 via SMB)
 [HIGH]     RDP Without NLA — 10.0.0.40:3389
 [HIGH]     WinRM Cleartext — 10.0.0.50:5985
 [HIGH]     EAP-MD5 Challenge — 192.168.1.100
 [MEDIUM]   LLMNR Broadcast — 192.168.1.100
 [LOW]      SSDP/UPnP Broadcast — 239.255.255.250
```

**Web:** Navigate to the **Security** tab → Weaknesses section.

### 7.8 Severity Levels

- **CRITICAL** — Immediate exploitation risk: credentials in cleartext, SMB signing disabled (relay), known C2 fingerprint, DCSync pipe access, MITM certificate
- **HIGH** — Significant security gap: NTLM hash extraction, RDP without NLA, WinRM cleartext, weak EAP, NTLMv1 downgrade, TACACS+ cleartext
- **MEDIUM** — Notable finding: broadcast protocols (LLMNR, NBT-NS, mDNS), DHCPv6, stealth scans, QUIC/DoH (inspection bypass)
- **LOW** — Informational: UPnP, SSDP, service discovery, CDP/LLDP, general protocol visibility

---

## Section 8: DNS Analysis

The `DnsAnalyzer` runs automatically during capture.

### 8.1 What Gets Analyzed

- All DNS queries and responses (A, AAAA, CNAME, MX, TXT, SRV, PTR, SOA, NS)
- Query frequency per domain
- DNS tunneling indicators (unusually long subdomain labels, high entropy, TXT record abuse)
- DGA (Domain Generation Algorithm) pattern detection
- Response anomalies (NXDOMAIN floods, TTL inconsistencies)

### 8.2 View DNS Data

**CLI:**
```
> dns
```

Output:
```
DNS Records: 245
Top Domains:
  google.com          — 42 queries
  microsoft.com       — 28 queries
  cloudflare.com      — 15 queries
  suspicious-domain.xyz — 3 queries  [!] Low reputation
```

**Web:** Navigate to the **DNS** tab for full query/response table.

---

## Section 9: TCP Connection Tracking & Stream Reassembly

Two modules handle TCP analysis: `TcpConnectionTracker` for connection-level metadata, and `TcpStreamReassembler` for ordered payload reconstruction.

### 9.1 Connection Tracking

The `TcpConnectionTracker` runs automatically during capture:

- Full TCP state machine tracking (SYN → ESTABLISHED → FIN)
- Connection duration, bytes transferred, packet count
- Half-open connection detection (SYN flood indicator)
- RST injection detection
- Retransmission tracking

### 9.2 Stream Reassembly

The `TcpStreamReassembler` reconstructs ordered TCP streams from captured packets, enabling accurate protocol analysis even when packets arrive out of order:

**Capabilities:**
- Sequence-number-ordered buffering — reassembles payload in correct order regardless of packet arrival sequence
- TCP Fast Open (TFO) support — handles data in SYN packets without dropping early payload
- RST injection awareness — detects injected RST packets (spoofed resets) based on sequence number validation
- Per-stream byte limit — prevents memory exhaustion from long-lived connections (configurable, default 256 KB per stream)
- Automatic stream expiration — idle streams are cleaned up after timeout

**Why This Matters:**

Without stream reassembly, protocol parsers that look at individual packets miss credentials and attacks that span multiple TCP segments. For example, an HTTP POST body split across 3 packets, or an NTLM AUTHENTICATE message fragmented by the TCP stack. The reassembler feeds complete protocol data units to the credential extractor and weakness detector.

### 9.3 View Connections

**CLI:**
```
> tcp
```

**Web:** Navigate to the **TCP** tab.

---

## Section 10: HTTP Request Logging

The `HttpRequestLogger` runs automatically during capture.

### 10.1 What Gets Logged

- Method, URL, Host, User-Agent, Referer
- Response status code
- Cookies (sent and received)
- Form POST data (login forms, file uploads)
- Content-Type and Content-Length

### 10.2 View HTTP Log

**CLI:**
```
> http
```

**Web:** Navigate to the **HTTP** tab — sortable table with all request details.

---

## Section 11: Network Host Discovery

The `NetworkHostTracker` runs automatically during capture.

### 11.1 What Gets Discovered

For every host seen in captured traffic:
- IP address and MAC address
- First seen / last seen timestamps
- OS fingerprint (based on TTL, TCP window size, TCP options)
- Hostname (from DNS reverse lookup, NetBIOS, mDNS)
- Open ports detected from traffic
- Traffic volume (bytes sent/received)
- Vendor identification from MAC OUI

### 11.2 View Discovered Hosts

**CLI:**
```
> hosts
```

**Web:** Navigate to the **Hosts** tab — interactive host table with subnet grouping.

---

## Section 12: Layer 2/3 Protocol Analysis

The `L2L3ProtocolAnalyzer` runs automatically during capture. This module provides critical intelligence for planning VLAN Hopping and ARP Spoofing attacks.

### 12.1 Protocols Analyzed

| Protocol | Information Extracted |
|----------|---------------------|
| **ARP** | ARP table, gratuitous ARP detection, ARP spoofing detection |
| **VLAN (802.1Q)** | VLAN IDs in traffic, trunk port detection, QinQ double-tagging detection |
| **STP** | Bridge ID, root bridge, port roles, topology changes |
| **CDP/LLDP** | Switch model, native VLAN, port description, management IP |
| **DTP** | Trunk negotiation status, DTP mode |
| **OSPF** | Router ID, area ID, neighbor relationships, authentication type |
| **HSRP/VRRP/GLBP** | Group number, priority, virtual IP, authentication, role conflict detection |
| **MPLS** | Label stack, TTL, traffic class |
| **NDP (IPv6)** | Neighbor Advertisement Override detection — IPv6 ARP spoofing equivalent |
| **ICMP** | ICMP Redirect detection — traffic rerouting attack |
| **DHCPv6** | Rogue DHCPv6 server detection — DNS/gateway takeover via IPv6 |

### 12.2 View L2/3 Findings

**CLI:**
```
> l2l3
```

**Web:** Navigate to the **L2/L3** tab — categorized findings with severity.

### 12.3 Why This Matters for Attack Planning

Layer 2/3 findings feed directly into the attack modules:
- **CDP/LLDP** → reveals native VLAN of the switch port (used by VLAN Hopping auto-detect)
- **DTP** → shows whether trunk negotiation is possible (used by VLAN Hopper to decide DTP Spoofing vs Double Tagging)
- **OSPF without auth** → route injection possibility
- **HSRP without auth** → virtual gateway takeover possibility
- **STP** → topology manipulation possibility

Run capture for a few minutes to collect these broadcast/multicast protocol frames before attempting VLAN Hopping.

---

## Section 13: VoIP Analysis

The `VoipAnalyzer` runs automatically during capture.

### 13.1 What Gets Analyzed

- **SIP** — REGISTER, INVITE, BYE, CANCEL messages; call flow reconstruction
- **SIP Auth** — Digest authentication credential extraction
- **RTP** — Media stream detection (codec, SSRC, packet count, jitter)
- **STUN** — Binding requests/responses (NAT traversal endpoints)

### 13.2 View VoIP Data

**CLI:**
```
> voip
```

**Web:** Navigate to the **VoIP** tab.

---

## Section 14: ARP Spoofing (MITM)

ARP Spoofing is an **active attack module** — it injects forged ARP replies into the network to redirect traffic through the attacker's machine.

> ⚠️ **Authorized use only.** ARP spoofing disrupts network communication. Always have written authorization.

### 14.1 Prerequisites

- Capture must be **started** on the correct adapter (ARP Spoofing uses the same adapter)
- Attacker must be on the **same VLAN/subnet** as the targets
- If targets are in a different VLAN, use **VLAN Hopping first** (see [Section 15](#section-15-vlan-hopping) and [Section 16](#section-16-full-attack-chain--vlan-hopping--arp-spoofing))

### 14.2 How It Works

```
Normal:      Victim ←→ Gateway
After spoof: Victim ←→ Attacker ←→ Gateway
```

When spoofing starts, Red Packet Sniffer automatically:
1. Enables Windows IP forwarding via `netsh` — so victim traffic flows through
2. Sends periodic forged ARP replies to both victim and gateway
3. All redirected traffic is analyzed by the passive modules (credential extraction, HTTP logging, etc.)

When spoofing stops:
1. Original ARP entries are restored
2. IP forwarding is disabled

### 14.3 CLI Workflow

```bash
# 1. Start capture first (required)
> start

# 2. Auto-detect gateway (recommended)
> arpspoof detect
# Output: Gateway: 192.168.1.1 (AA:BB:CC:DD:EE:FF)

# 3. Configure with detected values
> arpspoof configure 192.168.1.1 AA:BB:CC:DD:EE:FF

# 4. Scan for live hosts on the subnet
> arpspoof scan

# 5. Add targets from scan results
> arpspoof add 192.168.1.100 11:22:33:44:55:66
> arpspoof add 192.168.1.101 77:88:99:AA:BB:CC

# 6. Start ARP poisoning
> arpspoof start

# 7. Check status
> arpspoof status

# 8. View captured credentials from redirected traffic
> creds
> http

# 9. Stop and restore ARP tables
> arpspoof stop
```

### 14.4 Web Dashboard

1. Click the **ARP Spoof** tab
2. Click **Auto Detect** to find the gateway
3. Gateway IP and MAC are auto-populated → click **Configure**
4. Use **Scan Subnet** to discover hosts
5. Click a discovered host to add as target
6. Click **Start ARP Spoofing**
7. Monitor poisoned packet count in real-time
8. Check **Security** tab for credentials found in redirected traffic
9. Click **Stop** to restore ARP tables

### 14.5 Command Reference

| Command | Description |
|---------|-------------|
| `arpspoof detect` | Auto-detect gateway IP and MAC |
| `arpspoof configure <gw_ip> <gw_mac> [interval_ms]` | Set gateway for poisoning |
| `arpspoof add <ip> <mac>` | Add a target (victim) |
| `arpspoof remove <ip>` | Remove a target |
| `arpspoof scan` | Scan subnet for live hosts |
| `arpspoof start` | Start ARP poisoning + enable IP forwarding |
| `arpspoof stop` | Stop poisoning + restore ARP + disable forwarding |
| `arpspoof status` | Show current spoofing state |

---

## Section 15: VLAN Hopping

VLAN Hopping is an **active attack module** that bypasses VLAN segmentation to reach hosts in other VLANs. Use this when targets are in a different VLAN from the attacker.

> ⚠️ **Authorized use only.** VLAN hopping attacks switch infrastructure. Always have written authorization.

### 15.1 When Do You Need VLAN Hopping?

ARP Spoofing only works within the same VLAN/subnet. If your target is in VLAN 20 but you're in VLAN 1, you need VLAN Hopping first to bridge the gap:

```
Without VLAN Hopping:
  Attacker (VLAN 1) ──╳──  Target (VLAN 20)    ← ARP packets don't cross VLANs

With VLAN Hopping:
  Attacker (VLAN 1) ──────  Target (VLAN 20)    ← VLAN barrier bypassed
```

### 15.2 Attack Methods

**Method 1: DTP Spoofing (preferred — bidirectional)**

If the switch port has DTP enabled (default on many Cisco switches), Red Packet Sniffer sends DTP Desirable frames to negotiate a trunk link. Once trunked, the attacker receives traffic from **all VLANs**.

```
Attacker → Switch: DTP Desirable (I want to be a trunk)
Switch → Attacker: DTP (Trunk established)
Result: Attacker port becomes trunk → sees all VLANs
```

**Method 2: Double Tagging (fallback — one-way only)**

If DTP fails (port hardcoded as access, non-Cisco switch), falls back to double tagging: an outer 802.1Q tag with the native VLAN, and an inner tag with the target VLAN. The first switch strips the outer tag; the second switch forwards based on the inner tag.

```
Attacker → [Outer: VLAN 1][Inner: VLAN 20][Payload] → Switch 1
Switch 1 strips outer tag → [Inner: VLAN 20][Payload] → Switch 2
Switch 2 forwards to VLAN 20
```

> ⚠️ Double tagging is **one-way only** — responses from VLAN 20 do not come back to the attacker. Use it for probing (ARP requests, ping, port scans). For bidirectional MITM, you need DTP Spoofing.

### 15.3 Automatic Workflow

Red Packet Sniffer runs a two-phase workflow automatically:

```
Phase 1: DTP Probe (configurable timeout, default 30s)
  ├── Send DTP Desirable frames to switch
  ├── Listen for DTP responses
  ├── If switch responds → DTP Spoofing active (trunk negotiated) ✓
  └── If timeout → fallback to Phase 2

Phase 2: Double Tagging (fallback)
  ├── Construct 802.1Q-in-802.1Q frames
  └── Ready to send double-tagged packets to target VLAN
```

You don't need to choose the method — the tool decides based on whether the switch responds to DTP.

### 15.4 CLI Workflow

```bash
# 1. Start capture first (required — VLAN Hopper uses the same adapter)
> start

# 2. (Optional) Let L2L3 analyzer collect CDP/DTP data for a minute
#    Then check what it found:
> l2l3

# 3. Configure target VLAN
> vlanhop configure 20
# With explicit native VLAN and DTP timeout:
> vlanhop configure 20 1 45
# (target_vlan=20, native_vlan=1, dtp_timeout=45s)

# 4. Start VLAN hopping — auto DTP probe, then fallback
> vlanhop start
# Output shows which method was selected

# 5. Check status
> vlanhop status
# Shows: State, Active Method, DTP detected, frames sent

# 6. Send double-tagged ARP probe to discover hosts in target VLAN
> vlanhop arpreq 10.20.0.1

# 7. Stop
> vlanhop stop
```

### 15.5 Web Dashboard

1. Start capture on the correct adapter first
2. Click the **VLAN Hop** tab
3. **Auto Detect**: Click **Scan Network** — reads CDP/LLDP data already captured by L2L3 analyzer to auto-detect native VLAN and DTP presence
4. Enter **Target VLAN** (required). Native VLAN auto-fills from detect, DTP Timeout defaults to 30s
5. Click **Configure**
6. Click **Start VLAN Hopping**
7. Watch the workflow diagram — it highlights the current phase:
   - Yellow border = DTP Probing
   - Green "DTP Spoofing" = trunk negotiated
   - Yellow "Double Tagging" = DTP failed, using fallback
8. Use **Double Tag ARP Probe** to probe hosts in the target VLAN
9. Monitor the log area for real-time events
10. Click **Stop** when done

### 15.6 Command Reference

| Command | Description |
|---------|-------------|
| `vlanhop configure <target_vlan> [native_vlan] [dtp_timeout]` | Set VLAN hopping parameters |
| `vlanhop start` | Start DTP probe → auto fallback to double tagging |
| `vlanhop stop` | Stop VLAN hopping |
| `vlanhop status` | Show current state, method, frames sent |
| `vlanhop arpreq <ip>` | Send double-tagged ARP request to target VLAN |

---

## Section 16: Full Attack Chain — VLAN Hopping + ARP Spoofing

This section shows the complete workflow for MITM across VLANs — the reason these two modules exist together.

### 16.1 Scenario

```
Attacker:  VLAN 1 (192.168.1.0/24)
Target:    VLAN 20 (10.20.0.0/24)
Goal:      Intercept traffic between Target and its gateway
```

### 16.2 Step-by-Step (CLI)

```bash
# ─── Step 1: Start capture and gather intelligence ───
> start
# Wait 30-60 seconds for L2L3 analyzer to collect CDP/DTP frames

> l2l3
# Look for: CDP native VLAN, DTP status, switch model

> hosts
# See hosts in your current VLAN

# ─── Step 2: VLAN Hopping — bridge into VLAN 20 ───
> vlanhop configure 20
> vlanhop start
# Wait for DTP probe result...
# If DTP succeeds: you now have trunk access to all VLANs
# If DTP fails: double tagging mode (one-way into VLAN 20)

> vlanhop status
# Confirm: State=Active, Method=DtpSpoofing (or DoubleTagging)

# ─── Step 3: ARP Spoofing in the target VLAN ───
# (Only works with DTP Spoofing — bidirectional trunk needed)
> arpspoof detect
# Detect VLAN 20's gateway

> arpspoof configure 10.20.0.1 <gateway_mac>
> arpspoof add 10.20.0.100 <target_mac>
> arpspoof start

# ─── Step 4: Harvest ───
> creds            # Credentials from VLAN 20 traffic
> http             # HTTP requests from VLAN 20
> dns              # DNS queries from VLAN 20 hosts

# ─── Step 5: Clean up (reverse order) ───
> arpspoof stop    # Restore ARP tables first
> vlanhop stop     # Then stop VLAN hopping
> stop             # Stop capture last
```

### 16.3 Order Matters

```
Start order:   Capture → VLAN Hopping → ARP Spoofing
Stop order:    ARP Spoofing → VLAN Hopping → Capture  (reverse)
```

- **Capture first** — both VLAN Hopper and ARP Spoofer use the capture engine's adapter to send packets
- **VLAN Hopping before ARP Spoofing** — you need trunk access before you can ARP-spoof across VLANs
- **Stop in reverse** — restore ARP tables while the trunk is still up, then close the trunk

### 16.4 Web Dashboard — Same Flow

1. Select adapter → **Start Capture**
2. **VLAN Hop** tab → Auto Detect → Configure → **Start**
3. Wait for "Active" status
4. **ARP Spoof** tab → Auto Detect → Configure → Add targets → **Start**
5. Check **Security** tab for credentials
6. **ARP Spoof** tab → **Stop**
7. **VLAN Hop** tab → **Stop**
8. **Stop Capture**

### 16.5 Double Tagging Limitation

If only double tagging is available (DTP failed), full MITM is not possible because responses don't return to the attacker. You can still:
- Send ARP probes to discover hosts in the target VLAN (`vlanhop arpreq`)
- Send crafted packets one-way into the target VLAN
- Use traffic mirroring on the switch (if you have switch access) to capture responses

---

## Section 17: Export & Reporting

### 17.1 PCAP Export

Export captured packets to a standard PCAP file (Wireshark compatible):

**CLI:**
```
> export pcap output.pcap
[*] Exported 1523 packets to output.pcap
```

**Web:** Click the **Export PCAP** button, or `GET http://localhost:5000/api/export/pcap`.

### 17.2 Evidence Package Export

The `ExportEvidencePackage` feature creates a structured evidence directory from high-severity findings. Each finding that has raw evidence attached (see [Section 7.6](#76-evidence-packaging)) is exported with the original Ethernet frame in PCAP format.

**Output Directory Structure:**
```
evidence_output/
├── 10.0.0.5_findings.pcap         ← Per-host PCAP: all findings for this target
├── 10.0.0.10_findings.pcap
├── 10.0.0.20_findings.pcap
├── combined_evidence.pcap         ← All evidence frames in one PCAP
└── evidence_index.json            ← JSON mapping: host → findings with metadata
```

**Per-Host PCAP Files**
- One `.pcap` file per unique target host IP
- Contains the raw Ethernet frames that triggered each finding for that host
- Standard PCAP format (magic `0xA1B2C3D4`, version 2.4, `LINKTYPE_ETHERNET`)
- Openable directly in Wireshark for validation

**Combined PCAP**
- `combined_evidence.pcap` — all evidence frames from all hosts in a single file
- Useful for bulk analysis or importing into SIEM

**JSON Evidence Index**
- `evidence_index.json` — structured mapping for automated processing:

```json
{
  "10.0.0.5": [
    {
      "Title": "SMB Signing Not Required",
      "Severity": "Critical",
      "Timestamp": "2024-01-15T14:30:22Z",
      "Description": "SMB2 Negotiate response with signing not required...",
      "HasEvidence": true,
      "EvidenceBytes": 1024
    }
  ],
  "10.0.0.20": [
    {
      "Title": "Named Pipe: drsuapi",
      "Severity": "Critical",
      ...
    }
  ]
}
```

**Evidence Size Limit:** Each finding's raw evidence is capped at 16 KB (`MaxEvidenceBytes`). This captures the full protocol headers and enough payload for analysis without storing entire file transfers.

### 17.3 HTML Report

Generate a formatted HTML report with statistics and findings:

**CLI:**
```
> export report report.html
[*] Report generated: report.html
```

**Web:** Click **Export Report**, or `GET http://localhost:5000/api/export/report`.

### 17.4 JSON Report

For pipeline integration:

```
GET http://localhost:5000/api/export/report.json
```

Returns structured JSON with all capture statistics, credentials, weaknesses, and analysis results.

### 17.5 Auto-Export

```powershell
# Capture 60 seconds, auto-export PCAP
RedPacketSniffer.exe --cli --adapter 0 --duration 60 --pcap auto_capture.pcap
```

---

## Section 18: Web Dashboard Mode

### 18.1 Starting Web Mode

```powershell
# Default port 5000
RedPacketSniffer.exe --web

# Custom port
RedPacketSniffer.exe --web --port 8080
```

Open `http://localhost:5000` in your browser.

### 18.2 Dashboard Layout

| Area | Description |
|------|-------------|
| **Header** | Connection status, adapter dropdown, capture controls (Start/Stop/Clear) |
| **Stats Bar** | Real-time: packets, bytes, PPS, credentials, weaknesses, DNS, TCP, HTTP, hosts |
| **Packet Table** | Live packet stream with protocol coloring and direction indicators |
| **Display Filter** | Real-time packet filter (does NOT affect capture or analysis) |
| **Analysis Tabs** | Security, DNS, TCP, HTTP, Hosts, L2/L3, VoIP, ARP Spoof, VLAN Hop |
| **Detail Panel** | Selected packet detail + hex dump |

### 18.3 Tab Overview

| Tab | Type | Description |
|-----|------|-------------|
| **Security** | Passive results | Credentials found + protocol weaknesses |
| **DNS** | Passive results | DNS records table + top domains |
| **TCP** | Passive results | Active and completed TCP connections |
| **HTTP** | Passive results | HTTP request/response log |
| **Hosts** | Passive results | Discovered network hosts with MAC/OS/ports |
| **L2/L3** | Passive results | Layer 2/3 findings (CDP, STP, OSPF, HSRP, DTP) |
| **VoIP** | Passive results | SIP calls, RTP streams, STUN bindings |
| **ARP Spoof** | Active attack | Point-and-click ARP poisoning controls |
| **VLAN Hop** | Active attack | VLAN hopping with auto-detect and workflow visualization |

### 18.4 SignalR API (For Custom Clients)

```javascript
const connection = new signalR.HubConnectionBuilder()
    .withUrl("http://localhost:5000/hub/packets")
    .build();

// Real-time events (server → client)
connection.on("PacketBatch", (packets) => { });
connection.on("CredentialFound", (creds) => { });
connection.on("WeaknessDetected", (weaknesses) => { });
connection.on("StatsUpdate", (stats) => { });
connection.on("StateChanged", (state) => { });
connection.on("ArpSpoofStateChanged", (status) => { });
connection.on("VlanHopStateChanged", (status) => { });

// Commands (client → server)
await connection.invoke("StartCapture", adapterIndex, filterObj);
await connection.invoke("StopCapture");
await connection.invoke("GetAdapters");
await connection.invoke("GetStats");
await connection.invoke("GetCredentials");
await connection.invoke("GetWeaknesses");

await connection.start();
```

### 18.5 REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/export/pcap` | GET | Download PCAP file |
| `/api/export/report` | GET | Download HTML report |
| `/api/export/report.json` | GET | JSON report data |

---

## Section 19: PCAP Import (Offline Analysis)

Analyze previously captured traffic without a live network:

```powershell
RedPacketSniffer.exe --cli --pcap existing_capture.pcap
```

All 13 analysis modules run on the imported packets — credentials, weaknesses, Kerberos, DNS, TCP reassembly, HTTP, hosts, L2/L3, VoIP — as if captured live. View results with the same commands (`creds`, `alerts`, `dns`, etc.).

---

## Section 20: Tips & Troubleshooting

### 20.1 Common Issues

**"WinpkFilter driver not found"**
- Run `sc query ndisrd` — if not found, install WinpkFilter
- Must run as Administrator

**"Access denied" on capture**
- Right-click → Run as Administrator
- WinpkFilter requires elevated privileges

**No packets captured**
- Check adapter index with `--list`
- Check Windows Firewall
- Verify the adapter has active traffic

**Web dashboard not loading**
- Check port: `netstat -an | findstr 5000`
- Try different port: `--web --port 8080`

**ARP Spoofing not working**
- Verify gateway and target MACs are correct
- Check IP forwarding in `arpspoof status`
- Must be on same VLAN/subnet as targets (if not, use VLAN Hopping first)

**VLAN Hopping — DTP not detected**
- Not all switches support DTP (non-Cisco typically don't)
- Port may be hardcoded as access: `switchport mode access`
- Increase timeout: `vlanhop configure 20 1 60`
- If DTP fails, double tagging is automatic fallback (one-way only)

**"Method does not exist" in web mode**
- You're running an old binary. Rebuild: `dotnet clean && dotnet build`

### 20.2 Performance Tips

- Packet buffer: 50,000 packets max in memory — export periodically on long captures
- Use capture filters to reduce noise (`filter tcp port 80,443`)
- Web dashboard batches updates at 100ms — CLI has lower overhead for high-throughput networks
- ARP Spoof and VLAN Hop don't add significant overhead — they send small, periodic packets
- All analysis module trackers (TLS sessions, SMB pipes, DNS responses, stealth scan, NTLM) have hard size caps and time-based eviction — memory stays bounded even on long-running captures
- TCP Stream Reassembler limits per-stream buffering to 256 KB and auto-expires idle streams
- Evidence raw frames are capped at 16 KB each — large packet captures don't bloat the evidence store

### 20.3 Legal Considerations

- Always obtain written authorization before capturing network traffic
- Credential extraction, ARP spoofing, and VLAN hopping are offensive techniques
- Document scope and authorization for every engagement
- Never use on production networks without stakeholder consent

---

*Red Packet Sniffer — Built by Johto Robbie*

using System.Runtime.InteropServices;
using RedPacketSniffer.Core.NdisApi;

namespace RedPacketSniffer.Core.Capture;

/// <summary>
/// Parses a raw Ethernet frame into a CapturedPacket.
/// Uses unsafe pointer arithmetic to extract headers from an INTERMEDIATE_BUFFER.
/// </summary>
public static class PacketParser
{
    private static long _packetCounter = 0;

    /// <summary>
    /// Parse an INTERMEDIATE_BUFFER into a CapturedPacket.
    /// </summary>
    public static unsafe CapturedPacket Parse(INTERMEDIATE_BUFFER buffer)
    {
        long id = Interlocked.Increment(ref _packetCounter);
        var direction = buffer.m_dwDeviceFlags == NdisConst.PACKET_FLAG_ON_SEND
            ? PacketDirection.Outbound
            : PacketDirection.Inbound;

        // Copy raw data from the fixed-size buffer.
        // m_IBuffer is a C# fixed-size buffer — already a fixed expression, so we
        // take its address directly (no 'fixed' statement needed; the struct is a
        // stack-local copy and won't move).
        int length = (int)Math.Min(buffer.m_Length, NdisConst.MAX_ETHER_FRAME);
        byte[] rawData = new byte[length];
        byte* pSrc = buffer.m_IBuffer;
        Marshal.Copy((IntPtr)pSrc, rawData, 0, length);

        var packet = new CapturedPacket
        {
            Id = id,
            Timestamp = DateTime.UtcNow,
            Direction = direction,
            Length = length,
            RawData = rawData
        };

        if (length < EthernetHeader.SIZE)
            return packet;

        // Parse Ethernet header
        fixed (byte* pBuf = rawData)
        {
            var eth = (EthernetHeader*)pBuf;
            packet = packet with
            {
                SourceMac = eth->Source.ToString(),
                DestMac = eth->Destination.ToString(),
                EtherType = eth->Protocol
            };

            ushort etherType = eth->Protocol;
            int ipOffset = EthernetHeader.SIZE;
            ushort vlanId = 0;
            ushort outerVlanId = 0;

            // Handle nested VLAN tags — 802.1Q (0x8100), QinQ 802.1ad (0x88A8, 0x9100).
            // PacketDotNet pattern: loop until there are no more VLAN tags.
            while (length >= ipOffset + 4 &&
                   (etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100))
            {
                ushort tci = NetUtils.Ntohs(*(ushort*)(pBuf + ipOffset));
                ushort innerVlan = (ushort)(tci & 0x0FFF);

                if (vlanId == 0)
                {
                    vlanId = innerVlan;
                }
                else
                {
                    // QinQ: outer VLAN already set, this is the inner VLAN
                    outerVlanId = vlanId;
                    vlanId = innerVlan;
                }

                etherType = NetUtils.Ntohs(*(ushort*)(pBuf + ipOffset + 2));
                ipOffset += 4;
            }

            if (vlanId > 0 || etherType != eth->Protocol)
            {
                packet = packet with { EtherType = etherType, VlanId = vlanId, OuterVlanId = outerVlanId };
            }

            // Detect an 802.2 LLC frame (EtherType < 0x0600 means it is actually a length field)
            if (etherType < 0x0600 && length >= ipOffset + LlcHeader.SIZE)
            {
                packet = packet with { IsLlcFrame = true };
                ParseLlcFrame(pBuf, ipOffset, length, ref packet);
            }
            // Parse LLDP (EtherType 0x88CC)
            else if (etherType == EthernetHeader.ETH_P_LLDP)
            {
                packet.ApplicationProtocol = "LLDP";
                ParseLldp(pBuf, ipOffset, length, ref packet);
            }
            // Parse IPv4
            else if (etherType == EthernetHeader.ETH_P_IP && length >= ipOffset + IPv4Header.MIN_SIZE)
            {
                var ip = (IPv4Header*)(pBuf + ipOffset);
                int ipHeaderLen = ip->HeaderLength;

                packet = packet with
                {
                    SourceIP = ip->SourceAddress.ToString(),
                    DestIP = ip->DestinationAddress.ToString(),
                    IpProtocol = ip->Protocol,
                    TTL = ip->TTL
                };

                int transportOffset = ipOffset + ipHeaderLen;

                // Parse TCP
                if (ip->Protocol == IPv4Header.PROTO_TCP && length >= transportOffset + TcpHeader.MIN_SIZE)
                {
                    var tcp = (TcpHeader*)(pBuf + transportOffset);
                    // DataOffset is expressed in bytes here (same convention ParseTcpOptions relies on);
                    // clamp to the 20-byte minimum to stay safe on malformed headers.
                    int tcpHeaderLen = Math.Max(tcp->DataOffset, TcpHeader.MIN_SIZE);
                    packet = packet with
                    {
                        SourcePort = tcp->SourcePort,
                        DestPort = tcp->DestPort,
                        TcpFlags = tcp->Flags,
                        TcpSeq = NetUtils.Ntohl(tcp->SequenceBE),
                        PayloadOffset = transportOffset + tcpHeaderLen
                    };

                    packet.ApplicationProtocol = DetectAppProtocol(tcp->SourcePort, tcp->DestPort, true);

                    // Parse TCP options — PacketDotNet pattern
                    ParseTcpOptions(pBuf, transportOffset, length, ref packet);
                }
                // Parse UDP
                else if (ip->Protocol == IPv4Header.PROTO_UDP && length >= transportOffset + UdpHeader.SIZE)
                {
                    var udp = (UdpHeader*)(pBuf + transportOffset);
                    packet = packet with
                    {
                        SourcePort = udp->SourcePort,
                        DestPort = udp->DestPort,
                        PayloadOffset = transportOffset + UdpHeader.SIZE
                    };

                    packet.ApplicationProtocol = DetectAppProtocol(udp->SourcePort, udp->DestPort, false);

                    // Parse DHCP (UDP port 67/68) — PacketDotNet pattern: magic cookie check
                    if ((udp->DestPort == 67 || udp->DestPort == 68 ||
                         udp->SourcePort == 67 || udp->SourcePort == 68))
                    {
                        int dhcpOffset = transportOffset + UdpHeader.SIZE;
                        ParseDhcp(pBuf, dhcpOffset, length, ref packet);
                    }

                    // Parse HSRP (UDP port 1985 for v1 or 2029 for v2)
                    if ((udp->DestPort == 1985 || udp->DestPort == 2029) &&
                        length >= transportOffset + UdpHeader.SIZE + HsrpHeader.SIZE)
                    {
                        packet.ApplicationProtocol = "HSRP";
                        ParseHsrp(pBuf, transportOffset + UdpHeader.SIZE, length, ref packet);
                    }

                    // Parse IKE (UDP 500 / NAT-T 4500) — passive only, no probing
                    if (udp->DestPort == 500 || udp->DestPort == 4500 ||
                        udp->SourcePort == 500 || udp->SourcePort == 4500)
                    {
                        ParseIke(pBuf, transportOffset + UdpHeader.SIZE, length, ref packet);
                    }
                }
                // Deep-parse ICMP
                else if (ip->Protocol == IPv4Header.PROTO_ICMP && length >= transportOffset + IcmpHeader.SIZE)
                {
                    var icmp = (IcmpHeader*)(pBuf + transportOffset);
                    packet.ApplicationProtocol = "ICMP";
                    packet.Info = FormatIcmpInfo(icmp->Type, icmp->Code, packet.SourceIP!, packet.DestIP!);
                }
                // Parse OSPF
                else if (ip->Protocol == IPv4Header.PROTO_OSPF && length >= transportOffset + OspfHeader.SIZE)
                {
                    packet.ApplicationProtocol = "OSPF";
                    ParseOspf(pBuf, transportOffset, length, ref packet);
                }
                // Parse EIGRP
                else if (ip->Protocol == IPv4Header.PROTO_EIGRP && length >= transportOffset + EigrpHeader.SIZE)
                {
                    packet.ApplicationProtocol = "EIGRP";
                    ParseEigrp(pBuf, transportOffset, length, ref packet);
                }
                // Parse VRRP
                else if (ip->Protocol == IPv4Header.PROTO_VRRP && length >= transportOffset + VrrpHeader.SIZE)
                {
                    packet.ApplicationProtocol = "VRRP";
                    ParseVrrp(pBuf, transportOffset, length, ref packet);
                }
                // Parse GRE — PacketDotNet pattern: variable-length header + recursive inner parse
                else if (ip->Protocol == IPv4Header.PROTO_GRE && length >= transportOffset + GreHeader.SIZE)
                {
                    var gre = (GreHeader*)(pBuf + transportOffset);
                    packet.ApplicationProtocol = "GRE";

                    string innerProto = gre->ProtocolType switch
                    {
                        0x0800 => "IPv4",
                        0x86DD => "IPv6",
                        0x6558 => "Transparent Ethernet",
                        0x880B => "PPP",
                        _ => $"0x{gre->ProtocolType:X4}"
                    };

                    // Variable-length GRE header — PacketDotNet pattern
                    int greHeaderLen = gre->HeaderLength;
                    string keyStr = "";
                    if (gre->HasKey && transportOffset + 8 <= length)
                    {
                        int keyOffset = transportOffset + 4 + (gre->HasChecksum ? 4 : 0);
                        if (keyOffset + 4 <= length)
                        {
                            uint key = NetUtils.Ntohl(*(uint*)(pBuf + keyOffset));
                            keyStr = $" Key=0x{key:X8}";
                        }
                    }

                    packet.Info = $"GRE tunnel -> {innerProto}{keyStr}" +
                                  (gre->HasChecksum ? " [Checksum]" : "") +
                                  (gre->HasSequence ? " [Seq]" : "");

                    // Recursive inner packet decapsulation
                    int innerOffset = transportOffset + greHeaderLen;
                    if (innerOffset < length)
                    {
                        string? innerInfo = DecapGreInner(pBuf, innerOffset, length, gre->ProtocolType);
                        if (innerInfo != null)
                            packet.GreInnerInfo = innerInfo;
                    }
                }
                // Parse IGMP
                else if (ip->Protocol == IPv4Header.PROTO_IGMP && length >= transportOffset + 8)
                {
                    byte igmpType = pBuf[transportOffset];
                    string typeStr = igmpType switch
                    {
                        0x11 => "Membership Query",
                        0x12 => "v1 Membership Report",
                        0x16 => "v2 Membership Report",
                        0x17 => "Leave Group",
                        0x22 => "v3 Membership Report",
                        _ => $"Type(0x{igmpType:X2})"
                    };
                    uint groupBE = *(uint*)(pBuf + transportOffset + 4);
                    packet.ApplicationProtocol = "IGMP";
                    packet.Info = $"IGMP {typeStr} group={NetUtils.IpToString(groupBE)}";
                }
            }
            // Parse IPv6
            else if (etherType == EthernetHeader.ETH_P_IPV6 && length >= ipOffset + IPv6Header.SIZE)
            {
                var ipv6 = (IPv6Header*)(pBuf + ipOffset);

                // Format IPv6 addresses from the raw bytes
                string srcIpv6 = FormatIPv6(pBuf + ipOffset + 8);
                string dstIpv6 = FormatIPv6(pBuf + ipOffset + 24);

                packet = packet with
                {
                    SourceIP = srcIpv6,
                    DestIP = dstIpv6,
                    TTL = ipv6->HopLimit,
                    IsIPv6 = true
                };

                // Walk extension headers — PacketDotNet pattern
                int transportOffset = ipOffset + IPv6Header.SIZE;
                byte nextHeader = ipv6->NextHeader;

                while (IPv6Header.IsExtensionHeader(nextHeader) && transportOffset + 2 <= length)
                {
                    byte thisNH = pBuf[transportOffset];
                    int extLen;

                    if (nextHeader == IPv6Header.PROTO_FRAGMENT)
                    {
                        // Fragment header is a fixed 8 bytes
                        extLen = 8;
                    }
                    else if (nextHeader == IPv6Header.PROTO_AH)
                    {
                        // AH: (payload length + 2) * 4
                        extLen = (pBuf[transportOffset + 1] + 2) * 4;
                    }
                    else
                    {
                        // Generic: (length + 1) * 8
                        extLen = (pBuf[transportOffset + 1] + 1) * 8;
                    }

                    nextHeader = thisNH;
                    transportOffset += extLen;
                }

                // Set the final protocol after walking the extensions
                packet = packet with { IpProtocol = nextHeader };

                // Parse the transport layer — reuse the IPv4 TCP/UDP/ICMP logic
                if (nextHeader == IPv4Header.PROTO_TCP && length >= transportOffset + TcpHeader.MIN_SIZE)
                {
                    var tcp = (TcpHeader*)(pBuf + transportOffset);
                    // DataOffset is expressed in bytes here; clamp to the 20-byte minimum.
                    int tcpHeaderLen = Math.Max(tcp->DataOffset, TcpHeader.MIN_SIZE);
                    packet = packet with
                    {
                        SourcePort = tcp->SourcePort,
                        DestPort = tcp->DestPort,
                        TcpFlags = tcp->Flags,
                        TcpSeq = NetUtils.Ntohl(tcp->SequenceBE),
                        PayloadOffset = transportOffset + tcpHeaderLen
                    };
                    packet.ApplicationProtocol = DetectAppProtocol(tcp->SourcePort, tcp->DestPort, true);

                    // Parse TCP options
                    ParseTcpOptions(pBuf, transportOffset, length, ref packet);
                }
                else if (nextHeader == IPv4Header.PROTO_UDP && length >= transportOffset + UdpHeader.SIZE)
                {
                    var udp = (UdpHeader*)(pBuf + transportOffset);
                    packet = packet with
                    {
                        SourcePort = udp->SourcePort,
                        DestPort = udp->DestPort,
                        PayloadOffset = transportOffset + UdpHeader.SIZE
                    };
                    packet.ApplicationProtocol = DetectAppProtocol(udp->SourcePort, udp->DestPort, false);

                    // DHCP for IPv6 uses ports 546/547 (DHCPv6)
                    if (udp->DestPort == 546 || udp->DestPort == 547 ||
                        udp->SourcePort == 546 || udp->SourcePort == 547)
                    {
                        packet.ApplicationProtocol = "DHCPv6";
                    }

                    // Parse IKE (UDP 500 / NAT-T 4500) — passive only, no probing
                    if (udp->DestPort == 500 || udp->DestPort == 4500 ||
                        udp->SourcePort == 500 || udp->SourcePort == 4500)
                    {
                        ParseIke(pBuf, transportOffset + UdpHeader.SIZE, length, ref packet);
                    }
                }
                else if (nextHeader == IPv6Header.PROTO_ICMPV6 && length >= transportOffset + ICMPv6Header.SIZE)
                {
                    var icmpv6 = (ICMPv6Header*)(pBuf + transportOffset);
                    packet.ApplicationProtocol = "ICMPv6";
                    packet.Info = FormatICMPv6Info(icmpv6->Type, icmpv6->Code, srcIpv6, dstIpv6);
                }
            }
            // Parse ARP
            else if (etherType == EthernetHeader.ETH_P_ARP && length >= ipOffset + 28)
            {
                var arp = (ArpHeader*)(pBuf + ipOffset);
                string opStr = arp->Opcode == ArpHeader.ARP_REQUEST ? "Request" : "Reply";
                string senderIp = NetUtils.IpToString(arp->SenderIpBE);
                string targetIp = NetUtils.IpToString(arp->TargetIpBE);

                packet = packet with { IpProtocol = 0 };
                packet.ApplicationProtocol = "ARP";
                packet.Info = $"ARP {opStr}: {senderIp} ({arp->SenderMac}) -> {targetIp} ({arp->TargetMac})";
            }
        }

        return packet;
    }

    /// <summary>
    /// Detect the application protocol from the port number.
    /// </summary>
    private static string? DetectAppProtocol(ushort srcPort, ushort dstPort, bool isTcp)
    {
        ushort serverPort = Math.Min(srcPort, dstPort); // Heuristic: the lower port is usually the server

        if (isTcp) return serverPort switch
        {
            20 or 21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 or 587 => "SMTP",
            53 => "DNS",
            80 or 8080 or 8000 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 or 8443 => "HTTPS",
            445 => "SMB",
            1433 => "MSSQL",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            5985 or 5986 => "WinRM",
            6379 => "Redis",
            8888 => "HTTP-Alt",
            9200 => "Elasticsearch",
            _ => null
        };

        // UDP
        return serverPort switch
        {
            53 => "DNS",
            67 or 68 => "DHCP",
            69 => "TFTP",
            123 => "NTP",
            137 or 138 => "NetBIOS",
            161 or 162 => "SNMP",
            500 => "IKE",
            514 => "Syslog",
            520 => "RIP",
            1900 => "SSDP",
            1985 => "HSRP",
            2029 => "HSRPv2",
            4500 => "NAT-T",
            5353 => "mDNS",
            5355 => "LLMNR",
            _ => null
        };
    }

    // ============================================================
    // Layer 2 Protocol Parsers
    // ============================================================

    /// <summary>
    /// Parse an 802.2 LLC frame — STP and CDP arrive through here.
    /// </summary>
    private static unsafe void ParseLlcFrame(byte* pBuf, int offset, int length, ref CapturedPacket packet)
    {
        var llc = (LlcHeader*)(pBuf + offset);

        // STP: DSAP=SSAP=0x42, dst MAC 01:80:C2:00:00:xx
        if (llc->DSAP == LlcHeader.SAP_STP && llc->SSAP == LlcHeader.SAP_STP)
        {
            packet.ApplicationProtocol = "STP";
            int bpduOffset = offset + LlcHeader.SIZE;
            if (length >= bpduOffset + StpBpdu.MIN_SIZE)
            {
                var bpdu = (StpBpdu*)(pBuf + bpduOffset);
                string typeStr = bpdu->Type switch
                {
                    StpBpdu.TYPE_CONFIG => "Configuration",
                    StpBpdu.TYPE_TCN => "Topology Change",
                    StpBpdu.TYPE_RST => "RST/MST",
                    _ => $"Type(0x{bpdu->Type:X2})"
                };
                bool tcFlag = (bpdu->Flags & 0x01) != 0;
                bool tcaFlag = (bpdu->Flags & 0x80) != 0;
                packet.Info = $"STP {typeStr} v{bpdu->Version}" +
                              (tcFlag ? " [TC]" : "") +
                              (tcaFlag ? " [TCA]" : "");

                // Parse the root bridge ID if this is a config BPDU (>= 35 bytes)
                if (bpdu->Type == StpBpdu.TYPE_CONFIG && length >= bpduOffset + 35)
                {
                    // Root bridge ID: offset 5-12 (2 priority + 6 MAC)
                    ushort rootPri = NetUtils.Ntohs(*(ushort*)(pBuf + bpduOffset + 4));
                    byte* rootMac = pBuf + bpduOffset + 6;
                    ushort bridgePri = NetUtils.Ntohs(*(ushort*)(pBuf + bpduOffset + 16));
                    byte* bridgeMac = pBuf + bpduOffset + 18;
                    ushort portId = NetUtils.Ntohs(*(ushort*)(pBuf + bpduOffset + 24));

                    packet.Info = $"STP {typeStr} Root={rootPri:X}:" +
                                  $"{rootMac[0]:X2}:{rootMac[1]:X2}:{rootMac[2]:X2}:{rootMac[3]:X2}:{rootMac[4]:X2}:{rootMac[5]:X2} " +
                                  $"Bridge={bridgePri:X}:" +
                                  $"{bridgeMac[0]:X2}:{bridgeMac[1]:X2}:{bridgeMac[2]:X2}:{bridgeMac[3]:X2}:{bridgeMac[4]:X2}:{bridgeMac[5]:X2} " +
                                  $"Port=0x{portId:X4}" +
                                  (tcFlag ? " [TC]" : "") + (tcaFlag ? " [TCA]" : "");
                }
            }
        }
        // SNAP: DSAP=SSAP=0xAA — CDP and VTP arrive through here
        else if (llc->DSAP == LlcHeader.SAP_SNAP && llc->SSAP == LlcHeader.SAP_SNAP)
        {
            int snapOffset = offset + LlcHeader.SIZE;
            if (length >= snapOffset + SnapHeader.SIZE)
            {
                var snap = (SnapHeader*)(pBuf + snapOffset);
                // CDP: OUI 00:00:0C, Type 0x2000
                if (snap->OUI0 == 0x00 && snap->OUI1 == 0x00 && snap->OUI2 == 0x0C &&
                    snap->ProtocolType == SnapHeader.SNAP_CDP)
                {
                    packet.ApplicationProtocol = "CDP";
                    ParseCdp(pBuf, snapOffset + SnapHeader.SIZE, length, ref packet);
                }
                // DTP: OUI 00:00:0C, Type 0x2004 — VlanHopper.AnalyzePacket dựa vào
                // ApplicationProtocol này để detect switch có bật DTP hay không.
                // (Trước đây thiếu branch này nên DTP không bao giờ được detect,
                // workflow luôn chờ hết 30s probe rồi fallback double tagging.)
                else if (snap->OUI0 == 0x00 && snap->OUI1 == 0x00 && snap->OUI2 == 0x0C &&
                    snap->ProtocolType == SnapHeader.SNAP_DTP)
                {
                    packet.ApplicationProtocol = "DTP";
                    ParseDtp(pBuf, snapOffset + SnapHeader.SIZE, length, ref packet);
                }
            }
        }
    }

    /// <summary>
    /// Parse DTP (Dynamic Trunking Protocol) — TLV format.
    /// Dst MAC: 01:00:0C:CC:CC:CC, SNAP OUI 00:00:0C type 0x2004.
    /// Payload: version(1) + TLVs. Status TLV (0x0002) giá trị 4 bytes,
    /// byte cuối là trunk status (0x03=Off, 0x04=Auto, 0x81=On, 0xA5=Desirable).
    /// </summary>
    private static unsafe void ParseDtp(byte* pBuf, int offset, int length, ref CapturedPacket packet)
    {
        packet.Info = "DTP frame";
        if (length < offset + 1) return;

        int pos = offset + 1; // skip version
        string statusStr = "";
        string domainStr = "";

        while (pos + 4 <= length)
        {
            ushort type = NetUtils.Ntohs(*(ushort*)(pBuf + pos));
            ushort len = NetUtils.Ntohs(*(ushort*)(pBuf + pos + 2));
            if (len < 4 || pos + len > length) break;

            if (type == 0x0002 && len >= 8) // Status TLV
            {
                byte status = pBuf[pos + len - 1];
                statusStr = status switch
                {
                    0x03 => "Off",
                    0x04 => "Auto",
                    0x81 => "On",
                    0x82 => "On-NoNegotiate",
                    0xA5 => "Desirable",
                    _ => $"0x{status:X2}"
                };
            }
            else if (type == 0x0001 && len > 4) // Domain TLV
            {
                domainStr = ExtractAscii(pBuf, pos + 4, Math.Min(len - 4, 32));
            }

            pos += len;
        }

        packet.Info = "DTP" +
                      (statusStr != "" ? $" Status={statusStr}" : "") +
                      (domainStr != "" ? $" Domain={domainStr}" : "");
    }

    /// <summary>
    /// Parse CDP (Cisco Discovery Protocol) — TLV format.
    /// Dst MAC: 01:00:0C:CC:CC:CC
    /// </summary>
    private static unsafe void ParseCdp(byte* pBuf, int offset, int length, ref CapturedPacket packet)
    {
        if (length < offset + 4) return;

        byte version = pBuf[offset];
        byte ttl = pBuf[offset + 1];
        int tlvOffset = offset + 4; // Skip version + TTL + checksum

        string deviceId = "";
        string platform = "";
        string portId = "";
        var addresses = new List<string>();
        string nativeVlan = "";
        string duplex = "";

        // Parse TLVs (Type-Length-Value)
        while (tlvOffset + 4 <= length)
        {
            ushort type = NetUtils.Ntohs(*(ushort*)(pBuf + tlvOffset));
            ushort len = NetUtils.Ntohs(*(ushort*)(pBuf + tlvOffset + 2));
            if (len < 4 || tlvOffset + len > length) break;

            int dataOffset = tlvOffset + 4;
            int dataLen = len - 4;

            switch (type)
            {
                case 0x0001: // Device ID
                    deviceId = ExtractAscii(pBuf, dataOffset, dataLen);
                    break;
                case 0x0002: // Addresses
                    if (dataLen >= 8)
                    {
                        uint numAddr = NetUtils.Ntohl(*(uint*)(pBuf + dataOffset));
                        int addrPos = dataOffset + 4;
                        for (uint a = 0; a < numAddr && a < 4 && addrPos + 9 <= length; a++)
                        {
                            byte protoType = pBuf[addrPos];
                            byte protoLen = pBuf[addrPos + 1];
                            addrPos += 2 + protoLen;
                            if (addrPos + 2 > length) break;
                            ushort addrLen = NetUtils.Ntohs(*(ushort*)(pBuf + addrPos));
                            addrPos += 2;
                            if (addrLen == 4 && addrPos + 4 <= length)
                            {
                                addresses.Add(NetUtils.IpToString(*(uint*)(pBuf + addrPos)));
                            }
                            addrPos += addrLen;
                        }
                    }
                    break;
                case 0x0003: // Port ID
                    portId = ExtractAscii(pBuf, dataOffset, dataLen);
                    break;
                case 0x0006: // Platform
                    platform = ExtractAscii(pBuf, dataOffset, dataLen);
                    break;
                case 0x000A: // Native VLAN
                    if (dataLen >= 2)
                        nativeVlan = NetUtils.Ntohs(*(ushort*)(pBuf + dataOffset)).ToString();
                    break;
                case 0x000B: // Duplex
                    if (dataLen >= 1)
                        duplex = pBuf[dataOffset] == 1 ? "Full" : "Half";
                    break;
            }

            tlvOffset += len;
        }

        var parts = new List<string> { $"CDPv{version} TTL={ttl}" };
        if (!string.IsNullOrEmpty(deviceId)) parts.Add($"Device={deviceId}");
        if (!string.IsNullOrEmpty(platform)) parts.Add($"Platform={platform}");
        if (!string.IsNullOrEmpty(portId)) parts.Add($"Port={portId}");
        if (addresses.Count > 0) parts.Add($"IP={string.Join(",", addresses)}");
        if (!string.IsNullOrEmpty(nativeVlan)) parts.Add($"VLAN={nativeVlan}");
        if (!string.IsNullOrEmpty(duplex)) parts.Add($"Duplex={duplex}");

        packet.Info = string.Join(" ", parts);
    }

    /// <summary>
    /// Parse LLDP (Link Layer Discovery Protocol) — TLV format.
    /// EtherType 0x88CC
    /// </summary>
    private static unsafe void ParseLldp(byte* pBuf, int offset, int length, ref CapturedPacket packet)
    {
        string chassisId = "";
        string portId = "";
        string sysName = "";
        string sysDesc = "";
        int ttl = 0;

        int pos = offset;
        while (pos + 2 <= length)
        {
            ushort typeLen = NetUtils.Ntohs(*(ushort*)(pBuf + pos));
            int type = (typeLen >> 9) & 0x7F;
            int len = typeLen & 0x01FF;
            pos += 2;

            if (type == 0) break; // End of LLDPDU
            if (pos + len > length) break;

            switch (type)
            {
                case 1: // Chassis ID
                    if (len > 1)
                    {
                        byte subtype = pBuf[pos];
                        if (subtype == 4 && len == 7) // MAC address
                            chassisId = $"{pBuf[pos+1]:X2}:{pBuf[pos+2]:X2}:{pBuf[pos+3]:X2}:{pBuf[pos+4]:X2}:{pBuf[pos+5]:X2}:{pBuf[pos+6]:X2}";
                        else
                            chassisId = ExtractAscii(pBuf, pos + 1, len - 1);
                    }
                    break;
                case 2: // Port ID
                    if (len > 1)
                        portId = ExtractAscii(pBuf, pos + 1, len - 1);
                    break;
                case 3: // TTL
                    if (len >= 2)
                        ttl = NetUtils.Ntohs(*(ushort*)(pBuf + pos));
                    break;
                case 5: // System Name
                    sysName = ExtractAscii(pBuf, pos, len);
                    break;
                case 6: // System Description
                    sysDesc = ExtractAscii(pBuf, pos, Math.Min(len, 80));
                    break;
            }

            pos += len;
        }

        var parts = new List<string> { "LLDP" };
        if (!string.IsNullOrEmpty(sysName)) parts.Add($"Name={sysName}");
        if (!string.IsNullOrEmpty(chassisId)) parts.Add($"Chassis={chassisId}");
        if (!string.IsNullOrEmpty(portId)) parts.Add($"Port={portId}");
        if (ttl > 0) parts.Add($"TTL={ttl}");
        if (!string.IsNullOrEmpty(sysDesc)) parts.Add($"Desc={sysDesc}");

        packet.Info = string.Join(" ", parts);
    }

    // ============================================================
    // Layer 3 Protocol Parsers
    // ============================================================

    /// <summary>
    /// Parse OSPF — extract auth type, router ID, area, packet type.
    /// </summary>
    private static unsafe void ParseOspf(byte* pBuf, int offset, int length, ref CapturedPacket packet)
    {
        var ospf = (OspfHeader*)(pBuf + offset);
        string typeStr = ospf->Type switch
        {
            OspfHeader.TYPE_HELLO => "Hello",
            OspfHeader.TYPE_DB_DESC => "DB Description",
            OspfHeader.TYPE_LS_REQUEST => "LS Request",
            OspfHeader.TYPE_LS_UPDATE => "LS Update",
            OspfHeader.TYPE_LS_ACK => "LS Ack",
            _ => $"Type({ospf->Type})"
        };

        string routerId = NetUtils.IpToString(ospf->RouterIdBE);
        string areaId = NetUtils.IpToString(ospf->AreaIdBE);

        string authStr = ospf->AuthType switch
        {
            OspfHeader.AUTH_NONE => "Auth=NONE",
            OspfHeader.AUTH_PLAINTEXT => "Auth=PLAINTEXT",
            OspfHeader.AUTH_MD5 => "Auth=MD5",
            _ => $"Auth=Unknown({ospf->AuthType})"
        };

        string info = $"OSPFv{ospf->Version} {typeStr} Router={routerId} Area={areaId} {authStr}";

        // Extract the plaintext password when auth type = 1
        if (ospf->AuthType == OspfHeader.AUTH_PLAINTEXT)
        {
            // The auth data field (8 bytes) holds the plaintext password
            byte* authBytes = pBuf + offset + 16; // offset to auth data
            if (offset + 24 <= length)
            {
                string password = ExtractAscii(authBytes, 0, 8).TrimEnd('\0');
                if (!string.IsNullOrEmpty(password))
                    info += $" Password=\"{password}\"";
            }
            info += " [INSECURE]";
        }

        // Parse the Hello packet details
        if (ospf->Type == OspfHeader.TYPE_HELLO && length >= offset + OspfHeader.SIZE + OspfHello.SIZE)
        {
            var hello = (OspfHello*)(pBuf + offset + OspfHeader.SIZE);
            string mask = NetUtils.IpToString(hello->NetworkMaskBE);
            string dr = NetUtils.IpToString(hello->DesignatedRouterBE);
            string bdr = NetUtils.IpToString(hello->BackupDesignatedRouterBE);
            info += $" Mask={mask} Hello={hello->HelloInterval}s Dead={hello->DeadInterval}s DR={dr} BDR={bdr} Pri={hello->Priority}";

            // Count neighbors
            int neighborOffset = offset + OspfHeader.SIZE + OspfHello.SIZE;
            int neighborCount = 0;
            while (neighborOffset + 4 <= length && neighborOffset + 4 <= offset + ospf->PacketLength)
            {
                neighborCount++;
                neighborOffset += 4;
            }
            if (neighborCount > 0) info += $" Neighbors={neighborCount}";
        }

        // Extract the MD5 key ID when auth type = 2
        if (ospf->AuthType == OspfHeader.AUTH_MD5 && offset + 24 <= length)
        {
            // MD5 auth data layout: 2 bytes reserved, key ID (1 byte), auth data length (1 byte), seq number (4 bytes)
            byte keyId = pBuf[offset + 18];
            byte authDataLen = pBuf[offset + 19];
            uint cryptoSeq = NetUtils.Ntohl(*(uint*)(pBuf + offset + 20));
            info += $" KeyID={keyId} SeqNum={cryptoSeq} DigestLen={authDataLen}";
        }

        packet.Info = info;
    }

    /// <summary>
    /// Parse EIGRP — extract opcode, AS, flags.
    /// </summary>
    private static unsafe void ParseEigrp(byte* pBuf, int offset, int length, ref CapturedPacket packet)
    {
        var eigrp = (EigrpHeader*)(pBuf + offset);
        string opcodeStr = eigrp->Opcode switch
        {
            EigrpHeader.OPCODE_UPDATE => "Update",
            EigrpHeader.OPCODE_QUERY => "Query",
            EigrpHeader.OPCODE_REPLY => "Reply",
            EigrpHeader.OPCODE_HELLO => "Hello/Ack",
            _ => $"Opcode({eigrp->Opcode})"
        };

        uint flags = NetUtils.Ntohl(eigrp->FlagsBE);
        uint seq = NetUtils.Ntohl(eigrp->SeqBE);
        uint ack = NetUtils.Ntohl(eigrp->AckBE);

        string info = $"EIGRP {opcodeStr} Seq={seq}";
        if (ack > 0) info += $" Ack={ack}";

        var flagParts = new List<string>();
        if ((flags & 0x01) != 0) flagParts.Add("INIT");
        if ((flags & 0x02) != 0) flagParts.Add("CR"); // Conditional Receive
        if ((flags & 0x04) != 0) flagParts.Add("RS"); // Restart
        if ((flags & 0x08) != 0) flagParts.Add("EOT"); // End of Table
        if (flagParts.Count > 0) info += $" [{string.Join(",", flagParts)}]";

        // Parse TLVs to find the AS number and auth
        int tlvOffset = offset + EigrpHeader.SIZE;
        bool hasAuth = false;
        while (tlvOffset + 4 <= length)
        {
            ushort tlvType = NetUtils.Ntohs(*(ushort*)(pBuf + tlvOffset));
            ushort tlvLen = NetUtils.Ntohs(*(ushort*)(pBuf + tlvOffset + 2));
            if (tlvLen < 4 || tlvOffset + tlvLen > length) break;

            if (tlvType == 0x0001) // Parameters TLV — contains K values
            {
                // K1-K5 values at offset 4-8
            }
            else if (tlvType == 0x0002) // Auth TLV
            {
                hasAuth = true;
                if (tlvLen >= 8)
                {
                    ushort authType = NetUtils.Ntohs(*(ushort*)(pBuf + tlvOffset + 4));
                    info += authType switch
                    {
                        2 => " Auth=MD5",
                        3 => " Auth=SHA256",
                        _ => $" Auth=Type({authType})"
                    };
                }
            }
            else if (tlvType == 0x0003) // Software Version
            {
                // EIGRP software version
            }
            else if (tlvType == 0x0004) // Multi-Protocol TLV
            {
                // Contains topology info
            }

            tlvOffset += tlvLen;
        }

        if (!hasAuth) info += " Auth=NONE [INSECURE]";

        packet.Info = info;
    }

    /// <summary>
    /// Parse VRRP — virtual router ID, priority, auth.
    /// </summary>
    private static unsafe void ParseVrrp(byte* pBuf, int offset, int length, ref CapturedPacket packet)
    {
        var vrrp = (VrrpHeader*)(pBuf + offset);
        string authStr = vrrp->AuthType switch
        {
            VrrpHeader.AUTH_NONE => "Auth=NONE",
            VrrpHeader.AUTH_SIMPLE => "Auth=SIMPLE [INSECURE]",
            _ => $"Auth=Type({vrrp->AuthType})"
        };

        string info = $"VRRPv{vrrp->Version} VRID={vrrp->VirtualRouterId} Priority={vrrp->Priority} " +
                       $"Interval={vrrp->AdvertInterval}s IPs={vrrp->CountIpAddrs} {authStr}";

        // Extract the virtual IP addresses
        int ipOffset = offset + VrrpHeader.SIZE;
        var vips = new List<string>();
        for (int i = 0; i < vrrp->CountIpAddrs && ipOffset + 4 <= length && i < 4; i++)
        {
            vips.Add(NetUtils.IpToString(*(uint*)(pBuf + ipOffset)));
            ipOffset += 4;
        }
        if (vips.Count > 0) info += $" VIP={string.Join(",", vips)}";

        packet.Info = info;
    }

    /// <summary>
    /// Parse HSRP — group, state, priority, auth.
    /// </summary>
    private static unsafe void ParseHsrp(byte* pBuf, int offset, int length, ref CapturedPacket packet)
    {
        var hsrp = (HsrpHeader*)(pBuf + offset);
        string stateStr = hsrp->State switch
        {
            0 => "Initial",
            1 => "Learn",
            2 => "Listen",
            HsrpHeader.STATE_SPEAK => "Speak",
            HsrpHeader.STATE_STANDBY => "Standby",
            HsrpHeader.STATE_ACTIVE => "Active",
            _ => $"State({hsrp->State})"
        };

        string opcodeStr = hsrp->Opcode switch
        {
            0 => "Hello",
            1 => "Coup",
            2 => "Resign",
            3 => "Advertise",
            _ => $"Op({hsrp->Opcode})"
        };

        string vip = NetUtils.IpToString(hsrp->VirtualIpBE);

        // Extract the plaintext auth (8 bytes — usually the "cisco" default)
        byte* authBytes = pBuf + offset + 8;
        string authPassword = "";
        if (offset + 16 <= length)
        {
            authPassword = ExtractAscii(authBytes, 0, 8).TrimEnd('\0');
        }

        string info = $"HSRPv{hsrp->Version} {opcodeStr} Group={hsrp->Group} State={stateStr} " +
                       $"Priority={hsrp->Priority} Hello={hsrp->HelloTime}s Hold={hsrp->HoldTime}s VIP={vip}";

        if (!string.IsNullOrEmpty(authPassword))
            info += $" Auth=\"{authPassword}\" [PLAINTEXT]";

        packet.Info = info;
    }

    // ============================================================
    // TCP Options Parser — PacketDotNet pattern
    // ============================================================

    /// <summary>
    /// Parse the TCP options (after the 20-byte fixed header).
    /// PacketDotNet uses polymorphic TcpOption subclasses; here it is inlined because
    /// we only need to extract the values.
    /// </summary>
    private static unsafe void ParseTcpOptions(byte* pBuf, int tcpOffset, int length, ref CapturedPacket packet)
    {
        var tcp = (TcpHeader*)(pBuf + tcpOffset);
        int dataOffset = tcp->DataOffset;
        if (dataOffset <= TcpHeader.MIN_SIZE) return; // No options

        int optStart = tcpOffset + TcpHeader.MIN_SIZE;
        int optEnd = Math.Min(tcpOffset + dataOffset, length);

        var opts = new List<string>();
        int pos = optStart;

        while (pos < optEnd)
        {
            byte kind = pBuf[pos];

            // End of Options List
            if (kind == 0) break;

            // NOP (padding)
            if (kind == 1)
            {
                pos++;
                continue;
            }

            // All other options: kind + length + data
            if (pos + 1 >= optEnd) break;
            byte optLen = pBuf[pos + 1];
            if (optLen < 2 || pos + optLen > optEnd) break;

            switch (kind)
            {
                case 2: // MSS (Maximum Segment Size) — 4 bytes
                    if (optLen == 4 && pos + 4 <= optEnd)
                    {
                        ushort mss = NetUtils.Ntohs(*(ushort*)(pBuf + pos + 2));
                        packet.TcpMss = mss;
                        opts.Add($"MSS={mss}");
                    }
                    break;

                case 3: // Window Scale — 3 bytes
                    if (optLen == 3 && pos + 3 <= optEnd)
                    {
                        byte scale = pBuf[pos + 2];
                        packet.TcpWindowScale = scale;
                        opts.Add($"WS={scale}");
                    }
                    break;

                case 4: // SACK Permitted — 2 bytes
                    if (optLen == 2)
                    {
                        packet.TcpSackPermitted = true;
                        opts.Add("SACK_PERM");
                    }
                    break;

                case 5: // SACK blocks — variable
                    {
                        int blockCount = (optLen - 2) / 8;
                        opts.Add($"SACK({blockCount}blk)");
                    }
                    break;

                case 8: // Timestamps — 10 bytes
                    if (optLen == 10 && pos + 10 <= optEnd)
                    {
                        uint tsVal = NetUtils.Ntohl(*(uint*)(pBuf + pos + 2));
                        uint tsEcr = NetUtils.Ntohl(*(uint*)(pBuf + pos + 6));
                        packet.TcpTimestampValue = tsVal;
                        packet.TcpTimestampEcho = tsEcr;
                        opts.Add($"TS={tsVal}/{tsEcr}");
                    }
                    break;

                default:
                    opts.Add($"Opt{kind}");
                    break;
            }

            pos += optLen;
        }

        if (opts.Count > 0)
            packet.TcpOptionsStr = string.Join(" ", opts);
    }

    // ============================================================
    // DHCP Parser — PacketDotNet pattern: magic cookie + TLV options
    // ============================================================

    /// <summary>
    /// Parse a DHCP packet — extract the message type, offered IP, server, hostname, and options.
    /// </summary>
    private static unsafe void ParseDhcp(byte* pBuf, int offset, int length, ref CapturedPacket packet)
    {
        // Need at least the DHCP fixed header + magic cookie
        if (length < offset + DhcpHeader.OPTIONS_OFFSET) return;

        byte op = pBuf[offset]; // 1=Request, 2=Reply
        uint xid = NetUtils.Ntohl(*(uint*)(pBuf + offset + 4));
        uint yiaddr = *(uint*)(pBuf + offset + 16); // Offered IP (network byte order)

        // Client MAC (first 6 bytes of chaddr at offset +28)
        string clientMac = $"{pBuf[offset+28]:X2}:{pBuf[offset+29]:X2}:{pBuf[offset+30]:X2}:" +
                           $"{pBuf[offset+31]:X2}:{pBuf[offset+32]:X2}:{pBuf[offset+33]:X2}";

        // Check the magic cookie: 0x63825363 at offset 236
        uint cookie = NetUtils.Ntohl(*(uint*)(pBuf + offset + DhcpHeader.FIXED_SIZE));
        if (cookie != DhcpHeader.MAGIC_COOKIE) return;

        packet.ApplicationProtocol = "DHCP";

        // Parse the DHCP options (TLV after the magic cookie)
        int optPos = offset + DhcpHeader.OPTIONS_OFFSET;
        byte messageType = 0;
        string? serverIp = null;
        string? requestedIp = null;
        string? hostname = null;
        string? domainName = null;
        uint leaseTime = 0;

        while (optPos < length)
        {
            byte optCode = pBuf[optPos];

            if (optCode == 255) break; // End
            if (optCode == 0) { optPos++; continue; } // Pad

            if (optPos + 1 >= length) break;
            byte optLen = pBuf[optPos + 1];
            int dataPos = optPos + 2;
            if (dataPos + optLen > length) break;

            switch (optCode)
            {
                case 53: // DHCP Message Type
                    if (optLen >= 1) messageType = pBuf[dataPos];
                    break;
                case 54: // Server Identifier
                    if (optLen == 4) serverIp = NetUtils.IpToString(*(uint*)(pBuf + dataPos));
                    break;
                case 50: // Requested IP
                    if (optLen == 4) requestedIp = NetUtils.IpToString(*(uint*)(pBuf + dataPos));
                    break;
                case 12: // Hostname
                    hostname = ExtractAscii(pBuf, dataPos, Math.Min((int)optLen, 64));
                    break;
                case 15: // Domain Name
                    domainName = ExtractAscii(pBuf, dataPos, Math.Min((int)optLen, 64));
                    break;
                case 51: // Lease Time
                    if (optLen == 4) leaseTime = NetUtils.Ntohl(*(uint*)(pBuf + dataPos));
                    break;
            }

            optPos += 2 + optLen;
        }

        string msgTypeStr = messageType switch
        {
            DhcpHeader.MSG_DISCOVER => "DISCOVER",
            DhcpHeader.MSG_OFFER => "OFFER",
            DhcpHeader.MSG_REQUEST => "REQUEST",
            DhcpHeader.MSG_DECLINE => "DECLINE",
            DhcpHeader.MSG_ACK => "ACK",
            DhcpHeader.MSG_NAK => "NAK",
            DhcpHeader.MSG_RELEASE => "RELEASE",
            DhcpHeader.MSG_INFORM => "INFORM",
            _ => $"Type({messageType})"
        };

        var parts = new List<string> { $"DHCP {msgTypeStr} XID=0x{xid:X8}" };

        string offeredIp = NetUtils.IpToString(yiaddr);
        if (offeredIp != "0.0.0.0") parts.Add($"Offered={offeredIp}");
        if (requestedIp != null) parts.Add($"Requested={requestedIp}");
        if (serverIp != null) parts.Add($"Server={serverIp}");
        if (hostname != null) parts.Add($"Host={hostname}");
        if (domainName != null) parts.Add($"Domain={domainName}");
        if (leaseTime > 0) parts.Add($"Lease={leaseTime}s");
        parts.Add($"Client={clientMac}");

        packet.Info = string.Join(" ", parts);
    }

    // ============================================================
    // IKE Passive Parser — ISAKMP header + payload chain, no probing
    // RFC 2408/2409 (IKEv1) + RFC 7296 (IKEv2). Only reads bytes.
    // Collects: version, exchange/mode, flags, payload list,
    // Vendor-ID guess. No PSK/hash extraction, no crack.
    // ============================================================

    private static unsafe void ParseIke(byte* pBuf, int offset, int length, ref CapturedPacket packet)
    {
        int ikeOffset = offset;

        // NAT-T (UDP 4500): strip 4-byte Non-ESP marker (all zero) -> IKE follows.
        bool isNatT = packet.SourcePort == 4500 || packet.DestPort == 4500;
        if (isNatT && length >= ikeOffset + 4 &&
            pBuf[ikeOffset] == 0 && pBuf[ikeOffset + 1] == 0 &&
            pBuf[ikeOffset + 2] == 0 && pBuf[ikeOffset + 3] == 0)
        {
            ikeOffset += 4;
        }

        if (length < ikeOffset + 28)
        {
            packet.Info = isNatT
                ? "NAT-T ESP data (no ISAKMP header)"
                : "IKE fragment (payload < 28B ISAKMP header)";
            return;
        }

        byte nextPayload = pBuf[ikeOffset + 16];
        byte verByte = pBuf[ikeOffset + 17];
        int major = (verByte >> 4) & 0x0F;
        int minor = verByte & 0x0F;
        byte exchange = pBuf[ikeOffset + 18];
        byte flags = pBuf[ikeOffset + 19];

        bool rCookieZero = true;
        for (int i = 0; i < 8; i++)
        {
            if (pBuf[ikeOffset + 8 + i] != 0) { rCookieZero = false; break; }
        }

        string versionStr = major == 2 ? "IKEv2" : major == 1 ? "IKEv1" : $"IKE ver{major}.{minor}";
        string exchStr = major == 2 ? IkeV2ExchangeName(exchange) : IkeV1ExchangeName(exchange);
        string role = rCookieZero ? "Initiator (1st msg)" : "Responder/ongoing";

        var payloadNames = new List<string>();
        var vidGuesses = new List<string>();
        int pos = ikeOffset + 28;
        byte cur = nextPayload;
        for (int depth = 0; depth < 16 && cur != 0 && pos + 4 <= length; depth++)
        {
            byte next = pBuf[pos];
            int payLen = (pBuf[pos + 2] << 8) | pBuf[pos + 3];
            if (payLen < 4 || pos + payLen > length) break;

            payloadNames.Add(major == 2 ? IkeV2PayloadName(cur) : IkeV1PayloadName(cur));

            if (cur == 13 || cur == 43)
            {
                string hex = IkeBytesToHex(pBuf, pos + 4, Math.Min(payLen - 4, 24));
                string? guess = GuessVendorId(hex);
                if (guess != null) vidGuesses.Add(guess);
            }

            cur = next;
            pos += payLen;
        }

        var parts = new List<string> { $"{versionStr} {exchStr} Flags=0x{flags:X2} {role}" };
        if (payloadNames.Count > 0) parts.Add($"Payloads=[{string.Join(",", payloadNames)}]");
        if (vidGuesses.Count > 0) parts.Add($"VID={string.Join("|", vidGuesses)}");
        packet.Info = string.Join(" ", parts);
    }

    private static string IkeV1ExchangeName(byte ex) => ex switch
    {
        1 => "Base",
        2 => "Main Mode (ID Protection)",
        3 => "Auth Only",
        4 => "Aggressive Mode",
        5 => "Informational",
        6 => "Transaction (Mode Config)",
        _ => $"Exchange({ex})"
    };

    private static string IkeV2ExchangeName(byte ex) => ex switch
    {
        34 => "IKE_SA_INIT",
        35 => "IKE_AUTH",
        36 => "CREATE_CHILD_SA",
        37 => "INFORMATIONAL",
        _ => $"Exchange({ex})"
    };

    private static string IkeV1PayloadName(byte t) => t switch
    {
        1 => "SA",
        2 => "Proposal",
        3 => "Transform",
        4 => "KE",
        5 => "ID",
        6 => "CERT",
        7 => "CERTREQ",
        8 => "Hash",
        9 => "SIG",
        10 => "Nonce",
        11 => "Notify",
        12 => "Delete",
        13 => "VendorID",
        _ => $"P({t})"
    };

    private static string IkeV2PayloadName(byte t) => t switch
    {
        33 => "SA",
        34 => "KE",
        35 => "IDi",
        36 => "IDr",
        37 => "CERT",
        38 => "CERTREQ",
        39 => "AUTH",
        40 => "Nonce",
        41 => "Notify",
        42 => "Delete",
        43 => "VendorID",
        44 => "TSi",
        45 => "TSr",
        46 => "SK",
        47 => "CP",
        _ => $"P({t})"
    };

    private static unsafe string IkeBytesToHex(byte* pBuf, int offset, int count)
    {
        var sb = new System.Text.StringBuilder(count * 2);
        for (int i = 0; i < count; i++)
            sb.Append(pBuf[offset + i].ToString("x2"));
        return sb.ToString();
    }

    private static string? GuessVendorId(string hexLower)
    {
        string h = hexLower.ToLowerInvariant();
        if (h.StartsWith("12f5f28c457168a9702d9fe274cc01")) return "Cisco Unity";
        if (h.StartsWith("09002689dfd6b712")) return "XAUTH";
        if (h.StartsWith("4048b7d56ebce88525e7de7f00d6c2d3")) return "IKE Fragmentation";
        if (h.StartsWith("1f07f70eaa6514d3b0fa96542a5001")) return "Cisco VPN Concentrator";
        if (h.StartsWith("4a131c8343b5878225ad5a55a494a5")) return "NAT-T RFC3947";
        if (h.StartsWith("afcad71368a1f1c96b8696ff01c6d4a")) return "DPD";
        if (h.StartsWith("90cb80913ebb696e086381b5ec427b")) return "Fragmentation (RFC 7383)";
        return null;
    }

    // ============================================================
    // GRE Inner Decapsulation — PacketDotNet CustomPayloadDecoder pattern
    // ============================================================

    /// <summary>
    /// Decapsulate the inner packet inside a GRE tunnel — extract IP src/dst + protocol.
    /// </summary>
    private static unsafe string? DecapGreInner(byte* pBuf, int innerOffset, int length, ushort innerEtherType)
    {
        if (innerEtherType == 0x0800 && length >= innerOffset + IPv4Header.MIN_SIZE)
        {
            // Inner IPv4
            var innerIp = (IPv4Header*)(pBuf + innerOffset);
            string srcIp = innerIp->SourceAddress.ToString();
            string dstIp = innerIp->DestinationAddress.ToString();
            string proto = innerIp->Protocol switch
            {
                IPv4Header.PROTO_TCP => "TCP",
                IPv4Header.PROTO_UDP => "UDP",
                IPv4Header.PROTO_ICMP => "ICMP",
                _ => $"Proto({innerIp->Protocol})"
            };

            string innerInfo = $"Inner: {proto} {srcIp} -> {dstIp}";

            // Extract the inner ports when TCP/UDP
            int innerTransport = innerOffset + innerIp->HeaderLength;
            if ((innerIp->Protocol == IPv4Header.PROTO_TCP || innerIp->Protocol == IPv4Header.PROTO_UDP)
                && length >= innerTransport + 4)
            {
                ushort srcPort = NetUtils.Ntohs(*(ushort*)(pBuf + innerTransport));
                ushort dstPort = NetUtils.Ntohs(*(ushort*)(pBuf + innerTransport + 2));
                innerInfo += $" {srcPort}->{dstPort}";
            }

            return innerInfo;
        }
        else if (innerEtherType == 0x86DD && length >= innerOffset + IPv6Header.SIZE)
        {
            // Inner IPv6
            string srcIpv6 = FormatIPv6(pBuf + innerOffset + 8);
            string dstIpv6 = FormatIPv6(pBuf + innerOffset + 24);
            byte nh = pBuf[innerOffset + 6];
            string proto = nh switch
            {
                IPv4Header.PROTO_TCP => "TCP",
                IPv4Header.PROTO_UDP => "UDP",
                IPv6Header.PROTO_ICMPV6 => "ICMPv6",
                _ => $"Proto({nh})"
            };
            return $"Inner: {proto} {srcIpv6} -> {dstIpv6}";
        }

        return null;
    }

    // ============================================================
    // IPv6 Address Formatting
    // ============================================================

    /// <summary>
    /// Format 16 bytes of an IPv6 address into a compressed string (RFC 5952).
    /// </summary>
    private static unsafe string FormatIPv6(byte* addr)
    {
        // Parse 8 groups of 16-bit values
        var groups = new ushort[8];
        for (int i = 0; i < 8; i++)
            groups[i] = (ushort)((addr[i * 2] << 8) | addr[i * 2 + 1]);

        // Find the longest run of zeros for :: compression
        int bestStart = -1, bestLen = 0;
        int curStart = -1, curLen = 0;

        for (int i = 0; i < 8; i++)
        {
            if (groups[i] == 0)
            {
                if (curStart == -1) curStart = i;
                curLen++;
                if (curLen > bestLen)
                {
                    bestStart = curStart;
                    bestLen = curLen;
                }
            }
            else
            {
                curStart = -1;
                curLen = 0;
            }
        }

        // Build the string
        var sb = new System.Text.StringBuilder(39);
        if (bestLen < 2) bestStart = -1; // Only compress runs of 2+

        for (int i = 0; i < 8; i++)
        {
            if (i == bestStart)
            {
                sb.Append(i == 0 ? "::" : ":");
                i += bestLen - 1;
                continue;
            }

            if (i > 0 && !(i == bestStart + bestLen && bestStart >= 0))
                sb.Append(':');

            sb.Append(groups[i].ToString("x"));
        }

        return sb.ToString();
    }

    // ============================================================
    // ICMPv6 Info Formatter
    // ============================================================

    /// <summary>
    /// Format the ICMPv6 type/code — including NDP messages.
    /// </summary>
    private static string FormatICMPv6Info(byte type, byte code, string srcIp, string dstIp)
    {
        string typeStr = type switch
        {
            ICMPv6Header.DEST_UNREACHABLE => code switch
            {
                0 => "No Route to Destination",
                1 => "Administratively Prohibited",
                3 => "Address Unreachable",
                4 => "Port Unreachable",
                _ => $"Dest Unreachable (code={code})"
            },
            ICMPv6Header.PACKET_TOO_BIG => "Packet Too Big",
            ICMPv6Header.TIME_EXCEEDED => code == 0 ? "Hop Limit Exceeded" : "Fragment Reassembly Exceeded",
            ICMPv6Header.PARAMETER_PROBLEM => "Parameter Problem",
            ICMPv6Header.ECHO_REQUEST => "Echo Request",
            ICMPv6Header.ECHO_REPLY => "Echo Reply",
            // NDP — important for network recon
            ICMPv6Header.ROUTER_SOLICITATION => "Router Solicitation",
            ICMPv6Header.ROUTER_ADVERTISEMENT => "Router Advertisement [RECON]",
            ICMPv6Header.NEIGHBOR_SOLICITATION => "Neighbor Solicitation",
            ICMPv6Header.NEIGHBOR_ADVERTISEMENT => "Neighbor Advertisement",
            ICMPv6Header.REDIRECT => "Redirect [POTENTIAL_MITM]",
            // MLD
            ICMPv6Header.MLD_QUERY => "MLD Query",
            ICMPv6Header.MLD_REPORT => "MLD Report",
            ICMPv6Header.MLD_DONE => "MLD Done",
            ICMPv6Header.MLD2_REPORT => "MLDv2 Report",
            _ => $"Type({type}) Code({code})"
        };

        return $"ICMPv6 {typeStr}: {srcIp} -> {dstIp}";
    }

    // ============================================================
    // Helpers
    // ============================================================

    /// <summary>
    /// Format an ICMP type/code into a readable string.
    /// </summary>
    private static string FormatIcmpInfo(byte type, byte code, string srcIp, string dstIp)
    {
        string typeStr = type switch
        {
            IcmpHeader.ECHO_REPLY => "Echo Reply",
            IcmpHeader.DEST_UNREACHABLE => code switch
            {
                0 => "Destination Net Unreachable",
                1 => "Destination Host Unreachable",
                2 => "Destination Protocol Unreachable",
                3 => "Destination Port Unreachable",
                4 => "Fragmentation Needed",
                6 => "Destination Network Unknown",
                9 => "Network Administratively Prohibited",
                10 => "Host Administratively Prohibited",
                13 => "Communication Administratively Prohibited",
                _ => $"Dest Unreachable (code={code})"
            },
            IcmpHeader.REDIRECT => code switch
            {
                0 => "Redirect for Network",
                1 => "Redirect for Host",
                2 => "Redirect for TOS+Network",
                3 => "Redirect for TOS+Host",
                _ => $"Redirect (code={code})"
            } + " [POTENTIAL_MITM]",
            IcmpHeader.ECHO_REQUEST => "Echo Request",
            IcmpHeader.TIME_EXCEEDED => code == 0 ? "TTL Exceeded" : "Fragment Reassembly Exceeded",
            IcmpHeader.TIMESTAMP_REQUEST => "Timestamp Request",
            IcmpHeader.TIMESTAMP_REPLY => "Timestamp Reply",
            IcmpHeader.ADDRESS_MASK_REQUEST => "Address Mask Request",
            IcmpHeader.ADDRESS_MASK_REPLY => "Address Mask Reply",
            _ => $"Type({type}) Code({code})"
        };

        return $"ICMP {typeStr}: {srcIp} -> {dstIp}";
    }

    /// <summary>
    /// Extract an ASCII string from the buffer, replacing non-printable characters.
    /// </summary>
    private static unsafe string ExtractAscii(byte* pBuf, int offset, int maxLen)
    {
        var sb = new System.Text.StringBuilder(maxLen);
        for (int i = 0; i < maxLen; i++)
        {
            byte b = pBuf[offset + i];
            if (b == 0) break;
            sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
        }
        return sb.ToString();
    }

    public static void ResetCounter() => Interlocked.Exchange(ref _packetCounter, 0);
}

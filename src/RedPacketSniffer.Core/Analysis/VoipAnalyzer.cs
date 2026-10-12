using System.Text;
using System.Text.RegularExpressions;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// VoIP/SIP Protocol Analyzer — trích xuất thông tin nhạy cảm từ VoIP traffic.
///
/// Những gì sniff được:
/// 1. SIP Credentials: Digest Auth (username, realm, nonce, response hash → hashcat crack được)
///    - SIP REGISTER → auth challenge → REGISTER with Authorization header
///    - Hash format: username:realm:password → MD5 → crackable
///
/// 2. Call Metadata: Caller/Callee (số điện thoại, extension), Call-ID, User-Agent (IP phone model)
///    - INVITE → caller + callee + SDP media info
///    - BYE → call duration
///
/// 3. RTP Streams: Real-time audio/video data (nếu không mã hóa = cleartext voice)
///    - Even-numbered UDP ports, PT (payload type) → codec identification
///    - Có thể reconstruct audio nếu codec là G.711 (PCM)
///
/// 4. SDP (Session Description Protocol): Codec negotiation, media IP/port
///    - Embedded trong SIP INVITE/200 OK
///    - Reveals internal network topology (media IP ≠ signaling IP)
///
/// 5. SRTP vs RTP: Detect nếu voice traffic bị mã hóa hay không
///    - SDP "RTP/SAVP" = SRTP (encrypted), "RTP/AVP" = RTP (cleartext)
///
/// 6. WebRTC leaks:
///    - STUN binding requests → leak internal/external IP mapping (ICE candidates)
///    - TURN allocation → relay server info
///    - WebRTC media luôn dùng DTLS-SRTP nên voice data encrypted,
///      nhưng STUN/TURN metadata vẫn lộ
/// </summary>
public sealed class VoipAnalyzer
{
    private readonly List<SipCredential> _credentials = new();
    private readonly List<SipCall> _calls = new();
    private readonly List<RtpStream> _rtpStreams = new();
    private readonly List<StunBinding> _stunBindings = new();
    private readonly Dictionary<string, SipCall> _activeCallsByCallId = new();
    private readonly object _lock = new();
    private long _nextId = 1;
    private DateTime _lastEviction = DateTime.MinValue;
    private long _analyzeCount;

    /// <summary>Maximum bytes of SIP payload to convert to string. SIP headers + SDP body rarely exceed 4 KB.</summary>
    private const int MaxSipPayloadBytes = 4096;

    /// <summary>Size caps to prevent unbounded RAM growth on long-running captures.</summary>
    private const int MaxCredentials = 2000;
    private const int MaxCalls = 5000;
    private const int MaxRtpStreams = 2000;
    private const int MaxStunBindings = 2000;
    private const int MaxActiveCalls = 1000;

    /// <summary>How often to run state eviction (in analyzed-packet count).</summary>
    private const int EvictionInterval = 4096;

    /// <summary>Active calls older than this are considered dead (no BYE received).</summary>
    private static readonly TimeSpan ActiveCallTimeout = TimeSpan.FromMinutes(10);

    // SIP Ports
    private static readonly HashSet<int> SipPorts = new() { 5060, 5061 };

    // STUN/TURN ports
    private static readonly HashSet<int> StunPorts = new() { 3478, 3479, 5349, 19302 };

    public event Action<SipCredential>? OnCredentialFound;
    public event Action<SipCall>? OnCallDetected;
    public event Action<RtpStream>? OnRtpDetected;
    public event Action<StunBinding>? OnStunDetected;
    public event Action<VoipFinding>? OnFinding;

    public void Analyze(CapturedPacket packet)
    {
        // Periodic state eviction to bound memory
        if (Interlocked.Increment(ref _analyzeCount) % EvictionInterval == 0)
            EvictStaleState(packet.Timestamp);

        if (packet.IpProtocol == 17) // UDP only
        {
            // SIP (port 5060/5061)
            if (SipPorts.Contains(packet.SourcePort) || SipPorts.Contains(packet.DestPort))
            {
                AnalyzeSip(packet);
                return;
            }

            // STUN/TURN
            if (StunPorts.Contains(packet.DestPort) || StunPorts.Contains(packet.SourcePort))
            {
                AnalyzeStun(packet);
                return;
            }

            // RTP detection (even-numbered high ports, specific payload patterns)
            if (packet.SourcePort >= 1024 && packet.DestPort >= 1024)
            {
                AnalyzeRtp(packet);
            }
        }
        else if (packet.IpProtocol == 6) // TCP — SIP over TCP
        {
            if (SipPorts.Contains(packet.SourcePort) || SipPorts.Contains(packet.DestPort))
            {
                AnalyzeSip(packet);
            }
        }
    }

    // ============================================================
    // SIP Analysis
    // ============================================================

    private void AnalyzeSip(CapturedPacket packet)
    {
        var payload = packet.GetPayload();
        if (payload.Length < 20) return;

        // Span-based quick check BEFORE allocating a string — reject non-SIP packets at zero cost.
        // SIP requests start with a method name; responses start with "SIP/".
        if (!IsSipPayload(payload))
            return;

        // Limit string conversion to MaxSipPayloadBytes to avoid GC pressure on jumbo packets.
        int convertLen = Math.Min(payload.Length, MaxSipPayloadBytes);
        string text;
        try { text = Encoding.ASCII.GetString(payload[..convertLen]); }
        catch { return; }

        packet.ApplicationProtocol = "SIP";

        // Parse headers
        var headers = ParseSipHeaders(text);
        string method = GetSipMethod(text);
        string callId = headers.GetValueOrDefault("call-id", "");

        // 1. Extract credentials from Authorization / Proxy-Authorization
        ExtractSipAuth(text, headers, packet);

        // 2. Track calls
        TrackSipCall(method, text, headers, packet);

        // 3. Parse SDP for media info
        if (text.Contains("Content-Type: application/sdp", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("content-type: application/sdp", StringComparison.OrdinalIgnoreCase))
        {
            ParseSdp(text, callId, packet);
        }

        // 4. Check for security issues
        CheckSipSecurity(method, headers, packet);
    }

    private void ExtractSipAuth(string text, Dictionary<string, string> headers, CapturedPacket packet)
    {
        // Look for Authorization or Proxy-Authorization headers
        var authPatterns = new[] { "Authorization:", "Proxy-Authorization:" };
        foreach (var pattern in authPatterns)
        {
            int idx = text.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;

            int lineEnd = text.IndexOf('\n', idx);
            if (lineEnd < 0) lineEnd = text.Length;
            string authLine = text[idx..lineEnd].Trim();

            if (!authLine.Contains("Digest", StringComparison.OrdinalIgnoreCase)) continue;

            // Parse Digest auth parameters
            var username = ExtractParam(authLine, "username");
            var realm = ExtractParam(authLine, "realm");
            var nonce = ExtractParam(authLine, "nonce");
            var uri = ExtractParam(authLine, "uri");
            var response = ExtractParam(authLine, "response");
            var algorithm = ExtractParam(authLine, "algorithm") ?? "MD5";

            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(response))
            {
                var cred = new SipCredential
                {
                    Id = Interlocked.Increment(ref _nextId),
                    Username = username,
                    Realm = realm ?? "",
                    Nonce = nonce ?? "",
                    Uri = uri ?? "",
                    Response = response,
                    Algorithm = algorithm,
                    SourceIp = packet.SourceIP ?? "",
                    DestIp = packet.DestIP ?? "",
                    Timestamp = packet.Timestamp,
                    // Hashcat format cho SIP digest: $sip$*<uri>*<realm>*<nonce>*...
                    HashcatFormat = $"$sip$*{uri}*{realm}*{GetSipMethod(text)}*{nonce}*{response}"
                };

                lock (_lock)
                {
                    // Deduplicate + inline cap check
                    if (_credentials.Count < MaxCredentials &&
                        !_credentials.Any(c => c.Username == cred.Username && c.Nonce == cred.Nonce))
                    {
                        _credentials.Add(cred);
                        OnCredentialFound?.Invoke(cred);

                        EmitFinding("SIP", "CRITICAL", "Credential Capture",
                            $"SIP Digest Auth: {username}@{realm}",
                            $"Captured SIP credentials for user '{username}' at realm '{realm}'. " +
                            $"Response hash: {response}. Algorithm: {algorithm}. " +
                            $"Can be cracked with hashcat mode 11400.",
                            packet.SourceIP ?? "");
                    }
                }
            }
        }

        // Also check for plaintext auth (rare but exists)
        if (text.Contains("Authorization: Basic", StringComparison.OrdinalIgnoreCase))
        {
            int idx = text.IndexOf("Authorization: Basic", StringComparison.OrdinalIgnoreCase);
            int lineEnd = text.IndexOf('\n', idx);
            if (lineEnd > idx)
            {
                string b64 = text[(idx + 21)..lineEnd].Trim();
                try
                {
                    string decoded = Encoding.ASCII.GetString(Convert.FromBase64String(b64));
                    var parts = decoded.Split(':');
                    if (parts.Length >= 2)
                    {
                        EmitFinding("SIP", "CRITICAL", "Credential Capture",
                            $"SIP Basic Auth PLAINTEXT: {parts[0]}",
                            $"Captured plaintext SIP credentials: {parts[0]}:{parts[1]}. " +
                            $"Basic Auth over SIP is extremely insecure.",
                            packet.SourceIP ?? "");
                    }
                }
                catch { }
            }
        }
    }

    private void TrackSipCall(string method, string text, Dictionary<string, string> headers, CapturedPacket packet)
    {
        string callId = headers.GetValueOrDefault("call-id", "");
        if (string.IsNullOrEmpty(callId)) return;

        string from = ExtractSipAddress(headers.GetValueOrDefault("from", ""));
        string to = ExtractSipAddress(headers.GetValueOrDefault("to", ""));
        string userAgent = headers.GetValueOrDefault("user-agent", "");
        string contact = headers.GetValueOrDefault("contact", "");

        lock (_lock)
        {
            if (method == "INVITE")
            {
                // Guard against unbounded active call tracking
                if (_activeCallsByCallId.Count >= MaxActiveCalls)
                    return;

                var call = new SipCall
                {
                    Id = Interlocked.Increment(ref _nextId),
                    CallId = callId,
                    Caller = from,
                    Callee = to,
                    UserAgent = userAgent,
                    Contact = contact,
                    SourceIp = packet.SourceIP ?? "",
                    DestIp = packet.DestIP ?? "",
                    StartTime = packet.Timestamp,
                    State = "INVITE"
                };
                _activeCallsByCallId[callId] = call;
                _calls.Add(call);
                OnCallDetected?.Invoke(call);

                EmitFinding("SIP", "HIGH", "Call Metadata",
                    $"SIP Call: {from} → {to}",
                    $"INVITE from {from} to {to}. Call-ID: {callId}. " +
                    $"User-Agent: {userAgent}. " +
                    $"Source: {packet.SourceIP}:{packet.SourcePort} → {packet.DestIP}:{packet.DestPort}",
                    packet.SourceIP ?? "");
            }
            else if (method == "BYE" && _activeCallsByCallId.TryGetValue(callId, out var activeCall))
            {
                activeCall.EndTime = packet.Timestamp;
                activeCall.State = "BYE";
                activeCall.Duration = activeCall.EndTime - activeCall.StartTime;
                _activeCallsByCallId.Remove(callId);

                EmitFinding("SIP", "MEDIUM", "Call Metadata",
                    $"SIP Call Ended: {activeCall.Caller} → {activeCall.Callee}",
                    $"Call duration: {activeCall.Duration:mm\\:ss}. Call-ID: {callId}",
                    packet.SourceIP ?? "");
            }
            else if (method == "REGISTER")
            {
                // Registration reveals user's extension, server, and contact address
                EmitFinding("SIP", "MEDIUM", "Registration",
                    $"SIP REGISTER: {from}",
                    $"Registration from {from} (UA: {userAgent}). Contact: {contact}. " +
                    $"Source: {packet.SourceIP} → Server: {packet.DestIP}",
                    packet.SourceIP ?? "");
            }
        }
    }

    private void ParseSdp(string text, string callId, CapturedPacket packet)
    {
        // SDP follows empty line in SIP message
        int sdpStart = text.IndexOf("\r\n\r\n");
        if (sdpStart < 0) sdpStart = text.IndexOf("\n\n");
        if (sdpStart < 0) return;

        string sdp = text[(sdpStart + 2)..];
        var lines = sdp.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

        string? mediaIp = null;
        int mediaPort = 0;
        string? mediaTransport = null;
        var codecs = new List<string>();

        foreach (var line in lines)
        {
            if (line.StartsWith("c="))
            {
                // c=IN IP4 192.168.1.100
                var parts = line[2..].Split(' ');
                if (parts.Length >= 3) mediaIp = parts[2].Trim();
            }
            else if (line.StartsWith("m=audio"))
            {
                // m=audio 20000 RTP/AVP 0 8 18 101
                var parts = line[2..].Split(' ');
                if (parts.Length >= 3)
                {
                    int.TryParse(parts[1], out mediaPort);
                    mediaTransport = parts[2]; // RTP/AVP or RTP/SAVP
                }
            }
            else if (line.StartsWith("a=rtpmap:"))
            {
                // a=rtpmap:0 PCMU/8000
                codecs.Add(line[9..].Trim());
            }
        }

        if (mediaIp != null && mediaPort > 0)
        {
            bool isEncrypted = mediaTransport?.Contains("SAVP") == true;
            string severity = isEncrypted ? "INFO" : "HIGH";

            EmitFinding("SDP", severity, "Media Negotiation",
                $"SDP Media: {mediaIp}:{mediaPort} ({mediaTransport})",
                $"Media endpoint: {mediaIp}:{mediaPort}. Transport: {mediaTransport}. " +
                $"Codecs: {string.Join(", ", codecs)}. " +
                (isEncrypted ? "SRTP (encrypted) — voice data protected." :
                    "RTP (CLEARTEXT) — voice data can be intercepted and reconstructed!") +
                (mediaIp != packet.SourceIP ? $" Internal IP leak: media at {mediaIp}, signaling from {packet.SourceIP}" : ""),
                packet.SourceIP ?? "");

            // Track internal IP leak
            if (mediaIp != packet.SourceIP && mediaIp != packet.DestIP)
            {
                EmitFinding("SDP", "MEDIUM", "Information Disclosure",
                    $"Internal IP Leak via SDP: {mediaIp}",
                    $"SDP reveals internal media IP {mediaIp} different from signaling IP {packet.SourceIP}. " +
                    $"This exposes internal network topology.",
                    packet.SourceIP ?? "");
            }
        }
    }

    private void CheckSipSecurity(string method, Dictionary<string, string> headers, CapturedPacket packet)
    {
        // Check for SIP over unencrypted transport (port 5060 = UDP/TCP, 5061 = TLS)
        if (packet.DestPort == 5060 || packet.SourcePort == 5060)
        {
            // Already flagged by analyzing content — SIP on 5060 is cleartext
        }

        // User-Agent reveals IP phone model/firmware
        string ua = headers.GetValueOrDefault("user-agent", "");
        if (!string.IsNullOrEmpty(ua) && (ua.Contains("Cisco", StringComparison.OrdinalIgnoreCase) ||
            ua.Contains("Polycom", StringComparison.OrdinalIgnoreCase) ||
            ua.Contains("Grandstream", StringComparison.OrdinalIgnoreCase) ||
            ua.Contains("Yealink", StringComparison.OrdinalIgnoreCase) ||
            ua.Contains("Avaya", StringComparison.OrdinalIgnoreCase) ||
            ua.Contains("Asterisk", StringComparison.OrdinalIgnoreCase) ||
            ua.Contains("FreeSWITCH", StringComparison.OrdinalIgnoreCase) ||
            ua.Contains("FreePBX", StringComparison.OrdinalIgnoreCase)))
        {
            EmitFinding("SIP", "LOW", "Information Disclosure",
                $"VoIP Device: {ua}",
                $"SIP User-Agent reveals device/software: {ua}. " +
                $"This may help identify known vulnerabilities for this specific device/version.",
                packet.SourceIP ?? "");
        }
    }

    // ============================================================
    // RTP Analysis
    // ============================================================

    private void AnalyzeRtp(CapturedPacket packet)
    {
        var payload = packet.GetPayload();
        if (payload.Length < 12) return; // RTP header = 12 bytes minimum

        // RTP header check
        byte version = (byte)((payload[0] >> 6) & 0x03);
        if (version != 2) return; // RTP version 2

        byte payloadType = (byte)(payload[1] & 0x7F);
        bool marker = (payload[1] & 0x80) != 0;
        ushort seqNum = (ushort)((payload[2] << 8) | payload[3]);
        uint timestamp = (uint)((payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]);
        uint ssrc = (uint)((payload[8] << 24) | (payload[9] << 16) | (payload[10] << 8) | payload[11]);

        // Filter: known audio payload types
        string? codec = payloadType switch
        {
            0 => "G.711 μ-law (PCMU)",
            3 => "GSM",
            4 => "G.723.1",
            8 => "G.711 A-law (PCMA)",
            9 => "G.722",
            18 => "G.729",
            26 => "JPEG (video)",
            31 => "H.261 (video)",
            32 => "MPV (MPEG video)",
            33 => "MP2T (MPEG2-TS)",
            34 => "H.263 (video)",
            96 or 97 or 98 or 99 or 100 or 101 => "Dynamic", // Dynamic payload types
            _ => null
        };

        if (codec == null) return; // Not a recognized RTP stream

        string streamKey = $"{packet.SourceIP}:{packet.SourcePort}→{packet.DestIP}:{packet.DestPort}|{ssrc}";

        lock (_lock)
        {
            var existing = _rtpStreams.FirstOrDefault(r => r.StreamKey == streamKey);
            if (existing != null)
            {
                existing.PacketCount++;
                existing.LastSeen = packet.Timestamp;
                return; // Already tracked
            }

            var stream = new RtpStream
            {
                Id = Interlocked.Increment(ref _nextId),
                StreamKey = streamKey,
                SourceIp = packet.SourceIP ?? "",
                SourcePort = packet.SourcePort,
                DestIp = packet.DestIP ?? "",
                DestPort = packet.DestPort,
                SSRC = ssrc,
                PayloadType = payloadType,
                Codec = codec,
                FirstSeen = packet.Timestamp,
                LastSeen = packet.Timestamp,
                PacketCount = 1,
                IsEncrypted = false // SRTP detection would require looking at SDP negotiation
            };
            if (_rtpStreams.Count >= MaxRtpStreams) return;
            _rtpStreams.Add(stream);
            OnRtpDetected?.Invoke(stream);

            bool isCleartext = codec.Contains("G.711") || codec.Contains("G.722") || codec == "GSM";
            string severity = isCleartext ? "CRITICAL" : "HIGH";

            EmitFinding("RTP", severity, "Voice/Video Stream",
                $"RTP Stream: {codec} ({packet.SourceIP}→{packet.DestIP})",
                $"Detected {(isCleartext ? "CLEARTEXT" : "")} RTP stream: {codec} (PT={payloadType}). " +
                $"SSRC: 0x{ssrc:X8}. {packet.SourceIP}:{packet.SourcePort} → {packet.DestIP}:{packet.DestPort}. " +
                (isCleartext ? "G.711 voice data CAN BE RECONSTRUCTED from captured packets! " +
                    "Use Wireshark → Telephony → RTP Streams → Play to listen." : ""),
                packet.SourceIP ?? "");
        }
    }

    // ============================================================
    // STUN/TURN Analysis
    // ============================================================

    private void AnalyzeStun(CapturedPacket packet)
    {
        var payload = packet.GetPayload();
        if (payload.Length < 20) return;

        // STUN message: first 2 bits = 00, bytes 4-7 = magic cookie 0x2112A442
        ushort msgType = (ushort)((payload[0] << 8) | payload[1]);
        if ((msgType & 0xC000) != 0) return; // Not STUN

        uint magicCookie = (uint)((payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]);
        if (magicCookie != 0x2112A442) return; // Not a valid STUN message

        string method = (msgType & 0x000F) switch
        {
            0x001 => "Binding",
            0x003 => "Allocate (TURN)",
            0x004 => "Refresh (TURN)",
            0x006 => "Send (TURN)",
            0x007 => "Data (TURN)",
            0x008 => "CreatePermission (TURN)",
            0x009 => "ChannelBind (TURN)",
            _ => $"Unknown(0x{msgType:X4})"
        };

        bool isRequest = (msgType & 0x0110) == 0x0000;
        bool isResponse = (msgType & 0x0110) == 0x0100;

        // Parse STUN attributes for XOR-MAPPED-ADDRESS (reveals public/private IP mapping)
        string? mappedAddress = null;
        int offset = 20; // After STUN header
        while (offset + 4 <= payload.Length)
        {
            ushort attrType = (ushort)((payload[offset] << 8) | payload[offset + 1]);
            ushort attrLen = (ushort)((payload[offset + 2] << 8) | payload[offset + 3]);
            offset += 4;

            if (offset + attrLen > payload.Length) break;

            // XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
            if ((attrType == 0x0020 || attrType == 0x0001) && attrLen >= 8)
            {
                byte family = payload[offset + 1];
                if (family == 0x01) // IPv4
                {
                    ushort port = (ushort)((payload[offset + 2] << 8) | payload[offset + 3]);
                    uint ip = (uint)((payload[offset + 4] << 24) | (payload[offset + 5] << 16) |
                                     (payload[offset + 6] << 8) | payload[offset + 7]);

                    if (attrType == 0x0020) // XOR with magic cookie
                    {
                        port ^= 0x2112;
                        ip ^= 0x2112A442;
                    }

                    mappedAddress = $"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}:{port}";
                }
            }

            // Align to 4-byte boundary
            offset += attrLen;
            if (attrLen % 4 != 0) offset += 4 - (attrLen % 4);
        }

        lock (_lock)
        {
            var binding = new StunBinding
            {
                Id = Interlocked.Increment(ref _nextId),
                Method = method,
                IsRequest = isRequest,
                SourceIp = packet.SourceIP ?? "",
                DestIp = packet.DestIP ?? "",
                SourcePort = packet.SourcePort,
                DestPort = packet.DestPort,
                MappedAddress = mappedAddress ?? "",
                Timestamp = packet.Timestamp
            };
            if (_stunBindings.Count < MaxStunBindings)
            {
                _stunBindings.Add(binding);
                OnStunDetected?.Invoke(binding);
            }
        }

        string severity = method.Contains("TURN") ? "MEDIUM" : "LOW";
        string detail = $"STUN {method} {(isRequest ? "Request" : isResponse ? "Response" : "Indication")}. " +
            $"{packet.SourceIP}:{packet.SourcePort} → {packet.DestIP}:{packet.DestPort}. ";

        if (!string.IsNullOrEmpty(mappedAddress))
        {
            detail += $"Mapped address: {mappedAddress} — reveals NAT binding / public IP.";
            severity = "MEDIUM";
        }

        if (method.Contains("TURN"))
        {
            detail += "TURN relay detected — may expose relay infrastructure.";
        }

        EmitFinding("STUN", severity, "WebRTC/VoIP Discovery",
            $"STUN {method}: {packet.SourceIP} → {packet.DestIP}" +
            (mappedAddress != null ? $" (Mapped: {mappedAddress})" : ""),
            detail,
            packet.SourceIP ?? "");
    }

    // ============================================================
    // Getters
    // ============================================================

    public List<SipCredential> GetCredentials()
    {
        lock (_lock) { return new List<SipCredential>(_credentials); }
    }

    public List<SipCall> GetCalls()
    {
        lock (_lock) { return new List<SipCall>(_calls); }
    }

    public List<RtpStream> GetRtpStreams()
    {
        lock (_lock) { return new List<RtpStream>(_rtpStreams); }
    }

    public List<StunBinding> GetStunBindings()
    {
        lock (_lock) { return new List<StunBinding>(_stunBindings); }
    }

    public VoipSummary GetSummary()
    {
        lock (_lock)
        {
            return new VoipSummary
            {
                TotalCredentials = _credentials.Count,
                TotalCalls = _calls.Count,
                ActiveCalls = _activeCallsByCallId.Count,
                TotalRtpStreams = _rtpStreams.Count,
                CleartextStreams = _rtpStreams.Count(r => !r.IsEncrypted),
                TotalStunBindings = _stunBindings.Count
            };
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _credentials.Clear();
            _calls.Clear();
            _rtpStreams.Clear();
            _stunBindings.Clear();
            _activeCallsByCallId.Clear();
        }
    }

    // ============================================================
    // State eviction — prevent unbounded RAM growth
    // ============================================================

    private void EvictStaleState(DateTime now)
    {
        lock (_lock)
        {
            // Evict dead active calls (no BYE received within timeout)
            if (_activeCallsByCallId.Count > 0)
            {
                var deadCalls = new List<string>();
                foreach (var kv in _activeCallsByCallId)
                {
                    if ((now - kv.Value.StartTime) > ActiveCallTimeout)
                        deadCalls.Add(kv.Key);
                }
                foreach (var key in deadCalls)
                {
                    var call = _activeCallsByCallId[key];
                    call.State = "TIMEOUT";
                    _activeCallsByCallId.Remove(key);
                }
            }

            // Hard caps: trim oldest entries when collections exceed limits.
            // Credentials are high-value — keep newest.
            if (_credentials.Count > MaxCredentials)
                _credentials.RemoveRange(0, _credentials.Count - MaxCredentials);
            if (_calls.Count > MaxCalls)
                _calls.RemoveRange(0, _calls.Count - MaxCalls);
            if (_rtpStreams.Count > MaxRtpStreams)
                _rtpStreams.RemoveRange(0, _rtpStreams.Count - MaxRtpStreams);
            if (_stunBindings.Count > MaxStunBindings)
                _stunBindings.RemoveRange(0, _stunBindings.Count - MaxStunBindings);
        }
    }

    // ============================================================
    // Span-based SIP detection (zero allocation)
    // ============================================================

    /// <summary>
    /// Checks whether the payload starts with a known SIP method or "SIP/" response prefix
    /// using byte-level comparison — no string allocation.
    /// </summary>
    private static bool IsSipPayload(ReadOnlySpan<byte> payload)
    {
        // SIP methods and response prefix as UTF8 byte sequences.
        // Methods sorted by frequency in typical traffic: INVITE > REGISTER > OPTIONS > BYE > ACK > ...
        ReadOnlySpan<byte> sip = "SIP/"u8;
        ReadOnlySpan<byte> invite = "INVITE"u8;
        ReadOnlySpan<byte> register = "REGISTER"u8;
        ReadOnlySpan<byte> options = "OPTIONS"u8;
        ReadOnlySpan<byte> bye = "BYE"u8;
        ReadOnlySpan<byte> ack = "ACK"u8;
        ReadOnlySpan<byte> cancel = "CANCEL"u8;
        ReadOnlySpan<byte> notify = "NOTIFY"u8;
        ReadOnlySpan<byte> subscribe = "SUBSCRIBE"u8;
        ReadOnlySpan<byte> info = "INFO"u8;

        return payload.StartsWith(sip) || payload.StartsWith(invite) ||
               payload.StartsWith(register) || payload.StartsWith(options) ||
               payload.StartsWith(bye) || payload.StartsWith(ack) ||
               payload.StartsWith(cancel) || payload.StartsWith(notify) ||
               payload.StartsWith(subscribe) || payload.StartsWith(info);
    }

    // ============================================================
    // Helpers
    // ============================================================

    private static Dictionary<string, string> ParseSipHeaders(string text)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

        for (int i = 1; i < lines.Length; i++) // Skip first line (request/status)
        {
            if (string.IsNullOrEmpty(lines[i])) break; // Empty line = end of headers

            int colonIdx = lines[i].IndexOf(':');
            if (colonIdx > 0)
            {
                string key = lines[i][..colonIdx].Trim().ToLowerInvariant();
                string val = lines[i][(colonIdx + 1)..].Trim();
                headers[key] = val;
            }
        }
        return headers;
    }

    private static string GetSipMethod(string text)
    {
        int spaceIdx = text.IndexOf(' ');
        if (spaceIdx < 0) return "";

        // Request: METHOD sip:user@host SIP/2.0
        string first = text[..spaceIdx];
        if (first == "SIP/2.0") return "RESPONSE";
        return first.ToUpperInvariant();
    }

    private static string? ExtractParam(string line, string param)
    {
        var match = Regex.Match(line, $@"{param}\s*=\s*""?([^"",\s]+)""?", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static string ExtractSipAddress(string headerValue)
    {
        // From: "Display Name" <sip:user@host>;tag=xxx
        // Extract sip:user@host or just user@host
        var match = Regex.Match(headerValue, @"<sip:([^>]+)>");
        if (match.Success) return match.Groups[1].Value;

        match = Regex.Match(headerValue, @"sip:(\S+)");
        if (match.Success) return match.Groups[1].Value;

        return headerValue.Trim();
    }

    private void EmitFinding(string protocol, string severity, string category, string title, string detail, string sourceIp)
    {
        OnFinding?.Invoke(new VoipFinding
        {
            Id = Interlocked.Increment(ref _nextId),
            Protocol = protocol,
            Severity = severity,
            Category = category,
            Title = title,
            Detail = detail,
            SourceIp = sourceIp,
            Timestamp = DateTime.UtcNow
        });
    }
}

// ============================================================
// Data Models
// ============================================================

public class SipCredential
{
    public long Id { get; init; }
    public string Username { get; init; } = "";
    public string Realm { get; init; } = "";
    public string Nonce { get; init; } = "";
    public string Uri { get; init; } = "";
    public string Response { get; init; } = "";
    public string Algorithm { get; init; } = "MD5";
    public string SourceIp { get; init; } = "";
    public string DestIp { get; init; } = "";
    public DateTime Timestamp { get; init; }
    /// <summary>Format cho hashcat mode 11400</summary>
    public string HashcatFormat { get; init; } = "";
}

public class SipCall
{
    public long Id { get; init; }
    public string CallId { get; init; } = "";
    public string Caller { get; init; } = "";
    public string Callee { get; init; } = "";
    public string UserAgent { get; init; } = "";
    public string Contact { get; init; } = "";
    public string SourceIp { get; init; } = "";
    public string DestIp { get; init; } = "";
    public DateTime StartTime { get; init; }
    public DateTime EndTime { get; set; }
    public TimeSpan Duration { get; set; }
    public string State { get; set; } = "";
}

public class RtpStream
{
    public long Id { get; init; }
    public string StreamKey { get; init; } = "";
    public string SourceIp { get; init; } = "";
    public int SourcePort { get; init; }
    public string DestIp { get; init; } = "";
    public int DestPort { get; init; }
    public uint SSRC { get; init; }
    public int PayloadType { get; init; }
    public string Codec { get; init; } = "";
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
    public int PacketCount { get; set; }
    public bool IsEncrypted { get; init; }
}

public class StunBinding
{
    public long Id { get; init; }
    public string Method { get; init; } = "";
    public bool IsRequest { get; init; }
    public string SourceIp { get; init; } = "";
    public string DestIp { get; init; } = "";
    public int SourcePort { get; init; }
    public int DestPort { get; init; }
    public string MappedAddress { get; init; } = "";
    public DateTime Timestamp { get; init; }
}

public class VoipFinding
{
    public long Id { get; init; }
    public string Protocol { get; init; } = "";
    public string Severity { get; init; } = "";
    public string Category { get; init; } = "";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string SourceIp { get; init; } = "";
    public DateTime Timestamp { get; init; }
}

public class VoipSummary
{
    public int TotalCredentials { get; init; }
    public int TotalCalls { get; init; }
    public int ActiveCalls { get; init; }
    public int TotalRtpStreams { get; init; }
    public int CleartextStreams { get; init; }
    public int TotalStunBindings { get; init; }
}

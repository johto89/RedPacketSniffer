using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// Trích xuất credentials từ network traffic cleartext
///
/// Hỗ trợ:
/// - HTTP Basic Authentication (Authorization: Basic ...)
/// - HTTP NTLM Authentication (Authorization: NTLM/Negotiate — detect Type 1/2/3)
/// - HTTP Form POST (username/password fields trong body)
/// - FTP USER/PASS commands (kèm phát hiện anonymous)
/// - Telnet login sequence (char-mode + line-mode, kèm phát hiện anonymous/no-password)
/// - SMTP AUTH LOGIN/PLAIN
/// - POP3 USER/PASS
/// - IMAP LOGIN
///
/// Ngoài việc bắt credential (attempt), extractor còn parse response code từ server để xác
/// nhận login thành công/thất bại. Credential được emit ngay với LoginStatus.Unknown; khi
/// response tương ứng tới, LoginStatus được cập nhật và event OnLoginResult được raise.
///
/// Lưu ý: Chỉ detect được traffic CLEARTEXT.
/// HTTPS/TLS traffic không decode được (cần proxy MitM riêng).
/// </summary>
public sealed class CredentialExtractor
{
    // TTL and prune cadence for half-finished login sessions (USER seen but PASS never arrives).
    private const int SessionTtlSeconds = 120;
    private const int SessionPruneEvery = 2048;

    /// <summary>Size caps to prevent unbounded RAM growth on long-running captures.</summary>
    private const int MaxCredentials = 5000;
    private const int MaxSeenSignatures = 10_000;

    private readonly List<ExtractedCredential> _credentials = new();
    private readonly HashSet<string> _seen = new();
    private readonly object _lock = new();

    // ConcurrentDictionary: Analyze runs on the capture/worker thread while Clear() may run on
    // the UI thread. Plain Dictionary would corrupt under that concurrency; these are safe for
    // the per-operation access pattern here (single writer thread + concurrent Clear/prune).
    private readonly ConcurrentDictionary<string, FtpSession> _ftpSessions = new();
    private readonly ConcurrentDictionary<string, TelnetSession> _telnetSessions = new();
    private readonly ConcurrentDictionary<string, SmtpSession> _smtpSessions = new();

    // Credentials awaiting a server response to confirm success/failure, keyed by normalized
    // connection so the response direction (server -> client) matches the attempt direction.
    private readonly ConcurrentDictionary<string, PendingLogin> _pendingResults = new();

    private long _analyzeCounter;

    /// <summary>
    /// When false, HTTP credential extraction is skipped so it can be handled by a
    /// stream-based parser (HttpStreamCredentialParser) fed via TCP reassembly. Line-based
    /// protocols (FTP/POP3/IMAP/SMTP/Telnet) are unaffected. Default true preserves the
    /// original standalone behavior.
    /// </summary>
    public bool HandleHttp { get; set; } = true;

    /// <summary>Raised when a captured credential is first seen (with LoginStatus.Unknown).</summary>
    public event Action<ExtractedCredential>? OnCredentialFound;

    /// <summary>
    /// Raised when a server response confirms the outcome of a previously reported credential.
    /// The same ExtractedCredential instance is passed back with its LoginStatus updated.
    /// </summary>
    public event Action<ExtractedCredential>? OnLoginResult;

    /// <summary>
    /// Phân tích packet, trích xuất credential nếu có
    /// </summary>
    public void Analyze(CapturedPacket packet)
    {
        if (packet.RawData.Length == 0) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 4) return;

        // Periodically drop stale half-finished sessions so they don't accumulate on a busy link.
        if (Interlocked.Increment(ref _analyzeCounter) % SessionPruneEvery == 0)
            PruneSessions(packet.Timestamp);

        ExtractedCredential? cred = null;

        try
        {
            // Route theo protocol
            if (packet.IpProtocol == 6) // TCP
            {
                ushort serverPort = Math.Min(packet.SourcePort, packet.DestPort);

                cred = serverPort switch
                {
                    80 or 8080 or 8000 or 8888 => HandleHttp ? ExtractHttpCredentials(payload, packet) : null,
                    21 => ExtractFtpCredentials(payload, packet),
                    23 => ExtractTelnetCredentials(payload, packet),
                    25 or 587 => ExtractSmtpCredentials(payload, packet),
                    110 => ExtractPop3Credentials(payload, packet),
                    143 => ExtractImapCredentials(payload, packet),
                    _ => HandleHttp ? TryExtractHttpCredentials(payload, packet) : null // Có thể HTTP trên port non-standard
                };

                // Server -> client packet: correlate to a pending attempt to confirm the outcome.
                if (packet.SourcePort == serverPort &&
                    serverPort is 21 or 110 or 143 or 25 or 587 or 23)
                {
                    HandleLoginResponse(payload, packet, serverPort);
                }
            }
        }
        catch
        {
            // Skip malformed data
        }

        if (cred != null)
        {
            // Dedup so a credential repeated across many packets (e.g. HTTP Basic on every
            // request, or a re-login) is reported once.
            string signature = $"{cred.Protocol}|{cred.DestIP}:{cred.DestPort}|{cred.Username}|{cred.Password}";
            bool isNew;
            lock (_lock)
            {
                // Prevent unbounded growth of dedup set.
                // HashSet has no insertion order, so partial eviction removes an arbitrary
                // half. This may re-report some credentials but prevents memory exhaustion.
                if (_seen.Count >= MaxSeenSignatures)
                {
                    int toKeep = _seen.Count / 2;
                    int removed = 0;
                    int target = _seen.Count - toKeep;
                    _seen.RemoveWhere(_ => removed++ < target);
                }

                isNew = _seen.Add(signature);
                if (isNew)
                {
                    // Trim oldest credentials when cap exceeded
                    if (_credentials.Count >= MaxCredentials)
                        _credentials.RemoveRange(0, _credentials.Count / 4);

                    _credentials.Add(cred);
                }
            }
            if (isNew) OnCredentialFound?.Invoke(cred);
        }
    }

    public List<ExtractedCredential> GetAllCredentials()
    {
        lock (_lock) { return new List<ExtractedCredential>(_credentials); }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _credentials.Clear();
            _seen.Clear();
        }
        _ftpSessions.Clear();
        _telnetSessions.Clear();
        _smtpSessions.Clear();
        _pendingResults.Clear();
    }

    // ============================================================
    // HTTP
    // ============================================================

    private ExtractedCredential? ExtractHttpCredentials(ReadOnlySpan<byte> payload, CapturedPacket packet)
    {
        return TryExtractHttpCredentials(payload, packet);
    }

    /// <summary>Maximum bytes to convert for HTTP credential extraction. Covers headers + typical form body.</summary>
    private const int MaxHttpCredPayloadBytes = 4096;
    private const int MaxLineProtocolPayloadBytes = 1024; // FTP, SMTP, POP3, IMAP commands are short

    private ExtractedCredential? TryExtractHttpCredentials(ReadOnlySpan<byte> payload, CapturedPacket packet)
    {
        // Span-based quick check BEFORE allocating a string.
        if (!payload.StartsWith("GET "u8) && !payload.StartsWith("POST "u8) &&
            !payload.StartsWith("PUT "u8) && !payload.StartsWith("HTTP/"u8))
            return null;

        // Limit string conversion — credential headers are in the first few KB.
        int convertLen = Math.Min(payload.Length, MaxHttpCredPayloadBytes);
        string payloadStr;
        try { payloadStr = Encoding.ASCII.GetString(payload[..convertLen]); }
        catch { return null; }

        // --- HTTP Basic Auth ---
        var basicMatch = Regex.Match(payloadStr, @"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", RegexOptions.IgnoreCase);
        if (basicMatch.Success)
        {
            try
            {
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(basicMatch.Groups[1].Value));
                int colonIdx = decoded.IndexOf(':');
                string user = colonIdx >= 0 ? decoded[..colonIdx] : decoded;
                string pass = colonIdx >= 0 ? decoded[(colonIdx + 1)..] : "";

                // Lấy Host header
                string host = ExtractHttpHeader(payloadStr, "Host") ?? packet.DestIP ?? "unknown";

                return new ExtractedCredential
                {
                    Timestamp = packet.Timestamp,
                    Protocol = "HTTP Basic",
                    SourceIP = packet.SourceIP ?? "",
                    DestIP = packet.DestIP ?? "",
                    DestPort = packet.DestPort,
                    Host = host,
                    Username = user,
                    Password = pass,
                    RawData = $"Authorization: Basic {basicMatch.Groups[1].Value}",
                    Severity = CredentialSeverity.Critical
                };
            }
            catch { /* Invalid base64 */ }
        }

        // --- NTLM Auth ---
        var ntlmMatch = Regex.Match(payloadStr, @"Authorization:\s*(NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)", RegexOptions.IgnoreCase);
        if (ntlmMatch.Success)
        {
            string authType = ntlmMatch.Groups[1].Value;
            string b64Data = ntlmMatch.Groups[2].Value;
            try
            {
                byte[] ntlmBytes = Convert.FromBase64String(b64Data);
                string ntlmType = IdentifyNtlmMessageType(ntlmBytes);
                string host = ExtractHttpHeader(payloadStr, "Host") ?? packet.DestIP ?? "unknown";

                // Type 3 message chứa domain\user — trích xuất
                string username = "";
                string domain = "";
                if (ntlmType == "Type3" && ntlmBytes.Length > 36)
                {
                    (domain, username) = ExtractNtlmType3Info(ntlmBytes);
                }

                return new ExtractedCredential
                {
                    Timestamp = packet.Timestamp,
                    Protocol = $"HTTP {authType} ({ntlmType})",
                    SourceIP = packet.SourceIP ?? "",
                    DestIP = packet.DestIP ?? "",
                    DestPort = packet.DestPort,
                    Host = host,
                    Username = string.IsNullOrEmpty(domain) ? username : $"{domain}\\{username}",
                    Password = ntlmType == "Type3" ? "[NTLM Hash - capture for relay/crack]" : "[Challenge]",
                    RawData = $"Authorization: {authType} (len={b64Data.Length})",
                    NtlmData = b64Data,
                    Severity = ntlmType == "Type3" ? CredentialSeverity.High : CredentialSeverity.Info
                };
            }
            catch { /* Invalid NTLM data */ }
        }

        // --- HTTP Form POST with credentials ---
        if (payloadStr.StartsWith("POST ", StringComparison.Ordinal))
        {
            string? contentType = ExtractHttpHeader(payloadStr, "Content-Type");
            if (contentType != null && contentType.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                // Tìm body sau \r\n\r\n
                int bodyStart = payloadStr.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (bodyStart >= 0)
                {
                    string body = payloadStr[(bodyStart + 4)..];
                    var formCred = ExtractFormCredentials(body);
                    if (formCred != null)
                    {
                        string host = ExtractHttpHeader(payloadStr, "Host") ?? packet.DestIP ?? "unknown";
                        string url = ExtractHttpUrl(payloadStr);
                        return new ExtractedCredential
                        {
                            Timestamp = packet.Timestamp,
                            Protocol = "HTTP Form POST",
                            SourceIP = packet.SourceIP ?? "",
                            DestIP = packet.DestIP ?? "",
                            DestPort = packet.DestPort,
                            Host = host,
                            Username = formCred.Value.user,
                            Password = formCred.Value.pass,
                            RawData = $"POST {url} — {body[..Math.Min(body.Length, 200)]}",
                            Severity = CredentialSeverity.Critical
                        };
                    }
                }
            }
        }

        return null;
    }

    private static string? ExtractHttpHeader(string httpData, string headerName)
    {
        var match = Regex.Match(httpData, $@"{Regex.Escape(headerName)}:\s*(.+?)(?:\r\n|\r|\n)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

    private static string ExtractHttpUrl(string httpData)
    {
        int spaceIdx = httpData.IndexOf(' ');
        if (spaceIdx < 0) return "";
        int endIdx = httpData.IndexOf(' ', spaceIdx + 1);
        return endIdx > spaceIdx ? httpData[(spaceIdx + 1)..endIdx] : "";
    }

    private static (string user, string pass)? ExtractFormCredentials(string formBody)
    {
        // Tìm các field name phổ biến cho username/password
        var userPatterns = new[] { "username", "user", "login", "email", "usr", "uname", "userid", "user_name", "log" };
        var passPatterns = new[] { "password", "pass", "passwd", "pwd", "secret", "passw", "user_pass" };

        // Case-insensitive, last-value-wins field map. (ToDictionary throws on duplicate keys —
        // a real risk when a form repeats a field name.)
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string pair in formBody.Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length != 2) continue;
            try { fields[Uri.UnescapeDataString(kv[0])] = Uri.UnescapeDataString(kv[1]); }
            catch { /* skip malformed field */ }
        }

        string? user = null, pass = null;
        foreach (var pattern in userPatterns)
        {
            if (fields.TryGetValue(pattern, out var val)) { user = val; break; }
        }
        foreach (var pattern in passPatterns)
        {
            if (fields.TryGetValue(pattern, out var val)) { pass = val; break; }
        }

        if (user != null || pass != null)
            return (user ?? "", pass ?? "");
        return null;
    }

    // ============================================================
    // NTLM Message Parsing
    // ============================================================

    private static string IdentifyNtlmMessageType(byte[] data)
    {
        // NTLMSSP signature: "NTLMSSP\0" at offset 0
        if (data.Length < 12) return "Unknown";
        if (data[0] != 'N' || data[1] != 'T' || data[2] != 'L' || data[3] != 'M' ||
            data[4] != 'S' || data[5] != 'S' || data[6] != 'P' || data[7] != 0)
            return "Unknown";

        uint messageType = BitConverter.ToUInt32(data, 8);
        return messageType switch
        {
            1 => "Type1",  // Negotiate
            2 => "Type2",  // Challenge
            3 => "Type3",  // Authenticate
            _ => $"Type{messageType}"
        };
    }

    private static (string domain, string username) ExtractNtlmType3Info(byte[] data)
    {
        try
        {
            // Type 3 structure offsets:
            // Domain: len at 28-29, offset at 32-33
            // User:   len at 36-37, offset at 40-41
            if (data.Length < 44) return ("", "");

            ushort domainLen = BitConverter.ToUInt16(data, 28);
            uint domainOffset = BitConverter.ToUInt32(data, 32);
            ushort userLen = BitConverter.ToUInt16(data, 36);
            uint userOffset = BitConverter.ToUInt32(data, 40);

            string domain = "";
            if (domainLen > 0 && domainOffset + domainLen <= data.Length)
                domain = Encoding.Unicode.GetString(data, (int)domainOffset, domainLen);

            string username = "";
            if (userLen > 0 && userOffset + userLen <= data.Length)
                username = Encoding.Unicode.GetString(data, (int)userOffset, userLen);

            return (domain, username);
        }
        catch
        {
            return ("", "");
        }
    }

    // ============================================================
    // FTP
    // ============================================================

    private ExtractedCredential? ExtractFtpCredentials(ReadOnlySpan<byte> payload, CapturedPacket packet)
    {
        int convertLen = Math.Min(payload.Length, MaxLineProtocolPayloadBytes);
        string line;
        try { line = Encoding.ASCII.GetString(payload[..convertLen]).TrimEnd('\r', '\n'); }
        catch { return null; }

        string sessionKey = $"{packet.SourceIP}:{packet.SourcePort}-{packet.DestIP}:{packet.DestPort}";
        string reverseKey = $"{packet.DestIP}:{packet.DestPort}-{packet.SourceIP}:{packet.SourcePort}";

        // FTP USER command
        if (line.StartsWith("USER ", StringComparison.OrdinalIgnoreCase))
        {
            string username = line[5..].Trim();
            _ftpSessions[sessionKey] = new FtpSession
            {
                Username = username,
                SourceIP = packet.SourceIP ?? "",
                DestIP = packet.DestIP ?? "",
                LastActivity = packet.Timestamp
            };
            return null; // Chờ PASS
        }

        // FTP PASS command
        if (line.StartsWith("PASS ", StringComparison.OrdinalIgnoreCase))
        {
            string password = line[5..].Trim();

            // Tìm session tương ứng
            FtpSession? session = null;
            if (_ftpSessions.TryGetValue(sessionKey, out session) || _ftpSessions.TryGetValue(reverseKey, out session))
            {
                _ftpSessions.TryRemove(sessionKey, out _);
                _ftpSessions.TryRemove(reverseKey, out _);

                // Anonymous FTP là một misconfiguration finding, không phải leak mật khẩu thật.
                bool anon = IsAnonymousUser(session.Username);
                var cred = new ExtractedCredential
                {
                    Timestamp = packet.Timestamp,
                    Protocol = anon ? "FTP (Anonymous)" : "FTP",
                    SourceIP = session.SourceIP,
                    DestIP = session.DestIP,
                    DestPort = 21,
                    Host = session.DestIP,
                    Username = session.Username,
                    Password = password,
                    RawData = anon
                        ? $"Anonymous FTP access: USER {session.Username} / PASS {password}"
                        : $"USER {session.Username} / PASS {password}",
                    Severity = anon ? CredentialSeverity.Medium : CredentialSeverity.Critical
                };
                RegisterPending(packet, cred);
                return cred;
            }

            // Không có USER trước — vẫn báo PASS
            return new ExtractedCredential
            {
                Timestamp = packet.Timestamp,
                Protocol = "FTP",
                SourceIP = packet.SourceIP ?? "",
                DestIP = packet.DestIP ?? "",
                DestPort = 21,
                Host = packet.DestIP ?? "",
                Username = "[unknown]",
                Password = password,
                RawData = $"PASS {password}",
                Severity = CredentialSeverity.High
            };
        }

        return null;
    }

    // ============================================================
    // Telnet — char-mode aware
    //
    // Telnet mặc định chạy character-at-a-time: mỗi ký tự client gõ đi trong một packet riêng
    // (và server echo lại username, nhưng KHÔNG echo password). Vì vậy phải buffer từng ký tự
    // theo session và chỉ chốt một dòng khi gặp CR/LF, thay vì đoán theo độ dài packet.
    //
    // Chỉ đọc chiều client -> server để tích lũy input (tránh nhân đôi do echo). Chiều
    // server -> client chỉ dùng để nhận biết prompt "login:" / "password:".
    // ============================================================

    private ExtractedCredential? ExtractTelnetCredentials(ReadOnlySpan<byte> payload, CapturedPacket packet)
    {
        List<byte> data = ExtractTelnetData(payload);   // strip IAC negotiation
        if (data.Count == 0) return null;

        string connKey = "telnet-" + NormalizeConnection(
            packet.SourceIP ?? "", packet.SourcePort, packet.DestIP ?? "", packet.DestPort);

        bool clientToServer = packet.DestPort == 23;

        // --- Server -> client: detect login / password prompts ---
        if (!clientToServer)
        {
            string text = BytesToPrintable(data).ToLowerInvariant();

            if (text.Contains("login:") || text.Contains("username:"))
            {
                var s = _telnetSessions.GetOrAdd(connKey, _ => new TelnetSession());
                s.Reset();
                s.State = TelnetState.WaitingUser;
                s.LastActivity = packet.Timestamp;
            }
            else if (text.Contains("password:"))
            {
                if (_telnetSessions.TryGetValue(connKey, out var s))
                {
                    // Commit any username typed so far, then wait for the password.
                    if (s.State == TelnetState.WaitingUser && s.UserBuffer.Length > 0)
                        s.Username = s.UserBuffer.ToString();
                    s.State = TelnetState.WaitingPass;
                    s.LastActivity = packet.Timestamp;
                }
            }
            return null;
        }

        // --- Client -> server: accumulate typed characters ---
        if (!_telnetSessions.TryGetValue(connKey, out var session))
            return null; // no prompt seen yet — cannot tell input apart from a shell command

        foreach (byte b in data)
        {
            switch (b)
            {
                case 0x0D: // CR — end of line
                    {
                        var cred = CommitTelnetLine(session, packet);
                        session.LastByteWasCr = true;
                        if (cred != null) { _telnetSessions.TryRemove(connKey, out _); return cred; }
                        break;
                    }
                case 0x0A: // LF — end of line, unless it is the LF half of a CRLF
                    if (session.LastByteWasCr) { session.LastByteWasCr = false; break; }
                    {
                        var cred = CommitTelnetLine(session, packet);
                        if (cred != null) { _telnetSessions.TryRemove(connKey, out _); return cred; }
                        break;
                    }
                case 0x00: // NUL — part of CR NUL line ending
                    session.LastByteWasCr = false;
                    break;
                case 0x08: // Backspace
                case 0x7F: // Delete
                    {
                        session.LastByteWasCr = false;
                        var buf = session.State == TelnetState.WaitingPass ? session.PassBuffer : session.UserBuffer;
                        if (buf.Length > 0) buf.Length--;
                        break;
                    }
                default:
                    session.LastByteWasCr = false;
                    if (b >= 0x20 && b < 0x7F)
                    {
                        var buf = session.State == TelnetState.WaitingPass ? session.PassBuffer : session.UserBuffer;
                        if (buf.Length < 256) buf.Append((char)b);
                    }
                    break;
            }
            session.LastActivity = packet.Timestamp;
        }

        return null;
    }

    /// <summary>
    /// Commit the current line. Transitioning from username to password returns null; committing
    /// a password returns the credential. An empty password with a known username is still
    /// reported (a no-password / anonymous login is itself a finding).
    /// </summary>
    private ExtractedCredential? CommitTelnetLine(TelnetSession s, CapturedPacket packet)
    {
        if (s.State == TelnetState.WaitingUser)
        {
            if (s.UserBuffer.Length == 0) return null; // ignore empty line before username
            s.Username = s.UserBuffer.ToString();
            s.UserBuffer.Clear();
            s.State = TelnetState.WaitingPass;
            return null;
        }

        if (s.State == TelnetState.WaitingPass)
        {
            string password = s.PassBuffer.ToString();
            s.PassBuffer.Clear();
            if (string.IsNullOrEmpty(s.Username) && password.Length == 0)
                return null;

            bool anon = IsAnonymousUser(s.Username);
            bool noPass = password.Length == 0;
            string protocol = anon ? "Telnet (Anonymous)" : "Telnet";
            var severity = anon || noPass ? CredentialSeverity.Medium : CredentialSeverity.Critical;

            var cred = new ExtractedCredential
            {
                Timestamp = packet.Timestamp,
                Protocol = protocol,
                SourceIP = packet.SourceIP ?? "",     // client
                DestIP = packet.DestIP ?? "",         // server
                DestPort = 23,
                Host = packet.DestIP ?? "",
                Username = s.Username,
                Password = password,
                RawData = noPass
                    ? $"Telnet: {s.Username} / (empty password)"
                    : $"Telnet: {s.Username} / {password}",
                Severity = severity
            };
            RegisterPending(packet, cred);
            return cred;
        }

        return null;
    }

    /// <summary>Strip Telnet IAC negotiation sequences, returning only the data bytes.</summary>
    private static List<byte> ExtractTelnetData(ReadOnlySpan<byte> payload)
    {
        const byte IAC = 0xFF, SB = 250, SE = 240;
        var data = new List<byte>(payload.Length);

        int i = 0;
        while (i < payload.Length)
        {
            byte b = payload[i];
            if (b != IAC) { data.Add(b); i++; continue; }

            if (i + 1 >= payload.Length) break;
            byte cmd = payload[i + 1];

            if (cmd == IAC) { data.Add(IAC); i += 2; }        // escaped 0xFF
            else if (cmd >= 251 && cmd <= 254) i += 3;         // WILL/WONT/DO/DONT + option
            else if (cmd == SB)
            {
                // Subnegotiation: skip until IAC SE
                i += 2;
                while (i + 1 < payload.Length && !(payload[i] == IAC && payload[i + 1] == SE)) i++;
                i += 2;
            }
            else i += 2;                                       // other 2-byte command
        }

        return data;
    }

    private static string BytesToPrintable(List<byte> data)
    {
        var sb = new StringBuilder(data.Count);
        foreach (byte b in data)
            sb.Append(b >= 0x20 && b < 0x7F ? (char)b : ' ');
        return sb.ToString();
    }

    // ============================================================
    // SMTP
    // ============================================================

    private ExtractedCredential? ExtractSmtpCredentials(ReadOnlySpan<byte> payload, CapturedPacket packet)
    {
        int convertLen = Math.Min(payload.Length, MaxLineProtocolPayloadBytes);
        string line;
        try { line = Encoding.ASCII.GetString(payload[..convertLen]).TrimEnd('\r', '\n'); }
        catch { return null; }

        if (line.Length == 0) return null;

        // Chỉ xét chiều client -> server. Server response bắt đầu bằng mã 3 chữ số (334/235/535...).
        bool clientToServer = packet.DestPort == 25 || packet.DestPort == 587;
        if (!clientToServer) return null;

        string sessionKey = $"smtp-{packet.SourceIP}:{packet.SourcePort}-{packet.DestIP}:{packet.DestPort}";

        // AUTH PLAIN — base64(\0username\0password), inline trên cùng một dòng
        if (line.StartsWith("AUTH PLAIN ", StringComparison.OrdinalIgnoreCase))
        {
            string b64 = line[11..].Trim();
            try
            {
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                // Format: \0username\0password
                var parts = decoded.Split('\0');
                string user = parts.Length > 1 ? parts[1] : "";
                string pass = parts.Length > 2 ? parts[2] : "";

                var cred = new ExtractedCredential
                {
                    Timestamp = packet.Timestamp,
                    Protocol = "SMTP AUTH PLAIN",
                    SourceIP = packet.SourceIP ?? "",
                    DestIP = packet.DestIP ?? "",
                    DestPort = packet.DestPort,
                    Host = packet.DestIP ?? "",
                    Username = user,
                    Password = pass,
                    RawData = $"AUTH PLAIN {b64}",
                    Severity = CredentialSeverity.Critical
                };
                RegisterPending(packet, cred);
                return cred;
            }
            catch { /* Invalid base64 */ }
        }

        // AUTH LOGIN — username/password đến dưới dạng base64 trên các dòng client kế tiếp:
        //   C: AUTH LOGIN
        //   S: 334 VXNlcm5hbWU6      (bỏ qua — server response)
        //   C: <base64 username>
        //   S: 334 UGFzc3dvcmQ6
        //   C: <base64 password>
        // Biến thể inline: "AUTH LOGIN <base64 username>" thì bỏ qua bước hỏi username.
        if (line.Equals("AUTH LOGIN", StringComparison.OrdinalIgnoreCase))
        {
            _smtpSessions[sessionKey] = new SmtpSession
            {
                State = SmtpAuthState.WaitingUser,
                SourceIP = packet.SourceIP ?? "",
                DestIP = packet.DestIP ?? "",
                LastActivity = packet.Timestamp
            };
            return null;
        }
        if (line.StartsWith("AUTH LOGIN ", StringComparison.OrdinalIgnoreCase))
        {
            string arg = line[11..].Trim();
            string user = TryDecodeBase64(arg, out bool ok);
            _smtpSessions[sessionKey] = new SmtpSession
            {
                State = SmtpAuthState.WaitingPass,
                Username = ok ? user : arg,
                SourceIP = packet.SourceIP ?? "",
                DestIP = packet.DestIP ?? "",
                LastActivity = packet.Timestamp
            };
            return null;
        }

        if (_smtpSessions.TryGetValue(sessionKey, out var session))
        {
            // Một lệnh SMTP mới hủy phiên AUTH đang dở (client abort / gõ lệnh khác).
            if (IsSmtpCommand(line))
            {
                _smtpSessions.TryRemove(sessionKey, out _);
                return null;
            }

            if (session.State == SmtpAuthState.WaitingUser)
            {
                string user = TryDecodeBase64(line, out bool ok);
                if (ok)
                {
                    session.Username = user;
                    session.State = SmtpAuthState.WaitingPass;
                    session.LastActivity = packet.Timestamp;
                }
                else
                {
                    _smtpSessions.TryRemove(sessionKey, out _);
                }
                return null;
            }

            if (session.State == SmtpAuthState.WaitingPass)
            {
                string pass = TryDecodeBase64(line, out bool ok);
                _smtpSessions.TryRemove(sessionKey, out _);
                if (ok)
                {
                    var cred = new ExtractedCredential
                    {
                        Timestamp = packet.Timestamp,
                        Protocol = "SMTP AUTH LOGIN",
                        SourceIP = session.SourceIP,
                        DestIP = session.DestIP,
                        DestPort = packet.DestPort,
                        Host = session.DestIP,
                        Username = session.Username,
                        Password = pass,
                        RawData = $"AUTH LOGIN {session.Username} / {pass}",
                        Severity = CredentialSeverity.Critical
                    };
                    RegisterPending(packet, cred);
                    return cred;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Decode a base64 client line. Returns the decoded text and sets <paramref name="ok"/>;
    /// on failure returns the original string with ok = false.
    /// </summary>
    private static string TryDecodeBase64(string s, out bool ok)
    {
        try
        {
            string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(s.Trim()));
            ok = true;
            return decoded;
        }
        catch
        {
            ok = false;
            return s;
        }
    }

    private static bool IsSmtpCommand(string line)
    {
        // Common SMTP verbs; a base64 credential line would not begin with one of these.
        string[] verbs = { "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "QUIT",
                           "NOOP", "VRFY", "EXPN", "AUTH", "STARTTLS", "HELP" };
        foreach (string verb in verbs)
            if (line.StartsWith(verb, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    // ============================================================
    // POP3
    // ============================================================

    private ExtractedCredential? ExtractPop3Credentials(ReadOnlySpan<byte> payload, CapturedPacket packet)
    {
        int convertLen = Math.Min(payload.Length, MaxLineProtocolPayloadBytes);
        string line;
        try { line = Encoding.ASCII.GetString(payload[..convertLen]).TrimEnd('\r', '\n'); }
        catch { return null; }

        string sessionKey = $"pop3-{packet.SourceIP}-{packet.DestIP}";

        if (line.StartsWith("USER ", StringComparison.OrdinalIgnoreCase))
        {
            _ftpSessions[sessionKey] = new FtpSession
            {
                Username = line[5..].Trim(),
                SourceIP = packet.SourceIP ?? "",
                DestIP = packet.DestIP ?? "",
                LastActivity = packet.Timestamp
            };
            return null;
        }

        if (line.StartsWith("PASS ", StringComparison.OrdinalIgnoreCase))
        {
            string password = line[5..].Trim();
            if (_ftpSessions.TryGetValue(sessionKey, out var session))
            {
                _ftpSessions.TryRemove(sessionKey, out _);
                var cred = new ExtractedCredential
                {
                    Timestamp = packet.Timestamp,
                    Protocol = "POP3",
                    SourceIP = session.SourceIP,
                    DestIP = session.DestIP,
                    DestPort = 110,
                    Host = session.DestIP,
                    Username = session.Username,
                    Password = password,
                    RawData = $"USER {session.Username} / PASS {password}",
                    Severity = CredentialSeverity.Critical
                };
                RegisterPending(packet, cred);
                return cred;
            }
        }

        return null;
    }

    // ============================================================
    // IMAP
    // ============================================================

    private ExtractedCredential? ExtractImapCredentials(ReadOnlySpan<byte> payload, CapturedPacket packet)
    {
        int convertLen = Math.Min(payload.Length, MaxLineProtocolPayloadBytes);
        string line;
        try { line = Encoding.ASCII.GetString(payload[..convertLen]).TrimEnd('\r', '\n'); }
        catch { return null; }

        // IMAP LOGIN command: tag LOGIN user pass
        var loginMatch = Regex.Match(line, @"^(\S+)\s+LOGIN\s+""?(\S+?)""?\s+""?(.+?)""?\s*$", RegexOptions.IgnoreCase);
        if (loginMatch.Success)
        {
            string tag = loginMatch.Groups[1].Value;
            var cred = new ExtractedCredential
            {
                Timestamp = packet.Timestamp,
                Protocol = "IMAP LOGIN",
                SourceIP = packet.SourceIP ?? "",
                DestIP = packet.DestIP ?? "",
                DestPort = 143,
                Host = packet.DestIP ?? "",
                Username = loginMatch.Groups[2].Value,
                Password = loginMatch.Groups[3].Value,
                RawData = line,
                Severity = CredentialSeverity.Critical
            };
            RegisterPending(packet, cred, tag);
            return cred;
        }

        return null;
    }

    // ============================================================
    // Login response correlation
    // ============================================================

    /// <summary>Remember a credential attempt so a later server response can confirm its outcome.</summary>
    private void RegisterPending(CapturedPacket packet, ExtractedCredential cred, string? imapTag = null)
    {
        string key = "res-" + NormalizeConnection(
            packet.SourceIP ?? "", packet.SourcePort, packet.DestIP ?? "", packet.DestPort);
        _pendingResults[key] = new PendingLogin
        {
            Cred = cred,
            ImapTag = imapTag,
            LastActivity = packet.Timestamp
        };
    }

    /// <summary>
    /// Parse a server -> client line and, if it confirms the outcome of a pending attempt on the
    /// same connection, update that credential's LoginStatus and raise OnLoginResult.
    /// </summary>
    private void HandleLoginResponse(ReadOnlySpan<byte> payload, CapturedPacket packet, ushort serverPort)
    {
        string key = "res-" + NormalizeConnection(
            packet.SourceIP ?? "", packet.SourcePort, packet.DestIP ?? "", packet.DestPort);
        if (!_pendingResults.TryGetValue(key, out var pending)) return;

        int convertLen = Math.Min(payload.Length, MaxLineProtocolPayloadBytes);
        string line;
        try { line = Encoding.ASCII.GetString(payload[..convertLen]).TrimStart(); }
        catch { return; }

        LoginStatus? status = serverPort switch
        {
            21 => ParseFtpStatus(line),
            110 => ParsePop3Status(line),
            143 => ParseImapStatus(line, pending.ImapTag),
            25 or 587 => ParseSmtpStatus(line),
            23 => ParseTelnetStatus(line),
            _ => null
        };

        if (status.HasValue)
        {
            _pendingResults.TryRemove(key, out _);
            pending.Cred.LoginStatus = status.Value;
            OnLoginResult?.Invoke(pending.Cred);
        }
        else
        {
            pending.LastActivity = packet.Timestamp; // still waiting on a definitive reply
        }
    }

    private static string? FirstReplyCode(string line)
    {
        if (line.Length < 3) return null;
        if (char.IsDigit(line[0]) && char.IsDigit(line[1]) && char.IsDigit(line[2]))
            return line[..3];
        return null;
    }

    private static LoginStatus? ParseFtpStatus(string line)
    {
        // 230 = logged in; 530 = not logged in; 430 = invalid user/pass; 421 = service closing.
        return FirstReplyCode(line) switch
        {
            "230" => LoginStatus.Success,
            "530" or "430" or "421" => LoginStatus.Failed,
            _ => null // 331/332/other intermediate — keep waiting
        };
    }

    private static LoginStatus? ParsePop3Status(string line)
    {
        if (line.StartsWith("+OK", StringComparison.OrdinalIgnoreCase)) return LoginStatus.Success;
        if (line.StartsWith("-ERR", StringComparison.OrdinalIgnoreCase)) return LoginStatus.Failed;
        return null;
    }

    private static LoginStatus? ParseImapStatus(string line, string? expectedTag)
    {
        // Tagged response: "<tag> OK|NO|BAD ...". Match the LOGIN command's tag when known.
        var m = Regex.Match(line, @"^(\S+)\s+(OK|NO|BAD)\b", RegexOptions.IgnoreCase);
        if (!m.Success) return null;
        if (expectedTag != null && !string.Equals(m.Groups[1].Value, expectedTag, StringComparison.OrdinalIgnoreCase))
            return null; // a different command's response
        return m.Groups[2].Value.ToUpperInvariant() == "OK" ? LoginStatus.Success : LoginStatus.Failed;
    }

    private static LoginStatus? ParseSmtpStatus(string line)
    {
        // 235 = auth successful; 535/534/454 = auth failed/unavailable.
        return FirstReplyCode(line) switch
        {
            "235" => LoginStatus.Success,
            "535" or "534" or "454" => LoginStatus.Failed,
            _ => null // 334 challenge / other intermediate
        };
    }

    private static LoginStatus? ParseTelnetStatus(string line)
    {
        // Telnet has no status codes; this is a best-effort keyword heuristic.
        string l = line.ToLowerInvariant();
        if (l.Contains("incorrect") || l.Contains("login failed") ||
            l.Contains("authentication fail") || l.Contains("access denied"))
            return LoginStatus.Failed;
        if (l.Contains("last login") || l.Contains("welcome"))
            return LoginStatus.Success;
        return null;
    }

    // ============================================================
    // Shared helpers
    // ============================================================

    /// <summary>True for well-known anonymous/guest account names (a misconfiguration finding).</summary>
    private static bool IsAnonymousUser(string username)
    {
        string u = username.Trim().ToLowerInvariant();
        return u is "anonymous" or "ftp" or "anon" or "guest";
    }

    /// <summary>Direction-independent connection identity (both endpoints sorted).</summary>
    private static string NormalizeConnection(string ip1, ushort p1, string ip2, ushort p2)
    {
        string a = $"{ip1}:{p1}";
        string b = $"{ip2}:{p2}";
        return string.CompareOrdinal(a, b) <= 0 ? $"{a}|{b}" : $"{b}|{a}";
    }

    // ============================================================
    // Session eviction
    // ============================================================

    /// <summary>
    /// Drop half-finished login sessions older than the TTL so a stream of USER-without-PASS
    /// (aborted logins, missed segments) does not grow the session maps without bound.
    /// </summary>
    private void PruneSessions(DateTime now)
    {
        DateTime cutoff = now.AddSeconds(-SessionTtlSeconds);
        PruneDict(_ftpSessions, cutoff);
        PruneDict(_telnetSessions, cutoff);
        PruneDict(_smtpSessions, cutoff);
        PruneDict(_pendingResults, cutoff);
    }

    private static void PruneDict<T>(ConcurrentDictionary<string, T> dict, DateTime cutoff)
        where T : ISessionActivity
    {
        foreach (var kv in dict)
            if (kv.Value.LastActivity < cutoff)
                dict.TryRemove(kv.Key, out _);
    }

    // ============================================================
    // Session tracking types
    // ============================================================

    private interface ISessionActivity
    {
        DateTime LastActivity { get; set; }
    }

    private class FtpSession : ISessionActivity
    {
        public string Username { get; set; } = "";
        public string SourceIP { get; set; } = "";
        public string DestIP { get; set; } = "";
        public DateTime LastActivity { get; set; }
    }

    private class TelnetSession : ISessionActivity
    {
        public TelnetState State { get; set; }
        public string Username { get; set; } = "";
        public StringBuilder UserBuffer { get; } = new();
        public StringBuilder PassBuffer { get; } = new();
        public bool LastByteWasCr { get; set; }
        public DateTime LastActivity { get; set; }

        public void Reset()
        {
            State = TelnetState.WaitingUser;
            Username = "";
            UserBuffer.Clear();
            PassBuffer.Clear();
            LastByteWasCr = false;
        }
    }

    private class SmtpSession : ISessionActivity
    {
        public SmtpAuthState State { get; set; }
        public string Username { get; set; } = "";
        public string SourceIP { get; set; } = "";
        public string DestIP { get; set; } = "";
        public DateTime LastActivity { get; set; }
    }

    private class PendingLogin : ISessionActivity
    {
        public ExtractedCredential Cred { get; set; } = null!;
        public string? ImapTag { get; set; }
        public DateTime LastActivity { get; set; }
    }

    private enum TelnetState { WaitingUser, WaitingPass }
    private enum SmtpAuthState { WaitingUser, WaitingPass }
}

/// <summary>
/// Outcome of a login attempt, as confirmed by the server response (if captured).
/// </summary>
public enum LoginStatus
{
    Unknown,
    Success,
    Failed
}

/// <summary>
/// Credential đã trích xuất
/// </summary>
public class ExtractedCredential
{
    public DateTime Timestamp { get; init; }
    public string Protocol { get; init; } = "";
    public string SourceIP { get; init; } = "";
    public string DestIP { get; init; } = "";
    public ushort DestPort { get; init; }
    public string Host { get; init; } = "";
    public string Username { get; init; } = "";
    public string Password { get; init; } = "";
    public string RawData { get; init; } = "";
    public string? NtlmData { get; init; }
    public CredentialSeverity Severity { get; init; }

    /// <summary>
    /// Login outcome. Set to Unknown when the credential is first captured, then updated to
    /// Success/Failed if a matching server response is seen (see OnLoginResult). Mutable by
    /// design: the outcome arrives after the attempt is already reported.
    /// </summary>
    public LoginStatus LoginStatus { get; set; } = LoginStatus.Unknown;

    public string SeverityStr => Severity switch
    {
        CredentialSeverity.Critical => "CRITICAL",
        CredentialSeverity.High => "HIGH",
        CredentialSeverity.Medium => "MEDIUM",
        CredentialSeverity.Info => "INFO",
        _ => "UNKNOWN"
    };

    public string LoginStatusStr => LoginStatus switch
    {
        LoginStatus.Success => "SUCCESS",
        LoginStatus.Failed => "FAILED",
        _ => "UNKNOWN"
    };
}

public enum CredentialSeverity
{
    Info,
    Medium,
    High,
    Critical
}

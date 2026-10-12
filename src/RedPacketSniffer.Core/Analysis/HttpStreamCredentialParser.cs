using System.Text;
using System.Text.RegularExpressions;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// Extracts HTTP credentials from reassembled TCP streams.
///
/// This is the stream-based counterpart to the HTTP branch of <see cref="CredentialExtractor"/>.
/// It consumes <see cref="TcpStreamData"/> raised by <see cref="TcpStreamReassembler"/>, so a
/// request whose headers and body span several segments is seen whole — the case the per-packet
/// extractor could not handle (a form-POST body almost always lands in a later segment).
///
/// Handles:
///   - HTTP Basic Authentication (Authorization: Basic ...)
///   - HTTP form POST credentials (application/x-www-form-urlencoded body)
///   - HTTP NTLM/Negotiate. The server challenge (Type 2) travels server -> client in a
///     WWW-Authenticate response header, while the response (Type 3) travels client -> server
///     in an Authorization header — two separate half-streams. This parser inspects BOTH
///     directions, caches the Type 2 challenge per connection, and when the matching Type 3
///     arrives it emits a crack-ready NetNTLMv1/NetNTLMv2 string:
///       NetNTLMv1 (hashcat -m 5500): user::domain:LMresp:NTresp:serverChallenge
///       NetNTLMv2 (hashcat -m 5600): user::domain:serverChallenge:NTproof:blob
///     If the challenge was not captured, the Type 3 is still reported (identity only).
///
/// Results reuse <see cref="ExtractedCredential"/>; the crack-ready string is placed in
/// <see cref="ExtractedCredential.Password"/> so it can be copied straight into a hash file.
///
/// Threading: <see cref="Parse"/> runs on the reassembler's producer thread (the capture
/// thread). <see cref="GetAllCredentials"/> and <see cref="Clear"/> may be called from other
/// threads; shared state is guarded by a lock.
/// </summary>
public sealed class HttpStreamCredentialParser
{
    private const int MaxCachedChallenges = 2048;

    private static readonly string[] HttpMethods =
        { "GET ", "POST ", "PUT ", "HEAD ", "OPTIONS ", "DELETE ", "PATCH " };

    private static readonly string[] UsernameFields =
        { "username", "user", "login", "email", "usr", "uname", "userid", "user_name", "log" };

    private static readonly string[] PasswordFields =
        { "password", "pass", "passwd", "pwd", "secret", "passw", "user_pass" };

    private readonly List<ExtractedCredential> _credentials = new();
    private readonly HashSet<string> _seen = new();
    private readonly Dictionary<string, CachedChallenge> _challenges = new();
    private readonly object _lock = new();

    public event Action<ExtractedCredential>? OnCredentialFound;

    /// <summary>
    /// Parse the reassembled bytes of one half-stream. Safe to call repeatedly as the stream
    /// grows; duplicate credentials are suppressed. Request directions yield credentials;
    /// response directions contribute NTLM Type 2 challenges used to correlate Type 3 responses.
    /// </summary>
    public void Parse(TcpStreamData stream)
    {
        if (stream.Data.Length < 8) return;

        // Latin1 gives a 1:1 byte<->char mapping, so string offsets equal byte offsets — which
        // matters for slicing the body by Content-Length.
        string data = Encoding.Latin1.GetString(stream.Data.Span);

        // A half-stream is one direction, so it is either all request or all response. Use the
        // initiator hint, corroborated by content, to decide which side we are looking at.
        bool looksResponse = !stream.IsInitiator || data.StartsWith("HTTP/", StringComparison.Ordinal);
        bool looksRequest = stream.IsInitiator || FindRequestStart(data, 0) == 0;

        if (looksResponse)
            ScanResponseChallenges(data, stream.Flow, stream.Timestamp);

        if (looksRequest)
            ParseRequests(data, stream);
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
            _challenges.Clear();
        }
    }

    // ============================================================
    // Request scanning (client -> server)
    // ============================================================

    private void ParseRequests(string data, TcpStreamData stream)
    {
        int pos = 0;
        while (pos < data.Length)
        {
            int methodStart = FindRequestStart(data, pos);
            if (methodStart < 0) break;

            int headerEnd = data.IndexOf("\r\n\r\n", methodStart, StringComparison.Ordinal);
            if (headerEnd < 0) break;                         // headers incomplete — wait for more data

            string headerBlock = data[methodStart..headerEnd];
            int bodyStart = headerEnd + 4;

            string method = headerBlock[..headerBlock.IndexOf(' ')];
            string host = ExtractHeader(headerBlock, "Host") ?? stream.Flow.DstIP;

            // Authorization schemes (Basic / NTLM) — available once headers are complete.
            string? authorization = ExtractHeader(headerBlock, "Authorization");
            if (authorization != null)
            {
                var authCred = ParseAuthorization(authorization, host, stream);
                if (authCred != null) Emit(authCred);
            }

            int nextPos;
            if (method.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                string? contentType = ExtractHeader(headerBlock, "Content-Type");
                bool isUrlEncoded = contentType != null &&
                    contentType.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase);

                int contentLength = ParseContentLength(headerBlock);

                if (isUrlEncoded)
                {
                    string? body = null;
                    if (contentLength >= 0)
                    {
                        if (bodyStart + contentLength > data.Length)
                            break;                            // body not fully arrived yet — wait
                        body = data.Substring(bodyStart, contentLength);
                    }
                    else if (stream.Closed)
                    {
                        body = data[bodyStart..];             // no Content-Length; take remainder once closed
                    }
                    else
                    {
                        break;                                // unknown length, still open — wait
                    }

                    var formCred = ParseFormCredentials(body, host, stream);
                    if (formCred != null) Emit(formCred);
                }

                if (contentLength >= 0 && bodyStart + contentLength <= data.Length)
                    nextPos = bodyStart + contentLength;
                else
                    break;
            }
            else
            {
                nextPos = bodyStart;                          // bodyless method: next request follows headers
            }

            if (nextPos <= methodStart) break;                // guard against non-progress loops
            pos = nextPos;
        }
    }

    // ============================================================
    // Response scanning (server -> client) — cache NTLM Type 2 challenges
    // ============================================================

    private void ScanResponseChallenges(string data, TcpFlowKey flow, DateTime timestamp)
    {
        foreach (Match m in Regex.Matches(data,
            @"WWW-Authenticate:\s*(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)",
            RegexOptions.IgnoreCase))
        {
            try
            {
                byte[] blob = Convert.FromBase64String(m.Groups[1].Value);
                if (IdentifyNtlmMessageType(blob) == "Type2" && blob.Length >= 32)
                {
                    var challenge = new byte[8];
                    Array.Copy(blob, 24, challenge, 0, 8);    // ServerChallenge at offset 24
                    StoreChallenge(ConnectionKey(flow), challenge, timestamp);
                }
            }
            catch { /* invalid base64 / short blob */ }
        }
    }

    // ============================================================
    // Authorization header parsing
    // ============================================================

    private ExtractedCredential? ParseAuthorization(string authorization, string host, TcpStreamData stream)
    {
        // --- Basic ---
        var basicMatch = Regex.Match(authorization, @"^Basic\s+([A-Za-z0-9+/=]+)", RegexOptions.IgnoreCase);
        if (basicMatch.Success)
        {
            try
            {
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(basicMatch.Groups[1].Value));
                int colon = decoded.IndexOf(':');
                string user = colon >= 0 ? decoded[..colon] : decoded;
                string pass = colon >= 0 ? decoded[(colon + 1)..] : "";

                return NewCredential(stream, "HTTP Basic", host, user, pass,
                    $"Authorization: Basic {basicMatch.Groups[1].Value}", CredentialSeverity.Critical);
            }
            catch { /* invalid base64 */ }
        }

        // --- NTLM / Negotiate ---
        var ntlmMatch = Regex.Match(authorization, @"^(NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)", RegexOptions.IgnoreCase);
        if (ntlmMatch.Success)
        {
            string authType = ntlmMatch.Groups[1].Value;
            string b64 = ntlmMatch.Groups[2].Value;
            try
            {
                byte[] ntlm = Convert.FromBase64String(b64);
                string type = IdentifyNtlmMessageType(ntlm);

                if (type != "Type3")
                {
                    // Type 1 (negotiate) — presence only.
                    return new ExtractedCredential
                    {
                        Timestamp = stream.Timestamp,
                        Protocol = $"HTTP {authType} ({type})",
                        SourceIP = stream.Flow.SrcIP,
                        DestIP = stream.Flow.DstIP,
                        DestPort = stream.Flow.DstPort,
                        Host = host,
                        Username = "",
                        Password = "[negotiate]",
                        RawData = $"Authorization: {authType} (len={b64.Length})",
                        NtlmData = b64,
                        Severity = CredentialSeverity.Info
                    };
                }

                return BuildType3Credential(ntlm, b64, authType, host, stream);
            }
            catch { /* invalid NTLM blob */ }
        }

        return null;
    }

    /// <summary>
    /// Build a credential from an NTLM Type 3 message, correlating the cached server challenge
    /// to produce a hashcat-ready NetNTLMv1/v2 line when possible.
    /// </summary>
    private ExtractedCredential BuildType3Credential(byte[] ntlm, string b64, string authType, string host, TcpStreamData stream)
    {
        var (domain, user) = ExtractNtlmType3Info(ntlm);
        var (lm, nt) = ExtractNtlmType3Responses(ntlm);
        byte[]? challenge = LookupChallenge(ConnectionKey(stream.Flow));

        string account = string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";

        if (challenge != null && nt.Length > 0)
        {
            string crack;
            string proto;
            string note = "";

            if (nt.Length == 24)
            {
                // NetNTLMv1: user::domain:LM:NT:challenge (hashcat -m 5500)
                proto = "HTTP NTLMv1 (crackable)";
                crack = $"{user}::{domain}:{Hex(lm)}:{Hex(nt)}:{Hex(challenge)}";

                // Extended Session Security (NTLMv1-ESS) puts an 8-byte client challenge in the
                // LM field with the rest zeroed; the emitted -m 5500 line then needs the ESS
                // handling and may not crack as-is. Flag it rather than pretend otherwise.
                if (IsEssLmResponse(lm))
                    note = " [NTLMv1-ESS: verify challenge handling before cracking]";
            }
            else
            {
                // NetNTLMv2: user::domain:challenge:NTproof:blob (hashcat -m 5600)
                proto = "HTTP NTLMv2 (crackable)";
                byte[] ntProof = nt[..16];
                byte[] blob = nt[16..];
                crack = $"{user}::{domain}:{Hex(challenge)}:{Hex(ntProof)}:{Hex(blob)}";
            }

            return new ExtractedCredential
            {
                Timestamp = stream.Timestamp,
                Protocol = proto,
                SourceIP = stream.Flow.SrcIP,
                DestIP = stream.Flow.DstIP,
                DestPort = stream.Flow.DstPort,
                Host = host,
                Username = account,
                Password = crack,                             // ready to paste into a hash file
                RawData = $"NetNTLM for {account} via {authType}{note}",
                NtlmData = b64,
                Severity = CredentialSeverity.Critical
            };
        }

        // Type 3 seen but no matching challenge captured — identity only.
        return new ExtractedCredential
        {
            Timestamp = stream.Timestamp,
            Protocol = $"HTTP {authType} (Type3)",
            SourceIP = stream.Flow.SrcIP,
            DestIP = stream.Flow.DstIP,
            DestPort = stream.Flow.DstPort,
            Host = host,
            Username = account,
            Password = "[NTLM Type3 - server challenge not captured]",
            RawData = $"Authorization: {authType} (len={b64.Length})",
            NtlmData = b64,
            Severity = CredentialSeverity.High
        };
    }

    // ============================================================
    // Form body parsing
    // ============================================================

    private static ExtractedCredential? ParseFormCredentials(string body, string host, TcpStreamData stream)
    {
        // Case-insensitive field map, last-value-wins. (ToDictionary would throw on duplicate keys.)
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string pair in body.Split('&'))
        {
            int eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            string k, v;
            try
            {
                k = Uri.UnescapeDataString(pair[..eq]);
                v = Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
            catch { continue; }
            fields[k] = v;
        }

        string? user = FirstMatch(fields, UsernameFields);
        string? pass = FirstMatch(fields, PasswordFields);
        if (user == null && pass == null) return null;

        string preview = body.Length > 200 ? body[..200] : body;
        return NewCredential(stream, "HTTP Form POST", host, user ?? "", pass ?? "",
            $"POST body: {preview}", CredentialSeverity.Critical);
    }

    private static string? FirstMatch(Dictionary<string, string> fields, string[] candidates)
    {
        foreach (string name in candidates)
            if (fields.TryGetValue(name, out var value)) return value;
        return null;
    }

    // ============================================================
    // Challenge cache
    // ============================================================

    /// <summary>Connection identity independent of direction (client and server endpoints sorted).</summary>
    private static string ConnectionKey(TcpFlowKey flow)
    {
        string a = $"{flow.SrcIP}:{flow.SrcPort}";
        string b = $"{flow.DstIP}:{flow.DstPort}";
        return string.CompareOrdinal(a, b) <= 0 ? $"{a}|{b}" : $"{b}|{a}";
    }

    private void StoreChallenge(string key, byte[] challenge, DateTime timestamp)
    {
        lock (_lock)
        {
            if (_challenges.Count >= MaxCachedChallenges && !_challenges.ContainsKey(key))
                EvictOldestChallengeLocked();
            _challenges[key] = new CachedChallenge { Challenge = challenge, Time = timestamp };
        }
    }

    private byte[]? LookupChallenge(string key)
    {
        lock (_lock)
        {
            return _challenges.TryGetValue(key, out var c) ? c.Challenge : null;
        }
    }

    private void EvictOldestChallengeLocked()
    {
        string? oldestKey = null;
        DateTime oldest = DateTime.MaxValue;
        foreach (var kv in _challenges)
        {
            if (kv.Value.Time < oldest)
            {
                oldest = kv.Value.Time;
                oldestKey = kv.Key;
            }
        }
        if (oldestKey != null) _challenges.Remove(oldestKey);
    }

    // ============================================================
    // Emission + dedup
    // ============================================================

    private void Emit(ExtractedCredential cred)
    {
        string signature = $"{cred.Protocol}|{cred.Host}|{cred.Username}|{cred.Password}";
        bool isNew;
        lock (_lock)
        {
            isNew = _seen.Add(signature);
            if (isNew) _credentials.Add(cred);
        }
        if (isNew) OnCredentialFound?.Invoke(cred);
    }

    // ============================================================
    // HTTP parsing helpers
    // ============================================================

    /// <summary>
    /// Find the offset of the next HTTP request line at or after <paramref name="from"/>.
    /// A method token only counts at the start of the buffer or immediately after a newline,
    /// so tokens inside header values or bodies are not mistaken for a request line.
    /// </summary>
    private static int FindRequestStart(string data, int from)
    {
        int best = -1;
        foreach (string method in HttpMethods)
        {
            int idx = from;
            while (true)
            {
                idx = data.IndexOf(method, idx, StringComparison.Ordinal);
                if (idx < 0) break;
                if (idx == 0 || data[idx - 1] == '\n')
                {
                    if (best < 0 || idx < best) best = idx;
                    break;
                }
                idx += method.Length;                         // false hit mid-line; keep looking
            }
        }
        return best;
    }

    private static string? ExtractHeader(string headerBlock, string name)
    {
        var match = Regex.Match(headerBlock,
            $@"^{Regex.Escape(name)}:\s*(.+?)\s*$",
            RegexOptions.IgnoreCase | RegexOptions.Multiline);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static int ParseContentLength(string headerBlock)
    {
        string? value = ExtractHeader(headerBlock, "Content-Length");
        if (value != null && int.TryParse(value.Trim(), out int len) && len >= 0)
            return len;
        return -1;
    }

    // ============================================================
    // NTLM message parsing
    // ============================================================

    private static string IdentifyNtlmMessageType(byte[] data)
    {
        // "NTLMSSP\0" signature at offset 0, message type (uint32 LE) at offset 8.
        if (data.Length < 12) return "Unknown";
        if (data[0] != 'N' || data[1] != 'T' || data[2] != 'L' || data[3] != 'M' ||
            data[4] != 'S' || data[5] != 'S' || data[6] != 'P' || data[7] != 0)
            return "Unknown";

        uint messageType = BitConverter.ToUInt32(data, 8);
        return messageType switch
        {
            1 => "Type1",
            2 => "Type2",
            3 => "Type3",
            _ => $"Type{messageType}"
        };
    }

    private static (string domain, string username) ExtractNtlmType3Info(byte[] data)
    {
        // Type 3 field descriptors: Domain len@28/off@32, User len@36/off@40. Strings are UTF-16LE
        // when NEGOTIATE_UNICODE is set (the usual case for modern clients).
        try
        {
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

    private static (byte[] lm, byte[] nt) ExtractNtlmType3Responses(byte[] data)
    {
        // Type 3 field descriptors: LmResponse len@12/off@16, NtResponse len@20/off@24.
        try
        {
            if (data.Length < 28) return (Array.Empty<byte>(), Array.Empty<byte>());

            ushort lmLen = BitConverter.ToUInt16(data, 12);
            uint lmOffset = BitConverter.ToUInt32(data, 16);
            ushort ntLen = BitConverter.ToUInt16(data, 20);
            uint ntOffset = BitConverter.ToUInt32(data, 24);

            byte[] lm = (lmLen > 0 && lmOffset + lmLen <= data.Length)
                ? data[(int)lmOffset..(int)(lmOffset + lmLen)]
                : Array.Empty<byte>();

            byte[] nt = (ntLen > 0 && ntOffset + ntLen <= data.Length)
                ? data[(int)ntOffset..(int)(ntOffset + ntLen)]
                : Array.Empty<byte>();

            return (lm, nt);
        }
        catch
        {
            return (Array.Empty<byte>(), Array.Empty<byte>());
        }
    }

    /// <summary>
    /// Heuristic for NTLMv1 Extended Session Security: the LM field carries an 8-byte client
    /// challenge followed by zero padding.
    /// </summary>
    private static bool IsEssLmResponse(byte[] lm)
    {
        if (lm.Length != 24) return false;
        for (int i = 8; i < 24; i++)
            if (lm[i] != 0) return false;
        return true;
    }

    // ============================================================
    // Helpers
    // ============================================================

    private static string Hex(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

    private static ExtractedCredential NewCredential(
        TcpStreamData stream, string protocol, string host,
        string user, string pass, string raw, CredentialSeverity severity)
    {
        return new ExtractedCredential
        {
            Timestamp = stream.Timestamp,
            Protocol = protocol,
            SourceIP = stream.Flow.SrcIP,
            DestIP = stream.Flow.DstIP,
            DestPort = stream.Flow.DstPort,
            Host = host,
            Username = user,
            Password = pass,
            RawData = raw,
            Severity = severity
        };
    }

    private sealed class CachedChallenge
    {
        public byte[] Challenge = Array.Empty<byte>();
        public DateTime Time;
    }
}
